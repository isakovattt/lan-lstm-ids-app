from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

import numpy as np
#подключение к модели
ROOT = Path(__file__).resolve().parent
MODEL_BUNDLE = ROOT / "model_bundle"
DEFAULT_THRESHOLD = 0.82
CONTEXT_LEN = 31
HALF = CONTEXT_LEN // 2

# результат работы модели
@dataclass
class LSTMResult:
    probability: float
    threshold: float
    is_anomaly: bool
    message: str
    details: Dict[str, Any]

# функция категоризации портов
def port_category(value: Any) -> int:
    try:
        port = int(float(value or 0))
    except Exception:
        port = 0
    if port <= 0:
        return 0
    if port <= 1023:
        return 1
    if port <= 49151:
        return 2
    if port <= 65535:
        return 3
    return 0

#функция получение чисел
def _num(row: Dict[str, Any], key: str, default: float = 0.0) -> float:
    try:
        return float(row.get(key, default) or default)
    except Exception:
        return float(default)


class TemporalAttentionFallback:  # Нужен только для проверки типов.
    pass


class LANLSTMAnalyzer:
    def __init__(self, bundle_dir: Path = MODEL_BUNDLE, threshold: float = DEFAULT_THRESHOLD):
        self.bundle_dir = Path(bundle_dir)
        self.threshold = float(threshold)
        self.available = False
        self.error = ""
        self.model = None
        self.feature_columns: List[str] = []
        self.mean = None
        self.scale = None
        self._load()
#функция загрузки модели
    def _load(self) -> None:
        try:
            import tensorflow as tf
            from tensorflow.keras import layers

            @tf.keras.utils.register_keras_serializable(package="CustomLAN")
            class TemporalAttention(layers.Layer):
                def __init__(self, **kwargs):
                    super().__init__(**kwargs)
                    self.score = layers.Dense(1, activation="tanh")
                    self.softmax = layers.Softmax(axis=1)

                def call(self, inputs):
                    weights = self.softmax(self.score(inputs))
                    return tf.reduce_sum(inputs * weights, axis=1)

                def get_config(self):
                    return super().get_config()

            feature_path = self.bundle_dir / "feature_columns.json"
            scaler_path = self.bundle_dir / "scaler_params.npz"
            model_path = self.bundle_dir / "final_best_lan_lstm_smooth_90.keras"

            self.feature_columns = json.loads(feature_path.read_text(encoding="utf-8"))["packet_features"]
            scaler = np.load(scaler_path)
            self.mean = scaler["mean"].astype("float32")
            self.scale = scaler["scale"].astype("float32")
            self.scale[self.scale == 0] = 1.0
            self.model = tf.keras.models.load_model(model_path, custom_objects={"TemporalAttention": TemporalAttention})
            self.available = True
            self.error = ""
            logging.info("LSTM model loaded from %s", model_path)
        except Exception as exc:  # keep server alive; UI will show diagnostic
            self.available = False
            self.error = str(exc)
            logging.exception("Could not load LSTM model")
#Преобразует пакет агента в формат модели.
    def packet_to_model_row(self, pkt: Dict[str, Any]) -> Dict[str, float]:
        proto = str(pkt.get("Protocol", "")).upper()
        if not proto:
            if _num(pkt, "TCP Src Port") or _num(pkt, "TCP Dst Port") or any(_num(pkt, f) for f in ["SYN", "ACK", "FIN", "RST", "PSH", "URG"]):
                proto = "TCP"
            elif _num(pkt, "UDP Src Port") or _num(pkt, "UDP Dst Port"):
                proto = "UDP"
            else:
                proto = "ARP" if _num(pkt, "TTL") == 0 else "TCP"

        flag_count = sum(_num(pkt, f) for f in ["SYN", "ACK", "FIN", "RST", "PSH", "URG"])
        direction = str(pkt.get("Direction", "out")).lower()
        row = {
            "SYN": _num(pkt, "SYN"),
            "ACK": _num(pkt, "ACK"),
            "FIN": _num(pkt, "FIN"),
            "RST": _num(pkt, "RST"),
            "PSH": _num(pkt, "PSH"),
            "URG": _num(pkt, "URG"),
            "Flag_Count": flag_count,
            "TCP Window Size": _num(pkt, "TCP Window Size"),
            "TCP Reserved": _num(pkt, "TCP Reserved"),
            "TCP Urgent Pointer": _num(pkt, "TCP Urgent Pointer"),
            "TCP Src Port": _num(pkt, "TCP Src Port"),
            "TCP Dst Port": _num(pkt, "TCP Dst Port"),
            "UDP Src Port": _num(pkt, "UDP Src Port"),
            "UDP Dst Port": _num(pkt, "UDP Dst Port"),
            "TTL": _num(pkt, "TTL"),
            "IP Packet Length": _num(pkt, "IP Packet Length"),
            "Protocol_TCP": 1.0 if proto == "TCP" else 0.0,
            "Protocol_UDP": 1.0 if proto == "UDP" else 0.0,
            "Protocol_ARP": 1.0 if proto == "ARP" else 0.0,
            "Direction_out": 1.0 if direction == "out" else 0.0,
            "Direction_in": 1.0 if direction == "in" else 0.0,
            "TCP_Src_Port_Category": float(port_category(pkt.get("TCP Src Port"))),
            "TCP_Dst_Port_Category": float(port_category(pkt.get("TCP Dst Port"))),
            "UDP_Src_Port_Category": float(port_category(pkt.get("UDP Src Port"))),
            "UDP_Dst_Port_Category": float(port_category(pkt.get("UDP Dst Port"))),
        }
        return row
#подготовка последовательности;
    def build_matrix(self, packets: List[Dict[str, Any]]) -> np.ndarray:
        rows = [self.packet_to_model_row(pkt) for pkt in packets if isinstance(pkt, dict)]
        if not rows:
            rows = [self.packet_to_model_row({})]

        for i, row in enumerate(rows):
            prev = rows[i - 1] if i > 0 else row
            for col in ["IP Packet Length", "TTL", "Flag_Count"]:
                row[f"{col}_prev_diff"] = row[col] - prev[col] if i > 0 else 0.0
                start = max(0, i - 2)
                row[f"{col}_roll3_mean"] = float(np.mean([rows[j][col] for j in range(start, i + 1)]))

        return np.array([[row.get(col, 0.0) for col in self.feature_columns] for row in rows], dtype="float32")
#создание временных окон длиной 31 пакет;
    def _context_samples(self, arr: np.ndarray, max_samples: int = 160) -> np.ndarray:
        n = len(arr)
        if n <= max_samples:
            centers = np.arange(n)
        else:
            centers = np.linspace(0, n - 1, max_samples).round().astype(int)
        samples = []
        for center in centers:
            s = max(0, int(center) - HALF)
            e = min(n, int(center) + HALF + 1)
            chunk = arr[s:e]
            scaled = ((chunk - self.mean) / self.scale).astype("float32")
            x = np.zeros((CONTEXT_LEN, len(self.feature_columns)), dtype="float32")
            left = (CONTEXT_LEN - len(scaled)) // 2 if len(scaled) < CONTEXT_LEN else 0
            x[left:left + min(len(scaled), CONTEXT_LEN)] = scaled[:CONTEXT_LEN]
            samples.append(x)
        return np.stack(samples).astype("float32")
#получение итоговой вероятности аномалии с помощью LSTM и механизма Attention.
    def predict(self, packets: List[Dict[str, Any]], window_stats: Dict[str, Any] | None = None) -> LSTMResult:
        if not self.available:
            return self.heuristic_predict(packets, window_stats or {}, reason=f"LSTM unavailable: {self.error}")
        arr = self.build_matrix(packets)
        x = self._context_samples(arr)
        probs = self.model.predict(x, batch_size=512, verbose=0).ravel().astype(float)
        if len(probs) == 0:
            prob = 0.0
        else:
            # A live window is suspicious when several packet contexts are suspicious,
            # but one isolated spike should not dominate completely.
            prob = float(0.55 * np.percentile(probs, 90) + 0.30 * np.mean(probs) + 0.15 * np.max(probs))
        prob = max(0.0, min(1.0, prob))
        is_anomaly = prob >= self.threshold
        return LSTMResult(
            probability=prob,
            threshold=self.threshold,
            is_anomaly=is_anomaly,
            message="Аномалия по LSTM" if is_anomaly else "Норма по LSTM",
            details={
                "engine": "lstm",
                "contexts": int(len(probs)),
                "packet_rows": int(len(arr)),
                "prob_mean": float(np.mean(probs)) if len(probs) else 0.0,
                "prob_p90": float(np.percentile(probs, 90)) if len(probs) else 0.0,
                "prob_max": float(np.max(probs)) if len(probs) else 0.0,
            },
        )
#резервный механизм (fallback). Она используется, когда LSTM-модель не смогла загрузиться или недоступна.
    def heuristic_predict(self, packets: List[Dict[str, Any]], window_stats: Dict[str, Any], reason: str = "") -> LSTMResult:
        total = float(window_stats.get("Total Packets per Window", len(packets)) or 0)
        syn = float(window_stats.get("SYN Flags per Window", 0) or 0)
        rst = float(window_stats.get("RST Flags per Window", 0) or 0)
        arp = float(window_stats.get("ARP Protocol Count per Window", 0) or 0)
        score = 0.18 + min(0.28, total / 700.0) + min(0.30, syn / 65.0) + min(0.16, rst / 30.0) + min(0.08, arp / 80.0)
        prob = float(max(0.01, min(0.99, score)))
        is_anomaly = prob >= self.threshold
        return LSTMResult(
            probability=prob,
            threshold=self.threshold,
            is_anomaly=is_anomaly,
            message="Аномалия (fallback)" if is_anomaly else "Норма (fallback)",
            details={"engine": "heuristic_fallback", "reason": reason},
        )
