from flask import Flask, request, jsonify
import psycopg
from psycopg.rows import dict_row
import threading
import time
import logging
from datetime import datetime
import json
import os
import csv

from lstm_runtime import LANLSTMAnalyzer

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Latest saved Kaggle LSTM bundle. If TensorFlow is not installed in the venv,
# LANLSTMAnalyzer keeps the server alive and reports a heuristic fallback.
analyzer = LANLSTMAnalyzer()
SERVER_HOST = os.environ.get("IDS_SERVER_HOST", "0.0.0.0")
SERVER_PORT = int(os.environ.get("IDS_SERVER_PORT", "5050"))
DATABASE_URL = os.environ.get("IDS_DATABASE_URL", "postgresql://ids_user:ids_password@127.0.0.1:5432/ids_db")
MIN_CONSECUTIVE_ANOMALY_WINDOWS = int(os.environ.get("IDS_MIN_CONSECUTIVE_ANOMALY_WINDOWS", "2"))
DEFAULT_CAPTURE_WINDOW_SECONDS = int(os.environ.get("IDS_CAPTURE_WINDOW_SECONDS", "20"))
CONFIG_PATH = os.environ.get("IDS_CONFIG_PATH", "server_config.json")
OPERATOR_LABELS_JSONL = os.environ.get("IDS_OPERATOR_LABELS_JSONL", "operator_packet_labels.jsonl")
OPERATOR_LABELS_CSV = os.environ.get("IDS_OPERATOR_LABELS_CSV", "operator_packet_labels.csv")
_anomaly_streak = 0


NORMAL_FEATURE_RANGES = [
    ("Protocol", None, None, "TCP, UDP, ARP; ICMP допускается ограниченно", "В рабочей LAN основная доля трафика обычно TCP/UDP, ARP используется для обнаружения устройств.", "Если появляется много ICMP/OTHER, проверить источник, запустить ping/traceroute только при необходимости и убедиться, что нет сканирования или неизвестного протокола."),
    ("MAC Src", None, None, "валидный unicast MAC; broadcast ff:ff:ff:ff:ff:ff только для ARP/служебного трафика", "MAC-адрес источника должен принадлежать известному устройству сегмента сети.", "Сверить MAC с таблицей устройств/роутером. Если MAC неизвестен — изолировать устройство, проверить ARP-таблицу и исключить подмену MAC/ARP spoofing."),
    ("MAC Dst", None, None, "валидный unicast MAC; broadcast/multicast допустимы для ARP, DHCP, mDNS, SSDP", "Назначение обычно unicast; массовая рассылка должна быть редкой и служебной.", "Если много broadcast/multicast вне служебных протоколов — проверить источник рассылки, отключить подозрительное устройство или ограничить широковещательный трафик."),
    ("TTL", 32, 255, "32–255 для IP; 0 только для ARP/non-IP", "Для IP-пакетов TTL обычно находится в диапазоне 32–255.", "Если TTL слишком мал или равен 0 у IP-пакета — проверить маршрут, VPN/туннели, петли маршрутизации и источник пакетов."),
    ("IP Packet Length", 20, 1500, "20–1500 байт для обычного Ethernet MTU", "Типичный пакет не должен превышать стандартный MTU 1500 байт.", "При превышении MTU проверить jumbo frames, фрагментацию, драйвер сетевой карты и источник нестандартных пакетов."),
    ("TCP Src Port", 1, 65535, "1–65535; 0 для не-TCP пакетов", "TCP-порт источника должен быть в допустимом диапазоне.", "Если порт 0 или вне диапазона у TCP — проверить генератор пакетов, вредоносную активность или ошибку парсинга."),
    ("TCP Dst Port", 1, 65535, "1–65535; частые нормальные: 22, 53, 80, 123, 443, 445, 5050", "Назначение должно быть допустимым портом; множество разных редких портов за короткое окно похоже на сканирование.", "При серии SYN/RST к разным или редким портам проверить хост-источник, firewall, запущенные nmap/сканеры и заблокировать источник при подтверждении атаки."),
    ("UDP Src Port", 1, 65535, "1–65535; 0 для не-UDP пакетов", "UDP-порт источника должен быть валидным.", "Если порт некорректен — проверить приложение-источник и наличие аномального UDP-трафика."),
    ("UDP Dst Port", 1, 65535, "1–65535; частые служебные: 53, 67, 68, 123, 1900, 5353", "UDP-направление должно попадать в допустимый диапазон; служебные порты допустимы при умеренной частоте.", "При всплеске UDP на неизвестные порты проверить источник, DNS/DHCP/mDNS активность и правила firewall."),
    ("TCP Window Size", 0, 65535, "0–65535", "Размер TCP-окна должен быть в диапазоне поля TCP.", "Если значение нестандартное или часто нулевое — проверить качество соединения, сбросы TCP и возможный crafted traffic."),
    ("TCP Reserved", 0, 0, "0", "Зарезервированные TCP-биты в норме равны 0.", "Если reserved-биты не 0 — проверить пакет как сформированный вручную/scanner traffic; при подтверждении заблокировать источник."),
    ("TCP Urgent Pointer", 0, 0, "0; ненулевой только при URG=1", "Указатель срочности TCP обычно 0 и используется редко.", "Если указатель срочности ненулевой или URG=1 без причины — проверить приложение и исключить crafted/сканирующий трафик."),
    ("Flag_Count", 1, 3, "обычно 1–3 активных TCP-флага", "У TCP-пакета обычно установлено небольшое число флагов.", "При странных комбинациях флагов проверить SYN/FIN/RST storm, сканирование и firewall-журналы."),
    ("SYN/RST pattern", None, None, "единичные SYN/RST допустимы; повторения по редким портам подозрительны", "Повторяющиеся SYN без ACK и ответы RST часто указывают на port scan.", "Проверить источник серии SYN/RST, сравнить с разрешёнными сервисами, при атаке добавить правило firewall и сохранить pcap как доказательство."),
    ("Direction", None, None, "in/out", "Направление должно быть определено относительно MAC локального интерфейса.", "Если направление выглядит неверным — проверить выбранный интерфейс перехвата и MAC локального устройства."),
]


def load_runtime_config():
    config = {"capture_window_seconds": DEFAULT_CAPTURE_WINDOW_SECONDS}
    try:
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                saved = json.load(f)
            if isinstance(saved, dict):
                config.update(saved)
    except Exception as exc:
        logging.warning(f"Не удалось прочитать {CONFIG_PATH}: {exc}")
    config["capture_window_seconds"] = max(5, min(300, int(config.get("capture_window_seconds", DEFAULT_CAPTURE_WINDOW_SECONDS))))
    return config


def save_runtime_config(config):
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)


runtime_config = load_runtime_config()


def is_background_packet(pkt):
    """Filter common LAN service chatter that creates false alarms at idle."""
    proto = str(pkt.get("Protocol", "")).upper()
    dst_mac = str(pkt.get("MAC Dst", "")).lower()
    udp_src = int(float(pkt.get("UDP Src Port", 0) or 0))
    udp_dst = int(float(pkt.get("UDP Dst Port", 0) or 0))
    tcp_src = int(float(pkt.get("TCP Src Port", 0) or 0))
    tcp_dst = int(float(pkt.get("TCP Dst Port", 0) or 0))
    ports = {udp_src, udp_dst, tcp_src, tcp_dst}

    # Broadcast/multicast discovery and maintenance traffic on a quiet LAN.
    if dst_mac == "ff:ff:ff:ff:ff:ff" or dst_mac.startswith(("01:00:5e", "33:33")):
        return True
    if proto == "ARP":
        return True
    if proto == "UDP" and ports & {53, 67, 68, 123, 137, 138, 1900, 5353, 5355}:
        return True
    return False

def detect_tcp_scan_evidence(packet_features):
    """Detect clear current-window TCP scan evidence.

    This prevents LSTM temporal afterglow: after an attack ends, the model can keep
    a high probability for a few windows. We only confirm an anomaly when the
    current window still contains repeated SYN/RST activity on uncommon ports.
    """
    common_tcp = {20, 21, 22, 25, 53, 80, 110, 123, 143, 443, 445, 465, 587, 993, 995, 3389, 5050}
    port_counts = {}
    for pkt in packet_features:
        if not isinstance(pkt, dict):
            continue
        if str(pkt.get("Protocol", "")).upper() != "TCP":
            continue
        syn = int(pkt.get("SYN", 0) or 0)
        ack = int(pkt.get("ACK", 0) or 0)
        rst = int(pkt.get("RST", 0) or 0)
        src = int(float(pkt.get("TCP Src Port", 0) or 0))
        dst = int(float(pkt.get("TCP Dst Port", 0) or 0))
        candidate = 0
        if syn and not ack and dst and dst not in common_tcp:
            candidate = dst
        elif rst and src and src not in common_tcp:
            candidate = src
        if candidate:
            port_counts[candidate] = port_counts.get(candidate, 0) + 1
    suspicious_ports = {port for port, count in port_counts.items() if count >= 2}
    return {
        "has_evidence": bool(suspicious_ports),
        "suspicious_tcp_ports": sorted(suspicious_ports),
        "tcp_scan_port_counts": port_counts,
    }



def normalize_mac(mac):
    return str(mac or "").strip().lower()


def mac_kind(mac):
    mac = normalize_mac(mac)
    if not mac or len(mac.split(":")) != 6:
        return "invalid"
    if mac == "ff:ff:ff:ff:ff:ff":
        return "broadcast"
    try:
        first = int(mac.split(":")[0], 16)
    except ValueError:
        return "invalid"
    return "multicast" if first & 1 else "unicast"


def migrate_devices_schema(conn):
    """Keep devices table MAC-only: add missing columns for older PostgreSQL DBs."""
    c = conn.cursor()
    c.execute("""
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'devices'
    """)
    cols = {row["column_name"] for row in c.fetchall()}
    for column in ["status", "device_name", "first_seen", "last_seen", "note"]:
        if column not in cols:
            c.execute(f"ALTER TABLE devices ADD COLUMN {column} TEXT")


def register_device_events(packet_features):
    """Create/update MAC inventory and return anomaly-relevant device events."""
    now = datetime.now().isoformat()
    seen = []
    for pkt in packet_features:
        if not isinstance(pkt, dict):
            continue
        mac = normalize_mac(pkt.get("MAC Src"))
        if mac_kind(mac) == "unicast" and mac not in seen:
            seen.append(mac)

    if not seen:
        return []

    conn = get_db()
    c = conn.cursor()
    events = []
    for mac in seen:
        c.execute("SELECT * FROM devices WHERE mac=%s", (mac,))
        row = c.fetchone()
        if not row:
            c.execute(
                "INSERT INTO devices (mac, status, device_name, first_seen, last_seen, note) VALUES (%s,%s,%s,%s,%s,%s)",
                (mac, "unknown", "", now, now, "обнаружено автоматически"),
            )
            events.append({"mac": mac, "status": "unknown", "event": "new_mac", "message": "Новый MAC-адрес не найден в доверенном списке"})
        else:
            status = row["status"] or "unknown"
            c.execute("UPDATE devices SET last_seen=%s WHERE mac=%s", (now, mac))
            if status == "unknown":
                events.append({"mac": mac, "status": status, "event": "unknown_mac", "message": "MAC-адрес ожидает подтверждения оператора"})
            elif status == "retired":
                events.append({"mac": mac, "status": status, "event": "retired_mac_seen", "message": "В сети появился MAC, выведенный из эксплуатации"})
            elif status == "blocked":
                events.append({"mac": mac, "status": status, "event": "blocked_mac_seen", "message": "В сети появился заблокированный MAC"})
    conn.commit()
    conn.close()
    return events

# ====================== ИНИЦИАЛИЗАЦИЯ БАЗЫ ДАННЫХ ======================
def get_db():
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS devices
                 (mac TEXT PRIMARY KEY, status TEXT, device_name TEXT,
                  first_seen TEXT, last_seen TEXT, note TEXT)''')
    migrate_devices_schema(conn)
    c.execute('''CREATE TABLE IF NOT EXISTS results
                 (id SERIAL PRIMARY KEY, timestamp TEXT,
                  anomaly_prob DOUBLE PRECISION, is_anomaly INTEGER, message TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS incidents
                 (id SERIAL PRIMARY KEY, timestamp TEXT, data TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS packets
                 (id SERIAL PRIMARY KEY, incident_id INTEGER,
                  packet_index INTEGER, data TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS packet_reviews
                 (incident_id INTEGER, packet_index INTEGER, reviewed_at TEXT,
                  operator TEXT, model_label TEXT, operator_label TEXT,
                  final_label TEXT, overrode_model INTEGER, comment TEXT,
                  packet_data TEXT,
                  PRIMARY KEY (incident_id, packet_index))''')
    c.execute('''CREATE TABLE IF NOT EXISTS normal_feature_ranges
                 (feature TEXT PRIMARY KEY, normal_min DOUBLE PRECISION, normal_max DOUBLE PRECISION,
                  allowed_values TEXT, normal_note TEXT, recommendation TEXT,
                  updated_at TEXT)''')
    c.executemany(
        """INSERT INTO normal_feature_ranges
           (feature, normal_min, normal_max, allowed_values, normal_note, recommendation, updated_at)
           VALUES (%s,%s,%s,%s,%s,%s,%s)
           ON CONFLICT (feature) DO UPDATE SET
             normal_min = EXCLUDED.normal_min,
             normal_max = EXCLUDED.normal_max,
             allowed_values = EXCLUDED.allowed_values,
             normal_note = EXCLUDED.normal_note,
             recommendation = EXCLUDED.recommendation,
             updated_at = EXCLUDED.updated_at""",
        [(feature, normal_min, normal_max, allowed, note, rec, datetime.now().isoformat())
         for feature, normal_min, normal_max, allowed, note, rec in NORMAL_FEATURE_RANGES]
    )
    conn.commit()
    conn.close()


init_db()


def model_label_for_packet(incident_item, packet):
    """Model label stored before operator correction."""
    if not incident_item.get("is_anomaly"):
        return "BENIGN"
    if isinstance(packet, dict):
        for key in ("model_label", "predicted_label", "prediction", "Label", "label"):
            value = packet.get(key)
            if value not in (None, ""):
                return str(value)
    return "ANOMALY"


def append_operator_label_files(record):
    """Persist operator packet labels in retraining-friendly JSONL and CSV files."""
    with open(OPERATOR_LABELS_JSONL, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

    flat = {
        "incident_id": record["incident_id"],
        "packet_index": record["packet_index"],
        "reviewed_at": record["reviewed_at"],
        "operator": record["operator"],
        "model_label": record["model_label"],
        "operator_label": record["operator_label"],
        "final_label": record["final_label"],
        "overrode_model": record["overrode_model"],
        "comment": record.get("comment", ""),
    }
    write_header = not os.path.exists(OPERATOR_LABELS_CSV)
    with open(OPERATOR_LABELS_CSV, "a", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(flat.keys()))
        if write_header:
            writer.writeheader()
        writer.writerow(flat)


def get_packet_reviews(conn, incident_id):
    c = conn.cursor()
    c.execute("SELECT * FROM packet_reviews WHERE incident_id=%s", (incident_id,))
    return {
        str(row["packet_index"]): {
            "incident_id": row["incident_id"],
            "packet_index": row["packet_index"],
            "reviewed_at": row["reviewed_at"],
            "operator": row["operator"],
            "model_label": row["model_label"],
            "operator_label": row["operator_label"],
            "final_label": row["final_label"],
            "overrode_model": bool(row["overrode_model"]),
            "comment": row["comment"] or "",
        }
        for row in c.fetchall()
    }

def analyze_with_nn(data):
    global _anomaly_streak
    window = data.get("window_stats", {}) or {}
    packet_features = data.get("packet_features", []) or []
    total_packets = int(data.get("total_packets", len(packet_features)) or 0)
    filtered_packet_features = [p for p in packet_features if isinstance(p, dict) and not is_background_packet(p)]
    background_filtered = max(0, len(packet_features) - len(filtered_packet_features))

    if total_packets <= 0 or len(packet_features) <= 0:
        prob = 0.0
        is_anomaly = False
        message = "Нет пакетов — анализа нет, это не аномалия"
        details = {"engine": "no_packets", "packet_rows": 0}
        threshold = analyzer.threshold
        _anomaly_streak = 0
    elif not filtered_packet_features:
        prob = 0.0
        is_anomaly = False
        message = "Только служебный LAN-трафик — это норма"
        details = {
            "engine": "background_only",
            "packet_rows": 0,
            "background_filtered": background_filtered,
        }
        threshold = analyzer.threshold
        _anomaly_streak = 0
    else:
        lstm_result = analyzer.predict(filtered_packet_features, window)
        prob = float(lstm_result.probability)
        threshold = lstm_result.threshold
        raw_is_anomaly = bool(lstm_result.is_anomaly)
        evidence = detect_tcp_scan_evidence(filtered_packet_features)
        has_current_attack_evidence = evidence["has_evidence"]

        if raw_is_anomaly and has_current_attack_evidence:
            _anomaly_streak += 1
        else:
            _anomaly_streak = 0

        is_anomaly = raw_is_anomaly and has_current_attack_evidence and _anomaly_streak >= MIN_CONSECUTIVE_ANOMALY_WINDOWS
        if raw_is_anomaly and not has_current_attack_evidence:
            message = "LSTM даёт высокий риск, но текущих SYN/RST-признаков атаки нет — считаю остаточным подозрением"
        elif raw_is_anomaly and not is_anomaly:
            message = f"Подозрительное окно {_anomaly_streak}/{MIN_CONSECUTIVE_ANOMALY_WINDOWS}; ждём подтверждения"
        else:
            message = "Аномалия по LSTM подтверждена" if is_anomaly else "Норма по LSTM"
        details = lstm_result.details
        details["raw_is_anomaly"] = raw_is_anomaly
        details["current_attack_evidence"] = has_current_attack_evidence
        details["suspicious_tcp_ports"] = evidence["suspicious_tcp_ports"]
        details["tcp_scan_port_counts"] = evidence["tcp_scan_port_counts"]
        details["anomaly_streak"] = _anomaly_streak
        details["min_consecutive_windows"] = MIN_CONSECUTIVE_ANOMALY_WINDOWS
        details["background_filtered"] = background_filtered
        details["packet_rows_after_filter"] = len(filtered_packet_features)

    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT INTO results (timestamp, anomaly_prob, is_anomaly, message) VALUES (%s,%s,%s,%s)",
              (datetime.now().isoformat(), prob, int(is_anomaly), message))
    conn.commit()
    conn.close()

    return {
        "anomaly_prob": round(prob, 4),
        "is_anomaly": is_anomaly,
        "message": message,
        "threshold": threshold,
        "engine": details.get("engine", "unknown"),
        "details": details,
    }

# ====================== API ======================
@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Нет данных"}), 400

    window_stats = data.get("window_stats", {}) or {}
    packet_features = data.get("packet_features", []) or []

    result = analyze_with_nn(data)
    device_events = register_device_events(packet_features)
    if device_events:
        result.setdefault("details", {})["device_events"] = device_events
        result["is_anomaly"] = True
        priority = {"blocked": 3, "retired": 2, "unknown": 1}
        worst = max(device_events, key=lambda e: priority.get(e.get("status"), 0))
        result["message"] = worst.get("message") or "Обнаружено отклонение по MAC-адресу"

    conn = get_db()
    c = conn.cursor()
    c.execute(
        "INSERT INTO incidents (timestamp, data) VALUES (%s,%s) RETURNING id",
        (datetime.now().isoformat(), json.dumps({
            "window_stats": window_stats,
            "packet_count": data.get("total_packets", len(packet_features)),
            "filtered_packet_count": result.get("details", {}).get("packet_rows_after_filter", len(packet_features)),
            "background_filtered": result.get("details", {}).get("background_filtered", 0),
            "packet_features": packet_features[:250],
            "is_anomaly": result["is_anomaly"],
            "anomaly_prob": result["anomaly_prob"],
            "message": result.get("message", ""),
            "threshold": result.get("threshold"),
            "engine": result.get("engine"),
            "details": result.get("details", {}),
        }, ensure_ascii=False))
    )
    incident_id = c.fetchone()["id"]
    for idx, pkt in enumerate(packet_features[:500]):
        c.execute(
            "INSERT INTO packets (incident_id, packet_index, data) VALUES (%s,%s,%s)",
            (incident_id, idx, json.dumps(pkt, ensure_ascii=False)),
        )
    conn.commit()
    conn.close()

    return jsonify(result)

@app.route('/latest', methods=['GET'])
def get_latest():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT 1")
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({})

    item = json.loads(row["data"])
    conn.close()
    return jsonify({
        "id": row["id"],
        "time": row["timestamp"],
        "stats": item.get("window_stats", {}),
        "packet_count": item.get("packet_count", 0),
        "filtered_packet_count": item.get("filtered_packet_count", item.get("packet_count", 0)),
        "background_filtered": item.get("background_filtered", 0),
        "is_anomaly": item.get("is_anomaly", False),
        "prob": item.get("anomaly_prob", 0),
        "message": item.get("message", ""),
        "engine": item.get("engine", "unknown"),
        "threshold": item.get("threshold", 0),
    })

@app.route('/incidents', methods=['GET'])
def get_incidents():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT 50")
    rows = c.fetchall()

    data = []
    for row in rows:
        item = json.loads(row["data"])
        data.append({
            "id": row["id"],
            "time": row["timestamp"],
            "stats": item.get("window_stats", {}),
            "packets": item.get("packet_features", []),
            "packet_count": item.get("packet_count", 0),
            "filtered_packet_count": item.get("filtered_packet_count", item.get("packet_count", 0)),
            "background_filtered": item.get("background_filtered", 0),
            "is_anomaly": item.get("is_anomaly", False),
            "prob": item.get("anomaly_prob", 0),
            "message": item.get("message", ""),
            "engine": item.get("engine", "unknown"),
            "threshold": item.get("threshold", 0),
            "packet_reviews": get_packet_reviews(conn, row["id"]),
        })

    conn.close()
    return jsonify(data)

@app.route('/incident/<int:incident_id>', methods=['GET'])
def get_incident(incident_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM incidents WHERE id=%s", (incident_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "incident not found"}), 404
    item = json.loads(row["data"])
    c.execute("SELECT packet_index, data FROM packets WHERE incident_id=%s ORDER BY packet_index", (incident_id,))
    packets = [json.loads(r["data"]) for r in c.fetchall()]
    reviews = get_packet_reviews(conn, incident_id)
    conn.close()
    item["id"] = incident_id
    item["time"] = row["timestamp"]
    item["packet_features"] = packets or item.get("packet_features", [])
    item["packet_reviews"] = reviews
    return jsonify(item)

@app.route('/incident/<int:incident_id>/packet_review', methods=['POST'])
def review_incident_packet(incident_id):
    data = request.get_json() or {}
    try:
        packet_index = int(data.get("packet_index"))
    except (TypeError, ValueError):
        return jsonify({"error": "packet_index должен быть числом"}), 400

    operator_label = str(data.get("operator_label", "")).upper().strip()
    if operator_label not in {"ANOMALY", "BENIGN"}:
        return jsonify({"error": "operator_label должен быть ANOMALY или BENIGN"}), 400

    operator = str(data.get("operator") or "IDS operator")
    comment = str(data.get("comment") or "")

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM incidents WHERE id=%s", (incident_id,))
    incident_row = c.fetchone()
    if not incident_row:
        conn.close()
        return jsonify({"error": "incident not found"}), 404

    incident_item = json.loads(incident_row["data"])
    c.execute("SELECT data FROM packets WHERE incident_id=%s AND packet_index=%s", (incident_id, packet_index))
    packet_row = c.fetchone()
    packets = incident_item.get("packet_features", [])
    if packet_row:
        packet = json.loads(packet_row["data"])
    elif 0 <= packet_index < len(packets):
        packet = packets[packet_index]
    else:
        conn.close()
        return jsonify({"error": "packet not found"}), 404

    model_label = model_label_for_packet(incident_item, packet)
    final_label = operator_label
    reviewed_at = datetime.now().isoformat()
    record = {
        "schema_version": 1,
        "task": "lan_lstm_ids_packet_operator_label",
        "incident_id": incident_id,
        "packet_index": packet_index,
        "reviewed_at": reviewed_at,
        "operator": operator,
        "model_label": model_label,
        "operator_label": operator_label,
        "final_label": final_label,
        "overrode_model": str(model_label).upper() != final_label,
        "comment": comment,
        "packet": packet,
    }

    c.execute(
        """INSERT INTO packet_reviews
           (incident_id, packet_index, reviewed_at, operator, model_label, operator_label,
            final_label, overrode_model, comment, packet_data)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
           ON CONFLICT (incident_id, packet_index) DO UPDATE SET
             reviewed_at = EXCLUDED.reviewed_at,
             operator = EXCLUDED.operator,
             model_label = EXCLUDED.model_label,
             operator_label = EXCLUDED.operator_label,
             final_label = EXCLUDED.final_label,
             overrode_model = EXCLUDED.overrode_model,
             comment = EXCLUDED.comment,
             packet_data = EXCLUDED.packet_data""",
        (
            incident_id, packet_index, reviewed_at, operator, model_label, operator_label,
            final_label, int(record["overrode_model"]), comment, json.dumps(packet, ensure_ascii=False),
        ),
    )
    conn.commit()
    conn.close()
    append_operator_label_files(record)
    return jsonify({"status": "ok", "review": record})


@app.route('/normal_feature_ranges', methods=['GET'])
def normal_feature_ranges():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM normal_feature_ranges ORDER BY feature")
    rows = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify(rows)

@app.route('/model_status', methods=['GET'])
def model_status():
    return jsonify({
        "available": analyzer.available,
        "error": analyzer.error,
        "threshold": analyzer.threshold,
        "bundle": str(analyzer.bundle_dir),
        "features": analyzer.feature_columns,
        "capture_window_seconds": runtime_config.get("capture_window_seconds", DEFAULT_CAPTURE_WINDOW_SECONDS),
    })

@app.route('/config', methods=['GET', 'POST'])
def config_api():
    global runtime_config
    if request.method == 'GET':
        return jsonify(runtime_config)

    data = request.get_json() or {}
    try:
        seconds = int(data.get("capture_window_seconds", runtime_config.get("capture_window_seconds", DEFAULT_CAPTURE_WINDOW_SECONDS)))
    except (TypeError, ValueError):
        return jsonify({"error": "capture_window_seconds должен быть числом"}), 400

    if seconds < 5 or seconds > 300:
        return jsonify({"error": "Интервал должен быть от 5 до 300 секунд"}), 400

    runtime_config["capture_window_seconds"] = seconds
    save_runtime_config(runtime_config)
    logging.info(f"Интервал перехвата пользователей обновлён: {seconds} сек")
    return jsonify({"status": "ok", **runtime_config})

@app.route('/devices', methods=['GET'])
def list_devices():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT mac, status, device_name, first_seen, last_seen, note FROM devices ORDER BY status, mac")
    rows = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify(rows)


@app.route('/devices/<path:mac>', methods=['PATCH'])
def update_device(mac):
    mac = normalize_mac(mac)
    if mac_kind(mac) != "unicast":
        return jsonify({"error": "Некорректный MAC-адрес"}), 400
    data = request.get_json() or {}
    allowed_status = {"trusted", "unknown", "retired", "blocked"}
    status = data.get("status")
    device_name = data.get("device_name")
    note = data.get("note")
    now = datetime.now().isoformat()

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM devices WHERE mac=%s", (mac,))
    row = c.fetchone()
    if not row:
        c.execute(
            "INSERT INTO devices (mac, status, device_name, first_seen, last_seen, note) VALUES (%s,%s,%s,%s,%s,%s)",
            (mac, "unknown", "", now, now, ""),
        )
    if status is not None:
        status = str(status).lower().strip()
        if status not in allowed_status:
            conn.close()
            return jsonify({"error": "status должен быть trusted/unknown/retired/blocked"}), 400
        c.execute("UPDATE devices SET status=%s WHERE mac=%s", (status, mac))
    if device_name is not None:
        c.execute("UPDATE devices SET device_name=%s WHERE mac=%s", (str(device_name), mac))
    if note is not None:
        c.execute("UPDATE devices SET note=%s WHERE mac=%s", (str(note), mac))
    conn.commit()
    c.execute("SELECT mac, status, device_name, first_seen, last_seen, note FROM devices WHERE mac=%s", (mac,))
    result = dict(c.fetchone())
    conn.close()
    return jsonify(result)


@app.route('/confirm_device', methods=['POST'])
def confirm_device():
    data = request.get_json() or {}
    mac = normalize_mac(data.get("mac"))
    if mac_kind(mac) != "unicast":
        return jsonify({"error": "Некорректный MAC-адрес"}), 400
    now = datetime.now().isoformat()
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT mac FROM devices WHERE mac=%s", (mac,))
    if c.fetchone():
        c.execute("UPDATE devices SET status='trusted', last_seen=%s WHERE mac=%s", (now, mac))
    else:
        c.execute(
            "INSERT INTO devices (mac, status, device_name, first_seen, last_seen, note) VALUES (%s,%s,%s,%s,%s,%s)",
            (mac, "trusted", "", now, now, "добавлено оператором"),
        )
    conn.commit()
    conn.close()
    logging.info(f"Устройство {mac} подтверждено как разрешённое")
    return jsonify({"status": "ok", "message": f"Устройство {mac} добавлено в доверенные"})

# ====================== ОЧИСТКА ДАННЫХ ======================
def cleanup_old_data():
    while True:
        time.sleep(3600)
        conn = get_db()
        c = conn.cursor()
        c.execute("DELETE FROM results WHERE is_anomaly=0 AND timestamp::timestamp < NOW() - INTERVAL '24 hours'")
        conn.commit()
        conn.close()
        logging.info("Выполнена очистка старых нормальных данных")

# ====================== ЗАПУСК СЕРВЕРА ======================
if __name__ == "__main__":
    cleanup_thread = threading.Thread(target=cleanup_old_data, daemon=True)
    cleanup_thread.start()

    print("="*60)
    print("🚀 СЕРВЕР УСПЕШНО ЗАПУЩЕН")
    print(f"Адрес: http://127.0.0.1:{SERVER_PORT}")
    print(f"LSTM: {'OK' if analyzer.available else 'fallback'}")
    if not analyzer.available:
        print(f"Причина: {analyzer.error}")
    print("="*60)
    app.run(host=SERVER_HOST, port=SERVER_PORT, debug=False)
