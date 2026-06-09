import logging
import os
import socket
import time
from datetime import datetime

import requests
from scapy.all import ARP, ICMP, Ether, IP, TCP, UDP, conf, get_if_addr, get_if_hwaddr, get_if_list, sniff

SERVER_URL = os.environ.get("IDS_SERVER_URL", "http://127.0.0.1:5050/analyze")
SERVER_BASE = SERVER_URL.rsplit("/", 1)[0] if SERVER_URL.endswith("/analyze") else os.environ.get("IDS_SERVER_BASE", "http://127.0.0.1:5050")
DEFAULT_CAPTURE_WINDOW_SECONDS = int(os.environ.get("IDS_CAPTURE_WINDOW_SECONDS", "20"))
AGENT_ID = socket.gethostname()

logging.basicConfig(filename="agent.log", level=logging.INFO, format="%(asctime)s - %(message)s")


def choose_default_iface():
    preferred = []
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
        except Exception:
            ip = "0.0.0.0"
        if ip and ip != "0.0.0.0" and not ip.startswith("127.") and not ip.startswith("169.254."):
            preferred.append((iface, ip))
    for iface, _ in preferred:
        if iface.startswith("en0"):
            return iface
    for iface, _ in preferred:
        if not iface.startswith(("utun", "awdl", "llw", "lo")):
            return iface
    return conf.iface


def extract_features(packets):
    """Build packet rows + window stats compatible with the LSTM server."""
    try:
        local_mac = get_if_hwaddr(conf.iface).lower()
    except Exception:
        local_mac = None

    stats = {
        "Total Packets per Window": len(packets),
        "Incoming Packets per Window": 0,
        "Outgoing Packets per Window": 0,
        "TCP Protocol Count per Window": 0,
        "UDP Protocol Count per Window": 0,
        "ICMP Protocol Count per Window": 0,
        "ARP Protocol Count per Window": 0,
        "SYN Flags per Window": 0,
        "ACK Flags per Window": 0,
        "FIN Flags per Window": 0,
        "RST Flags per Window": 0,
    }
    rows = []

    for pkt in packets:
        if Ether not in pkt:
            continue
        src_mac = pkt[Ether].src.lower()
        dst_mac = pkt[Ether].dst.lower()
        direction = "out" if local_mac and src_mac == local_mac else "in"
        stats["Outgoing Packets per Window" if direction == "out" else "Incoming Packets per Window"] += 1
        row = {
            "Protocol": "OTHER",
            "IP Src": "",
            "IP Dst": "",
            "SYN": 0, "ACK": 0, "FIN": 0, "RST": 0, "PSH": 0, "URG": 0,
            "TCP Window Size": 0,
            "TCP Reserved": 0,
            "TCP Urgent Pointer": 0,
            "TCP Src Port": 0,
            "TCP Dst Port": 0,
            "UDP Src Port": 0,
            "UDP Dst Port": 0,
            "MAC Src": src_mac,
            "MAC Dst": dst_mac,
            "TTL": 0,
            "IP Packet Length": int(len(pkt)),
            "Direction": direction,
        }
        if IP in pkt:
            row["IP Src"] = pkt[IP].src
            row["IP Dst"] = pkt[IP].dst
            row["TTL"] = int(pkt[IP].ttl)
            row["IP Packet Length"] = int(pkt[IP].len or len(pkt))
        if TCP in pkt:
            row["Protocol"] = "TCP"
            stats["TCP Protocol Count per Window"] += 1
            flags = int(pkt[TCP].flags)
            row["SYN"] = 1 if flags & 0x02 else 0
            row["ACK"] = 1 if flags & 0x10 else 0
            row["FIN"] = 1 if flags & 0x01 else 0
            row["RST"] = 1 if flags & 0x04 else 0
            row["PSH"] = 1 if flags & 0x08 else 0
            row["URG"] = 1 if flags & 0x20 else 0
            row["TCP Window Size"] = int(pkt[TCP].window)
            row["TCP Reserved"] = int(getattr(pkt[TCP], "reserved", 0) or 0)
            row["TCP Urgent Pointer"] = int(pkt[TCP].urgptr)
            row["TCP Src Port"] = int(pkt[TCP].sport)
            row["TCP Dst Port"] = int(pkt[TCP].dport)
            stats["SYN Flags per Window"] += row["SYN"]
            stats["ACK Flags per Window"] += row["ACK"]
            stats["FIN Flags per Window"] += row["FIN"]
            stats["RST Flags per Window"] += row["RST"]
        elif UDP in pkt:
            row["Protocol"] = "UDP"
            stats["UDP Protocol Count per Window"] += 1
            row["UDP Src Port"] = int(pkt[UDP].sport)
            row["UDP Dst Port"] = int(pkt[UDP].dport)
        elif ICMP in pkt:
            row["Protocol"] = "ICMP"
            stats["ICMP Protocol Count per Window"] += 1
        elif ARP in pkt:
            row["Protocol"] = "ARP"
            stats["ARP Protocol Count per Window"] += 1
            row["IP Packet Length"] = 60
        rows.append(row)

    return rows, stats


def get_capture_window_seconds():
    try:
        r = requests.get(f"{SERVER_BASE}/config", timeout=5)
        r.raise_for_status()
        return max(5, min(300, int(r.json().get("capture_window_seconds", DEFAULT_CAPTURE_WINDOW_SECONDS))))
    except Exception as e:
        logging.warning(f"Не удалось получить config, использую {DEFAULT_CAPTURE_WINDOW_SECONDS} сек: {e}")
        return DEFAULT_CAPTURE_WINDOW_SECONDS


def run_agent():
    iface = os.environ.get("IDS_IFACE") or choose_default_iface()
    conf.iface = iface
    print(f"🚀 Консольный агент запущен | interface={iface}")
    logging.info(f"Агент запущен | interface={iface}")
    while True:
        try:
            capture_seconds = get_capture_window_seconds()
            print(f"📡 Сбор пакетов на {iface} ({capture_seconds} сек)...")
            packets = sniff(iface=iface, timeout=capture_seconds, store=True)
            if not packets:
                print("0 пакетов — это НЕ аномалия.")
                continue
            packet_features, window_stats = extract_features(packets)
            data = {
                "agent_id": AGENT_ID,
                "window_stats": window_stats,
                "packet_features": packet_features,
                "total_packets": len(packet_features),
                "captured_at": datetime.now().isoformat(),
                "capture_window_seconds": capture_seconds,
            }
            response = requests.post(SERVER_URL, json=data, timeout=30)
            response.raise_for_status()
            result = response.json()
            prob = result.get("anomaly_prob", 0)
            engine = result.get("engine", "unknown")
            status = "АНОМАЛИЯ" if result.get("is_anomaly") else "норма"
            print(f"📊 {len(packet_features)} пакетов | P={prob:.3f} | {status} | {engine}")
            logging.info(f"{len(packet_features)} packets | P={prob:.3f} | {status} | {engine}")
        except Exception as e:
            print(f"❌ Ошибка: {e}")
            logging.error(f"Ошибка: {e}")
        time.sleep(2)


if __name__ == "__main__":
    run_agent()
