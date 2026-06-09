import os
import re
import threading
import time
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, simpledialog

import requests
from scapy.all import ARP, ICMP, Ether, IP, TCP, UDP, get_if_addr, get_if_hwaddr, get_if_list, sniff, wrpcap

# ====================== НАСТРОЙКИ ======================
SERVER_BASE = os.environ.get("IDS_SERVER_BASE", "http://127.0.0.1:5050")
SERVER_URL = f"{SERVER_BASE}/analyze"
ADMIN_MONITOR_ONLY = os.environ.get("IDS_ADMIN_MONITOR_ONLY", "0") == "1"
DUMP_DIR = "dumps"
os.makedirs(DUMP_DIR, exist_ok=True)

BG = "#0b1020"
CARD = "#111827"
CARD_2 = "#182235"
SURFACE = "#070b14"
BORDER = "#263247"
TEXT = "#f3f4f6"
MUTED = "#9ca3af"
CYAN = "#38bdf8"
GREEN = "#10b981"
RED = "#f43f5e"
YELLOW = "#f59e0b"
BLUE = "#6366f1"
VIOLET = "#8b5cf6"


NORMAL_FEATURE_RECOMMENDATIONS = {
    "Protocol": {
        "normal": "TCP, UDP, ARP; ICMP допускается ограниченно",
        "recommendation": "Проверить источник нетипичного протокола, сопоставить его с разрешёнными сервисами и при необходимости ограничить правило firewall.",
    },
    "MAC Src": {
        "normal": "валидный unicast MAC известного устройства",
        "recommendation": "Сверить MAC с таблицей устройств/роутером. Если MAC неизвестен — изолировать устройство, проверить ARP-таблицу и исключить подмену MAC.",
    },
    "MAC Dst": {
        "normal": "unicast MAC; broadcast/multicast только для ARP/DHCP/mDNS/SSDP",
        "recommendation": "Если рассылка не служебная — найти источник широковещательного трафика, проверить настройки устройства и ограничить broadcast/multicast.",
    },
    "MAC device status": {
        "normal": "MAC должен иметь статус trusted в списке устройств",
        "recommendation": "Откройте Настройки → MAC-адреса. Если устройство легитимно — подтвердите его. Если старое устройство заменено — переведите старый MAC в retired. Если устройство чужое — заблокируйте.",
    },
    "TTL": {
        "normal": "32–255 для IP; 0 только для ARP/non-IP",
        "recommendation": "Проверить маршрут, VPN/туннели, петли маршрутизации и источник пакетов с нетипичным TTL.",
    },
    "IP Packet Length": {
        "normal": "20–1500 байт для обычного Ethernet MTU",
        "recommendation": "Проверить jumbo frames, фрагментацию, драйвер сетевой карты и источник нестандартных пакетов.",
    },
    "TCP Src Port": {
        "normal": "1–65535 для TCP; 0 только у не-TCP пакетов",
        "recommendation": "Проверить приложение-источник. Некорректный TCP-порт может указывать на crafted traffic или ошибку парсинга.",
    },
    "TCP Dst Port": {
        "normal": "1–65535; повторения по редким портам подозрительны",
        "recommendation": "При серии SYN/RST к редким портам проверить хост-источник, firewall, активность nmap/сканеров и заблокировать источник при подтверждении атаки.",
    },
    "UDP Src Port": {
        "normal": "1–65535 для UDP; 0 только у не-UDP пакетов",
        "recommendation": "Проверить приложение-источник и наличие аномального UDP-трафика.",
    },
    "UDP Dst Port": {
        "normal": "1–65535; служебные: 53, 67, 68, 123, 1900, 5353",
        "recommendation": "При всплеске UDP на неизвестные порты проверить DNS/DHCP/mDNS активность и правила firewall.",
    },
    "TCP Window Size": {
        "normal": "0–65535",
        "recommendation": "При частом нулевом или нетипичном TCP-окне проверить качество соединения, сбросы TCP и источник пакетов.",
    },
    "TCP Reserved": {
        "normal": "0",
        "recommendation": "Reserved-биты не должны быть установлены. Проверить пакет как crafted/scanner traffic; при подтверждении заблокировать источник.",
    },
    "TCP Urgent Pointer": {
        "normal": "0; ненулевой только при URG=1 и редких легитимных сценариях",
        "recommendation": "Проверить приложение и исключить crafted/сканирующий трафик. Если URG не используется в сети — пометить пакет как подозрительный.",
    },
    "Flag_Count": {
        "normal": "обычно 1–3 активных TCP-флага",
        "recommendation": "Проверить странные комбинации TCP-флагов, SYN/FIN/RST storm и firewall-журналы.",
    },
    "SYN/RST pattern": {
        "normal": "единичные SYN/RST допустимы; повторения по редким портам подозрительны",
        "recommendation": "Проверить источник серии SYN/RST, сравнить с разрешёнными сервисами, при атаке добавить правило firewall и сохранить pcap.",
    },
    "Direction": {
        "normal": "in/out относительно MAC локального интерфейса",
        "recommendation": "Если направление неверное — проверить выбранный интерфейс перехвата и MAC локального устройства.",
    },
}


def choose_default_iface():
    """Prefer the real LAN/Wi‑Fi interface, not lo0/utun/awdl."""
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
    return get_if_list()[0] if get_if_list() else ""


class Tooltip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip = None
        if text:
            widget.bind("<Enter>", self.show, add="+")
            widget.bind("<Leave>", self.hide, add="+")
            widget.bind("<ButtonPress>", self.hide, add="+")

    def show(self, _event=None):
        if self.tip or not self.text:
            return
        x = self.widget.winfo_rootx() + self.widget.winfo_width() // 2
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 8
        self.tip = tk.Toplevel(self.widget)
        self.tip.wm_overrideredirect(True)
        self.tip.wm_geometry(f"+{x}+{y}")
        label = tk.Label(
            self.tip, text=self.text, bg="#111827", fg=TEXT,
            font=("Arial", 10), padx=10, pady=6,
            highlightbackground=BORDER, highlightthickness=1
        )
        label.pack()

    def hide(self, _event=None):
        if self.tip:
            self.tip.destroy()
            self.tip = None


class RoundedButton(tk.Canvas):
    def __init__(self, parent, text, command=None, kind="secondary", width=None, height=38, tooltip=""):
        self.palette = {
            "primary": {"bg": BLUE, "fg": "#ffffff", "hover": "#4f46e5", "disabled": "#151d2c", "disabled_fg": MUTED},
            "secondary": {"bg": CARD_2, "fg": TEXT, "hover": "#24324a", "disabled": "#151d2c", "disabled_fg": MUTED},
            "danger": {"bg": "#3b1118", "fg": "#fecdd3", "hover": "#5f1722", "disabled": "#151d2c", "disabled_fg": MUTED},
            "disabled": {"bg": "#151d2c", "fg": MUTED, "hover": "#151d2c", "disabled": "#151d2c", "disabled_fg": MUTED},
        }
        self.kind = kind
        self.command = command
        self.text = text
        self.state = "normal"
        self.radius = 14
        self.height = height
        self.pad_x = 18
        self.font = ("Arial", 17, "bold") if width and width <= 56 else ("Arial", 10, "bold")
        estimated = max(120, len(text) * 8 + self.pad_x * 2) if width is None else width
        super().__init__(parent, width=estimated, height=height, bg=parent.cget("bg"), highlightthickness=0, bd=0, relief="flat", cursor="hand2")
        self._bg_item = None
        self._text_item = None
        self._draw(self.palette[self.kind]["bg"])
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<Button-1>", self._on_click)
        self.tooltip = Tooltip(self, tooltip)

    def _rounded_rect(self, x1, y1, x2, y2, r, **kwargs):
        points = [
            x1+r, y1, x2-r, y1, x2, y1, x2, y1+r,
            x2, y2-r, x2, y2, x2-r, y2, x1+r, y2,
            x1, y2, x1, y2-r, x1, y1+r, x1, y1,
        ]
        return self.create_polygon(points, smooth=True, **kwargs)

    def _draw(self, color):
        self.delete("all")
        w = int(self.cget("width"))
        h = int(self.cget("height"))
        pal = self.palette[self.kind]
        fg = pal["disabled_fg"] if self.state == "disabled" else pal["fg"]
        self._bg_item = self._rounded_rect(1, 1, w-1, h-1, self.radius, fill=color, outline="")
        self._text_item = self.create_text(w//2, h//2, text=self.text, fill=fg, font=self.font)

    def _current_color(self):
        pal = self.palette[self.kind]
        return pal["disabled"] if self.state == "disabled" else pal["bg"]

    def _on_enter(self, _event=None):
        if self.state != "disabled":
            self._draw(self.palette[self.kind]["hover"])

    def _on_leave(self, _event=None):
        self._draw(self._current_color())

    def _on_click(self, _event=None):
        if self.state != "disabled" and self.command:
            self.command()

    def config(self, cnf=None, **kw):
        if cnf:
            kw.update(cnf)
        if "state" in kw:
            self.state = kw.pop("state")
            self.configure(cursor="arrow" if self.state == "disabled" else "hand2")
            self._draw(self._current_color())
        if "text" in kw:
            self.text = kw.pop("text")
            self._draw(self._current_color())
        if kw:
            super().config(**kw)

    configure = config


class NetworkAgent:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Программа-агент — LSTM IDS")
        self.root.geometry("1240x820")
        self.root.minsize(1080, 720)
        self.root.configure(bg=BG)

        self.stop_event = threading.Event()
        self.last_packet_features = []
        self.incident_cache = {}
        self.sniff_thread = None
        self.last_seen_incident_id = None
        self.last_alerted_incident_id = None
        self.initial_latest_synced = False
        self.selected_incident_id = None
        self.event_buffer = []
        self.log_text = None
        self.log_window = None
        self.capture_window_var = tk.IntVar(value=20)
        self.model_status_text = None
        self.model_threshold = 0.82

        self.configure_style()
        self.create_gui()
        threading.Thread(target=self.auto_update, daemon=True).start()

    def configure_style(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("TFrame", background=BG)
        style.configure("Card.TFrame", background=CARD, relief="flat")
        style.configure("Panel.TFrame", background=CARD_2, relief="flat")
        style.configure("TLabel", background=BG, foreground=TEXT, font=("Arial", 11))
        style.configure("Muted.TLabel", background=BG, foreground=MUTED, font=("Arial", 10))
        style.configure("Card.TLabel", background=CARD, foreground=TEXT, font=("Arial", 11))
        style.configure("Section.TLabel", background=CARD, foreground=TEXT, font=("Arial", 13, "bold"))
        style.configure("Title.TLabel", background=BG, foreground=TEXT, font=("Arial", 26, "bold"))
        style.configure("Subtitle.TLabel", background=BG, foreground=MUTED, font=("Arial", 11))
        style.configure("Metric.TLabel", background=CARD, foreground=TEXT, font=("Arial", 18, "bold"))
        style.configure("TButton", font=("Arial", 10, "bold"), padding=(14, 8), borderwidth=0, focusthickness=0)
        style.configure("Primary.TButton", background=BLUE, foreground="#ffffff")
        style.configure("Secondary.TButton", background=CARD_2, foreground=TEXT)
        style.configure("Danger.TButton", background="#7f1d1d", foreground="#fecaca")
        style.configure("Disabled.TButton", background="#1e293b", foreground=MUTED)
        style.map("Primary.TButton", background=[("active", "#2563eb"), ("disabled", "#1e293b")])
        style.map("Secondary.TButton", background=[("active", "#334155"), ("disabled", "#1e293b")])
        style.map("Danger.TButton", background=[("active", "#991b1b"), ("disabled", "#1e293b")])
        style.configure("Treeview", background=SURFACE, foreground=TEXT, fieldbackground=SURFACE, rowheight=34, borderwidth=0, font=("Arial", 10))
        style.configure("Treeview.Heading", background=CARD_2, foreground=TEXT, font=("Arial", 10, "bold"), relief="flat")
        style.map("Treeview", background=[("selected", "#1d4ed8")], foreground=[("selected", "#ffffff")])
        style.configure("TRadiobutton", background=CARD, foreground=TEXT, font=("Arial", 10))
        style.configure("TCombobox", fieldbackground=SURFACE, background=SURFACE, foreground=TEXT, arrowcolor=TEXT)
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=CARD_2, foreground=TEXT, padding=(16, 8), font=("Arial", 10, "bold"))
        style.map("TNotebook.Tab", background=[("selected", CARD)], foreground=[("selected", CYAN)])

    def create_gui(self):
        shell = tk.Frame(self.root, bg=BG)
        shell.pack(fill="both", expand=True, padx=24, pady=22)

        header = tk.Frame(shell, bg=BG)
        header.pack(fill="x", pady=(0, 18))
        title_block = tk.Frame(header, bg=BG)
        title_block.pack(side="left", fill="x", expand=True)
        tk.Label(title_block, text="Программа-агент", bg=BG, fg=TEXT, font=("Arial", 30, "bold")).pack(anchor="w")

        header_actions = tk.Frame(header, bg=BG)
        header_actions.pack(side="right", pady=(6, 0))
        self.server_badge = tk.Label(header_actions, text="SERVER ONLINE", bg="#0f2f2a", fg=GREEN, font=("Arial", 10, "bold"), padx=16, pady=8)
        self.server_badge.pack(side="left", padx=(0, 12))
        self.refresh_btn = self.icon_button(header_actions, "↻", self.load_incidents, tooltip="Обновить историю")
        self.refresh_btn.pack(side="left", padx=(0, 8))
        self.last_packets_btn = self.icon_button(header_actions, "◷", self.show_last_packets, tooltip="Последние пакеты")
        self.last_packets_btn.pack(side="left", padx=(0, 8))
        self.log_btn = self.icon_button(header_actions, "▤", self.show_event_log, tooltip="Журнал")
        self.log_btn.pack(side="left", padx=(0, 8))
        self.start_btn = self.icon_button(header_actions, "▶", self.start_agent, kind="primary", tooltip="Запуск")
        self.start_btn.pack(side="left", padx=(0, 8))
        self.stop_btn = self.icon_button(header_actions, "■", self.stop_agent, kind="danger", tooltip="Остановка")
        self.stop_btn.config(state="disabled")
        self.stop_btn.pack(side="left", padx=(0, 8))
        self.settings_btn = self.icon_button(header_actions, "⚙", self.show_settings, kind="secondary", tooltip="Настройки")
        self.settings_btn.pack(side="left")

        top = tk.Frame(shell, bg=BG)
        top.pack(fill="x", pady=(0, 14))
        self.metric_prob = self.metric_card(top, "Вероятность", "—", CYAN)
        self.metric_status = self.metric_card(top, "Состояние", "Готов", GREEN)
        self.metric_packets = self.metric_card(top, "Пакеты", "0", BLUE)
        self.metric_engine = self.metric_card(top, "Модель", "LSTM", YELLOW)

        self.mode_var = tk.StringVar(value="detector")
        self.iface_combo = ttk.Combobox(shell, width=50)
        self.iface_combo["values"] = get_if_list()
        default_iface = choose_default_iface()
        if default_iface:
            self.iface_combo.set(default_iface)

        self.capture_hint = None
        self.settings_window = None
        self.load_config(silent=True)

        main = tk.Frame(shell, bg=BG)
        main.pack(fill="both", expand=True)

        left = tk.Frame(main, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        left.pack(fill="both", expand=True)
        tk.Label(left, text="Инциденты", bg=CARD, fg=TEXT, font=("Arial", 14, "bold")).pack(anchor="w", padx=16, pady=(16, 8))

        columns = ("review", "id", "time", "packets", "prob", "engine", "status")
        self.tree = ttk.Treeview(left, columns=columns, show="headings", height=15)
        headings = {"review": "✓", "id": "ID", "time": "Время", "packets": "Пакеты", "prob": "P", "engine": "Модель", "status": "Статус"}
        widths = {"review": 54, "id": 50, "time": 180, "packets": 80, "prob": 70, "engine": 90, "status": 150}
        for col in columns:
            self.tree.heading(col, text=headings[col])
            self.tree.column(col, width=widths[col], anchor="center")
        self.tree.tag_configure("anomaly", foreground=RED)
        self.tree.tag_configure("normal", foreground=GREEN)
        self.tree.tag_configure("processed", foreground=YELLOW)
        self.tree.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self.tree.bind("<<TreeviewSelect>>", self.on_incident_selected)
        self.tree.bind("<Double-1>", self.show_incident_details)

        self.status = tk.Label(shell, text="Готово. Ожидаю данные от пользовательских агентов", bg=BG, fg=MUTED, font=("Arial", 11))
        self.status.pack(fill="x", pady=(14, 0))
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def action_button(self, parent, text, command, kind="secondary", tooltip=""):
        return RoundedButton(parent, text=text, command=command, kind=kind, tooltip=tooltip)

    def icon_button(self, parent, text, command, kind="secondary", tooltip=""):
        return RoundedButton(parent, text=text, command=command, kind=kind, width=50, height=46, tooltip=tooltip)

    def metric_card(self, parent, title, value, color):
        frame = tk.Frame(parent, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        frame.pack(side="left", fill="x", expand=True, padx=7)
        accent = tk.Frame(frame, bg=color, width=4)
        accent.pack(side="left", fill="y")
        body = tk.Frame(frame, bg=CARD)
        body.pack(side="left", fill="both", expand=True)
        tk.Label(body, text=title.upper(), bg=CARD, fg=MUTED, font=("Arial", 9, "bold")).pack(anchor="w", padx=16, pady=(14, 0))
        label = tk.Label(body, text=value, bg=CARD, fg=color, font=("Arial", 24, "bold"))
        label.pack(anchor="w", padx=16, pady=(2, 14))
        return label

    def show_settings(self):
        if self.settings_window and self.settings_window.winfo_exists():
            self.settings_window.lift()
            return
        self.settings_window = tk.Toplevel(self.root)
        self.settings_window.title("Настройки")
        self.settings_window.geometry("980x760")
        self.settings_window.configure(bg=BG)
        panel = tk.Frame(self.settings_window, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        panel.pack(fill="both", expand=True, padx=18, pady=18)
        tk.Label(panel, text="Настройки", bg=CARD, fg=TEXT, font=("Arial", 18, "bold")).pack(anchor="w", padx=18, pady=(18, 4))
        tk.Label(panel, text="Параметры пользовательских агентов, состояние LSTM-модели и управление MAC-адресами.", bg=CARD, fg=MUTED, font=("Arial", 11), wraplength=860, justify="left").pack(anchor="w", padx=18, pady=(0, 18))

        row = tk.Frame(panel, bg=CARD)
        row.pack(fill="x", padx=18, pady=(0, 14))
        tk.Label(row, text="Окно перехвата", bg=CARD, fg=TEXT, font=("Arial", 12, "bold")).pack(side="left")
        self.capture_spin = tk.Spinbox(row, from_=5, to=300, increment=5, width=7, textvariable=self.capture_window_var, bg=SURFACE, fg=TEXT, insertbackground=TEXT, buttonbackground=CARD_2, relief="flat", highlightthickness=1, highlightbackground=BORDER, highlightcolor=CYAN, font=("Arial", 12))
        self.capture_spin.pack(side="left", padx=(18, 6))
        tk.Label(row, text="сек", bg=CARD, fg=MUTED, font=("Arial", 11)).pack(side="left")

        footer = tk.Frame(panel, bg=CARD)
        footer.pack(fill="x", padx=18, pady=(4, 18))
        self.capture_hint = tk.Label(footer, text="Клиенты применят значение перед следующим окном", bg=CARD, fg=MUTED, font=("Arial", 10))
        self.capture_hint.pack(side="left", fill="x", expand=True)
        self.action_button(footer, "Сохранить", self.save_capture_window, kind="primary").pack(side="right")

        model_panel = tk.Frame(panel, bg=SURFACE, highlightbackground=BORDER, highlightthickness=1)
        model_panel.pack(fill="both", expand=True, padx=18, pady=(0, 18))
        model_header = tk.Frame(model_panel, bg=SURFACE)
        model_header.pack(fill="x", padx=14, pady=(12, 6))
        tk.Label(model_header, text="Статус модели", bg=SURFACE, fg=TEXT, font=("Arial", 13, "bold")).pack(side="left")
        self.action_button(model_header, "Обновить", self.refresh_model_status).pack(side="right")
        self.model_status_text = tk.Label(model_panel, text="Загрузка...", bg=SURFACE, fg=MUTED, font=("Menlo", 10), justify="left", anchor="nw")
        self.model_status_text.pack(fill="x", padx=14, pady=(0, 12))

        devices_panel = tk.Frame(panel, bg=SURFACE, highlightbackground=BORDER, highlightthickness=1)
        devices_panel.pack(fill="both", expand=True, padx=18, pady=(0, 18))
        devices_header = tk.Frame(devices_panel, bg=SURFACE)
        devices_header.pack(fill="x", padx=14, pady=(12, 6))
        tk.Label(devices_header, text="MAC-адреса устройств", bg=SURFACE, fg=TEXT, font=("Arial", 13, "bold")).pack(side="left")
        self.action_button(devices_header, "Обновить", self.refresh_devices).pack(side="right", padx=(8, 0))
        self.action_button(devices_header, "Добавить MAC", self.add_device_dialog, kind="primary").pack(side="right")

        device_columns = ("mac", "status", "name", "first_seen", "last_seen", "note")
        self.devices_tree = ttk.Treeview(devices_panel, columns=device_columns, show="headings", height=7)
        device_headings = {"mac": "MAC", "status": "Статус", "name": "Имя", "first_seen": "Первое появление", "last_seen": "Последнее появление", "note": "Комментарий"}
        device_widths = {"mac": 150, "status": 90, "name": 140, "first_seen": 150, "last_seen": 150, "note": 260}
        for col in device_columns:
            self.devices_tree.heading(col, text=device_headings[col])
            self.devices_tree.column(col, width=device_widths[col], anchor="w")
        self.devices_tree.pack(fill="both", expand=True, padx=14, pady=(0, 8))

        device_actions = tk.Frame(devices_panel, bg=SURFACE)
        device_actions.pack(fill="x", padx=14, pady=(0, 12))
        self.action_button(device_actions, "Подтвердить", lambda: self.set_selected_device_status("trusted"), kind="primary", tooltip="unknown → trusted").pack(side="left", padx=(0, 8))
        self.action_button(device_actions, "Вывести из эксплуатации", lambda: self.set_selected_device_status("retired"), tooltip="trusted/unknown → retired").pack(side="left", padx=(0, 8))
        self.action_button(device_actions, "Заблокировать", lambda: self.set_selected_device_status("blocked"), kind="danger", tooltip="запретить устройство").pack(side="left", padx=(0, 8))
        self.action_button(device_actions, "Снова неизвестный", lambda: self.set_selected_device_status("unknown"), tooltip="вернуть на проверку").pack(side="left", padx=(0, 8))
        self.action_button(device_actions, "Имя/комментарий", self.edit_selected_device).pack(side="left")

        self.load_config(silent=True)
        self.refresh_model_status()
        self.refresh_devices()
        self.settings_window.protocol("WM_DELETE_WINDOW", self.close_settings)

    def refresh_model_status(self):
        try:
            r = requests.get(f"{SERVER_BASE}/model_status", timeout=5)
            r.raise_for_status()
            data = r.json()
            self.model_threshold = float(data.get('threshold', self.model_threshold) or self.model_threshold)
            text = (
                f"LSTM доступна: {data.get('available')}\n"
                f"Признаков: {len(data.get('features', []))}"
            )
            if data.get("error"):
                text += f"\nОшибка: {data.get('error')}"
            if hasattr(self, "model_status_text") and self.model_status_text.winfo_exists():
                self.model_status_text.config(text=text, fg=TEXT)
        except Exception as e:
            if hasattr(self, "model_status_text") and self.model_status_text.winfo_exists():
                self.model_status_text.config(text=f"Сервер недоступен: {e}", fg=RED)

    def refresh_devices(self):
        if not hasattr(self, "devices_tree") or not self.devices_tree.winfo_exists():
            return
        try:
            r = requests.get(f"{SERVER_BASE}/devices", timeout=5)
            r.raise_for_status()
            data = r.json()
            for row in self.devices_tree.get_children():
                self.devices_tree.delete(row)
            for item in data:
                mac = item.get("mac", "")
                self.devices_tree.insert("", "end", iid=mac, values=(
                    mac,
                    item.get("status", ""),
                    item.get("device_name", ""),
                    str(item.get("first_seen", ""))[:19].replace("T", " "),
                    str(item.get("last_seen", ""))[:19].replace("T", " "),
                    item.get("note", ""),
                ))
        except Exception as e:
            self.log(f"Не удалось загрузить MAC-адреса: {e}", "error")

    def selected_device_mac(self):
        if not hasattr(self, "devices_tree"):
            return None
        sel = self.devices_tree.selection()
        if not sel:
            messagebox.showinfo("MAC-адреса", "Выберите устройство в таблице.")
            return None
        return sel[0]

    def patch_device(self, mac, payload):
        r = requests.patch(f"{SERVER_BASE}/devices/{mac}", json=payload, timeout=5)
        r.raise_for_status()
        self.refresh_devices()
        return r.json()

    def set_selected_device_status(self, status):
        mac = self.selected_device_mac()
        if not mac:
            return
        labels = {"trusted": "доверенные", "retired": "выведенные из эксплуатации", "blocked": "заблокированные", "unknown": "неизвестные"}
        if status in {"retired", "blocked"}:
            if not messagebox.askyesno("MAC-адреса", f"Перевести {mac} в статус «{labels[status]}»?"):
                return
        try:
            self.patch_device(mac, {"status": status})
            self.log(f"MAC {mac}: статус → {status}", "success")
        except Exception as e:
            messagebox.showerror("MAC-адреса", f"Не удалось изменить статус: {e}")

    def add_device_dialog(self):
        dialog = tk.Toplevel(self.settings_window or self.root)
        dialog.title("Добавить MAC-адрес")
        dialog.geometry("520x390")
        dialog.configure(bg=BG)
        dialog.transient(self.settings_window or self.root)
        dialog.grab_set()
        dialog.resizable(False, False)

        panel = tk.Frame(dialog, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        panel.pack(fill="both", expand=True, padx=18, pady=18)
        tk.Label(panel, text="Добавить MAC-адрес", bg=CARD, fg=TEXT, font=("Arial", 17, "bold")).pack(anchor="w", padx=18, pady=(18, 4))
        tk.Label(panel, text="Заполните данные устройства в одном окне.", bg=CARD, fg=MUTED, font=("Arial", 10)).pack(anchor="w", padx=18, pady=(0, 16))

        form = tk.Frame(panel, bg=CARD)
        form.pack(fill="x", padx=18)
        form.columnconfigure(1, weight=1)

        def field(label, row, placeholder=""):
            tk.Label(form, text=label, bg=CARD, fg=TEXT, font=("Arial", 11, "bold")).grid(row=row, column=0, sticky="w", pady=(0, 10))
            entry = tk.Entry(form, bg=SURFACE, fg=TEXT, insertbackground=TEXT, relief="flat", highlightthickness=1, highlightbackground=BORDER, highlightcolor=CYAN, font=("Arial", 11))
            entry.grid(row=row, column=1, sticky="ew", padx=(14, 0), pady=(0, 10), ipady=6)
            if placeholder:
                entry.insert(0, placeholder)
                entry.selection_range(0, tk.END)
            return entry

        mac_entry = field("MAC-адрес", 0, "aa:bb:cc:dd:ee:ff")
        name_entry = field("Имя устройства", 1)

        tk.Label(form, text="Статус", bg=CARD, fg=TEXT, font=("Arial", 11, "bold")).grid(row=2, column=0, sticky="w", pady=(0, 10))
        status_var = tk.StringVar(value="trusted")
        status_box = ttk.Combobox(form, textvariable=status_var, values=("trusted", "unknown", "blocked", "retired"), state="readonly", font=("Arial", 11))
        status_box.grid(row=2, column=1, sticky="ew", padx=(14, 0), pady=(0, 10), ipady=3)

        tk.Label(form, text="Комментарий", bg=CARD, fg=TEXT, font=("Arial", 11, "bold")).grid(row=3, column=0, sticky="nw", pady=(0, 10))
        note_text = tk.Text(form, height=4, bg=SURFACE, fg=TEXT, insertbackground=TEXT, relief="flat", highlightthickness=1, highlightbackground=BORDER, highlightcolor=CYAN, font=("Arial", 11), wrap="word")
        note_text.grid(row=3, column=1, sticky="ew", padx=(14, 0), pady=(0, 10))

        error_label = tk.Label(panel, text="", bg=CARD, fg=RED, font=("Arial", 10), wraplength=460, justify="left")
        error_label.pack(anchor="w", padx=18, pady=(2, 0))

        def normalize_mac(value):
            value = value.strip().lower().replace("-", ":")
            if re.fullmatch(r"[0-9a-f]{12}", value):
                value = ":".join(value[i:i + 2] for i in range(0, 12, 2))
            return value

        def save():
            mac = normalize_mac(mac_entry.get())
            if not re.fullmatch(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", mac):
                error_label.config(text="Введите корректный MAC-адрес, например aa:bb:cc:dd:ee:ff")
                mac_entry.focus_set()
                return
            payload = {
                "status": status_var.get(),
                "device_name": name_entry.get().strip(),
                "note": note_text.get("1.0", "end").strip(),
            }
            try:
                self.patch_device(mac, payload)
                self.log(f"MAC {mac}: добавлен/обновлен, статус → {payload['status']}", "success")
                dialog.destroy()
            except Exception as e:
                error_label.config(text=f"Не удалось добавить устройство: {e}")

        buttons = tk.Frame(panel, bg=CARD)
        buttons.pack(fill="x", padx=18, pady=(12, 16))
        self.action_button(buttons, "Отмена", dialog.destroy).pack(side="right", padx=(8, 0))
        self.action_button(buttons, "Сохранить", save, kind="primary").pack(side="right")
        dialog.bind("<Return>", lambda _event: save())
        dialog.bind("<Escape>", lambda _event: dialog.destroy())
        mac_entry.focus_set()

    def edit_selected_device(self):
        mac = self.selected_device_mac()
        if not mac:
            return
        values = self.devices_tree.item(mac).get("values", [])
        old_name = values[2] if len(values) > 2 else ""
        old_note = values[5] if len(values) > 5 else ""
        name = simpledialog.askstring("Имя устройства", "Имя устройства:", initialvalue=old_name)
        if name is None:
            return
        note = simpledialog.askstring("Комментарий", "Комментарий:", initialvalue=old_note)
        if note is None:
            return
        try:
            self.patch_device(mac, {"device_name": name, "note": note})
            self.log(f"MAC {mac}: обновлены имя/комментарий", "success")
        except Exception as e:
            messagebox.showerror("MAC-адреса", f"Не удалось обновить устройство: {e}")

    def close_settings(self):
        if self.settings_window and self.settings_window.winfo_exists():
            self.settings_window.destroy()
        self.settings_window = None
        self.capture_hint = None

    def log(self, text, level="info"):
        colors = {"info": CYAN, "success": GREEN, "warning": YELLOW, "error": RED}
        timestamp = datetime.now().strftime("%H:%M:%S")
        entry = (timestamp, text, level)
        self.event_buffer.append(entry)
        self.event_buffer = self.event_buffer[-500:]
        if hasattr(self, "status"):
            self.status.config(text=text, fg=colors.get(level, MUTED))
        if self.log_text and self.log_text.winfo_exists():
            self.log_text.insert("end", f"[{timestamp}] {text}\n", level)
            self.log_text.see("end")
            self.log_text.tag_config(level, foreground=colors.get(level, TEXT))

    def show_event_log(self):
        if self.log_window and self.log_window.winfo_exists():
            self.log_window.lift()
            return
        self.log_window = tk.Toplevel(self.root)
        self.log_window.title("Журнал событий")
        self.log_window.geometry("760x460")
        self.log_window.configure(bg=BG)
        panel = tk.Frame(self.log_window, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        panel.pack(fill="both", expand=True, padx=18, pady=18)
        header = tk.Frame(panel, bg=CARD)
        header.pack(fill="x", padx=16, pady=(14, 8))
        tk.Label(header, text="Журнал событий", bg=CARD, fg=TEXT, font=("Arial", 16, "bold")).pack(side="left")
        self.action_button(header, "Очистить", self.clear_event_log).pack(side="right")
        self.log_text = scrolledtext.ScrolledText(panel, height=22, bg=SURFACE, fg=TEXT, insertbackground=TEXT, relief="flat", borderwidth=0, font=("Menlo", 10))
        self.log_text.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        for lvl, color in {"info": CYAN, "success": GREEN, "warning": YELLOW, "error": RED}.items():
            self.log_text.tag_config(lvl, foreground=color)
        for timestamp, text, level in self.event_buffer:
            self.log_text.insert("end", f"[{timestamp}] {text}\n", level)
        self.log_text.see("end")
        self.log_window.protocol("WM_DELETE_WINDOW", self.close_event_log)

    def clear_event_log(self):
        self.event_buffer.clear()
        if self.log_text and self.log_text.winfo_exists():
            self.log_text.delete("1.0", "end")
        self.status.config(text="Журнал очищен", fg=MUTED)

    def close_event_log(self):
        if self.log_window and self.log_window.winfo_exists():
            self.log_window.destroy()
        self.log_window = None
        self.log_text = None

    def extract_features(self, packets):
        local_mac = None
        try:
            local_mac = get_if_hwaddr(self.iface_combo.get()).lower()
        except Exception:
            pass

        packet_list = []
        window_stats = {
            "Total Packets per Window": len(packets),
            "TCP Protocol Count per Window": 0,
            "UDP Protocol Count per Window": 0,
            "ICMP Protocol Count per Window": 0,
            "ARP Protocol Count per Window": 0,
            "SYN Flags per Window": 0,
            "ACK Flags per Window": 0,
            "FIN Flags per Window": 0,
            "RST Flags per Window": 0,
            "Incoming Packets per Window": 0,
            "Outgoing Packets per Window": 0,
        }

        for pkt in packets:
            if Ether not in pkt:
                continue
            src_mac = pkt[Ether].src.lower()
            dst_mac = pkt[Ether].dst.lower()
            direction = "out" if local_mac and src_mac == local_mac else "in"
            if direction == "out":
                window_stats["Outgoing Packets per Window"] += 1
            else:
                window_stats["Incoming Packets per Window"] += 1

            feat = {
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
                feat["IP Src"] = pkt[IP].src
                feat["IP Dst"] = pkt[IP].dst
                feat["TTL"] = int(pkt[IP].ttl)
                feat["IP Packet Length"] = int(pkt[IP].len or len(pkt))

            if TCP in pkt:
                feat["Protocol"] = "TCP"
                window_stats["TCP Protocol Count per Window"] += 1
                flags = int(pkt[TCP].flags)
                feat["SYN"] = 1 if flags & 0x02 else 0
                feat["ACK"] = 1 if flags & 0x10 else 0
                feat["FIN"] = 1 if flags & 0x01 else 0
                feat["RST"] = 1 if flags & 0x04 else 0
                feat["PSH"] = 1 if flags & 0x08 else 0
                feat["URG"] = 1 if flags & 0x20 else 0
                feat["TCP Window Size"] = int(pkt[TCP].window)
                feat["TCP Reserved"] = int(getattr(pkt[TCP], "reserved", 0) or 0)
                feat["TCP Urgent Pointer"] = int(pkt[TCP].urgptr)
                feat["TCP Src Port"] = int(pkt[TCP].sport)
                feat["TCP Dst Port"] = int(pkt[TCP].dport)
                window_stats["SYN Flags per Window"] += feat["SYN"]
                window_stats["ACK Flags per Window"] += feat["ACK"]
                window_stats["FIN Flags per Window"] += feat["FIN"]
                window_stats["RST Flags per Window"] += feat["RST"]
            elif UDP in pkt:
                feat["Protocol"] = "UDP"
                window_stats["UDP Protocol Count per Window"] += 1
                feat["UDP Src Port"] = int(pkt[UDP].sport)
                feat["UDP Dst Port"] = int(pkt[UDP].dport)
            elif ICMP in pkt:
                feat["Protocol"] = "ICMP"
                window_stats["ICMP Protocol Count per Window"] += 1
            elif ARP in pkt:
                feat["Protocol"] = "ARP"
                window_stats["ARP Protocol Count per Window"] += 1
                feat["TTL"] = 0
                feat["IP Packet Length"] = 60

            packet_list.append(feat)

        return packet_list, window_stats

    def sniff_batch(self):
        try:
            iface = self.iface_combo.get()
            self.log(f"Перехват пакетов на {iface} (20 сек)...", "info")
            packets = sniff(iface=iface, timeout=20, store=True)
            if not packets:
                self.update_metrics(0.0, False, 0, "no_packets")
                self.log("0 пакетов — это НЕ аномалия. Скорее всего выбран не тот интерфейс или сейчас нет трафика.", "warning")
                return

            packet_features, window_stats = self.extract_features(packets)
            self.last_packet_features = packet_features
            data = {
                "packet_features": packet_features,
                "window_stats": window_stats,
                "total_packets": len(packet_features),
                "mode": self.mode_var.get(),
            }
            self.log(f"Отправка {len(packet_features)} пакетов в LSTM...", "info")
            response = requests.post(SERVER_URL, json=data, timeout=30)
            response.raise_for_status()
            result = response.json()
            prob = float(result.get("anomaly_prob", 0))
            is_anomaly = bool(result.get("is_anomaly", False))
            engine = result.get("engine", "unknown")

            self.update_metrics(prob, is_anomaly, len(packet_features), engine)
            status_text = "АНОМАЛИЯ" if is_anomaly else "Норма"
            message = result.get("message", "")
            self.log(f"{status_text}: P={prob:.3f}, engine={engine}; {message}", "warning" if is_anomaly else "success")

            if is_anomaly:
                filename = os.path.join(DUMP_DIR, f"anomaly_{int(time.time())}.pcap")
                wrpcap(filename, packets)
                self.log(f"Дамп сохранён: {filename}", "error")
                self.show_anomalous_packets(packet_features, window_stats, prob)

            self.load_incidents(silent=True)
        except Exception as e:
            self.log(f"Ошибка: {e}", "error")

    def update_metrics(self, prob, is_anomaly, packets, engine):
        model_alert = prob >= self.model_threshold
        self.metric_prob.config(text=f"{prob:.3f}", fg=RED if model_alert else GREEN)
        self.metric_status.config(text="Аномалия" if is_anomaly else "Норма", fg=RED if is_anomaly else GREEN)
        self.metric_packets.config(text=str(packets), fg=BLUE)
        self.metric_engine.config(text=str(engine), fg=YELLOW if engine != "lstm" else CYAN)
        self.status.config(text=f"Последний анализ: P={prob:.3f}", fg=RED if is_anomaly else GREEN)

    def update_metrics_from_incident(self, item, status_text=None):
        prob = float(item.get("prob", 0) or 0)
        threshold = float(item.get("threshold", self.model_threshold) or self.model_threshold)
        model_alert = prob >= threshold
        is_anomaly = bool(item.get("is_anomaly"))
        processed, _, _ = self.incident_review_state(item)
        status_text = status_text or ("Обработан" if processed else ("Аномалия" if is_anomaly else "Норма"))
        status_color = YELLOW if status_text == "Обработан" else (RED if is_anomaly else GREEN)
        packet_count = item.get("packet_count", 0)
        filtered_count = item.get("filtered_packet_count", packet_count)
        packet_text = f"{packet_count} / {filtered_count}" if filtered_count != packet_count else str(packet_count)
        self.metric_prob.config(text=f"{prob:.3f}", fg=RED if model_alert else GREEN)
        self.metric_status.config(text=status_text, fg=status_color)
        self.metric_packets.config(text=packet_text, fg=BLUE)
        engine = item.get("engine", "") or "unknown"
        self.metric_engine.config(text=str(engine), fg=YELLOW if engine != "lstm" else CYAN)
        incident_id = item.get("id", "—")
        self.status.config(text=f"Выбран инцидент #{incident_id}: P={prob:.3f}", fg=status_color)

    def on_incident_selected(self, _event=None):
        selection = self.tree.selection()
        if not selection:
            self.selected_incident_id = None
            return
        values = self.tree.item(selection[0], "values")
        if len(values) < 7:
            return
        incident_id = str(values[1])
        item = self.incident_cache.get(incident_id)
        if not item:
            return
        self.selected_incident_id = incident_id
        self.update_metrics_from_incident(item, status_text=str(values[6]))

    def agent_loop(self):
        while not self.stop_event.is_set():
            self.sniff_batch()
            time.sleep(2)

    def auto_update(self):
        while True:
            try:
                r = requests.get(f"{SERVER_BASE}/latest", timeout=2)
                data = r.json()
                if data and not self.initial_latest_synced:
                    # При запуске приложения /latest может вернуть старый инцидент из БД.
                    # Считаем его уже просмотренным, чтобы не показывать ложную тревогу
                    # и не переводить статус главного экрана в «Аномалия» до реальной новой активности.
                    self.last_seen_incident_id = data.get("id")
                    self.last_alerted_incident_id = data.get("id")
                    self.initial_latest_synced = True
                    self.load_incidents(silent=True)
                    self.status.config(text="Готово. Старые инциденты загружены без тревоги", fg=MUTED)
                    time.sleep(3)
                    continue
                if not data and not self.initial_latest_synced:
                    self.initial_latest_synced = True
                if data and data.get("id") != self.last_seen_incident_id:
                    self.last_seen_incident_id = data.get("id")
                    is_anomaly = bool(data.get("is_anomaly"))
                    if not self.tree.selection():
                        self.update_metrics(float(data.get("prob", 0)), is_anomaly, int(data.get("packet_count", 0)), data.get("engine", "unknown"))
                    self.load_incidents(silent=True)
                    if is_anomaly:
                        self.root.after(0, lambda d=data: self.alert_anomaly(d))
            except Exception:
                pass
            time.sleep(3)

    def alert_anomaly(self, data):
        incident_id = data.get("id")
        if incident_id == self.last_alerted_incident_id:
            return
        self.last_alerted_incident_id = incident_id
        prob = float(data.get("prob", 0))
        packets = int(data.get("packet_count", 0))
        self.root.bell()
        messagebox.showwarning(
            "Обнаружена аномалия",
            f"Обнаружена аномалия у пользовательского агента.\n\n"
            f"Инцидент: #{incident_id}\n"
            f"Вероятность: {prob:.3f}\n"
            f"Пакетов в окне: {packets}\n"
            f"Модель: {data.get('engine', 'unknown')}"
        )

    def load_config(self, silent=False):
        try:
            r = requests.get(f"{SERVER_BASE}/config", timeout=5)
            r.raise_for_status()
            seconds = int(r.json().get("capture_window_seconds", 20))
            self.capture_window_var.set(seconds)
            if self.capture_hint and self.capture_hint.winfo_exists():
                self.capture_hint.config(text=f"Активно: {seconds} сек. Клиенты применят перед следующим окном", fg=MUTED)
        except Exception as e:
            if not silent:
                self.log(f"Не удалось загрузить настройки: {e}", "error")

    def save_capture_window(self):
        try:
            seconds = int(self.capture_window_var.get())
            r = requests.post(f"{SERVER_BASE}/config", json={"capture_window_seconds": seconds}, timeout=5)
            r.raise_for_status()
            saved = int(r.json().get("capture_window_seconds", seconds))
            self.capture_window_var.set(saved)
            if self.capture_hint and self.capture_hint.winfo_exists():
                self.capture_hint.config(text=f"Сохранено: {saved} сек", fg=GREEN)
            self.log(f"Окно перехвата пользователей: {saved} сек", "success")
        except Exception as e:
            if self.capture_hint and self.capture_hint.winfo_exists():
                self.capture_hint.config(text="Ошибка сохранения", fg=RED)
            self.log(f"Не удалось сохранить интервал: {e}", "error")
            messagebox.showerror("Настройки", f"Не удалось сохранить интервал: {e}")


    def incident_review_state(self, item):
        """Return (is_processed, reviewed_count, suspicious_count) for an incident row."""
        if not item.get("is_anomaly"):
            return False, 0, 0
        packets = item.get("packets") or item.get("packet_features") or []
        reviews = item.get("packet_reviews") or {}
        context = self.build_packet_highlight_context(packets, True)
        for ev in (item.get("details") or {}).get("device_events", []):
            context.setdefault("device_status", {})[str(ev.get("mac", "")).lower()] = ev
        suspicious = []
        for idx, pkt in enumerate(packets[:500]):
            if self.packet_anomaly_reason(pkt, True, context):
                suspicious.append(idx)
        reviewed = sum(1 for idx in suspicious if str(idx) in reviews or idx in reviews)
        return bool(suspicious) and reviewed == len(suspicious), reviewed, len(suspicious)

    def load_incidents(self, silent=False):
        try:
            previous_selection = self.selected_incident_id
            r = requests.get(f"{SERVER_BASE}/incidents", timeout=5)
            r.raise_for_status()
            data = r.json()
            for row in self.tree.get_children():
                self.tree.delete(row)
            self.incident_cache = {}
            selected_row = None
            for item in data:
                iid = item.get("id")
                self.incident_cache[str(iid)] = item
                is_anomaly = item.get("is_anomaly")
                prob = float(item.get("prob", 0))
                processed, reviewed_count, suspicious_count = self.incident_review_state(item)
                review_icon = "●" if processed else (f"{reviewed_count}/{suspicious_count}" if is_anomaly and suspicious_count else "")
                status_text = "Обработан" if processed else ("Аномалия" if is_anomaly else "Норма")
                tag = "processed" if processed else ("anomaly" if is_anomaly else "normal")
                row_id = self.tree.insert("", "end", values=(
                    review_icon,
                    iid,
                    str(item.get("time", ""))[:19].replace("T", " "),
                    f"{item.get('packet_count', 0)} / {item.get('filtered_packet_count', item.get('packet_count', 0))}",
                    f"{prob:.3f}",
                    item.get("engine", ""),
                    status_text,
                ), tags=(tag,))
                if previous_selection and str(iid) == str(previous_selection):
                    selected_row = row_id
            if selected_row:
                self.tree.selection_set(selected_row)
                self.tree.focus(selected_row)
                self.update_metrics_from_incident(self.incident_cache[str(previous_selection)])
            if not silent:
                self.log("История загружена", "success")
        except Exception as e:
            if not silent:
                self.log(f"Ошибка загрузки истории: {e}", "error")

    def show_model_status(self):
        try:
            r = requests.get(f"{SERVER_BASE}/model_status", timeout=5)
            r.raise_for_status()
            data = r.json()
            msg = (
                f"LSTM доступна: {data.get('available')}\n"
                f"Признаков: {len(data.get('features', []))}\n"
            )
            if data.get("error"):
                msg += f"\nОшибка: {data.get('error')}"
            messagebox.showinfo("Статус модели", msg)
        except Exception as e:
            messagebox.showerror("Статус модели", f"Сервер недоступен: {e}")

    def show_incident_details(self, event=None):
        selected = self.tree.selection()
        if not selected:
            return
        values = self.tree.item(selected[0])["values"]
        incident_id = values[1]
        try:
            r = requests.get(f"{SERVER_BASE}/incident/{incident_id}", timeout=5)
            r.raise_for_status()
            item = r.json()
        except Exception as e:
            self.log(f"Ошибка загрузки деталей: {e}", "error")
            return
        self.show_details_window(item)

    def show_details_window(self, item):
        win = tk.Toplevel(self.root)
        win.title(f"Инцидент #{item.get('id', '')}")
        win.geometry("1200x720")
        win.configure(bg=BG)

        nb = ttk.Notebook(win)
        nb.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        stats_tab = ttk.Frame(nb)
        pkt_tab = ttk.Frame(nb)
        nb.add(stats_tab, text="Статистика окна")
        nb.add(pkt_tab, text="Пакеты")

        self.pack_window_stats(stats_tab, item)

        self.pack_packet_table(pkt_tab, item.get("packet_features", []), item)

    def pack_window_stats(self, parent, item):
        stats = item.get("window_stats") or {}
        details = item.get("details") or {}

        outer = tk.Frame(parent, bg=BG)
        outer.pack(fill="both", expand=True, padx=18, pady=18)

        header = tk.Frame(outer, bg=BG)
        header.pack(fill="x", pady=(0, 14))
        title = f"Статистика окна инцидента #{self.format_incident_id(item.get('id'))}"
        tk.Label(header, text=title, bg=BG, fg=TEXT, font=("Arial", 18, "bold")).pack(anchor="w")
        tk.Label(header, text="Сводные показатели временного окна, переданного на LSTM-анализ", bg=BG, fg=MUTED, font=("Arial", 11)).pack(anchor="w", pady=(4, 0))

        cards = tk.Frame(outer, bg=BG)
        cards.pack(fill="x", pady=(0, 16))

        def stat_value(key, default=0):
            return stats.get(key, default)

        quick = [
            ("Всего пакетов", stat_value("Total Packets per Window", item.get("packet_count", 0)), BLUE),
            ("Входящие", stat_value("Incoming Packets per Window"), CYAN),
            ("Исходящие", stat_value("Outgoing Packets per Window"), VIOLET),
            ("Вероятность", f"{float(item.get('prob', item.get('anomaly_prob', 0)) or 0):.3f}", RED if item.get("is_anomaly") else GREEN),
        ]
        for label, value, color in quick:
            card = tk.Frame(cards, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
            card.pack(side="left", fill="x", expand=True, padx=6)
            tk.Frame(card, bg=color, height=4).pack(fill="x")
            tk.Label(card, text=label.upper(), bg=CARD, fg=MUTED, font=("Arial", 9, "bold")).pack(anchor="w", padx=14, pady=(12, 0))
            tk.Label(card, text=str(value), bg=CARD, fg=color, font=("Arial", 22, "bold")).pack(anchor="w", padx=14, pady=(2, 12))

        content = tk.Frame(outer, bg=BG)
        content.pack(fill="both", expand=True)
        left = tk.Frame(content, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        right = tk.Frame(content, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        left.pack(side="left", fill="both", expand=True, padx=(0, 8))
        right.pack(side="left", fill="both", expand=True, padx=(8, 0))

        def add_section(panel, title_text):
            tk.Label(panel, text=title_text, bg=CARD, fg=TEXT, font=("Arial", 13, "bold")).pack(anchor="w", padx=16, pady=(14, 8))

        def add_row(panel, label, value):
            row = tk.Frame(panel, bg=SURFACE, highlightbackground=BORDER, highlightthickness=1)
            row.pack(fill="x", padx=14, pady=4)
            tk.Label(row, text=label, bg=SURFACE, fg="#cbd5e1", font=("Arial", 10, "bold"), width=26, anchor="w").pack(side="left", padx=(12, 8), pady=8)
            tk.Label(row, text=str(value), bg=SURFACE, fg=TEXT, font=("Arial", 10), anchor="w", justify="left", wraplength=360).pack(side="left", fill="x", expand=True, padx=(0, 12), pady=8)

        add_section(left, "Состав трафика")
        for label, key in [
            ("TCP-пакеты", "TCP Protocol Count per Window"),
            ("UDP-пакеты", "UDP Protocol Count per Window"),
            ("ICMP-пакеты", "ICMP Protocol Count per Window"),
            ("ARP-пакеты", "ARP Protocol Count per Window"),
        ]:
            add_row(left, label, stat_value(key))

        add_section(left, "TCP-флаги")
        for label, key in [
            ("SYN", "SYN Flags per Window"),
            ("ACK", "ACK Flags per Window"),
            ("FIN", "FIN Flags per Window"),
            ("RST", "RST Flags per Window"),
        ]:
            add_row(left, label, stat_value(key))

        add_section(right, "Результат анализа")
        add_row(right, "Статус", "Аномалия" if item.get("is_anomaly") else "Норма")
        add_row(right, "Модель", item.get("engine", "unknown"))
        add_row(right, "Пакетов сохранено", item.get("filtered_packet_count", item.get("packet_count", len(item.get("packet_features", [])))))


    def format_incident_id(self, value):
        try:
            return f"ID-{int(value):04d}"
        except (TypeError, ValueError):
            return f"ID-{value or 'LIVE'}"

    def endpoint_text(self, pkt, prefix):
        ip = pkt.get(f"IP {prefix}") or pkt.get(f"{prefix} IP") or ""
        mac = pkt.get(f"MAC {prefix}") or ""
        if ip and mac:
            return f"{ip} / {mac}"
        return ip or mac or "—"

    def infer_incident_card_fields(self, item):
        packets = item.get("packet_features") or []
        details = item.get("details") or {}
        incident_is_anomaly = bool(item.get("is_anomaly"))
        context = self.build_packet_highlight_context(packets, incident_is_anomaly)
        for ev in (details or {}).get("device_events", []):
            context.setdefault("device_status", {})[str(ev.get("mac", "")).lower()] = ev
        suspicious_packet = None
        suspicious_reason = ""
        for pkt in packets[:500]:
            reason = self.packet_anomaly_reason(pkt, incident_is_anomaly, context)
            if reason:
                suspicious_packet = pkt
                suspicious_reason = reason
                break
        first_packet = suspicious_packet or (packets[0] if packets else {})
        protocol = first_packet.get("Protocol") or details.get("dominant_protocol") or "—"
        prob = float(item.get("anomaly_prob", item.get("prob", 0)) or 0)
        if not incident_is_anomaly:
            criticality = "Низкая"
        elif prob >= 0.9:
            criticality = "Высокая"
        elif prob >= 0.7:
            criticality = "Средняя"
        else:
            criticality = "Наблюдение"

        device_events = details.get("device_events") or []
        suspicious_ports = details.get("suspicious_tcp_ports") or sorted(context.get("suspicious_tcp_ports", []))
        if device_events:
            ev = device_events[0]
            reason = ev.get("message") or f"MAC: {ev.get('status')}"
        elif suspicious_ports:
            reason = "серия обращений к разным портам" if len(suspicious_ports) > 1 else f"повторные обращения к порту {suspicious_ports[0]}"
        elif suspicious_reason:
            reason = suspicious_reason
        elif item.get("message"):
            reason = item.get("message")
        else:
            reason = "аномальная последовательность пакетов" if incident_is_anomaly else "отклонений не обнаружено"

        return {
            "time": str(item.get("time") or "")[:19].replace("T", " ") or "—",
            "source": self.endpoint_text(first_packet, "Src"),
            "destination": self.endpoint_text(first_packet, "Dst"),
            "protocol": protocol,
            "probability": f"{prob:.2f}",
            "criticality": criticality,
            "packets": f"контекст {item.get('packet_count', len(packets))} пакет(ов)",
            "reason": reason,
        }

    def pack_incident_card(self, parent, item):
        fields = self.infer_incident_card_fields(item)
        is_anomaly = bool(item.get("is_anomaly"))
        accent = RED if is_anomaly else GREEN

        outer = tk.Frame(parent, bg=BG)
        outer.pack(fill="x", padx=12, pady=12)
        card = tk.Frame(outer, bg=CARD, highlightbackground="#64748b", highlightthickness=2)
        card.pack(fill="x", expand=True)

        header = tk.Frame(card, bg=CARD)
        header.pack(fill="x", padx=28, pady=(24, 16))
        tk.Label(header, text=f"Инцидент #{self.format_incident_id(item.get('id'))}", bg=CARD, fg=TEXT, font=("Arial", 21, "bold")).pack(side="left")
        badge_text = "АНОМАЛИЯ" if is_anomaly else "НОРМА"
        badge_bg = "#3b1118" if is_anomaly else "#0f2f2a"
        tk.Label(header, text=badge_text, bg=badge_bg, fg=accent, font=("Arial", 10, "bold"), padx=14, pady=6).pack(side="right")

        grid = tk.Frame(card, bg=CARD)
        grid.pack(fill="x", padx=28, pady=(0, 28))
        rows = [
            ("Время обнаружения", fields["time"]),
            ("Источник", fields["source"]),
            ("Назначение", fields["destination"]),
            ("Протокол", fields["protocol"]),
            ("Вероятность аномалии", fields["probability"]),
            ("Критичность", fields["criticality"]),
            ("Связанные пакеты", fields["packets"]),
            ("Причина", fields["reason"]),
        ]
        for label, value in rows:
            row = tk.Frame(grid, bg=SURFACE, highlightbackground=BORDER, highlightthickness=1)
            row.pack(fill="x", pady=5)
            tk.Label(row, text=label, bg=SURFACE, fg="#cbd5e1", font=("Arial", 11, "bold"), width=28, anchor="w").pack(side="left", padx=(16, 10), pady=8)
            tk.Label(row, text=value, bg=SURFACE, fg=TEXT, font=("Arial", 11), anchor="w", justify="left", wraplength=760).pack(side="left", fill="x", expand=True, padx=(0, 16), pady=8)

    def build_packet_highlight_context(self, packets, incident_is_anomaly=False):
        """Find compact per-window hints for packet-row highlighting.

        The LSTM marks the whole window. Row highlighting is an explanation layer.
        For a one-port scan against Windows, the capture may contain:
        - incoming SYN packets with TCP Dst Port = scanned port;
        - outgoing RST/RST-ACK packets with TCP Src Port = scanned port.
        We therefore learn suspicious ports from both directions.
        """
        device_status = {}
        if isinstance(incident_is_anomaly, dict):
            # defensive; normal calls pass bool, item details are read below in pack methods
            pass
        if not incident_is_anomaly:
            return {"suspicious_tcp_ports": set(), "device_status": device_status}

        common_tcp = {20, 21, 22, 25, 53, 80, 110, 123, 143, 443, 445, 465, 587, 993, 995, 3389, 5050}
        port_counts = {}

        for pkt in packets[:500]:
            if not isinstance(pkt, dict):
                continue
            proto = str(pkt.get("Protocol", "")).upper()
            if proto != "TCP":
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

        return {
            # 2 is enough for a deliberately small 5-attempt demo scan,
            # but still avoids marking random one-off packets.
            "suspicious_tcp_ports": {port for port, count in port_counts.items() if count >= 2},
            "device_status": device_status,
        }

    def safe_int(self, value, default=0):
        try:
            return int(float(value or 0))
        except (TypeError, ValueError):
            return default

    def mac_kind(self, mac):
        mac = str(mac or "").lower().strip()
        if not mac or len(mac.split(":")) != 6:
            return "invalid"
        if mac == "ff:ff:ff:ff:ff:ff":
            return "broadcast"
        try:
            first = int(mac.split(":")[0], 16)
        except ValueError:
            return "invalid"
        return "multicast" if first & 1 else "unicast"

    def make_finding(self, feature, value, reason):
        meta = NORMAL_FEATURE_RECOMMENDATIONS.get(feature, {})
        return {
            "feature": feature,
            "value": value,
            "reason": reason,
            "normal": meta.get("normal", "см. справочник нормальных значений"),
            "recommendation": meta.get("recommendation", "Проверить источник отклонения и сопоставить с политикой сети."),
        }

    def packet_anomaly_findings(self, pkt, incident_is_anomaly=False, context=None):
        """Return detailed deviations used for highlighting and recommendations."""
        if not incident_is_anomaly or not isinstance(pkt, dict):
            return []
        context = context or {}
        findings = []
        suspicious_ports = context.get("suspicious_tcp_ports", set())
        common_udp = {53, 67, 68, 123, 137, 138, 1900, 5353, 5355}
        proto = str(pkt.get("Protocol", "")).upper()
        ip_src = str(pkt.get("IP Src", "") or "")
        ip_dst = str(pkt.get("IP Dst", "") or "")
        has_ip = bool(ip_src or ip_dst)

        src_mac = pkt.get("MAC Src", "")
        dst_mac = pkt.get("MAC Dst", "")
        src_kind = self.mac_kind(src_mac)
        dst_kind = self.mac_kind(dst_mac)
        if src_kind != "unicast":
            findings.append(self.make_finding("MAC Src", src_mac or "—", "MAC источника не является обычным unicast-адресом"))
        device_event = (context.get("device_status") or {}).get(str(src_mac or "").lower())
        if device_event:
            status = device_event.get("status", "unknown")
            if status == "unknown":
                reason = "новый или неподтверждённый MAC-адрес"
            elif status == "retired":
                reason = "MAC-адрес выведен из эксплуатации, но снова появился в сети"
            elif status == "blocked":
                reason = "заблокированный MAC-адрес снова появился в сети"
            else:
                reason = device_event.get("message", "статус MAC требует проверки")
            findings.append(self.make_finding("MAC device status", src_mac or "—", reason))
        if dst_kind in {"broadcast", "multicast"} and proto not in {"ARP", "UDP"}:
            findings.append(self.make_finding("MAC Dst", dst_mac or "—", "broadcast/multicast назначение вне типичного служебного трафика"))
        elif dst_kind == "invalid":
            findings.append(self.make_finding("MAC Dst", dst_mac or "—", "MAC назначения имеет некорректный формат"))

        if proto not in {"TCP", "UDP", "ARP"}:
            findings.append(self.make_finding("Protocol", proto or "—", "нетипичный протокол для нормальной работы LAN"))

        direction = str(pkt.get("Direction", "") or "")
        if direction not in {"in", "out"}:
            findings.append(self.make_finding("Direction", direction or "—", "направление пакета не определено"))

        ttl = self.safe_int(pkt.get("TTL"))
        if has_ip and not (32 <= ttl <= 255):
            findings.append(self.make_finding("TTL", ttl, "TTL вне нормального диапазона для IP-пакета"))

        length = self.safe_int(pkt.get("IP Packet Length"))
        if length and not (20 <= length <= 1500):
            findings.append(self.make_finding("IP Packet Length", length, "размер пакета выходит за стандартный Ethernet MTU"))

        if proto == "TCP":
            syn = self.safe_int(pkt.get("SYN"))
            ack = self.safe_int(pkt.get("ACK"))
            rst = self.safe_int(pkt.get("RST"))
            flags = ["SYN", "ACK", "FIN", "RST", "PSH", "URG"]
            flag_count = sum(self.safe_int(pkt.get(flag)) for flag in flags)
            tcp_src = self.safe_int(pkt.get("TCP Src Port"))
            tcp_dst = self.safe_int(pkt.get("TCP Dst Port"))
            reserved = self.safe_int(pkt.get("TCP Reserved"))
            urgent = self.safe_int(pkt.get("TCP Urgent Pointer"))
            urg_flag = self.safe_int(pkt.get("URG"))
            window = self.safe_int(pkt.get("TCP Window Size"))

            if not (1 <= tcp_src <= 65535):
                findings.append(self.make_finding("TCP Src Port", tcp_src, "TCP-порт источника вне допустимого диапазона"))
            if not (1 <= tcp_dst <= 65535):
                findings.append(self.make_finding("TCP Dst Port", tcp_dst, "TCP-порт назначения вне допустимого диапазона"))
            if tcp_dst in suspicious_ports and syn and not ack:
                findings.append(self.make_finding("SYN/RST pattern", f"SYN → {tcp_dst}", "входящий SYN к подозрительному/редкому порту"))
            if tcp_src in suspicious_ports and rst:
                findings.append(self.make_finding("SYN/RST pattern", f"RST с {tcp_src}", "ответ RST с подозрительного порта"))
            if tcp_dst in suspicious_ports and rst:
                findings.append(self.make_finding("SYN/RST pattern", f"RST → {tcp_dst}", "RST к подозрительному порту"))
            if reserved != 0:
                findings.append(self.make_finding("TCP Reserved", reserved, "зарезервированные TCP-биты должны быть равны 0"))
            if urgent != 0 or urg_flag:
                findings.append(self.make_finding("TCP Urgent Pointer", urgent, "используется указатель срочности/URG, что редко для обычной LAN"))
            if flag_count < 1 or flag_count > 3:
                findings.append(self.make_finding("Flag_Count", flag_count, "нетипичное количество TCP-флагов"))
            if not (0 <= window <= 65535):
                findings.append(self.make_finding("TCP Window Size", window, "размер TCP-окна вне диапазона"))

        if proto == "UDP":
            udp_src = self.safe_int(pkt.get("UDP Src Port"))
            udp_dst = self.safe_int(pkt.get("UDP Dst Port"))
            if not (1 <= udp_src <= 65535):
                findings.append(self.make_finding("UDP Src Port", udp_src, "UDP-порт источника вне допустимого диапазона"))
            if not (1 <= udp_dst <= 65535):
                findings.append(self.make_finding("UDP Dst Port", udp_dst, "UDP-порт назначения вне допустимого диапазона"))
            elif udp_dst not in common_udp and dst_kind in {"broadcast", "multicast"}:
                findings.append(self.make_finding("UDP Dst Port", udp_dst, "multicast/broadcast UDP не похож на типичный служебный порт"))

        return findings

    def short_feature_label(self, feature):
        labels = {
            "SYN/RST pattern": "SYN/RST",
            "IP Packet Length": "Размер пакета",
            "MAC Src": "MAC источника",
            "MAC Dst": "MAC назначения",
            "MAC device status": "Новый MAC",
            "TCP Dst Port": "TCP порт",
            "TCP Src Port": "TCP порт",
            "UDP Dst Port": "UDP порт",
            "UDP Src Port": "UDP порт",
            "TCP Reserved": "TCP reserved",
            "TCP Urgent Pointer": "URG pointer",
            "TCP Window Size": "TCP окно",
            "Flag_Count": "TCP флаги",
            "Protocol": "Протокол",
            "Direction": "Направление",
            "TTL": "TTL",
        }
        return labels.get(feature, feature)

    def packet_anomaly_reason(self, pkt, incident_is_anomaly=False, context=None):
        """Return a very short reason for the table. Full text is shown via ⓘ."""
        findings = self.packet_anomaly_findings(pkt, incident_is_anomaly, context)
        if not findings:
            return ""
        labels = []
        for item in findings:
            label = self.short_feature_label(item.get("feature", ""))
            if label and label not in labels:
                labels.append(label)
        visible = labels[:2]
        text = ", ".join(visible)
        if len(labels) > 2:
            text += f" +{len(labels) - 2}"
        return text

    def show_recommendation_window(self, packet_index, row):
        findings = row.get("findings") or []
        if not findings:
            messagebox.showinfo("Рекомендации", "Для этого пакета нет явных отклонений от нормы.")
            return
        win = tk.Toplevel(self.root)
        win.title(f"Рекомендации по пакету PKT-{packet_index:04d}")
        win.geometry("820x680")
        win.configure(bg=BG)

        outer = tk.Frame(win, bg=BG)
        outer.pack(fill="both", expand=True, padx=18, pady=18)

        header = tk.Frame(outer, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        header.pack(fill="x", pady=(0, 14))
        tk.Frame(header, bg=YELLOW, width=5).pack(side="left", fill="y")
        header_body = tk.Frame(header, bg=CARD)
        header_body.pack(side="left", fill="x", expand=True, padx=18, pady=14)
        tk.Label(header_body, text=f"Пакет PKT-{packet_index:04d}", bg=CARD, fg=TEXT, font=("Arial", 20, "bold")).pack(anchor="w")
        tk.Label(header_body, text="Причины подсветки и рекомендуемые действия оператора", bg=CARD, fg=MUTED, font=("Arial", 11)).pack(anchor="w", pady=(4, 0))
        tk.Label(header, text=f"{len(findings)} признак(а)", bg="#3a2a08", fg="#fde68a", font=("Arial", 10, "bold"), padx=12, pady=6).pack(side="right", padx=16)

        canvas = tk.Canvas(outer, bg=BG, highlightthickness=0, bd=0)
        scrollbar = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        content = tk.Frame(canvas, bg=BG)
        content.bind("<Configure>", lambda _event: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas_window = canvas.create_window((0, 0), window=content, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        canvas.bind("<Configure>", lambda event: canvas.itemconfig(canvas_window, width=event.width))

        def add_info_row(parent, label, value, accent_color=TEXT):
            row = tk.Frame(parent, bg=SURFACE, highlightbackground=BORDER, highlightthickness=1)
            row.pack(fill="x", pady=4)
            tk.Label(row, text=label, bg=SURFACE, fg="#cbd5e1", font=("Arial", 10, "bold"), width=18, anchor="w").pack(side="left", padx=(12, 8), pady=8)
            tk.Label(row, text=str(value), bg=SURFACE, fg=accent_color, font=("Arial", 10), anchor="w", justify="left", wraplength=520).pack(side="left", fill="x", expand=True, padx=(0, 12), pady=8)

        for num, item in enumerate(findings, 1):
            card = tk.Frame(content, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
            card.pack(fill="x", pady=(0, 12))

            top = tk.Frame(card, bg=CARD)
            top.pack(fill="x", padx=16, pady=(14, 8))
            tk.Label(top, text=f"{num}. {self.short_feature_label(item.get('feature', ''))}", bg=CARD, fg=YELLOW, font=("Arial", 14, "bold")).pack(side="left")
            tk.Label(top, text="требует проверки", bg="#3b1118", fg=RED, font=("Arial", 9, "bold"), padx=10, pady=5).pack(side="right")

            body = tk.Frame(card, bg=CARD)
            body.pack(fill="x", padx=16, pady=(0, 16))
            add_info_row(body, "Значение", item.get("value", "—"), TEXT)
            add_info_row(body, "Норма", item.get("normal", "—"), GREEN)
            add_info_row(body, "Причина", item.get("reason", "—"), YELLOW)
            add_info_row(body, "Что сделать", item.get("recommendation", "—"), CYAN)

    def pack_packet_table(self, parent, packets, item=None):
        if not packets:
            ttk.Label(parent, text="Пакеты не сохранены").pack(pady=20)
            return

        item = item or {}
        incident_id = item.get("id")
        incident_is_anomaly = bool(item.get("is_anomaly"))
        packet_reviews = item.get("packet_reviews") or {}
        base_columns = list(packets[0].keys())
        columns = (["Mark", "Reason", "Operator", "Final"] + base_columns) if incident_is_anomaly else base_columns

        top = tk.Frame(parent, bg=BG)
        top.grid(row=0, column=0, columnspan=3, sticky="ew", padx=4, pady=(0, 8))
        filter_var = tk.BooleanVar(value=False)
        hint = tk.Label(top, text="", bg=BG, fg=MUTED, font=("Arial", 11), anchor="w")
        hint.pack(side="left", fill="x", expand=True)

        body = tk.Frame(parent, bg=BG)
        body.grid(row=1, column=0, sticky="nsew")
        side = tk.Frame(parent, bg=CARD, highlightbackground=BORDER, highlightthickness=1, width=310)
        if incident_is_anomaly:
            side.grid(row=1, column=1, sticky="ns", padx=(12, 0))
            side.grid_propagate(False)
        yscroll = ttk.Scrollbar(parent, orient="vertical")
        yscroll.grid(row=1, column=2, sticky="ns")
        xscroll = ttk.Scrollbar(parent, orient="horizontal")
        xscroll.grid(row=2, column=0, sticky="ew")

        tree = ttk.Treeview(body, columns=columns, show="headings", yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        yscroll.configure(command=tree.yview)
        xscroll.configure(command=tree.xview)
        tree.pack(fill="both", expand=True)
        tree.tag_configure("suspect", background="#3b1118", foreground="#fecdd3")
        tree.tag_configure("reviewed", background="#3a2a08", foreground="#fde68a")
        tree.tag_configure("normal", background=SURFACE, foreground=TEXT)

        headings = {"Mark": "!", "Reason": "Причина подсветки  ⓘ", "Operator": "Решение", "Final": "Итог"}
        for col in columns:
            tree.heading(col, text=headings.get(col, col))
            width = 46 if col == "Mark" else 130 if col in {"Operator", "Final"} else 230 if col == "Reason" else 110
            tree.column(col, width=width, anchor="center")

        highlight_context = self.build_packet_highlight_context(packets, incident_is_anomaly)
        for ev in (item.get("details") or {}).get("device_events", []):
            highlight_context.setdefault("device_status", {})[str(ev.get("mac", "")).lower()] = ev
        rows = []
        for packet_index, pkt in enumerate(packets[:500]):
            findings = self.packet_anomaly_findings(pkt, incident_is_anomaly, highlight_context)
            reason = self.packet_anomaly_reason(pkt, incident_is_anomaly, highlight_context)
            display_reason = f"ⓘ {reason}" if reason else ""
            review = packet_reviews.get(str(packet_index)) or packet_reviews.get(packet_index)
            if incident_is_anomaly:
                mark = "ANOM" if reason else ""
                operator_label = review.get("operator_label", "") if review else ""
                final_label = review.get("final_label", "") if review else ""
                values = [mark, display_reason, operator_label, final_label] + [pkt.get(c, "") for c in base_columns]
            else:
                values = [pkt.get(c, "") for c in base_columns]
            if review:
                tag = "reviewed"
            elif reason:
                tag = "suspect"
            else:
                tag = "normal"
            rows.append({"packet_index": packet_index, "values": values, "tag": tag, "is_suspect": bool(reason), "review": review, "packet": pkt, "reason": reason, "findings": findings})

        def suspect_total():
            return sum(1 for row in rows if row["is_suspect"])

        def reviewed_suspects():
            return sum(1 for row in rows if row["is_suspect"] and row["review"])

        def update_hint(visible=0):
            if not incident_is_anomaly:
                hint.config(text=f"Пакетов: {len(rows)}", fg=MUTED)
                return
            total = suspect_total()
            done = reviewed_suspects()
            if total:
                hint.config(text=f"Подозрительные пакеты: обработано {done}/{total}. Показано: {visible}", fg=YELLOW)
            else:
                hint.config(text="Окно аномальное, но явные SYN/RST-пакеты в сохранённых строках не выделены", fg=YELLOW)

        def render_rows(select_index=None):
            for row_id in tree.get_children():
                tree.delete(row_id)
            only_suspect = filter_var.get()
            visible = 0
            for row in rows:
                if only_suspect and not row["is_suspect"]:
                    continue
                iid = str(row["packet_index"])
                tree.insert("", "end", iid=iid, values=row["values"], tags=(row["tag"],))
                visible += 1
            update_hint(visible)
            if select_index is not None and tree.exists(str(select_index)):
                tree.selection_set(str(select_index))
                tree.focus(str(select_index))
                tree.see(str(select_index))

        if incident_is_anomaly:
            toggle = tk.Checkbutton(
                top, text="Только подозрительные", variable=filter_var, command=render_rows,
                bg=BG, fg=TEXT, selectcolor=SURFACE, activebackground=BG, activeforeground=TEXT,
                font=("Arial", 11, "bold")
            )
            toggle.pack(side="right", padx=(16, 0))

        parent.grid_rowconfigure(1, weight=1)
        parent.grid_columnconfigure(0, weight=1)

        selected_label = None
        comment_text = None
        anomaly_btn = None
        normal_btn = None
        selected_packet_index = {"value": None}

        def find_row(packet_index):
            for row in rows:
                if row["packet_index"] == packet_index:
                    return row
            return None

        def set_buttons_enabled(enabled):
            state = "normal" if enabled else "disabled"
            if anomaly_btn:
                anomaly_btn.config(state=state)
            if normal_btn:
                normal_btn.config(state=state)

        def refresh_side(_event=None):
            if not incident_is_anomaly:
                return
            sel = tree.selection()
            if not sel:
                selected_packet_index["value"] = None
                selected_label.config(text="Выберите подозрительный пакет", fg=MUTED)
                set_buttons_enabled(False)
                return
            packet_index = int(sel[0])
            selected_packet_index["value"] = packet_index
            row = find_row(packet_index)
            if not row:
                set_buttons_enabled(False)
                return
            if not row["is_suspect"]:
                selected_label.config(text=f"Пакет #{packet_index}: не требует реакции", fg=MUTED)
                set_buttons_enabled(False)
                return
            if row["review"]:
                selected_label.config(text=f"Пакет #{packet_index}: уже обработан → {row['review'].get('final_label')}", fg=YELLOW)
                set_buttons_enabled(False)
                return
            selected_label.config(text=f"Пакет #{packet_index}: требуется решение", fg=YELLOW)
            set_buttons_enabled(str(incident_id).isdigit())

        def submit_review(operator_label):
            packet_index = selected_packet_index.get("value")
            row = find_row(packet_index) if packet_index is not None else None
            if not row or not row["is_suspect"]:
                messagebox.showinfo("IDS", "Выберите подозрительный пакет.")
                return
            if row["review"]:
                messagebox.showinfo("IDS", "Этот пакет уже обработан.")
                return
            if not str(incident_id).isdigit():
                messagebox.showwarning("IDS", "Для live-окна сначала откройте сохранённый инцидент из списка.")
                return
            try:
                payload = {
                    "packet_index": packet_index,
                    "operator_label": operator_label,
                    "operator": os.environ.get("USER", "IDS operator"),
                    "comment": comment_text.get("1.0", "end").strip() if comment_text else "",
                }
                r = requests.post(f"{SERVER_BASE}/incident/{incident_id}/packet_review", json=payload, timeout=5)
                r.raise_for_status()
                review = r.json().get("review", {})
                row["review"] = review
                row["values"][2] = review.get("operator_label", operator_label)
                row["values"][3] = review.get("final_label", operator_label)
                row["tag"] = "reviewed"
                if comment_text:
                    comment_text.delete("1.0", "end")
                render_rows(select_index=packet_index)
                refresh_side()
                self.log(f"Пакет #{packet_index} инцидента #{incident_id}: итоговая метка {operator_label}", "success")
                self.load_incidents(silent=True)
                if suspect_total() and reviewed_suspects() == suspect_total():
                    messagebox.showinfo("IDS", "Все подозрительные пакеты этого инцидента обработаны.")
            except Exception as e:
                self.log(f"Не удалось сохранить решение по пакету: {e}", "error")
                messagebox.showerror("IDS", f"Не удалось сохранить решение: {e}")

        def show_packet_card_popup(_event=None):
            sel = tree.selection()
            if not sel:
                return
            packet_index = int(sel[0])
            row = find_row(packet_index)
            if not row:
                return
            pkt = row.get("packet", {})
            win = tk.Toplevel(self.root)
            win.title(f"Пакет PKT-{packet_index:04d}")
            win.geometry("720x760")
            win.configure(bg=BG)
            outer = tk.Frame(win, bg=CARD, highlightbackground="#64748b", highlightthickness=2)
            outer.pack(fill="both", expand=True, padx=18, pady=18)
            canvas = tk.Canvas(outer, bg=CARD, highlightthickness=0, bd=0)
            scrollbar = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
            card = tk.Frame(canvas, bg=CARD)
            card.bind("<Configure>", lambda _event: canvas.configure(scrollregion=canvas.bbox("all")))
            canvas_window = canvas.create_window((0, 0), window=card, anchor="nw")
            canvas.configure(yscrollcommand=scrollbar.set)
            canvas.pack(side="left", fill="both", expand=True)
            scrollbar.pack(side="right", fill="y")
            canvas.bind("<Configure>", lambda event: canvas.itemconfig(canvas_window, width=event.width))
            canvas.bind_all("<MouseWheel>", lambda event: canvas.yview_scroll(int(-1 * (event.delta / 120)), "units"))
            header = tk.Frame(card, bg=CARD)
            header.pack(fill="x", padx=22, pady=(20, 14))
            tk.Label(header, text=f"Пакет PKT-{packet_index:04d}", bg=CARD, fg=TEXT, font=("Arial", 20, "bold")).pack(side="left")
            if row.get("is_suspect"):
                tk.Label(header, text="ПОДОЗРИТЕЛЬНЫЙ", bg="#3b1118", fg=RED, font=("Arial", 10, "bold"), padx=12, pady=6).pack(side="right")

            flags = [name for name in ("SYN", "ACK", "FIN", "RST", "PSH", "URG") if int(pkt.get(name, 0) or 0)]
            values = [
                ("Источник", self.endpoint_text(pkt, "Src")),
                ("Назначение", self.endpoint_text(pkt, "Dst")),
                ("Протокол", pkt.get("Protocol", "—")),
                ("Порт источника", pkt.get("TCP Src Port") or pkt.get("UDP Src Port") or "—"),
                ("Порт назначения", pkt.get("TCP Dst Port") or pkt.get("UDP Dst Port") or "—"),
                ("TCP-флаги", ", ".join(flags) if flags else "—"),
                ("TTL", pkt.get("TTL", "—")),
                ("Длина пакета", pkt.get("IP Packet Length", "—")),
                ("Направление", pkt.get("Direction", "—")),
                ("Причина", row.get("reason") or "нет явной причины подсветки"),
            ]
            def add_card_row(label, value):
                line = tk.Frame(card, bg=SURFACE, highlightbackground=BORDER, highlightthickness=1)
                line.pack(fill="x", padx=22, pady=4)
                tk.Label(line, text=label, bg=SURFACE, fg="#cbd5e1", font=("Arial", 10, "bold"), width=20, anchor="w").pack(side="left", padx=(12, 8), pady=8)
                tk.Label(line, text=value, bg=SURFACE, fg=TEXT, font=("Arial", 10), anchor="w", justify="left", wraplength=440).pack(side="left", fill="x", expand=True, padx=(0, 12), pady=8)

            for label, value in values:
                add_card_row(label, value)

            tk.Label(card, text="Все признаки пакета", bg=CARD, fg=TEXT, font=("Arial", 13, "bold")).pack(anchor="w", padx=22, pady=(14, 6))
            add_card_row("Индекс пакета", packet_index)
            add_card_row("Причина подсветки", row.get("reason") or "—")
            if row.get("findings"):
                add_card_row("Рекомендации", "Нажмите ⓘ в графе «Причина подсветки» или откройте окно рекомендаций двойным кликом по строке причины.")
                for finding in row.get("findings", []):
                    add_card_row(f"{finding['feature']}: норма", finding.get("normal", "—"))
                    add_card_row(f"{finding['feature']}: что сделать", finding.get("recommendation", "—"))
            if row.get("review"):
                for key, value in row.get("review", {}).items():
                    add_card_row(f"review.{key}", value)
            shown_keys = {
                "Protocol", "TCP Src Port", "TCP Dst Port", "UDP Src Port", "UDP Dst Port",
                "TTL", "IP Packet Length", "Direction"
            }
            for key, value in pkt.items():
                if key in shown_keys or key.startswith("IP ") or key.startswith("MAC "):
                    continue
                add_card_row(key, value)

        if incident_is_anomaly:
            tk.Label(side, text="Решение оператора IDS", bg=CARD, fg=TEXT, font=("Arial", 14, "bold")).pack(anchor="w", padx=14, pady=(16, 6))
            selected_label = tk.Label(side, text="Выберите подозрительный пакет", bg=CARD, fg=MUTED, font=("Arial", 11), wraplength=260, justify="left")
            selected_label.pack(anchor="w", padx=14, pady=(0, 12))
            tk.Label(side, text="Комментарий", bg=CARD, fg=MUTED, font=("Arial", 10, "bold")).pack(anchor="w", padx=14)
            comment_text = tk.Text(side, height=5, bg=SURFACE, fg=TEXT, insertbackground=TEXT, relief="flat", borderwidth=0, font=("Arial", 10), wrap="word")
            comment_text.pack(fill="x", padx=14, pady=(6, 12))
            anomaly_btn = self.action_button(side, "Аномалия", lambda: submit_review("ANOMALY"), kind="danger", tooltip="Подтвердить аномальный пакет")
            anomaly_btn.pack(fill="x", padx=14, pady=(0, 8))
            normal_btn = self.action_button(side, "Нормальный", lambda: submit_review("BENIGN"), kind="primary", tooltip="Перезаписать метку IDS как норму")
            normal_btn.pack(fill="x", padx=14, pady=(0, 12))
            tk.Label(side, text="Решение сохраняется в БД и файлы operator_packet_labels.jsonl/csv для последующего переобучения.", bg=CARD, fg=MUTED, font=("Arial", 10), wraplength=260, justify="left").pack(anchor="w", padx=14, pady=(0, 16))
            set_buttons_enabled(False)
            tree.bind("<<TreeviewSelect>>", refresh_side)

        def on_packet_table_click(event):
            if not incident_is_anomaly:
                return
            if tree.identify_region(event.x, event.y) != "cell":
                return
            row_id = tree.identify_row(event.y)
            column = tree.identify_column(event.x)
            # In anomalous mode columns are: #1 Mark, #2 Reason, #3 Operator, #4 Final, ...
            if not row_id or column != "#2":
                return
            row = find_row(int(row_id))
            if row and row.get("findings"):
                self.show_recommendation_window(int(row_id), row)

        tree.bind("<Button-1>", on_packet_table_click, add="+")
        tree.bind("<Double-1>", show_packet_card_popup)
        render_rows()
    def show_anomalous_packets(self, packet_features, window_stats, prob=None):
        item = {
            "id": "live",
            "time": datetime.now().isoformat(),
            "packet_count": len(packet_features),
            "packet_features": packet_features,
            "window_stats": window_stats,
            "anomaly_prob": prob or 0,
            "is_anomaly": True,
            "engine": "lstm",
        }
        self.show_details_window(item)

    def start_agent(self):
        if self.sniff_thread and self.sniff_thread.is_alive():
            self.log("Агент уже запущен", "warning")
            return
        self.stop_event.clear()
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.sniff_thread = threading.Thread(target=self.agent_loop, daemon=True)
        self.sniff_thread.start()
        self.status.config(text="Агент запущен", fg=GREEN)
        self.log("Агент запущен", "success")

    def stop_agent(self):
        self.stop_event.set()
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.status.config(text="Агент остановлен", fg=RED)
        self.log("Агент остановлен", "warning")

    def confirm_device(self):
        mac = simpledialog.askstring("Подтверждение устройства", "Введите MAC-адрес устройства:")
        if mac:
            try:
                r = requests.post(f"{SERVER_BASE}/confirm_device", json={"mac": mac.strip()}, timeout=5)
                r.raise_for_status()
                self.log(f"Устройство {mac} подтверждено", "success")
                messagebox.showinfo("Успех", "Устройство добавлено в белый список")
            except Exception as e:
                self.log(f"Не удалось подключиться к серверу: {e}", "error")

    def show_last_packets(self):
        if not self.last_packet_features:
            messagebox.showinfo("Информация", "Пока нет перехваченных пакетов. Запусти агент и подожди 20 секунд.")
            return
        self.show_details_window({
            "id": "last",
            "time": datetime.now().isoformat(),
            "packet_count": len(self.last_packet_features),
            "packet_features": self.last_packet_features,
            "window_stats": {},
            "anomaly_prob": 0,
            "is_anomaly": False,
            "engine": "local",
        })

    def on_closing(self):
        if self.sniff_thread and self.sniff_thread.is_alive():
            self.stop_agent()
        self.root.destroy()


if __name__ == "__main__":
    app = NetworkAgent()
    app.root.mainloop()
