"""Modern, user-friendly ZAPRET // NETDOCTOR desktop GUI built with clear visual hierarchy."""

from __future__ import annotations

import argparse
import ctypes
import gc
import json
import os
import queue
import re
import sys
import threading
import tkinter as tk
import traceback
import webbrowser
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any, Callable

from netdoctor.gui_backend import GuiBackend, elevate_gui
from netdoctor.supervisor import _is_admin
from netdoctor.tray import (
    NetdoctorTrayIcon,
    acquire_single_instance_mutex,
    release_single_instance_mutex,
    terminate_pid_gracefully,
)

# --------------------------------------------------------------------------------------
# Design Tokens (Midnight Slate / Fluent Dark)
# --------------------------------------------------------------------------------------

BG = "#0B0F17"
SIDEBAR_BG = "#0F1520"
CARD = "#141C2B"
CARD_ALT = "#192336"
CARD_ACTIVE = "#182840"
INFO_BG = "#112236"
INPUT = "#1B2538"
INPUT_HOVER = "#24314A"
BORDER = "#24314A"
BORDER_LIGHT = "#314263"

FG = "#F1F5F9"
FG_SOFT = "#CBD5E1"
MUTED = "#8A99B0"
DIM = "#5E6E85"

ACCENT = "#38BDF8"
PRIMARY_BG = "#0284C7"
PRIMARY_HOVER = "#0EA5E9"
SELECT_BG = "#1E3A5F"

OK = "#22C55E"
OK_TEXT = "#4ADE80"
OK_BG = "#112A20"
OK_BTN = "#16A34A"
OK_BTN_HOVER = "#22C55E"

WARN = "#F59E0B"
WARN_TEXT = "#FBBF24"
WARN_BG = "#2A2010"
WARN_BTN = "#D97706"
WARN_BTN_HOVER = "#F59E0B"

ERR = "#EF4444"
ERR_TEXT = "#F87171"
ERR_BG = "#2D1519"
ERR_BTN = "#DC2626"
ERR_BTN_HOVER = "#EF4444"

PURPLE = "#A78BFA"
PURPLE_BG = "#211A38"

FONT_UI = ("Segoe UI", 10)
FONT_UI_B = ("Segoe UI", 10, "bold")
FONT_HERO = ("Segoe UI", 13, "bold")
FONT_H2 = ("Segoe UI", 11, "bold")
FONT_SMALL = ("Segoe UI", 9)
FONT_SMALL_B = ("Segoe UI", 9, "bold")
FONT_MICRO = ("Segoe UI", 8, "bold")
FONT_TITLE = ("Segoe UI", 13, "bold")
FONT_MONO = ("Consolas", 10)
FONT_MONO_S = ("Consolas", 9)

LAYER_FILTERS = ("ALL", "dpi", "vpn", "dns", "direct")
LAYER_FILTER_LABELS: dict[str, str] = {
    "ALL": "Все",
    "dpi": "DPI",
    "dns": "DNS",
    "vpn": "VPN",
    "direct": "Напрямую",
}
OVERRIDE_LAYERS = ("dpi", "vpn", "dns", "direct")
OVERRIDE_LAYER_HINTS: dict[str, str] = {
    "dpi": "Быстрый обход через winws2 на полной скорости без VPN.",
    "dns": "Направить сайт через выбранный персональный DNS-резолвер.",
    "vpn": "Пустить сайт через защищённый VPN-туннель sing-box.",
    "direct": "Открывать напрямую без обхода и без VPN.",
}

LOG_FILES = ("winws2.log", "sing-box.log", "tg-ws-proxy.log")
PROCESS_LEDS: tuple[tuple[str, str], ...] = (
    ("winws2", "winws2.exe"),
    ("sing-box", "sing-box.exe"),
    ("tg-ws-proxy", "tg-ws-proxy"),
)

DOMAIN_COLUMNS: tuple[tuple[str, str, int, str], ...] = (
    ("domain", "Сайт / Домен", 190, "w"),
    ("protocol", "Прот.", 62, "center"),
    ("verdicts", "Причина блокировки", 135, "w"),
    ("layer", "Слой", 64, "center"),
    ("strategy", "Подобранная стратегия", 175, "w"),
    ("test", "Тест", 88, "center"),
    ("success", "Успех %", 92, "center"),
    ("sockets", "Сокеты", 78, "center"),
    ("fallback", "Запасные", 120, "w"),
    ("ttfb", "Пинг (ms)", 74, "e"),
    ("updated", "Обновлено", 108, "center"),
)

PRESET_COLUMNS: tuple[tuple[str, str, int, str], ...] = (
    ("name", "Название пресета", 250, "w"),
    ("source", "Источник", 105, "center"),
    ("status", "Статус", 115, "center"),
    ("success", "Успех %", 90, "center"),
    ("description", "Описание", 300, "w"),
)

CONN_COLUMNS: tuple[tuple[str, str, int, str], ...] = (
    ("process", "Приложение", 145, "w"),
    ("domain", "Сайт / Домен", 205, "w"),
    ("remote", "IP:Порт", 150, "w"),
    ("protocol", "Протокол", 74, "center"),
    ("socket", "Сокет", 95, "center"),
    ("layer", "Слой", 72, "center"),
    ("strategy", "Стратегия", 185, "w"),
    ("health", "Состояние", 145, "center"),
)

SERVICE_ACTIONS: tuple[tuple[str, str], ...] = (
    ("layers", "Замерить задержку всех слоёв"),
    ("reload", "Перезагрузить winws2 (Hot-Reload)"),
    ("reload_sb", "Перезагрузить sing-box"),
    ("reval", "Проверить решения (Канарейка)"),
    ("gen", "Пересобрать конфиги"),
    ("verify", "Проверить целостность файлов"),
)

VERDICT_EXPLANATIONS: dict[str, str] = {
    "ok": "Доступен напрямую — блокировок не обнаружено",
    "sni_dpi": "Блокировка HTTPS по имени сайта (SNI DPI)",
    "throttle": "Искусственное замедление скорости провайдером (TSPU)",
    "quic_block": "Блокировка быстрого протокола HTTP/3 (QUIC)",
    "dns_poison": "Подмена DNS-ответа провайдером",
    "ip_block": "Полная блокировка доступа по IP-адресу",
    "protocol_block": "Блокировка VPN / туннельного протокола",
    "unknown": "Таймаут или неизвестная сетевая ошибка",
}

_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_DOH_CERT_ERR_RE = re.compile(
    r"cannot validate certificate for ([0-9a-fA-F:.]+) because it doesn't contain any IP SANs",
    re.IGNORECASE,
)


# --------------------------------------------------------------------------------------
# Headless controller (backward compatible)
# --------------------------------------------------------------------------------------


class NetdoctorController:
    """Controller bridging GUI actions and the underlying netdoctor storage/config/supervisor API."""

    def __init__(
        self,
        db_path: str | Path = "netdoctor.db",
        configs_dir: str | Path = "configs",
        lists_dir: str | Path = "lists",
        logs_dir: str | Path = "logs",
        bin_dir: str | Path = "bin",
    ) -> None:
        self.db_path = Path(db_path)
        self.configs_dir = Path(configs_dir)
        self.lists_dir = Path(lists_dir)
        self.logs_dir = Path(logs_dir)
        self.bin_dir = Path(bin_dir)
        self.backend = GuiBackend(
            db_path=self.db_path,
            configs_dir=self.configs_dir,
            lists_dir=self.lists_dir,
            logs_dir=self.logs_dir,
            bin_dir=self.bin_dir,
        )

    def get_status_snapshot(self) -> dict[str, Any]:
        return self.backend.get_status_snapshot()

    def trigger_apply_configs(self) -> dict[str, Any]:
        return self.backend.trigger_apply_configs()

    def trigger_stop(self) -> list[str]:
        return self.backend.stop_services()

    def trigger_revalidate(self) -> dict[str, Any]:
        return self.backend.trigger_revalidate()


# --------------------------------------------------------------------------------------
# Pure formatting & filtering helpers
# --------------------------------------------------------------------------------------


def normalize_domain(text: str) -> str:
    """Strip scheme/path/port/whitespace from user input and lowercase the host."""
    value = text.strip().lower()
    for prefix in ("https://", "http://"):
        if value.startswith(prefix):
            value = value[len(prefix) :]
    value = value.split("/", 1)[0].split("?", 1)[0]
    if value.count(":") == 1:
        value = value.split(":", 1)[0]
    return value.strip(". ")


def format_updated(value: Any) -> str:
    if not value:
        return ""
    try:
        return datetime.fromisoformat(str(value)).strftime("%m-%d %H:%M:%S")
    except ValueError:
        return str(value)[:19]


def _num(value: Any, digits: int = 0) -> str:
    if value is None or value == "":
        return "—"
    try:
        return f"{float(value):.{digits}f}"
    except (TypeError, ValueError):
        return str(value)


def row_iid(row: dict[str, Any]) -> str:
    return f"{row.get('domain', '')}|{row.get('protocol', '')}"


def conn_iid(conn: dict[str, Any]) -> str:
    return f"{conn.get('process', '')}|{conn.get('remote', '')}|{conn.get('protocol', '')}"


def row_matches(row: dict[str, Any], needle: str, layer_filter: str) -> bool:
    if layer_filter and layer_filter != "ALL" and str(row.get("layer", "")).lower() != layer_filter.lower():
        return False
    needle = needle.strip().lower()
    return not needle or needle in str(row.get("domain", "")).lower()


def row_tag(row: dict[str, Any]) -> str:
    status = str(row.get("status", "active")).lower()
    if status == "expired":
        return "expired"
    if status == "degraded" or int(row.get("consecutive_fails") or 0) > 0:
        return "degraded"
    layer = str(row.get("layer", "")).lower()
    return layer if layer in ("dpi", "vpn", "dns", "direct") else "other"


def dumps_pretty(data: Any) -> str:
    if isinstance(data, dict):
        data = {k: v for k, v in data.items() if k != "winws2_args"}
    return json.dumps(data, indent=2, ensure_ascii=False, default=str)


def strip_ansi(text: str) -> str:
    """Remove ANSI CSI color escape sequences from log lines."""
    return _ANSI_ESCAPE_RE.sub("", text)


def verdict_human_label(verdict: str) -> str:
    """Return a plain-Russian description alongside technical verdict identifier."""
    clean = str(verdict or "").strip().lower()
    desc = VERDICT_EXPLANATIONS.get(clean)
    return f"{desc} ({clean})" if desc else clean


def detect_log_alert(log_name: str, text: str) -> str | None:
    """Detect well-known actionable errors in service logs and surface a clear UI hint."""
    if log_name != "sing-box.log" or not text:
        return None
    m = _DOH_CERT_ERR_RE.search(text)
    if m:
        ip = m.group(1)
        return (
            f"DoH-сервер {ip} отклонил TLS-сертификат (нет IP SAN). "
            "Откройте «DNS и нейросети» и выберите другой DNS (например Comss DNS или Control D)."
        )
    return None


def format_probe_lines(probes: dict[str, Any]) -> list[tuple[str, str, str]]:
    """Return (label, text, status) tuples; status in {'ok', 'bad', 'muted'}."""

    def st(val: Any) -> str:
        v = str(val)
        if v == "ok":
            return "ok"
        if v in ("skipped", "—", "None", ""):
            return "muted"
        return "bad"

    out: list[tuple[str, str, str]] = []
    dns = probes.get("dns") or {}
    if dns:
        bad = st(dns.get("system")) == "bad" or st(dns.get("doh")) == "bad"
        out.append(
            (
                "DNS",
                f"system={dns.get('system', '—')}  doh={dns.get('doh', '—')}  "
                f"ips={','.join(dns.get('doh_ips') or dns.get('system_ips') or []) or '—'}",
                "bad" if bad else "ok",
            )
        )
    tcp = probes.get("tcp") or {}
    if tcp:
        out.append(
            (
                "TCP",
                f"{tcp.get('result', '—')}  rtt={_num(tcp.get('rtt_ms'), 1)} ms  ip={tcp.get('target_ip') or '—'}",
                st(tcp.get("result")),
            )
        )
    tls = probes.get("tls") or {}
    if tls:
        bad = st(tls.get("real_sni")) == "bad" or st(tls.get("neutral_sni")) == "bad"
        out.append(
            (
                "TLS",
                f"real SNI={tls.get('real_sni', '—')}  neutral SNI={tls.get('neutral_sni', '—')}  "
                f"ttfb={_num(tls.get('ttfb_ms'), 0)} ms",
                "bad" if bad else "ok",
            )
        )
    stall = probes.get("stall") or {}
    if stall:
        out.append(
            (
                "Stall",
                f"{stall.get('result', '—')}  bytes={stall.get('bytes_read', 0)}  "
                f"speed={_num(stall.get('throughput_kbps'), 0)} kbps",
                st(stall.get("result")),
            )
        )
    quic = probes.get("quic") or {}
    if quic:
        out.append(("QUIC", f"{quic.get('result', '—')}  rtt={_num(quic.get('rtt_ms'), 1)} ms", st(quic.get("result"))))
    tun = probes.get("protocol_tunnel") or {}
    if tun and str(tun.get("result", "skipped")) != "skipped":
        out.append(("Tunnel", f"{tun.get('result')}  {tun.get('detail', '')}", st(tun.get("result"))))
    return out


# --------------------------------------------------------------------------------------
# Main application
# --------------------------------------------------------------------------------------


def _ensure_windows_tcl_env() -> None:
    """Resolve non-ASCII Windows TCL_LIBRARY / TK_LIBRARY paths to 8.3 short paths.

    Prevents intermittent ``tk.TclError: couldn't read file ".../init.tcl"`` on
    repeated Tk root creations under Windows user profiles with non-ASCII chars.
    """
    gc.collect()
    if os.name != "nt":
        return
    tcl_root = Path(sys.base_prefix) / "tcl"
    if not tcl_root.is_dir():
        return
    try:
        get_short = ctypes.windll.kernel32.GetShortPathNameW
    except Exception:  # noqa: BLE001
        return

    def _to_short(p: Path) -> str:
        raw = str(p)
        buf = ctypes.create_unicode_buffer(32768)
        res = get_short(raw, buf, len(buf))
        return buf.value if res else raw

    for env_key, subdir in (("TCL_LIBRARY", "tcl8.6"), ("TK_LIBRARY", "tk8.6")):
        candidate = tcl_root / subdir
        if candidate.is_dir():
            os.environ[env_key] = _to_short(candidate)


class NetdoctorGuiApp(tk.Tk):
    """Modern, self-explanatory ZAPRET // NETDOCTOR desktop control panel.

    ``auto_start=False`` skips background refresh timers and initial snapshot loading
    (used in unit tests).
    """

    SNAPSHOT_INTERVAL_MS = 5000
    LOG_INTERVAL_MS = 2000
    REALTIME_INTERVAL_MS = 3000

    def __init__(
        self,
        backend: GuiBackend | None = None,
        *,
        auto_start: bool = True,
        minimized: bool = False,
        auto_start_stack: bool = False,
        enable_tray: bool | None = None,
        db_path: str | Path = "netdoctor.db",
        configs_dir: str | Path = "configs",
        lists_dir: str | Path = "lists",
        logs_dir: str | Path = "logs",
        bin_dir: str | Path = "bin",
    ) -> None:
        _ensure_windows_tcl_env()
        super().__init__()
        self.backend = backend or GuiBackend(
            db_path=db_path,
            configs_dir=configs_dir,
            lists_dir=lists_dir,
            logs_dir=logs_dir,
            bin_dir=bin_dir,
        )
        self.title("ZAPRET // NETDOCTOR")
        self.geometry("1280x840")
        self.minsize(1040, 700)
        self.configure(bg=BG)

        self.all_rows: list[dict[str, Any]] = []
        self.rows_by_iid: dict[str, dict[str, Any]] = {}
        self.selected_row: dict[str, Any] | None = None
        self._inspector_sig: tuple[Any, ...] | None = None
        self.live_connections: list[dict[str, Any]] = []
        self.conns_by_iid: dict[str, dict[str, Any]] = {}
        self.selected_conn: dict[str, Any] | None = None
        self._last_conn_events: list[dict[str, Any]] | None = None
        self.conn_health_filter: str = "ALL"
        self.catalog: list[dict[str, Any]] = []
        self.dns_catalog: list[dict[str, Any]] = []
        self.active_dns_id: str = "cloudflare"
        self.dns_category_filter: str = "ALL"
        self._dns_signature = ""
        self._dns_cat_buttons: dict[str, tk.Button] = {}
        self._domain_filter_buttons: dict[str, tk.Button] = {}
        self._conn_filter_buttons: dict[str, tk.Button] = {}
        self._preset_filter_buttons: dict[str, tk.Button] = {}
        self._nav_items: dict[str, tuple[tk.Frame, tk.Frame, tk.Label, tk.Label, tk.Label]] = {}
        self.last_snapshot: dict[str, Any] = {}
        self.config_previews: dict[str, str] = {}
        self._vpn_signature = ""
        self._vpn_nodes_by_iid: dict[str, dict[str, Any]] = {}
        self.zapret_presets: list[dict[str, Any]] = []
        self.presets_by_iid: dict[str, dict[str, Any]] = {}
        self.selected_preset: dict[str, Any] | None = None
        self.active_preset_id: str = "auto"
        self.active_preset_name: str = "Авто-оркестратор (подбор по доменам)"
        self.preset_filter: str = "ALL"
        self._home_preset_label_to_id: dict[str, str] = {}
        self._home_preset_id_to_label: dict[str, str] = {}
        self._domains_subview_mode: str = "domains"
        self._busy = 0
        self._closed = False
        self._exiting = False
        self._unlocker_custom_synced = False
        self._refreshing = False
        self._log_refreshing = False
        self._rt_busy = False
        self.radar_enabled = True
        self._sort_state: tuple[str, bool] = ("domain", False)
        self._sock_counts: dict[str, int] = {}
        self._last_preset_err_shown: str = ""
        self._post_queue: queue.Queue[tuple[Callable[..., Any], tuple[Any, ...]]] = queue.Queue()
        self._active_bg_labels: set[str] = set()
        self._tray: NetdoctorTrayIcon | None = None
        self._icon_image: tk.PhotoImage | None = None
        self._guide_visible = True

        self.minimize_to_tray_var = tk.BooleanVar(value=True)
        self.autostart_var = tk.BooleanVar(value=False)
        self.byedpi_var = tk.BooleanVar(value=False)
        self.debug_log_var = tk.BooleanVar(value=False)
        self.dpi_only_var = tk.BooleanVar(value=False)
        self.tun_stack_var = tk.StringVar(value="gvisor")

        self._apply_window_chrome(enable_dark=auto_start and not minimized)
        self._build_style()
        self._build_statusbar()
        self._build_shell()

        use_tray = enable_tray if enable_tray is not None else auto_start
        if use_tray:
            try:
                self._tray = NetdoctorTrayIcon(
                    on_show=lambda: self._post(self.show_from_tray),
                    on_toggle_protection=lambda: self._post(self.on_toggle_autopilot),
                    on_rotate_vpn=lambda: self._post(self.on_rotate_vpn_node),
                    on_flush_dns=lambda: self._post(self.on_flush_dns),
                    on_exit=lambda: self._post(self.on_exit_app),
                )
                self._tray.start()
            except Exception:  # noqa: BLE001
                self._tray = None

        self.protocol("WM_DELETE_WINDOW", self.on_window_delete)
        self.bind("<F5>", lambda _e: self.refresh_async())
        self.bind("<Control-f>", self._on_shortcut_search)
        self.bind("<Control-F>", self._on_shortcut_search)
        self.bind_all("<Control-KeyPress>", self._on_ctrl_keypress_non_ascii, add="+")
        if auto_start or use_tray:
            self.after(40, self._drain_post_queue)
        if auto_start:
            if minimized:
                self.withdraw()
            self.refresh_async()
            self.load_catalog_async()
            self.load_zapret_presets_async()
            self.load_dns_catalog_async()
            self.refresh_previews_async()
            self.refresh_realtime_async()
            self._load_autostart_async()
            self.after(self.SNAPSHOT_INTERVAL_MS, self._snapshot_tick)
            self.after(self.LOG_INTERVAL_MS, self._log_tick)
            self.after(self.REALTIME_INTERVAL_MS, self._realtime_tick)
            if auto_start_stack:
                self.after(350, self.on_start)

    # ---------------------------------------------------------------- window chrome & lifecycle

    def _apply_window_chrome(self, *, enable_dark: bool) -> None:
        ico_path = Path(__file__).with_name("netdoctor.ico")
        if sys.platform == "win32" and ico_path.is_file():
            try:
                self.iconbitmap(default=str(ico_path))
            except tk.TclError:
                pass
        # Custom crisp 16x16 shield-dot icon so Windows titlebar doesn't show legacy Tk feather
        try:
            img = tk.PhotoImage(width=16, height=16)
            img.put(BG, to=(0, 0, 16, 16))
            for y in range(2, 14):
                half = 5 if y < 8 else max(1, 13 - y)
                x0, x1 = 8 - half, 8 + half
                img.put(PRIMARY_BG, to=(x0, y, x1, y + 1))
            img.put(ACCENT, to=(6, 5, 10, 9))
            img.put(OK, to=(7, 6, 9, 8))
            self._icon_image = img
            self.iconphoto(True, img)
        except tk.TclError:
            pass

        if enable_dark and sys.platform == "win32":
            try:
                self.update_idletasks()
                hwnd = ctypes.windll.user32.GetParent(self.winfo_id())
                if hwnd:
                    val = ctypes.c_int(1)
                    for attr in (20, 19):
                        ctypes.windll.dwmapi.DwmSetWindowAttribute(
                            hwnd, attr, ctypes.byref(val), ctypes.sizeof(val)
                        )
            except Exception:  # noqa: BLE001
                pass

    def _is_window_hidden(self) -> bool:
        try:
            return self.state() == "withdrawn"
        except tk.TclError:
            return False

    def show_from_tray(self) -> None:
        if self._closed:
            return
        try:
            self.deiconify()
            self.lift()
            self.focus_force()
        except tk.TclError:
            pass
        self.refresh_async()

    def on_window_delete(self) -> None:
        if self._tray is not None and self.minimize_to_tray_var.get():
            try:
                self.withdraw()
                self.set_status("netdoctor свёрнут в системный трей — защита продолжает работать", ACCENT)
            except tk.TclError:
                pass
            return
        self.on_exit_app()

    def on_exit_app(self) -> None:
        """Stop all supervised bypass services and exit completely (invoked from tray / Exit button)."""
        if self._exiting or self._closed:
            return
        self._exiting = True

        def _stop_then_close() -> None:
            try:
                self.backend.stop_services()
            except Exception:  # noqa: BLE001
                pass
            self._post(self.on_close)

        threading.Thread(target=_stop_then_close, name="gui-exit", daemon=True).start()

    def _on_shortcut_search(self, _event: Any = None) -> str:
        try:
            self._select_tab(self.tab_domains)
            if hasattr(self, "search_entry"):
                self.search_entry.focus_set()
                self.search_entry.select_range(0, "end")
        except tk.TclError:
            pass
        return "break"

    @staticmethod
    def _is_widget_readonly_or_disabled(widget: Any) -> bool:
        if isinstance(widget, ttk.Widget):
            try:
                return bool(widget.instate(["disabled"]) or widget.instate(["readonly"]))
            except tk.TclError:
                return False
        try:
            return str(widget.cget("state")) in ("disabled", "readonly")
        except tk.TclError:
            return False

    def _on_ctrl_keypress_non_ascii(self, event: Any) -> str | None:
        """Handle standard Ctrl shortcuts (V/C/X/A/Z/Y/F) when a non-Latin layout (e.g. Russian) is active."""
        if self._closed:
            return None
        state = int(getattr(event, "state", 0) or 0)
        # Skip Alt/AltGr combos
        if state & 0x20000:
            return None
        keysym = str(getattr(event, "keysym", "") or "")
        # Let Tk's native ASCII bindings handle English/Latin layouts to avoid double-triggering
        if len(keysym) == 1 and keysym.isascii():
            return None

        kc = int(getattr(event, "keycode", 0) or 0)
        if kc == 70:  # Ctrl+F
            return self._on_shortcut_search(event)

        widget = getattr(event, "widget", None)
        if not isinstance(widget, (tk.Entry, ttk.Entry, ttk.Combobox, tk.Text)):
            return None

        ro = self._is_widget_readonly_or_disabled(widget)
        is_text = isinstance(widget, tk.Text)

        if kc == 86:  # Ctrl+V (Paste)
            if not ro:
                try:
                    clip = str(widget.clipboard_get() or "")
                except tk.TclError:
                    clip = ""
                if clip:
                    if is_text:
                        try:
                            widget.delete("sel.first", "sel.last")
                        except tk.TclError:
                            pass
                        widget.insert("insert", clip)
                        widget.see("insert")
                    else:
                        clean_clip = clip.replace("\r\n", " ").replace("\r", " ").replace("\n", " ")
                        try:
                            if widget.selection_present():
                                widget.delete("sel.first", "sel.last")
                        except tk.TclError:
                            pass
                        widget.insert("insert", clean_clip)
            return "break"

        if kc == 67:  # Ctrl+C (Copy — works on readonly/disabled widgets too)
            try:
                if is_text:
                    sel_text = widget.get("sel.first", "sel.last")
                elif widget.selection_present():
                    first = int(widget.index("sel.first"))
                    last = int(widget.index("sel.last"))
                    sel_text = str(widget.get())[first:last]
                else:
                    sel_text = ""
                if sel_text:
                    widget.clipboard_clear()
                    widget.clipboard_append(sel_text)
            except tk.TclError:
                pass
            return "break"

        if kc == 88:  # Ctrl+X (Cut)
            if not ro:
                try:
                    if is_text:
                        sel_text = widget.get("sel.first", "sel.last")
                        if sel_text:
                            widget.clipboard_clear()
                            widget.clipboard_append(sel_text)
                            widget.delete("sel.first", "sel.last")
                    elif widget.selection_present():
                        first = int(widget.index("sel.first"))
                        last = int(widget.index("sel.last"))
                        sel_text = str(widget.get())[first:last]
                        if sel_text:
                            widget.clipboard_clear()
                            widget.clipboard_append(sel_text)
                            widget.delete("sel.first", "sel.last")
                except tk.TclError:
                    pass
            return "break"

        if kc == 65:  # Ctrl+A (Select All)
            try:
                if is_text:
                    widget.tag_add("sel", "1.0", "end-1c")
                    widget.mark_set("insert", "end-1c")
                else:
                    widget.select_range(0, "end")
                    widget.icursor("end")
            except tk.TclError:
                pass
            return "break"

        if kc in (89, 90) and is_text:  # Ctrl+Z / Ctrl+Y / Ctrl+Shift+Z (Undo / Redo)
            if not ro:
                try:
                    if kc == 89 or (kc == 90 and bool(state & 0x1)):
                        widget.edit_redo()
                    else:
                        widget.edit_undo()
                except tk.TclError:
                    pass
            return "break"

        return None

    def on_close(self) -> None:
        self._closed = True
        if self._tray is not None:
            try:
                self._tray.stop()
            except Exception:  # noqa: BLE001
                pass
            self._tray = None
        try:
            self.dns_canvas.unbind_all("<MouseWheel>")
            self.unbind_all("<Control-KeyPress>")
        except tk.TclError:
            pass
        self._icon_image = None
        try:
            self.destroy()
        except tk.TclError:
            pass
        gc.collect()

    def _drain_post_queue(self) -> None:
        if self._closed:
            return
        while True:
            try:
                fn, args = self._post_queue.get_nowait()
            except queue.Empty:
                break
            try:
                fn(*args)
            except Exception:  # noqa: BLE001
                pass
        if not self._closed:
            try:
                self.after(40, self._drain_post_queue)
            except tk.TclError:
                pass

    def _post(self, fn: Callable[..., Any], *args: Any) -> None:
        """Marshal a call onto the Tk main loop from any thread safely via queue."""
        if self._closed:
            return
        if threading.current_thread() is threading.main_thread():
            try:
                fn(*args)
            except tk.TclError:
                pass
            return
        self._post_queue.put((fn, args))

    def run_bg(
        self,
        label: str,
        work: Callable[[], Any],
        on_ok: Callable[[Any], None] | None = None,
        on_err: Callable[[Exception], None] | None = None,
    ) -> threading.Thread:
        """Run ``work`` in a daemon thread; deduplicate identical in-flight tasks."""
        if label in self._active_bg_labels:
            self.set_status(f"Уже выполняется: {label}…", WARN_TEXT)
            t = threading.Thread(target=lambda: None, daemon=True)
            t.start()
            return t

        self._active_bg_labels.add(label)
        self._busy += 1
        self.set_status(f"Выполняется: {label}…", ACCENT)
        self._progress_update()

        def runner() -> None:
            try:
                result = work()
            except Exception as exc:  # noqa: BLE001
                self._post(self._bg_failed, label, exc, on_err)
            else:
                self._post(self._bg_done, label, result, on_ok)

        thread = threading.Thread(target=runner, name=f"gui-{label[:20]}", daemon=True)
        thread.start()
        return thread

    def _bg_done(self, label: str, result: Any, on_ok: Callable[[Any], None] | None) -> None:
        self._active_bg_labels.discard(label)
        self._busy = max(0, self._busy - 1)
        self._progress_update()
        self.set_status(f"Готово: {label}", OK_TEXT)
        if on_ok is not None:
            try:
                on_ok(result)
            except Exception as exc:  # noqa: BLE001
                self.set_status(f"Ошибка обработки ({label}): {exc}", ERR_TEXT)

    def _bg_failed(self, label: str, exc: Exception, on_err: Callable[[Exception], None] | None) -> None:
        self._active_bg_labels.discard(label)
        self._busy = max(0, self._busy - 1)
        self._progress_update()
        self.set_status(f"Ошибка ({label}): {exc}", ERR_TEXT)
        self.log_console(f"[ERROR] {label}: {exc}")
        if on_err is not None:
            try:
                on_err(exc)
            except Exception:  # noqa: BLE001
                pass

    def _progress_update(self) -> None:
        if self._busy > 0:
            if not self.progress.winfo_manager():
                self.progress.pack(side="right", padx=12, pady=5)
            self.progress.start(12)
        else:
            self.progress.stop()
            self.progress.pack_forget()

    def set_status(self, text: str, color: str = FG_SOFT) -> None:
        self.status_var.set(text)
        self.status_label.configure(fg=color)

    def log_console(self, text: str) -> None:
        stamp = datetime.now().strftime("%H:%M:%S")
        self.console.configure(state="normal")
        self.console.insert("end", f"[{stamp}] ", "muted")
        tag = "bad" if "[ERROR]" in text or "ошибка" in text.lower() else ("ok" if "готово" in text.lower() else "")
        self.console.insert("end", f"{text}\n", tag)
        self.console.see("end")
        self.console.configure(state="disabled")

    # ---------------------------------------------------------------- style & reusable primitives

    def _build_style(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(".", background=BG, foreground=FG, fieldbackground=INPUT, bordercolor=BORDER, font=FONT_UI)
        style.configure("TFrame", background=BG)
        style.configure("TLabel", background=BG, foreground=FG)

        # Hidden-tab notebook so left sidebar drives navigation cleanly while preserving ttk.Notebook API
        style.layout("NavHidden.TNotebook", [("Notebook.client", {"sticky": "nswe"})])
        style.layout("NavHidden.TNotebook.Tab", [])
        style.configure(
            "NavHidden.TNotebook",
            background=BG,
            borderwidth=0,
            tabmargins=0,
            lightcolor=BG,
            darkcolor=BG,
            bordercolor=BG,
        )

        style.configure(
            "Treeview",
            background=CARD,
            fieldbackground=CARD,
            foreground=FG,
            rowheight=30,
            bordercolor=BORDER,
            borderwidth=0,
            lightcolor=CARD,
            darkcolor=CARD,
            font=FONT_UI,
        )
        style.configure(
            "Treeview.Heading",
            background=SIDEBAR_BG,
            foreground=FG_SOFT,
            relief="flat",
            font=FONT_SMALL_B,
            padding=(8, 7),
            bordercolor=BORDER,
            lightcolor=SIDEBAR_BG,
            darkcolor=SIDEBAR_BG,
        )
        style.map(
            "Treeview",
            background=[("selected", SELECT_BG)],
            foreground=[("selected", "#FFFFFF")],
        )
        style.map("Treeview.Heading", background=[("active", INPUT)])

        for orient in ("Vertical", "Horizontal"):
            style.configure(
                f"{orient}.TScrollbar",
                background=INPUT,
                troughcolor=BG,
                bordercolor=BG,
                arrowcolor=MUTED,
                lightcolor=INPUT,
                darkcolor=INPUT,
                gripcount=0,
            )
            style.map(f"{orient}.TScrollbar", background=[("active", BORDER_LIGHT)])

        style.configure(
            "TCombobox",
            fieldbackground=INPUT,
            background=INPUT,
            foreground=FG,
            arrowcolor=ACCENT,
            bordercolor=BORDER,
            lightcolor=INPUT,
            darkcolor=INPUT,
            selectbackground=INPUT,
            selectforeground=FG,
            padding=5,
        )
        style.map(
            "TCombobox",
            fieldbackground=[("readonly", INPUT)],
            foreground=[("readonly", FG)],
            selectbackground=[("readonly", INPUT)],
            selectforeground=[("readonly", FG)],
        )
        style.configure("TPanedwindow", background=BG)
        style.configure("Sash", sashthickness=6, background=BG, lightcolor=BORDER, darkcolor=BORDER)
        style.configure(
            "Horizontal.TProgressbar",
            background=ACCENT,
            troughcolor=INPUT,
            bordercolor=BG,
            lightcolor=ACCENT,
            darkcolor=ACCENT,
        )

        self.option_add("*TCombobox*Listbox.background", INPUT)
        self.option_add("*TCombobox*Listbox.foreground", FG)
        self.option_add("*TCombobox*Listbox.selectBackground", SELECT_BG)
        self.option_add("*TCombobox*Listbox.selectForeground", "#FFFFFF")
        self.option_add("*TCombobox*Listbox.font", FONT_UI)

    @staticmethod
    def _button_palette(kind: str) -> tuple[str, str, str, str, str]:
        palettes: dict[str, tuple[str, str, str, str, str]] = {
            "neutral": (INPUT, FG, INPUT_HOVER, BORDER, BORDER_LIGHT),
            "ghost": (CARD, FG_SOFT, CARD_ALT, BORDER, BORDER_LIGHT),
            "primary": (PRIMARY_BG, "#FFFFFF", PRIMARY_HOVER, "#0369A1", ACCENT),
            "success": (OK_BTN, "#FFFFFF", OK_BTN_HOVER, "#15803D", OK_TEXT),
            "danger": (ERR_BTN, "#FFFFFF", ERR_BTN_HOVER, "#B91C1C", ERR_TEXT),
            "warn": (WARN_BTN, "#FFFFFF", WARN_BTN_HOVER, "#B45309", WARN_TEXT),
        }
        return palettes.get(kind, palettes["neutral"])

    def make_button(
        self,
        parent: tk.Misc,
        text: str,
        command: Callable[[], Any],
        kind: str = "neutral",
        width: int | None = None,
        font: tuple[Any, ...] = FONT_UI_B,
        padx: int = 12,
        pady: int = 6,
    ) -> tk.Button:
        bg, fg, hover, border, border_hover = self._button_palette(kind)
        btn = tk.Button(
            parent,
            text=text,
            command=command,
            bg=bg,
            fg=fg,
            activebackground=hover,
            activeforeground=fg,
            relief="flat",
            bd=0,
            padx=padx,
            pady=pady,
            font=font,
            cursor="hand2",
            highlightthickness=1,
            highlightbackground=border,
        )
        btn._netdoc_palette = (bg, fg, hover, border, border_hover)  # type: ignore[attr-defined]
        if width:
            btn.configure(width=width)
        btn.bind("<Enter>", lambda _e, b=btn: b.configure(bg=b._netdoc_palette[2], highlightbackground=b._netdoc_palette[4]))  # type: ignore[attr-defined]
        btn.bind("<Leave>", lambda _e, b=btn: b.configure(bg=b._netdoc_palette[0], highlightbackground=b._netdoc_palette[3]))  # type: ignore[attr-defined]
        return btn

    @classmethod
    def _restyle_button(cls, btn: tk.Button, text: str, kind: str) -> None:
        bg, fg, hover, border, border_hover = cls._button_palette(kind)
        btn._netdoc_palette = (bg, fg, hover, border, border_hover)  # type: ignore[attr-defined]
        btn.configure(
            text=text,
            bg=bg,
            fg=fg,
            activebackground=hover,
            activeforeground=fg,
            highlightbackground=border,
        )

    def make_entry(self, parent: tk.Misc, textvariable: tk.StringVar, width: int = 24) -> tk.Entry:
        return tk.Entry(
            parent,
            textvariable=textvariable,
            width=width,
            bg=INPUT,
            fg=FG,
            insertbackground=ACCENT,
            relief="flat",
            highlightthickness=1,
            highlightbackground=BORDER,
            highlightcolor=ACCENT,
            font=FONT_UI,
            disabledbackground=INPUT,
        )

    def make_text(self, parent: tk.Misc, height: int = 10, wrap: str = "none") -> tk.Text:
        return tk.Text(
            parent,
            width=30,
            height=height,
            wrap=wrap,
            bg=SIDEBAR_BG,
            fg=FG_SOFT,
            insertbackground=ACCENT,
            relief="flat",
            highlightthickness=0,
            font=FONT_MONO,
            padx=10,
            pady=8,
            selectbackground=SELECT_BG,
            selectforeground="#FFFFFF",
            state="disabled",
        )

    def make_tree(self, parent: tk.Misc, columns: tuple[str, ...], height: int = 10) -> ttk.Treeview:
        return ttk.Treeview(parent, columns=columns, show="headings", selectmode="browse", height=height)

    def _scrolled(self, parent: tk.Misc, widget: Any, horizontal: bool = False) -> None:
        vsb = ttk.Scrollbar(parent, orient="vertical", command=widget.yview)
        widget.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        if horizontal:
            hsb = ttk.Scrollbar(parent, orient="horizontal", command=widget.xview)
            widget.configure(xscrollcommand=hsb.set)
            hsb.pack(side="bottom", fill="x")
        widget.pack(side="left", fill="both", expand=True)

    @staticmethod
    def _set_text(widget: tk.Text, text: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    def _make_page_header(self, parent: tk.Misc, title: str, subtitle: str) -> tk.Frame:
        hdr = tk.Frame(parent, bg=BG)
        hdr.pack(fill="x", pady=(2, 6))
        tk.Label(hdr, text=title, bg=BG, fg=FG, font=FONT_HERO, anchor="w").pack(anchor="w")
        sub_lbl = tk.Label(hdr, text=subtitle, bg=BG, fg=MUTED, font=FONT_SMALL, anchor="w", justify="left")
        sub_lbl.pack(fill="x", anchor="w", pady=(2, 0))
        self._bind_responsive_wrap(sub_lbl, min_wrap=260, pad=16)
        return hdr

    def _bind_card_hover(
        self,
        card: tk.Frame,
        bg_widgets: list[tk.Misc],
        normal_bg: str,
        hover_bg: str,
        normal_border: str = BORDER,
        hover_border: str = ACCENT,
    ) -> None:
        def _set_state(hovered: bool) -> None:
            try:
                bg = hover_bg if hovered else normal_bg
                brd = hover_border if hovered else normal_border
                card.configure(bg=bg, highlightbackground=brd)
                for w in bg_widgets:
                    if w is not card:
                        w.configure(bg=bg)
            except tk.TclError:
                pass

        def _on_leave(_e: Any) -> None:
            try:
                px, py = self.winfo_pointerxy()
                under = self.winfo_containing(px, py)
                cur = under
                while cur is not None:
                    if cur == card:
                        return
                    cur = cur.master  # type: ignore[assignment]
            except tk.TclError:
                pass
            _set_state(False)

        for w in [card, *bg_widgets]:
            w.bind("<Enter>", lambda _e: _set_state(True), add="+")
            w.bind("<Leave>", _on_leave, add="+")

    @staticmethod
    def _bind_responsive_wrap(label: tk.Label, min_wrap: int = 160, pad: int = 28) -> None:
        def _on_cfg(event: Any) -> None:
            w = getattr(event, "width", 0)
            if w and w > 60:
                try:
                    label.configure(wraplength=max(min_wrap, w - pad))
                except tk.TclError:
                    pass

        label.bind("<Configure>", _on_cfg, add="+")

    # ---------------------------------------------------------------- statusbar & shell layout

    def _build_statusbar(self) -> None:
        bar = tk.Frame(self, bg=SIDEBAR_BG, highlightthickness=1, highlightbackground=BORDER)
        bar.pack(side="bottom", fill="x")
        self.status_var = tk.StringVar(value="Готово к работе")
        self.status_label = tk.Label(bar, textvariable=self.status_var, bg=SIDEBAR_BG, fg=FG_SOFT, font=FONT_SMALL, anchor="w")
        self.status_label.pack(side="left", fill="x", expand=True, padx=14, pady=5)
        self.progress = ttk.Progressbar(bar, mode="indeterminate", length=140)

    def _build_shell(self) -> None:
        shell = tk.Frame(self, bg=BG)
        shell.pack(fill="both", expand=True)

        self._build_sidebar(shell)

        right_col = tk.Frame(shell, bg=BG)
        right_col.pack(side="left", fill="both", expand=True)

        self._build_header(right_col)
        self._build_notebook(right_col)

    def _build_sidebar(self, parent: tk.Misc) -> None:
        sidebar = tk.Frame(parent, bg=SIDEBAR_BG, width=232)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        # Subtle vertical divider on the right edge of sidebar
        tk.Frame(parent, bg=BORDER, width=1).pack(side="left", fill="y")

        # Brand block
        brand = tk.Frame(sidebar, bg=SIDEBAR_BG)
        brand.pack(fill="x", padx=16, pady=(16, 12))
        title_row = tk.Frame(brand, bg=SIDEBAR_BG)
        title_row.pack(fill="x")
        tk.Label(title_row, text="NETDOCTOR", bg=SIDEBAR_BG, fg=FG, font=FONT_TITLE).pack(side="left")
        tk.Label(
            title_row,
            text=" ZAPRET v2 ",
            bg=INFO_BG,
            fg=ACCENT,
            font=FONT_MICRO,
            padx=5,
            pady=2,
        ).pack(side="left", padx=(8, 0))

        self.priv_label = tk.Label(
            brand,
            text="Проверка прав…",
            bg=INPUT,
            fg=MUTED,
            font=FONT_MICRO,
            anchor="w",
            padx=8,
            pady=3,
        )
        self.priv_label.pack(anchor="w", pady=(8, 0))

        tk.Frame(sidebar, bg=BORDER_LIGHT, height=1).pack(fill="x", padx=16, pady=(4, 10))

        tk.Label(sidebar, text="НАВИГАЦИЯ", bg=SIDEBAR_BG, fg=DIM, font=FONT_MICRO, anchor="w").pack(
            fill="x", padx=18, pady=(0, 6)
        )
        self._nav_container = tk.Frame(sidebar, bg=SIDEBAR_BG)
        self._nav_container.pack(fill="x", padx=10)

        # Bottom pinned process stack card
        stack_card = tk.Frame(sidebar, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
        stack_card.pack(side="bottom", fill="x", padx=12, pady=12)
        tk.Label(stack_card, text="СЛУЖБЫ ОБХОДА", bg=CARD, fg=DIM, font=FONT_MICRO, anchor="w").pack(
            fill="x", padx=10, pady=(8, 4)
        )

        self.leds: dict[str, tuple[tk.Canvas, int, tk.Label]] = {}
        for key, title in PROCESS_LEDS:
            row = tk.Frame(stack_card, bg=CARD)
            row.pack(fill="x", padx=10, pady=2)
            canvas = tk.Canvas(row, width=12, height=12, bg=CARD, highlightthickness=0)
            canvas.pack(side="left", padx=(0, 6), pady=2)
            oval = canvas.create_oval(2, 2, 10, 10, fill=ERR, outline="")
            lbl = tk.Label(row, text=title, bg=CARD, fg=MUTED, font=FONT_MONO_S, anchor="w")
            lbl.pack(side="left", fill="x", expand=True)
            self.leds[key] = (canvas, oval, lbl)
        tk.Frame(stack_card, bg=CARD, height=6).pack()

    def _build_header(self, parent: tk.Misc) -> None:
        banner = tk.Frame(parent, bg=CARD)
        banner.pack(fill="x")
        tk.Frame(parent, bg=BORDER, height=1).pack(fill="x")

        inner = tk.Frame(banner, bg=CARD)
        inner.pack(fill="x", padx=18, pady=10)

        # Right: Single unambiguous primary action cluster (packed first so left gets remaining width cleanly)
        ctrl = tk.Frame(inner, bg=CARD)
        ctrl.pack(side="right", padx=(14, 0))
        self.make_button(ctrl, "↻", self.refresh_async, kind="ghost", width=3, pady=8).pack(side="right", padx=(6, 0))
        self.autopilot_btn = self.make_button(
            ctrl,
            "Включить защиту",
            self.on_toggle_autopilot,
            "success",
            font=FONT_UI_B,
            padx=18,
            pady=8,
        )
        self.autopilot_btn.pack(side="right")
        self._priv_btn_slot = tk.Frame(ctrl, bg=CARD)
        self._priv_btn_slot.pack(side="right")
        self.priv_btn = self.make_button(
            self._priv_btn_slot,
            "Запустить от Admin",
            self.on_elevate,
            "warn",
            pady=8,
        )

        # Left: Hero status pill + network metadata on row 1, conditional bypass banner, clean wrapped hint
        left = tk.Frame(inner, bg=CARD)
        left.pack(side="left", fill="x", expand=True)

        status_row = tk.Frame(left, bg=CARD)
        status_row.pack(fill="x", anchor="w")
        self.hero_state_pill = tk.Label(
            status_row,
            text="● Остановлена",
            bg=INPUT,
            fg=MUTED,
            font=FONT_SMALL_B,
            padx=9,
            pady=3,
        )
        self.hero_state_pill.pack(side="left", padx=(0, 10))
        self.network_label = tk.Label(
            status_row, text="Сеть: определение…", bg=CARD, fg=MUTED, font=FONT_SMALL, anchor="w", justify="left"
        )
        self.network_label.pack(side="left", fill="x", expand=True)
        self._bind_responsive_wrap(self.network_label, min_wrap=150, pad=8)

        self.bypass_label = tk.Label(
            left,
            text="",
            bg=WARN_BG,
            fg=WARN_TEXT,
            font=FONT_SMALL_B,
            anchor="w",
            justify="left",
            padx=8,
            pady=2,
        )
        self._bind_responsive_wrap(self.bypass_label, min_wrap=220, pad=16)

        self.hint_label = tk.Label(
            left,
            text="Нажмите «Включить защиту» — программа подберёт обход и начнёт следить за связью.",
            bg=CARD,
            fg=FG_SOFT,
            font=FONT_SMALL,
            anchor="w",
            justify="left",
        )
        self.hint_label.pack(fill="x", anchor="w", pady=(5, 0))
        self._bind_responsive_wrap(self.hint_label, min_wrap=240, pad=16)

    def _build_notebook(self, parent: tk.Misc) -> None:
        wrap = tk.Frame(parent, bg=BG)
        wrap.pack(fill="both", expand=True, padx=16, pady=(10, 10))

        self.notebook = ttk.Notebook(wrap, style="NavHidden.TNotebook")
        self.notebook.pack(fill="both", expand=True)

        self.tab_home = ttk.Frame(self.notebook)
        self.tab_domains = ttk.Frame(self.notebook)
        self.tab_presets = ttk.Frame(self.notebook)
        self.tab_dns = ttk.Frame(self.notebook)
        self.tab_vpn = ttk.Frame(self.notebook)
        self.tab_service = ttk.Frame(self.notebook)
        # Backward-compatible alias: Live Connections is now unified inside tab_domains
        self.tab_realtime = self.tab_domains

        self.notebook.add(self.tab_home, text="Главная")
        self.notebook.add(self.tab_domains, text="Домены и Трафик")
        self.notebook.add(self.tab_presets, text="Пресеты Zapret")
        self.notebook.add(self.tab_dns, text="DNS и Нейросети")
        self.notebook.add(self.tab_vpn, text="VPN Подписки")
        self.notebook.add(self.tab_service, text="Сервис и Конфиги")

        nav_defs: tuple[tuple[ttk.Frame, str, str, str], ...] = (
            (self.tab_home, "⌂", "Главная", ""),
            (self.tab_domains, "◈", "Домены и трафик", "0/0"),
            (self.tab_presets, "✦", "Пресеты Zapret", "0"),
            (self.tab_dns, "◉", "DNS и нейросети", "36"),
            (self.tab_vpn, "⊕", "VPN и журналы", "0"),
            (self.tab_service, "⚙", "Сервис и конфиги", ""),
        )
        for tab, icon, title, badge in nav_defs:
            self._add_nav_item(tab, icon, title, badge)

        self.notebook.bind("<<NotebookTabChanged>>", lambda _e: self._sync_sidebar_selection())

        self._build_home_tab()
        self._build_domains_tab()
        self._build_presets_tab()
        self._build_dns_tab()
        self._build_vpn_tab()
        self._build_service_tab()
        self._sync_sidebar_selection()

    def _add_nav_item(self, tab: ttk.Frame, icon: str, title: str, badge_text: str) -> None:
        tab_key = str(tab)
        row = tk.Frame(self._nav_container, bg=SIDEBAR_BG, cursor="hand2")
        row.pack(fill="x", pady=2)

        indicator = tk.Frame(row, bg=SIDEBAR_BG, width=3)
        indicator.pack(side="left", fill="y")

        icon_lbl = tk.Label(row, text=icon, bg=SIDEBAR_BG, fg=MUTED, font=FONT_UI_B, width=2, anchor="center", pady=8)
        icon_lbl.pack(side="left", padx=(6, 4))

        text_lbl = tk.Label(row, text=title, bg=SIDEBAR_BG, fg=FG_SOFT, font=FONT_UI, anchor="w", pady=8)
        text_lbl.pack(side="left", fill="x", expand=True)

        badge_lbl = tk.Label(
            row,
            text=badge_text,
            bg=INPUT if badge_text else SIDEBAR_BG,
            fg=MUTED,
            font=FONT_MICRO,
            padx=6 if badge_text else 0,
            pady=1,
        )
        badge_lbl.pack(side="right", padx=(4, 8))

        self._nav_items[tab_key] = (row, indicator, icon_lbl, text_lbl, badge_lbl)

        for w in (row, indicator, icon_lbl, text_lbl, badge_lbl):
            w.bind("<Button-1>", lambda _e, t=tab: self._select_tab(t))
            w.bind("<Enter>", lambda _e, k=tab_key: self._hover_nav_item(k, True))
            w.bind("<Leave>", lambda _e, k=tab_key: self._hover_nav_item(k, False))

    def _select_tab(self, tab: ttk.Frame) -> None:
        self.notebook.select(tab)
        self._sync_sidebar_selection()

    def _hover_nav_item(self, tab_key: str, entering: bool) -> None:
        try:
            active_key = str(self.notebook.select())
        except tk.TclError:
            active_key = ""
        if tab_key == active_key or tab_key not in self._nav_items:
            return
        row, indicator, icon_lbl, text_lbl, badge_lbl = self._nav_items[tab_key]
        if not entering:
            try:
                px, py = self.winfo_pointerxy()
                cur = self.winfo_containing(px, py)
                while cur is not None:
                    if cur == row:
                        return
                    cur = cur.master  # type: ignore[assignment]
            except tk.TclError:
                pass
        bg = CARD if entering else SIDEBAR_BG
        fg = FG if entering else FG_SOFT
        try:
            row.configure(bg=bg)
            indicator.configure(bg=bg)
            icon_lbl.configure(bg=bg, fg=ACCENT if entering else MUTED)
            text_lbl.configure(bg=bg, fg=fg)
            if not badge_lbl.cget("text"):
                badge_lbl.configure(bg=bg)
        except tk.TclError:
            pass

    def _sync_sidebar_selection(self) -> None:
        try:
            active_key = str(self.notebook.select())
        except tk.TclError:
            active_key = ""
        for tab_key, (row, indicator, icon_lbl, text_lbl, badge_lbl) in self._nav_items.items():
            active = tab_key == active_key
            bg = CARD_ALT if active else SIDEBAR_BG
            try:
                row.configure(bg=bg)
                indicator.configure(bg=ACCENT if active else bg)
                icon_lbl.configure(bg=bg, fg=ACCENT if active else MUTED)
                text_lbl.configure(bg=bg, fg=FG if active else FG_SOFT, font=FONT_UI_B if active else FONT_UI)
                has_badge = bool(badge_lbl.cget("text"))
                badge_lbl.configure(
                    bg=INFO_BG if (active and has_badge) else (INPUT if has_badge else bg),
                    fg=ACCENT if active else MUTED,
                )
            except tk.TclError:
                pass

    def _update_nav_badge(self, tab: ttk.Frame, text: str) -> None:
        item = self._nav_items.get(str(tab))
        if not item:
            return
        _row, _ind, _ic, _tx, badge_lbl = item
        try:
            badge_lbl.configure(text=text, padx=6 if text else 0)
            self._sync_sidebar_selection()
        except tk.TclError:
            pass

    # ---------------------------------------------------------------- Tab 1: Главная (Dashboard)

    def _build_home_tab(self) -> None:
        tab = self.tab_home
        hdr = tk.Frame(tab, bg=BG)
        hdr.pack(fill="x", pady=(2, 5))
        tk.Label(hdr, text="Панель управления", bg=BG, fg=FG, font=FONT_HERO, anchor="w").pack(side="left")
        tk.Label(
            hdr,
            text="— включите защиту или настройте нужный сервис в один клик",
            bg=BG,
            fg=MUTED,
            font=FONT_SMALL,
            anchor="w",
        ).pack(side="left", padx=(8, 0), pady=(3, 0))

        # Compact, dismissible 1-row quick-start bar (right label packed first so left text wraps safely)
        self._home_guide_frame = tk.Frame(tab, bg=INFO_BG, highlightthickness=1, highlightbackground="#1E3A5F")
        self._home_guide_frame.pack(fill="x", pady=(0, 4))
        hide_lbl = tk.Label(
            self._home_guide_frame,
            text="Скрыть ✕",
            bg=INFO_BG,
            fg=ACCENT,
            font=FONT_SMALL_B,
            cursor="hand2",
            padx=10,
            pady=3,
        )
        hide_lbl.pack(side="right")
        hide_lbl.bind("<Button-1>", lambda _e: self._toggle_home_guide())
        guide_lbl = tk.Label(
            self._home_guide_frame,
            text="1. Выберите рабочий пресет Zapret2 (или Авто-оркестратор)  →  2. Включите защиту  →  3. Нажмите «Проверить сейчас»",
            bg=INFO_BG,
            fg=FG_SOFT,
            font=FONT_SMALL,
            anchor="w",
            justify="left",
        )
        guide_lbl.pack(side="left", fill="x", expand=True, padx=(10, 4), pady=3)
        self._bind_responsive_wrap(guide_lbl, min_wrap=260, pad=16)

        # Conditional DoH / DNS alert banner (shown dynamically on Dashboard when active DNS fails TLS)
        self._home_alert_frame = tk.Frame(tab, bg=WARN_BG, highlightthickness=1, highlightbackground=WARN)
        alert_btns = tk.Frame(self._home_alert_frame, bg=WARN_BG)
        alert_btns.pack(side="right", padx=8, pady=3)
        self.make_button(
            alert_btns, "Открыть DNS →", lambda: self._select_tab(self.tab_dns), "neutral", font=FONT_MICRO, padx=8, pady=2
        ).pack(side="right", padx=(4, 0))
        self.make_button(
            alert_btns, "Включить Comss DNS", lambda: self.on_select_dns("comss_dns"), "warn", font=FONT_MICRO, padx=8, pady=2
        ).pack(side="right")
        self._home_alert_lbl = tk.Label(
            self._home_alert_frame,
            text="",
            bg=WARN_BG,
            fg=WARN_TEXT,
            font=FONT_SMALL,
            anchor="w",
            justify="left",
        )
        self._home_alert_lbl.pack(side="left", fill="x", expand=True, padx=(10, 4), pady=3)
        self._bind_responsive_wrap(self._home_alert_lbl, min_wrap=220, pad=16)

        # Section 1: 4 Protection Layers
        self._home_section1_lbl = tk.Label(
            tab, text="Слои защиты (нажмите карточку для перехода)", bg=BG, fg=FG, font=FONT_H2
        )
        self._home_section1_lbl.pack(anchor="w", pady=(0, 3))
        grid = tk.Frame(tab, bg=BG)
        grid.pack(fill="x", pady=(0, 5))
        for col in range(4):
            grid.columnconfigure(col, weight=1, uniform="home_cards")

        def _make_card(
            col: int, title: str, color: str, desc: str, target_tab: ttk.Frame
        ) -> tuple[tk.Label, tk.Label]:
            card = tk.Frame(grid, bg=CARD, highlightthickness=1, highlightbackground=BORDER, cursor="hand2")
            card.grid(row=0, column=col, sticky="nsew", padx=(0 if col == 0 else 4, 0 if col == 3 else 4))

            stripe = tk.Frame(card, bg=color, height=3)
            stripe.pack(fill="x")

            top_r = tk.Frame(card, bg=CARD)
            top_r.pack(fill="x", padx=9, pady=(5, 1))
            go_lbl = tk.Label(top_r, text="→", bg=CARD, fg=DIM, font=FONT_SMALL_B)
            go_lbl.pack(side="right")
            hdr = tk.Label(top_r, text=title, bg=CARD, fg=color, font=FONT_SMALL_B, anchor="w")
            hdr.pack(side="left", fill="x", expand=True)

            val = tk.Label(card, text="—", bg=CARD, fg=FG, font=FONT_SMALL_B, anchor="w", justify="left", wraplength=150)
            val.pack(fill="x", padx=9, pady=(0, 1))
            self._bind_responsive_wrap(val, min_wrap=125, pad=18)

            sub = tk.Label(
                card, text="—", bg=CARD, fg=ACCENT, font=FONT_MICRO, anchor="w", justify="left", wraplength=150
            )
            sub.pack(fill="x", padx=9, pady=(0, 1))
            self._bind_responsive_wrap(sub, min_wrap=125, pad=18)

            note = tk.Label(card, text=desc, bg=CARD, fg=MUTED, font=FONT_MICRO, anchor="w", wraplength=150, justify="left")
            note.pack(fill="x", padx=9, pady=(0, 5))
            self._bind_responsive_wrap(note, min_wrap=125, pad=18)

            inner_widgets: list[tk.Misc] = [top_r, hdr, go_lbl, val, sub, note]
            self._bind_card_hover(card, inner_widgets, CARD, CARD_ALT, BORDER, color)
            for w in [card, stripe, *inner_widgets]:
                w.bind("<Button-1>", lambda _e, t=target_tab: self._select_tab(t))
            return val, sub

        self.card_dns_val, self.card_dns_sub = _make_card(
            0,
            "Слой 1 • DNS",
            PURPLE,
            "DNS-обход и персональные DNS",
            self.tab_dns,
        )
        self.card_dpi_val, self.card_dpi_sub = _make_card(
            1,
            "Слой 2–3 • DPI",
            ACCENT,
            "Пресет Zapret2 или автоподбор",
            self.tab_presets,
        )
        self.card_vpn_val, self.card_vpn_sub = _make_card(
            2,
            "Слой 4 • VPN и TG",
            WARN,
            "Точечный туннель и MTProto",
            self.tab_vpn,
        )
        self.card_rt_val, self.card_rt_sub = _make_card(
            3,
            "Трафик и тесты",
            OK_TEXT,
            "Живые сокеты и % успеха",
            self.tab_domains,
        )

        # Section 2: Active Zapret2 Preset Selector (replaces redundant quick-service cards on Home)
        preset_card = tk.Frame(tab, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
        preset_card.pack(fill="x", pady=(0, 5))

        p_top = tk.Frame(preset_card, bg=CARD)
        p_top.pack(fill="x", padx=12, pady=(6, 2))
        self.home_preset_mode_pill = tk.Label(
            p_top,
            text="● Авто-оркестратор",
            bg=INFO_BG,
            fg=ACCENT,
            font=FONT_MICRO,
            padx=7,
            pady=2,
        )
        self.home_preset_mode_pill.pack(side="right")
        tk.Label(
            p_top,
            text="Режим Zapret2 (рабочий пресет или авто-оркестратор)",
            bg=CARD,
            fg=FG,
            font=FONT_SMALL_B,
            anchor="w",
        ).pack(side="left", fill="x", expand=True)

        p_row = tk.Frame(preset_card, bg=CARD)
        p_row.pack(fill="x", padx=12, pady=(2, 7))
        self.make_button(
            p_row,
            "Все пресеты →",
            lambda: self._select_tab(self.tab_presets),
            "ghost",
            font=FONT_SMALL,
            padx=8,
            pady=3,
        ).pack(side="right", padx=(4, 0))
        self.make_button(
            p_row,
            "+ Свой пресет",
            self._open_add_preset_focus,
            "neutral",
            font=FONT_SMALL_B,
            padx=8,
            pady=3,
        ).pack(side="right", padx=(4, 0))
        self.make_button(
            p_row,
            "Применить",
            self.on_apply_home_preset,
            "primary",
            font=FONT_SMALL_B,
            padx=10,
            pady=3,
        ).pack(side="right", padx=(6, 0))
        self.home_preset_var = tk.StringVar(value="Авто-оркестратор (подбор по доменам)")
        self.home_preset_cb = ttk.Combobox(
            p_row,
            textvariable=self.home_preset_var,
            state="readonly",
            values=["Авто-оркестратор (подбор по доменам)"],
        )
        self.home_preset_cb.pack(side="left", fill="x", expand=True)

        # Section 3: Live Connectivity Test Strip (YouTube, Discord, Telegram, Overall %)
        test_card = tk.Frame(tab, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
        test_card.pack(fill="x", pady=(0, 5))

        t_row = tk.Frame(test_card, bg=CARD)
        t_row.pack(fill="x", padx=12, pady=7)
        self.make_button(
            t_row,
            "Подробно →",
            lambda: self._open_domains_subview("domains"),
            "ghost",
            font=FONT_SMALL,
            padx=8,
            pady=3,
        ).pack(side="right", padx=(4, 0))
        self.make_button(
            t_row,
            "▶ Проверить сейчас",
            lambda: self.on_run_connectivity_tests(include_picked=False),
            "success",
            font=FONT_SMALL_B,
            padx=10,
            pady=3,
        ).pack(side="right", padx=(6, 0))

        pills_wrap = tk.Frame(t_row, bg=CARD)
        pills_wrap.pack(side="left", fill="x", expand=True)
        tk.Label(pills_wrap, text="Тест:", bg=CARD, fg=MUTED, font=FONT_SMALL_B).pack(side="left", padx=(0, 6))

        self._home_service_pills: dict[str, tk.Label] = {}
        for sg_key, sg_title in (("youtube", "YouTube"), ("discord", "Discord"), ("telegram", "Telegram")):
            lbl = tk.Label(
                pills_wrap,
                text=f"● {sg_title}: —",
                bg=INPUT,
                fg=MUTED,
                font=FONT_SMALL_B,
                padx=8,
                pady=2,
            )
            lbl.pack(side="left", padx=(0, 5))
            self._home_service_pills[sg_key] = lbl

        self.home_test_rate_pill = tk.Label(
            pills_wrap,
            text="Успех: —",
            bg=INFO_BG,
            fg=ACCENT,
            font=FONT_SMALL_B,
            padx=8,
            pady=2,
        )
        self.home_test_rate_pill.pack(side="left", padx=(2, 0))

        # Section 3: Unified Tools & Unlocker Guard Card (right controls packed first to avoid squashing)
        tools_card = tk.Frame(tab, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
        tools_card.pack(fill="x", pady=(2, 0))

        helpers = tk.Frame(tools_card, bg=CARD)
        helpers.pack(fill="x", padx=12, pady=4)
        self.make_button(
            helpers,
            "Очистить DNS-кэш",
            self.on_flush_dns,
            "neutral",
            font=FONT_SMALL_B,
            padx=9,
            pady=3,
        ).pack(side="right", padx=(6, 0))
        self.tg_proxy_btn = self.make_button(
            helpers,
            "✈ Telegram прокси",
            self.on_connect_telegram_proxy,
            "ghost",
            font=FONT_SMALL_B,
            padx=8,
            pady=3,
        )
        self.tg_proxy_btn.pack(side="right", padx=(4, 0))
        self.radar_btn = self.make_button(
            helpers,
            "Live-Радар: ВКЛ",
            self.on_toggle_radar,
            "primary",
            font=FONT_SMALL_B,
            padx=10,
            pady=3,
        )
        self.radar_btn.pack(side="right", padx=(4, 0))
        self.game_filter_var = tk.BooleanVar(value=False)
        tk.Checkbutton(
            helpers,
            text="Игровой фильтр (UDP 1024–65535)",
            variable=self.game_filter_var,
            command=self.on_toggle_game_filter,
            bg=CARD,
            fg=FG,
            selectcolor=PRIMARY_BG,
            activebackground=CARD,
            activeforeground=ACCENT,
            font=FONT_SMALL_B,
            anchor="w",
            cursor="hand2",
            bd=0,
            highlightthickness=0,
        ).pack(side="left", fill="x", expand=True)

        tk.Frame(tools_card, bg=BORDER_LIGHT, height=1).pack(fill="x", padx=12)

        guard_strip = tk.Frame(tools_card, bg=CARD)
        guard_strip.pack(fill="x", padx=12, pady=6)
        self.make_button(
            guard_strip,
            "Настроить исключения →",
            lambda: self._select_tab(self.tab_service),
            "ghost",
            font=FONT_SMALL,
            padx=8,
            pady=2,
        ).pack(side="right", padx=(8, 0))
        self.unlocker_status_label = tk.Label(
            guard_strip,
            text="Защита Antigravity Unlocker и файла hosts: проверяется…",
            bg=CARD,
            fg=OK_TEXT,
            font=FONT_SMALL,
            anchor="w",
            justify="left",
            wraplength=460,
        )
        self.unlocker_status_label.pack(side="left", fill="x", expand=True)
        self._bind_responsive_wrap(self.unlocker_status_label, min_wrap=200, pad=16)

    def _toggle_home_guide(self) -> None:
        if self._guide_visible:
            self._home_guide_frame.pack_forget()
            self._guide_visible = False

    # ---------------------------------------------------------------- Tab 2: Домены, тесты и живой трафик (Unified)

    def _build_domains_tab(self) -> None:
        tab = self.tab_domains
        self._make_page_header(
            tab,
            "Домены, тесты и живой трафик",
            "Подобранные стратегии, процент успеха тестов (YouTube / Discord / Telegram) и активные соединения ПК в одном окне.",
        )

        # Unified view switcher + overall success summary + quick test actions
        switch_bar = tk.Frame(tab, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
        switch_bar.pack(fill="x", pady=(0, 6))

        sw_row = tk.Frame(switch_bar, bg=CARD)
        sw_row.pack(fill="x", padx=12, pady=6)

        self.make_button(
            sw_row,
            "▶ Тест всех доменов",
            lambda: self.on_run_connectivity_tests(include_picked=True),
            "neutral",
            font=FONT_SMALL_B,
            padx=9,
            pady=4,
        ).pack(side="right", padx=(4, 0))
        self.make_button(
            sw_row,
            "▶ Тест YT / DC / TG",
            lambda: self.on_run_connectivity_tests(include_picked=False),
            "success",
            font=FONT_SMALL_B,
            padx=9,
            pady=4,
        ).pack(side="right", padx=(6, 0))

        self._subtab_domains_btn = self.make_button(
            sw_row,
            "Подобранные домены (0)",
            lambda: self._switch_domains_subview("domains"),
            "primary",
            font=FONT_SMALL_B,
            padx=10,
            pady=4,
        )
        self._subtab_domains_btn.pack(side="left", padx=(0, 4))

        self._subtab_conns_btn = self.make_button(
            sw_row,
            "Активные сокеты (0)",
            lambda: self._switch_domains_subview("connections"),
            "neutral",
            font=FONT_SMALL_B,
            padx=10,
            pady=4,
        )
        self._subtab_conns_btn.pack(side="left", padx=(0, 10))

        self._domains_test_summary_lbl = tk.Label(
            sw_row,
            text="Успех тестов: —  •  Подобрано: 0  •  Живых сокетов: 0",
            bg=CARD,
            fg=FG_SOFT,
            font=FONT_SMALL_B,
            anchor="w",
        )
        self._domains_test_summary_lbl.pack(side="left", fill="x", expand=True)

        self._domains_view_container = tk.Frame(tab, bg=BG)
        self._domains_view_container.pack(fill="both", expand=True)

        # ---- Sub-view 1: Picked Domains, Tests & Strategy Inspector ----
        self._domains_subview = tk.Frame(self._domains_view_container, bg=BG)
        self._domains_subview.pack(fill="both", expand=True)

        toolbar = tk.Frame(self._domains_subview, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
        toolbar.pack(fill="x", pady=(0, 6))

        filt_top = tk.Frame(toolbar, bg=CARD)
        filt_top.pack(fill="x", padx=12, pady=(7, 4))

        self.layer_filter_var = tk.StringVar(value="ALL")
        self.layer_filter_var.trace_add("write", lambda *_: self._sync_domain_filter_pills())
        pill_box = tk.Frame(filt_top, bg=CARD)
        pill_box.pack(side="right", padx=(8, 0))
        self._domain_filter_buttons.clear()
        for lid in LAYER_FILTERS:
            btn = self.make_button(
                pill_box,
                LAYER_FILTER_LABELS.get(lid, lid),
                lambda c=lid: self._set_domain_layer_filter(c),
                "primary" if lid == "ALL" else "neutral",
                font=FONT_SMALL,
                padx=8,
                pady=3,
            )
            btn.pack(side="left", padx=2)
            self._domain_filter_buttons[lid] = btn

        tk.Label(filt_top, text="Поиск:", bg=CARD, fg=MUTED, font=FONT_SMALL_B).pack(side="left", padx=(0, 6))
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self.populate_domain_table())
        self.search_entry = self.make_entry(filt_top, self.search_var, 18)
        self.search_entry.pack(side="left", fill="x", expand=True, ipady=3)
        self.make_button(
            filt_top, "✕", lambda: self.search_var.set(""), "ghost", font=FONT_SMALL, padx=6, pady=2
        ).pack(side="left", padx=(4, 0))

        tk.Frame(toolbar, bg=BORDER_LIGHT, height=1).pack(fill="x", padx=12)

        filt_bot = tk.Frame(toolbar, bg=CARD)
        filt_bot.pack(fill="x", padx=12, pady=(5, 7))
        self.make_button(
            filt_bot, "Проверить базовый список", self.on_diag_all, "neutral", font=FONT_SMALL_B, padx=10, pady=3
        ).pack(side="right", padx=(8, 0))
        tk.Label(filt_bot, text="Добавить сайт:", bg=CARD, fg=ACCENT, font=FONT_SMALL_B).pack(side="left", padx=(0, 6))
        self.new_domain_var = tk.StringVar()
        entry = self.make_entry(filt_bot, self.new_domain_var, 22)
        entry.pack(side="left", fill="x", expand=True, ipady=3)
        entry.bind("<Return>", lambda _e: self.on_check_new_domain())
        self.make_button(
            filt_bot, "Подобрать для сайта", self.on_check_new_domain, "primary", font=FONT_SMALL_B, padx=10, pady=3
        ).pack(side="left", padx=(8, 0))

        paned = ttk.PanedWindow(self._domains_subview, orient="vertical")
        paned.pack(fill="both", expand=True)

        tree_wrap = tk.Frame(paned, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
        cols = tuple(c[0] for c in DOMAIN_COLUMNS)
        self.domain_tree = self.make_tree(tree_wrap, cols, height=10)
        for cid, title, width, anchor in DOMAIN_COLUMNS:
            heading_txt = f"{title} ▲" if cid == "domain" else title
            self.domain_tree.heading(cid, text=heading_txt, command=lambda c=cid: self.sort_domains(c))
            self.domain_tree.column(cid, width=width, anchor=anchor, stretch=cid in ("domain", "strategy"))  # type: ignore[arg-type]
        self.domain_tree.tag_configure("dpi", foreground=ACCENT)
        self.domain_tree.tag_configure("vpn", foreground=WARN_TEXT)
        self.domain_tree.tag_configure("dns", foreground=PURPLE)
        self.domain_tree.tag_configure("direct", foreground=OK_TEXT)
        self.domain_tree.tag_configure("other", foreground=FG)
        self.domain_tree.tag_configure("degraded", foreground=ERR_TEXT)
        self.domain_tree.tag_configure("expired", foreground=MUTED)
        self.domain_tree.bind("<<TreeviewSelect>>", self.on_domain_select)
        self.domain_tree.bind("<Button-3>", self._on_domain_context_menu)
        self._scrolled(tree_wrap, self.domain_tree, horizontal=True)
        paned.add(tree_wrap, weight=3)

        paned.add(self._build_inspector(paned), weight=2)

        self._domain_menu = tk.Menu(self, tearoff=0, bg=CARD_ALT, fg=FG, activebackground=SELECT_BG, activeforeground="#FFFFFF")
        self._domain_menu.add_command(label="▶ Проверить доступность сейчас", command=self.on_test_selected_domain)
        self._domain_menu.add_command(label="📌 Закрепить / Открепить правило", command=self.on_toggle_pin_selected)
        self._domain_menu.add_separator()
        self._domain_menu.add_command(label="Автоподбор DPI", command=self.on_recheck_selected)
        self._domain_menu.add_command(label="Подобрать персональный DNS", command=self.on_roll_dns_selected)
        self._domain_menu.add_command(label="Глубокий поиск blockcheck2", command=self.on_blockcheck2_selected)
        self._domain_menu.add_separator()
        self._domain_menu.add_command(label="Направить через VPN", command=lambda: self._quick_pin_selected("vpn", "vpn-select"))
        self._domain_menu.add_command(label="Открывать напрямую (direct)", command=lambda: self._quick_pin_selected("direct", None))
        self._domain_menu.add_command(label="Копировать домен", command=self._copy_selected_domain)

        # ---- Sub-view 2: Active PC Sockets (formerly separate Live Connections tab) ----
        self._conns_subview = tk.Frame(self._domains_view_container, bg=BG)
        self._build_conns_subview(self._conns_subview)

    def _build_conns_subview(self, parent: tk.Frame) -> None:
        bar = tk.Frame(parent, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
        bar.pack(fill="x", pady=(0, 6))

        top_r = tk.Frame(bar, bg=CARD)
        top_r.pack(fill="x", padx=12, pady=(7, 5))

        self.make_button(top_r, "Сканировать сейчас", self.refresh_realtime_async, "neutral", font=FONT_SMALL_B, pady=3).pack(
            side="right", padx=(6, 0)
        )
        self.make_button(
            top_r, "Починить выбранное", self.on_heal_selected_connection, "primary", font=FONT_SMALL_B, pady=3
        ).pack(side="right", padx=(8, 0))
        self._rt_summary_lbl = tk.Label(
            top_r,
            text="Всего: 0  •  Под защитой: 0  •  Нужна починка: 0  •  Напрямую: 0",
            bg=CARD,
            fg=FG_SOFT,
            font=FONT_SMALL_B,
            anchor="w",
        )
        self._rt_summary_lbl.pack(side="left", fill="x", expand=True)

        tk.Frame(bar, bg=BORDER_LIGHT, height=1).pack(fill="x", padx=12)

        bot_r = tk.Frame(bar, bg=CARD)
        bot_r.pack(fill="x", padx=12, pady=(5, 7))

        pill_wrap = tk.Frame(bot_r, bg=CARD)
        pill_wrap.pack(side="right", padx=(8, 0))
        self._conn_filter_buttons.clear()
        for fid, flabel in (("ALL", "Все"), ("needs_fix", "Нужна починка"), ("protected", "Под защитой")):
            btn = self.make_button(
                pill_wrap,
                flabel,
                lambda f=fid: self._set_conn_health_filter(f),
                "primary" if fid == "ALL" else "neutral",
                font=FONT_SMALL,
                padx=8,
                pady=3,
            )
            btn.pack(side="left", padx=2)
            self._conn_filter_buttons[fid] = btn

        self.auto_heal_var = tk.BooleanVar(value=True)
        tk.Checkbutton(
            bot_r,
            text="Автоподбор стратегий для новых/зависших сокетов (откл. при фикс. пресете)",
            variable=self.auto_heal_var,
            bg=CARD,
            fg=FG,
            selectcolor=PRIMARY_BG,
            activebackground=CARD,
            activeforeground=ACCENT,
            font=FONT_SMALL_B,
            anchor="w",
            cursor="hand2",
            bd=0,
            highlightthickness=0,
        ).pack(side="left", fill="x", expand=True)

        paned = ttk.PanedWindow(parent, orient="vertical")
        paned.pack(fill="both", expand=True)

        conn_wrap = tk.Frame(paned, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
        cols = tuple(c[0] for c in CONN_COLUMNS)
        self.conn_tree = self.make_tree(conn_wrap, cols, height=10)
        for cid, title, width, anchor in CONN_COLUMNS:
            self.conn_tree.heading(cid, text=title)
            self.conn_tree.column(cid, width=width, anchor=anchor, stretch=cid in ("domain", "strategy"))  # type: ignore[arg-type]
        self.conn_tree.tag_configure("protected", foreground=ACCENT)
        self.conn_tree.tag_configure("needs_fix", foreground=ERR_TEXT)
        self.conn_tree.tag_configure("direct", foreground=MUTED)
        self.conn_tree.bind("<<TreeviewSelect>>", self.on_conn_select)
        self.conn_tree.bind("<Double-1>", lambda _e: self.on_heal_selected_connection())
        self.conn_tree.bind("<Button-3>", self._on_conn_context_menu)
        self._scrolled(conn_wrap, self.conn_tree, horizontal=True)
        paned.add(conn_wrap, weight=3)

        self._conn_menu = tk.Menu(self, tearoff=0, bg=CARD_ALT, fg=FG, activebackground=SELECT_BG, activeforeground="#FFFFFF")
        self._conn_menu.add_command(label="Починить выбранное (автоподбор)", command=self.on_heal_selected_connection)
        self._conn_menu.add_command(label="Показать в «Подобранных доменах»", command=self._open_selected_conn_domain)
        self._conn_menu.add_command(label="Копировать домен", command=self._copy_selected_conn_domain)

        feed_panel = tk.Frame(paned, bg=BG)
        tk.Label(
            feed_panel,
            text="Журнал автоподбора в реальном времени",
            bg=BG,
            fg=ACCENT,
            font=FONT_SMALL_B,
            anchor="w",
        ).pack(fill="x", pady=(6, 4))
        feed_box = tk.Frame(feed_panel, bg=SIDEBAR_BG, highlightthickness=1, highlightbackground=BORDER)
        feed_box.pack(fill="both", expand=True)
        self.realtime_feed = self.make_text(feed_box, height=5, wrap="word")
        self.realtime_feed.tag_configure("ok", foreground=OK_TEXT)
        self.realtime_feed.tag_configure("muted", foreground=MUTED)
        self._scrolled(feed_box, self.realtime_feed)
        paned.add(feed_panel, weight=1)

    def _switch_domains_subview(self, mode: str) -> None:
        self._domains_subview_mode = "connections" if mode == "connections" else "domains"
        if self._domains_subview_mode == "connections":
            self._domains_subview.pack_forget()
            self._conns_subview.pack(fill="both", expand=True)
            self._restyle_button(self._subtab_domains_btn, self._subtab_domains_btn.cget("text"), "neutral")
            self._restyle_button(self._subtab_conns_btn, self._subtab_conns_btn.cget("text"), "primary")
        else:
            self._conns_subview.pack_forget()
            self._domains_subview.pack(fill="both", expand=True)
            self._restyle_button(self._subtab_domains_btn, self._subtab_domains_btn.cget("text"), "primary")
            self._restyle_button(self._subtab_conns_btn, self._subtab_conns_btn.cget("text"), "neutral")

    def _open_domains_subview(self, mode: str) -> None:
        self._select_tab(self.tab_domains)
        self._switch_domains_subview(mode)

    def _set_domain_layer_filter(self, layer: str) -> None:
        self.layer_filter_var.set(layer)
        self.populate_domain_table()

    def _sync_domain_filter_pills(self) -> None:
        cur = self.layer_filter_var.get() or "ALL"
        for lid, btn in self._domain_filter_buttons.items():
            self._restyle_button(btn, LAYER_FILTER_LABELS.get(lid, lid), "primary" if lid == cur else "neutral")

    def _on_domain_context_menu(self, event: Any) -> None:
        iid = self.domain_tree.identify_row(event.y)
        if iid:
            self.domain_tree.selection_set(iid)
            self.on_domain_select()
            try:
                self._domain_menu.tk_popup(event.x_root, event.y_root)
            finally:
                self._domain_menu.grab_release()

    def _quick_pin_selected(self, layer: str, strategy: str | None) -> None:
        if not self.selected_row:
            return
        self.override_layer_var.set(layer)
        self._refresh_strategy_choices(str(self.selected_row.get("protocol", "")))
        self.override_strategy_var.set(strategy or "")
        self.on_pin()

    def _copy_selected_domain(self) -> None:
        if not self.selected_row:
            return
        dom = str(self.selected_row.get("domain") or "")
        if dom:
            self.clipboard_clear()
            self.clipboard_append(dom)
            self.set_status(f"Скопировано в буфер: {dom}", ACCENT)

    def _build_inspector(self, parent: tk.Misc) -> tk.Frame:
        panel = tk.Frame(parent, bg=CARD, highlightthickness=1, highlightbackground=BORDER)

        right = tk.Frame(panel, bg=CARD_ALT, width=310, highlightthickness=1, highlightbackground=BORDER)
        right.pack(side="right", fill="y", padx=(6, 10), pady=8)
        right.pack_propagate(False)

        left = tk.Frame(panel, bg=CARD)
        left.pack(side="left", fill="both", expand=True, padx=(12, 6), pady=8)
        self.inspector_title = tk.Label(
            left, text="Выберите сайт в таблице выше, чтобы увидеть результаты проб", bg=CARD, fg=ACCENT, font=FONT_UI_B, anchor="w"
        )
        self.inspector_title.pack(fill="x")
        box = tk.Frame(left, bg=SIDEBAR_BG, highlightthickness=1, highlightbackground=BORDER)
        box.pack(fill="both", expand=True, pady=(6, 0))
        self.inspector = self.make_text(box, height=8, wrap="word")
        self.inspector.tag_configure("h", foreground=ACCENT, font=("Consolas", 10, "bold"))
        self.inspector.tag_configure("ok", foreground=OK_TEXT)
        self.inspector.tag_configure("bad", foreground=ERR_TEXT)
        self.inspector.tag_configure("muted", foreground=MUTED)
        self.inspector.tag_configure("warn", foreground=WARN_TEXT)
        self.inspector.tag_configure("args", foreground="#93C5FD")
        self.inspector.configure(state="normal")
        self.inspector.insert(
            "1.0",
            "Выберите любой сайт в таблице выше — здесь появятся результаты DNS/TCP/TLS/QUIC проб, "
            "подобранная стратегия и параметры обхода.\n",
            "muted",
        )
        self.inspector.configure(state="disabled")
        self._scrolled(box, self.inspector)

        tk.Label(right, text="Управление правилом", bg=CARD_ALT, fg=FG, font=FONT_UI_B, anchor="w").pack(
            fill="x", padx=12, pady=(10, 2)
        )
        tk.Label(
            right,
            text="Запустите автоподбор или задайте слой вручную:",
            bg=CARD_ALT,
            fg=MUTED,
            font=FONT_SMALL,
            anchor="w",
        ).pack(fill="x", padx=12, pady=(0, 8))

        auto_row = tk.Frame(right, bg=CARD_ALT)
        auto_row.pack(fill="x", padx=12, pady=(0, 6))
        self.make_button(auto_row, "▶ Тест", self.on_test_selected_domain, "success", font=FONT_SMALL_B, padx=5, pady=4).pack(
            side="left", fill="x", expand=True, padx=(0, 3)
        )
        self.make_button(auto_row, "Авто DPI", self.on_recheck_selected, "primary", font=FONT_SMALL_B, padx=5, pady=4).pack(
            side="left", fill="x", expand=True, padx=(0, 3)
        )
        self.make_button(auto_row, "Авто DNS", self.on_roll_dns_selected, "neutral", font=FONT_SMALL_B, padx=5, pady=4).pack(
            side="left", fill="x", expand=True
        )

        tk.Frame(right, bg=BORDER_LIGHT, height=1).pack(fill="x", padx=12, pady=(0, 6))

        tk.Label(right, text="Ручной выбор слоя и стратегии:", bg=CARD_ALT, fg=FG_SOFT, font=FONT_SMALL_B, anchor="w").pack(
            fill="x", padx=12
        )
        self.override_layer_var = tk.StringVar(value="dpi")
        self.override_layer_cb = ttk.Combobox(
            right, textvariable=self.override_layer_var, values=OVERRIDE_LAYERS, state="readonly"
        )
        self.override_layer_cb.pack(fill="x", padx=12, pady=(4, 2))
        self.override_layer_cb.bind("<<ComboboxSelected>>", lambda _e: self._on_override_layer_changed())

        self._override_layer_hint_lbl = tk.Label(
            right,
            text=OVERRIDE_LAYER_HINTS["dpi"],
            bg=CARD_ALT,
            fg=MUTED,
            font=FONT_SMALL,
            anchor="w",
            wraplength=274,
            justify="left",
        )
        self._override_layer_hint_lbl.pack(fill="x", padx=12, pady=(0, 5))
        self._bind_responsive_wrap(self._override_layer_hint_lbl, min_wrap=220, pad=24)

        self.override_strategy_var = tk.StringVar()
        self.override_strategy_cb = ttk.Combobox(right, textvariable=self.override_strategy_var, state="readonly")
        self.override_strategy_cb.pack(fill="x", padx=12, pady=(0, 6))

        pin_row = tk.Frame(right, bg=CARD_ALT)
        pin_row.pack(fill="x", padx=12, pady=(0, 6))
        self.make_button(pin_row, "📌 Закрепить (Pin)", self.on_pin, "primary", font=FONT_SMALL_B, padx=8, pady=5).pack(
            side="left", fill="x", expand=True, padx=(0, 4)
        )
        self.unpin_btn = self.make_button(
            pin_row, "Открепить", self.on_toggle_pin_selected, "neutral", font=FONT_SMALL, padx=8, pady=5
        )
        self.unpin_btn.pack(side="left")
        return panel

    # ---------------------------------------------------------------- Tab 3: Пресеты Zapret2

    def _build_presets_tab(self) -> None:
        tab = self.tab_presets
        self._make_page_header(
            tab,
            "Пресеты Zapret2 (готовые и свои рабочие)",
            "Выберите готовый пресет из Zapret2 (C:\\vso\\Dev) или добавьте свой рабочий — при активном пресете оркестратор не тратит ресурсы на перебор.",
        )

        # Active mode bar + quick import actions
        top_card = tk.Frame(tab, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
        top_card.pack(fill="x", pady=(0, 6))

        r1 = tk.Frame(top_card, bg=CARD)
        r1.pack(fill="x", padx=12, pady=(7, 5))
        self.make_button(
            r1, "Импорт из C:\\vso\\Dev", self.on_import_presets_dir, "neutral", font=FONT_SMALL_B, padx=9, pady=4
        ).pack(side="right", padx=(4, 0))
        self.make_button(
            r1, "Импорт файла (.txt/.bat)", self.on_import_preset_file, "neutral", font=FONT_SMALL_B, padx=9, pady=4
        ).pack(side="right", padx=(4, 0))
        self.make_button(
            r1, "Включить Авто-оркестратор", lambda: self.on_select_zapret_preset("auto"), "ghost", font=FONT_SMALL_B, padx=9, pady=4
        ).pack(side="right", padx=(6, 0))

        self.presets_active_lbl = tk.Label(
            r1,
            text="Активный режим: Авто-оркестратор (подбор по доменам)",
            bg=CARD,
            fg=ACCENT,
            font=FONT_UI_B,
            anchor="w",
        )
        self.presets_active_lbl.pack(side="left", fill="x", expand=True)

        tk.Frame(top_card, bg=BORDER_LIGHT, height=1).pack(fill="x", padx=12)

        r2 = tk.Frame(top_card, bg=CARD)
        r2.pack(fill="x", padx=12, pady=(5, 7))

        pill_wrap = tk.Frame(r2, bg=CARD)
        pill_wrap.pack(side="right", padx=(8, 0))
        self._preset_filter_buttons.clear()
        for pf_id, pf_lbl in (("ALL", "Все"), ("user", "Мои рабочие"), ("featured", "Рекомендуемые")):
            btn = self.make_button(
                pill_wrap,
                pf_lbl,
                lambda f=pf_id: self._set_preset_filter(f),
                "primary" if pf_id == "ALL" else "neutral",
                font=FONT_SMALL,
                padx=8,
                pady=3,
            )
            btn.pack(side="left", padx=2)
            self._preset_filter_buttons[pf_id] = btn

        tk.Label(r2, text="Поиск пресета:", bg=CARD, fg=MUTED, font=FONT_SMALL_B).pack(side="left", padx=(0, 6))
        self.preset_search_var = tk.StringVar()
        self.preset_search_var.trace_add("write", lambda *_: self.populate_presets_table())
        self.make_entry(r2, self.preset_search_var, 20).pack(side="left", fill="x", expand=True, ipady=2)

        paned = ttk.PanedWindow(tab, orient="vertical")
        paned.pack(fill="both", expand=True)

        # Top pane: Presets table + action buttons
        top_pane = tk.Frame(paned, bg=BG)
        act_bar = tk.Frame(top_pane, bg=BG)
        act_bar.pack(fill="x", pady=(0, 4))
        self.make_button(
            act_bar, "✔ Активировать выбранный", self.on_activate_selected_preset, "success", font=FONT_SMALL_B, padx=10, pady=4
        ).pack(side="left", padx=(0, 6))
        self.make_button(
            act_bar, "▶ Тест пресета (YT/DC/TG)", self.on_test_selected_preset, "primary", font=FONT_SMALL_B, padx=10, pady=4
        ).pack(side="left", padx=(0, 6))
        self.make_button(
            act_bar, "В редактор ↓", self.on_load_selected_preset_to_editor, "neutral", font=FONT_SMALL, padx=8, pady=4
        ).pack(side="left", padx=(0, 6))
        self.make_button(
            act_bar, "Удалить свой", self.on_delete_selected_preset, "danger", font=FONT_SMALL, padx=8, pady=4
        ).pack(side="right")

        tree_wrap = tk.Frame(top_pane, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
        tree_wrap.pack(fill="both", expand=True)
        pcols = tuple(c[0] for c in PRESET_COLUMNS)
        self.presets_tree = self.make_tree(tree_wrap, pcols, height=9)
        for cid, title, width, anchor in PRESET_COLUMNS:
            self.presets_tree.heading(cid, text=title)
            self.presets_tree.column(cid, width=width, anchor=anchor, stretch=cid in ("name", "description"))  # type: ignore[arg-type]
        self.presets_tree.tag_configure("active", foreground=OK_TEXT)
        self.presets_tree.tag_configure("user", foreground=ACCENT)
        self.presets_tree.tag_configure("featured", foreground=WARN_TEXT)
        self.presets_tree.tag_configure("builtin", foreground=FG_SOFT)
        self.presets_tree.bind("<<TreeviewSelect>>", self.on_preset_select)
        self.presets_tree.bind("<Double-1>", lambda _e: self.on_activate_selected_preset())
        self._scrolled(tree_wrap, self.presets_tree, horizontal=True)
        paned.add(top_pane, weight=3)

        # Bottom pane: Add / Edit custom working preset
        ed_card = tk.Frame(paned, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
        ed_hdr = tk.Frame(ed_card, bg=CARD)
        ed_hdr.pack(fill="x", padx=12, pady=(7, 4))
        self.user_preset_activate_var = tk.BooleanVar(value=True)
        self.make_button(
            ed_hdr, "+ Сохранить рабочий пресет", self.on_add_user_preset, "primary", font=FONT_SMALL_B, padx=10, pady=4
        ).pack(side="right")
        tk.Checkbutton(
            ed_hdr,
            text="Активировать сразу",
            variable=self.user_preset_activate_var,
            bg=CARD,
            fg=FG_SOFT,
            selectcolor=PRIMARY_BG,
            activebackground=CARD,
            activeforeground=ACCENT,
            font=FONT_SMALL,
            cursor="hand2",
            bd=0,
            highlightthickness=0,
        ).pack(side="right", padx=(0, 10))
        tk.Label(
            ed_hdr,
            text="Добавить свой рабочий пресет (текст winws2, .bat или --lua-desync=...)",
            bg=CARD,
            fg=OK_TEXT,
            font=FONT_UI_B,
            anchor="w",
        ).pack(side="left", fill="x", expand=True)

        meta_r = tk.Frame(ed_card, bg=CARD)
        meta_r.pack(fill="x", padx=12, pady=(0, 5))
        tk.Label(meta_r, text="Название:", bg=CARD, fg=MUTED, font=FONT_SMALL).pack(side="left", padx=(0, 5))
        self.user_preset_name_var = tk.StringVar()
        self.user_preset_name_entry = self.make_entry(meta_r, self.user_preset_name_var, 22)
        self.user_preset_name_entry.pack(side="left", fill="x", expand=True, padx=(0, 10), ipady=2)
        tk.Label(meta_r, text="Описание:", bg=CARD, fg=MUTED, font=FONT_SMALL).pack(side="left", padx=(0, 5))
        self.user_preset_desc_var = tk.StringVar()
        self.make_entry(meta_r, self.user_preset_desc_var, 24).pack(side="left", fill="x", expand=True, ipady=2)

        txt_wrap = tk.Frame(ed_card, bg=SIDEBAR_BG, highlightthickness=1, highlightbackground=BORDER)
        txt_wrap.pack(fill="both", expand=True, padx=12, pady=(0, 8))
        self.user_preset_text = tk.Text(
            txt_wrap,
            height=5,
            wrap="none",
            undo=True,
            bg=SIDEBAR_BG,
            fg=FG,
            insertbackground=ACCENT,
            relief="flat",
            highlightthickness=0,
            font=FONT_MONO_S,
            padx=8,
            pady=6,
            selectbackground=SELECT_BG,
            selectforeground="#FFFFFF",
        )
        self._scrolled(txt_wrap, self.user_preset_text, horizontal=True)
        paned.add(ed_card, weight=2)

    # ---------------------------------------------------------------- Tab 3: DNS и Нейросети

    def _build_dns_tab(self) -> None:
        tab = self.tab_dns
        hdr = tk.Frame(tab, bg=BG)
        hdr.pack(fill="x", pady=(2, 8))
        self.active_dns_pill = tk.Label(
            hdr,
            text="Активный общий DNS: Cloudflare (1.1.1.1)",
            bg=INFO_BG,
            fg=ACCENT,
            font=FONT_SMALL_B,
            padx=10,
            pady=4,
        )
        self.active_dns_pill.pack(side="right", anchor="n", padx=(10, 0), pady=(2, 0))
        hdr_left = tk.Frame(hdr, bg=BG)
        hdr_left.pack(side="left", fill="x", expand=True)
        tk.Label(hdr_left, text="DNS и нейросети", bg=BG, fg=FG, font=FONT_HERO, anchor="w").pack(anchor="w")
        sub_lbl = tk.Label(
            hdr_left,
            text="Выберите общий DNS по умолчанию или назначьте персональный DNS для нейросетей.",
            bg=BG,
            fg=MUTED,
            font=FONT_SMALL,
            anchor="w",
            justify="left",
        )
        sub_lbl.pack(fill="x", anchor="w", pady=(2, 0))
        self._bind_responsive_wrap(sub_lbl, min_wrap=220, pad=16)

        # Category filter pills + latency tools (right buttons packed first)
        bar = tk.Frame(tab, bg=BG)
        bar.pack(fill="x", pady=(0, 8))
        self.make_button(
            bar,
            "Лучший DNS",
            lambda: self.on_auto_select_dns("uncommon"),
            "neutral",
            font=FONT_SMALL_B,
            padx=8,
            pady=3,
        ).pack(side="right", padx=(4, 0))
        self.make_button(
            bar,
            "Пинг всех",
            self.on_ping_dns_catalog,
            "success",
            font=FONT_SMALL_B,
            padx=8,
            pady=3,
        ).pack(side="right", padx=(6, 0))

        cat_btns: tuple[tuple[str, str], ...] = (
            ("ALL", "Все"),
            ("popular", "Популярные"),
            ("security", "Безопасные"),
            ("uncommon", "Малоизвестные"),
            ("ai_bypass", "Для ИИ"),
            ("custom", "Мои DNS"),
        )
        for cat_id, label in cat_btns:
            btn = self.make_button(
                bar,
                label,
                lambda c=cat_id: self.set_dns_category_filter(c),
                "primary" if cat_id == "ALL" else "neutral",
                font=FONT_SMALL,
                padx=7,
                pady=3,
            )
            btn.pack(side="left", padx=(0, 3))
            self._dns_cat_buttons[cat_id] = btn

        # Clean two-column action row (each card has ample room without horizontal clipping)
        tools_row = tk.Frame(tab, bg=BG)
        tools_row.pack(fill="x", pady=(0, 8))
        tools_row.columnconfigure(0, weight=1, uniform="dnstools")
        tools_row.columnconfigure(1, weight=1, uniform="dnstools")

        roll_box = tk.Frame(tools_row, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
        roll_box.grid(row=0, column=0, sticky="nsew", padx=(0, 5))
        tk.Label(roll_box, text="Персональный DNS для сайта / нейросети", bg=CARD, fg=OK_TEXT, font=FONT_UI_B, anchor="w").pack(
            fill="x", padx=12, pady=(8, 2)
        )
        roll_sub = tk.Label(
            roll_box,
            text="Подбирает отдельный рабочий DNS для домена.",
            bg=CARD,
            fg=MUTED,
            font=FONT_SMALL,
            anchor="w",
            wraplength=280,
            justify="left",
        )
        roll_sub.pack(fill="x", padx=12, pady=(0, 6))
        self._bind_responsive_wrap(roll_sub, min_wrap=200, pad=24)
        r_inner = tk.Frame(roll_box, bg=CARD)
        r_inner.pack(fill="x", padx=12, pady=(0, 10))
        self.make_button(r_inner, "Ролл для ИИ", self.on_roll_all_ai_dns, "primary", font=FONT_SMALL_B, padx=8, pady=4).pack(
            side="right", padx=(4, 0)
        )
        self.make_button(r_inner, "Подобрать", self.on_roll_dns_domain, "success", font=FONT_SMALL_B, padx=8, pady=4).pack(
            side="right", padx=(6, 0)
        )
        self.dns_roll_domain_var = tk.StringVar()
        roll_entry = self.make_entry(r_inner, self.dns_roll_domain_var, 10)
        roll_entry.pack(side="left", fill="x", expand=True, ipady=3)
        roll_entry.bind("<Return>", lambda _e: self.on_roll_dns_domain())

        custom_box = tk.Frame(tools_row, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
        custom_box.grid(row=0, column=1, sticky="nsew", padx=(5, 0))
        tk.Label(custom_box, text="Добавить свой DNS-сервер", bg=CARD, fg=ACCENT, font=FONT_UI_B, anchor="w").pack(
            fill="x", padx=12, pady=(8, 4)
        )
        c_row1 = tk.Frame(custom_box, bg=CARD)
        c_row1.pack(fill="x", padx=12, pady=(0, 4))
        tk.Label(c_row1, text="Имя:", bg=CARD, fg=MUTED, font=FONT_SMALL).pack(side="left", padx=(0, 4))
        self.custom_dns_name_var = tk.StringVar()
        self.make_entry(c_row1, self.custom_dns_name_var, 10).pack(side="left", fill="x", expand=True, padx=(0, 8), ipady=2)
        tk.Label(c_row1, text="IP:", bg=CARD, fg=MUTED, font=FONT_SMALL).pack(side="left", padx=(0, 4))
        self.custom_dns_ip_var = tk.StringVar()
        self.make_entry(c_row1, self.custom_dns_ip_var, 11).pack(side="left", fill="x", expand=True, ipady=2)

        c_row2 = tk.Frame(custom_box, bg=CARD)
        c_row2.pack(fill="x", padx=12, pady=(0, 10))
        self.make_button(c_row2, "+ Добавить", self.on_add_custom_dns, "primary", font=FONT_SMALL_B, padx=8, pady=4).pack(
            side="right", padx=(6, 0)
        )
        tk.Label(c_row2, text="DoH / заметка:", bg=CARD, fg=MUTED, font=FONT_SMALL).pack(side="left", padx=(0, 4))
        self.custom_dns_desc_var = tk.StringVar()
        self.make_entry(c_row2, self.custom_dns_desc_var, 10).pack(side="left", fill="x", expand=True, ipady=2)

        # Scrollable DNS card grid
        wrap = tk.Frame(tab, bg=BG, highlightthickness=1, highlightbackground=BORDER)
        wrap.pack(fill="both", expand=True)

        self.dns_canvas = tk.Canvas(wrap, bg=BG, highlightthickness=0)
        dns_vsb = ttk.Scrollbar(wrap, orient="vertical", command=self.dns_canvas.yview)
        self.dns_canvas.configure(yscrollcommand=dns_vsb.set)
        dns_vsb.pack(side="right", fill="y")
        self.dns_canvas.pack(side="left", fill="both", expand=True)

        self.dns_grid_frame = tk.Frame(self.dns_canvas, bg=BG)
        self._dns_window_id = self.dns_canvas.create_window((0, 0), window=self.dns_grid_frame, anchor="nw")

        self.dns_grid_frame.bind(
            "<Configure>",
            lambda _e: self.dns_canvas.configure(scrollregion=self.dns_canvas.bbox("all")),
        )
        self.dns_canvas.bind(
            "<Configure>",
            lambda e: self.dns_canvas.itemconfigure(self._dns_window_id, width=e.width),
        )
        self.dns_canvas.bind("<MouseWheel>", self._on_dns_mousewheel)
        self.dns_grid_frame.bind("<MouseWheel>", self._on_dns_mousewheel)
        self.dns_canvas.bind("<Enter>", lambda _e: self.dns_canvas.bind_all("<MouseWheel>", self._on_dns_mousewheel))
        self.dns_canvas.bind("<Leave>", lambda _e: self.dns_canvas.unbind_all("<MouseWheel>"))

    def _on_dns_mousewheel(self, event: Any) -> str | None:
        if self._closed:
            return None
        try:
            if not self.dns_canvas.winfo_viewable():
                return None
        except tk.TclError:
            return None
        delta = getattr(event, "delta", 0)
        if delta:
            step = -1 if delta > 0 else 1
            if abs(delta) >= 120:
                step = int(-delta / 120)
            self.dns_canvas.yview_scroll(step, "units")
            return "break"
        return None

    def _bind_dns_mousewheel(self, widget: tk.Misc) -> None:
        """Recursively attach <MouseWheel> handler to all card sub-widgets for Windows scrolling."""
        widget.bind("<MouseWheel>", self._on_dns_mousewheel)
        for child in widget.winfo_children():
            self._bind_dns_mousewheel(child)

    def set_dns_category_filter(self, category: str) -> None:
        self.dns_category_filter = category
        for cid, btn in self._dns_cat_buttons.items():
            self._restyle_button(btn, btn.cget("text"), "primary" if cid == category else "neutral")
        self._dns_signature = ""
        if self.dns_catalog:
            self.render_dns_grid(self.dns_catalog, self.active_dns_id)

    def load_dns_catalog_async(self) -> None:
        def done(data: dict[str, Any]) -> None:
            self.dns_catalog = list(data.get("servers") or [])
            self.active_dns_id = str(data.get("active_dns_id") or "cloudflare")
            self.render_dns_grid(self.dns_catalog, self.active_dns_id)

        def runner() -> None:
            try:
                data = self.backend.get_dns_catalog()
            except Exception:  # noqa: BLE001
                return
            self._post(done, data)

        threading.Thread(target=runner, name="gui-dns-cat", daemon=True).start()

    def render_dns_grid(self, servers: list[dict[str, Any]], active_dns_id: str) -> None:
        """Render the categorized card grid of DNS servers."""
        self.dns_catalog = list(servers)
        self.active_dns_id = active_dns_id
        self.notebook.tab(self.tab_dns, text=f"DNS и Нейросети ({len(servers)})")
        self._update_nav_badge(self.tab_dns, str(len(servers)))

        active_srv = next((s for s in servers if s.get("id") == active_dns_id), None)
        if active_srv:
            self.active_dns_pill.configure(
                text=f"Активный общий DNS: {active_srv.get('name', active_dns_id)} ({active_srv.get('ip', '')})"
            )

        sig = repr(
            (
                self.dns_category_filter,
                active_dns_id,
                [
                    (s.get("id"), s.get("ping_ms"), s.get("alive"), tuple(s.get("assigned_domains") or []))
                    for s in servers
                ],
            )
        )
        if sig == self._dns_signature:
            return
        self._dns_signature = sig

        for child in self.dns_grid_frame.winfo_children():
            child.destroy()

        cat_meta: tuple[tuple[str, str, str], ...] = (
            ("popular", "Популярные", "быстрые мировые и локальные DNS"),
            ("security", "Безопасные", "с защитой от вирусов, рекламы или 18+"),
            ("uncommon", "Малоизвестные", "реже попадают под блокировки"),
            ("ai_bypass", "Для ИИ", "серверы сообщества — ChatGPT, Claude, Grok, Spotify"),
            ("custom", "Мои DNS", "добавленные вами вручную"),
        )
        cat_colors = {
            "popular": ACCENT,
            "security": OK_TEXT,
            "uncommon": PURPLE,
            "ai_bypass": WARN_TEXT,
            "custom": "#FB923C",
        }

        for cat_id, cat_title, cat_hint in cat_meta:
            if self.dns_category_filter != "ALL" and self.dns_category_filter != cat_id:
                continue
            items = [s for s in servers if s.get("category") == cat_id]
            if not items and cat_id != "custom":
                continue

            sec_hdr = tk.Frame(self.dns_grid_frame, bg=BG)
            sec_hdr.pack(fill="x", padx=12, pady=(12, 4))
            tk.Label(sec_hdr, text=cat_title, bg=BG, fg=FG, font=FONT_H2).pack(side="left")
            tk.Label(sec_hdr, text=f" {len(items)} ", bg=INPUT, fg=MUTED, font=FONT_MICRO, padx=5, pady=1).pack(
                side="left", padx=(8, 0)
            )
            if cat_hint:
                tk.Label(sec_hdr, text=cat_hint, bg=BG, fg=MUTED, font=FONT_SMALL).pack(side="left", padx=(10, 0))

            if not items:
                tk.Label(
                    self.dns_grid_frame,
                    text="Добавьте свой DNS-сервер справа вверху — он появится в этом разделе.",
                    bg=BG,
                    fg=MUTED,
                    font=FONT_SMALL,
                    anchor="w",
                ).pack(fill="x", padx=12, pady=(0, 8))
                continue

            grid = tk.Frame(self.dns_grid_frame, bg=BG)
            grid.pack(fill="x", padx=6, pady=(0, 4))
            for c_idx in range(3):
                grid.columnconfigure(c_idx, weight=1, uniform=f"dns_{cat_id}")

            for idx, srv in enumerate(items):
                r_idx, c_idx = divmod(idx, 3)
                self._make_dns_card(grid, r_idx, c_idx, srv, cat_colors.get(cat_id, ACCENT), srv["id"] == active_dns_id)

        self._bind_dns_mousewheel(self.dns_grid_frame)

    def _make_dns_card(
        self,
        parent: tk.Misc,
        row: int,
        col: int,
        srv: dict[str, Any],
        accent_color: str,
        is_active: bool,
    ) -> None:
        card_bg = CARD_ACTIVE if is_active else CARD
        hover_bg = CARD_ACTIVE if is_active else CARD_ALT
        border_col = ACCENT if is_active else BORDER
        border_w = 2 if is_active else 1

        card = tk.Frame(
            parent,
            bg=card_bg,
            highlightthickness=border_w,
            highlightbackground=border_col,
            cursor="hand2",
        )
        card.grid(row=row, column=col, sticky="nsew", padx=4, pady=4)

        top = tk.Frame(card, bg=card_bg)
        top.pack(fill="x", padx=8, pady=(8, 2))
        clickable: list[tk.Misc] = [card, top]
        hover_widgets: list[tk.Misc] = [top]

        if is_active:
            chk = tk.Label(top, text="✔ Общий", bg=INFO_BG, fg=ACCENT, font=FONT_MICRO, padx=5, pady=1)
            chk.pack(side="right", padx=(4, 0))
            clickable.append(chk)

        if not srv.get("builtin", True):
            del_btn = tk.Label(top, text="✕", bg=card_bg, fg=ERR_TEXT, font=FONT_SMALL_B, cursor="hand2", padx=4)
            del_btn.pack(side="right", padx=(0, 4))
            del_btn.bind("<Button-1>", lambda _e, sid=srv["id"]: self.on_delete_custom_dns(sid))
            hover_widgets.append(del_btn)

        dot = tk.Label(top, text="●", bg=card_bg, fg=accent_color, font=FONT_SMALL_B)
        dot.pack(side="left", padx=(0, 4))
        name_lbl = tk.Label(top, text=str(srv.get("name", "")), bg=card_bg, fg=FG, font=FONT_SMALL_B, anchor="w")
        name_lbl.pack(side="left", fill="x", expand=True)
        clickable.extend([dot, name_lbl])
        hover_widgets.extend([dot, name_lbl])

        desc_lbl = tk.Label(
            card,
            text=str(srv.get("description") or ""),
            bg=card_bg,
            fg=MUTED,
            font=FONT_SMALL,
            anchor="w",
            justify="left",
            wraplength=175,
        )
        desc_lbl.pack(fill="x", padx=8, pady=(0, 4))
        self._bind_responsive_wrap(desc_lbl, min_wrap=150, pad=18)
        clickable.append(desc_lbl)
        hover_widgets.append(desc_lbl)

        assigned = list(srv.get("assigned_domains") or [])
        if assigned:
            preview_doms = ", ".join(assigned[:3]) + (f" (+{len(assigned) - 3})" if len(assigned) > 3 else "")
            asg_lbl = tk.Label(
                card,
                text=f"Персонально: {preview_doms}",
                bg=OK_BG,
                fg=OK_TEXT,
                font=FONT_MICRO,
                anchor="w",
                justify="left",
                wraplength=175,
                padx=6,
                pady=2,
            )
            asg_lbl.pack(fill="x", padx=8, pady=(0, 4))
            self._bind_responsive_wrap(asg_lbl, min_wrap=150, pad=18)
            clickable.append(asg_lbl)

        meta_row = tk.Frame(card, bg=card_bg)
        meta_row.pack(fill="x", padx=8, pady=(2, 4 if srv.get("badges") else 8))

        ping_val = srv.get("ping_ms")
        alive = srv.get("alive")
        if alive is True and ping_val is not None:
            p_ms = float(ping_val)
            p_color = OK_TEXT if p_ms < 55 else (WARN_TEXT if p_ms < 115 else ERR_TEXT)
            p_text = f"● {p_ms:.0f} мс"
        elif alive is False:
            p_color = MUTED
            p_text = "● нет ответа"
        else:
            p_color = DIM
            p_text = "● не проверен"

        ping_lbl = tk.Label(meta_row, text=p_text, bg=card_bg, fg=p_color, font=FONT_SMALL)
        ping_lbl.pack(side="right", padx=(6, 0))
        ip_lbl = tk.Label(meta_row, text=str(srv.get("ip", "")), bg=card_bg, fg=FG_SOFT, font=FONT_MONO_S, anchor="w")
        ip_lbl.pack(side="left", fill="x", expand=True)
        clickable.extend([meta_row, ip_lbl, ping_lbl])
        hover_widgets.extend([meta_row, ip_lbl, ping_lbl])

        badges_list = list(srv.get("badges") or [])[:3]
        if badges_list:
            badges_row = tk.Frame(card, bg=card_bg)
            badges_row.pack(fill="x", padx=8, pady=(0, 8))
            clickable.append(badges_row)
            hover_widgets.append(badges_row)
            for idx_b, badge in enumerate(badges_list):
                b_str = str(badge)
                if b_str == "блокируется":
                    b_bg, b_fg = ERR_BG, ERR_TEXT
                elif b_str == "под угрозой":
                    b_bg, b_fg = WARN_BG, WARN_TEXT
                elif b_str == "DoH":
                    b_bg, b_fg = INFO_BG, ACCENT
                else:
                    b_bg, b_fg = INPUT, MUTED
                b_lbl = tk.Label(badges_row, text=b_str, bg=b_bg, fg=b_fg, font=FONT_MICRO, padx=5, pady=1)
                b_lbl.pack(side="left", padx=(0 if idx_b == 0 else 3, 0))
                clickable.append(b_lbl)

        if not is_active:
            self._bind_card_hover(card, hover_widgets, card_bg, hover_bg, border_col, accent_color)

        sid = str(srv["id"])
        for widget in clickable:
            widget.bind("<Button-1>", lambda _e, s_id=sid: self.on_select_dns(s_id))

    # ---------------------------------------------------------------- Live Connections helpers (unified inside tab_domains)

    def _on_conn_context_menu(self, event: Any) -> None:
        iid = self.conn_tree.identify_row(event.y)
        if iid:
            self.conn_tree.selection_set(iid)
            self.on_conn_select()
            try:
                self._conn_menu.tk_popup(event.x_root, event.y_root)
            finally:
                self._conn_menu.grab_release()

    def _open_selected_conn_domain(self) -> None:
        if not self.selected_conn:
            return
        dom = normalize_domain(str(self.selected_conn.get("domain") or ""))
        if not dom:
            return
        self.layer_filter_var.set("ALL")
        self.search_var.set(dom)
        self._open_domains_subview("domains")

    def _copy_selected_conn_domain(self) -> None:
        if not self.selected_conn:
            return
        dom = str(self.selected_conn.get("domain") or "").strip()
        if dom and dom != "—":
            self.clipboard_clear()
            self.clipboard_append(dom)
            self.set_status(f"Скопировано в буфер: {dom}", ACCENT)

    def _set_conn_health_filter(self, health: str) -> None:
        self.conn_health_filter = health
        for fid, btn in self._conn_filter_buttons.items():
            self._restyle_button(btn, btn.cget("text"), "primary" if fid == health else "neutral")
        self.populate_connections_table(self.live_connections, events=self._last_conn_events)

    # ---------------------------------------------------------------- Tab 5: VPN Подписки и Журналы

    def _build_vpn_tab(self) -> None:
        tab = self.tab_vpn
        self._make_page_header(
            tab,
            "VPN-подписки и журналы служб",
            "Обычный трафик идёт напрямую; VPN-туннель sing-box используется точечно для сайтов из слоя «vpn».",
        )

        vpn_card = tk.Frame(tab, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
        vpn_card.pack(fill="x", pady=(0, 8))

        row1 = tk.Frame(vpn_card, bg=CARD)
        row1.pack(fill="x", padx=12, pady=(8, 5))
        self.make_button(row1, "Обновить подписки", self.on_refresh_subscriptions, "neutral", font=FONT_SMALL_B, padx=9, pady=4).pack(
            side="right", padx=(4, 0)
        )
        self.make_button(row1, "+ Добавить", self.on_add_subscription, "primary", font=FONT_SMALL_B, padx=10, pady=4).pack(
            side="right", padx=(8, 0)
        )
        tk.Label(row1, text="Подписка / URI:", bg=CARD, fg=MUTED, font=FONT_SMALL_B).pack(side="left", padx=(0, 8))
        self.sub_var = tk.StringVar()
        sub_entry = self.make_entry(row1, self.sub_var, 20)
        sub_entry.pack(side="left", ipady=3, fill="x", expand=True)
        sub_entry.bind("<Return>", lambda _e: self.on_add_subscription())

        tk.Frame(vpn_card, bg=BORDER_LIGHT, height=1).pack(fill="x", padx=12)

        row2 = tk.Frame(vpn_card, bg=CARD)
        row2.pack(fill="x", padx=12, pady=(5, 8))
        self.make_button(row2, "Ротировать узел", self.on_rotate_vpn_node, "warn", font=FONT_SMALL_B, padx=9, pady=4).pack(
            side="right", padx=(6, 0)
        )
        self.make_button(
            row2, "Проверить туннель / пинг", self.on_ping_vpn_nodes, "success", font=FONT_SMALL_B, padx=9, pady=4
        ).pack(side="right", padx=(8, 0))
        self._vpn_summary_lbl = tk.Label(
            row2,
            text="Узлы VPN-пула (Circuit Breaker и задержка внутри туннеля)",
            bg=CARD,
            fg=FG_SOFT,
            font=FONT_SMALL,
            anchor="w",
            justify="left",
        )
        self._vpn_summary_lbl.pack(side="left", fill="x", expand=True)
        self._bind_responsive_wrap(self._vpn_summary_lbl, min_wrap=200, pad=16)

        paned = ttk.PanedWindow(tab, orient="vertical")
        paned.pack(fill="both", expand=True)

        vpn_wrap = tk.Frame(paned, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
        self.vpn_tree = self.make_tree(vpn_wrap, ("tag", "region", "protocol", "transport", "server", "health"), height=6)
        for cid, title, width in (
            ("tag", "Сервер (tag)", 180),
            ("region", "Регион", 70),
            ("protocol", "Протокол", 85),
            ("transport", "Транспорт", 85),
            ("server", "Адрес : Порт / Пинг", 220),
            ("health", "Circuit Breaker / Статус", 175),
        ):
            self.vpn_tree.heading(cid, text=title)
            self.vpn_tree.column(cid, width=width, anchor="w", stretch=cid in ("tag", "health"))  # type: ignore[arg-type]
        self.vpn_tree.tag_configure("ok", foreground=OK_TEXT)
        self.vpn_tree.tag_configure("warn", foreground=WARN_TEXT)
        self.vpn_tree.tag_configure("bad", foreground=ERR_TEXT)
        self._scrolled(vpn_wrap, self.vpn_tree, horizontal=True)
        paned.add(vpn_wrap, weight=2)

        log_panel = tk.Frame(paned, bg=BG)
        head = tk.Frame(log_panel, bg=BG)
        head.pack(fill="x", pady=(8, 4))
        tk.Label(head, text="Журнал фоновой службы:", bg=BG, fg=FG_SOFT, font=FONT_SMALL_B).pack(side="left", padx=(0, 8))
        self.log_var = tk.StringVar(value=LOG_FILES[0])
        log_cb = ttk.Combobox(head, textvariable=self.log_var, values=LOG_FILES, state="readonly", width=20)
        log_cb.pack(side="left")
        log_cb.bind("<<ComboboxSelected>>", lambda _e: self.refresh_logs_async())
        tk.Label(head, text="● автообновление 2с", bg=OK_BG, fg=OK_TEXT, font=FONT_MICRO, padx=7, pady=2).pack(
            side="left", padx=10
        )

        # Smart inline alert bar (shown only when actionable error detected in sing-box.log)
        self._log_alert_bar = tk.Frame(log_panel, bg=WARN_BG, highlightthickness=1, highlightbackground=WARN)
        self.make_button(
            self._log_alert_bar,
            "Открыть DNS →",
            lambda: self._select_tab(self.tab_dns),
            "warn",
            font=FONT_MICRO,
            padx=8,
            pady=2,
        ).pack(side="right", padx=8, pady=4)
        self._log_alert_lbl = tk.Label(
            self._log_alert_bar, text="", bg=WARN_BG, fg=WARN_TEXT, font=FONT_SMALL, anchor="w", justify="left"
        )
        self._log_alert_lbl.pack(side="left", fill="x", expand=True, padx=10, pady=5)
        self._bind_responsive_wrap(self._log_alert_lbl, min_wrap=220, pad=20)

        wrap = tk.Frame(log_panel, bg=SIDEBAR_BG, highlightthickness=1, highlightbackground=BORDER)
        wrap.pack(fill="both", expand=True)
        self.log_view = self.make_text(wrap, height=10, wrap="none")
        self.log_view.configure(font=FONT_MONO_S)
        self.log_view.tag_configure("err", foreground=ERR_TEXT)
        self.log_view.tag_configure("warn", foreground=WARN_TEXT)
        self.log_view.tag_configure("info", foreground=FG_SOFT)
        self.log_view.tag_configure("muted", foreground=MUTED)
        self._scrolled(wrap, self.log_view, horizontal=True)
        paned.add(log_panel, weight=3)

    # ---------------------------------------------------------------- Tab 6: Сервис и Конфиги

    def _build_service_tab(self) -> None:
        tab = self.tab_service
        self._make_page_header(
            tab,
            "Сервис, исключения и конфигурация",
            "Управление службами, защита сторонних анлокеров и просмотр сгенерированных файлов winws2 / sing-box.",
        )

        body = tk.Frame(tab, bg=BG)
        body.pack(fill="both", expand=True)

        # Left column: actions, settings, exit
        left = tk.Frame(body, bg=BG, width=282)
        left.pack(side="left", fill="y", padx=(0, 10))
        left.pack_propagate(False)

        act_card = tk.Frame(left, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
        act_card.pack(fill="x", pady=(0, 5))
        tk.Label(act_card, text="Обслуживание стека", bg=CARD, fg=ACCENT, font=FONT_UI_B, anchor="w").pack(
            fill="x", padx=10, pady=(6, 3)
        )
        handlers: dict[str, Callable[[], None]] = {
            "layers": self.on_check_layers,
            "reload": self.on_reload,
            "reload_sb": self.on_reload_singbox,
            "reval": self.on_revalidate,
            "gen": self.on_generate,
            "verify": self.on_verify,
        }
        kinds = {"layers": "primary"}
        for key, title in SERVICE_ACTIONS:
            btn = self.make_button(act_card, title, handlers[key], kinds.get(key, "neutral"), font=FONT_SMALL_B, padx=9, pady=3)
            btn.configure(anchor="w")
            btn.pack(fill="x", padx=10, pady=1)
        tk.Frame(act_card, bg=CARD, height=5).pack()

        opt_card = tk.Frame(left, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
        opt_card.pack(fill="x", pady=(0, 5))
        tk.Label(opt_card, text="Параметры работы", bg=CARD, fg=ACCENT, font=FONT_UI_B, anchor="w").pack(
            fill="x", padx=10, pady=(6, 3)
        )
        for var, label, cmd in (
            (self.minimize_to_tray_var, "Сворачивать в трей при закрытии (X)", None),
            (self.autostart_var, "Автозапуск Windows при входе", self.on_toggle_autostart),
            (self.dpi_only_var, "Режим без TUN (только Zapret2 + TG)", self.on_toggle_dpi_only),
            (self.byedpi_var, "ByeDPI SOCKS5 резерв (ciadpi.exe)", self.on_toggle_byedpi),
            (self.debug_log_var, "Подробный лог winws2 (--debug=1)", self.on_toggle_debug_log),
        ):
            tk.Checkbutton(
                opt_card,
                text=label,
                variable=var,
                command=cmd,
                bg=CARD,
                fg=FG_SOFT,
                selectcolor=PRIMARY_BG,
                activebackground=CARD,
                activeforeground=ACCENT,
                font=FONT_SMALL,
                cursor="hand2",
                anchor="w",
                bd=0,
                highlightthickness=0,
            ).pack(fill="x", padx=9, pady=1)

        net_row = tk.Frame(opt_card, bg=CARD)
        net_row.pack(fill="x", padx=10, pady=(4, 6))
        tk.Label(net_row, text="TUN:", bg=CARD, fg=MUTED, font=FONT_SMALL).pack(side="left", padx=(0, 4))
        self.tun_stack_cb = ttk.Combobox(
            net_row,
            textvariable=self.tun_stack_var,
            values=("gvisor", "mixed", "system"),
            state="readonly",
            width=7,
        )
        self.tun_stack_cb.pack(side="left", padx=(0, 8))
        self.tun_stack_cb.bind("<<ComboboxSelected>>", lambda _e: self.on_change_tun_stack())

        tk.Label(net_row, text="ifIndex:", bg=CARD, fg=MUTED, font=FONT_SMALL).pack(side="left", padx=(0, 4))
        self.iface_var = tk.StringVar()
        self.make_entry(net_row, self.iface_var, 6).pack(side="left", fill="x", expand=True, ipady=2)

        exit_btn = self.make_button(
            left, "Полный выход (остановить службы)", self.on_exit_app, "danger", font=FONT_SMALL_B, pady=4
        )
        exit_btn.pack(fill="x", pady=(1, 0))

        # Right column: Unlocker Guard + Vertical Split (Config Preview + Operations Console)
        right = tk.Frame(body, bg=BG)
        right.pack(side="left", fill="both", expand=True)

        guard_box = tk.Frame(right, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
        guard_box.pack(fill="x", pady=(0, 6))
        tk.Label(
            guard_box,
            text="Защита сторонних анлокеров (Antigravity Unlocker, hosts, прокси)",
            bg=CARD,
            fg=OK_TEXT,
            font=FONT_UI_B,
            anchor="w",
        ).pack(fill="x", padx=12, pady=(6, 2))
        self.unlocker_guard_var = tk.BooleanVar(value=True)
        tk.Checkbutton(
            guard_box,
            text="Не трогать Antigravity.exe, Cursor, ag_dns.exe, xray/happ и hosts",
            variable=self.unlocker_guard_var,
            command=self.on_save_unlocker_guard,
            bg=CARD,
            fg=FG_SOFT,
            selectcolor=PRIMARY_BG,
            activebackground=CARD,
            activeforeground=ACCENT,
            font=FONT_SMALL,
            cursor="hand2",
            bd=0,
            highlightthickness=0,
        ).pack(anchor="w", padx=10, pady=(0, 3))
        g_row = tk.Frame(guard_box, bg=CARD)
        g_row.pack(fill="x", padx=12, pady=(0, 8))
        self.make_button(g_row, "Сохранить", self.on_save_unlocker_guard, "primary", font=FONT_SMALL_B, pady=3).pack(
            side="right", padx=(6, 0)
        )
        tk.Label(g_row, text="Исключения (.exe, домены, IP):", bg=CARD, fg=MUTED, font=FONT_SMALL).pack(
            side="left", padx=(0, 6)
        )
        self.unlocker_custom_var = tk.StringVar()
        self.make_entry(g_row, self.unlocker_custom_var, 12).pack(side="left", fill="x", expand=True, ipady=2)

        r_paned = ttk.PanedWindow(right, orient="vertical")
        r_paned.pack(fill="both", expand=True)

        preview_panel = tk.Frame(r_paned, bg=BG)
        head = tk.Frame(preview_panel, bg=BG)
        head.pack(fill="x", pady=(0, 4))
        self.make_button(head, "↻ Обновить", self.refresh_previews_async, "neutral", font=FONT_SMALL_B, pady=3).pack(
            side="right", padx=(6, 0)
        )
        tk.Label(head, text="Просмотр файла:", bg=BG, fg=FG_SOFT, font=FONT_SMALL_B).pack(side="left", padx=(0, 8))
        self.file_var = tk.StringVar()
        self.file_cb = ttk.Combobox(head, textvariable=self.file_var, state="readonly", width=24)
        self.file_cb.pack(side="left", fill="x", expand=True)
        self.file_cb.bind("<<ComboboxSelected>>", lambda _e: self.show_selected_file())
        wrap = tk.Frame(preview_panel, bg=SIDEBAR_BG, highlightthickness=1, highlightbackground=BORDER)
        wrap.pack(fill="both", expand=True)
        self.preview = self.make_text(wrap, height=8, wrap="none")
        self._scrolled(wrap, self.preview, horizontal=True)
        r_paned.add(preview_panel, weight=3)

        con_panel = tk.Frame(r_paned, bg=BG)
        tk.Label(con_panel, text="Журнал операций", bg=BG, fg=ACCENT, font=FONT_SMALL_B, anchor="w").pack(
            fill="x", pady=(4, 3)
        )
        con_wrap = tk.Frame(con_panel, bg=SIDEBAR_BG, highlightthickness=1, highlightbackground=BORDER)
        con_wrap.pack(fill="both", expand=True)
        self.console = self.make_text(con_wrap, height=5, wrap="word")
        self.console.configure(font=FONT_MONO_S)
        self.console.tag_configure("muted", foreground=MUTED)
        self.console.tag_configure("ok", foreground=OK_TEXT)
        self.console.tag_configure("bad", foreground=ERR_TEXT)
        self._scrolled(con_wrap, self.console)
        r_paned.add(con_panel, weight=2)

    # ---------------------------------------------------------------- snapshot / cards / header updates

    def refresh_async(self, *, run_watchdog: bool = False) -> None:
        """Quietly reload the full status snapshot in a background thread (and run winws2 watchdog on ticks)."""
        if self._refreshing or self._closed:
            return
        self._refreshing = True

        def done(payload: tuple[dict[str, Any], dict[str, Any] | None]) -> None:
            self._refreshing = False
            snap, wd = payload
            self.apply_snapshot(snap)
            if isinstance(wd, dict) and wd.get("restarted"):
                cnt = wd.get("restarts_count", 1)
                reason = wd.get("crash_reason") or "внезапное завершение"
                self.log_console(f"[WATCHDOG] winws2.exe автоматически перезапущен (#{cnt}): {reason}")
                self.set_status(f"Watchdog восстановил winws2.exe после сбоя (#{cnt})", WARN_TEXT)
            elif isinstance(wd, dict) and wd.get("fallback_switched_to"):
                fb_id = wd.get("fallback_switched_to")
                self.log_console(f"[WATCHDOG] Автооткат пресета после повторных сбоев -> {fb_id}")
                self.set_status(f"Watchdog откатил пресет на безопасный ({fb_id})", WARN_TEXT)
            elif isinstance(wd, dict) and wd.get("capped"):
                self.log_console(
                    f"[WATCHDOG] winws2.exe падал слишком часто ({wd.get('restarts_count', 0)} раз) — "
                    f"проверьте лог winws2.log: {wd.get('last_crash_reason', '')}"
                )

        def failed(exc: Exception) -> None:
            self._refreshing = False
            self.set_status(f"Снимок состояния: {exc}", ERR_TEXT)

        def runner() -> None:
            try:
                wd_res: dict[str, Any] | None = None
                if run_watchdog and hasattr(self.backend, "ensure_services_healthy"):
                    try:
                        wd_res = self.backend.ensure_services_healthy()
                    except Exception:  # noqa: BLE001
                        wd_res = None
                snap = self.backend.get_status_snapshot()
            except Exception as exc:  # noqa: BLE001
                self._post(failed, exc)
            else:
                self._post(done, (snap, wd_res))

        threading.Thread(target=runner, name="gui-snapshot", daemon=True).start()

    def _watchdog_only_async(self) -> None:
        """Lightweight tray-mode watchdog tick skipping full snapshot/UI redraws."""
        if self._refreshing or self._closed or not hasattr(self.backend, "ensure_services_healthy"):
            return
        self._refreshing = True

        def done(wd: dict[str, Any] | None) -> None:
            self._refreshing = False
            if isinstance(wd, dict) and wd.get("restarted"):
                cnt = wd.get("restarts_count", 1)
                self.log_console(f"[WATCHDOG/tray] Перезапуск {', '.join(wd['restarted'])} (#{cnt})")
            elif isinstance(wd, dict) and wd.get("fallback_switched_to"):
                self.log_console(f"[WATCHDOG/tray] Автооткат пресета -> {wd.get('fallback_switched_to')}")

        def runner() -> None:
            try:
                wd = self.backend.ensure_services_healthy()
            except Exception:  # noqa: BLE001
                wd = None
            self._post(done, wd)

        threading.Thread(target=runner, name="gui-watchdog", daemon=True).start()

    def _snapshot_tick(self) -> None:
        if self._closed:
            return
        if self._busy == 0:
            if self._is_window_hidden():
                self._watchdog_only_async()
            else:
                self.refresh_async(run_watchdog=True)
        self.after(self.SNAPSHOT_INTERVAL_MS, self._snapshot_tick)

    def apply_snapshot(self, snap: dict[str, Any]) -> None:
        """Update header, layer cards, preset bar, test pills, domain table, and VPN table from snapshot."""
        self.last_snapshot = snap
        asn = snap.get("network_asn", 0)
        kind = snap.get("network_kind", "unknown")
        isp = str(snap.get("network_isp") or "")
        net_text = f"Сеть: AS{asn} • {kind}"
        if isp and isp != "unknown":
            isp_short = f"{isp[:14].rstrip()}…" if len(isp) > 16 else isp
            net_text += f" ({isp_short})"
        self.network_label.configure(text=net_text)

        is_admin = bool(snap.get("is_admin"))
        if is_admin:
            self.priv_label.configure(text="ADMIN ✔", bg=OK_BG, fg=OK_TEXT)
            self.priv_btn.pack_forget()
        else:
            self.priv_label.configure(text="Нужны права Admin", bg=WARN_BG, fg=WARN_TEXT)
            if not self.priv_btn.winfo_manager():
                self.priv_btn.pack(side="right", padx=(0, 8))

        ext_bypass = snap["external_bypass_active"] if "external_bypass_active" in snap else snap.get("bypass_active")
        if ext_bypass:
            self.bypass_label.configure(text="⚠ Обнаружен сторонний обход/VPN")
            if not self.bypass_label.winfo_manager():
                self.bypass_label.pack(fill="x", anchor="w", pady=(4, 0), before=self.hint_label)
        else:
            self.bypass_label.configure(text="")
            if self.bypass_label.winfo_manager():
                self.bypass_label.pack_forget()

        dns_alert = snap.get("dns_alert")
        if dns_alert:
            self._home_alert_lbl.configure(text=f"⚠ {dns_alert}")
            if not self._home_alert_frame.winfo_manager():
                self._home_alert_frame.pack(fill="x", pady=(0, 6), before=self._home_section1_lbl)
        elif self._home_alert_frame.winfo_manager():
            self._home_alert_frame.pack_forget()

        if "active_preset_id" in snap:
            self.active_preset_id = str(snap.get("active_preset_id") or "auto")
            self.active_preset_name = str(snap.get("active_preset_name") or "Авто-оркестратор (подбор по доменам)")
            self._sync_active_preset_indicators()
        if "zapret_presets_count" in snap:
            self._update_nav_badge(self.tab_presets, str(snap.get("zapret_presets_count") or 0))

        processes = snap.get("processes") or {}
        for key, (canvas, oval, lbl) in self.leds.items():
            running = bool((processes.get(key) or {}).get("running"))
            canvas.itemconfigure(oval, fill=OK if running else ERR)
            lbl.configure(fg=FG if running else MUTED)

        stack_running = bool(snap.get("running"))
        preset_locked = self.active_preset_id != "auto"
        wd = snap.get("watchdog") or {}
        wd_cnt = int(wd.get("restarts_count") or 0)
        wd_note = f"  •  Watchdog перезапусков: {wd_cnt}" if wd_cnt > 0 else ""

        if stack_running:
            self._restyle_button(self.autopilot_btn, "Остановить защиту", "danger")
            self.hero_state_pill.configure(text="● Защита активна", bg=OK_BG, fg=OK_TEXT)
            if preset_locked:
                self.hint_label.configure(
                    text=f"Работает пресет «{self.active_preset_name}» — оркестратор на паузе, Watchdog следит за winws2.{wd_note}",
                    fg=OK_TEXT,
                )
            elif self.radar_enabled:
                self.hint_label.configure(
                    text=f"Защита работает + Live-Радар активен — стратегии подбираются на лету.{wd_note}",
                    fg=OK_TEXT,
                )
            else:
                self.hint_label.configure(
                    text=f"Защита работает. Live-Радар выключен — включите на «Главной» для автолечения.{wd_note}",
                    fg=ACCENT,
                )
        else:
            self._restyle_button(self.autopilot_btn, "Включить защиту", "success")
            self.hero_state_pill.configure(text="● Защита выключена", bg=INPUT, fg=MUTED)
            if is_admin:
                self.hint_label.configure(
                    text="Выберите готовый пресет Zapret2 (или Авто-оркестратор) и нажмите «Включить защиту».",
                    fg=FG_SOFT,
                )
            else:
                self.hint_label.configure(
                    text="Нажмите «Запустить от Admin» или «Включить защиту» для запроса прав.",
                    fg=WARN_TEXT,
                )

        if "game_filter" in snap:
            self.game_filter_var.set(bool(snap["game_filter"]))
        if "byedpi_fallback" in snap:
            self.byedpi_var.set(bool(snap["byedpi_fallback"]))
        if "winws2_debug_log" in snap:
            self.debug_log_var.set(bool(snap["winws2_debug_log"]))
        if "stack_mode" in snap:
            self.dpi_only_var.set(str(snap["stack_mode"]) == "dpi_only")
        if "tun_stack" in snap and str(snap["tun_stack"]) in ("gvisor", "mixed", "system"):
            self.tun_stack_var.set(str(snap["tun_stack"]))
        preset_err = str(snap.get("preset_compile_error") or "")
        if preset_err:
            if preset_err != self._last_preset_err_shown:
                self._last_preset_err_shown = preset_err
                self.log_console(f"[ERROR] {preset_err}")
                self.set_status(preset_err, ERR_TEXT)
        else:
            self._last_preset_err_shown = ""
        if self._tray is not None:
            state_txt = "Защита ВКЛ" if stack_running else "Остановлен"
            self._tray.update_tooltip(f"netdoctor — {state_txt} (AS{asn})")
            self._tray.set_icon_state("active" if stack_running else "idle")

        guard = snap.get("unlocker_guard")
        if isinstance(guard, dict):
            enabled = bool(guard.get("enabled", True))
            self.unlocker_guard_var.set(enabled)
            if not self._unlocker_custom_synced:
                if guard.get("custom_exclusions"):
                    self.unlocker_custom_var.set(str(guard["custom_exclusions"]))
                self._unlocker_custom_synced = True
            if enabled:
                self.unlocker_status_label.configure(
                    text=(
                        f"Защита Antigravity Unlocker и hosts: АКТИВНА "
                        f"(исключено {guard.get('hosts_domains_count', 0)} доменов из hosts и "
                        f"{guard.get('hosts_proxy_ips_count', 0)} прокси-IP)"
                    ),
                    fg=OK_TEXT,
                )
            else:
                self.unlocker_status_label.configure(
                    text="⚠ Защита сторонних анлокеров и hosts отключена пользователем",
                    fg=WARN_TEXT,
                )

        if "active_dns_id" in snap and snap["active_dns_id"] != self.active_dns_id:
            self.active_dns_id = str(snap["active_dns_id"])
            if self.dns_catalog:
                self.render_dns_grid(self.dns_catalog, self.active_dns_id)

        if isinstance(snap.get("test_summary"), dict):
            self._update_test_summary_ui(snap["test_summary"])

        if "orchestrators" in snap and isinstance(snap["orchestrators"], dict):
            self.update_layer_cards(snap["orchestrators"])

        self.populate_domain_table(snap.get("domain_rows") or [])
        self.populate_vpn_table(snap.get("vpn_nodes") or [])

    def _sync_active_preset_indicators(self) -> None:
        is_preset = self.active_preset_id != "auto"
        short_name = (
            self.active_preset_name[:34] + "…" if len(self.active_preset_name) > 36 else self.active_preset_name
        )
        if is_preset:
            self.home_preset_mode_pill.configure(text=f"🔒 Пресет: {short_name}", bg=OK_BG, fg=OK_TEXT)
            self.presets_active_lbl.configure(
                text=f"Активный пресет: {self.active_preset_name}  (оркестратор не перебирает правила)",
                fg=OK_TEXT,
            )
        else:
            self.home_preset_mode_pill.configure(text="● Авто-оркестратор", bg=INFO_BG, fg=ACCENT)
            self.presets_active_lbl.configure(
                text="Активный режим: Авто-оркестратор (подбор по доменам)",
                fg=ACCENT,
            )
        if self.active_preset_id in self._home_preset_id_to_label:
            self.home_preset_var.set(self._home_preset_id_to_label[self.active_preset_id])
        elif not is_preset:
            self.home_preset_var.set("Авто-оркестратор (подбор по доменам)")

    def _update_test_summary_ui(self, summary: dict[str, Any]) -> None:
        by_srv = summary.get("by_service") or {}
        labels = {"youtube": "YouTube", "discord": "Discord", "telegram": "Telegram"}
        for key, title in labels.items():
            pill = self._home_service_pills.get(key)
            if pill is None:
                continue
            info = by_srv.get(key)
            if not info:
                pill.configure(text=f"● {title}: —", bg=INPUT, fg=MUTED)
            else:
                rate = info.get("success_rate")
                rate_s = f"{rate:.0f}%" if rate is not None else "—"
                if info.get("ok"):
                    pill.configure(text=f"✔ {title}: {rate_s}", bg=OK_BG, fg=OK_TEXT)
                elif info.get("partial"):
                    pill.configure(text=f"◐ {title}: {rate_s}", bg=WARN_BG, fg=WARN_TEXT)
                else:
                    pill.configure(text=f"✖ {title}: {rate_s}", bg=ERR_BG, fg=ERR_TEXT)

        overall = summary.get("overall_success_rate")
        tested = int(summary.get("tested_domains") or 0)
        passing = int(summary.get("passing_domains") or 0)
        if overall is None or tested == 0:
            self.home_test_rate_pill.configure(text="Успех: —", bg=INFO_BG, fg=ACCENT)
            rate_str = "—"
        else:
            rate_str = f"{overall:.0f}% ({passing}/{tested})"
            if overall >= 80.0:
                self.home_test_rate_pill.configure(text=f"Успех: {rate_str}", bg=OK_BG, fg=OK_TEXT)
            elif overall >= 40.0:
                self.home_test_rate_pill.configure(text=f"Успех: {rate_str}", bg=WARN_BG, fg=WARN_TEXT)
            else:
                self.home_test_rate_pill.configure(text=f"Успех: {rate_str}", bg=ERR_BG, fg=ERR_TEXT)

        self._domains_test_summary_lbl.configure(
            text=(
                f"Успех тестов: {rate_str}  •  Подобрано: {len(self.all_rows)}  •  "
                f"Живых сокетов: {len(self.live_connections)}"
            )
        )

    def update_layer_cards(self, orch: dict[str, Any]) -> None:
        dns = orch.get("dns") or {}
        rtt_txt = f" ({dns['best_rtt_ms']} мс)" if dns.get("best_rtt_ms") is not None else ""
        dns_name = dns.get("best_name") or ""
        dns_ip = dns.get("best_server", "1.1.1.1")
        dns_label = f"{dns_name} • {dns_ip}" if dns_name and dns_name != dns_ip else dns_ip
        self.card_dns_val.configure(
            text=f"Общий: {dns_label}{rtt_txt}",
            fg=OK_TEXT if dns.get("status") == "ok" else WARN_TEXT,
        )
        self.card_dns_sub.configure(
            text=f"Сайтов под DNS: {dns.get('doh_protected_count', 0)} • подмен: {dns.get('poisoned_count', 0)}"
        )

        dpi = orch.get("dpi") or {}
        dpi_running = bool(dpi.get("running"))
        self.card_dpi_val.configure(
            text=f"{'АКТИВЕН' if dpi_running else 'ОЖИДАНИЕ'} • {dpi.get('domains_count', 0)} сайтов",
            fg=OK_TEXT if dpi_running else ACCENT,
        )
        if self.active_preset_id != "auto":
            short_p = self.active_preset_name[:26] + "…" if len(self.active_preset_name) > 28 else self.active_preset_name
            self.card_dpi_sub.configure(text=f"Пресет: {short_p}")
        else:
            top_s = dpi.get("top_strategy") or "не выбрана"
            self.card_dpi_sub.configure(text=f"Основная: {top_s}")

        vpn = orch.get("vpn") or {}
        vpn_running = bool(vpn.get("running"))
        alive_txt = (
            f"{vpn.get('alive_count')}/{vpn.get('total_count', 0)} живых"
            if vpn.get("alive_count") is not None
            else f"Узлов: {vpn.get('total_count', 0)}"
        )
        ping_txt = f" ({vpn['best_ping_ms']} мс)" if vpn.get("best_ping_ms") is not None else ""
        self.card_vpn_val.configure(
            text=f"{'АКТИВЕН' if vpn_running else 'ГОТОВ'} • {alive_txt}{ping_txt}",
            fg=OK_TEXT if vpn_running else (WARN_TEXT if vpn.get("total_count", 0) else MUTED),
        )
        tg_ok = "✔" if (vpn.get("tg_proxy_running") or vpn.get("tg_proxy_alive")) else "выкл"
        self.card_vpn_sub.configure(text=f"Через VPN: {vpn.get('vpn_domains_count', 0)} сайтов • TG-WS: {tg_ok}")

        rt = orch.get("realtime") or {}
        needs_fix = int(rt.get("needs_fix_count", 0))
        ts = self.last_snapshot.get("test_summary") or {}
        overall = ts.get("overall_success_rate")
        rate_s = f" • Успех {overall:.0f}%" if overall is not None else ""
        self.card_rt_val.configure(
            text=f"{rt.get('active_connections', 0)} сокетов • {rt.get('apps_count', 0)} прилож.",
            fg=WARN_TEXT if needs_fix > 0 else (OK_TEXT if self.radar_enabled else MUTED),
        )
        self.card_rt_sub.configure(
            text=f"Ждут починки: {needs_fix}{rate_s}"
        )

    # ---------------------------------------------------------------- domains table

    def sort_domains(self, column: str) -> None:
        prev_col, prev_rev = self._sort_state
        self._sort_state = (column, (not prev_rev) if prev_col == column else False)
        for cid, title, _width, _anchor in DOMAIN_COLUMNS:
            arrow = (" ▼" if self._sort_state[1] else " ▲") if cid == column else ""
            self.domain_tree.heading(cid, text=f"{title}{arrow}")
        self.populate_domain_table()

    def _sort_key(self, row: dict[str, Any]) -> Any:
        col = self._sort_state[0]
        if col == "ttfb":
            return float(row.get("ttfb_ms") or row.get("last_test_latency_ms") or 0)
        if col == "success":
            sr = row.get("success_rate")
            return float(sr) if sr is not None else -1.0
        if col == "test":
            lo = row.get("last_test_ok")
            return 2 if lo is True else (1 if lo is False else 0)
        if col == "sockets":
            dom = str(row.get("domain") or "").lower()
            return self._sock_counts.get(dom, 0)
        if col == "updated":
            return str(row.get("updated_at") or "")
        if col == "layer":
            return str(row.get("layer") or "")
        if col == "protocol":
            return str(row.get("protocol") or "")
        if col == "strategy":
            return str(row.get("strategy_id") or "")
        if col == "verdicts":
            return ",".join(row.get("verdicts") or [])
        if col == "fallback":
            return ",".join(row.get("fallback_strategies") or [])
        return (str(row.get("domain") or ""), str(row.get("protocol") or ""))

    def populate_domain_table(self, rows: list[dict[str, Any]] | None = None) -> None:
        """Differentially update the domain Treeview without resetting scroll position."""
        if rows is not None:
            self.all_rows = list(rows)

        # Count live sockets per domain once (O(C) instead of O(D*C)) so Domains table sorts & renders fast
        sock_counts: dict[str, int] = {}
        for c in self.live_connections:
            cdom = str(c.get("domain") or "").lower()
            if cdom and cdom != "—":
                sock_counts[cdom] = sock_counts.get(cdom, 0) + 1
        self._sock_counts = sock_counts

        needle = self.search_var.get()
        layer = self.layer_filter_var.get()
        visible = [r for r in self.all_rows if row_matches(r, needle, layer)]
        visible.sort(key=self._sort_key, reverse=self._sort_state[1])

        prev_selected = row_iid(self.selected_row) if self.selected_row else None
        ordered_iids: list[str] = []
        new_rows_by_iid: dict[str, dict[str, Any]] = {}
        values_by_iid: dict[str, tuple[Any, ...]] = {}
        tags_by_iid: dict[str, tuple[str, ...]] = {}
        for row in visible:
            iid = row_iid(row)
            if iid in new_rows_by_iid:
                continue
            new_rows_by_iid[iid] = row
            ordered_iids.append(iid)

            dom = str(row.get("domain", ""))
            dom_display = f"📌 {dom}" if row.get("pinned") else dom

            last_ok = row.get("last_test_ok")
            last_ms = row.get("last_test_latency_ms")
            if last_ok is True:
                test_txt = f"✔ {float(last_ms):.0f}ms" if last_ms is not None else "✔ OK"
            elif last_ok is False:
                test_txt = f"✖ {row.get('last_test_stage') or 'сбой'}"
            else:
                test_txt = "—"

            sr = row.get("success_rate")
            t_tot = int(row.get("test_total") or 0)
            t_pass = int(row.get("test_passed") or 0)
            success_txt = f"{float(sr):.0f}% ({t_pass}/{t_tot})" if (sr is not None and t_tot > 0) else "—"

            scnt = sock_counts.get(dom.lower(), 0)
            sock_txt = f"⚡ {scnt}" if scnt > 0 else "—"

            ping_val = row.get("last_test_latency_ms") if row.get("last_test_latency_ms") is not None else row.get("ttfb_ms")
            values_by_iid[iid] = (
                dom_display,
                str(row.get("protocol", "")).upper(),
                ", ".join(row.get("verdicts") or []) or "—",
                row.get("layer", ""),
                row.get("strategy_id") or "—",
                test_txt,
                success_txt,
                sock_txt,
                ", ".join(row.get("fallback_strategies") or []) or "—",
                _num(ping_val, 0),
                format_updated(row.get("updated_at")),
            )
            tags_by_iid[iid] = (row_tag(row),)

        existing_children = set(self.domain_tree.get_children())
        wanted_set = set(ordered_iids)
        obsolete = [cid for cid in existing_children if cid not in wanted_set]
        if obsolete:
            self.domain_tree.delete(*obsolete)

        for idx, iid in enumerate(ordered_iids):
            if iid in existing_children:
                self.domain_tree.item(iid, values=values_by_iid[iid], tags=tags_by_iid[iid])
                self.domain_tree.move(iid, "", idx)
            else:
                self.domain_tree.insert("", idx, iid=iid, values=values_by_iid[iid], tags=tags_by_iid[iid])

        self.rows_by_iid = new_rows_by_iid
        if prev_selected and prev_selected in self.rows_by_iid:
            self.domain_tree.selection_set(prev_selected)
            self.selected_row = self.rows_by_iid[prev_selected]
            self.show_inspector(self.selected_row, sync_controls=False)
        elif prev_selected:
            self.selected_row = None
            self.show_inspector(None)

        badge_txt = f"{len(self.rows_by_iid)}/{len(self.all_rows)}"
        self.notebook.tab(self.tab_domains, text=f"Домены и Трафик ({badge_txt})")
        self._update_nav_badge(self.tab_domains, badge_txt)
        self._restyle_button(
            self._subtab_domains_btn,
            f"Подобранные домены ({len(self.rows_by_iid)})",
            "primary" if self._domains_subview_mode == "domains" else "neutral",
        )

    def on_domain_select(self, _event: Any = None) -> None:
        sel = self.domain_tree.selection()
        if not sel:
            return
        row = self.rows_by_iid.get(sel[0])
        if row is None:
            return
        self.selected_row = row
        self.show_inspector(row)

    def show_inspector(self, row: dict[str, Any] | None, sync_controls: bool = True) -> None:
        w = self.inspector
        if row is None:
            if self._inspector_sig is not None or not w.get("1.0", "end-1c").strip():
                self._inspector_sig = None
                self.inspector_title.configure(text="Выберите сайт в таблице выше, чтобы увидеть результаты проб")
                w.configure(state="normal")
                w.delete("1.0", "end")
                w.insert(
                    "1.0",
                    "Выберите любой сайт в таблице выше — здесь появятся результаты тестов доступности (%), "
                    "проб DNS/TCP/TLS/QUIC, подобранная стратегия и параметры обхода.\n",
                    "muted",
                )
                w.configure(state="disabled")
            return

        sig = (
            row.get("domain"),
            row.get("protocol"),
            row.get("layer"),
            row.get("strategy_id"),
            bool(row.get("pinned")),
            row.get("success_rate"),
            row.get("test_total"),
            row.get("last_tested_at"),
            tuple(row.get("verdicts") or ()),
            row.get("status"),
            row.get("consecutive_fails"),
            row.get("ttfb_ms"),
            row.get("throughput_kbps"),
            tuple(row.get("fallback_strategies") or ()),
            repr(row.get("probes") or {}),
        )
        if not sync_controls and sig == self._inspector_sig:
            return
        self._inspector_sig = sig

        try:
            prev_y = w.yview()[0] if not sync_controls else 0.0
        except tk.TclError:
            prev_y = 0.0

        w.configure(state="normal")
        w.delete("1.0", "end")

        proto = str(row.get("protocol", "")).upper()
        pin_mark = "  📌 ЗАКРЕПЛЕНО" if row.get("pinned") else ""
        self.inspector_title.configure(text=f"Инспектор: {row.get('domain', '')}  [{proto}]{pin_mark}")
        if hasattr(self, "unpin_btn"):
            self._restyle_button(
                self.unpin_btn,
                "Открепить" if row.get("pinned") else "Закрепить",
                "warn" if row.get("pinned") else "neutral",
            )

        raw_verdicts = list(row.get("verdicts") or [])
        verdict_readable = ", ".join(verdict_human_label(v) for v in raw_verdicts) or "—"
        w.insert("end", "Диагноз:     ", "h")
        w.insert(
            "end",
            f"{verdict_readable}\n",
            "ok" if raw_verdicts == ["ok"] else ("muted" if not raw_verdicts else "warn"),
        )
        w.insert("end", "Слой:        ", "h")
        w.insert("end", f"{row.get('layer', '')}   ")
        w.insert("end", "Статус: ", "h")
        status = str(row.get("status", ""))
        w.insert("end", status, "ok" if status == "active" else "bad")
        w.insert("end", f"   ошибок={row.get('consecutive_fails', 0)}   закреплено={'Да' if row.get('pinned') else 'Нет'}\n")

        # Real connectivity test statistics
        t_tot = int(row.get("test_total") or 0)
        t_pass = int(row.get("test_passed") or 0)
        sr = row.get("success_rate")
        w.insert("end", "\nТесты доступности\n", "h")
        if t_tot > 0 and sr is not None:
            tag = "ok" if float(sr) >= 80.0 else ("warn" if float(sr) >= 40.0 else "bad")
            w.insert("end", f"  Успешность: {float(sr):.0f}% ({t_pass}/{t_tot})", tag)
            if row.get("last_test_latency_ms") is not None:
                w.insert("end", f"   •   последний ответ: {float(row['last_test_latency_ms']):.0f} мс")
            if row.get("last_test_error"):
                w.insert("end", f"\n  Последняя ошибка: {row['last_test_error']}", "bad")
            w.insert("end", "\n")
            for rt in (row.get("recent_tests") or [])[:3]:
                mark = "✔" if rt.get("ok") else "✖"
                ms_s = f"{float(rt['latency_ms']):.0f}ms" if rt.get("latency_ms") is not None else rt.get("stage", "")
                w.insert(
                    "end",
                    f"    {mark} {format_updated(rt.get('tested_at'))}  [{rt.get('stage') or 'https'}]  {ms_s}\n",
                    "ok" if rt.get("ok") else "bad",
                )
        else:
            w.insert("end", "  (ещё не тестировался — нажмите «▶ Тест»)\n", "muted")

        w.insert("end", "\nРезультаты сетевых проб\n", "h")
        probe_lines = format_probe_lines(row.get("probes") or {})
        if not probe_lines:
            w.insert("end", "  (нет данных — запустите диагностику)\n", "muted")
        for label, text, status_tag in probe_lines:
            icon = "✔" if status_tag == "ok" else ("✖" if status_tag == "bad" else "—")
            w.insert("end", f"  {icon} {label:<7}", "h")
            w.insert("end", f"{text}\n", status_tag)

        w.insert("end", "\nСтратегия\n", "h")
        w.insert("end", f"  {row.get('strategy_id') or '—'}")
        if row.get("tier") is not None:
            w.insert("end", f"   (уровень {row['tier']})", "muted")
        w.insert("end", "\n")
        if row.get("strategy_description"):
            w.insert("end", f"  {row['strategy_description']}\n", "muted")
        fallback = row.get("fallback_strategies") or []
        if fallback:
            w.insert("end", "  Запасные: ", "h")
            w.insert("end", ", ".join(fallback) + "\n")
        args = row.get("strategy_args") or []
        if args:
            w.insert("end", "\nАргументы winws2\n", "h")
            for arg in args:
                w.insert("end", f"  {arg}\n", "args")
        w.configure(state="disabled")
        if not sync_controls and prev_y > 0.0:
            try:
                w.yview_moveto(prev_y)
            except tk.TclError:
                pass

        if sync_controls:
            layer = str(row.get("layer") or "dpi")
            self.override_layer_var.set(layer)
            self._override_layer_hint_lbl.configure(text=OVERRIDE_LAYER_HINTS.get(layer.lower(), ""))
            self._refresh_strategy_choices(str(row.get("protocol", "")))
            self.override_strategy_var.set(row.get("strategy_id") or "")

    def _on_override_layer_changed(self) -> None:
        layer = (self.override_layer_var.get() or "dpi").lower()
        self._override_layer_hint_lbl.configure(text=OVERRIDE_LAYER_HINTS.get(layer, ""))
        proto = str(self.selected_row.get("protocol", "")) if self.selected_row else ""
        self._refresh_strategy_choices(proto)

    def _refresh_strategy_choices(self, protocol: str = "") -> None:
        layer = (self.override_layer_var.get() or "dpi").lower()
        if layer == "dns":
            dns_ids = [f"dns:{s['id']}" for s in self.dns_catalog if s.get("id")]
            self.override_strategy_cb.configure(values=["", "doh", *dns_ids])
            return
        if layer == "vpn":
            self.override_strategy_cb.configure(values=["vpn-select", "vpn-ai", "byedpi-out", ""])
            return
        if layer == "direct":
            self.override_strategy_cb.configure(values=[""])
            return
        ids = [
            str(s.get("id"))
            for s in self.catalog
            if not protocol or str(s.get("protocol", "")).lower() == protocol.lower()
        ]
        self.override_strategy_cb.configure(values=[""] + ids)

    # ---------------------------------------------------------------- real-time radar tab

    def populate_connections_table(
        self,
        connections: list[dict[str, Any]],
        events: list[dict[str, Any]] | None = None,
    ) -> None:
        """Differentially update Live Connections table without jumping scroll position."""
        self.live_connections = list(connections)
        if events is not None:
            self._last_conn_events = list(events)
        prev_selected = conn_iid(self.selected_conn) if self.selected_conn else None

        total = len(connections)
        protected_cnt = sum(1 for c in connections if str(c.get("health") or "") == "protected")
        needs_fix_cnt = sum(1 for c in connections if str(c.get("health") or "") == "needs_fix")
        direct_cnt = max(0, total - protected_cnt - needs_fix_cnt)
        self._rt_summary_lbl.configure(
            text=f"Всего: {total}  •  Под защитой: {protected_cnt}  •  Нужна починка: {needs_fix_cnt}  •  Напрямую: {direct_cnt}",
            fg=WARN_TEXT if needs_fix_cnt > 0 else FG_SOFT,
        )

        health_labels = {
            "needs_fix": "⚠ Нужна починка",
            "protected": "✔ Под защитой",
            "direct": "● Напрямую",
        }
        ordered_iids: list[str] = []
        new_conns_by_iid: dict[str, dict[str, Any]] = {}
        values_by_iid: dict[str, tuple[Any, ...]] = {}
        tags_by_iid: dict[str, tuple[str, ...]] = {}
        for c in connections:
            health = str(c.get("health") or "direct")
            if self.conn_health_filter != "ALL" and health != self.conn_health_filter:
                continue
            iid = conn_iid(c)
            if iid in new_conns_by_iid:
                continue
            new_conns_by_iid[iid] = c
            ordered_iids.append(iid)
            if str(c.get("layer")) == "unlocker":
                badge_text = "🛡 Анлокер / hosts"
            else:
                badge_text = health_labels.get(health, health)
            values_by_iid[iid] = (
                c.get("process", ""),
                c.get("domain", "—"),
                c.get("remote", ""),
                str(c.get("protocol", "")).upper(),
                c.get("socket_status", ""),
                c.get("layer", "direct"),
                c.get("strategy_id") or "—",
                badge_text,
            )
            tags_by_iid[iid] = (health if health in ("protected", "needs_fix", "direct") else "direct",)

        existing_children = set(self.conn_tree.get_children())
        wanted_set = set(ordered_iids)
        obsolete = [cid for cid in existing_children if cid not in wanted_set]
        if obsolete:
            self.conn_tree.delete(*obsolete)

        for idx, iid in enumerate(ordered_iids):
            if iid in existing_children:
                self.conn_tree.item(iid, values=values_by_iid[iid], tags=tags_by_iid[iid])
                self.conn_tree.move(iid, "", idx)
            else:
                self.conn_tree.insert("", idx, iid=iid, values=values_by_iid[iid], tags=tags_by_iid[iid])

        self.conns_by_iid = new_conns_by_iid
        if prev_selected and prev_selected in self.conns_by_iid:
            self.conn_tree.selection_set(prev_selected)
            self.selected_conn = self.conns_by_iid[prev_selected]

        self._restyle_button(
            self._subtab_conns_btn,
            f"Активные сокеты ({len(self.conns_by_iid)})",
            "primary" if self._domains_subview_mode == "connections" else "neutral",
        )
        new_sock_counts: dict[str, int] = {}
        for c in connections:
            cdom = str(c.get("domain") or "").lower()
            if cdom and cdom != "—":
                new_sock_counts[cdom] = new_sock_counts.get(cdom, 0) + 1
        if self.all_rows and new_sock_counts != self._sock_counts:
            self.populate_domain_table()
        if isinstance(self.last_snapshot.get("test_summary"), dict):
            self._update_test_summary_ui(self.last_snapshot["test_summary"])

        if events is not None:
            w = self.realtime_feed
            w.configure(state="normal")
            w.delete("1.0", "end")
            if not events:
                w.insert("1.0", "(ожидание событий реального времени…)", "muted")
            else:
                for ev in events:
                    stamp = f"[{ev.get('timestamp', '')}] "
                    body = f"{ev.get('process', '')} • {ev.get('domain', '')}: {ev.get('action', '')}\n"
                    w.insert("end", stamp, "muted")
                    w.insert("end", body, "ok")
            w.configure(state="disabled")

    def on_conn_select(self, _event: Any = None) -> None:
        sel = self.conn_tree.selection()
        if sel:
            self.selected_conn = self.conns_by_iid.get(sel[0])

    def refresh_realtime_async(self, auto_heal: bool = False) -> None:
        if self._rt_busy or self._closed:
            return
        self._rt_busy = True

        def done(res: dict[str, Any]) -> None:
            self._rt_busy = False
            conns = res.get("connections") or []
            events = res.get("events") or []
            self.populate_connections_table(conns, events)
            healed = res.get("healed") or []
            if healed:
                names = ", ".join(f"{h['domain']}→{h.get('strategy_id') or h['layer']}" for h in healed)
                self.log_console(f"Live-Радар автоподбор: {names}")
                self.set_status(f"Live-Радар подобрал: {names}", OK_TEXT)
                self.refresh_async()

        def failed(_exc: Exception) -> None:
            self._rt_busy = False

        def runner() -> None:
            try:
                if auto_heal:
                    res = self.backend.run_realtime_auto_heal_tick(max_domains_per_tick=1, require_running=True)
                else:
                    res = self.backend.scan_live_connections()
            except Exception as exc:  # noqa: BLE001
                self._post(failed, exc)
            else:
                self._post(done, res)

        threading.Thread(target=runner, name="gui-realtime", daemon=True).start()

    def _realtime_tick(self) -> None:
        if self._closed:
            return
        hidden = self._is_window_hidden()
        stack_running = bool(self.last_snapshot.get("running"))
        can_auto_heal = bool(self.auto_heal_var.get()) and stack_running
        should_scan = (not hidden) or (self.active_preset_id == "auto" and can_auto_heal)
        if self.radar_enabled and self._busy == 0 and should_scan:
            self.refresh_realtime_async(auto_heal=can_auto_heal)
        self.after(self.REALTIME_INTERVAL_MS, self._realtime_tick)

    def on_toggle_radar(self) -> None:
        self.radar_enabled = not self.radar_enabled
        if self.radar_enabled:
            self._restyle_button(self.radar_btn, "Live-Радар: ВКЛ", "primary")
            self.refresh_realtime_async(
                auto_heal=bool(self.auto_heal_var.get()) and bool(self.last_snapshot.get("running"))
            )
        else:
            self._restyle_button(self.radar_btn, "Live-Радар: ВЫКЛ", "neutral")
        if self.last_snapshot:
            self.apply_snapshot(self.last_snapshot)

    def on_heal_selected_connection(self) -> None:
        if not self.selected_conn:
            self.set_status("Выберите соединение в таблице Live-Радара", WARN_TEXT)
            return
        domain = str(self.selected_conn.get("domain") or "")
        if not domain or domain == "—":
            self.set_status(
                f"У IP {self.selected_conn.get('remote_ip')} не определено доменное имя — добавьте сайт на вкладке «Сайты»",
                WARN_TEXT,
            )
            return
        self._diag_domains([domain], f"Автоподбор для {domain}")

    # ---------------------------------------------------------------- service / config helpers

    def refresh_previews_async(self) -> None:
        def runner() -> None:
            try:
                previews = self.backend.read_config_preview()
            except Exception as exc:  # noqa: BLE001
                previews = {"error": f"[не удалось прочитать конфиги: {exc}]"}
            self._post(self.set_previews, previews)

        threading.Thread(target=runner, name="gui-preview", daemon=True).start()

    def set_previews(self, previews: dict[str, str]) -> None:
        self.config_previews = previews
        names = list(previews.keys())
        self.file_cb.configure(values=names)
        if names:
            if self.file_var.get() not in previews:
                self.file_var.set(names[0])
            self.show_selected_file()
        else:
            self.file_var.set("")
            self._set_text(self.preview, "(конфиги ещё не сгенерированы — нажмите «Включить защиту»)")

    def show_selected_file(self) -> None:
        self._set_text(self.preview, self.config_previews.get(self.file_var.get(), ""))

    def load_catalog_async(self) -> None:
        def done(catalog: list[dict[str, Any]]) -> None:
            self.catalog = catalog
            proto = str(self.selected_row.get("protocol", "")) if self.selected_row else ""
            self._refresh_strategy_choices(proto)

        def runner() -> None:
            try:
                catalog = self.backend.get_strategies_catalog()
            except Exception:  # noqa: BLE001
                return
            self._post(done, catalog)

        threading.Thread(target=runner, name="gui-catalog", daemon=True).start()

    def _iface(self) -> int | None:
        raw = self.iface_var.get().strip()
        if not raw:
            return None
        try:
            return int(raw)
        except ValueError:
            raise ValueError(f"ifIndex должен быть числом, получено: {raw!r}") from None

    def _after_change(self) -> None:
        self.refresh_async()
        self.refresh_previews_async()

    # ---------------------------------------------------------------- VPN / logs tab

    def populate_vpn_table(self, nodes: list[dict[str, Any]]) -> None:
        signature = repr(nodes)
        if signature == self._vpn_signature:
            return
        self._vpn_signature = signature
        self.vpn_tree.delete(*self.vpn_tree.get_children())
        self._vpn_nodes_by_iid = {}
        alive_cnt = 0
        for i, node in enumerate(nodes):
            iid = f"n{i}"
            self._vpn_nodes_by_iid[iid] = node
            endpoint = f"{node.get('server', '')}:{node.get('server_port', '')}"
            if "ping_ms" in node and node.get("ping_ms") is not None:
                suffix = "✔ (туннель)" if node.get("tunnel_verified") else "✔"
                endpoint += f"  •  {node['ping_ms']} ms {suffix}"
            elif node.get("alive") is False:
                endpoint += f"  •  {node.get('probe_result') or 'таймаут'} ✖"

            cb_state = str(node.get("cb_state") or "closed")
            proto_ok = node.get("protocol_ok", True)
            if cb_state == "open":
                health_txt = "🔴 Карантин (block)" if not proto_ok else "🔴 Карантин"
                tag = "bad"
            elif cb_state == "half_open":
                health_txt = "🟡 Проверка восстановления"
                tag = "warn"
            elif node.get("alive"):
                health_txt = "🟢 Активен"
                tag = "ok"
                alive_cnt += 1
            else:
                health_txt = "● Готов"
                tag = "ok"

            self.vpn_tree.insert(
                "",
                "end",
                iid=f"n{i}",
                values=(
                    node.get("display_name") or node.get("tag", ""),
                    str(node.get("region") or "other").upper(),
                    node.get("protocol", ""),
                    node.get("transport", "tcp"),
                    endpoint,
                    health_txt,
                ),
                tags=(tag,),
            )

        self._vpn_summary_lbl.configure(
            text=f"Узлов в пуле: {len(nodes)}" + (f" (доступных: {alive_cnt})" if alive_cnt else "")
        )
        self._update_nav_badge(self.tab_vpn, str(len(nodes)))

    def refresh_logs_async(self) -> None:
        if self._log_refreshing or self._closed:
            return
        self._log_refreshing = True
        name = self.log_var.get()

        def runner() -> None:
            try:
                logs = self.backend.read_logs_tail(max_lines=200)
            except Exception as exc:  # noqa: BLE001
                logs = {name: f"[не удалось прочитать лог: {exc}]"}
            self._post(self._apply_log, name, logs.get(name, ""))

        threading.Thread(target=runner, name="gui-logs", daemon=True).start()

    def _apply_log(self, name: str, text: str) -> None:
        self._log_refreshing = False
        if name != self.log_var.get():
            return
        clean = strip_ansi(text) if text else ""
        shown = clean or f"(лог {name} пуст или не найден)"

        alert = detect_log_alert(name, shown)
        if alert:
            self._log_alert_lbl.configure(text=alert)
            if not self._log_alert_bar.winfo_manager():
                self._log_alert_bar.pack(fill="x", pady=(0, 6), before=self.log_view.master)
        elif self._log_alert_bar.winfo_manager():
            self._log_alert_bar.pack_forget()

        if self.log_view.get("1.0", "end-1c") != shown:
            at_bottom = self.log_view.yview()[1] >= 0.99
            w = self.log_view
            w.configure(state="normal")
            w.delete("1.0", "end")
            if not clean:
                w.insert("1.0", shown, "muted")
            else:
                for line in shown.splitlines(keepends=True):
                    low = line.lower()
                    if "error" in low or "fatal" in low or "failed" in low:
                        tag = "err"
                    elif "warn" in low:
                        tag = "warn"
                    else:
                        tag = "info"
                    w.insert("end", line, tag)
            w.configure(state="disabled")
            if at_bottom:
                self.log_view.see("end")

    def _log_tick(self) -> None:
        if self._closed:
            return
        try:
            on_logs_tab = self.notebook.select() == str(self.tab_vpn)
        except tk.TclError:
            on_logs_tab = False
        if on_logs_tab and not self._is_window_hidden():
            self.refresh_logs_async()
        self.after(self.LOG_INTERVAL_MS, self._log_tick)

    # ---------------------------------------------------------------- actions

    def on_toggle_autopilot(self) -> None:
        if bool(self.last_snapshot.get("running")):
            self.on_stop()
        else:
            self.on_start()

    def on_start(self) -> None:
        try:
            iface = self._iface()
        except ValueError as exc:
            self.set_status(str(exc), ERR_TEXT)
            return

        def done(res: dict[str, Any]) -> None:
            self.log_console(dumps_pretty(res))
            if res.get("live_connections") is not None:
                self.populate_connections_table(res["live_connections"])
            if res.get("orchestrators"):
                self.update_layer_cards(res["orchestrators"])
            if res.get("ok"):
                self.radar_enabled = True
                self._restyle_button(self.radar_btn, "Live-Радар: ВКЛ", "primary")
                self.set_status("Защита запущена: " + ", ".join(res.get("services", [])), OK_TEXT)
            elif res.get("requires_admin"):
                self.set_status("Конфиги готовы! Нужны права Admin (UAC) для запуска служб", WARN_TEXT)
                if not self._is_window_hidden() and messagebox.askyesno(
                    "netdoctor",
                    "Стратегии подобраны и конфиги готовы.\n"
                    "Для запуска winws2 и sing-box TUN нужны права администратора.\n\n"
                    "Перезапустить программу от Admin?",
                ):
                    self.on_elevate()
            else:
                self.set_status(f"Ошибка запуска: {res.get('error', 'неизвестная ошибка')}", ERR_TEXT)
            self._after_change()

        self.run_bg("Запуск защиты (Автопилот)", lambda: self.backend.start_autopilot(iface=iface), done)

    def on_stop(self) -> None:
        def done(stopped: list[str]) -> None:
            self.log_console("Остановлено: " + (", ".join(stopped) if stopped else "ничего не запущено"))
            self._after_change()

        self.run_bg("Остановка защиты", self.backend.stop_services, done)

    def on_check_layers(self) -> None:
        def done(orch: dict[str, Any]) -> None:
            self.update_layer_cards(orch)
            self.log_console("Оркестраторы слоёв:\n" + dumps_pretty(orch))
            if orch.get("vpn", {}).get("nodes"):
                self.populate_vpn_table(orch["vpn"]["nodes"])
            self.refresh_async()

        self.run_bg("Замер задержки всех слоёв", lambda: self.backend.get_orchestrators_summary(probe_live=True), done)

    def on_ping_vpn_nodes(self) -> None:
        def done(nodes: list[dict[str, Any]]) -> None:
            self.populate_vpn_table(nodes)
            alive = sum(1 for n in nodes if n.get("alive"))
            self.log_console(f"Пинг VPN узлов: {alive}/{len(nodes)} доступны")
            self.refresh_async()

        self.run_bg("Проверка пинга VPN узлов", self.backend.probe_all_vpn_nodes, done)

    def on_generate(self) -> None:
        try:
            iface = self._iface()
        except ValueError as exc:
            self.set_status(str(exc), ERR_TEXT)
            return

        def done(res: dict[str, Any]) -> None:
            self.log_console(
                f"Конфиги собраны: {res.get('winws2_preset')} | {res.get('singbox_config')} | "
                f"hostlists={res.get('hostlists_count')}"
            )
            self._after_change()

        self.run_bg("Сборка конфигов", lambda: self.backend.trigger_apply_configs(iface=iface), done)

    def on_reload(self) -> None:
        try:
            iface = self._iface()
        except ValueError as exc:
            self.set_status(str(exc), ERR_TEXT)
            return

        def done(res: dict[str, Any]) -> None:
            self.log_console(dumps_pretty(res))
            if res.get("ok"):
                self.set_status("winws2 перезагружен", OK_TEXT)
            elif res.get("requires_admin"):
                self.set_status("Нужны права администратора (UAC)", WARN_TEXT)
            else:
                self.set_status(f"Hot-reload: {res.get('error', 'ошибка')}", ERR_TEXT)
            self._after_change()

        self.run_bg("Hot-reload winws2", lambda: self.backend.reload_winws2(iface=iface), done)

    def on_verify(self) -> None:
        def done(res: dict[str, Any]) -> None:
            self.log_console("Verify Binaries:\n" + dumps_pretty(res))

        self.run_bg("Проверка целостности файлов", self.backend.verify_deps, done)

    def on_elevate(self) -> None:
        def done(res: dict[str, Any]) -> None:
            if res.get("ok"):
                self.set_status("Запущено окно с правами администратора — закрытие старого окна...", OK_TEXT)
                self.log_console("Запущено окно с правами администратора")
                if not self._closed:
                    self.after(150, self.on_close)
            elif res.get("cancelled"):
                self.set_status("Запрос прав администратора отменён", WARN_TEXT)
                self.log_console("Запрос прав администратора (UAC) отменён пользователем")
            else:
                self.set_status(f"Не удалось запросить UAC: {res.get('error')}", ERR_TEXT)

        self.run_bg("Запрос прав Admin (UAC)", self.backend.elevate_gui, done)

    def on_diag_all(self) -> None:
        def done(rows: list[dict[str, Any]]) -> None:
            self.log_console(f"Диагностика завершена: {len(rows)} записей")
            self.populate_domain_table(rows)
            self._after_change()

        self.run_bg("Проверка базового списка сайтов", lambda: self.backend.run_diag_sync(None), done)

    def on_revalidate(self) -> None:
        def done(summary: dict[str, Any]) -> None:
            self.log_console(
                f"Канарейка: проверено={len(summary.get('checked', []))}, "
                f"promoted={summary.get('promoted')}, expired={summary.get('expired')}"
            )
            self._after_change()

        self.run_bg("Канарейка (проверка решений)", self.backend.trigger_revalidate, done)

    def _diag_domains(self, domains: list[str], label: str) -> None:
        def done(rows: list[dict[str, Any]]) -> None:
            self.populate_domain_table(rows)
            self.log_console(f"{label}: готово ({', '.join(domains)})")
            self._after_change()

        self.run_bg(label, lambda: self.backend.run_diag_sync(domains), done)

    def on_check_new_domain(self) -> None:
        domain = normalize_domain(self.new_domain_var.get())
        if not domain:
            self.set_status("Введите адрес сайта, например discord.com", WARN_TEXT)
            return
        self.new_domain_var.set("")
        self._diag_domains([domain], f"Подбор для {domain}")

    def on_recheck_selected(self) -> None:
        if not self.selected_row:
            self.set_status("Сначала выберите сайт в таблице", WARN_TEXT)
            return
        domain = str(self.selected_row["domain"])
        self._diag_domains([domain], f"Автоподбор для {domain}")

    def on_pin(self) -> None:
        if not self.selected_row:
            self.set_status("Сначала выберите сайт в таблице", WARN_TEXT)
            return
        domain = str(self.selected_row["domain"])
        protocol = str(self.selected_row["protocol"])
        layer = self.override_layer_var.get() or "dpi"
        strategy = self.override_strategy_var.get().strip() or None
        if layer == "dpi" and strategy is None:
            self.set_status("Для слоя dpi выберите стратегию", WARN_TEXT)
            return

        def done(decision: dict[str, Any]) -> None:
            self.log_console(
                f"Закреплено: {decision.get('domain')} [{decision.get('protocol')}] → "
                f"{decision.get('layer')} / {decision.get('strategy_id') or '—'}"
            )
            self._after_change()

        self.run_bg(
            f"Закрепление {domain}",
            lambda: self.backend.pin_domain_strategy(domain, protocol, layer, strategy),
            done,
        )

    def on_add_subscription(self) -> None:
        value = self.sub_var.get().strip()
        if not value:
            self.set_status("Введите URL подписки или URI узла", WARN_TEXT)
            return

        def done(count: int) -> None:
            self.log_console(f"Подписка добавлена: {count} узлов")
            if count:
                self.sub_var.set("")
            else:
                self.set_status("Узлы не найдены в подписке", WARN_TEXT)
            self._after_change()

        self.run_bg("Добавление подписки", lambda: self.backend.add_vpn_subscription(value), done)

    def on_refresh_subscriptions(self) -> None:
        def done(results: dict[str, int]) -> None:
            self.log_console("Подписки обновлены: " + json.dumps(results, ensure_ascii=False))
            self._after_change()

        self.run_bg("Обновление подписок", self.backend.refresh_vpn_subscriptions, done)

    # ---------------------------------------------------------------- DNS & Preset actions

    def on_select_dns(self, dns_id: str) -> None:
        def done(selected: dict[str, Any]) -> None:
            self.active_dns_id = str(selected.get("id") or dns_id)
            self._dns_signature = ""
            if self.dns_catalog:
                self.render_dns_grid(self.dns_catalog, self.active_dns_id)
            self.log_console(f"Общий DNS: {selected.get('name')} ({selected.get('ip')})")
            self.set_status(f"Общий DNS: {selected.get('name')} ({selected.get('ip')})", OK_TEXT)
            self._after_change()

        self.run_bg(f"Выбор общего DNS ({dns_id})", lambda: self.backend.select_dns_server(dns_id), done)

    def on_ping_dns_catalog(self) -> None:
        cat = None if self.dns_category_filter == "ALL" else self.dns_category_filter

        def done(servers: list[dict[str, Any]]) -> None:
            self._dns_signature = ""
            self.render_dns_grid(servers, self.active_dns_id)
            alive = sum(1 for s in servers if s.get("alive"))
            self.log_console(f"Пинг DNS завершён: {alive} серверов доступны")
            self._after_change()

        self.run_bg("Измерение пинга DNS-серверов", lambda: self.backend.ping_dns_catalog(category=cat), done)

    def on_auto_select_dns(self, category: str) -> None:
        def done(selected: dict[str, Any]) -> None:
            self.load_dns_catalog_async()
            ping = f" ({selected['ping_ms']} мс)" if selected.get("ping_ms") is not None else ""
            self.log_console(f"Выбран лучший общий DNS ({category}): {selected.get('name')} [{selected.get('ip')}]{ping}")
            self.set_status(f"Лучший общий DNS: {selected.get('name')} {selected.get('ip')}{ping}", OK_TEXT)
            self._after_change()

        self.run_bg(f"Выбор лучшего DNS ({category})", lambda: self.backend.auto_select_best_dns(category), done)

    def on_add_custom_dns(self) -> None:
        name = self.custom_dns_name_var.get().strip()
        ip = self.custom_dns_ip_var.get().strip()
        extra = self.custom_dns_desc_var.get().strip()
        doh_url = extra if extra.startswith("https://") else ""
        desc = "" if doh_url else extra

        def done(saved: dict[str, Any]) -> None:
            self.custom_dns_name_var.set("")
            self.custom_dns_ip_var.set("")
            self.custom_dns_desc_var.set("")
            self.active_dns_id = str(saved["id"])
            self.load_dns_catalog_async()
            self.log_console(f"Добавлен свой DNS: {saved.get('name')} ({saved.get('ip')})")
            self._after_change()

        self.run_bg(
            "Добавление своего DNS",
            lambda: self.backend.add_custom_dns(name=name, ip=ip, description=desc, doh_url=doh_url),
            done,
        )

    def on_delete_custom_dns(self, dns_id: str) -> None:
        def done(_ok: bool) -> None:
            self.load_dns_catalog_async()
            self.log_console(f"Удалён свой DNS: {dns_id}")
            self._after_change()

        self.run_bg("Удаление DNS", lambda: self.backend.remove_custom_dns(dns_id), done)

    def on_toggle_game_filter(self) -> None:
        enabled = bool(self.game_filter_var.get())

        def done(res: dict[str, Any]) -> None:
            state = "включён" if res.get("game_filter") else "выключен"
            self.log_console(f"Игровой фильтр (1024-65535 UDP/TCP): {state}")
            self._after_change()

        self.run_bg("Переключение игрового фильтра", lambda: self.backend.set_game_filter(enabled), done)

    def on_apply_preset(self, preset_id: str) -> None:
        def done(res: dict[str, Any]) -> None:
            preset = res.get("preset") or {}
            title = preset.get("title", preset_id)
            dns_info = res.get("selected_dns")
            extra = f" + DNS {dns_info['name']}" if dns_info else ""
            self.log_console(f"Пресет «{title}» применён: {', '.join(res.get('domains') or [])}{extra}")
            self.set_status(f"{title} настроен ({len(res.get('domains') or [])} доменов)", OK_TEXT)
            self.load_dns_catalog_async()
            self._after_change()

        self.run_bg(f"Настройка {preset_id}", lambda: self.backend.apply_service_preset(preset_id), done)

    def on_flush_dns(self) -> None:
        def done(res: dict[str, Any]) -> None:
            self.log_console(f"DNS-кэш Windows: {res.get('output')}")
            if res.get("ok"):
                self.set_status("DNS-кэш Windows очищен (flushdns)", OK_TEXT)
            else:
                self.set_status(f"Сброс DNS-кэша: {res.get('output')}", WARN_TEXT)

        self.run_bg("Очистка DNS-кэша Windows", self.backend.flush_windows_dns_cache, done)

    def _roll_dns_target(self, domain: str) -> None:
        def done(res: dict[str, Any]) -> None:
            srv = res.get("dns_server") or {}
            dec = res.get("decision") or {}
            name = srv.get("name") or res.get("dns_id")
            ip = srv.get("ip") or ""
            self.log_console(f"Ролл DNS для {domain}: {name} ({ip}) | fallback={dec.get('fallback_strategies')}")
            self.set_status(f"Для {domain} подобран персональный DNS: {name} ({ip})", OK_TEXT)
            self.load_dns_catalog_async()
            self._after_change()

        self.run_bg(f"Ролл DNS для {domain}", lambda: self.backend.roll_dns_for_domain_sync(domain), done)

    def on_roll_dns_domain(self) -> None:
        domain = normalize_domain(self.dns_roll_domain_var.get())
        if not domain:
            self.set_status("Введите адрес сайта, например chatgpt.com", WARN_TEXT)
            return
        self.dns_roll_domain_var.set("")
        self._roll_dns_target(domain)

    def on_roll_dns_selected(self) -> None:
        if not self.selected_row:
            self.set_status("Сначала выберите сайт в таблице", WARN_TEXT)
            return
        self._roll_dns_target(str(self.selected_row["domain"]))

    def on_roll_all_ai_dns(self) -> None:
        def done(decisions: list[dict[str, Any]]) -> None:
            summary = ", ".join(f"{d['domain']}→{d.get('strategy_id')}" for d in decisions)
            self.log_console(f"Персональный ролл DNS для ИИ завершён: {summary}")
            self.set_status(f"Персональный DNS подобран для {len(decisions)} ИИ-сервисов", OK_TEXT)
            self.load_dns_catalog_async()
            self._after_change()

        self.run_bg("Ролл DNS для всех нейросетей (ИИ)", self.backend.roll_ai_dns_batch_sync, done)

    def on_save_unlocker_guard(self) -> None:
        enabled = bool(self.unlocker_guard_var.get())
        raw = self.unlocker_custom_var.get().strip()

        def done(res: dict[str, Any]) -> None:
            g = res.get("guard") or {}
            self.log_console(
                f"Защита анлокеров: {'вкл' if g.get('enabled') else 'выкл'} | "
                f"hosts доменов={g.get('hosts_domains_count', 0)}, прокси-IP={g.get('hosts_proxy_ips_count', 0)}"
            )
            self.set_status("Исключения для анлокеров/hosts сохранены и конфиги пересобраны", OK_TEXT)
            self._after_change()

        self.run_bg("Сохранение исключений анлокеров", lambda: self.backend.set_unlocker_exclusions(raw, enabled=enabled), done)

    def _load_autostart_async(self) -> None:
        def runner() -> None:
            try:
                st = self.backend.get_autostart_status()
            except Exception:  # noqa: BLE001
                return
            self._post(lambda res=st: self.autostart_var.set(bool(res.get("enabled"))))

        threading.Thread(target=runner, name="gui-autostart-chk", daemon=True).start()

    def on_reload_singbox(self) -> None:
        try:
            iface = self._iface()
        except ValueError as exc:
            self.set_status(str(exc), ERR_TEXT)
            return

        def done(res: dict[str, Any]) -> None:
            self.log_console(dumps_pretty(res))
            if res.get("ok"):
                self.set_status("sing-box перезагружен", OK_TEXT)
            elif res.get("requires_admin"):
                self.set_status("Нужны права администратора (UAC)", WARN_TEXT)
            else:
                self.set_status(f"Перезагрузка sing-box: {res.get('error', 'ошибка')}", ERR_TEXT)
            self._after_change()

        self.run_bg("Перезагрузка sing-box", lambda: self.backend.reload_singbox(iface=iface), done)

    def on_rotate_vpn_node(self) -> None:
        target_tag: str | None = None
        sel = self.vpn_tree.selection() if hasattr(self, "vpn_tree") else ()
        if sel:
            node_row = self._vpn_nodes_by_iid.get(sel[0])
            if isinstance(node_row, dict) and node_row.get("tag"):
                target_tag = str(node_row["tag"])
            else:
                vals = self.vpn_tree.item(sel[0], "values")
                if vals:
                    sel_name = str(vals[0])
                    for n in self.last_snapshot.get("vpn_nodes") or []:
                        if sel_name in (n.get("tag"), n.get("display_name")):
                            target_tag = str(n.get("tag"))
                            break

        def done(res: dict[str, Any]) -> None:
            if res.get("ok"):
                self.log_console(
                    f"VPN ротация: {res.get('previous') or '—'} -> {res.get('selected')} "
                    f"(live={res.get('switched_live')}, closed_conns={res.get('closed_connections')})"
                )
                self.set_status(f"Активный VPN-узел: {res.get('selected')}", OK_TEXT)
            else:
                self.set_status(f"Ротация VPN: {res.get('error', 'не выполнена')}", WARN_TEXT)
            self._after_change()

        self.run_bg("Ротация VPN-узла", lambda: self.backend.rotate_vpn_node(target_tag=target_tag), done)

    def on_blockcheck2_selected(self) -> None:
        if not self.selected_row:
            self.set_status("Сначала выберите сайт в таблице", WARN_TEXT)
            return
        domain = str(self.selected_row["domain"])

        def done(res: dict[str, Any]) -> None:
            cnt = int(res.get("discovered_count") or 0)
            self.log_console(f"blockcheck2 ({domain}): найдено стратегий = {cnt}")
            if cnt > 0:
                self.load_catalog_async()
                self.set_status(f"blockcheck2 нашёл {cnt} стратегий для {domain}", OK_TEXT)
            else:
                self.set_status(f"blockcheck2 для {domain}: новых стратегий не найдено (требуется Admin)", WARN_TEXT)

        self.run_bg(f"blockcheck2 ({domain})", lambda: self.backend.run_blockcheck2_sync(domain), done)

    def on_toggle_autostart(self) -> None:
        enabled = bool(self.autostart_var.get())

        def done(res: dict[str, Any]) -> None:
            if res.get("ok"):
                self.set_status(f"Автозапуск Windows {'включён' if res.get('enabled') else 'отключён'}", OK_TEXT)
            else:
                self.autostart_var.set(bool(res.get("enabled")))
                self.set_status(f"Автозапуск: {res.get('error', 'ошибка настройки')}", WARN_TEXT)

        self.run_bg("Настройка автозапуска Windows", lambda: self.backend.set_autostart(enabled), done)

    def on_toggle_byedpi(self) -> None:
        enabled = bool(self.byedpi_var.get())

        def done(res: dict[str, Any]) -> None:
            state = "включён" if res.get("byedpi_fallback") else "выключен"
            self.log_console(f"ByeDPI SOCKS5 (ciadpi): {state}")
            self._after_change()

        self.run_bg("Переключение ByeDPI", lambda: self.backend.set_byedpi_fallback(enabled), done)

    def on_toggle_debug_log(self) -> None:
        enabled = bool(self.debug_log_var.get())

        def done(res: dict[str, Any]) -> None:
            state = "включён" if res.get("winws2_debug_log") else "выключен"
            self.log_console(f"Подробный лог winws2 (--debug=1): {state}")
            self._after_change()

        self.run_bg("Переключение лога winws2", lambda: self.backend.set_winws2_debug_log(enabled), done)

    # ---------------------------------------------------------------- Zapret2 Presets & Live Connectivity Tests

    def load_zapret_presets_async(self) -> None:
        def done(data: dict[str, Any]) -> None:
            self.active_preset_id = str(data.get("active_preset_id") or "auto")
            self.active_preset_name = str(data.get("active_preset_name") or "Авто-оркестратор (подбор по доменам)")
            self.populate_presets_table(list(data.get("presets") or []))
            self._sync_active_preset_indicators()

        def runner() -> None:
            try:
                data = self.backend.get_zapret_presets()
            except Exception:  # noqa: BLE001
                return
            self._post(done, data)

        threading.Thread(target=runner, name="gui-presets", daemon=True).start()

    def _set_preset_filter(self, flt: str) -> None:
        self.preset_filter = flt
        for pid, btn in self._preset_filter_buttons.items():
            self._restyle_button(btn, btn.cget("text"), "primary" if pid == flt else "neutral")
        self.populate_presets_table()

    def _sync_home_preset_combo(self) -> None:
        auto_label = "Авто-оркестратор (подбор по доменам)"
        label_to_id: dict[str, str] = {auto_label: "auto"}
        id_to_label: dict[str, str] = {"auto": auto_label}
        values: list[str] = [auto_label]
        for p in self.zapret_presets:
            pid = str(p.get("id") or "")
            name = str(p.get("name") or pid)
            prefix = "★ [Мой] " if not p.get("builtin", True) else ("★ " if p.get("featured") else "")
            sr = p.get("success_rate")
            suffix = f" ({float(sr):.0f}%)" if sr is not None else ""
            label = f"{prefix}{name}{suffix}"
            if label in label_to_id:
                label = f"{label} [{pid[:8]}]"
            label_to_id[label] = pid
            id_to_label[pid] = label
            values.append(label)
        self._home_preset_label_to_id = label_to_id
        self._home_preset_id_to_label = id_to_label
        self.home_preset_cb.configure(values=values)
        if self.active_preset_id in id_to_label:
            self.home_preset_var.set(id_to_label[self.active_preset_id])
        else:
            self.home_preset_var.set(auto_label)

    def populate_presets_table(self, presets: list[dict[str, Any]] | None = None) -> None:
        if presets is not None:
            self.zapret_presets = list(presets)
            self._sync_home_preset_combo()

        needle = self.preset_search_var.get().strip().lower() if hasattr(self, "preset_search_var") else ""
        filtered: list[dict[str, Any]] = []
        for p in self.zapret_presets:
            is_user = not bool(p.get("builtin", True))
            if self.preset_filter == "user" and not is_user:
                continue
            if self.preset_filter == "featured" and not (is_user or p.get("featured") or p.get("is_working")):
                continue
            if needle:
                hay = f"{p.get('name', '')} {p.get('description', '')} {p.get('source', '')}".lower()
                if needle not in hay:
                    continue
            filtered.append(p)

        prev_sel = str(self.selected_preset.get("id") or "") if self.selected_preset else ""
        self.presets_tree.delete(*self.presets_tree.get_children())
        new_map: dict[str, dict[str, Any]] = {}
        for p in filtered:
            pid = str(p.get("id") or "")
            if not pid or pid in new_map:
                continue
            new_map[pid] = p
            is_active = pid == self.active_preset_id
            is_user = not bool(p.get("builtin", True))
            src = "Мой рабочий" if is_user else ("ZDY .bat" if p.get("source") == "builtin_zdy" else "Zapret2")
            if is_active:
                status_txt = "🔒 АКТИВЕН"
                tag = "active"
            elif is_user:
                status_txt = "★ Рабочий" if p.get("is_working") else "Пользователь"
                tag = "user"
            elif p.get("featured"):
                status_txt = "★ Рекоменд."
                tag = "featured"
            else:
                status_txt = "Готов"
                tag = "builtin"
            sr = p.get("success_rate")
            sr_txt = f"{float(sr):.0f}%" if sr is not None else "—"
            self.presets_tree.insert(
                "",
                "end",
                iid=pid,
                values=(
                    str(p.get("name") or pid),
                    src,
                    status_txt,
                    sr_txt,
                    str(p.get("description") or ""),
                ),
                tags=(tag,),
            )

        self.presets_by_iid = new_map
        if prev_sel and prev_sel in self.presets_by_iid:
            self.presets_tree.selection_set(prev_sel)
            self.selected_preset = self.presets_by_iid[prev_sel]
        self._update_nav_badge(self.tab_presets, str(len(self.zapret_presets)))
        self.notebook.tab(self.tab_presets, text=f"Пресеты Zapret ({len(self.zapret_presets)})")

    def on_preset_select(self, _event: Any = None) -> None:
        sel = self.presets_tree.selection()
        if sel:
            self.selected_preset = self.presets_by_iid.get(sel[0])

    def _open_add_preset_focus(self) -> None:
        self._select_tab(self.tab_presets)
        try:
            self.user_preset_name_entry.focus_set()
        except tk.TclError:
            pass

    def on_apply_home_preset(self) -> None:
        label = self.home_preset_var.get()
        pid = self._home_preset_label_to_id.get(label, "auto")
        self.on_select_zapret_preset(pid)

    def on_select_zapret_preset(self, preset_id: str) -> None:
        def done(res: dict[str, Any]) -> None:
            self.active_preset_id = str(res.get("active_preset_id") or "auto")
            self.active_preset_name = str(res.get("active_preset_name") or "Авто-оркестратор")
            self._sync_active_preset_indicators()
            self.populate_presets_table()
            if self.active_preset_id == "auto":
                self.log_console("Режим Zapret2: Авто-оркестратор (подбор стратегий по доменам)")
                self.set_status("Включён режим Авто-оркестратор", ACCENT)
            else:
                self.log_console(f"Активирован рабочий пресет Zapret2: {self.active_preset_name}")
                self.set_status(f"Активен пресет: {self.active_preset_name} (оркестратор на паузе)", OK_TEXT)
            self._after_change()

        self.run_bg(f"Применение пресета ({preset_id})", lambda: self.backend.select_zapret_preset(preset_id), done)

    def on_activate_selected_preset(self) -> None:
        if not self.selected_preset:
            self.set_status("Выберите пресет в списке выше", WARN_TEXT)
            return
        self.on_select_zapret_preset(str(self.selected_preset["id"]))

    def on_load_selected_preset_to_editor(self) -> None:
        if not self.selected_preset:
            self.set_status("Выберите пресет в списке выше", WARN_TEXT)
            return
        name = str(self.selected_preset.get("name") or "")
        self.user_preset_name_var.set(f"{name} (мой)" if self.selected_preset.get("builtin", True) else name)
        self.user_preset_desc_var.set(str(self.selected_preset.get("description") or ""))
        self.user_preset_text.delete("1.0", "end")
        self.user_preset_text.insert("1.0", str(self.selected_preset.get("content") or ""))
        self.set_status(f"Загружено в редактор: {name}", ACCENT)

    def on_add_user_preset(self) -> None:
        name = self.user_preset_name_var.get().strip()
        desc = self.user_preset_desc_var.get().strip()
        content = self.user_preset_text.get("1.0", "end-1c").strip()
        activate = bool(self.user_preset_activate_var.get())
        if not name or not content:
            self.set_status("Укажите название и вставьте текст/аргументы пресета", WARN_TEXT)
            return

        def done(res: dict[str, Any]) -> None:
            saved = res.get("preset") or {}
            self.user_preset_name_var.set("")
            self.user_preset_desc_var.set("")
            self.user_preset_text.delete("1.0", "end")
            self.log_console(f"Сохранён пользовательский пресет: {saved.get('name')} (активирован={res.get('activated')})")
            self.set_status(f"Пресет «{saved.get('name')}» сохранён", OK_TEXT)
            self.load_zapret_presets_async()
            self._after_change()

        self.run_bg(
            f"Сохранение пресета {name}",
            lambda: self.backend.add_user_zapret_preset(
                name=name,
                content=content,
                description=desc,
                is_working=True,
                activate=activate,
            ),
            done,
        )

    def on_import_preset_file(self) -> None:
        fpath = filedialog.askopenfilename(
            title="Выберите файл пресета Zapret (.txt или .bat)",
            filetypes=[("Zapret Presets", "*.txt *.bat *.cmd"), ("All files", "*.*")],
        )
        if not fpath:
            return

        def done(res: dict[str, Any]) -> None:
            saved = res.get("preset") or {}
            self.log_console(f"Импортирован пресет из файла: {saved.get('name')}")
            self.set_status(f"Импортирован и активирован пресет: {saved.get('name')}", OK_TEXT)
            self.load_zapret_presets_async()
            self._after_change()

        self.run_bg(
            "Импорт пресета из файла",
            lambda: self.backend.import_zapret_preset_file(fpath, activate=True),
            done,
        )

    def on_import_presets_dir(self) -> None:
        default_dir = r"C:\vso\Dev\presets\winws2" if Path(r"C:\vso\Dev\presets\winws2").is_dir() else str(Path.cwd())
        dpath = filedialog.askdirectory(title="Выберите папку с пресетами Zapret2", initialdir=default_dir)
        if not dpath:
            return

        def done(res: dict[str, Any]) -> None:
            cnt = int(res.get("imported_count") or 0)
            self.log_console(f"Импорт из {res.get('dir_path')}: добавлено {cnt} пресетов")
            self.set_status(f"Импортировано пресетов: {cnt}", OK_TEXT if cnt > 0 else WARN_TEXT)
            self.load_zapret_presets_async()

        self.run_bg(
            "Импорт пресетов из папки",
            lambda: self.backend.import_zapret_presets_from_dir(dpath),
            done,
        )

    def on_delete_selected_preset(self) -> None:
        if not self.selected_preset:
            self.set_status("Выберите свой пресет для удаления", WARN_TEXT)
            return
        if self.selected_preset.get("builtin", True):
            self.set_status("Встроенные пресеты Zapret2 нельзя удалить — можно удалить только свои", WARN_TEXT)
            return
        pid = str(self.selected_preset["id"])
        pname = str(self.selected_preset.get("name") or pid)

        def done(res: dict[str, Any]) -> None:
            self.selected_preset = None
            self.log_console(f"Удалён пользовательский пресет: {pname}")
            self.set_status(f"Удалён пресет «{pname}»", OK_TEXT)
            self.load_zapret_presets_async()
            self._after_change()

        self.run_bg(f"Удаление пресета {pname}", lambda: self.backend.delete_zapret_preset(pid), done)

    def on_test_selected_preset(self) -> None:
        pid = str(self.selected_preset["id"]) if self.selected_preset else None
        activate = bool(pid and pid != self.active_preset_id)

        def done(res: dict[str, Any]) -> None:
            passed = int(res.get("passed") or 0)
            total = int(res.get("total") or 0)
            rate = float(res.get("success_rate") or 0.0)
            if isinstance(res.get("summary"), dict):
                self._update_test_summary_ui(res["summary"])
            self.log_console(
                f"Тест пресета ({res.get('active_preset_name')}): {passed}/{total} ({rate:.0f}%)"
            )
            self.set_status(
                f"Тест пресета: {passed}/{total} ({rate:.0f}%)",
                OK_TEXT if rate >= 80 else (WARN_TEXT if rate >= 40 else ERR_TEXT),
            )
            self.load_zapret_presets_async()
            self._after_change()

        self.run_bg(
            "Тест пресета (YT/DC/TG)",
            lambda: self.backend.test_zapret_preset(preset_id=pid, activate_if_needed=activate),
            done,
        )

    def on_run_connectivity_tests(self, include_picked: bool = False) -> None:
        label = "Тест всех подобранных доменов" if include_picked else "Тест сервисов (YouTube / Discord / Telegram)"

        def done(res: dict[str, Any]) -> None:
            passed = int(res.get("passed") or 0)
            total = int(res.get("total") or 0)
            rate = float(res.get("success_rate") or 0.0)
            if isinstance(res.get("summary"), dict):
                self._update_test_summary_ui(res["summary"])
            lines = [
                f"  {'✔' if r.get('ok') else '✖'} {r.get('domain')} "
                f"({r.get('latency_ms')}ms)" if r.get("ok") else f"  ✖ {r.get('domain')} [{r.get('stage')}] {r.get('error', '')}"
                for r in (res.get("results") or [])
            ]
            self.log_console(f"{label}: {passed}/{total} ({rate:.0f}%)\n" + "\n".join(lines))
            self.set_status(
                f"Проверка завершена: {passed}/{total} ({rate:.0f}%)",
                OK_TEXT if rate >= 80 else (WARN_TEXT if rate >= 40 else ERR_TEXT),
            )
            self.load_zapret_presets_async()
            self.refresh_async()

        self.run_bg(
            label,
            lambda: self.backend.run_connectivity_tests(
                include_key_services=True,
                include_picked_domains=include_picked,
            ),
            done,
        )

    def on_test_selected_domain(self) -> None:
        if not self.selected_row:
            self.set_status("Сначала выберите сайт в таблице", WARN_TEXT)
            return
        dom = str(self.selected_row["domain"])

        def done(res: dict[str, Any]) -> None:
            r0 = (res.get("results") or [{}])[0]
            ok = bool(r0.get("ok"))
            ms = r0.get("latency_ms")
            msg = f"Тест {dom}: {'✔ ДОСТУПЕН' + (f' ({ms:.0f}ms)' if ms is not None else '') if ok else '✖ НЕДОСТУПЕН (' + str(r0.get('stage') or 'err') + ')'}"
            self.log_console(msg)
            self.set_status(msg, OK_TEXT if ok else ERR_TEXT)
            self.refresh_async()

        self.run_bg(
            f"Тест {dom}",
            lambda: self.backend.run_connectivity_tests(domains=[dom], include_key_services=False),
            done,
        )

    def on_toggle_pin_selected(self) -> None:
        if not self.selected_row:
            self.set_status("Сначала выберите сайт в таблице", WARN_TEXT)
            return
        dom = str(self.selected_row["domain"])
        proto = str(self.selected_row["protocol"])
        new_pin = not bool(self.selected_row.get("pinned"))

        def done(res: dict[str, Any]) -> None:
            state = "закреплено (оркестратор не тронет)" if res.get("pinned") else "откреплено"
            self.log_console(f"Правило {dom} [{proto}]: {state}")
            self.set_status(f"Правило {dom}: {state}", OK_TEXT)
            self.refresh_async()

        self.run_bg(
            f"{'Закрепление' if new_pin else 'Открепление'} {dom}",
            lambda: self.backend.set_domain_pinned(dom, proto, new_pin),
            done,
        )

    def on_connect_telegram_proxy(self) -> None:
        """Open tg://proxy?... link to bind Telegram Desktop to local tg-ws-proxy in 1 click and copy backup."""
        cached_tg = self.last_snapshot.get("telegram_proxy") if isinstance(self.last_snapshot, dict) else None
        info = cached_tg if isinstance(cached_tg, dict) and cached_tg.get("url") else self.backend.get_telegram_proxy_info()
        url = str(info["url"])
        try:
            self.clipboard_clear()
            self.clipboard_append(url)
        except tk.TclError:
            pass
        opened = False
        if sys.platform == "win32" and hasattr(os, "startfile"):
            try:
                os.startfile(url)  # type: ignore[attr-defined]
                opened = True
            except OSError:
                opened = False
        if not opened:
            try:
                opened = bool(webbrowser.open(url))
            except Exception:  # noqa: BLE001
                opened = False
        state = "открыто в Telegram Desktop" if opened else "ссылка скопирована в буфер"
        self.log_console(f"Telegram MTProto прокси (127.0.0.1:{info['port']}): {state} ({url})")
        self.set_status(
            f"Telegram прокси {state} (127.0.0.1:{info['port']})",
            OK_TEXT if info.get("running") else WARN_TEXT,
        )

    def on_toggle_dpi_only(self) -> None:
        mode = "dpi_only" if bool(self.dpi_only_var.get()) else "hybrid"

        def done(res: dict[str, Any]) -> None:
            txt = "Без TUN (только Zapret2 + TG)" if res.get("stack_mode") == "dpi_only" else "Гибрид (Zapret2 + sing-box TUN)"
            self.log_console(f"Режим стека: {txt}")
            self.set_status(f"Режим стека: {txt}", OK_TEXT)
            self._after_change()

        self.run_bg("Переключение режима без TUN", lambda: self.backend.set_stack_mode(mode), done)

    def on_change_tun_stack(self) -> None:
        stack = (self.tun_stack_var.get() or "gvisor").strip()

        def done(res: dict[str, Any]) -> None:
            self.log_console(f"TUN стек sing-box: {res.get('tun_stack')}")
            self.set_status(f"TUN стек sing-box: {res.get('tun_stack')}", OK_TEXT)
            self._after_change()

        self.run_bg(f"Смена TUN стека ({stack})", lambda: self.backend.set_tun_stack(stack), done)


# --------------------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------------------


def _ensure_gui_stdio() -> None:
    """Ensure sys.stdout/sys.stderr are writable streams when running under pythonw.exe."""
    for stream_name in ("stdout", "stderr"):
        if getattr(sys, stream_name) is None:
            setattr(sys, stream_name, open(os.devnull, "w", encoding="utf-8", errors="replace"))


def _has_console_window() -> bool:
    """Return True when the current process has an attached Windows console window."""
    if sys.platform != "win32":
        return True
    try:
        return bool(ctypes.windll.kernel32.GetConsoleWindow())
    except Exception:  # noqa: BLE001
        return False


def _resolve_workspace_root(db_path: str | Path = "netdoctor.db") -> Path:
    """Locate the netdoctor project root even when launched from System32 or Explorer."""
    cwd = Path.cwd().resolve()
    if (cwd / "pyproject.toml").is_file() or ((cwd / "bin").is_dir() and (cwd / "configs").is_dir()):
        return cwd
    db_candidate = Path(db_path)
    if db_candidate.is_absolute():
        parent = db_candidate.resolve().parent
        if (parent / "bin").is_dir() or (parent / "presets").is_dir():
            return parent
    parents = Path(__file__).resolve().parents
    if len(parents) > 2:
        repo_root = parents[2]
        if (repo_root / "pyproject.toml").is_file() or (repo_root / "bin").is_dir() or (repo_root / "presets").is_dir():
            return repo_root
    return cwd


def _show_startup_error(message: str, logs_dir: Path) -> None:
    """Record GUI startup errors to logs/gui_startup.log and show MessageBoxW when no console exists."""
    try:
        logs_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with (logs_dir / "gui_startup.log").open("a", encoding="utf-8", errors="replace") as f:
            f.write(f"[{stamp}] {message.rstrip()}\n")
    except OSError:
        pass
    if sys.platform == "win32" and not _has_console_window():
        try:
            ctypes.windll.user32.MessageBoxW(0, message[:1500], "netdoctor", 0x10)
        except Exception:  # noqa: BLE001
            pass
    else:
        try:
            sys.stderr.write(message.rstrip() + "\n")
        except Exception:  # noqa: BLE001
            pass


def _enable_dpi_awareness() -> None:
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        pass
    if sys.platform == "win32":
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("netdoctor.gui")
        except Exception:  # noqa: BLE001
            pass


def launch_gui(
    db_path: str = "netdoctor.db",
    logs_dir: str = "logs",
    configs_dir: str = "configs",
    lists_dir: str = "lists",
    bin_dir: str = "bin",
    headless_check: bool = False,
    minimized: bool = False,
    auto_start_stack: bool = False,
) -> dict[str, Any]:
    """Launch the desktop control panel, or return the status snapshot immediately when headless_check=True."""
    if headless_check:
        return NetdoctorController(
            db_path=db_path,
            configs_dir=configs_dir,
            lists_dir=lists_dir,
            logs_dir=logs_dir,
            bin_dir=bin_dir,
        ).get_status_snapshot()

    _ensure_gui_stdio()
    workspace_root = _resolve_workspace_root(db_path)
    if workspace_root != Path.cwd().resolve():
        os.chdir(workspace_root)

    ctrl = NetdoctorController(
        db_path=db_path,
        configs_dir=configs_dir,
        lists_dir=lists_dir,
        logs_dir=logs_dir,
        bin_dir=bin_dir,
    )

    acquired, mutex_handle = acquire_single_instance_mutex()
    if not acquired:
        return ctrl.get_status_snapshot()

    _enable_dpi_awareness()
    try:
        app = NetdoctorGuiApp(
            backend=ctrl.backend,
            minimized=minimized,
            auto_start_stack=auto_start_stack,
        )
        app.mainloop()
    finally:
        release_single_instance_mutex(mutex_handle)
    return ctrl.get_status_snapshot()


def _resolve_arg_path(raw: str, base: Path) -> Path:
    candidate = Path(raw).expanduser()
    return candidate.resolve() if candidate.is_absolute() else (base / candidate).resolve()


def main(argv: list[str] | None = None) -> int:
    """Non-console Windows GUI entry point (`netdoctor-gui.exe`) with automatic UAC elevation."""
    _ensure_gui_stdio()
    parser = argparse.ArgumentParser(prog="netdoctor-gui", description="netdoctor desktop control panel")
    parser.add_argument("--db", default="netdoctor.db", help="Path to SQLite database")
    parser.add_argument("--logs-dir", default="logs", help="Directory for process logs and supervisor state")
    parser.add_argument("--configs-dir", default="configs", help="Directory for generated configs")
    parser.add_argument("--lists-dir", default="lists", help="Directory for winws2 hostlists")
    parser.add_argument("--bin-dir", default="bin", help="Directory containing external binaries")
    parser.add_argument("--headless-check", action="store_true", help="Print GUI controller snapshot JSON and exit")
    parser.add_argument("--minimized", action="store_true", help="Start minimized to system tray")
    parser.add_argument("--auto-start", action="store_true", help="Trigger protection autopilot right after GUI startup")
    parser.add_argument("--replace-pid", type=int, default=None, help="Gracefully stop an older GUI PID")
    parser.add_argument("--no-elevate", action="store_true", help="Skip automatic Administrator UAC prompt")
    args = parser.parse_args(argv)

    if args.headless_check:
        snap = launch_gui(
            db_path=args.db,
            logs_dir=args.logs_dir,
            configs_dir=args.configs_dir,
            lists_dir=args.lists_dir,
            bin_dir=args.bin_dir,
            headless_check=True,
            minimized=args.minimized,
            auto_start_stack=args.auto_start,
        )
        sys.stdout.write(json.dumps(snap, indent=2, ensure_ascii=False) + "\n")
        sys.stdout.flush()
        return 0

    workspace_root = _resolve_workspace_root(args.db)
    if workspace_root != Path.cwd().resolve():
        os.chdir(workspace_root)

    db_resolved = _resolve_arg_path(args.db, workspace_root)
    configs_resolved = _resolve_arg_path(args.configs_dir, workspace_root)
    lists_resolved = _resolve_arg_path(args.lists_dir, workspace_root)
    logs_resolved = _resolve_arg_path(args.logs_dir, workspace_root)
    bin_resolved = _resolve_arg_path(args.bin_dir, workspace_root)

    if sys.platform == "win32" and not args.no_elevate and not _is_admin():
        res = elevate_gui(
            db_path=db_resolved,
            configs_dir=configs_resolved,
            lists_dir=lists_resolved,
            logs_dir=logs_resolved,
            working_dir=workspace_root,
            bin_dir=bin_resolved,
            replace_pid=args.replace_pid,
            auto_start=args.auto_start,
            minimized=args.minimized,
        )
        if res.get("ok") or res.get("cancelled"):
            return 0
        _show_startup_error(
            f"Не удалось запустить netdoctor с правами администратора:\n{res.get('error', 'Unknown error')}",
            logs_resolved,
        )
        return 1

    if args.replace_pid is not None:
        terminate_pid_gracefully(args.replace_pid)

    try:
        launch_gui(
            db_path=str(db_resolved),
            logs_dir=str(logs_resolved),
            configs_dir=str(configs_resolved),
            lists_dir=str(lists_resolved),
            bin_dir=str(bin_resolved),
            headless_check=False,
            minimized=args.minimized,
            auto_start_stack=args.auto_start,
        )
        return 0
    except Exception as exc:  # noqa: BLE001
        _show_startup_error(
            f"Ошибка запуска GUI netdoctor: {exc}\n{traceback.format_exc()}",
            logs_resolved,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
