"""Modern, user-friendly ZAPRET // NETDOCTOR desktop GUI built with clear visual hierarchy."""

from __future__ import annotations

import argparse
from collections import deque
import ctypes
import gc
import json
import math
import os
import queue
import re
import sys
import threading
import tkinter as tk
import tkinter.font as tkfont
import traceback
import webbrowser
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any, Callable

from netdoctor import __version__
from netdoctor.gui_backend import GuiBackend, elevate_gui
from netdoctor.supervisor import _is_admin
from netdoctor.vpn import is_auto_select_node, is_placeholder_node
from netdoctor.tray import (
    NetdoctorTrayIcon,
    acquire_single_instance_mutex,
    release_single_instance_mutex,
    terminate_pid_gracefully,
)

# --------------------------------------------------------------------------------------
# Design Tokens (ZAPRET UI — Soft Deep Obsidian Indigo, Electric Cyan & Periwinkle Lavender)
# --------------------------------------------------------------------------------------

BG = "#090A14"
SIDEBAR_BG = "#0D0F1D"
HEADER_BG = "#0B0D19"
CARD = "#121528"
CARD_ALT = "#171B32"
CARD_ACTIVE = "#152238"
INFO_BG = "#13263A"
INPUT = "#181C34"
INPUT_HOVER = "#212747"
BORDER = "#252B4A"
BORDER_LIGHT = "#353E6B"
CYAN_BORDER = "#22B8CF"

FG = "#F4F6FF"
FG_SOFT = "#C9D1EC"
MUTED = "#8590B3"
DIM = "#566080"

ACCENT = "#38E2F7"
LAVENDER = "#B69DF8"
LAVENDER_HOVER = "#C9B6FA"
LAVENDER_DARK = "#0D0F1E"
PILL_ACTIVE_BG = "#32295E"
PILL_ACTIVE_BORDER = "#8B74E8"
PRIMARY_BG = "#352B66"
PRIMARY_HOVER = "#453882"
SELECT_BG = "#2C2654"

OK = "#22D3EE"
OK_TEXT = "#38E2F7"
OK_BG = "#102837"
OK_BTN = "#1599B2"
OK_BTN_HOVER = "#22B8CF"

WARN = "#F59E0B"
WARN_TEXT = "#FBBF24"
WARN_BG = "#291F12"
WARN_BTN = "#D97706"
WARN_BTN_HOVER = "#F59E0B"

ERR = "#F43F5E"
ERR_TEXT = "#FB7185"
ERR_BG = "#281320"
ERR_BTN = "#4C182B"
ERR_BTN_HOVER = "#6D213C"

PURPLE = "#B69DF8"
PURPLE_BG = "#221C3E"

FONT_UI = ("Segoe UI", 10)
FONT_UI_B = ("Segoe UI", 10, "bold")
FONT_HERO = ("Segoe UI", 14, "bold")
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
    "dpi": "Обход DPI",
    "dns": "Свой DNS",
    "vpn": "Через VPN",
    "direct": "Напрямую",
}
OVERRIDE_LAYERS = ("dpi", "vpn", "dns", "direct")
OVERRIDE_LAYER_HINTS: dict[str, str] = {
    "dpi": "Быстрый обход блокировок на полной скорости интернета без VPN.",
    "dns": "Открывать сайт через персональный защищённый DNS-сервер.",
    "vpn": "Направить сайт через защищённый VPN-туннель (для блокировок по IP).",
    "direct": "Открывать сайт напрямую без обхода и без VPN.",
}

LOG_FILES = ("winws2.log", "sing-box.log", "tg-ws-proxy.log")
VPN_MODE_AUTO_LABEL = "Автовыбор лучшего сервера"
VPN_MODE_PRIORITY_LABEL = "Приоритетный сервер"
PROCESS_LEDS: tuple[tuple[str, str, str], ...] = (
    ("winws2", "DPI", "Модуль обхода блокировок (winws2.exe)"),
    ("sing-box", "VPN", "Модуль точечного VPN и защищённого DNS (sing-box.exe)"),
    ("tg-ws-proxy", "TG", "Локальный MTProto-прокси для Telegram Desktop (tg-ws-proxy)"),
)

DOMAIN_COLUMNS: tuple[tuple[str, str, int, str], ...] = (
    ("domain", "Сайт / Домен", 190, "w"),
    ("protocol", "Прот.", 62, "center"),
    ("verdicts", "Причина блокировки", 145, "w"),
    ("layer", "Способ", 68, "center"),
    ("strategy", "Выбранное правило", 175, "w"),
    ("test", "Проверка", 90, "center"),
    ("success", "Стабильность", 95, "center"),
    ("sockets", "Подкл.", 76, "center"),
    ("fallback", "Резервные варианты", 125, "w"),
    ("ttfb", "Отклик (мс)", 78, "e"),
    ("updated", "Обновлено", 108, "center"),
)

PRESET_COLUMNS: tuple[tuple[str, str, int, str], ...] = (
    ("name", "Название стратегии / пресета", 250, "w"),
    ("source", "Источник", 105, "center"),
    ("status", "Статус", 115, "center"),
    ("success", "Стабильность", 95, "center"),
    ("description", "Описание", 300, "w"),
)

CONN_COLUMNS: tuple[tuple[str, str, int, str], ...] = (
    ("process", "Приложение", 145, "w"),
    ("domain", "Сайт / Домен", 205, "w"),
    ("remote", "Удалённый адрес", 150, "w"),
    ("protocol", "Протокол", 74, "center"),
    ("socket", "Состояние сети", 105, "center"),
    ("layer", "Маршрут", 76, "center"),
    ("strategy", "Правило обхода", 185, "w"),
    ("health", "Статус защиты", 145, "center"),
)

SERVICE_ACTIONS: tuple[tuple[str, str, str], ...] = (
    ("layers", "Проверить задержку модулей", "Измеряет время отклика DNS, DPI и VPN-серверов."),
    ("reload", "Перезапустить обход (winws2)", "Применяет новые правила DPI без остановки всей защиты."),
    ("reload_sb", "Перезапустить VPN (sing-box)", "Обновляет конфигурацию VPN-туннеля и DNS."),
    ("reval", "Проверить рабочие правила", "Тестирует уже сохранённые стратегии и переключает сбойные на резерв."),
    ("gen", "Обновить файлы конфигов", "Пересобирает конфиги и списки доменов из базы данных."),
    ("flush_dns", "Очистить DNS-кэш Windows", "Сбрасывает устаревшие системные записи DNS (ipconfig /flushdns)."),
    ("verify", "Проверить и докачать файлы", "Проверяет целостность рабочих модулей обхода и скачивает недостающие."),
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

    def force_apply_pending_changes(self, iface: int | None = None) -> dict[str, Any]:
        return self.backend.force_apply_pending_changes(iface=iface)

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
# Animation Helpers & Custom Widgets (Tooltips, Animated Toggles, Sparkline Chart)
# --------------------------------------------------------------------------------------


def lerp_hex(c1: str, c2: str, t: float) -> str:
    """Linearly interpolate between two ``#RRGGBB`` colors (clamped ``t`` in 0..1)."""
    t = max(0.0, min(1.0, float(t)))
    try:
        s1 = c1.lstrip("#")
        s2 = c2.lstrip("#")
        r1, g1, b1 = int(s1[0:2], 16), int(s1[2:4], 16), int(s1[4:6], 16)
        r2, g2, b2 = int(s2[0:2], 16), int(s2[2:4], 16), int(s2[4:6], 16)
    except (ValueError, IndexError, TypeError):
        return c2
    r = round(r1 + (r2 - r1) * t)
    g = round(g1 + (g2 - g1) * t)
    b = round(b1 + (b2 - b1) * t)
    return f"#{r:02x}{g:02x}{b:02x}"


def draw_rounded_rect(
    canvas: tk.Canvas,
    x1: float,
    y1: float,
    x2: float,
    y2: float,
    r: float,
    **kwargs: Any,
) -> int:
    """Draw a smooth rounded rectangle on a Tk ``Canvas``."""
    r = max(0.0, min(float(r), (x2 - x1) / 2.0, (y2 - y1) / 2.0))
    pts = (
        x1 + r, y1,
        x1 + r, y1,
        x2 - r, y1,
        x2 - r, y1,
        x2, y1,
        x2, y1 + r,
        x2, y1 + r,
        x2, y2 - r,
        x2, y2 - r,
        x2, y2,
        x2 - r, y2,
        x2 - r, y2,
        x1 + r, y2,
        x1 + r, y2,
        x1, y2,
        x1, y2 - r,
        x1, y2 - r,
        x1, y1 + r,
        x1, y1 + r,
        x1, y1,
    )
    return canvas.create_polygon(pts, smooth=True, splinesteps=16, **kwargs)


class HoverTooltip:
    """Singleton floating rounded dark-indigo tooltip with delayed reveal and soft fade-in."""

    _active: HoverTooltip | None = None
    _pending: HoverTooltip | None = None

    def __init__(self, widget: tk.Misc, text: str, title: str | None = None, delay_ms: int = 180) -> None:
        self.widget = widget
        self.text = text
        self.title = title
        self.delay_ms = delay_ms
        self._after_id: str | None = None
        self._fade_id: str | None = None
        self._win: tk.Toplevel | None = None

        widget.bind("<Enter>", self._on_enter, add="+")
        widget.bind("<Leave>", self._on_leave, add="+")
        widget.bind("<ButtonPress>", self._on_leave, add="+")
        widget.bind("<Destroy>", self._on_destroy, add="+")

    def set_text(self, text: str, title: str | None = None) -> None:
        self.text = text
        if title is not None:
            self.title = title

    def _cancel_timers(self) -> None:
        if self._after_id is not None:
            try:
                self.widget.after_cancel(self._after_id)
            except tk.TclError:
                pass
            self._after_id = None
        if self._fade_id is not None:
            try:
                self.widget.after_cancel(self._fade_id)
            except tk.TclError:
                pass
            self._fade_id = None
        if HoverTooltip._pending is self:
            HoverTooltip._pending = None

    def _on_enter(self, _event: Any = None) -> None:
        if HoverTooltip._pending is not None and HoverTooltip._pending is not self:
            HoverTooltip._pending._cancel_timers()
        active = HoverTooltip._active
        if active is not None and active._win is not None:
            if active is self or (active.text == self.text and active.title == self.title):
                return
            active.hide()
        self._cancel_timers()
        try:
            if not self.widget.winfo_viewable():
                return
            HoverTooltip._pending = self
            self._after_id = self.widget.after(self.delay_ms, self.show)
        except tk.TclError:
            pass

    def _on_leave(self, _event: Any = None) -> None:
        self._cancel_timers()
        self.hide()

    def _on_destroy(self, _event: Any = None) -> None:
        self._cancel_timers()
        self.hide()

    def show(self) -> None:
        if HoverTooltip._pending is self:
            HoverTooltip._pending = None
        if HoverTooltip._active is not None and HoverTooltip._active is not self:
            HoverTooltip._active.hide()
        if self._win is not None or not self.text:
            return
        try:
            if not self.widget.winfo_exists() or not self.widget.winfo_viewable():
                return
            win = tk.Toplevel(self.widget)
            win.wm_overrideredirect(True)
            win.attributes("-topmost", True)
            trans_col = "#010102"
            use_trans = sys.platform == "win32"
            if use_trans:
                try:
                    win.configure(bg=trans_col)
                    win.attributes("-transparentcolor", trans_col)
                except tk.TclError:
                    use_trans = False
                    win.configure(bg=CARD_ALT)
            else:
                win.configure(bg=CARD_ALT)
            try:
                win.attributes("-alpha", 0.0)
            except tk.TclError:
                pass

            canvas = tk.Canvas(
                win,
                bg=trans_col if use_trans else CARD_ALT,
                highlightthickness=0,
                bd=0,
            )
            canvas.pack()

            inner = tk.Frame(canvas, bg=CARD_ALT, padx=11, pady=7)
            if self.title:
                tk.Label(
                    inner, text=self.title, bg=CARD_ALT, fg=ACCENT, font=FONT_SMALL_B, anchor="w", justify="left"
                ).pack(fill="x", pady=(0, 2))
            tk.Label(
                inner,
                text=self.text,
                bg=CARD_ALT,
                fg=FG_SOFT,
                font=FONT_SMALL,
                anchor="w",
                justify="left",
                wraplength=290,
            ).pack(fill="x")
            inner.update_idletasks()
            iw = max(80, inner.winfo_reqwidth() + 4)
            ih = max(28, inner.winfo_reqheight() + 4)
            canvas.configure(width=iw, height=ih)
            draw_rounded_rect(canvas, 1, 1, iw - 1, ih - 1, 10, fill=CARD_ALT, outline=PILL_ACTIVE_BORDER, width=1)
            canvas.create_window(iw // 2, ih // 2, window=inner, anchor="center")
            win.update_idletasks()

            rx = self.widget.winfo_rootx() + min(18, max(4, self.widget.winfo_width() // 4))
            ry = self.widget.winfo_rooty() + self.widget.winfo_height() + 6
            sw = win.winfo_screenwidth()
            sh = win.winfo_screenheight()
            tw = win.winfo_reqwidth()
            th = win.winfo_reqheight()
            if rx + tw > sw - 12:
                rx = max(8, sw - tw - 12)
            if ry + th > sh - 12:
                ry = max(8, self.widget.winfo_rooty() - th - 6)
            win.wm_geometry(f"+{rx}+{ry}")
            self._win = win
            HoverTooltip._active = self
            self._fade_step(0)
        except tk.TclError:
            self.hide()

    def _fade_step(self, step: int) -> None:
        if self._win is None:
            return
        try:
            alpha = min(0.97, 0.25 + step * 0.24)
            self._win.attributes("-alpha", alpha)
            if alpha < 0.96:
                self._fade_id = self.widget.after(22, lambda: self._fade_step(step + 1))
        except tk.TclError:
            self.hide()

    def hide(self) -> None:
        self._cancel_timers()
        if HoverTooltip._active is self:
            HoverTooltip._active = None
        if HoverTooltip._pending is self:
            HoverTooltip._pending = None
        if self._win is not None:
            try:
                self._win.destroy()
            except tk.TclError:
                pass
            self._win = None


class AnimatedToggle(tk.Canvas):
    """Smooth animated capsule toggle switch synced with a ``tk.BooleanVar``."""

    def __init__(
        self,
        parent: tk.Misc,
        variable: tk.BooleanVar,
        command: Callable[[], Any] | None = None,
        bg: str = CARD,
        width: int = 42,
        height: int = 20,
    ) -> None:
        self._tog_w = int(width)
        self._tog_h = int(height)
        super().__init__(
            parent,
            width=self._tog_w,
            height=self._tog_h,
            bg=bg,
            highlightthickness=0,
            bd=0,
            cursor="hand2",
        )
        self.variable = variable
        self.command = command
        self._progress = 1.0 if bool(variable.get()) else 0.0
        self._anim_id: str | None = None
        self._trace_id: str | None = None

        self._draw(self._progress)
        self.bind("<Button-1>", self._on_click)
        self.bind("<Destroy>", self._on_destroy)
        self._trace_id = self.variable.trace_add("write", self._on_var_changed)

    def _draw(self, t: float) -> None:
        self.delete("all")
        t = max(0.0, min(1.0, t))
        track_col = lerp_hex("#232846", "#3E3275", t)
        border_col = lerp_hex(BORDER_LIGHT, LAVENDER, t)
        thumb_col = lerp_hex("#8590B3", LAVENDER, t)

        pad = 2
        r = (self._tog_h - pad * 2) / 2.0
        x0, y0, x1, y1 = pad, pad, self._tog_w - pad, self._tog_h - pad
        draw_rounded_rect(self, x0, y0, x1, y1, r, fill=track_col, outline=border_col, width=1)

        cx = (x0 + r) + ((x1 - r) - (x0 + r)) * t
        cy = self._tog_h / 2.0
        tr = max(3.5, r - 2.3)
        self.create_oval(cx - tr, cy - tr, cx + tr, cy + tr, fill=thumb_col, outline="")

    def _on_click(self, _event: Any = None) -> None:
        self.variable.set(not bool(self.variable.get()))
        if self.command is not None:
            self.command()

    def _on_var_changed(self, *_args: Any) -> None:
        target = 1.0 if bool(self.variable.get()) else 0.0
        self._animate_to(target)

    def _animate_to(self, target: float) -> None:
        if self._anim_id is not None:
            try:
                self.after_cancel(self._anim_id)
            except tk.TclError:
                pass
            self._anim_id = None
        try:
            viewable = bool(self.winfo_viewable())
        except tk.TclError:
            return
        if not viewable:
            self._progress = target
            self._draw(target)
            return
        start = self._progress
        steps = 6

        def _step(idx: int) -> None:
            try:
                if not self.winfo_exists():
                    return
                frac = idx / steps
                eased = 1.0 - (1.0 - frac) ** 2
                self._progress = start + (target - start) * eased
                self._draw(self._progress)
                if idx < steps:
                    self._anim_id = self.after(18, lambda: _step(idx + 1))
                else:
                    self._anim_id = None
            except tk.TclError:
                self._anim_id = None

        _step(1)

    def _on_destroy(self, _event: Any = None) -> None:
        if self._anim_id is not None:
            try:
                self.after_cancel(self._anim_id)
            except tk.TclError:
                pass
            self._anim_id = None
        if self._trace_id is not None:
            try:
                self.variable.trace_remove("write", self._trace_id)
            except tk.TclError:
                pass
            self._trace_id = None


class RoundedButton(tk.Canvas):
    """Soft-corner animated button rendered on Tk ``Canvas`` with ``tk.Button``-compatible API."""

    def __init__(
        self,
        parent: tk.Misc,
        text: str,
        command: Callable[[], Any],
        palette: tuple[str, str, str, str, str],
        *,
        width: int | None = None,
        font: tuple[Any, ...] = FONT_UI_B,
        padx: int = 12,
        pady: int = 6,
        radius: int = 10,
        anchor: str = "center",
    ) -> None:
        try:
            parent_bg = str(parent.cget("bg"))
        except tk.TclError:
            parent_bg = BG
        self._parent_bg = parent_bg
        self._text = text
        self._command = command
        self._font = font
        self._padx = padx
        self._pady = pady
        self._radius = radius
        self._anchor = anchor
        self._width_chars = width
        self._netdoc_palette = palette
        self._cur_bg, self._cur_fg, _hov, self._cur_brd, _bhov = palette
        self._pressed = False
        self._hovered = False
        self._tween_id: str | None = None

        self._measure()
        super().__init__(
            parent,
            width=self._req_w,
            height=self._req_h,
            bg=self._parent_bg,
            highlightthickness=0,
            bd=0,
            cursor="hand2",
        )
        self._redraw()
        self.bind("<Configure>", lambda _e: self._redraw())
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<ButtonPress-1>", self._on_press)
        self.bind("<ButtonRelease-1>", self._on_release)
        self.bind("<Destroy>", self._on_destroy)

    def _measure(self) -> None:
        try:
            fnt = tkfont.Font(font=self._font)
            tw = fnt.measure(self._text or " ")
            lh = fnt.metrics("linespace")
            ch = max(7, fnt.measure("0"))
        except tk.TclError:
            tw = max(24, len(self._text) * 8)
            lh = 16
            ch = 8
        if self._width_chars:
            self._req_w = max(tw + self._padx * 2 + 4, self._width_chars * ch + self._padx * 2)
        else:
            self._req_w = tw + self._padx * 2 + 6
        self._req_h = max(24 if self._pady >= 2 else 22, lh + self._pady * 2 + 2)

    def _redraw(self) -> None:
        try:
            w = self.winfo_width()
            h = self.winfo_height()
        except tk.TclError:
            return
        if w <= 1:
            w = self._req_w
        if h <= 1:
            h = self._req_h
        self.delete("all")
        fill = lerp_hex(self._cur_bg, "#FFFFFF", 0.08) if self._pressed else self._cur_bg
        draw_rounded_rect(self, 1, 1, w - 1, h - 1, min(self._radius, (h - 2) / 2.0), fill=fill, outline=self._cur_brd, width=1)
        if self._anchor == "w":
            tx = self._padx + 3
            anc = "w"
        else:
            tx = w / 2.0
            anc = "center"
        ty = h / 2.0 + (1 if self._pressed else 0)
        self.create_text(tx, ty, text=self._text, fill=self._cur_fg, font=self._font, anchor=anc)

    def _tween_to(self, target_bg: str, target_brd: str) -> None:
        if self._tween_id is not None:
            try:
                self.after_cancel(self._tween_id)
            except tk.TclError:
                pass
            self._tween_id = None
        try:
            viewable = bool(self.winfo_viewable())
        except tk.TclError:
            return
        if not viewable:
            self._cur_bg = target_bg
            self._cur_brd = target_brd
            self._redraw()
            return
        s_bg, s_brd = self._cur_bg, self._cur_brd
        steps = 4

        def _step(idx: int) -> None:
            try:
                if not self.winfo_exists():
                    return
                frac = idx / steps
                self._cur_bg = lerp_hex(s_bg, target_bg, frac)
                self._cur_brd = lerp_hex(s_brd, target_brd, frac)
                self._redraw()
                if idx < steps:
                    self._tween_id = self.after(16, lambda: _step(idx + 1))
                else:
                    self._tween_id = None
            except tk.TclError:
                self._tween_id = None

        _step(1)

    def _on_enter(self, _e: Any = None) -> None:
        self._hovered = True
        self._tween_to(self._netdoc_palette[2], self._netdoc_palette[4])

    def _on_leave(self, _e: Any = None) -> None:
        self._hovered = False
        self._pressed = False
        self._tween_to(self._netdoc_palette[0], self._netdoc_palette[3])

    def _on_press(self, _e: Any = None) -> None:
        self._pressed = True
        self._redraw()

    def _on_release(self, event: Any = None) -> None:
        was_pressed = self._pressed
        self._pressed = False
        self._redraw()
        if not was_pressed:
            return
        if event is not None:
            try:
                if not (0 <= event.x <= self.winfo_width() and 0 <= event.y <= self.winfo_height()):
                    return
            except tk.TclError:
                pass
        if self._command is not None:
            self._command()

    def invoke(self) -> Any:
        if self._command is not None:
            return self._command()
        return None

    def cget(self, key: str) -> Any:
        if key == "text":
            return self._text
        if key in ("bg", "background"):
            return self._cur_bg
        if key in ("fg", "foreground"):
            return self._cur_fg
        if key == "anchor":
            return self._anchor
        return super().cget(key)

    def configure(self, cnf: dict[str, Any] | None = None, **kw: Any) -> Any:  # type: ignore[override]
        opts = dict(cnf or {})
        opts.update(kw)
        recalc = False
        if "text" in opts:
            self._text = str(opts.pop("text"))
            recalc = True
        if "font" in opts:
            self._font = opts.pop("font")
            recalc = True
        if "anchor" in opts:
            self._anchor = str(opts.pop("anchor"))
        if "bg" in opts:
            self._cur_bg = str(opts.pop("bg"))
        if "fg" in opts:
            self._cur_fg = str(opts.pop("fg"))
        if "highlightbackground" in opts:
            self._cur_brd = str(opts.pop("highlightbackground"))
        opts.pop("activebackground", None)
        opts.pop("activeforeground", None)
        if recalc:
            self._measure()
            opts.setdefault("width", self._req_w)
            opts.setdefault("height", self._req_h)
        res = super().configure(**opts) if opts else None
        self._redraw()
        return res

    config = configure

    def _on_destroy(self, _e: Any = None) -> None:
        if self._tween_id is not None:
            try:
                self.after_cancel(self._tween_id)
            except tk.TclError:
                pass
            self._tween_id = None


class RoundedCard(tk.Canvas):
    """Soft rounded surface card hosting a ``self.body`` frame with dynamic border glow."""

    def __init__(
        self,
        parent: tk.Misc,
        *,
        bg: str = CARD,
        outer_bg: str | None = None,
        border: str = BORDER,
        radius: int = 14,
        pad: int = 2,
        border_width: int = 1,
    ) -> None:
        if outer_bg is None:
            try:
                outer_bg = str(parent.cget("bg"))
            except tk.TclError:
                outer_bg = BG
        self._card_bg = bg
        self._border = border
        self._radius = radius
        self._pad = pad
        self._bw = border_width
        self._last_req = (0, 0)
        super().__init__(parent, bg=outer_bg, highlightthickness=0, bd=0)
        self.body = tk.Frame(self, bg=bg)
        self._win_id = self.create_window(pad, pad, window=self.body, anchor="nw")
        self.body.bind("<Configure>", self._on_body_cfg)
        self.bind("<Configure>", self._on_canvas_cfg)

    def _on_body_cfg(self, _e: Any = None) -> None:
        try:
            rh = max(20, self.body.winfo_reqheight() + self._pad * 2)
            rw = max(40, self.body.winfo_reqwidth() + self._pad * 2)
            if (rw, rh) != self._last_req:
                self._last_req = (rw, rh)
                super().configure(width=rw, height=rh)
            self._redraw()
        except tk.TclError:
            pass

    def _on_canvas_cfg(self, e: Any) -> None:
        try:
            w = max(24, int(getattr(e, "width", 0)) - self._pad * 2)
            self.itemconfigure(self._win_id, width=w)
            self._redraw()
        except tk.TclError:
            pass

    def _redraw(self) -> None:
        try:
            w = max(self._last_req[0], self.winfo_width())
            h = max(self._last_req[1], self.winfo_height())
            if w <= 4 or h <= 4:
                return
            self.delete("card_bg")
            tid = draw_rounded_rect(
                self,
                1,
                1,
                w - 1,
                h - 1,
                self._radius,
                fill=self._card_bg,
                outline=self._border,
                width=self._bw,
                tags=("card_bg",),
            )
            self.tag_lower(tid)
        except tk.TclError:
            pass

    def set_border(self, color: str) -> None:
        if color != self._border:
            self._border = color
            self._redraw()

    def cget(self, key: str) -> Any:
        if key == "highlightbackground":
            return self._border
        if key in ("bg", "background"):
            return self._card_bg
        return super().cget(key)

    def configure(self, cnf: dict[str, Any] | None = None, **kw: Any) -> Any:  # type: ignore[override]
        opts = dict(cnf or {})
        opts.update(kw)
        need_redraw = False
        if "highlightbackground" in opts:
            self._border = str(opts.pop("highlightbackground"))
            need_redraw = True
        if "bg" in opts or "background" in opts:
            bg_val = str(opts.pop("bg", opts.pop("background", self._card_bg)))
            self._card_bg = bg_val
            try:
                self.body.configure(bg=bg_val)
            except tk.TclError:
                pass
            need_redraw = True
        if "outer_bg" in opts:
            opts["bg"] = str(opts.pop("outer_bg"))
        res = super().configure(**opts) if opts else None
        if need_redraw:
            self._redraw()
        return res

    config = configure

    config = configure


class ActivityBar(tk.Canvas):
    """Thin sweeping cyan-lavender progress beam under header showing live background activity."""

    def __init__(self, parent: tk.Misc, bg: str = BG) -> None:
        super().__init__(parent, height=3, bg=bg, highlightthickness=0, bd=0)
        self._active = False
        self._pos = 0.0
        self.bind("<Configure>", lambda _e: self.redraw())

    def set_active(self, active: bool) -> None:
        if self._active != active:
            self._active = active
            self.redraw()

    def step(self) -> None:
        if self._active:
            self._pos = (self._pos + 0.045) % 1.35
            self.redraw()

    def redraw(self) -> None:
        try:
            w = max(120, int(self.winfo_width()))
        except tk.TclError:
            return
        self.delete("all")
        if not self._active:
            self.create_line(0, 1, w, 1, fill=BORDER, width=1)
            return
        self.create_line(0, 1, w, 1, fill="#151932", width=1)
        beam_w = max(80, int(w * 0.24))
        x0 = (self._pos - 0.24) * w
        x1 = x0 + beam_w
        mid = (x0 + x1) / 2.0
        self.create_rectangle(x0, 0, mid, 3, fill=LAVENDER, outline="")
        self.create_rectangle(mid, 0, x1, 3, fill=ACCENT, outline="")


class LiveSparklineCanvas(tk.Canvas):
    """Real-time dual-line connection activity chart inspired by the Traffic Monitor reference."""

    def __init__(self, parent: tk.Misc, height: int = 92, bg: str = CARD) -> None:
        super().__init__(parent, height=height, bg=bg, highlightthickness=0, bd=0)
        self._bg = bg
        self._total_hist: deque[int] = deque([0] * 32, maxlen=36)
        self._prot_hist: deque[int] = deque([0] * 32, maxlen=36)
        self._pulse = 0.5
        self.bind("<Configure>", lambda _e: self.redraw())

    def push_sample(self, total: int, protected: int) -> None:
        self._total_hist.append(max(0, int(total)))
        self._prot_hist.append(max(0, int(protected)))
        self.redraw()

    def set_pulse(self, phase: float) -> None:
        self._pulse = 0.5 + 0.5 * math.sin(phase)
        self.redraw()

    def redraw(self) -> None:
        try:
            w = max(240, int(self.winfo_width()))
            h = max(64, int(self.winfo_height()))
        except tk.TclError:
            return
        self.delete("all")
        pad_x, pad_top, pad_bot = 12, 10, 12
        plot_w = max(40, w - pad_x * 2 - 22)
        plot_h = max(24, h - pad_top - pad_bot)

        # Horizontal grid rules
        for i in range(4):
            y = pad_top + plot_h * (i / 3.0)
            self.create_line(pad_x, y, pad_x + plot_w, y, fill="#1B203B", width=1)

        max_val = max(4, max(self._total_hist, default=0), max(self._prot_hist, default=0))
        n = len(self._total_hist)
        if n < 2:
            return

        def _pts(series: deque[int]) -> list[float]:
            coords: list[float] = []
            for idx, val in enumerate(series):
                x = pad_x + plot_w * (idx / max(1, n - 1))
                y = pad_top + plot_h * (1.0 - min(1.0, val / max_val))
                coords.extend((x, y))
            return coords

        tot_pts = _pts(self._total_hist)
        prot_pts = _pts(self._prot_hist)

        # Draw soft lavender total line and electric cyan protected line
        self.create_line(*tot_pts, fill=LAVENDER, width=2, smooth=True)
        self.create_line(*prot_pts, fill=ACCENT, width=2, smooth=True)

        # Right-side glowing level markers (matching Reference 2 right edge bars)
        bx = pad_x + plot_w + 10
        tot_y = tot_pts[-1]
        prot_y = prot_pts[-1]
        tot_glow = lerp_hex("#8B74E8", LAVENDER_HOVER, self._pulse)
        prot_glow = lerp_hex("#22B8CF", ACCENT, self._pulse)
        self.create_rectangle(bx, tot_y, bx + 5, pad_top + plot_h, fill=tot_glow, outline="")
        self.create_rectangle(bx + 7, prot_y, bx + 12, pad_top + plot_h, fill=prot_glow, outline="")
        self.create_oval(tot_pts[-2] - 3, tot_y - 3, tot_pts[-2] + 3, tot_y + 3, fill=tot_glow, outline="")
        self.create_oval(prot_pts[-2] - 3, prot_y - 3, prot_pts[-2] + 3, prot_y + 3, fill=prot_glow, outline="")


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
        self.title(f"ZAPRET // NETDOCTOR v{__version__}")
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
        self._vpn_policy: dict[str, Any] = {"mode": "auto", "priority_node": "", "priorities": {}}
        self._vpn_mode_syncing: bool = False
        self._preset_cb_syncing: bool = False
        self._stack_mode_syncing: bool = False
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
        self._last_update_info: dict[str, Any] = {}
        self._post_queue: queue.Queue[tuple[Callable[..., Any], tuple[Any, ...]]] = queue.Queue()
        self._active_bg_labels: set[str] = set()
        self._tray: NetdoctorTrayIcon | None = None
        self._icon_image: tk.PhotoImage | None = None
        self._guide_visible = True
        self._extra_visible = False
        self._tooltips: list[HoverTooltip] = []
        self._anim_jobs: dict[int, str] = {}
        self._pulse_job: str | None = None
        self._fade_job: str | None = None
        self._pulse_phase: float = 0.0
        self._initial_loaded: bool = False
        self._power_transition: str | None = None
        self._spinner_idx: int = 0

        self.minimize_to_tray_var = tk.BooleanVar(value=True)
        self.autostart_var = tk.BooleanVar(value=False)
        self.autostart_protection_var = tk.BooleanVar(value=False)
        self.byedpi_var = tk.BooleanVar(value=False)
        self.debug_log_var = tk.BooleanVar(value=False)
        self.dpi_only_var = tk.BooleanVar(value=False)
        self.tun_stack_var = tk.StringVar(value="gvisor")
        self._auto_start_stack = bool(auto_start_stack)
        self._minimized = bool(minimized)
        self._auto_start_enabled = bool(auto_start)

        if auto_start and not minimized:
            try:
                self.attributes("-alpha", 0.0)
            except tk.TclError:
                pass

        self._apply_window_chrome(enable_dark=auto_start and not minimized)
        self._build_style()
        self._build_statusbar()
        self._build_shell()
        self._progress_update()

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
            else:
                self._start_entrance_fade()
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
            self._pulse_job = self.after(70, self._pulse_tick)
            self._ensure_deps_on_startup()
            self.after(2500, self._check_updates_on_startup)
            delay_ms = 1500 if (minimized and auto_start_stack) else 350
            self.after(delay_ms, self._maybe_auto_start_protection)

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
        self._busy += 1
        try:
            self.set_status("Остановка служб и выход…", WARN_TEXT)
        except tk.TclError:
            pass

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

    def _start_entrance_fade(self) -> None:
        if self._closed or self._exiting:
            return
        steps = 6

        def _step(idx: int) -> None:
            if self._closed:
                return
            try:
                alpha = min(1.0, idx / steps)
                self.attributes("-alpha", alpha)
                if idx < steps:
                    self._fade_job = self.after(28, lambda: _step(idx + 1))
                else:
                    self._fade_job = None
            except tk.TclError:
                self._fade_job = None

        self._fade_job = self.after(15, lambda: _step(1))

    def on_close(self) -> None:
        self._closed = True
        if self._fade_job is not None:
            try:
                self.after_cancel(self._fade_job)
            except tk.TclError:
                pass
            self._fade_job = None
        if self._pulse_job is not None:
            try:
                self.after_cancel(self._pulse_job)
            except tk.TclError:
                pass
            self._pulse_job = None
        for job_id in list(self._anim_jobs.values()):
            try:
                self.after_cancel(job_id)
            except tk.TclError:
                pass
        self._anim_jobs.clear()
        for tip in list(self._tooltips):
            tip.hide()
        self._tooltips.clear()
        if HoverTooltip._pending is not None:
            HoverTooltip._pending._cancel_timers()
        if HoverTooltip._active is not None:
            HoverTooltip._active.hide()
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
        is_busy = self._busy > 0 or not self._initial_loaded or self._power_transition is not None
        if hasattr(self, "activity_bar"):
            self.activity_bar.set_active(is_busy)
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
            "primary": (PILL_ACTIVE_BG, "#FFFFFF", PRIMARY_HOVER, PILL_ACTIVE_BORDER, LAVENDER),
            "pill_active": (PILL_ACTIVE_BG, "#FFFFFF", "#3F3475", PILL_ACTIVE_BORDER, LAVENDER),
            "hero": (LAVENDER, LAVENDER_DARK, LAVENDER_HOVER, "#9F82F6", "#DDD0FE"),
            "hero_active": ("#A78BFA", LAVENDER_DARK, "#C4B5FD", CYAN_BORDER, ACCENT),
            "cyan_ghost": ("#10192E", ACCENT, "#162440", "#1E425E", ACCENT),
            "success": (OK_BTN, "#FFFFFF", OK_BTN_HOVER, "#0E7490", ACCENT),
            "danger": (ERR_BTN, ERR_TEXT, ERR_BTN_HOVER, "#7F2642", ERR),
            "warn": (WARN_BTN, "#FFFFFF", WARN_BTN_HOVER, "#B45309", WARN_TEXT),
        }
        return palettes.get(kind, palettes["neutral"])

    def attach_tooltip(self, widget: tk.Misc, text: str, title: str | None = None) -> HoverTooltip:
        tip = HoverTooltip(widget, text, title=title)
        self._tooltips.append(tip)
        return tip

    def make_info_icon(
        self,
        parent: tk.Misc,
        tooltip_text: str,
        title: str | None = None,
        bg: str = CARD,
    ) -> tk.Label:
        badge = tk.Label(
            parent,
            text="ⓘ",
            bg=bg,
            fg=MUTED,
            font=FONT_SMALL_B,
            cursor="question_arrow",
            padx=3,
        )
        badge.bind("<Enter>", lambda _e, b=badge: b.configure(fg=ACCENT), add="+")
        badge.bind("<Leave>", lambda _e, b=badge: b.configure(fg=MUTED), add="+")
        self.attach_tooltip(badge, tooltip_text, title=title)
        return badge

    def _animate_widget_bg(
        self,
        widget: tk.Widget,
        target_bg: str,
        target_border: str | None = None,
        steps: int = 3,
        interval_ms: int = 16,
    ) -> None:
        key = id(widget)
        prev = self._anim_jobs.pop(key, None)
        if prev is not None:
            try:
                self.after_cancel(prev)
            except tk.TclError:
                pass
        try:
            if self._closed or not widget.winfo_viewable():
                widget.configure(bg=target_bg)
                if target_border is not None:
                    widget.configure(highlightbackground=target_border)
                return
            start_bg = str(widget.cget("bg"))
            start_brd = str(widget.cget("highlightbackground")) if target_border is not None else ""
        except tk.TclError:
            return

        def _step(idx: int) -> None:
            if self._closed:
                return
            try:
                if not widget.winfo_exists():
                    self._anim_jobs.pop(key, None)
                    return
                frac = idx / max(1, steps)
                widget.configure(bg=lerp_hex(start_bg, target_bg, frac))
                if target_border is not None:
                    widget.configure(highlightbackground=lerp_hex(start_brd, target_border, frac))
                if idx < steps:
                    self._anim_jobs[key] = self.after(interval_ms, lambda: _step(idx + 1))
                else:
                    self._anim_jobs.pop(key, None)
            except tk.TclError:
                self._anim_jobs.pop(key, None)

        _step(1)

    def _pulse_tick(self) -> None:
        if self._closed or self._exiting:
            return
        self._pulse_phase = (self._pulse_phase + 0.16) % (2.0 * math.pi)
        self._spinner_idx = (self._spinner_idx + 1) % 8
        spin = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧")[self._spinner_idx]
        dots = "." * ((self._spinner_idx // 2) % 4)
        try:
            hidden = self._is_window_hidden()
            if not hidden:
                if hasattr(self, "activity_bar"):
                    self.activity_bar.set_active(
                        self._busy > 0 or self._refreshing or not self._initial_loaded or self._power_transition is not None
                    )
                    self.activity_bar.step()

                if not self._initial_loaded:
                    if hasattr(self, "hero_state_pill"):
                        self.hero_state_pill.configure(text=f"{spin} ЗАГРУЗКА{dots}", fg=ACCENT, bg=INFO_BG)
                    if hasattr(self, "network_label"):
                        self.network_label.configure(text=f"Сеть: определение{dots}")
                elif self._power_transition == "starting" and hasattr(self, "autopilot_btn"):
                    self.autopilot_btn.configure(text=f"{spin} ЗАПУСК ЗАЩИТЫ{dots}")
                elif self._power_transition == "stopping" and hasattr(self, "autopilot_btn"):
                    self.autopilot_btn.configure(text=f"{spin} ОСТАНОВКА{dots}")

                if self.last_snapshot.get("running"):
                    wave = 0.5 + 0.5 * math.sin(self._pulse_phase)
                    glow_col = lerp_hex("#1B8CA3", ACCENT, wave)
                    if hasattr(self, "hero_state_pill"):
                        self.hero_state_pill.configure(fg=glow_col)
                    if hasattr(self, "_home_zapret_card"):
                        self._home_zapret_card.configure(highlightbackground=lerp_hex("#1B5A70", CYAN_BORDER, wave))
                    for key, (canvas, oval, _lbl) in self.leds.items():
                        running = bool(((self.last_snapshot.get("processes") or {}).get(key) or {}).get("running"))
                        if running:
                            canvas.itemconfigure(oval, fill=glow_col)
                if self.radar_enabled and hasattr(self, "sparkline_canvas"):
                    self.sparkline_canvas.set_pulse(self._pulse_phase)
        except tk.TclError:
            pass
        if self._auto_start_enabled:
            self._pulse_job = self.after(70, self._pulse_tick)

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
        radius: int | None = None,
        tooltip: str | None = None,
    ) -> RoundedButton:
        pal = self._button_palette(kind)
        if radius is None:
            radius = 12 if kind in ("hero", "hero_active") else (11 if kind in ("pill_active", "primary") else 9)
        btn = RoundedButton(
            parent,
            text=text,
            command=command,
            palette=pal,
            width=width,
            font=font,
            padx=padx,
            pady=pady,
            radius=radius,
        )
        if tooltip:
            self.attach_tooltip(btn, tooltip)
        return btn

    def make_toggle_row(
        self,
        parent: tk.Misc,
        text: str,
        variable: tk.BooleanVar,
        command: Callable[[], Any] | None = None,
        *,
        bg: str = CARD,
        font: tuple[Any, ...] = FONT_SMALL,
        fg: str = FG_SOFT,
        tooltip: str | None = None,
        slider_width: int = 38,
        slider_height: int = 18,
    ) -> tk.Frame:
        """Create a soft slider-switch row replacing legacy square checkboxes."""
        row = tk.Frame(parent, bg=bg, cursor="hand2")
        lbl = tk.Label(row, text=text, bg=bg, fg=fg, font=font, anchor="w", justify="left", cursor="hand2")
        lbl.pack(side="left", fill="x", expand=True, padx=(0, 8))
        tog = AnimatedToggle(row, variable=variable, command=command, bg=bg, width=slider_width, height=slider_height)
        tog.pack(side="right")

        def _toggle_from_label(_e: Any = None) -> None:
            tog._on_click()

        lbl.bind("<Button-1>", _toggle_from_label)
        lbl.bind("<Enter>", lambda _e: lbl.configure(fg=FG), add="+")
        lbl.bind("<Leave>", lambda _e: lbl.configure(fg=fg), add="+")
        if tooltip:
            for w in (row, lbl, tog):
                self.attach_tooltip(w, tooltip)
        return row

    @classmethod
    def _restyle_button(cls, btn: Any, text: str, kind: str) -> None:
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
        sidebar = tk.Frame(parent, bg=SIDEBAR_BG, width=78)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        # Subtle vertical divider on the right edge of sidebar
        tk.Frame(parent, bg=BORDER, width=1).pack(side="left", fill="y")

        # Minimal top emblem
        brand = tk.Frame(sidebar, bg=SIDEBAR_BG)
        brand.pack(fill="x", pady=(12, 8))
        emblem = tk.Label(
            brand,
            text="◈",
            bg=SIDEBAR_BG,
            fg=ACCENT,
            font=("Segoe UI", 18, "bold"),
            anchor="center",
        )
        emblem.pack()
        self.attach_tooltip(emblem, f"ZAPRET // NETDOCTOR v{__version__}\nАдаптивный обход блокировок")

        tk.Frame(sidebar, bg=BORDER, height=1).pack(fill="x", padx=14, pady=(2, 8))

        self._nav_container = tk.Frame(sidebar, bg=SIDEBAR_BG)
        self._nav_container.pack(fill="x", padx=6)

        # Bottom compact service status LEDs
        stack_card = tk.Frame(sidebar, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
        stack_card.pack(side="bottom", fill="x", padx=8, pady=10)
        tk.Label(stack_card, text="МОДУЛИ", bg=CARD, fg=DIM, font=("Segoe UI", 7, "bold"), anchor="center").pack(
            fill="x", pady=(5, 2)
        )

        self.leds: dict[str, tuple[tk.Canvas, int, tk.Label]] = {}
        for key, title, tip_text in PROCESS_LEDS:
            row = tk.Frame(stack_card, bg=CARD)
            row.pack(fill="x", padx=8, pady=1)
            canvas = tk.Canvas(row, width=10, height=10, bg=CARD, highlightthickness=0)
            canvas.pack(side="left", padx=(0, 5), pady=2)
            oval = canvas.create_oval(1, 1, 9, 9, fill=ERR, outline="")
            lbl = tk.Label(row, text=title, bg=CARD, fg=MUTED, font=FONT_MICRO, anchor="w")
            lbl.pack(side="left", fill="x", expand=True)
            self.leds[key] = (canvas, oval, lbl)
            for w in (row, canvas, lbl):
                self.attach_tooltip(w, tip_text)
        tk.Frame(stack_card, bg=CARD, height=4).pack()

    def _build_header(self, parent: tk.Misc) -> None:
        banner = tk.Frame(parent, bg=HEADER_BG)
        banner.pack(fill="x")
        self.activity_bar = ActivityBar(parent, bg=BG)
        self.activity_bar.pack(fill="x")

        inner = tk.Frame(banner, bg=HEADER_BG)
        inner.pack(fill="x", padx=16, pady=8)

        # Right: Metadata readouts + conditional badges + single Refresh icon
        ctrl = tk.Frame(inner, bg=HEADER_BG)
        ctrl.pack(side="right", padx=(14, 0))

        refresh_btn = self.make_button(
            ctrl,
            "↻",
            self.refresh_async,
            kind="ghost",
            width=3,
            pady=5,
            tooltip="Обновить состояние сети и всех служб (F5)",
        )
        refresh_btn.pack(side="right", padx=(8, 0))

        meta_box = tk.Frame(ctrl, bg=HEADER_BG)
        meta_box.pack(side="right", padx=(8, 4))

        ver_col = tk.Frame(meta_box, bg=HEADER_BG)
        ver_col.pack(side="left", padx=(0, 12))
        tk.Label(ver_col, text="ВЕРСИЯ", bg=HEADER_BG, fg=DIM, font=("Segoe UI", 7, "bold"), anchor="e").pack(anchor="e")
        tk.Label(ver_col, text=f"v{__version__}", bg=HEADER_BG, fg=LAVENDER, font=FONT_SMALL_B, anchor="e").pack(anchor="e")

        priv_col = tk.Frame(meta_box, bg=HEADER_BG)
        priv_col.pack(side="left")
        tk.Label(priv_col, text="ДОСТУП", bg=HEADER_BG, fg=DIM, font=("Segoe UI", 7, "bold"), anchor="e").pack(anchor="e")
        self.priv_label = tk.Label(
            priv_col,
            text="Проверка…",
            bg=INPUT,
            fg=MUTED,
            font=FONT_MICRO,
            anchor="e",
            padx=6,
            pady=1,
        )
        self.priv_label.pack(anchor="e")
        self.attach_tooltip(
            self.priv_label,
            "Права администратора необходимы для запуска драйвера обхода блокировок и VPN-туннеля.",
        )

        self._priv_btn_slot = tk.Frame(ctrl, bg=HEADER_BG)
        self._priv_btn_slot.pack(side="right")
        self.priv_btn = self.make_button(
            self._priv_btn_slot,
            "Права Admin",
            self.on_elevate,
            "warn",
            font=FONT_SMALL_B,
            padx=10,
            pady=5,
            tooltip="Перезапустить программу с правами администратора (UAC) для полноценной работы защиты.",
        )
        self._pending_btn_slot = tk.Frame(ctrl, bg=HEADER_BG)
        self._pending_btn_slot.pack(side="right")
        self.apply_pending_btn = self.make_button(
            self._pending_btn_slot,
            "Применить изменения",
            self.on_force_apply_pending,
            "primary",
            font=FONT_SMALL_B,
            padx=10,
            pady=5,
            tooltip="Применить отложенные изменения правил прямо сейчас.",
        )
        self._update_btn_slot = tk.Frame(ctrl, bg=HEADER_BG)
        self._update_btn_slot.pack(side="right")
        self.update_badge_btn = self.make_button(
            self._update_btn_slot,
            "↑ Обновление",
            lambda: self._select_tab(self.tab_service),
            "primary",
            font=FONT_SMALL_B,
            padx=10,
            pady=5,
            tooltip="Доступна новая версия NetDoctor — нажмите чтобы перейти к обновлению.",
        )

        # Left: App Title + live status pill + network fingerprint
        left = tk.Frame(inner, bg=HEADER_BG)
        left.pack(side="left", fill="x", expand=True)

        brand_row = tk.Frame(left, bg=HEADER_BG)
        brand_row.pack(fill="x", anchor="w")
        tk.Label(brand_row, text="NETDOCTOR", bg=HEADER_BG, fg=LAVENDER, font=FONT_TITLE).pack(side="left")
        tk.Label(brand_row, text="  adaptive bypass", bg=HEADER_BG, fg=DIM, font=FONT_SMALL).pack(side="left", pady=(2, 0))

        status_row = tk.Frame(left, bg=HEADER_BG)
        status_row.pack(fill="x", anchor="w", pady=(3, 0))
        self.hero_state_pill = tk.Label(
            status_row,
            text="● ОСТАНОВЛЕНО",
            bg=INPUT,
            fg=MUTED,
            font=FONT_MICRO,
            padx=8,
            pady=2,
        )
        self.hero_state_pill.pack(side="left", padx=(0, 10))
        self.attach_tooltip(self.hero_state_pill, "Текущее состояние системы обхода блокировок и активный режим.")

        self.network_label = tk.Label(
            status_row, text="Сеть: определение…", bg=HEADER_BG, fg=MUTED, font=FONT_SMALL, anchor="w", justify="left"
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

    def _build_notebook(self, parent: tk.Misc) -> None:
        wrap = tk.Frame(parent, bg=BG)
        wrap.pack(fill="both", expand=True, padx=14, pady=(8, 8))

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
        self.notebook.add(self.tab_domains, text="Монитор и Сайты")
        self.notebook.add(self.tab_presets, text="Стратегии Zapret")
        self.notebook.add(self.tab_dns, text="DNS и Нейросети")
        self.notebook.add(self.tab_vpn, text="VPN и Журналы")
        self.notebook.add(self.tab_service, text="Настройки")

        nav_defs: tuple[tuple[ttk.Frame, str, str, str, str], ...] = (
            (self.tab_home, "⌂", "Главная", "", "Главная — включение защиты и основные переключатели"),
            (self.tab_domains, "📊", "Монитор", "0/0", "Монитор трафика и сайты — живые подключения и правила"),
            (self.tab_presets, "⚡", "Пресеты", "0", "Стратегии Zapret — готовые и свои пресеты обхода"),
            (self.tab_dns, "◉", "DNS", "36", "DNS и нейросети — быстрые защищённые DNS и доступ к ИИ"),
            (self.tab_vpn, "☁", "VPN", "0", "VPN и журналы — точечный туннель и логи работы служб"),
            (self.tab_service, "⚙", "Система", "", "Настройки и система — автозапуск, исключения и конфиги"),
        )
        for tab, icon, title, badge, tip_text in nav_defs:
            self._add_nav_item(tab, icon, title, badge, tooltip=tip_text)

        self.notebook.bind("<<NotebookTabChanged>>", lambda _e: self._sync_sidebar_selection())

        self._build_home_tab()
        self._build_domains_tab()
        self._build_presets_tab()
        self._build_dns_tab()
        self._build_vpn_tab()
        self._build_service_tab()
        self._sync_sidebar_selection()

    def _add_nav_item(
        self,
        tab: ttk.Frame,
        icon: str,
        title: str,
        badge_text: str,
        *,
        tooltip: str = "",
    ) -> None:
        tab_key = str(tab)
        row = tk.Frame(self._nav_container, bg=SIDEBAR_BG, cursor="hand2")
        row.pack(fill="x", pady=4)

        indicator = tk.Frame(row, bg=SIDEBAR_BG, width=3)
        indicator.pack(side="left", fill="y", padx=(0, 3))

        box = tk.Frame(row, bg=SIDEBAR_BG)
        box.pack(side="left", fill="both", expand=True, padx=(0, 4))

        icon_lbl = tk.Label(box, text=icon, bg=SIDEBAR_BG, fg=MUTED, font=("Segoe UI", 14, "bold"), anchor="center", pady=4)
        icon_lbl.pack(fill="x")

        # Keep text_lbl hidden from rail to keep compact icon-rail look while preserving 5-tuple contract
        text_lbl = tk.Label(row, text=title, bg=SIDEBAR_BG, fg=FG_SOFT, font=FONT_MICRO)

        badge_lbl = tk.Label(
            box,
            text=badge_text,
            bg=INPUT if badge_text else SIDEBAR_BG,
            fg=MUTED,
            font=("Segoe UI", 7, "bold"),
            padx=5 if badge_text else 0,
            pady=0,
        )
        if badge_text:
            badge_lbl.pack(pady=(0, 3))

        self._nav_items[tab_key] = (row, indicator, icon_lbl, text_lbl, badge_lbl)

        for w in (row, indicator, box, icon_lbl, text_lbl, badge_lbl):
            w.bind("<Button-1>", lambda _e, t=tab: self._select_tab(t))
            w.bind("<Enter>", lambda _e, k=tab_key: self._hover_nav_item(k, True))
            w.bind("<Leave>", lambda _e, k=tab_key: self._hover_nav_item(k, False))
            if tooltip:
                self.attach_tooltip(w, tooltip)

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
            icon_lbl.master.configure(bg=bg)
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
            bg = PILL_ACTIVE_BG if active else SIDEBAR_BG
            try:
                row.configure(bg=bg)
                indicator.configure(bg=ACCENT if active else bg)
                icon_lbl.master.configure(bg=bg)
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
            badge_lbl.configure(text=text, padx=5 if text else 0)
            if text and not badge_lbl.winfo_manager():
                badge_lbl.pack(pady=(0, 3))
            elif not text and badge_lbl.winfo_manager():
                badge_lbl.pack_forget()
            self._sync_sidebar_selection()
        except tk.TclError:
            pass

    # ---------------------------------------------------------------- Tab 1: Главная (Dashboard)

    def _build_home_tab(self) -> None:
        tab = self.tab_home

        # Main reference-inspired dark container
        surface = tk.Frame(tab, bg=SIDEBAR_BG, highlightthickness=1, highlightbackground=BORDER)
        surface.pack(fill="both", expand=True)

        hero = tk.Frame(surface, bg=SIDEBAR_BG)
        hero.pack(fill="x", padx=18, pady=(5, 3))
        tk.Label(
            hero,
            text="СПОСОБ ПОДКЛЮЧЕНИЯ",
            bg=SIDEBAR_BG,
            fg=ACCENT,
            font=("Segoe UI", 14, "bold"),
            anchor="center",
        ).pack(fill="x")
        self.hint_label = tk.Label(
            hero,
            text="Выберите режим обхода и включите защиту одним нажатием",
            bg=SIDEBAR_BG,
            fg=MUTED,
            font=FONT_SMALL,
            anchor="center",
            justify="center",
        )
        self.hint_label.pack(fill="x", pady=(1, 0))
        self._bind_responsive_wrap(self.hint_label, min_wrap=280, pad=36)

        # Compact, dismissible 1-row quick-start bar
        self._home_guide_frame = RoundedCard(
            surface, bg=INFO_BG, outer_bg=SIDEBAR_BG, border="#1E425E", radius=11, pad=2
        )
        self._home_guide_frame.pack(fill="x", padx=16, pady=(0, 3))
        guide_body = self._home_guide_frame.body
        hide_lbl = tk.Label(
            guide_body,
            text="Скрыть ✕",
            bg=INFO_BG,
            fg=ACCENT,
            font=FONT_SMALL_B,
            cursor="hand2",
            padx=10,
            pady=1,
        )
        hide_lbl.pack(side="right")
        hide_lbl.bind("<Button-1>", lambda _e: self._toggle_home_guide())
        guide_lbl = tk.Label(
            guide_body,
            text="1. Выберите стратегию (или Автоподбор)  →  2. Нажмите «ВКЛЮЧИТЬ ЗАЩИТУ»  →  3. Проверьте доступность сервисов",
            bg=INFO_BG,
            fg=FG_SOFT,
            font=FONT_SMALL,
            anchor="w",
            justify="left",
        )
        guide_lbl.pack(side="left", fill="x", expand=True, padx=(10, 4), pady=1)
        self._bind_responsive_wrap(guide_lbl, min_wrap=260, pad=24)

        # Conditional DoH / DNS alert banner (shown only when active DNS fails TLS)
        self._home_alert_frame = RoundedCard(
            surface, bg=WARN_BG, outer_bg=SIDEBAR_BG, border=WARN, radius=11, pad=2
        )
        alert_body = self._home_alert_frame.body
        alert_btns = tk.Frame(alert_body, bg=WARN_BG)
        alert_btns.pack(side="right", padx=8, pady=2)
        self.make_button(
            alert_btns,
            "Включить рабочий DNS",
            lambda: self.on_select_dns("comss_dns"),
            "warn",
            font=FONT_MICRO,
            padx=8,
            pady=1,
            tooltip="Переключиться на рабочий защищённый DNS Comss без ошибки сертификата.",
        ).pack(side="right")
        self._home_alert_lbl = tk.Label(
            alert_body,
            text="",
            bg=WARN_BG,
            fg=WARN_TEXT,
            font=FONT_SMALL,
            anchor="w",
            justify="left",
        )
        self._home_alert_lbl.pack(side="left", fill="x", expand=True, padx=(10, 4), pady=2)
        self._bind_responsive_wrap(self._home_alert_lbl, min_wrap=220, pad=24)

        # Two equal primary connection cards (anchored via _home_section1_lbl for alert insertion)
        hero_grid = tk.Frame(surface, bg=SIDEBAR_BG)
        self._home_section1_lbl = hero_grid
        hero_grid.pack(fill="x", padx=16, pady=(2, 4))
        hero_grid.columnconfigure(0, weight=1, uniform="hero_cards")
        hero_grid.columnconfigure(1, weight=1, uniform="hero_cards")

        # ---- Left Card: ZAPRET (Primary Protection Toggle & Strategy) ----
        left_card_wrap = RoundedCard(hero_grid, bg=CARD, outer_bg=SIDEBAR_BG, border=BORDER, radius=16, pad=3)
        left_card_wrap.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        self._home_zapret_card = left_card_wrap
        left_card = left_card_wrap.body

        lc_head = tk.Frame(left_card, bg=CARD)
        lc_head.pack(fill="x", padx=14, pady=(5, 1))
        tk.Label(lc_head, text="⚡", bg=CARD, fg=ACCENT, font=("Segoe UI", 12, "bold")).pack(side="left", padx=(0, 6))
        tk.Label(lc_head, text="ZAPRET", bg=CARD, fg=FG, font=FONT_H2).pack(side="left")
        self.make_info_icon(
            lc_head,
            "Ускоряет YouTube, Discord и сайты на полной скорости интернета без изменения вашего IP-адреса.",
            title="Обход блокировок (DPI)",
            bg=CARD,
        ).pack(side="left", padx=(4, 0))
        self.home_preset_mode_pill = tk.Label(
            lc_head,
            text="● Автоподбор",
            bg=INFO_BG,
            fg=ACCENT,
            font=FONT_MICRO,
            padx=7,
            pady=1,
        )
        self.home_preset_mode_pill.pack(side="right")

        lc_sub = tk.Frame(left_card, bg=CARD)
        lc_sub.pack(fill="x", padx=14, pady=(0, 3))
        self._home_zapret_pill = tk.Label(
            lc_sub,
            text="● ОТКЛЮЧЕНО",
            bg=INPUT,
            fg=MUTED,
            font=FONT_MICRO,
            padx=7,
            pady=1,
        )
        self._home_zapret_pill.pack(side="left")
        tk.Label(lc_sub, text="  Обход блокировок сайтов", bg=CARD, fg=DIM, font=FONT_MICRO).pack(side="left")

        tk.Label(left_card, text="СТРАТЕГИЯ ОБХОДА", bg=CARD, fg=MUTED, font=FONT_MICRO, anchor="w").pack(
            fill="x", padx=14, pady=(1, 2)
        )
        self.home_preset_var = tk.StringVar(value="Авто-оркестратор (подбор по доменам)")
        self.home_preset_cb = ttk.Combobox(
            left_card,
            textvariable=self.home_preset_var,
            state="readonly",
            values=["Авто-оркестратор (подбор по доменам)"],
        )
        self.home_preset_cb.pack(fill="x", padx=14, pady=(0, 5))
        self.home_preset_cb.bind("<<ComboboxSelected>>", self._on_home_preset_selected)
        self.attach_tooltip(
            self.home_preset_cb,
            "Выберите автоматический подбор для каждого сайта или готовую стратегию — режим применится сразу.",
        )

        self.autopilot_btn = self.make_button(
            left_card,
            "ВКЛЮЧИТЬ ЗАЩИТУ  ⏻",
            self.on_toggle_autopilot,
            "hero",
            font=("Segoe UI", 11, "bold"),
            padx=14,
            pady=5,
            radius=13,
            tooltip="Запускает или полностью останавливает систему обхода блокировок.",
        )
        self.autopilot_btn.pack(fill="x", padx=14, pady=(0, 4))

        self.make_button(
            left_card,
            "ПРОВЕРИТЬ ДОСТУПНОСТЬ  ↗",
            lambda: self.on_run_connectivity_tests(include_picked=False),
            "cyan_ghost",
            font=FONT_SMALL_B,
            padx=10,
            pady=3,
            radius=10,
            tooltip="Быстрая проверка открытия YouTube, Discord и Telegram прямо сейчас.",
        ).pack(fill="x", padx=14, pady=(0, 4))

        pills_wrap = tk.Frame(left_card, bg=CARD)
        pills_wrap.pack(fill="x", padx=14, pady=(0, 5))
        self._home_service_pills: dict[str, tk.Label] = {}
        for sg_key, sg_title in (("youtube", "YouTube"), ("discord", "Discord"), ("telegram", "Telegram")):
            lbl = tk.Label(
                pills_wrap,
                text=f"● {sg_title}: —",
                bg=INPUT,
                fg=MUTED,
                font=FONT_MICRO,
                padx=6,
                pady=1,
            )
            lbl.pack(side="left", padx=(0, 4))
            self._home_service_pills[sg_key] = lbl
        self.home_test_rate_pill = tk.Label(
            pills_wrap,
            text="Успех: —",
            bg=INFO_BG,
            fg=ACCENT,
            font=FONT_MICRO,
            padx=6,
            pady=1,
        )
        self.home_test_rate_pill.pack(side="right")

        # ---- Right Card: VPN & Telegram Routing ----
        right_card_wrap = RoundedCard(hero_grid, bg=CARD, outer_bg=SIDEBAR_BG, border=BORDER, radius=16, pad=3)
        right_card_wrap.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        self._home_vpn_card = right_card_wrap
        right_card = right_card_wrap.body

        rc_head = tk.Frame(right_card, bg=CARD)
        rc_head.pack(fill="x", padx=14, pady=(5, 1))
        tk.Label(rc_head, text="☁", bg=CARD, fg="#FB923C", font=("Segoe UI", 12, "bold")).pack(side="left", padx=(0, 6))
        tk.Label(rc_head, text="VPN И TELEGRAM", bg=CARD, fg=FG, font=FONT_H2).pack(side="left")
        self.make_info_icon(
            rc_head,
            "Точечный VPN подключается только к сайтам, заблокированным по IP. Встроенный прокси ускоряет Telegram.",
            title="Дополнительное подключение",
            bg=CARD,
        ).pack(side="left", padx=(4, 0))
        self._home_vpn_state_pill = tk.Label(
            rc_head,
            text="● РЕЗЕРВ",
            bg=INPUT,
            fg=MUTED,
            font=FONT_MICRO,
            padx=7,
            pady=1,
        )
        self._home_vpn_state_pill.pack(side="right")

        rc_sub = tk.Frame(right_card, bg=CARD)
        rc_sub.pack(fill="x", padx=14, pady=(0, 3))
        tk.Label(rc_sub, text="Гибридная маршрутизация и MTProto-прокси", bg=CARD, fg=DIM, font=FONT_MICRO).pack(side="left")

        tk.Label(right_card, text="РЕЖИМ МАРШРУТИЗАЦИИ", bg=CARD, fg=MUTED, font=FONT_MICRO, anchor="w").pack(
            fill="x", padx=14, pady=(1, 2)
        )
        self._stack_mode_labels = (
            "Гибридный (Обход DPI + точечный VPN)",
            "Только обход DPI (без VPN-туннеля)",
        )
        self.home_stack_mode_var = tk.StringVar(value=self._stack_mode_labels[0])
        self.home_stack_mode_cb = ttk.Combobox(
            right_card,
            textvariable=self.home_stack_mode_var,
            state="readonly",
            values=self._stack_mode_labels,
        )
        self.home_stack_mode_cb.pack(fill="x", padx=14, pady=(0, 5))
        self.home_stack_mode_cb.bind("<<ComboboxSelected>>", self._on_home_stack_mode_selected)
        self.attach_tooltip(
            self.home_stack_mode_cb,
            "Гибридный режим включает точечный VPN только для заблокированных по IP сайтов. Без VPN работает только Zapret + Telegram.",
        )

        # Split 2-cell quick control strip (Reference 1 style)
        split_box_wrap = RoundedCard(right_card, bg=INPUT, outer_bg=CARD, border=BORDER, radius=11, pad=2)
        split_box_wrap.pack(fill="x", padx=14, pady=(0, 5))
        split_box = split_box_wrap.body
        split_box.columnconfigure(0, weight=1, uniform="rc_split")
        split_box.columnconfigure(1, weight=0)
        split_box.columnconfigure(2, weight=1, uniform="rc_split")

        cell_l = tk.Frame(split_box, bg=INPUT)
        cell_l.grid(row=0, column=0, sticky="nsew", padx=8, pady=3)
        bd_lbl = tk.Label(cell_l, text="Резерв ByeDPI", bg=INPUT, fg=FG_SOFT, font=FONT_SMALL_B)
        bd_lbl.pack(side="left")
        self.make_info_icon(
            cell_l,
            "Запускает дополнительный локальный SOCKS5-прокси ByeDPI (ciadpi.exe) как запасной путь.",
            bg=INPUT,
        ).pack(side="left", padx=(2, 4))
        self._home_byedpi_toggle = AnimatedToggle(cell_l, variable=self.byedpi_var, command=self.on_toggle_byedpi, bg=INPUT)
        self._home_byedpi_toggle.pack(side="right")
        self.attach_tooltip(self._home_byedpi_toggle, "Включить или выключить резервный SOCKS5-прокси ByeDPI.")

        tk.Frame(split_box, bg=BORDER, width=1).grid(row=0, column=1, sticky="ns", pady=3)

        cell_r = tk.Frame(split_box, bg=INPUT)
        cell_r.grid(row=0, column=2, sticky="nsew", padx=8, pady=2)
        self.tg_proxy_btn = self.make_button(
            cell_r,
            "✈ Прокси Telegram",
            self.on_connect_telegram_proxy,
            "ghost",
            font=FONT_SMALL_B,
            padx=8,
            pady=2,
            radius=9,
            tooltip="В один клик подключает Telegram Desktop к локальному MTProto-прокси и копирует ссылку.",
        )
        self.tg_proxy_btn.pack(fill="x", expand=True)

        # Live VPN / TG readout inside card
        vpn_info_wrap = RoundedCard(right_card, bg=CARD_ALT, outer_bg=CARD, border=BORDER, radius=11, pad=2)
        vpn_info_wrap.pack(fill="x", padx=14, pady=(0, 5))
        vpn_info = vpn_info_wrap.body
        self.card_vpn_val = tk.Label(vpn_info, text="ГОТОВ • загрузка узлов…", bg=CARD_ALT, fg=FG, font=FONT_SMALL_B, anchor="w")
        self.card_vpn_val.pack(fill="x", padx=10, pady=(3, 1))
        self._bind_responsive_wrap(self.card_vpn_val, min_wrap=180, pad=20)
        self.card_vpn_sub = tk.Label(vpn_info, text="—", bg=CARD_ALT, fg=MUTED, font=FONT_MICRO, anchor="w")
        self.card_vpn_sub.pack(fill="x", padx=10, pady=(0, 3))
        self._bind_responsive_wrap(self.card_vpn_sub, min_wrap=180, pad=20)

        # ---- Bottom Row: Summary Tiles (DNS / Rules) & Game Filter Switch ----
        bot_grid = tk.Frame(surface, bg=SIDEBAR_BG)
        bot_grid.pack(fill="x", padx=16, pady=(0, 4))
        bot_grid.columnconfigure(0, weight=1, uniform="home_bot")
        bot_grid.columnconfigure(1, weight=1, uniform="home_bot")

        # Left bottom card: DNS & Rules status tiles (click to jump)
        rules_card_wrap = RoundedCard(bot_grid, bg=CARD, outer_bg=SIDEBAR_BG, border=BORDER, radius=15, pad=3)
        rules_card_wrap.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        rules_card = rules_card_wrap.body
        rc_top = tk.Frame(rules_card, bg=CARD)
        rc_top.pack(fill="x", padx=12, pady=(4, 2))
        tk.Label(rc_top, text="DNS И БАЗА САЙТОВ", bg=CARD, fg=MUTED, font=FONT_MICRO, anchor="w").pack(side="left")
        self.make_info_icon(
            rc_top,
            "Быстрая сводка по активному DNS-серверу и количеству сайтов с подобранными правилами. Нажмите плитку для перехода.",
            bg=CARD,
        ).pack(side="left", padx=(4, 0))

        tiles_row = tk.Frame(rules_card, bg=CARD)
        tiles_row.pack(fill="x", padx=12, pady=(0, 4))
        tiles_row.columnconfigure(0, weight=1, uniform="home_tiles")
        tiles_row.columnconfigure(1, weight=1, uniform="home_tiles")

        dns_tile_wrap = RoundedCard(tiles_row, bg=CARD_ALT, outer_bg=CARD, border=BORDER, radius=11, pad=2)
        dns_tile_wrap.configure(cursor="hand2")
        dns_tile_wrap.grid(row=0, column=0, sticky="nsew", padx=(0, 4))
        dns_tile = dns_tile_wrap.body
        dns_tile.configure(cursor="hand2")
        dns_hdr = tk.Label(dns_tile, text="◉ Активный DNS", bg=CARD_ALT, fg=LAVENDER, font=FONT_MICRO, anchor="w")
        dns_hdr.pack(fill="x", padx=8, pady=(3, 1))
        self.card_dns_val = tk.Label(dns_tile, text="—", bg=CARD_ALT, fg=FG, font=FONT_SMALL_B, anchor="w")
        self.card_dns_val.pack(fill="x", padx=8)
        self._bind_responsive_wrap(self.card_dns_val, min_wrap=120, pad=16)
        self.card_dns_sub = tk.Label(dns_tile, text="—", bg=CARD_ALT, fg=MUTED, font=FONT_MICRO, anchor="w")
        self.card_dns_sub.pack(fill="x", padx=8, pady=(0, 3))
        self._bind_responsive_wrap(self.card_dns_sub, min_wrap=120, pad=16)
        self._bind_card_hover(
            dns_tile_wrap, [dns_tile, dns_hdr, self.card_dns_val, self.card_dns_sub], CARD_ALT, INPUT_HOVER, BORDER, LAVENDER
        )
        for w in (dns_tile_wrap, dns_tile, dns_hdr, self.card_dns_val, self.card_dns_sub):
            w.bind("<Button-1>", lambda _e: self._select_tab(self.tab_dns))
            self.attach_tooltip(w, "Нажмите, чтобы выбрать другой защищённый DNS или настроить DNS для нейросетей.")

        dpi_tile_wrap = RoundedCard(tiles_row, bg=CARD_ALT, outer_bg=CARD, border=BORDER, radius=11, pad=2)
        dpi_tile_wrap.configure(cursor="hand2")
        dpi_tile_wrap.grid(row=0, column=1, sticky="nsew", padx=(4, 0))
        dpi_tile = dpi_tile_wrap.body
        dpi_tile.configure(cursor="hand2")
        dpi_hdr = tk.Label(dpi_tile, text="◈ Правила сайтов", bg=CARD_ALT, fg=ACCENT, font=FONT_MICRO, anchor="w")
        dpi_hdr.pack(fill="x", padx=8, pady=(3, 1))
        self.card_dpi_val = tk.Label(dpi_tile, text="—", bg=CARD_ALT, fg=FG, font=FONT_SMALL_B, anchor="w")
        self.card_dpi_val.pack(fill="x", padx=8)
        self._bind_responsive_wrap(self.card_dpi_val, min_wrap=120, pad=16)
        self.card_dpi_sub = tk.Label(dpi_tile, text="—", bg=CARD_ALT, fg=MUTED, font=FONT_MICRO, anchor="w")
        self.card_dpi_sub.pack(fill="x", padx=8, pady=(0, 3))
        self._bind_responsive_wrap(self.card_dpi_sub, min_wrap=120, pad=16)
        self._bind_card_hover(
            dpi_tile_wrap, [dpi_tile, dpi_hdr, self.card_dpi_val, self.card_dpi_sub], CARD_ALT, INPUT_HOVER, BORDER, ACCENT
        )
        for w in (dpi_tile_wrap, dpi_tile, dpi_hdr, self.card_dpi_val, self.card_dpi_sub):
            w.bind("<Button-1>", lambda _e: self._select_tab(self.tab_domains))
            self.attach_tooltip(w, "Нажмите, чтобы открыть список сайтов, правила обхода и живой монитор подключений.")

        # Right bottom card: Game Filter toggle (Reference 1 style)
        game_card_wrap = RoundedCard(bot_grid, bg=CARD, outer_bg=SIDEBAR_BG, border=BORDER, radius=15, pad=3)
        game_card_wrap.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        game_card = game_card_wrap.body
        gc_top = tk.Frame(game_card, bg=CARD)
        gc_top.pack(fill="x", padx=12, pady=(4, 2))
        tk.Label(gc_top, text="ИГРОВОЙ ФИЛЬТР", bg=CARD, fg=MUTED, font=FONT_MICRO, anchor="w").pack(side="left")
        self.make_info_icon(
            gc_top,
            "Расширяет обход блокировок на высокие порты (1024–65535) для работы голосовых каналов Discord и онлайн-игр.",
            title="Голосовой трафик и игры",
            bg=CARD,
        ).pack(side="left", padx=(4, 0))
        self.game_filter_var = tk.BooleanVar(value=False)
        self._game_filter_toggle = AnimatedToggle(
            gc_top, variable=self.game_filter_var, command=self.on_toggle_game_filter, bg=CARD
        )
        self._game_filter_toggle.pack(side="right")
        self.attach_tooltip(self._game_filter_toggle, "Включить обход голосовых каналов Discord и онлайн-игр.")

        chips_row = tk.Frame(game_card, bg=CARD)
        chips_row.pack(fill="x", padx=12, pady=(0, 4))
        chips_row.columnconfigure(0, weight=1, uniform="gf_chips")
        chips_row.columnconfigure(1, weight=1, uniform="gf_chips")
        self._gf_chip1 = tk.Label(
            chips_row,
            text="🎙 Голосовые каналы",
            bg=CARD_ALT,
            fg=MUTED,
            font=FONT_SMALL,
            pady=4,
            highlightthickness=1,
            highlightbackground=BORDER,
        )
        self._gf_chip1.grid(row=0, column=0, sticky="nsew", padx=(0, 4))
        self._gf_chip2 = tk.Label(
            chips_row,
            text="🎮 Игровой UDP / TCP",
            bg=CARD_ALT,
            fg=MUTED,
            font=FONT_SMALL,
            pady=4,
            highlightthickness=1,
            highlightbackground=BORDER,
        )
        self._gf_chip2.grid(row=0, column=1, sticky="nsew", padx=(4, 0))
        self.game_filter_var.trace_add("write", lambda *_: self._sync_game_filter_chips())

        # ---- Bottom Collapsible Strip (preserves tools_card == unlocker_status_label.master.master) ----
        tools_card_wrap = RoundedCard(surface, bg=CARD, outer_bg=SIDEBAR_BG, border=BORDER, radius=14, pad=2)
        tools_card_wrap.pack(fill="x", padx=16, pady=(0, 5))
        tools_card = tools_card_wrap.body

        guard_strip = tk.Frame(tools_card, bg=CARD)
        guard_strip.pack(fill="x", padx=12, pady=3)
        self._extra_toggle_lbl = tk.Label(
            guard_strip,
            text="Детали трафика ⌄",
            bg=CARD,
            fg=LAVENDER,
            font=FONT_SMALL_B,
            cursor="hand2",
            padx=6,
        )
        self._extra_toggle_lbl.pack(side="right", padx=(8, 0))
        self._extra_toggle_lbl.bind("<Button-1>", lambda _e: self._toggle_home_extra())
        self.attach_tooltip(self._extra_toggle_lbl, "Показать или скрыть сводку активных подключений ПК.")

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

        self._home_extra_frame = tk.Frame(tools_card, bg=CARD_ALT)
        self.card_rt_val = tk.Label(self._home_extra_frame, text="—", bg=CARD_ALT, fg=FG_SOFT, font=FONT_SMALL_B, anchor="w")
        self.card_rt_val.pack(side="left", padx=(12, 8), pady=4)
        self.card_rt_sub = tk.Label(self._home_extra_frame, text="—", bg=CARD_ALT, fg=MUTED, font=FONT_SMALL, anchor="w")
        self.card_rt_sub.pack(side="left", fill="x", expand=True, padx=(0, 12), pady=4)

    def _toggle_home_guide(self) -> None:
        if self._guide_visible:
            self._home_guide_frame.pack_forget()
            self._guide_visible = False

    def _toggle_home_extra(self) -> None:
        if self._extra_visible:
            self._home_extra_frame.pack_forget()
            self._extra_visible = False
            self._extra_toggle_lbl.configure(text="Детали трафика ⌄")
        else:
            self._home_extra_frame.pack(fill="x")
            self._extra_visible = True
            self._extra_toggle_lbl.configure(text="Скрыть детали ⌃")

    def _sync_game_filter_chips(self) -> None:
        if not hasattr(self, "_gf_chip1"):
            return
        active = bool(self.game_filter_var.get())
        bg = PILL_ACTIVE_BG if active else CARD_ALT
        fg = FG if active else MUTED
        brd = PILL_ACTIVE_BORDER if active else BORDER
        for chip in (self._gf_chip1, self._gf_chip2):
            chip.configure(bg=bg, fg=fg, highlightbackground=brd)

    def _on_home_preset_selected(self, _event: Any = None) -> None:
        if self._preset_cb_syncing:
            return
        self.on_apply_home_preset()

    def _on_home_stack_mode_selected(self, _event: Any = None) -> None:
        if self._stack_mode_syncing:
            return
        want_dpi_only = self.home_stack_mode_var.get() == self._stack_mode_labels[1]
        if bool(self.dpi_only_var.get()) != want_dpi_only:
            self.dpi_only_var.set(want_dpi_only)
            self.on_toggle_dpi_only()

    # ---------------------------------------------------------------- Tab 2: Монитор трафика и сайты (Unified)

    def _build_domains_tab(self) -> None:
        tab = self.tab_domains
        hdr = tk.Frame(tab, bg=BG)
        hdr.pack(fill="x", pady=(2, 6))

        self.radar_btn = self.make_button(
            hdr,
            "⏹ Остановить мониторинг",
            self.on_toggle_radar,
            "danger",
            font=FONT_SMALL_B,
            padx=10,
            pady=4,
            tooltip="Включает или приостанавливает сканирование активных подключений ПК в реальном времени.",
        )
        self.radar_btn.pack(side="right", padx=(8, 0))

        title_col = tk.Frame(hdr, bg=BG)
        title_col.pack(side="left", fill="x", expand=True)
        t_row = tk.Frame(title_col, bg=BG)
        t_row.pack(fill="x")
        tk.Label(t_row, text="МОНИТОР ТРАФИКА И САЙТЫ", bg=BG, fg=FG, font=FONT_HERO, anchor="w").pack(side="left")
        tk.Label(
            t_row,
            text="  LIVE  ",
            bg=PILL_ACTIVE_BG,
            fg=LAVENDER,
            font=FONT_MICRO,
            padx=6,
            pady=2,
        ).pack(side="left", padx=(8, 0))
        sub_lbl = tk.Label(
            title_col,
            text="Живая активность подключений, правила обхода для отдельных сайтов и проверка доступности.",
            bg=BG,
            fg=MUTED,
            font=FONT_SMALL,
            anchor="w",
            justify="left",
        )
        sub_lbl.pack(fill="x", anchor="w", pady=(2, 0))
        self._bind_responsive_wrap(sub_lbl, min_wrap=260, pad=16)

        # Unified view switcher + overall success summary + full-list test
        switch_bar = tk.Frame(tab, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
        switch_bar.pack(fill="x", pady=(0, 6))

        sw_row = tk.Frame(switch_bar, bg=CARD)
        sw_row.pack(fill="x", padx=12, pady=6)

        self.make_button(
            sw_row,
            "▶ Проверить все сайты",
            lambda: self.on_run_connectivity_tests(include_picked=True),
            "cyan_ghost",
            font=FONT_SMALL_B,
            padx=10,
            pady=4,
            tooltip="Проверяет доступность всех сайтов из таблицы ниже (быстрый тест YT/DC/TG находится на Главной).",
        ).pack(side="right", padx=(6, 0))

        self._subtab_domains_btn = self.make_button(
            sw_row,
            "Правила для сайтов (0)",
            lambda: self._switch_domains_subview("domains"),
            "pill_active",
            font=FONT_SMALL_B,
            padx=10,
            pady=4,
            tooltip="Список сайтов с индивидуальными правилами обхода и инспектором проверок.",
        )
        self._subtab_domains_btn.pack(side="left", padx=(0, 4))

        self._subtab_conns_btn = self.make_button(
            sw_row,
            "Активные подключения (0)",
            lambda: self._switch_domains_subview("connections"),
            "neutral",
            font=FONT_SMALL_B,
            padx=10,
            pady=4,
            tooltip="График активности и текущие сетевые подключения программ на компьютере.",
        )
        self._subtab_conns_btn.pack(side="left", padx=(0, 10))

        self._domains_test_summary_lbl = tk.Label(
            sw_row,
            text="Успех проверок: —  •  Сайтов: 0  •  Подключений: 0",
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
                "pill_active" if lid == "ALL" else "neutral",
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
            filt_top,
            "✕",
            lambda: self.search_var.set(""),
            "ghost",
            font=FONT_SMALL,
            padx=6,
            pady=2,
            tooltip="Очистить строку поиска",
        ).pack(side="left", padx=(4, 0))

        tk.Frame(toolbar, bg=BORDER_LIGHT, height=1).pack(fill="x", padx=12)

        filt_bot = tk.Frame(toolbar, bg=CARD)
        filt_bot.pack(fill="x", padx=12, pady=(5, 7))
        self.make_button(
            filt_bot,
            "Проверить популярные сайты",
            self.on_diag_all,
            "neutral",
            font=FONT_SMALL_B,
            padx=10,
            pady=3,
            tooltip="Запускает полную диагностику и подбор обхода для базового списка популярных сервисов.",
        ).pack(side="right", padx=(8, 0))
        tk.Label(filt_bot, text="Добавить сайт:", bg=CARD, fg=ACCENT, font=FONT_SMALL_B).pack(side="left", padx=(0, 6))
        self.new_domain_var = tk.StringVar()
        entry = self.make_entry(filt_bot, self.new_domain_var, 22)
        entry.pack(side="left", fill="x", expand=True, ipady=3)
        entry.bind("<Return>", lambda _e: self.on_check_new_domain())
        self.attach_tooltip(entry, "Введите адрес сайта (например chatgpt.com или youtube.com) и нажмите Enter.")
        self.make_button(
            filt_bot,
            "Подобрать обход",
            self.on_check_new_domain,
            "primary",
            font=FONT_SMALL_B,
            padx=10,
            pady=3,
            tooltip="Проверит, почему сайт не открывается, и автоматически подберёт рабочий способ обхода.",
        ).pack(side="left", padx=(8, 0))

        paned = ttk.PanedWindow(self._domains_subview, orient="vertical")
        paned.pack(fill="both", expand=True)

        tree_wrap = tk.Frame(paned, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
        cols = tuple(c[0] for c in DOMAIN_COLUMNS)
        self.domain_tree = self.make_tree(tree_wrap, cols, height=8)
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
        paned.add(tree_wrap, weight=5)

        paned.add(self._build_inspector(paned), weight=4)

        self._domain_menu = tk.Menu(self, tearoff=0, bg=CARD_ALT, fg=FG, activebackground=SELECT_BG, activeforeground="#FFFFFF")
        self._domain_menu.add_command(label="▶ Проверить доступность сейчас", command=self.on_test_selected_domain)
        self._domain_menu.add_command(label="📌 Зафиксировать / Снять фиксацию", command=self.on_toggle_pin_selected)
        self._domain_menu.add_separator()
        self._domain_menu.add_command(label="Подобрать обход DPI", command=self.on_recheck_selected)
        self._domain_menu.add_command(label="Подобрать персональный DNS", command=self.on_roll_dns_selected)
        self._domain_menu.add_command(label="Глубокий поиск стратегии (blockcheck2)", command=self.on_blockcheck2_selected)
        self._domain_menu.add_separator()
        self._domain_menu.add_command(label="Направить через VPN", command=lambda: self._quick_pin_selected("vpn", "vpn-select"))
        self._domain_menu.add_command(label="Открывать напрямую (без обхода)", command=lambda: self._quick_pin_selected("direct", None))
        self._domain_menu.add_command(label="Копировать адрес сайта", command=self._copy_selected_domain)

        # ---- Sub-view 2: Live Activity Chart & Active PC Connections ----
        self._conns_subview = tk.Frame(self._domains_view_container, bg=BG)
        self._build_conns_subview(self._conns_subview)

    def _build_conns_subview(self, parent: tk.Frame) -> None:
        # Reference 2: 3 Metric Cards + Live Activity Sparkline
        metrics = tk.Frame(parent, bg=BG)
        metrics.pack(fill="x", pady=(0, 6))
        for col in range(3):
            metrics.columnconfigure(col, weight=1, uniform="rt_metrics")

        def _metric_card(col: int, title: str, fg_col: str, note: str) -> tk.Label:
            wrap = RoundedCard(metrics, bg=CARD, outer_bg=BG, border=BORDER, radius=13, pad=2)
            wrap.grid(row=0, column=col, sticky="nsew", padx=(0 if col == 0 else 4, 0 if col == 2 else 4))
            c = wrap.body
            tk.Label(c, text=title, bg=CARD, fg=MUTED, font=FONT_MICRO, anchor="w").pack(fill="x", padx=12, pady=(5, 1))
            val = tk.Label(c, text="0", bg=CARD, fg=fg_col, font=("Segoe UI", 16, "bold"), anchor="w")
            val.pack(fill="x", padx=12)
            tk.Label(c, text=note, bg=CARD, fg=DIM, font=FONT_MICRO, anchor="w").pack(fill="x", padx=12, pady=(0, 5))
            return val

        self._rt_metric_total = _metric_card(0, "ПОДКЛЮЧЕНИЯ", FG, "Всего активных соединений")
        self._rt_metric_prot = _metric_card(1, "ПОД ЗАЩИТОЙ", ACCENT, "Обрабатываются обходом")
        self._rt_metric_fix = _metric_card(2, "ТРЕБУЮТ ВНИМАНИЯ", LAVENDER, "Зависшие или без правила")

        chart_wrap = RoundedCard(parent, bg=CARD, outer_bg=BG, border=BORDER, radius=13, pad=2)
        chart_wrap.pack(fill="x", pady=(0, 6))
        chart_card = chart_wrap.body
        ch_hdr = tk.Frame(chart_card, bg=CARD)
        ch_hdr.pack(fill="x", padx=12, pady=(5, 0))
        tk.Label(ch_hdr, text="АКТИВНОСТЬ В РЕАЛЬНОМ ВРЕМЕНИ", bg=CARD, fg=MUTED, font=FONT_MICRO).pack(side="left")
        tk.Label(ch_hdr, text="● ВСЕГО", bg=CARD, fg=LAVENDER, font=FONT_MICRO).pack(side="right", padx=(8, 0))
        tk.Label(ch_hdr, text="● ПОД ЗАЩИТОЙ", bg=CARD, fg=ACCENT, font=FONT_MICRO).pack(side="right")
        self.sparkline_canvas = LiveSparklineCanvas(chart_card, height=74, bg=CARD)
        self.sparkline_canvas.pack(fill="x", padx=6, pady=(2, 4))

        bar_wrap = RoundedCard(parent, bg=CARD, outer_bg=BG, border=BORDER, radius=13, pad=2)
        bar_wrap.pack(fill="x", pady=(0, 6))
        bar = bar_wrap.body

        top_r = tk.Frame(bar, bg=CARD)
        top_r.pack(fill="x", padx=12, pady=(5, 4))

        self.make_button(
            top_r,
            "Обновить список",
            self.refresh_realtime_async,
            "neutral",
            font=FONT_SMALL_B,
            pady=3,
            tooltip="Немедленно просканировать текущие сетевые подключения программ.",
        ).pack(side="right", padx=(6, 0))
        self.make_button(
            top_r,
            "Подобрать обход",
            self.on_heal_selected_connection,
            "primary",
            font=FONT_SMALL_B,
            pady=3,
            tooltip="Найти рабочую стратегию обхода для выбранного в таблице подключения.",
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
        bot_r.pack(fill="x", padx=12, pady=(4, 5))

        pill_wrap = tk.Frame(bot_r, bg=CARD)
        pill_wrap.pack(side="right", padx=(8, 0))
        self._conn_filter_buttons.clear()
        for fid, flabel in (("ALL", "Все"), ("needs_fix", "Требуют обхода"), ("protected", "Под защитой")):
            btn = self.make_button(
                pill_wrap,
                flabel,
                lambda f=fid: self._set_conn_health_filter(f),
                "pill_active" if fid == "ALL" else "neutral",
                font=FONT_SMALL,
                padx=8,
                pady=3,
            )
            btn.pack(side="left", padx=2)
            self._conn_filter_buttons[fid] = btn

        self.auto_heal_var = tk.BooleanVar(value=True)
        ah_row = self.make_toggle_row(
            bot_r,
            "Автоматически подбирать обход для новых зависших подключений",
            self.auto_heal_var,
            bg=CARD,
            font=FONT_SMALL_B,
            fg=FG,
            slider_width=36,
            slider_height=18,
            tooltip="В режиме Автоподбора программа автоматически подбирает стратегию, если соединение зависло. При фиксированном пресете не вмешивается.",
        )
        ah_row.pack(side="left", fill="x", expand=True, padx=(0, 8))

        paned = ttk.PanedWindow(parent, orient="vertical")
        paned.pack(fill="both", expand=True)

        conn_wrap = tk.Frame(paned, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
        cols = tuple(c[0] for c in CONN_COLUMNS)
        self.conn_tree = self.make_tree(conn_wrap, cols, height=8)
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
        self._conn_menu.add_command(label="Подобрать обход для этого сайта", command=self.on_heal_selected_connection)
        self._conn_menu.add_command(label="Показать в таблице сайтов", command=self._open_selected_conn_domain)
        self._conn_menu.add_command(label="Копировать адрес сайта", command=self._copy_selected_conn_domain)

        feed_panel = tk.Frame(paned, bg=BG)
        tk.Label(
            feed_panel,
            text="Журнал подключений и автоподбора",
            bg=BG,
            fg=ACCENT,
            font=FONT_SMALL_B,
            anchor="w",
        ).pack(fill="x", pady=(4, 3))
        feed_box = tk.Frame(feed_panel, bg=SIDEBAR_BG, highlightthickness=1, highlightbackground=BORDER)
        feed_box.pack(fill="both", expand=True)
        self.realtime_feed = self.make_text(feed_box, height=4, wrap="word")
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
            self._restyle_button(self._subtab_conns_btn, self._subtab_conns_btn.cget("text"), "pill_active")
        else:
            self._conns_subview.pack_forget()
            self._domains_subview.pack(fill="both", expand=True)
            self._restyle_button(self._subtab_domains_btn, self._subtab_domains_btn.cget("text"), "pill_active")
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
            self._restyle_button(btn, LAYER_FILTER_LABELS.get(lid, lid), "pill_active" if lid == cur else "neutral")

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
        panel.rowconfigure(0, weight=1, minsize=185)
        panel.columnconfigure(0, weight=7, minsize=340)
        panel.columnconfigure(1, weight=4, minsize=320)

        left = tk.Frame(panel, bg=CARD)
        left.grid(row=0, column=0, sticky="nsew", padx=(12, 6), pady=8)
        self.inspector_title = tk.Label(
            left, text="Выберите сайт в таблице выше, чтобы увидеть результаты проверок", bg=CARD, fg=ACCENT, font=FONT_UI_B, anchor="w"
        )
        self.inspector_title.pack(fill="x")
        box = tk.Frame(left, bg=SIDEBAR_BG, highlightthickness=1, highlightbackground=BORDER)
        box.pack(fill="both", expand=True, pady=(6, 0))
        self.inspector = self.make_text(box, height=7, wrap="word")
        self.inspector.tag_configure("h", foreground=ACCENT, font=("Consolas", 10, "bold"))
        self.inspector.tag_configure("ok", foreground=OK_TEXT)
        self.inspector.tag_configure("bad", foreground=ERR_TEXT)
        self.inspector.tag_configure("muted", foreground=MUTED)
        self.inspector.tag_configure("warn", foreground=WARN_TEXT)
        self.inspector.tag_configure("args", foreground="#93C5FD")
        self.inspector.configure(state="normal")
        self.inspector.insert(
            "1.0",
            "Выберите любой сайт в таблице выше — здесь появятся причины блокировки, "
            "подобранная стратегия и история проверок.\n",
            "muted",
        )
        self.inspector.configure(state="disabled")
        self._scrolled(box, self.inspector)

        right_outer = tk.Frame(panel, bg=CARD_ALT, highlightthickness=1, highlightbackground=BORDER)
        right_outer.grid(row=0, column=1, sticky="nsew", padx=(6, 10), pady=8)

        self.rule_canvas = tk.Canvas(
            right_outer, bg=CARD_ALT, highlightthickness=0, bd=0, height=195, yscrollincrement=18
        )
        rule_vsb = ttk.Scrollbar(right_outer, orient="vertical")
        self._rule_vsb = rule_vsb

        def _sync_rule_scrollbar(first: str, last: str) -> None:
            rule_vsb.set(first, last)
            try:
                canv_h = self.rule_canvas.winfo_height()
                req_h = right.winfo_reqheight()
                if canv_h > 10:
                    need_scroll = req_h > canv_h + 4
                else:
                    need_scroll = float(first) > 0.001 or float(last) < 0.999
                if need_scroll:
                    if not rule_vsb.winfo_ismapped():
                        rule_vsb.pack(side="right", fill="y")
                elif rule_vsb.winfo_ismapped() and (canv_h <= 10 or req_h <= canv_h - 4):
                    rule_vsb.pack_forget()
                    self.rule_canvas.yview_moveto(0.0)
            except (ValueError, tk.TclError):
                pass

        rule_vsb.configure(command=self.rule_canvas.yview)
        self.rule_canvas.configure(yscrollcommand=_sync_rule_scrollbar)
        self.rule_canvas.pack(side="left", fill="both", expand=True)

        right = tk.Frame(self.rule_canvas, bg=CARD_ALT)
        self._rule_form_frame = right
        self._rule_window_id = self.rule_canvas.create_window((0, 0), window=right, anchor="nw")

        def _on_rule_frame_cfg(_e: Any = None) -> None:
            try:
                bbox = self.rule_canvas.bbox("all")
                if bbox:
                    self.rule_canvas.configure(scrollregion=bbox)
            except tk.TclError:
                pass

        def _on_rule_canvas_cfg(e: Any) -> None:
            try:
                w = max(240, int(getattr(e, "width", 0)))
                self.rule_canvas.itemconfigure(self._rule_window_id, width=w)
                bbox = self.rule_canvas.bbox("all")
                if bbox:
                    self.rule_canvas.configure(scrollregion=bbox)
            except tk.TclError:
                pass

        right.bind("<Configure>", _on_rule_frame_cfg)
        self.rule_canvas.bind("<Configure>", _on_rule_canvas_cfg)

        tk.Label(right, text="Настройка правила", bg=CARD_ALT, fg=FG, font=FONT_UI_B, anchor="w").pack(
            fill="x", padx=10, pady=(5, 0)
        )
        sub_rule_lbl = tk.Label(
            right,
            text="Запустите автоподбор или задайте способ обхода вручную:",
            bg=CARD_ALT,
            fg=MUTED,
            font=FONT_SMALL,
            anchor="w",
            justify="left",
        )
        sub_rule_lbl.pack(fill="x", padx=10, pady=(0, 3))
        self._bind_responsive_wrap(sub_rule_lbl, min_wrap=200, pad=20)

        auto_row = tk.Frame(right, bg=CARD_ALT)
        auto_row.pack(fill="x", padx=10, pady=(0, 4))
        self.make_button(
            auto_row,
            "▶ Проверить",
            self.on_test_selected_domain,
            "success",
            font=FONT_SMALL_B,
            padx=5,
            pady=2,
            tooltip="Проверить доступность выбранного сайта прямо сейчас.",
        ).pack(side="left", fill="x", expand=True, padx=(0, 3))
        self.make_button(
            auto_row,
            "Подбор DPI",
            self.on_recheck_selected,
            "primary",
            font=FONT_SMALL_B,
            padx=5,
            pady=2,
            tooltip="Автоматически подобрать рабочую стратегию DPI для этого сайта.",
        ).pack(side="left", fill="x", expand=True, padx=(0, 3))
        self.make_button(
            auto_row,
            "Подбор DNS",
            self.on_roll_dns_selected,
            "neutral",
            font=FONT_SMALL_B,
            padx=5,
            pady=2,
            tooltip="Найти отдельный рабочий DNS-сервер специально для этого сайта.",
        ).pack(side="left", fill="x", expand=True)

        tk.Frame(right, bg=BORDER_LIGHT, height=1).pack(fill="x", padx=10, pady=(0, 3))

        tk.Label(right, text="Способ обхода и правило вручную:", bg=CARD_ALT, fg=FG_SOFT, font=FONT_SMALL_B, anchor="w").pack(
            fill="x", padx=10
        )
        self.override_layer_var = tk.StringVar(value="dpi")
        self.override_layer_cb = ttk.Combobox(
            right, textvariable=self.override_layer_var, values=OVERRIDE_LAYERS, state="readonly"
        )
        self.override_layer_cb.pack(fill="x", padx=10, pady=(2, 1))
        self.override_layer_cb.bind("<<ComboboxSelected>>", lambda _e: self._on_override_layer_changed())
        self.attach_tooltip(self.override_layer_cb, "Выберите способ обхода: dpi (быстрый), dns, vpn или direct (напрямую).")

        self._override_layer_hint_lbl = tk.Label(
            right,
            text=OVERRIDE_LAYER_HINTS["dpi"],
            bg=CARD_ALT,
            fg=MUTED,
            font=FONT_SMALL,
            anchor="w",
            wraplength=280,
            justify="left",
        )
        self._override_layer_hint_lbl.pack(fill="x", padx=10, pady=(0, 3))
        self._bind_responsive_wrap(self._override_layer_hint_lbl, min_wrap=200, pad=20)

        self.override_strategy_var = tk.StringVar()
        self.override_strategy_cb = ttk.Combobox(right, textvariable=self.override_strategy_var, state="readonly")
        self.override_strategy_cb.pack(fill="x", padx=10, pady=(0, 4))

        pin_row = tk.Frame(right, bg=CARD_ALT)
        pin_row.pack(fill="x", padx=10, pady=(0, 6))
        self.pin_btn = self.make_button(
            pin_row,
            "Сохранить правило",
            self.on_pin,
            "hero",
            font=FONT_SMALL_B,
            padx=8,
            pady=3,
            tooltip="Применить выбранный выше способ и стратегию и закрепить за сайтом.",
        )
        self.pin_btn.pack(side="left", fill="x", expand=True, padx=(0, 4))
        self.unpin_btn = self.make_button(
            pin_row,
            "Снять фиксацию",
            self.on_toggle_pin_selected,
            "neutral",
            font=FONT_SMALL,
            padx=8,
            pady=3,
            tooltip="Разрешить или запретить программе автоматически менять правило при сбоях.",
        )
        self.unpin_btn.pack(side="left")

        self._bind_rule_mousewheel(right_outer)
        return panel

    def _on_rule_mousewheel(self, event: Any) -> str | None:
        if self._closed or not hasattr(self, "rule_canvas"):
            return None
        is_combo = isinstance(getattr(event, "widget", None), ttk.Combobox)
        try:
            if not self.rule_canvas.winfo_viewable():
                return "break" if is_combo else None
            first, last = self.rule_canvas.yview()
            if float(first) <= 0.001 and float(last) >= 0.999:
                return "break" if is_combo else None
        except tk.TclError:
            return None
        delta = getattr(event, "delta", 0)
        if delta:
            step = -2 if delta > 0 else 2
            if abs(delta) >= 120:
                step = int(-delta / 120) * 2
            if (step < 0 and float(first) <= 0.0) or (step > 0 and float(last) >= 1.0):
                return "break"
            self.rule_canvas.yview_scroll(step, "units")
            return "break"
        return "break" if is_combo else None

    def _bind_rule_mousewheel(self, widget: tk.Misc) -> None:
        """Recursively attach <MouseWheel> handler to rule management panel widgets (also stops Combobox accidental wheel changes)."""
        widget.bind("<MouseWheel>", self._on_rule_mousewheel, add="+")
        for child in widget.winfo_children():
            self._bind_rule_mousewheel(child)

    # ---------------------------------------------------------------- Tab 3: Стратегии обхода (Zapret)

    def _build_presets_tab(self) -> None:
        tab = self.tab_presets
        self._make_page_header(
            tab,
            "Стратегии и пресеты Zapret",
            "Выберите готовый пресет обхода или добавьте свой рабочий (.txt / .bat). Пока выбран пресет, автоподбор на паузе.",
        )

        # Active mode bar + quick import actions
        top_card = tk.Frame(tab, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
        top_card.pack(fill="x", pady=(0, 6))

        r1 = tk.Frame(top_card, bg=CARD)
        r1.pack(fill="x", padx=12, pady=(7, 5))
        self.make_button(
            r1,
            "Импорт из папки…",
            self.on_import_presets_dir,
            "neutral",
            font=FONT_SMALL_B,
            padx=9,
            pady=4,
            tooltip="Загрузить все файлы пресетов (.txt / .bat) из выбранной папки на диске.",
        ).pack(side="right", padx=(4, 0))
        self.make_button(
            r1,
            "Загрузить файл…",
            self.on_import_preset_file,
            "neutral",
            font=FONT_SMALL_B,
            padx=9,
            pady=4,
            tooltip="Импортировать один файл пресета (.txt, .bat или .cmd) и сразу включить его.",
        ).pack(side="right", padx=(4, 0))
        self.make_button(
            r1,
            "Режим автоподбора",
            lambda: self.on_select_zapret_preset("auto"),
            "cyan_ghost",
            font=FONT_SMALL_B,
            padx=9,
            pady=4,
            tooltip="Отключить фиксированный пресет и вернуть автоматический подбор правил для каждого сайта.",
        ).pack(side="right", padx=(6, 0))

        self.presets_active_lbl = tk.Label(
            r1,
            text="Активный режим: Автоподбор (для каждого сайта отдельно)",
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
                "pill_active" if pf_id == "ALL" else "neutral",
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
            act_bar,
            "✔ Включить выбранный",
            self.on_activate_selected_preset,
            "hero",
            font=FONT_SMALL_B,
            padx=10,
            pady=4,
            tooltip="Активировать выбранный в таблице пресет для всего трафика.",
        ).pack(side="left", padx=(0, 6))
        self.make_button(
            act_bar,
            "▶ Проверить пресет",
            self.on_test_selected_preset,
            "primary",
            font=FONT_SMALL_B,
            padx=10,
            pady=4,
            tooltip="Временнно применит выбранный пресет и измерит доступность YouTube, Discord и Telegram.",
        ).pack(side="left", padx=(0, 6))
        self.make_button(
            act_bar,
            "Изменить в редакторе ↓",
            self.on_load_selected_preset_to_editor,
            "neutral",
            font=FONT_SMALL,
            padx=8,
            pady=4,
            tooltip="Скопировать параметры выбранного пресета в редактор ниже для доработки.",
        ).pack(side="left", padx=(0, 6))
        self.make_button(
            act_bar,
            "Удалить свой",
            self.on_delete_selected_preset,
            "danger",
            font=FONT_SMALL,
            padx=8,
            pady=4,
            tooltip="Удалить выбранный пользовательский пресет (встроенные удалить нельзя).",
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
            ed_hdr,
            "+ Сохранить свой пресет",
            self.on_add_user_preset,
            "primary",
            font=FONT_SMALL_B,
            padx=10,
            pady=4,
            tooltip="Сохраняет текст параметров из поля ниже в вашу библиотеку пресетов.",
        ).pack(side="right")
        self.make_toggle_row(
            ed_hdr,
            "Включить сразу",
            self.user_preset_activate_var,
            bg=CARD,
            font=FONT_SMALL,
            fg=FG_SOFT,
            slider_width=34,
            slider_height=16,
            tooltip="Активировать новый пресет сразу после сохранения.",
        ).pack(side="right", padx=(4, 10))
        tk.Label(
            ed_hdr,
            text="Добавить свой рабочий пресет (аргументы winws2 или .bat)",
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
        tk.Label(meta_r, text="Заметка:", bg=CARD, fg=MUTED, font=FONT_SMALL).pack(side="left", padx=(0, 5))
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

    # ---------------------------------------------------------------- Tab 4: DNS и Нейросети

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
            text="Выберите общий защищённый DNS по умолчанию или назначьте персональный DNS для ChatGPT, Claude и других сервисов.",
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
            "Выбрать самый быстрый",
            lambda: self.on_auto_select_dns("uncommon" if self.dns_category_filter == "ALL" else self.dns_category_filter),
            "cyan_ghost",
            font=FONT_SMALL_B,
            padx=9,
            pady=3,
            tooltip="Измеряет задержку серверов в выбранной категории и автоматически включает самый быстрый рабочий DNS.",
        ).pack(side="right", padx=(4, 0))
        self.make_button(
            bar,
            "Измерить пинг всех",
            self.on_ping_dns_catalog,
            "success",
            font=FONT_SMALL_B,
            padx=9,
            pady=3,
            tooltip="Проверяет скорость отклика (мс) и доступность каждого DNS-сервера в текущем списке.",
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
                "pill_active" if cat_id == "ALL" else "neutral",
                font=FONT_SMALL,
                padx=7,
                pady=3,
            )
            btn.pack(side="left", padx=(0, 3))
            self._dns_cat_buttons[cat_id] = btn

        # Clean two-column action row
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
            text="Находит отдельный рабочий DNS для указанного домена или сразу для всех ИИ.",
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
        self.make_button(
            r_inner,
            "Настроить для всех ИИ",
            self.on_roll_all_ai_dns,
            "primary",
            font=FONT_SMALL_B,
            padx=8,
            pady=4,
            tooltip="Автоматически подбирает рабочие DNS для ChatGPT, Claude, Gemini и других нейросетей.",
        ).pack(side="right", padx=(4, 0))
        self.make_button(
            r_inner,
            "Подобрать",
            self.on_roll_dns_domain,
            "success",
            font=FONT_SMALL_B,
            padx=8,
            pady=4,
            tooltip="Проверит и назначит лучший персональный DNS для введённого сайта.",
        ).pack(side="right", padx=(6, 0))
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
        self.make_button(
            c_row2,
            "+ Добавить DNS",
            self.on_add_custom_dns,
            "primary",
            font=FONT_SMALL_B,
            padx=8,
            pady=4,
            tooltip="Сохранить собственный DNS или DoH-адрес в раздел «Мои DNS».",
        ).pack(side="right", padx=(6, 0))
        tk.Label(c_row2, text="DoH URL / заметка:", bg=CARD, fg=MUTED, font=FONT_SMALL).pack(side="left", padx=(0, 4))
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
            self._restyle_button(btn, btn.cget("text"), "pill_active" if cid == category else "neutral")
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
        border_col = CYAN_BORDER if is_active else BORDER
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
            self._restyle_button(btn, btn.cget("text"), "pill_active" if fid == health else "neutral")
        self.populate_connections_table(self.live_connections, events=self._last_conn_events)

    # ---------------------------------------------------------------- Tab 5: VPN и журналы

    def _build_vpn_tab(self) -> None:
        tab = self.tab_vpn
        self._make_page_header(
            tab,
            "VPN и журналы служб",
            "Обычный трафик идёт напрямую или через Zapret; VPN используется точечно для сайтов с блокировкой по IP.",
        )

        vpn_card = tk.Frame(tab, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
        vpn_card.pack(fill="x", pady=(0, 8))

        row1 = tk.Frame(vpn_card, bg=CARD)
        row1.pack(fill="x", padx=12, pady=(8, 5))
        self.make_button(
            row1,
            "Обновить список",
            self.on_refresh_subscriptions,
            "neutral",
            font=FONT_SMALL_B,
            padx=9,
            pady=4,
            tooltip="Скачать актуальный список серверов из всех добавленных подписок.",
        ).pack(side="right", padx=(4, 0))
        self.make_button(
            row1,
            "+ Добавить подписку",
            self.on_add_subscription,
            "primary",
            font=FONT_SMALL_B,
            padx=10,
            pady=4,
            tooltip="Добавить ссылку на подписку (URL) или отдельный ключ vless://, vmess://, trojan://, ss://.",
        ).pack(side="right", padx=(8, 0))
        tk.Label(row1, text="Ссылка / ключ:", bg=CARD, fg=MUTED, font=FONT_SMALL_B).pack(side="left", padx=(0, 8))
        self.sub_var = tk.StringVar()
        sub_entry = self.make_entry(row1, self.sub_var, 20)
        sub_entry.pack(side="left", ipady=3, fill="x", expand=True)
        sub_entry.bind("<Return>", lambda _e: self.on_add_subscription())

        tk.Frame(vpn_card, bg=BORDER_LIGHT, height=1).pack(fill="x", padx=12)

        row2 = tk.Frame(vpn_card, bg=CARD)
        row2.pack(fill="x", padx=12, pady=(5, 5))
        self.make_button(
            row2,
            "Сменить сервер",
            self.on_rotate_vpn_node,
            "warn",
            font=FONT_SMALL_B,
            padx=9,
            pady=4,
            tooltip="Переключить активный VPN на выбранный в таблице сервер или на следующий рабочий без перезапуска защиты.",
        ).pack(side="right", padx=(6, 0))
        self.make_button(
            row2,
            "Проверить пинг серверов",
            self.on_ping_vpn_nodes,
            "cyan_ghost",
            font=FONT_SMALL_B,
            padx=9,
            pady=4,
            tooltip="Измерить реальную задержку (пинг) и доступность каждого VPN-сервера внутри туннеля.",
        ).pack(side="right", padx=(8, 0))
        self._vpn_summary_lbl = tk.Label(
            row2,
            text="Список серверов VPN и текущая задержка внутри туннеля",
            bg=CARD,
            fg=FG_SOFT,
            font=FONT_SMALL,
            anchor="w",
            justify="left",
        )
        self._vpn_summary_lbl.pack(side="left", fill="x", expand=True)
        self._bind_responsive_wrap(self._vpn_summary_lbl, min_wrap=200, pad=16)

        tk.Frame(vpn_card, bg=BORDER_LIGHT, height=1).pack(fill="x", padx=12)

        row3 = tk.Frame(vpn_card, bg=CARD)
        row3.pack(fill="x", padx=12, pady=(5, 8))
        tk.Label(row3, text="Режим выбора:", bg=CARD, fg=MUTED, font=FONT_SMALL_B).pack(side="left", padx=(0, 6))
        self.vpn_mode_var = tk.StringVar(value=VPN_MODE_AUTO_LABEL)
        self.vpn_mode_cb = ttk.Combobox(
            row3,
            textvariable=self.vpn_mode_var,
            values=[VPN_MODE_AUTO_LABEL, VPN_MODE_PRIORITY_LABEL],
            state="readonly",
            width=26,
        )
        self.vpn_mode_cb.pack(side="left", padx=(0, 8))
        self.vpn_mode_cb.bind("<<ComboboxSelected>>", self.on_vpn_mode_change)
        self.attach_tooltip(
            self.vpn_mode_cb,
            "Автовыбор сам переключается на самый быстрый рабочий сервер; Приоритетный держит выбранный вами сервер №1.",
        )
        self.make_button(
            row3,
            "↓ Ниже",
            lambda: self.on_move_vpn_priority(1),
            "neutral",
            font=FONT_SMALL_B,
            padx=8,
            pady=3,
            tooltip="Понизить приоритет выбранного в таблице сервера.",
        ).pack(side="right", padx=(4, 0))
        self.make_button(
            row3,
            "↑ Выше",
            lambda: self.on_move_vpn_priority(-1),
            "neutral",
            font=FONT_SMALL_B,
            padx=8,
            pady=3,
            tooltip="Повысить приоритет выбранного в таблице сервера.",
        ).pack(side="right", padx=(4, 0))
        self.make_button(
            row3,
            "★ Сделать основным",
            self.on_set_priority_vpn_node,
            "primary",
            font=FONT_SMALL_B,
            padx=9,
            pady=3,
            tooltip="Назначить выбранный сервер основным (#1) и переключить режим на «Приоритетный».",
        ).pack(side="right", padx=(8, 0))

        paned = ttk.PanedWindow(tab, orient="vertical")
        paned.pack(fill="both", expand=True)

        vpn_wrap = tk.Frame(paned, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
        self.vpn_tree = self.make_tree(
            vpn_wrap, ("priority", "tag", "region", "protocol", "transport", "server", "health"), height=6
        )
        for cid, title, width in (
            ("priority", "Приоритет", 82),
            ("tag", "Сервер", 180),
            ("region", "Регион", 66),
            ("protocol", "Протокол", 82),
            ("transport", "Транспорт", 82),
            ("server", "Адрес : Порт / Пинг", 210),
            ("health", "Состояние сервера", 175),
        ):
            self.vpn_tree.heading(cid, text=title)
            self.vpn_tree.column(cid, width=width, anchor="w", stretch=cid in ("tag", "health"))  # type: ignore[arg-type]
        self.vpn_tree.tag_configure("ok", foreground=OK_TEXT)
        self.vpn_tree.tag_configure("warn", foreground=WARN_TEXT)
        self.vpn_tree.tag_configure("bad", foreground=ERR_TEXT)
        self.vpn_tree.tag_configure("muted", foreground=MUTED)
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
        self.attach_tooltip(log_cb, "winws2.log — обход DPI; sing-box.log — VPN и DNS; tg-ws-proxy.log — прокси Telegram.")
        tk.Label(head, text="● автообновление 2с", bg=OK_BG, fg=OK_TEXT, font=FONT_MICRO, padx=7, pady=2).pack(
            side="left", padx=10
        )

        # Smart inline alert bar (shown only when actionable error detected in sing-box.log)
        self._log_alert_bar = tk.Frame(log_panel, bg=WARN_BG, highlightthickness=1, highlightbackground=WARN)
        self.make_button(
            self._log_alert_bar,
            "Перейти в DNS →",
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

    # ---------------------------------------------------------------- Tab 6: Настройки и система

    def _build_service_tab(self) -> None:
        tab = self.tab_service
        self._make_page_header(
            tab,
            "Настройки и система",
            "Автозапуск, обслуживание модулей, исключения для сторонних программ и просмотр конфигов.",
        )

        body = tk.Frame(tab, bg=BG)
        body.pack(fill="both", expand=True)

        # Left column: actions, settings, exit
        left = tk.Frame(body, bg=BG, width=312)
        left.pack(side="left", fill="y", padx=(0, 10))
        left.pack_propagate(False)

        act_wrap = RoundedCard(left, bg=CARD, outer_bg=BG, border=BORDER, radius=13, pad=2)
        act_wrap.pack(fill="x", pady=(0, 4))
        act_card = act_wrap.body
        tk.Label(act_card, text="Обслуживание модулей", bg=CARD, fg=ACCENT, font=FONT_UI_B, anchor="w").pack(
            fill="x", padx=10, pady=(4, 2)
        )
        handlers: dict[str, Callable[[], None]] = {
            "layers": self.on_check_layers,
            "reload": self.on_reload,
            "reload_sb": self.on_reload_singbox,
            "reval": self.on_revalidate,
            "gen": self.on_generate,
            "flush_dns": self.on_flush_dns,
            "verify": self.on_verify,
        }
        kinds = {"layers": "primary"}
        for key, title, tip_text in SERVICE_ACTIONS:
            btn = self.make_button(
                act_card,
                title,
                handlers[key],
                kinds.get(key, "neutral"),
                font=FONT_SMALL_B,
                padx=9,
                pady=2,
                radius=8,
                tooltip=tip_text,
            )
            btn.configure(anchor="w")
            btn.pack(fill="x", padx=10, pady=1)
        tk.Frame(act_card, bg=CARD, height=3).pack()

        opt_wrap = RoundedCard(left, bg=CARD, outer_bg=BG, border=BORDER, radius=13, pad=2)
        opt_wrap.pack(fill="x", pady=(0, 4))
        opt_card = opt_wrap.body
        tk.Label(opt_card, text="Системные параметры", bg=CARD, fg=ACCENT, font=FONT_UI_B, anchor="w").pack(
            fill="x", padx=10, pady=(4, 2)
        )
        for var, label, cmd, tip_text in (
            (
                self.minimize_to_tray_var,
                "Сворачивать в трей при закрытии окна",
                None,
                "При нажатии на крестик окно скроется в значок у часов, а защита продолжит работать.",
            ),
            (
                self.autostart_var,
                "Запускать вместе с Windows",
                self.on_toggle_autostart,
                "Автоматически запускать NetDoctor в свёрнутом виде при входе в Windows.",
            ),
            (
                self.autostart_protection_var,
                "Включать защиту сразу при старте",
                self.on_toggle_autostart_protection,
                "Запускать обход блокировок сразу после открытия программы.",
            ),
            (
                self.debug_log_var,
                "Подробный журнал отладки winws2",
                self.on_toggle_debug_log,
                "Включает расширенное логирование (--debug=1) для диагностики проблем.",
            ),
        ):
            t_row = self.make_toggle_row(
                opt_card,
                label,
                var,
                command=cmd,
                bg=CARD,
                font=FONT_SMALL,
                fg=FG_SOFT,
                tooltip=tip_text,
                slider_width=34,
                slider_height=16,
            )
            t_row.pack(fill="x", padx=10, pady=1)

        net_row = tk.Frame(opt_card, bg=CARD)
        net_row.pack(fill="x", padx=10, pady=(3, 5))
        tun_lbl = tk.Label(net_row, text="TUN:", bg=CARD, fg=MUTED, font=FONT_SMALL)
        tun_lbl.pack(side="left", padx=(0, 4))
        self.tun_stack_cb = ttk.Combobox(
            net_row,
            textvariable=self.tun_stack_var,
            values=("gvisor", "mixed", "system"),
            state="readonly",
            width=7,
        )
        self.tun_stack_cb.pack(side="left", padx=(0, 8))
        self.tun_stack_cb.bind("<<ComboboxSelected>>", lambda _e: self.on_change_tun_stack())
        self.attach_tooltip(self.tun_stack_cb, "Стек сетевого драйвера для VPN-туннеля (рекомендуется gvisor).")

        if_lbl = tk.Label(net_row, text="Сеть:", bg=CARD, fg=MUTED, font=FONT_SMALL)
        if_lbl.pack(side="left", padx=(0, 4))
        self.iface_var = tk.StringVar()
        if_entry = self.make_entry(net_row, self.iface_var, 6)
        if_entry.pack(side="left", fill="x", expand=True, ipady=2)
        self.attach_tooltip(if_entry, "Необязательный номер сетевого адаптера (ifIndex) для привязки.")

        exit_btn = self.make_button(
            left,
            "Выход и остановка служб",
            self.on_exit_app,
            "danger",
            font=FONT_SMALL_B,
            pady=4,
            tooltip="Полностью останавливает все фоновые службы обхода и закрывает программу.",
        )
        exit_btn.pack(fill="x", pady=(1, 0))

        # Right column: Version/Updates Bar + Unlocker Guard + Vertical Split (Config Preview + Operations Console)
        right = tk.Frame(body, bg=BG)
        right.pack(side="left", fill="both", expand=True)

        mode_raw = self.backend.get_install_mode() if hasattr(self.backend, "get_install_mode") else "portable"
        mode_label = "git" if mode_raw == "git" else "ZIP"
        update_wrap = RoundedCard(right, bg=CARD, outer_bg=BG, border=BORDER, radius=13, pad=2)
        update_wrap.pack(fill="x", pady=(0, 6))
        update_bar = update_wrap.body
        u_row = tk.Frame(update_bar, bg=CARD)
        u_row.pack(fill="x", padx=12, pady=4)
        self.version_info_label = tk.Label(
            u_row,
            text=f"Версия: v{__version__} ({mode_label}) · Обновления не проверялись",
            bg=CARD,
            fg=FG_SOFT,
            font=FONT_SMALL,
            anchor="w",
        )
        self.version_info_label.pack(side="left", fill="x", expand=True)
        self.check_update_btn = self.make_button(
            u_row,
            "Проверить обновления",
            self.on_check_updates,
            "neutral",
            font=FONT_SMALL_B,
            padx=10,
            pady=2,
            tooltip="Проверить наличие новой версии NetDoctor на сервере.",
        )
        self.check_update_btn.pack(side="right")
        self.apply_update_btn = self.make_button(
            u_row,
            "Обновить",
            self.on_apply_update,
            "success",
            font=FONT_SMALL_B,
            padx=10,
            pady=2,
            tooltip="Скачать и установить доступное обновление программы.",
        )

        guard_wrap = RoundedCard(right, bg=CARD, outer_bg=BG, border=BORDER, radius=13, pad=2)
        guard_wrap.pack(fill="x", pady=(0, 6))
        guard_box = guard_wrap.body
        tk.Label(
            guard_box,
            text="Защита сторонних программ и файла hosts",
            bg=CARD,
            fg=OK_TEXT,
            font=FONT_UI_B,
            anchor="w",
        ).pack(fill="x", padx=12, pady=(5, 2))
        self.unlocker_guard_var = tk.BooleanVar(value=True)
        guard_row = self.make_toggle_row(
            guard_box,
            "Не вмешиваться в Antigravity.exe, Cursor, ag_dns.exe, xray/happ и hosts",
            self.unlocker_guard_var,
            command=self.on_save_unlocker_guard,
            bg=CARD,
            font=FONT_SMALL,
            fg=FG_SOFT,
            slider_width=34,
            slider_height=16,
            tooltip="Исключает перечисленные программы и домены из файла hosts из обработки VPN и Zapret.",
        )
        guard_row.pack(fill="x", padx=12, pady=(0, 3))
        g_row = tk.Frame(guard_box, bg=CARD)
        g_row.pack(fill="x", padx=12, pady=(0, 6))
        self.make_button(
            g_row,
            "Сохранить",
            self.on_save_unlocker_guard,
            "primary",
            font=FONT_SMALL_B,
            pady=3,
            tooltip="Сохранить список исключений и обновить конфигурацию.",
        ).pack(side="right", padx=(6, 0))
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
        self.make_button(
            head,
            "↻ Обновить",
            self.refresh_previews_async,
            "neutral",
            font=FONT_SMALL_B,
            pady=3,
            tooltip="Перечитать содержимое выбранного файла конфигурации с диска.",
        ).pack(side="right", padx=(6, 0))
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

        def done(payload: tuple[dict[str, Any], dict[str, Any] | None, dict[str, Any] | None]) -> None:
            self._refreshing = False
            snap, wd, vpn_rec = payload
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
            if isinstance(vpn_rec, dict):
                act = str(vpn_rec.get("action") or "")
                if act in ("failover", "failover_priority", "failback_priority", "return_to_auto"):
                    self.log_console(
                        f"[VPN] Автопереключение ({act}): {vpn_rec.get('previous') or '—'} -> {vpn_rec.get('selected')}"
                    )
                elif act == "all_unavailable":
                    self.log_console("[VPN] Все настроенные VPN-серверы сейчас недоступны")

        def failed(exc: Exception) -> None:
            self._refreshing = False
            self.set_status(f"Снимок состояния: {exc}", ERR_TEXT)

        def runner() -> None:
            try:
                wd_res: dict[str, Any] | None = None
                vpn_rec: dict[str, Any] | None = None
                if run_watchdog and hasattr(self.backend, "ensure_services_healthy"):
                    try:
                        wd_res = self.backend.ensure_services_healthy()
                    except Exception:  # noqa: BLE001
                        wd_res = None
                if run_watchdog and hasattr(self.backend, "reconcile_vpn_health"):
                    try:
                        vpn_rec = self.backend.reconcile_vpn_health(min_interval_sec=30.0)
                    except Exception:  # noqa: BLE001
                        vpn_rec = None
                snap = self.backend.get_status_snapshot()
            except Exception as exc:  # noqa: BLE001
                self._post(failed, exc)
            else:
                self._post(done, (snap, wd_res, vpn_rec))

        threading.Thread(target=runner, name="gui-snapshot", daemon=True).start()

    def _watchdog_only_async(self) -> None:
        """Lightweight tray-mode watchdog tick skipping full snapshot/UI redraws."""
        if self._refreshing or self._closed or self._exiting or not hasattr(self.backend, "ensure_services_healthy"):
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
        if self._closed or self._exiting:
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
        first_load = not self._initial_loaded
        self._initial_loaded = True
        if first_load:
            self._progress_update()
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
                self.bypass_label.pack(fill="x", anchor="w", pady=(3, 0))
        else:
            self.bypass_label.configure(text="")
            if self.bypass_label.winfo_manager():
                self.bypass_label.pack_forget()

        dns_alert = snap.get("dns_alert")
        if dns_alert:
            self._home_alert_lbl.configure(text=f"⚠ {dns_alert}")
            if not self._home_alert_frame.winfo_manager():
                self._home_alert_frame.pack(fill="x", padx=16, pady=(0, 5), before=self._home_section1_lbl)
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
        pending = snap.get("pending_changes") or {}
        p_cnt = int(pending.get("count") or 0)
        if p_cnt > 0:
            self._restyle_button(self.apply_pending_btn, f"Применить ({p_cnt})", "warn")
            if not self.apply_pending_btn.winfo_manager():
                self.apply_pending_btn.pack(side="right", padx=(0, 8))
        elif self.apply_pending_btn.winfo_manager():
            self.apply_pending_btn.pack_forget()

        preset_locked = self.active_preset_id != "auto"
        wd = snap.get("watchdog") or {}
        wd_cnt = int(wd.get("restarts_count") or 0)
        wd_note = f"  •  Перезапусков модуля: {wd_cnt}" if wd_cnt > 0 else ""

        if stack_running:
            if self._power_transition is None:
                self._restyle_button(self.autopilot_btn, "ОТКЛЮЧИТЬ ЗАЩИТУ  ⏻", "hero_active")
            self.hero_state_pill.configure(text="● ЗАЩИТА АКТИВНА", bg=OK_BG, fg=OK_TEXT)
            self._home_zapret_pill.configure(text="● ПОДКЛЮЧЕНО", bg=OK_BG, fg=OK_TEXT)
            self._home_zapret_card.configure(highlightbackground=CYAN_BORDER)
            if preset_locked:
                self.hint_label.configure(
                    text=f"Активен пресет «{self.active_preset_name}» — защита работает.{wd_note}",
                    fg=OK_TEXT,
                )
            elif self.radar_enabled:
                self.hint_label.configure(
                    text=f"Защита активна + Монитор включён — правила подбираются автоматически.{wd_note}",
                    fg=OK_TEXT,
                )
            else:
                self.hint_label.configure(
                    text=f"Защита активна. Монитор на паузе — можете включить его на вкладке «Монитор».{wd_note}",
                    fg=ACCENT,
                )
        else:
            if self._power_transition is None:
                self._restyle_button(self.autopilot_btn, "ВКЛЮЧИТЬ ЗАЩИТУ  ⏻", "hero")
            self.hero_state_pill.configure(text="● ОСТАНОВЛЕНО", bg=INPUT, fg=MUTED)
            self._home_zapret_pill.configure(text="● ОТКЛЮЧЕНО", bg=INPUT, fg=MUTED)
            self._home_zapret_card.configure(highlightbackground=BORDER)
            if is_admin:
                self.hint_label.configure(
                    text="Выберите стратегию обхода и нажмите «ВКЛЮЧИТЬ ЗАЩИТУ».",
                    fg=MUTED,
                )
            else:
                self.hint_label.configure(
                    text="Нажмите «Права Admin» вверху или «ВКЛЮЧИТЬ ЗАЩИТУ» для запуска.",
                    fg=WARN_TEXT,
                )

        vpn_or_tg_up = bool((processes.get("sing-box") or {}).get("running")) or bool(
            (processes.get("tg-ws-proxy") or {}).get("running")
        )
        if vpn_or_tg_up:
            self._home_vpn_state_pill.configure(text="● ПОДКЛЮЧЕНО", bg=OK_BG, fg=OK_TEXT)
            self._home_vpn_card.configure(highlightbackground=CYAN_BORDER)
        else:
            self._home_vpn_state_pill.configure(text="● РЕЗЕРВ", bg=INPUT, fg=MUTED)
            self._home_vpn_card.configure(highlightbackground=BORDER)

        if "game_filter" in snap:
            self.game_filter_var.set(bool(snap["game_filter"]))
        if "auto_start_protection" in snap:
            self.autostart_protection_var.set(bool(snap["auto_start_protection"]))
        if "byedpi_fallback" in snap:
            self.byedpi_var.set(bool(snap["byedpi_fallback"]))
        if "winws2_debug_log" in snap:
            self.debug_log_var.set(bool(snap["winws2_debug_log"]))
        if "stack_mode" in snap:
            dpi_only = str(snap["stack_mode"]) == "dpi_only"
            self.dpi_only_var.set(dpi_only)
            if hasattr(self, "home_stack_mode_var"):
                self._stack_mode_syncing = True
                try:
                    self.home_stack_mode_var.set(self._stack_mode_labels[1 if dpi_only else 0])
                finally:
                    self._stack_mode_syncing = False
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

        if isinstance(snap.get("vpn_policy"), dict):
            self._vpn_policy = dict(snap["vpn_policy"])
            self._sync_vpn_mode_combo()

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
            self._preset_cb_syncing = True
            try:
                self.home_preset_var.set(self._home_preset_id_to_label[self.active_preset_id])
            finally:
                self._preset_cb_syncing = False
        elif not is_preset:
            self._preset_cb_syncing = True
            try:
                self.home_preset_var.set("Авто-оркестратор (подбор по доменам)")
            finally:
                self._preset_cb_syncing = False

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
        best_n = str(vpn.get("best_node") or "").strip()
        sel_mode = str(vpn.get("selection_mode") or self._vpn_policy.get("mode") or "auto")
        mode_short = "Приор." if sel_mode == "priority" else "Авто"
        best_short = (best_n[:18] + "…") if len(best_n) > 20 else best_n
        node_part = f" • {mode_short}: {best_short}" if best_short else ""
        self.card_vpn_sub.configure(text=f"Через VPN: {vpn.get('vpn_domains_count', 0)} сайтов • TG-WS: {tg_ok}{node_part}")

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
        self.notebook.tab(self.tab_domains, text=f"Монитор и Сайты ({badge_txt})")
        self._update_nav_badge(self.tab_domains, badge_txt)
        self._restyle_button(
            self._subtab_domains_btn,
            f"Правила для сайтов ({len(self.rows_by_iid)})",
            "pill_active" if self._domains_subview_mode == "domains" else "neutral",
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
                "Снять фиксацию" if row.get("pinned") else "Зафиксировать",
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
            text=f"Всего: {total}  •  Под защитой: {protected_cnt}  •  Требуют обхода: {needs_fix_cnt}  •  Напрямую: {direct_cnt}",
            fg=WARN_TEXT if needs_fix_cnt > 0 else FG_SOFT,
        )
        if hasattr(self, "_rt_metric_total"):
            self._rt_metric_total.configure(text=str(total))
            self._rt_metric_prot.configure(text=str(protected_cnt))
            self._rt_metric_fix.configure(text=str(needs_fix_cnt), fg=WARN_TEXT if needs_fix_cnt > 0 else LAVENDER)
        if hasattr(self, "sparkline_canvas"):
            self.sparkline_canvas.push_sample(total, protected_cnt)

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
            f"Активные подключения ({len(self.conns_by_iid)})",
            "pill_active" if self._domains_subview_mode == "connections" else "neutral",
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
            deferred = res.get("reload_deferred") or []
            if healed:
                names = ", ".join(f"{h['domain']}→{h.get('strategy_id') or h['layer']}" for h in healed)
                self.log_console(f"Live-Радар автоподбор: {names}")
                self.set_status(f"Live-Радар подобрал: {names}", OK_TEXT)
                if deferred:
                    self.log_console(
                        f"Перезапуск {', '.join(deferred)} отложен — есть активные рабочие соединения"
                    )
                self.refresh_async()

        def failed(_exc: Exception) -> None:
            self._rt_busy = False

        def runner() -> None:
            try:
                if auto_heal:
                    res = self.backend.run_realtime_auto_heal_tick(max_domains_per_tick=3, require_running=True)
                else:
                    res = self.backend.scan_live_connections()
            except Exception as exc:  # noqa: BLE001
                self._post(failed, exc)
            else:
                self._post(done, res)

        threading.Thread(target=runner, name="gui-realtime", daemon=True).start()

    def _realtime_tick(self) -> None:
        if self._closed or self._exiting:
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
            self._restyle_button(self.radar_btn, "⏹ Остановить мониторинг", "danger")
            self.refresh_realtime_async(
                auto_heal=bool(self.auto_heal_var.get()) and bool(self.last_snapshot.get("running"))
            )
        else:
            self._restyle_button(self.radar_btn, "▶ Запустить мониторинг", "cyan_ghost")
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

    def _sync_vpn_mode_combo(self) -> None:
        if not hasattr(self, "vpn_mode_var"):
            return
        self._vpn_mode_syncing = True
        try:
            mode = str(self._vpn_policy.get("mode") or "auto")
            self.vpn_mode_var.set(VPN_MODE_PRIORITY_LABEL if mode == "priority" else VPN_MODE_AUTO_LABEL)
        finally:
            self._vpn_mode_syncing = False

    def _active_vpn_node_from_snap(self) -> str:
        vpn_orch = (self.last_snapshot.get("orchestrators") or {}).get("vpn") or {}
        return str(vpn_orch.get("best_node") or "").strip()

    def _selected_vpn_node(self) -> dict[str, Any] | None:
        sel = self.vpn_tree.selection() if hasattr(self, "vpn_tree") else ()
        if not sel:
            return None
        node_row = self._vpn_nodes_by_iid.get(sel[0])
        if isinstance(node_row, dict):
            return node_row
        vals = self.vpn_tree.item(sel[0], "values")
        if vals and len(vals) >= 2:
            raw_name = str(vals[1]).lstrip("▶ ").split(" [⚡", 1)[0].strip()
            for n in self.last_snapshot.get("vpn_nodes") or []:
                if raw_name in (str(n.get("tag") or "").strip(), str(n.get("display_name") or "").strip()):
                    return n
        return None

    def populate_vpn_table(self, nodes: list[dict[str, Any]]) -> None:
        active_vpn_node = self._active_vpn_node_from_snap()
        signature = repr((nodes, self._vpn_policy, active_vpn_node))
        if signature == self._vpn_signature:
            return
        self._vpn_signature = signature
        prev_node = self._selected_vpn_node()
        prev_sel_tag = str(prev_node.get("tag") or "").strip() if isinstance(prev_node, dict) else ""

        self.vpn_tree.delete(*self.vpn_tree.get_children())
        self._vpn_nodes_by_iid = {}

        mode = str(self._vpn_policy.get("mode") or "auto")
        pref_tag = str(self._vpn_policy.get("priority_node") or "").strip()
        alive_cnt = 0
        real_cnt = 0
        ph_cnt = 0
        restore_iid: str | None = None

        for i, node in enumerate(nodes):
            iid = f"n{i}"
            self._vpn_nodes_by_iid[iid] = node
            tag_str = str(node.get("tag") or "").strip()
            if prev_sel_tag and tag_str == prev_sel_tag:
                restore_iid = iid

            is_ph = bool(node["is_placeholder"]) if "is_placeholder" in node else is_placeholder_node(node)
            is_builtin_auto = bool(node["is_builtin_auto"]) if "is_builtin_auto" in node else is_auto_select_node(node)
            enabled = bool(node.get("enabled", True))
            try:
                prio = int(node.get("priority") if node.get("priority") is not None else 100)
            except (TypeError, ValueError):
                prio = 100

            if is_ph:
                ph_cnt += 1
                prio_txt = "—"
            else:
                real_cnt += 1
                if (pref_tag and tag_str == pref_tag) or prio == 1:
                    prio_txt = "★ #1"
                elif prio < 100:
                    prio_txt = f"#{prio}"
                elif mode == "priority":
                    prio_txt = "Резерв"
                else:
                    prio_txt = "Авто"

            is_active = bool(node.get("is_active") or (active_vpn_node and tag_str == active_vpn_node))
            shown = str(node.get("display_name") or tag_str).strip()
            if is_active:
                shown = f"▶ {shown}"
            if is_builtin_auto and not is_ph:
                shown = f"{shown} [⚡ Авто-VPN]"

            endpoint = f"{node.get('server', '')}:{node.get('server_port', '')}"
            if "ping_ms" in node and node.get("ping_ms") is not None:
                suffix = "✔ (туннель)" if node.get("tunnel_verified") else "✔"
                endpoint += f"  •  {node['ping_ms']} ms {suffix}"
            elif node.get("alive") is False and not is_ph:
                endpoint += f"  •  {node.get('probe_result') or 'таймаут'} ✖"

            cb_state = str(node.get("cb_state") or "closed")
            proto_ok = node.get("protocol_ok", True)
            if is_ph:
                health_txt = "ℹ Служебный (не сервер)"
                row_tag = "muted"
            elif not enabled:
                health_txt = "⏸ Отключён"
                row_tag = "muted"
            elif cb_state == "open":
                health_txt = "🔴 Карантин (block)" if not proto_ok else "🔴 Карантин"
                row_tag = "bad"
            elif cb_state == "half_open":
                health_txt = "🟡 Проверка восстановления"
                row_tag = "warn"
            elif node.get("alive") is False:
                health_txt = "🟠 Сбой (недоступен)"
                row_tag = "warn"
            elif node.get("alive"):
                health_txt = "🟢 Активен" if is_active else "🟢 Доступен"
                row_tag = "ok"
                alive_cnt += 1
            else:
                health_txt = "🟢 Активен" if is_active else "● Готов"
                row_tag = "ok"

            self.vpn_tree.insert(
                "",
                "end",
                iid=iid,
                values=(
                    prio_txt,
                    shown,
                    str(node.get("region") or "other").upper(),
                    node.get("protocol", ""),
                    node.get("transport", "tcp"),
                    endpoint,
                    health_txt,
                ),
                tags=(row_tag,),
            )

        if restore_iid:
            self.vpn_tree.selection_set(restore_iid)

        mode_lbl = (
            f"Приоритет ({pref_tag})"
            if (mode == "priority" and pref_tag)
            else ("Приоритетный" if mode == "priority" else "Автовыбор (внутри VPN)")
        )
        active_lbl = f" • Активен: {active_vpn_node}" if active_vpn_node else ""
        alive_lbl = f", доступных: {alive_cnt}" if alive_cnt else ""
        ph_lbl = f", служебных: {ph_cnt}" if ph_cnt else ""
        self._vpn_summary_lbl.configure(
            text=f"Режим: {mode_lbl}{active_lbl} • Серверов: {real_cnt}{alive_lbl}{ph_lbl}"
        )
        self._sync_vpn_mode_combo()
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
        if self._closed or self._exiting:
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

        self._power_transition = "starting"
        if hasattr(self, "autopilot_btn"):
            self._restyle_button(self.autopilot_btn, "⠋ ЗАПУСК ЗАЩИТЫ…", "hero_active")
        self._progress_update()

        def _restore_power_btn(active: bool) -> None:
            self._power_transition = None
            if hasattr(self, "autopilot_btn"):
                if active:
                    self._restyle_button(self.autopilot_btn, "ОТКЛЮЧИТЬ ЗАЩИТУ  ⏻", "hero_active")
                else:
                    self._restyle_button(self.autopilot_btn, "ВКЛЮЧИТЬ ЗАЩИТУ  ⏻", "hero")

        def done(res: dict[str, Any]) -> None:
            _restore_power_btn(bool(res.get("ok")))
            self.log_console(dumps_pretty(res))
            if res.get("live_connections") is not None:
                self.populate_connections_table(res["live_connections"])
            if res.get("orchestrators"):
                self.update_layer_cards(res["orchestrators"])
            if res.get("ok"):
                self.radar_enabled = True
                self._restyle_button(self.radar_btn, "⏹ Остановить мониторинг", "danger")
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

        def on_err(_exc: Exception) -> None:
            _restore_power_btn(bool(self.last_snapshot.get("running")))

        self.run_bg("Запуск защиты (Автопилот)", lambda: self.backend.start_autopilot(iface=iface), done, on_err=on_err)

    def on_stop(self) -> None:
        self._power_transition = "stopping"
        if hasattr(self, "autopilot_btn"):
            self._restyle_button(self.autopilot_btn, "⠋ ОСТАНОВКА…", "hero")
        self._progress_update()

        def done(stopped: list[str]) -> None:
            self._power_transition = None
            if hasattr(self, "autopilot_btn"):
                self._restyle_button(self.autopilot_btn, "ВКЛЮЧИТЬ ЗАЩИТУ  ⏻", "hero")
            self.log_console("Остановлено: " + (", ".join(stopped) if stopped else "ничего не запущено"))
            self._after_change()

        def on_err(_exc: Exception) -> None:
            self._power_transition = None
            if hasattr(self, "autopilot_btn"):
                running = bool(self.last_snapshot.get("running"))
                self._restyle_button(
                    self.autopilot_btn,
                    "ОТКЛЮЧИТЬ ЗАЩИТУ  ⏻" if running else "ВКЛЮЧИТЬ ЗАЩИТУ  ⏻",
                    "hero_active" if running else "hero",
                )

        self.run_bg("Остановка защиты", self.backend.stop_services, done, on_err=on_err)

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

    def on_force_apply_pending(self) -> None:
        try:
            iface = self._iface()
        except ValueError as exc:
            self.set_status(str(exc), ERR_TEXT)
            return

        def done(res: dict[str, Any]) -> None:
            reloaded = res.get("reloaded") or []
            vpn_sw = res.get("vpn_switched")
            parts: list[str] = []
            if reloaded:
                parts.append(f"перезагружено: {', '.join(reloaded)}")
            if vpn_sw:
                parts.append(f"VPN -> {vpn_sw}")
            summary = "; ".join(parts) if parts else "конфиги обновлены"
            self.log_console(f"[APPLY] Новые правила принудительно применены ({summary})")
            self.set_status(f"Правила применены ({summary})", OK_TEXT)
            self._after_change()

        self.run_bg("Применение новых правил", lambda: self.backend.force_apply_pending_changes(iface=iface), done)

    def _format_deps_status(self, res: dict[str, Any]) -> None:
        if res.get("fetch_error"):
            self.set_status(f"Ошибка скачивания компонентов: {res['fetch_error']}", ERR_TEXT)
        elif res.get("ok"):
            if res.get("downloaded"):
                self.set_status("Недостающие компоненты скачаны и проверены", OK_TEXT)
            else:
                self.set_status("Все компоненты проверены и готовы к работе", OK_TEXT)
        else:
            self.set_status("Часть компонентов повреждена или отсутствует", WARN_TEXT)

    def _ensure_deps_on_startup(self) -> None:
        manifest = self.backend.bin_dir / "manifest.json"
        has_outdated = hasattr(self.backend, "has_outdated_pinned_bins") and self.backend.has_outdated_pinned_bins()
        if self.backend.has_core_binaries() and manifest.is_file() and not has_outdated:
            return

        def done(res: dict[str, Any]) -> None:
            self.log_console("Автодокачка компонентов:\n" + dumps_pretty(res))
            self._format_deps_status(res)

        self.run_bg("Автодокачка компонентов", self.backend.ensure_deps, done)

    def _apply_update_check_result(self, info: dict[str, Any], *, silent: bool = False) -> None:
        self._last_update_info = dict(info or {})
        cur = str(info.get("current_version") or __version__)
        latest = str(info.get("latest_version") or cur)
        mode_raw = str(info.get("install_mode") or "portable")
        mode_label = "git" if mode_raw == "git" else "ZIP"

        if info.get("ok") and info.get("update_available"):
            self.version_info_label.configure(
                text=f"Версия: v{cur} ({mode_label}) · Доступно обновление v{latest}",
                fg=ACCENT,
            )
            self._restyle_button(self.update_badge_btn, f"↑ v{latest}", "primary")
            if not self.update_badge_btn.winfo_manager():
                self.update_badge_btn.pack(side="right", padx=(0, 8))
            if not self.apply_update_btn.winfo_manager():
                self.apply_update_btn.pack(side="right", padx=(0, 6))
            if not silent:
                self.set_status(f"Доступно обновление netdoctor v{latest}", ACCENT)
            return

        if self.update_badge_btn.winfo_manager():
            self.update_badge_btn.pack_forget()
        if self.apply_update_btn.winfo_manager():
            self.apply_update_btn.pack_forget()

        if info.get("ok"):
            self.version_info_label.configure(
                text=f"Версия: v{cur} ({mode_label}) · Установлена актуальная версия",
                fg=OK_TEXT,
            )
            if not silent:
                self.set_status(f"Установлена актуальная версия netdoctor v{cur}", OK_TEXT)
        else:
            err = str(info.get("error") or "ошибка сети")
            self.version_info_label.configure(
                text=f"Версия: v{cur} ({mode_label}) · Проверка не удалась",
                fg=WARN_TEXT,
            )
            if not silent:
                self.set_status(f"Не удалось проверить обновления: {err}", WARN_TEXT)

    def _check_updates_on_startup(self) -> None:
        if self._closed or self._exiting or not hasattr(self.backend, "check_updates"):
            return

        def runner() -> None:
            try:
                info = self.backend.check_updates(force=False)
            except Exception as exc:  # noqa: BLE001
                info = {"ok": False, "error": str(exc), "current_version": __version__}
            self._post(lambda res: self._apply_update_check_result(res, silent=True), info)

        threading.Thread(target=runner, name="gui-update-check", daemon=True).start()

    def on_check_updates(self) -> None:
        def done(info: dict[str, Any]) -> None:
            self.log_console("Проверка обновлений:\n" + dumps_pretty(info))
            self._apply_update_check_result(info, silent=False)

        self.run_bg("Проверка обновлений", lambda: self.backend.check_updates(force=True), done)

    def on_apply_update(self) -> None:
        info = self._last_update_info or {}
        latest = str(info.get("latest_version") or "").strip()
        mode_raw = str(info.get("install_mode") or "portable")
        mode_label = "git pull" if mode_raw == "git" else "ZIP-архив"
        prompt = (
            f"Обновить netdoctor до версии v{latest} ({mode_label})?\n\n"
            "На время обновления службы обхода будут остановлены, а затем программа перезапустится."
            if latest
            else f"Выполнить обновление netdoctor ({mode_label})?\n\n"
            "На время обновления службы обхода будут остановлены, а затем программа перезапустится."
        )
        if not messagebox.askyesno("Обновление netdoctor", prompt):
            return

        def done(res: dict[str, Any]) -> None:
            self.log_console("Обновление netdoctor:\n" + dumps_pretty(res))
            if not res.get("ok"):
                err = str(res.get("error") or "Неизвестная ошибка")
                self.set_status(f"Ошибка обновления: {err}", ERR_TEXT)
                messagebox.showerror("Ошибка обновления", err)
                return
            detail = str(res.get("detail") or "Обновление установлено")
            self.set_status(f"{detail} — перезапуск…", OK_TEXT)
            restart = self.backend.restart_gui_process()
            if restart.get("ok"):
                if not self._closed:
                    self.after(150, self.on_close)
            else:
                messagebox.showinfo("Обновление завершено", f"{detail}.\nПерезапустите программу вручную.")

        self.run_bg(
            "Обновление netdoctor",
            lambda: self.backend.apply_update(
                download_url=info.get("download_url") or None,
                target_version=latest or None,
            ),
            done,
        )

    def on_verify(self) -> None:
        def done(res: dict[str, Any]) -> None:
            self.log_console("Verify/Fetch Binaries:\n" + dumps_pretty(res))
            self._format_deps_status(res)

        self.run_bg("Проверка и докачка компонентов", self.backend.ensure_deps, done)

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

            def _apply(res: dict[str, Any] = st) -> None:
                self.autostart_var.set(bool(res.get("enabled")))
                if "auto_start_protection" in res:
                    self.autostart_protection_var.set(bool(res.get("auto_start_protection")))

            self._post(_apply)

        threading.Thread(target=runner, name="gui-autostart-chk", daemon=True).start()

    def _maybe_auto_start_protection(self) -> None:
        if self._closed or self._exiting or not _is_admin():
            return
        should_start = self._auto_start_stack or (
            hasattr(self.backend, "get_auto_start_protection") and self.backend.get_auto_start_protection()
        )
        if not should_start:
            return
        if hasattr(self.backend, "_collect_processes_state"):
            try:
                procs = self.backend._collect_processes_state()
                if bool((procs.get("winws2") or {}).get("running")):
                    return
            except Exception:  # noqa: BLE001
                pass
        self.on_start()

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
        sel_node = self._selected_vpn_node()
        if isinstance(sel_node, dict):
            is_ph = bool(sel_node["is_placeholder"]) if "is_placeholder" in sel_node else is_placeholder_node(sel_node)
            if is_ph:
                self.set_status(
                    "Служебная запись не является VPN-сервером — выберите сервер или снимите выделение для авто-ротации",
                    WARN_TEXT,
                )
                return
            if sel_node.get("tag"):
                target_tag = str(sel_node["tag"]).strip()

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

    def on_vpn_mode_change(self, _event: Any = None) -> None:
        if self._vpn_mode_syncing:
            return
        target_mode = "priority" if self.vpn_mode_var.get() == VPN_MODE_PRIORITY_LABEL else "auto"

        def done(res: dict[str, Any]) -> None:
            pol = res.get("policy") or {}
            self._vpn_policy = dict(pol) if isinstance(pol, dict) else self._vpn_policy
            rec = res.get("reconcile") or {}
            sel = rec.get("selected") or (self._vpn_policy.get("priority_node") if target_mode == "priority" else "vpn-auto")
            lbl = "Приоритетный" if target_mode == "priority" else "Автовыбор (внутри VPN)"
            self.log_console(f"Режим VPN: {lbl} (узел={sel or 'vpn-auto'})")
            self.set_status(f"Режим VPN: {lbl}", OK_TEXT)
            self._after_change()

        self.run_bg("Переключение режима VPN", lambda: self.backend.set_vpn_selection_mode(target_mode), done)

    def on_set_priority_vpn_node(self) -> None:
        node = self._selected_vpn_node()
        if not node or not node.get("tag"):
            self.set_status("Сначала выберите сервер в таблице VPN", WARN_TEXT)
            return
        is_ph = bool(node["is_placeholder"]) if "is_placeholder" in node else is_placeholder_node(node)
        if is_ph:
            self.set_status("Служебную запись нельзя сделать приоритетным сервером", WARN_TEXT)
            return
        tag = str(node["tag"]).strip()

        def done(res: dict[str, Any]) -> None:
            pol = res.get("policy") or {}
            self._vpn_policy = dict(pol) if isinstance(pol, dict) else self._vpn_policy
            rec = res.get("reconcile") or {}
            live_sel = rec.get("selected") or tag
            self.log_console(f"Приоритетный VPN #1: {tag} (активный={live_sel})")
            self.set_status(f"Приоритетный VPN #1: {tag}", OK_TEXT)
            self._after_change()

        self.run_bg(f"Приоритет VPN ({tag})", lambda: self.backend.set_vpn_priority_node(tag), done)

    def on_move_vpn_priority(self, delta: int) -> None:
        node = self._selected_vpn_node()
        if not node or not node.get("tag"):
            self.set_status("Сначала выберите сервер в таблице VPN", WARN_TEXT)
            return
        is_ph = bool(node["is_placeholder"]) if "is_placeholder" in node else is_placeholder_node(node)
        if is_ph:
            self.set_status("Служебная запись не участвует в приоритетах", WARN_TEXT)
            return
        tag = str(node["tag"]).strip()

        def done(res: dict[str, Any]) -> None:
            pol = res.get("policy") or {}
            self._vpn_policy = dict(pol) if isinstance(pol, dict) else self._vpn_policy
            top = res.get("priority_node") or tag
            self.log_console(f"Обновлён приоритет VPN ({tag}) • #1: {top}")
            self.set_status(f"Приоритет VPN обновлён (#1: {top})", OK_TEXT)
            self._after_change()

        self.run_bg("Изменение приоритета VPN", lambda: self.backend.move_vpn_node_priority(tag, delta), done)

    def on_set_vpn_auto_mode(self) -> None:
        def done(res: dict[str, Any]) -> None:
            pol = res.get("policy") or {}
            self._vpn_policy = dict(pol) if isinstance(pol, dict) else self._vpn_policy
            self.log_console("Режим VPN переключён на автовыбор (внутри VPN)")
            self.set_status("Режим VPN: автовыбор (внутри VPN)", OK_TEXT)
            self._after_change()

        self.run_bg("Автовыбор VPN-сервера", lambda: self.backend.set_vpn_selection_mode("auto"), done)

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
            if "auto_start_protection" in res:
                self.autostart_protection_var.set(bool(res.get("auto_start_protection")))
            if res.get("ok"):
                if res.get("enabled"):
                    suffix = " (с автозапуском защиты)" if res.get("auto_start_protection") else " (только приложение)"
                    self.set_status(f"Автозапуск с Windows включён{suffix}", OK_TEXT)
                else:
                    self.set_status("Автозапуск с Windows отключён", OK_TEXT)
            else:
                self.autostart_var.set(bool(res.get("enabled")))
                self.set_status(f"Автозапуск: {res.get('error', 'ошибка настройки')}", WARN_TEXT)

        self.run_bg("Настройка автозапуска Windows", lambda: self.backend.set_autostart(enabled), done)

    def on_toggle_autostart_protection(self) -> None:
        enabled = bool(self.autostart_protection_var.get())

        def done(res: dict[str, Any]) -> None:
            if res.get("ok"):
                state = "включён" if res.get("auto_start_protection") else "выключен"
                self.set_status(f"Автозапуск защиты при старте {state}", OK_TEXT)
            else:
                self.set_status(f"Автозапуск защиты: {res.get('error', 'ошибка')}", WARN_TEXT)
            self._after_change()

        self.run_bg(
            "Настройка автозапуска защиты",
            lambda: self.backend.set_auto_start_protection(enabled),
            done,
        )

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
            self._restyle_button(btn, btn.cget("text"), "pill_active" if pid == flt else "neutral")
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
        self._preset_cb_syncing = True
        try:
            if self.active_preset_id in id_to_label:
                self.home_preset_var.set(id_to_label[self.active_preset_id])
            else:
                self.home_preset_var.set(auto_label)
        finally:
            self._preset_cb_syncing = False

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
        presets_dir = Path.cwd() / "presets" / "zapret2"
        default_dir = str(presets_dir) if presets_dir.is_dir() else str(Path.cwd())
        dpath = filedialog.askdirectory(title="Выберите папку с пресетами Zapret", initialdir=default_dir)
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
        dpi_only = bool(self.dpi_only_var.get())
        mode = "dpi_only" if dpi_only else "hybrid"
        if hasattr(self, "home_stack_mode_var"):
            self._stack_mode_syncing = True
            try:
                self.home_stack_mode_var.set(self._stack_mode_labels[1 if dpi_only else 0])
            finally:
                self._stack_mode_syncing = False

        def done(res: dict[str, Any]) -> None:
            txt = "Без VPN (только обход DPI + TG)" if res.get("stack_mode") == "dpi_only" else "Гибрид (Обход DPI + точечный VPN)"
            self.log_console(f"Режим маршрутизации: {txt}")
            self.set_status(f"Режим маршрутизации: {txt}", OK_TEXT)
            self._after_change()

        self.run_bg("Переключение режима маршрутизации", lambda: self.backend.set_stack_mode(mode), done)

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
