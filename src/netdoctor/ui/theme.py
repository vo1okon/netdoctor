"""Design tokens, palettes, fonts, and pure formatting helpers for netdoctor UI."""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any

# Dark palette (default — Deep Obsidian Indigo, Electric Cyan & Periwinkle Lavender)
DARK_PALETTE: dict[str, str] = {
    "BG": "#090A14",
    "SIDEBAR_BG": "#0D0F1D",
    "HEADER_BG": "#0B0D19",
    "CARD": "#121528",
    "CARD_ALT": "#171B32",
    "CARD_ACTIVE": "#152238",
    "INFO_BG": "#13263A",
    "INPUT": "#181C34",
    "INPUT_HOVER": "#212747",
    "BORDER": "#252B4A",
    "BORDER_LIGHT": "#353E6B",
    "CYAN_BORDER": "#22B8CF",
    "FG": "#F4F6FF",
    "FG_SOFT": "#C9D1EC",
    "MUTED": "#8590B3",
    "DIM": "#566080",
    "ACCENT": "#38E2F7",
    "LAVENDER": "#B69DF8",
    "LAVENDER_HOVER": "#C9B6FA",
    "LAVENDER_DARK": "#0D0F1E",
    "PILL_ACTIVE_BG": "#32295E",
    "PILL_ACTIVE_BORDER": "#8B74E8",
    "PRIMARY_BG": "#352B66",
    "PRIMARY_HOVER": "#453882",
    "SELECT_BG": "#2C2654",
    "OK": "#22D3EE",
    "OK_TEXT": "#38E2F7",
    "OK_BG": "#102837",
    "OK_BTN": "#1599B2",
    "OK_BTN_HOVER": "#22B8CF",
    "WARN": "#F59E0B",
    "WARN_TEXT": "#FBBF24",
    "WARN_BG": "#291F12",
    "WARN_BTN": "#D97706",
    "WARN_BTN_HOVER": "#F59E0B",
    "ERR": "#F43F5E",
    "ERR_TEXT": "#FB7185",
    "ERR_BG": "#281320",
    "ERR_BTN": "#4C182B",
    "ERR_BTN_HOVER": "#6D213C",
    "PURPLE": "#B69DF8",
    "PURPLE_BG": "#221C3E",
}

LIGHT_PALETTE: dict[str, str] = {
    "BG": "#F4F6FB",
    "SIDEBAR_BG": "#E9EDF7",
    "HEADER_BG": "#FFFFFF",
    "CARD": "#FFFFFF",
    "CARD_ALT": "#F0F4FC",
    "CARD_ACTIVE": "#E6F6FA",
    "INFO_BG": "#E8F4FD",
    "INPUT": "#F7F9FD",
    "INPUT_HOVER": "#EAEFF9",
    "BORDER": "#D5DCEA",
    "BORDER_LIGHT": "#B9C5DC",
    "CYAN_BORDER": "#0891B2",
    "FG": "#111827",
    "FG_SOFT": "#334155",
    "MUTED": "#64748B",
    "DIM": "#94A3B8",
    "ACCENT": "#0284C7",
    "LAVENDER": "#6D28D9",
    "LAVENDER_HOVER": "#5B21B6",
    "LAVENDER_DARK": "#FFFFFF",
    "PILL_ACTIVE_BG": "#EDE9FE",
    "PILL_ACTIVE_BORDER": "#7C3AED",
    "PRIMARY_BG": "#E0E7FF",
    "PRIMARY_HOVER": "#C7D2FE",
    "SELECT_BG": "#DBEAFE",
    "OK": "#0891B2",
    "OK_TEXT": "#0E7490",
    "OK_BG": "#E0F7FA",
    "OK_BTN": "#0891B2",
    "OK_BTN_HOVER": "#0E7490",
    "WARN": "#D97706",
    "WARN_TEXT": "#B45309",
    "WARN_BG": "#FEF3C7",
    "WARN_BTN": "#D97706",
    "WARN_BTN_HOVER": "#B45309",
    "ERR": "#E11D48",
    "ERR_TEXT": "#BE123C",
    "ERR_BG": "#FFE4E6",
    "ERR_BTN": "#E11D48",
    "ERR_BTN_HOVER": "#BE123C",
    "PURPLE": "#7C3AED",
    "PURPLE_BG": "#F3E8FF",
}

BG = DARK_PALETTE["BG"]
SIDEBAR_BG = DARK_PALETTE["SIDEBAR_BG"]
HEADER_BG = DARK_PALETTE["HEADER_BG"]
CARD = DARK_PALETTE["CARD"]
CARD_ALT = DARK_PALETTE["CARD_ALT"]
CARD_ACTIVE = DARK_PALETTE["CARD_ACTIVE"]
INFO_BG = DARK_PALETTE["INFO_BG"]
INPUT = DARK_PALETTE["INPUT"]
INPUT_HOVER = DARK_PALETTE["INPUT_HOVER"]
BORDER = DARK_PALETTE["BORDER"]
BORDER_LIGHT = DARK_PALETTE["BORDER_LIGHT"]
CYAN_BORDER = DARK_PALETTE["CYAN_BORDER"]

FG = DARK_PALETTE["FG"]
FG_SOFT = DARK_PALETTE["FG_SOFT"]
MUTED = DARK_PALETTE["MUTED"]
DIM = DARK_PALETTE["DIM"]

ACCENT = DARK_PALETTE["ACCENT"]
LAVENDER = DARK_PALETTE["LAVENDER"]
LAVENDER_HOVER = DARK_PALETTE["LAVENDER_HOVER"]
LAVENDER_DARK = DARK_PALETTE["LAVENDER_DARK"]
PILL_ACTIVE_BG = DARK_PALETTE["PILL_ACTIVE_BG"]
PILL_ACTIVE_BORDER = DARK_PALETTE["PILL_ACTIVE_BORDER"]
PRIMARY_BG = DARK_PALETTE["PRIMARY_BG"]
PRIMARY_HOVER = DARK_PALETTE["PRIMARY_HOVER"]
SELECT_BG = DARK_PALETTE["SELECT_BG"]

OK = DARK_PALETTE["OK"]
OK_TEXT = DARK_PALETTE["OK_TEXT"]
OK_BG = DARK_PALETTE["OK_BG"]
OK_BTN = DARK_PALETTE["OK_BTN"]
OK_BTN_HOVER = DARK_PALETTE["OK_BTN_HOVER"]

WARN = DARK_PALETTE["WARN"]
WARN_TEXT = DARK_PALETTE["WARN_TEXT"]
WARN_BG = DARK_PALETTE["WARN_BG"]
WARN_BTN = DARK_PALETTE["WARN_BTN"]
WARN_BTN_HOVER = DARK_PALETTE["WARN_BTN_HOVER"]

ERR = DARK_PALETTE["ERR"]
ERR_TEXT = DARK_PALETTE["ERR_TEXT"]
ERR_BG = DARK_PALETTE["ERR_BG"]
ERR_BTN = DARK_PALETTE["ERR_BTN"]
ERR_BTN_HOVER = DARK_PALETTE["ERR_BTN_HOVER"]

PURPLE = DARK_PALETTE["PURPLE"]
PURPLE_BG = DARK_PALETTE["PURPLE_BG"]

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
    ("cleanup_db", "Очистить мусорные правила БД", "Удаляет устаревшие незакреплённые direct/rDNS-записи из базы и пересобирает конфиги."),
    ("verify", "Проверить и докачать файлы", "Проверяет целостность рабочих модулей обхода и скачивает недостающие."),
)

VERDICT_EXPLANATIONS: dict[str, str] = {
    "ok": "Доступен напрямую — блокировок не обнаружено",
    "sni_dpi": "Блокировка HTTPS по имени сайта (SNI DPI)",
    "throttle": "Искусственное замедление скорости провайдером (TSPU)",
    "quic_block": "Блокировка быстрого протокола HTTP/3 (QUIC)",
    "dns_poison": "Подмена DNS-ответа провайдером",
    "ip_block": "Полная блокировка доступа по IP-адресу",
    "geo_block": "Геоблокировка сервиса (HTTP 403/451 — решается через SmartDNS / VPN)",
    "protocol_block": "Блокировка VPN / туннельного протокола",
    "unknown": "Таймаут или неизвестная сетевая ошибка",
}

BUNDLE_MODE_LABELS: dict[str, str] = {
    "direct_clean": "Напрямую (чистый)",
    "direct_dpi": "Напрямую + DPI",
    "vpn": "Через VPN",
}

_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_DOH_CERT_ERR_RE = re.compile(
    r"cannot validate certificate for ([0-9a-fA-F:.]+) because it doesn't contain any IP SANs",
    re.IGNORECASE,
)


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
            "Откройте «DNS» в режиме эксперта и выберите другой DNS (например Comss DNS или Control D)."
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
