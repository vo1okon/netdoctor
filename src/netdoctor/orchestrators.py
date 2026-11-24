"""Per-layer orchestrators (DNS, DPI, VPN), real-time connection analyzer, and master orchestrator."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import threading
import time
import urllib.parse
from collections import Counter, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable

import dns.asyncresolver
import psutil

from netdoctor.clash_api import ClashApiClient
from netdoctor.classifier import classify_probes
from netdoctor.dynamics import parse_circular_rotations, promote_fallback_on_failure
from netdoctor.models import (
    Decision,
    DiagnosticReport,
    NetworkFingerprint,
    Protocol,
    Strategy,
    VerdictClass,
)
from netdoctor.probes import (
    detect_bypass_active,
    detect_network_fingerprint,
    is_stub_ip,
    probe_dns,
    probe_tcp,
    run_domain_probes,
)
from netdoctor.selector import (
    DEFAULT_STRATEGIES,
    _ordered_pool,
    live_winws2_strategy_evaluator,
    load_targets_from_yaml,
    select_best_strategy,
)
from netdoctor.storage import Storage
from netdoctor.supervisor import _is_admin
from netdoctor.vpn import infer_node_region, is_auto_select_node, is_placeholder_node

_LOCAL_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
)

_INTERNAL_PROXY_PROCESSES = {
    "winws.exe",
    "winws2.exe",
    "ciadpi.exe",
    "sing-box.exe",
    "tgwsproxy_windows.exe",
}

PROTECTED_UNLOCKER_PROCESSES: tuple[str, ...] = (
    "Antigravity.exe",
    "language_server_windows_x64.exe",
    "Cursor.exe",
    "Windsurf.exe",
    "Code.exe",
    "xray.exe",
    "v2ray.exe",
    "mihomo.exe",
    "clash.exe",
    "happd.exe",
    "Happ.exe",
    "goodbyedpi.exe",
    "AmneziaVPN.exe",
    "AmneziaVPN-service.exe",
    "Zapret.exe",
    "ag_dns.exe",
)

ANTIGRAVITY_CRITICAL_DOMAINS: tuple[str, ...] = (
    "antigravity.google",
    "www.antigravity.google",
    "ai.google.dev",
    "aistudio.google.com",
    "daily-cloudcode-pa.googleapis.com",
    "generativelanguage.googleapis.com",
    "alkalicore-pa.clients6.google.com",
    "alkalimakersuite-pa.clients6.google.com",
    "appcatalyst.pa.googleapis.com",
    "geller-pa.googleapis.com",
    "developerprofiles-pa.googleapis.com",
    "assistant-s3-pa.googleapis.com",
    "aisandbox-pa.googleapis.com",
    "gemini.google.com",
    "gemini.google",
    "deepmind.com",
    "deepmind.google",
    "jules.google",
    "jules.google.com",
    "labs.google",
    "labs.google.com",
    "notebook.google",
    "notebook.google.com",
)


def parse_custom_exclusions(raw_text: str) -> dict[str, list[str]]:
    """Split user exclusions (comma/newline/semicolon separated) into processes, IPs/CIDRs, and domains."""
    processes: list[str] = []
    ips: list[str] = []
    domains: list[str] = []
    for token in re.split(r"[\s,;]+", raw_text or ""):
        item = token.strip()
        if not item or item.startswith("#"):
            continue
        if item.lower().endswith(".exe"):
            processes.append(item)
            continue
        try:
            ipaddress.ip_network(item, strict=False)
            ips.append(item)
            continue
        except ValueError:
            pass
        clean_dom = item.lower().strip(".")
        if "." in clean_dom:
            domains.append(clean_dom)
        else:
            processes.append(item)
    return {
        "processes": list(dict.fromkeys(processes)),
        "ips": list(dict.fromkeys(ips)),
        "domains": list(dict.fromkeys(domains)),
    }


_TELEGRAM_NETWORKS = (
    ipaddress.ip_network("91.108.4.0/22"),
    ipaddress.ip_network("91.108.8.0/22"),
    ipaddress.ip_network("91.108.12.0/22"),
    ipaddress.ip_network("91.108.16.0/22"),
    ipaddress.ip_network("91.108.20.0/22"),
    ipaddress.ip_network("91.108.56.0/22"),
    ipaddress.ip_network("91.105.192.0/23"),
    ipaddress.ip_network("149.154.160.0/20"),
    ipaddress.ip_network("185.76.151.0/24"),
)


def _is_telegram_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return False
    return any(addr in net for net in _TELEGRAM_NETWORKS)


_HOSTS_FILE_CACHE: dict[tuple[Any, ...], dict[str, Any]] = {}


def parse_windows_hosts_file(
    hosts_path: str | Path | None = None,
    core_targets: set[str] | None = None,
) -> dict[str, Any]:
    """Parse active entries in Windows hosts file to protect Antigravity Unlocker and similar hosts-based tools."""
    path = Path(hosts_path) if hosts_path is not None else Path(r"C:\Windows\System32\drivers\etc\hosts")
    use_cache = core_targets is None
    cache_key: tuple[Any, ...] | None = None
    if use_cache:
        try:
            hst = path.stat()
            hosts_sig: tuple[int, int] | None = (hst.st_mtime_ns, hst.st_size)
        except OSError:
            hosts_sig = None
        targets_file = Path("configs/targets.yaml")
        try:
            tst = targets_file.stat()
            targets_sig: tuple[int, int] | None = (tst.st_mtime_ns, tst.st_size)
        except OSError:
            targets_sig = None
        cache_key = (str(path), hosts_sig, targets_sig)
        cached = _HOSTS_FILE_CACHE.get(cache_key)
        if cached is not None:
            return {
                "domains": list(cached["domains"]),
                "proxy_ips": list(cached["proxy_ips"]),
                "domain_to_ips": {k: list(v) for k, v in cached["domain_to_ips"].items()},
                "path": cached["path"],
            }

    if core_targets is None:
        core_targets = {e["domain"].lower() for e in load_targets_from_yaml("configs/targets.yaml") if e.get("domain")}
        # Always include canonical + alias domains (especially Telegram t.me / telegram.me / telesco.pe)
        # so ZapretGUI/Telegram hosts entries never exclude Telegram DC IPs from winws2!
        for aliases, canonical in _DOMAIN_ALIASES:
            core_targets.add(canonical)
            core_targets.update(aliases)
        core_targets.update({"telegram.dog", "telegram.space", "tg.dev", "telegram-cdn.org", "telegramusercontent.com"})

    domains: set[str] = set()
    domain_to_ips: dict[str, list[str]] = {}
    proxy_ips: set[str] = set()

    if not path.is_file():
        result = {"domains": [], "proxy_ips": [], "domain_to_ips": {}, "path": str(path)}
        if cache_key is not None:
            if len(_HOSTS_FILE_CACHE) > 8:
                _HOSTS_FILE_CACHE.clear()
            _HOSTS_FILE_CACHE[cache_key] = result
        return {"domains": [], "proxy_ips": [], "domain_to_ips": {}, "path": str(path)}

    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {"domains": [], "proxy_ips": [], "domain_to_ips": {}, "path": str(path)}

    def _matches_core(host: str) -> bool:
        return any(host == t or host.endswith("." + t) for t in core_targets)

    for line in raw.splitlines():
        body = line.split("#", 1)[0].strip()
        if not body:
            continue
        parts = body.split()
        if len(parts) < 2:
            continue
        ip_tok = parts[0].strip()
        try:
            ipaddress.ip_address(ip_tok)
        except ValueError:
            continue

        ext_ip = _is_external_ip(ip_tok) and not _is_telegram_ip(ip_tok)
        for host_tok in parts[1:]:
            host = host_tok.strip().lower().rstrip(".")
            if not host or host in ("localhost", "local") or "." not in host:
                continue
            domain_to_ips.setdefault(host, []).append(ip_tok)
            if not _matches_core(host):
                domains.add(host)
                if ext_ip:
                    proxy_ips.add(ip_tok)

    result = {
        "domains": sorted(domains),
        "proxy_ips": sorted(proxy_ips),
        "domain_to_ips": domain_to_ips,
        "path": str(path),
    }
    if cache_key is not None:
        if len(_HOSTS_FILE_CACHE) > 8:
            _HOSTS_FILE_CACHE.clear()
        _HOSTS_FILE_CACHE[cache_key] = {
            "domains": list(result["domains"]),
            "proxy_ips": list(result["proxy_ips"]),
            "domain_to_ips": {k: list(v) for k, v in result["domain_to_ips"].items()},
            "path": result["path"],
        }
    return result


def build_unlocker_protection_context(
    storage: Storage | None = None,
    hosts_path: str | Path | None = None,
) -> dict[str, Any]:
    """Compute effective unlocker guard exclusions (protected processes, domains, and proxy IPs)."""
    enabled = storage.get_setting("unlocker_guard", "1") == "1" if storage is not None else True
    custom_raw = storage.get_setting("unlocker_exclusions", "") if storage is not None else ""
    if not enabled:
        return {
            "enabled": False,
            "processes": [],
            "domains": [],
            "proxy_ips": [],
            "hosts_domains_count": 0,
            "hosts_proxy_ips_count": 0,
            "protected_processes": list(PROTECTED_UNLOCKER_PROCESSES),
            "custom_exclusions": custom_raw,
        }

    hosts_info = parse_windows_hosts_file(hosts_path=hosts_path)
    custom = parse_custom_exclusions(custom_raw)
    all_domains = sorted(set(ANTIGRAVITY_CRITICAL_DOMAINS).union(hosts_info["domains"]).union(custom["domains"]))
    all_ips = sorted(set(hosts_info["proxy_ips"]).union(custom["ips"]))
    all_procs = list(dict.fromkeys([*PROTECTED_UNLOCKER_PROCESSES, *custom["processes"]]))
    return {
        "enabled": True,
        "processes": all_procs,
        "domains": all_domains,
        "proxy_ips": all_ips,
        "hosts_domains_count": len(hosts_info["domains"]),
        "hosts_proxy_ips_count": len(hosts_info["proxy_ips"]),
        "protected_processes": all_procs,
        "custom_exclusions": custom_raw,
        "hosts_path": hosts_info["path"],
    }

_DOMAIN_ALIASES: tuple[tuple[tuple[str, ...], str], ...] = (
    (("discord.gg", "discordapp.com", "discordapp.net", "discord.media", "discordcdn.com"), "discord.com"),
    (
        (
            "googlevideo.com",
            "youtu.be",
            "ytimg.com",
            "ggpht.com",
            "youtubei.googleapis.com",
            "youtube.googleapis.com",
            "youtube-nocookie.com",
            "yt3.googleusercontent.com",
        ),
        "youtube.com",
    ),
    (("t.me", "telegram.me", "telesco.pe", "tdesktop.com"), "telegram.org"),
    (("twimg.com", "twitter.com"), "x.com"),
    (("cdninstagram.com", "ig.me"), "instagram.com"),
)

_LOG_DOMAIN_IP_RE = re.compile(
    r"\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9-]{1,63})*\.[a-z]{2,})(?::\d{1,5})?(?:\s*(?:->|=>|ip=|:)\s*|\s+)(\d{1,3}(?:\.\d{1,3}){3})\b",
    re.IGNORECASE,
)
_WINWS2_IP_HOST_RE = re.compile(
    r"\bip=(\d{1,3}(?:\.\d{1,3}){3})\b[^\r\n]*?\bhostname='([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9-]{1,63})*\.[a-z]{2,})'",
    re.IGNORECASE,
)
_LOG_HOSTNAME_RE = re.compile(
    r"\b(?:host|hostname|sni|domain)[=:\s]+([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9-]{1,63})*\.[a-z]{2,})\b",
    re.IGNORECASE,
)
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_SINGBOX_CONN_ERR_RE = re.compile(
    r"open connection to (?:\[([0-9a-fA-F:]+)\]|(\d{1,3}(?:\.\d{1,3}){3})|[a-z0-9.-]+):(\d{1,5})\b[^\r\n]*?(?:i/o timeout|connection reset|EOF|refused|forcibly closed|context deadline exceeded)",
    re.IGNORECASE,
)
_SINGBOX_DIAL_IP_RE = re.compile(
    r"\bdial (?:tcp|udp)[46]?\s+(?:\[([0-9a-fA-F:]+)\]|(\d{1,3}(?:\.\d{1,3}){3})):(\d{1,5})\b",
    re.IGNORECASE,
)
_SINGBOX_ARROW_IP_RE = re.compile(
    r"->(?:\[([0-9a-fA-F:]+)\]|(\d{1,3}(?:\.\d{1,3}){3})):(\d{1,5})\b",
)


_TELEMETRY_NOISE_SUFFIXES: tuple[str, ...] = (
    "aka.ms",
    "nel.cloudflare.com",
    "nelreports.net",
    "windowsupdate.com",
    "update.microsoft.com",
    "events.data.microsoft.com",
    "telemetry.microsoft.com",
    "dsp.mp.microsoft.com",
    "msedge.net",
    "trafficmanager.net",
    "msftconnecttest.com",
    "msftncsi.com",
    "cloudmessaging.edge.microsoft.com",
    "update.googleapis.com",
    "api.met.no",
    "glasswire.com",
    "digicert.com",
    "sectigo.com",
    "pki.goog",
    "lencr.org",
)

_RDNS_PTR_SUFFIXES: tuple[str, ...] = (
    "1e100.net",
    "akamaitechnologies.com",
    "bc.googleusercontent.com",
    "compute.amazonaws.com",
    "compute-1.amazonaws.com",
    "in-addr.arpa",
    "ip6.arpa",
)
_RDNS_PTR_PREFIX_RE = re.compile(
    r"^(?:a\d+-\d+-\d+-\d+|ec2-\d+-\d+-\d+-\d+|server-\d+-\d+-\d+-\d+|(?:\d{1,3}-){3}\d{1,3})\.",
    re.IGNORECASE,
)


def _is_rdns_ptr_hostname(domain: str | None) -> bool:
    """Return True for reverse-DNS PTR infrastructure names whose SNI differs from real app SNI."""
    low = (domain or "").strip().lower().rstrip(".")
    if not low or low == "—":
        return False
    if _RDNS_PTR_PREFIX_RE.match(low):
        return True
    if low.startswith("server-") and low.endswith(".r.cloudfront.net"):
        return True
    return any(low == s or low.endswith("." + s) for s in _RDNS_PTR_SUFFIXES)


def _is_telemetry_noise_domain(domain: str | None) -> bool:
    """Return True for OS telemetry / CRL / OCSP / NCSI / rDNS PTR domains that should stay direct unless failing."""
    low = (domain or "").strip().lower().rstrip(".")
    if not low or low == "—":
        return False
    if _is_rdns_ptr_hostname(low):
        return True
    if low.startswith(("ocsp.", "crl.")):
        return True
    return any(low == s or low.endswith("." + s) for s in _TELEMETRY_NOISE_SUFFIXES)


def _is_ip_literal(value: str) -> bool:
    clean = (value or "").strip().strip("[]")
    if not clean:
        return False
    try:
        ipaddress.ip_address(clean)
        return True
    except ValueError:
        return False


def _parse_singbox_failed_ips(sb_tail: str) -> set[str]:
    failed: set[str] = set()
    if not sb_tail:
        return failed
    clean_tail = _ANSI_RE.sub("", sb_tail)
    for m in _SINGBOX_CONN_ERR_RE.finditer(clean_tail):
        ip_cand = m.group(1) or m.group(2)
        if not ip_cand:
            dial_m = _SINGBOX_DIAL_IP_RE.search(m.group(0))
            if dial_m:
                ip_cand = dial_m.group(1) or dial_m.group(2)
        if not ip_cand:
            arrow_m = _SINGBOX_ARROW_IP_RE.search(m.group(0))
            if arrow_m:
                ip_cand = arrow_m.group(1) or arrow_m.group(2)
        if ip_cand and _is_external_ip(ip_cand):
            failed.add(ip_cand)
    return failed


def _parse_clash_conn_age_sec(start_raw: Any, now_dt: datetime | None = None) -> float | None:
    """Parse Clash API RFC3339/ISO-8601 connection start timestamp and return age in seconds."""
    if not start_raw or not isinstance(start_raw, str):
        return None
    raw = start_raw.strip()
    if not raw:
        return None
    if raw.endswith(("Z", "z")):
        raw = raw[:-1] + "+00:00"
    raw = re.sub(r"\.(\d+)", lambda m: "." + (m.group(1)[:6]).ljust(6, "0"), raw)
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    cur = now_dt or datetime.now(timezone.utc).astimezone()
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=cur.tzinfo)
    return max(0.0, (cur - parsed).total_seconds())


def _node_has_healthy_connections(clash_conns: list[dict[str, Any]], node_tag: str) -> bool:
    """Return True if any live Clash connection through `node_tag` has bidirectional traffic."""
    clean_tag = (node_tag or "").strip()
    if not clean_tag or not clash_conns:
        return False
    for c in clash_conns:
        if not isinstance(c, dict):
            continue
        if clean_tag not in (c.get("chains") or []):
            continue
        try:
            up = int(c.get("upload") or 0)
            dn = int(c.get("download") or 0)
        except (TypeError, ValueError):
            continue
        if up > 0 and dn > 0:
            return True
    return False


def _is_external_ip(ip_str: str) -> bool:
    """Return True if ip_str is a routable/external address (keeps RFC 5737 test IPs for unit tests)."""
    clean = ip_str.split("%", 1)[0].strip()
    if not clean:
        return False
    try:
        addr = ipaddress.ip_address(clean)
    except ValueError:
        return False
    if addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified:
        return False
    return not any(addr in net for net in _LOCAL_NETWORKS)


_SHARED_CDN_ANYCAST_NETS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "104.16.0.0/12",
        "172.64.0.0/13",
        "188.114.96.0/22",
        "162.158.0.0/15",
        "198.41.128.0/17",
        "108.162.192.0/18",
        "141.101.64.0/18",
        "190.93.240.0/20",
        "197.234.240.0/22",
    )
)


def _is_shared_cdn_anycast_ip(ip_str: str) -> bool:
    """Return True for multi-tenant shared CDN anycast IPs (e.g. Cloudflare) unsafe to attribute from history."""
    clean = ip_str.split("%", 1)[0].strip()
    if not clean:
        return False
    try:
        addr = ipaddress.ip_address(clean)
    except ValueError:
        return False
    return any(addr in net for net in _SHARED_CDN_ANYCAST_NETS)


def _tail_text(path: Path, max_bytes: int = 32768) -> str:
    if not path.is_file():
        return ""
    try:
        size = path.stat().st_size
        with path.open("rb") as f:
            if size > max_bytes:
                f.seek(size - max_bytes)
            return f.read(max_bytes).decode("utf-8", errors="replace")
    except OSError:
        return ""


def _match_decision_domain(host: str | None, decisions_map: dict[tuple[str, str], Decision]) -> tuple[str | None, Decision | None]:
    """Match an observed domain/hostname against exact or parent/alias decisions."""
    if not host:
        return None, None
    low = host.lower().strip(".")
    for proto in ("tls", "quic", "http"):
        if (low, proto) in decisions_map:
            return low, decisions_map[(low, proto)]

    # Check subdomain suffixes (e.g. gateway.discord.gg -> discord.gg -> discord.com)
    parts = low.split(".")
    for idx in range(1, len(parts) - 1):
        suffix = ".".join(parts[idx:])
        for proto in ("tls", "quic", "http"):
            if (suffix, proto) in decisions_map:
                return suffix, decisions_map[(suffix, proto)]

    for aliases, canonical in _DOMAIN_ALIASES:
        if low == canonical or any(low == a or low.endswith("." + a) for a in aliases):
            for proto in ("tls", "quic", "http"):
                if (canonical, proto) in decisions_map:
                    return canonical, decisions_map[(canonical, proto)]
            return canonical, None

    return low, None


DNS_CATEGORIES: tuple[tuple[str, str, str], ...] = (
    ("popular", "Популярные", "Базовые мировые и российские DNS"),
    ("security", "Безопасные", "Защита от вирусов, рекламы или 18+"),
    ("uncommon", "Малоизвестные", "реже попадают под блокировки"),
    ("ai_bypass", "Для ИИ", "серверы сообщества — ChatGPT, Claude, Grok, Spotify"),
    ("custom", "Мои DNS", "добавленные пользователем вручную"),
)


def _dns(
    dns_id: str,
    name: str,
    ip: str,
    description: str,
    category: str,
    badges: list[str],
    doh_url: str = "",
    *,
    doh_broken: bool = False,
) -> dict[str, Any]:
    return {
        "id": dns_id,
        "name": name,
        "ip": ip,
        "description": description,
        "category": category,
        "badges": badges,
        "doh_url": doh_url,
        "builtin": True,
        "doh_broken": doh_broken,
    }


BUILTIN_DNS_CATALOG: list[dict[str, Any]] = [
    # Популярные (3)
    _dns("cloudflare", "Cloudflare", "1.1.1.1", "Быстрый и приватный", "popular", ["блокируется", "DNSSEC", "IPv6", "DoH"], "https://1.1.1.1/dns-query"),
    _dns("google", "Google DNS", "8.8.8.8", "Надёжный", "popular", ["блокируется", "DNSSEC", "IPv6", "DoH"], "https://8.8.8.8/dns-query"),
    _dns("yandex", "Яндекс DNS", "77.88.8.8", "Российский, быстрый", "popular", ["IPv6", "DoH"], "https://common.dot.dns.yandex.net/dns-query"),
    # Безопасные (10)
    _dns("quad9", "Quad9", "9.9.9.9", "Антивирус", "security", ["DNSSEC", "IPv6", "DoH"], "https://dns.quad9.net/dns-query"),
    _dns("adguard", "AdGuard", "94.140.14.14", "Без рекламы", "security", ["под угрозой", "DNSSEC", "IPv6", "DoH"], "https://dns.adguard-dns.com/dns-query"),
    _dns("adguard_family", "AdGuard Семейный", "94.140.14.15", "Без рекламы и 18+", "security", ["под угрозой", "DNSSEC", "IPv6", "DoH"], "https://family.adguard-dns.com/dns-query"),
    _dns("opendns", "OpenDNS", "208.67.222.222", "Фильтрация", "security", ["под угрозой", "DNSSEC", "IPv6", "DoH"], "https://doh.opendns.com/dns-query"),
    _dns("yandex_safe", "Яндекс Безопасный", "77.88.8.88", "Антивирус, российский", "security", ["IPv6", "DoH"], "https://safe.dot.dns.yandex.net/dns-query"),
    _dns("yandex_family", "Яндекс Семейный", "77.88.8.7", "Без 18+, российский", "security", ["IPv6", "DoH"], "https://family.dot.dns.yandex.net/dns-query"),
    _dns("bizone", "BI.ZONE", "185.191.32.7", "Антивирус, российский", "security", ["IPv6"], ""),
    _dns("dns4eu_protective", "DNS4EU Защитный", "86.54.11.1", "Антивирус, Евросоюз", "security", ["DNSSEC", "IPv6", "DoH"], "https://protective.joindns4.eu/dns-query"),
    _dns("cleanbrowsing", "CleanBrowsing", "185.228.168.9", "Антивирус", "security", ["DNSSEC", "IPv6", "DoH"], "https://doh.cleanbrowsing.org/doh/security-filter/"),
    _dns("controld_adblock", "Control D Без рекламы", "76.76.2.2", "Без рекламы и слежки", "security", ["IPv6", "DoH"], "https://freedns.controld.com/p2"),
    _dns("cf_security", "Cloudflare Security", "1.1.1.2", "Защита от вредоносных сайтов", "security", ["DNSSEC", "IPv6", "DoH"], "https://security.cloudflare-dns.com/dns-query"),
    _dns("nextdns", "NextDNS", "45.90.28.0", "Настраиваемая защита и DoH", "security", ["DNSSEC", "IPv6", "DoH"], "https://dns.nextdns.io"),
    # Малоизвестные (16) — реже попадают под блокировки
    _dns("dnssb", "Dns.SB", "185.222.222.222", "Без цензуры", "uncommon", ["DNSSEC", "IPv6", "DoH"], "https://doh.dns.sb/dns-query"),
    _dns("dnsdoh_art", "dnsdoh.art", "194.180.189.33", "Без рекламы и записи", "uncommon", ["DNSSEC", "DoH"], "https://dnsdoh.art/dns-query"),
    _dns("controld_free", "Control D", "76.76.2.0", "Без фильтров и записи", "uncommon", ["IPv6", "DoH"], "https://freedns.controld.com/p0"),
    _dns("dns4eu", "DNS4EU", "86.54.11.100", "Без фильтров, Евросоюз", "uncommon", ["DNSSEC", "IPv6", "DoH"], "https://unfiltered.joindns4.eu/dns-query"),
    _dns("gcore", "Gcore", "95.85.95.85", "Быстрый, без записи", "uncommon", ["DNSSEC", "IPv6", "DoH"], "https://dns.gcorelabs.com/dns-query"),
    _dns("dnswatch", "DNS.Watch", "84.200.69.80", "Без цензуры и записи", "uncommon", ["DNSSEC", "IPv6"], ""),
    _dns("ultradns", "UltraDNS", "64.6.64.6", "Надёжный, без фильтров", "uncommon", ["DNSSEC", "IPv6"], ""),
    _dns("cznic", "CZ.NIC", "193.17.47.1", "Без фильтров, Чехия", "uncommon", ["DNSSEC", "IPv6", "DoH"], "https://odvr.nic.cz/doh"),
    _dns("cira", "CIRA Canadian Shield", "149.112.121.10", "Без фильтров, Канада", "uncommon", ["DNSSEC", "IPv6", "DoH"], "https://private.canadianshield.cira.ca/dns-query"),
    _dns("freifunk_munich", "Freifunk München", "5.1.66.255", "Без цензуры и записи", "uncommon", ["DNSSEC", "IPv6", "DoH"], "https://doh.ffmuc.net/dns-query"),
    _dns("stormycloud", "StormyCloud", "23.128.248.2", "Без цензуры и записи", "uncommon", ["DNSSEC", "IPv6"], ""),
    _dns("dnsforge", "dnsforge.de", "176.9.93.198", "Без рекламы и записи", "uncommon", ["DNSSEC", "IPv6", "DoH"], "https://dnsforge.de/dns-query"),
    _dns("surfshark_dns", "Surfshark DNS", "194.169.169.169", "Без записи запросов", "uncommon", ["DNSSEC", "IPv6"], ""),
    _dns("wikimedia_dns", "Wikimedia DNS", "185.71.138.138", "Без фильтров, Википедия", "uncommon", ["DNSSEC", "IPv6", "DoH"], "https://wikimedia-dns.org/dns-query"),
    _dns("rethinkdns", "RethinkDNS", "104.21.83.62", "Без цензуры, быстрый DoH", "uncommon", ["DNSSEC", "DoH"], "https://sky.rethinkdns.com/dns-query"),
    _dns("libredns", "LibreDNS", "116.202.176.26", "Без цензуры и логов, Греция", "uncommon", ["DNSSEC", "DoH"], "https://doh.libredns.gr/dns-query"),
    # Для ИИ (12) — серверы сообщества
    _dns("zapret_dns", "Zapret DNS", "188.114.97.1", "Нейросети и Spotify (устар. DoH)", "ai_bypass", ["DNSSEC", "DoH"], "https://188.114.97.1/dns-query", doh_broken=True),
    _dns("comss_dns", "Comss DNS", "141.133.184.24", "Нейросети, без рекламы", "ai_bypass", ["DoH"], "https://dns.comss.one/dns-query"),
    _dns("astracat", "AstraCat", "135.186.217.200", "ChatGPT, без рекламы", "ai_bypass", ["DNSSEC"], ""),
    _dns("geohide", "GeoHide", "193.233.112.67", "ChatGPT, Grok, Notion (нестаб. DoH)", "ai_bypass", ["DoH"], "https://193.233.112.67/dns-query", doh_broken=True),
    _dns("geohide_eu", "GeoHide EU", "5.175.161.3", "ChatGPT, узлы в Европе (нестаб. DoH)", "ai_bypass", ["DoH"], "https://5.175.161.3/dns-query", doh_broken=True),
    _dns("geohide_us", "GeoHide US", "192.255.159.240", "ChatGPT, узлы в США", "ai_bypass", ["DoH"], "https://192.255.159.240/dns-query"),
    _dns("malw_link", "Malw.link", "179.254.166.171", "Нейросети и сайты", "ai_bypass", ["DNSSEC", "DoH"], "https://dns.malw.link/dns-query"),
    _dns("bezmezhau", "Bezmezhau", "143.20.64.55", "ChatGPT и Claude (устар. DoH)", "ai_bypass", ["DoH"], "https://143.20.64.55/dns-query", doh_broken=True),
    _dns("dns_ai", "DNS-AI", "192.144.59.14", "Нейросети, без рекламы (устар. DoH)", "ai_bypass", ["DNSSEC", "IPv6", "DoH"], "https://192.144.59.14/dns-query", doh_broken=True),
    _dns("xbox_dns", "Xbox DNS", "176.99.11.77", "SmartDNS для Xbox, игр и ИИ", "ai_bypass", ["SmartDNS"], ""),
    _dns("comss_east", "Comss DNS (East)", "212.109.221.20", "Нейросети и игры, резерв East", "ai_bypass", ["DoH"], "https://dns.comss.one/dns-query"),
    _dns("comss_west", "Comss DNS (West)", "141.133.183.77", "Нейросети и игры, резерв West", "ai_bypass", ["DoH"], "https://dns.comss.one/dns-query"),
]


SERVICE_PRESETS: dict[str, dict[str, Any]] = {
    "discord": {
        "id": "discord",
        "title": "🎮 Discord + Голос",
        "domains": ["discord.com", "discord.gg", "discordapp.com"],
        "enable_game_filter": True,
        "recommended_dns": None,
    },
    "youtube": {
        "id": "youtube",
        "title": "▶ YouTube 4K",
        "domains": ["youtube.com", "googlevideo.com", "ytimg.com"],
        "enable_game_filter": False,
        "recommended_dns": None,
    },
    "ai": {
        "id": "ai",
        "title": "🤖 ChatGPT / Claude / ИИ",
        "domains": ["chatgpt.com", "openai.com", "claude.ai"],
        "enable_game_filter": False,
        "recommended_dns": "comss_dns",
    },
    "telegram": {
        "id": "telegram",
        "title": "✈ Telegram",
        "domains": ["telegram.org", "t.me", "telesco.pe"],
        "enable_game_filter": False,
        "recommended_dns": None,
    },
    "social": {
        "id": "social",
        "title": "📸 Instagram & X",
        "domains": ["instagram.com", "x.com"],
        "enable_game_filter": False,
        "recommended_dns": None,
    },
    "music": {
        "id": "music",
        "title": "🎵 Spotify & Twitch",
        "domains": ["spotify.com", "twitch.tv"],
        "enable_game_filter": False,
        "recommended_dns": "comss_dns",
    },
}

AI_GEOBLOCK_DOMAINS: tuple[str, ...] = (
    "chatgpt.com",
    "openai.com",
    "claude.ai",
    "anthropic.com",
    "grok.com",
    "x.ai",
    "gemini.google.com",
    "copilot.microsoft.com",
    "notion.so",
    "spotify.com",
    "canva.com",
    "login.live.com",
    "account.live.com",
    "xboxlive.com",
    "minecraftservices.com",
    "mojang.com",
)


def is_geoblock_or_ai_domain(domain: str) -> bool:
    """Return True if domain typically requires community geo-proxy / AI bypass DNS."""
    low = domain.lower().strip(".")
    return any(low == d or low.endswith("." + d) for d in AI_GEOBLOCK_DOMAINS)


class DnsLayerOrchestrator:
    """Layer 1 orchestrator: 36+ bypass & custom DNS catalog, DoH/DNS RTT probing, and DNS poison handling."""

    DOH_SERVERS: tuple[tuple[str, str], ...] = (
        ("1.1.1.1", "Cloudflare"),
        ("8.8.8.8", "Google"),
        ("9.9.9.9", "Quad9"),
    )

    def get_all_dns_servers(self, storage: Storage | None = None) -> list[dict[str, Any]]:
        """Return built-in 36 DNS servers plus user-defined custom DNS entries."""
        servers = [dict(item) for item in BUILTIN_DNS_CATALOG]
        if storage is not None:
            servers.extend(storage.get_custom_dns_list())
        return servers

    def get_active_dns(self, storage: Storage | None = None) -> dict[str, Any]:
        """Return currently selected DNS server dict (defaults to Cloudflare 1.1.1.1)."""
        servers = self.get_all_dns_servers(storage)
        active_id = storage.get_setting("active_dns_id", "cloudflare") if storage is not None else "cloudflare"
        for s in servers:
            if s["id"] == active_id:
                return s
        return servers[0]

    async def probe_dns_catalog(
        self,
        servers: list[dict[str, Any]],
        timeout: float = 1.2,
    ) -> list[dict[str, Any]]:
        """Concurrently probe TCP/443 (DoH) or TCP/53 latency for every DNS server in the catalog."""
        if not servers:
            return []

        sem = asyncio.Semaphore(16)

        async def _probe_one(srv: dict[str, Any]) -> dict[str, Any]:
            async with sem:
                ip = str(srv.get("ip") or "").strip()
                badges = list(srv.get("badges") or [])
                has_doh = ("DoH" in badges) or bool(srv.get("doh_url"))
                primary_port = 443 if has_doh else 53
                enriched = dict(srv)
                if not ip:
                    enriched["alive"] = False
                    enriched["ping_ms"] = None
                    enriched["probe_port"] = primary_port
                    return enriched

                res = await probe_tcp(ip, port=primary_port, timeout=timeout)
                used_port = primary_port
                if res.result != "ok" and primary_port == 443:
                    res53 = await probe_tcp(ip, port=53, timeout=min(timeout, 0.8))
                    if res53.result == "ok":
                        res = res53
                        used_port = 53
                enriched["alive"] = res.result == "ok"
                enriched["ping_ms"] = round(res.rtt_ms, 1) if res.rtt_ms is not None else None
                enriched["probe_port"] = used_port
                return enriched

        return await asyncio.gather(*(_probe_one(s) for s in servers))

    async def probe_dns_server_for_domain(
        self,
        domain: str,
        srv: dict[str, Any],
        baseline_ips: set[str] | None = None,
        timeout: float = 1.8,
    ) -> dict[str, Any]:
        """Resolve `domain` via a specific DNS server and verify TCP/443 reachability of returned IP."""
        t0 = time.perf_counter()
        resolved_ips: list[str] = []
        dns_ip = str(srv.get("ip") or "").strip()
        doh_url = str(srv.get("doh_url") or "").strip()
        has_https_doh = doh_url.startswith("https://")
        doh_host = (urllib.parse.urlparse(doh_url).hostname or "") if has_https_doh else ""
        doh_has_domain_sni = bool(doh_host and not self._is_ip_literal(doh_host))
        doh_ok = not has_https_doh

        if has_https_doh and doh_has_domain_sni:
            doh_res = await probe_dns(domain, doh_url=doh_url, timeout=timeout)
            if doh_res.doh == "ok":
                resolved_ips = [ip for ip in doh_res.doh_ips if not is_stub_ip(ip)]
                doh_ok = bool(resolved_ips)

        if not resolved_ips and dns_ip:
            try:
                resolver = dns.asyncresolver.Resolver(configure=False)
                resolver.nameservers = [dns_ip]
                resolver.port = 53
                resolver.lifetime = timeout
                ans = await resolver.resolve(domain, "A")
                resolved_ips = [r.address for r in ans if not is_stub_ip(r.address)]
            except Exception:
                resolved_ips = []

        if not resolved_ips and has_https_doh and not doh_has_domain_sni:
            doh_res = await probe_dns(domain, doh_url=doh_url, timeout=timeout)
            if doh_res.doh == "ok":
                resolved_ips = [ip for ip in doh_res.doh_ips if not is_stub_ip(ip)]
                doh_ok = bool(resolved_ips)

        if not resolved_ips:
            return {
                "dns_id": srv["id"],
                "name": srv["name"],
                "ip": dns_ip,
                "category": srv.get("category"),
                "ok": False,
                "doh_ok": False if has_https_doh else True,
                "resolved_ips": [],
                "rtt_ms": None,
                "is_proxy_ip": False,
            }

        if has_https_doh and not doh_has_domain_sni and not doh_ok:
            tcp_res, doh_check = await asyncio.gather(
                probe_tcp(resolved_ips[0], port=443, timeout=timeout),
                probe_dns(domain, doh_url=doh_url, timeout=min(timeout, 1.2)),
            )
            doh_ok = doh_check.doh == "ok" and any(not is_stub_ip(ip) for ip in doh_check.doh_ips)
        else:
            tcp_res = await probe_tcp(resolved_ips[0], port=443, timeout=timeout)

        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 1)
        is_proxy_ip = bool(baseline_ips and set(resolved_ips).isdisjoint(baseline_ips))
        return {
            "dns_id": srv["id"],
            "name": srv["name"],
            "ip": dns_ip,
            "category": srv.get("category"),
            "ok": tcp_res.result == "ok",
            "doh_ok": doh_ok,
            "resolved_ips": resolved_ips,
            "rtt_ms": elapsed_ms,
            "is_proxy_ip": is_proxy_ip,
        }

    @staticmethod
    def _is_ip_literal(value: str) -> bool:
        try:
            ipaddress.ip_address((value or "").strip().strip("[]"))
            return True
        except ValueError:
            return False

    async def roll_dns_for_domain(
        self,
        domain: str,
        network_key: str,
        storage: Storage | None = None,
        candidate_categories: tuple[str, ...] | None = None,
        probe_fn: Callable[[str, dict[str, Any]], Awaitable[dict[str, Any]]] | None = None,
        timeout: float = 1.8,
    ) -> Decision:
        """Concurrently test candidate bypass DNS servers for `domain` and pick the fastest working one."""
        clean_domain = domain.strip().lower()
        all_servers = self.get_all_dns_servers(storage)
        is_ai = is_geoblock_or_ai_domain(clean_domain)

        if candidate_categories is not None:
            pool = [s for s in all_servers if s.get("category") in candidate_categories]
        elif is_ai:
            top_uncommon_ids = {"dnssb", "gcore", "dns4eu", "controld_free"}
            pool = [
                s
                for s in all_servers
                if s.get("category") in ("ai_bypass", "custom") or s.get("id") in top_uncommon_ids
            ]
        else:
            pool = [s for s in all_servers if s.get("category") in ("custom", "uncommon", "popular", "security")]

        if not pool:
            pool = all_servers

        baseline_ips: set[str] = set()
        if probe_fn is None and is_ai:
            try:
                base_dns = await probe_dns(clean_domain, timeout=min(timeout, 1.2))
                baseline_ips = set(base_dns.system_ips or [])
            except Exception:
                baseline_ips = set()

        sem = asyncio.Semaphore(12)

        async def _eval(srv: dict[str, Any]) -> dict[str, Any]:
            async with sem:
                if probe_fn is not None:
                    res = dict(await probe_fn(clean_domain, srv))
                else:
                    res = await self.probe_dns_server_for_domain(
                        clean_domain, srv, baseline_ips=baseline_ips, timeout=timeout
                    )
                res.setdefault("doh_broken", bool(srv.get("doh_broken", False)))
                return res

        results = await asyncio.gather(*(_eval(s) for s in pool))
        passing = [r for r in results if r.get("ok")]

        if passing:
            if is_ai:
                passing.sort(
                    key=lambda r: (
                        0 if not r.get("doh_broken", False) else 1,
                        0 if r.get("doh_ok", True) else 1,
                        0 if r.get("category") in ("ai_bypass", "custom") else 1,
                        0 if r.get("is_proxy_ip") else 1,
                        0 if r.get("dns_id") == "comss_dns" else 1,
                        r.get("rtt_ms") if r.get("rtt_ms") is not None else 9999.0,
                        str(r.get("dns_id") or ""),
                    )
                )
            else:
                passing.sort(
                    key=lambda r: (
                        0 if not r.get("doh_broken", False) else 1,
                        0 if r.get("doh_ok", True) else 1,
                        0 if r.get("category") in ("custom", "uncommon") else 1,
                        r.get("rtt_ms") if r.get("rtt_ms") is not None else 9999.0,
                        str(r.get("dns_id") or ""),
                    )
                )
            winner = passing[0]
            fallbacks = [f"dns:{r['dns_id']}" for r in passing[1:3]]
            return Decision(
                network_key=network_key,
                domain=clean_domain,
                protocol=Protocol.TLS,
                layer="dns",
                strategy_id=f"dns:{winner['dns_id']}",
                fallback_strategies=fallbacks,
                ttfb_ms=winner.get("rtt_ms"),
            )

        # Heuristic fallback when all probes failed (e.g. offline)
        if is_ai:
            default_id, fb_ids = "comss_dns", ["dns:bezmezhau", "dns:geohide"]
        else:
            default_id, fb_ids = "dnssb", ["dns:gcore", "dns:cloudflare"]
        return Decision(
            network_key=network_key,
            domain=clean_domain,
            protocol=Protocol.TLS,
            layer="dns",
            strategy_id=f"dns:{default_id}",
            fallback_strategies=fb_ids,
        )

    async def roll_dns_for_domains_batch(
        self,
        domains: list[str],
        network_key: str,
        storage: Storage,
        probe_fn: Callable[[str, dict[str, Any]], Awaitable[dict[str, Any]]] | None = None,
        timeout: float = 1.8,
    ) -> list[Decision]:
        """Concurrently roll best per-domain bypass DNS servers across multiple domains and save to DB."""
        clean_domains = list(dict.fromkeys(d.strip().lower() for d in domains if d and d.strip()))
        decisions = await asyncio.gather(
            *(
                self.roll_dns_for_domain(
                    d,
                    network_key=network_key,
                    storage=storage,
                    probe_fn=probe_fn,
                    timeout=timeout,
                )
                for d in clean_domains
            )
        )
        for dec in decisions:
            storage.save_decision(dec)
        return decisions

    async def check_health(self, timeout: float = 2.0) -> dict[str, Any]:
        """Concurrently measure TCP/443 RTT to all configured DoH resolvers and choose fastest."""
        results = await asyncio.gather(
            *(probe_tcp(ip, port=443, timeout=timeout) for ip, _name in self.DOH_SERVERS)
        )
        resolvers: list[dict[str, Any]] = []
        for (ip, name), res in zip(self.DOH_SERVERS, results):
            resolvers.append(
                {
                    "ip": ip,
                    "name": name,
                    "ok": res.result == "ok",
                    "rtt_ms": round(res.rtt_ms, 1) if res.rtt_ms is not None else None,
                    "result": res.result,
                }
            )
        healthy = [r for r in resolvers if r["ok"]]
        healthy.sort(key=lambda r: r["rtt_ms"] if r["rtt_ms"] is not None else 9999.0)
        best = healthy[0] if healthy else None
        return {
            "layer": "dns",
            "status": "ok" if healthy else "degraded",
            "best_server": best["ip"] if best else "1.1.1.1",
            "best_name": best["name"] if best else "Cloudflare",
            "best_rtt_ms": best["rtt_ms"] if best else None,
            "healthy_count": len(healthy),
            "total_count": len(resolvers),
            "resolvers": resolvers,
        }

    async def evaluate_domain(
        self,
        domain: str,
        report: DiagnosticReport,
        network_key: str,
    ) -> Decision | None:
        """Produce a Layer 1 DNS/DoH decision when DNS poisoning is the sole blocker (ignoring QUIC timeout)."""
        effective = [v for v in report.verdicts if v != VerdictClass.QUIC_BLOCK]
        if VerdictClass.DNS_POISON not in effective:
            return None
        if effective == [VerdictClass.DNS_POISON]:
            return Decision(
                network_key=network_key,
                domain=domain,
                protocol=Protocol.TLS,
                layer="dns",
                strategy_id="doh",
                ttfb_ms=report.probes.tcp.rtt_ms,
            )
        return None

    def inspect_status(
        self,
        decisions: list[Decision],
        verdict_rows: list[dict[str, Any]] | None = None,
        active_dns: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Build a fast synchronous summary of Layer 1 DNS orchestrator state."""
        dns_domains = sorted({d.domain for d in decisions if d.layer == "dns"})
        doh_protected = sorted({d.domain for d in decisions if d.layer in ("dns", "dpi", "vpn")})
        poisoned_count = 0
        for row in verdict_rows or []:
            if VerdictClass.DNS_POISON.value in (row.get("verdicts") or []):
                poisoned_count += 1
        cur = active_dns or {"id": "cloudflare", "name": "Cloudflare", "ip": "1.1.1.1"}
        return {
            "layer": "dns",
            "status": "ok",
            "active_dns_id": cur.get("id", "cloudflare"),
            "best_server": cur.get("ip", "1.1.1.1"),
            "best_name": cur.get("name", "Cloudflare"),
            "best_rtt_ms": cur.get("ping_ms"),
            "dns_only_count": len(dns_domains),
            "doh_protected_count": len(doh_protected),
            "poisoned_count": poisoned_count,
        }


class DpiLayerOrchestrator:
    """Layers 2-3 orchestrator: manages winws2 desync strategies, fallbacks, and circular rotations."""

    async def evaluate_domain(
        self,
        domain: str,
        ip: str,
        verdicts: list[VerdictClass],
        network_key: str,
        protocol: Protocol = Protocol.TLS,
        candidates: list[Strategy] | None = None,
        live_eval: bool = True,
        bin_dir: str | Path = "bin",
        vpn_available: bool = True,
    ) -> Decision:
        """Select optimal DPI strategy (with live winws2 eval when elevated and no conflict active)."""
        bypass = detect_bypass_active()
        can_live = bool(live_eval and _is_admin() and not bypass)
        eval_fn = (
            (lambda d, target_ip, s: live_winws2_strategy_evaluator(d, target_ip, s, bin_dir=bin_dir))
            if can_live
            else None
        )
        return await select_best_strategy(
            network_key=network_key,
            domain=domain,
            ip=ip,
            verdicts=verdicts,
            candidates=candidates,
            protocol=protocol,
            evaluator=eval_fn,
            early_stop=True,
            vpn_available=vpn_available,
        )

    def inspect_status(
        self,
        decisions: list[Decision],
        winws2_log_path: Path,
        processes: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Summarize active DPI strategies, winws2 daemon state, and circular auto-rotations."""
        dpi_decisions = [d for d in decisions if d.layer == "dpi"]
        tls_count = sum(1 for d in dpi_decisions if d.protocol == Protocol.TLS)
        quic_count = sum(1 for d in dpi_decisions if d.protocol == Protocol.QUIC)
        strat_counts = Counter(d.strategy_id for d in dpi_decisions if d.strategy_id)
        top_strategy = strat_counts.most_common(1)[0][0] if strat_counts else None
        rotations = parse_circular_rotations(winws2_log_path)
        winws_running = bool(((processes or {}).get("winws2") or {}).get("running"))
        degraded_count = sum(1 for d in dpi_decisions if d.status != "active" or d.consecutive_fails > 0)
        return {
            "layer": "dpi",
            "status": "running" if winws_running else "idle",
            "running": winws_running,
            "domains_count": len({d.domain for d in dpi_decisions}),
            "tls_count": tls_count,
            "quic_count": quic_count,
            "top_strategy": top_strategy,
            "rotations_count": len(rotations),
            "degraded_count": degraded_count,
            "rotations": rotations[-10:],
        }


class VpnLayerOrchestrator:
    """Layer 4 orchestrator: probes VPN nodes (TCP + Clash API tunnel), tracks quarantine & sticky rotation."""

    QUARANTINE_BACKOFF_SEC: tuple[int, ...] = (60, 180, 600, 1800)

    def __init__(self) -> None:
        self._active_node_tag: str | None = None
        self._last_switch_ts: float = 0.0
        self._pending_optimal_node: str | None = None

    @staticmethod
    def _is_quarantine_expired(quarantined_until: str, now_dt: datetime | None = None) -> bool:
        if not quarantined_until:
            return True
        try:
            until_dt = datetime.fromisoformat(quarantined_until)
            cur = now_dt or datetime.now(timezone.utc).astimezone()
            if until_dt.tzinfo is None:
                until_dt = until_dt.replace(tzinfo=cur.tzinfo)
            return cur >= until_dt
        except ValueError:
            return True

    def record_node_result(
        self,
        storage: Storage,
        node: dict[str, Any],
        *,
        ok: bool,
        rtt_ms: float | None = None,
        protocol_ok: bool = True,
        error: str = "",
    ) -> dict[str, Any]:
        """Update Circuit Breaker state (`closed` / `open` / `half_open`) and EWMA RTT in Storage."""
        tag = str(node.get("tag") or "")
        sub_id = str(node.get("subscription_id") or "default")
        now_dt = datetime.now(timezone.utc).astimezone()
        now_iso = now_dt.isoformat(timespec="seconds")

        existing = storage.get_vpn_node_health_map().get(tag) or {}
        prev_ewma = existing.get("ewma_rtt_ms")
        prev_fails = int(existing.get("consecutive_fails") or 0)
        prev_state = str(existing.get("cb_state") or "closed")

        if ok:
            consecutive_fails = 0
            cb_state = "closed"
            quarantined_until = ""
            if rtt_ms is not None:
                ewma_rtt = round(
                    rtt_ms if prev_ewma is None else (0.4 * float(rtt_ms) + 0.6 * float(prev_ewma)),
                    1,
                )
            else:
                ewma_rtt = prev_ewma
            last_error = ""
        else:
            consecutive_fails = prev_fails + 1
            ewma_rtt = prev_ewma
            if prev_state == "half_open" or consecutive_fails >= 2:
                cb_state = "open"
                idx = min(max(consecutive_fails - 2, 0), len(self.QUARANTINE_BACKOFF_SEC) - 1)
                backoff = self.QUARANTINE_BACKOFF_SEC[idx]
                quarantined_until = (now_dt + timedelta(seconds=backoff)).isoformat(timespec="seconds")
            else:
                cb_state = "closed"
                quarantined_until = ""
            last_error = error or ("protocol_block" if not protocol_ok else "probe_failed")

        record = {
            "node_tag": tag,
            "subscription_id": sub_id,
            "cb_state": cb_state,
            "consecutive_fails": consecutive_fails,
            "quarantined_until": quarantined_until,
            "ewma_rtt_ms": ewma_rtt,
            "protocol_ok": 1 if protocol_ok else 0,
            "egress_ip": str(existing.get("egress_ip") or ""),
            "egress_country": str(existing.get("egress_country") or ""),
            "target_caps": dict(existing.get("target_caps") or {}),
            "last_error": last_error,
            "last_checked_at": now_iso,
        }
        storage.upsert_vpn_node_health(record)
        return record

    def should_switch_active_node(
        self,
        active_node: dict[str, Any] | None,
        candidate_node: dict[str, Any] | None,
        *,
        last_switch_ts: float | None = None,
        now_ts: float | None = None,
    ) -> bool:
        """Sticky hysteresis check preventing jitter IP-flapping within a VPN pool."""
        if candidate_node is None or not candidate_node.get("alive"):
            return False
        if str(candidate_node.get("cb_state") or "closed") == "open":
            return False
        if active_node is None:
            return True
        if str(active_node.get("cb_state") or "closed") == "open" or not active_node.get("alive", True):
            return True

        cur_now = now_ts if now_ts is not None else time.monotonic()
        sw_ts = self._last_switch_ts if last_switch_ts is None else last_switch_ts
        if sw_ts > 0 and (cur_now - sw_ts) < 120.0:
            return False

        active_rtt = active_node.get("ewma_rtt_ms") or active_node.get("ping_ms")
        cand_rtt = candidate_node.get("ewma_rtt_ms") or candidate_node.get("ping_ms")
        if active_rtt is None or cand_rtt is None:
            return False
        return float(cand_rtt) < (float(active_rtt) * 0.65) and (float(active_rtt) - float(cand_rtt)) > 120.0

    def rank_candidates(
        self,
        nodes: list[dict[str, Any]],
        health_map: dict[str, dict[str, Any]] | None = None,
        *,
        mode: str = "auto",
        preferred_tag: str | None = None,
        exclude_tag: str | None = None,
        prev_transport: str = "",
        had_proto_block: bool = False,
        allow_quarantined: bool = False,
        probed_map: dict[str, dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Rank real, enabled VPN candidates by health, policy mode (`auto` vs `priority`), transport diversity, and RTT."""
        hmap = health_map or {}
        pmap = probed_map or {}
        clean_mode = "priority" if str(mode or "auto").strip().lower() == "priority" else "auto"
        pref = (preferred_tag or "").strip()
        excl = (exclude_tag or "").strip()

        scored: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
        for idx, n in enumerate(nodes):
            if not isinstance(n, dict) or not n.get("enabled", True) or is_placeholder_node(n):
                continue
            tag = str(n.get("tag") or "").strip()
            if not tag or (excl and tag == excl):
                continue

            h = hmap.get(tag) or {}
            p = pmap.get(tag) or {}
            raw_cb = str(p.get("cb_state") or h.get("cb_state") or "closed")
            quar_until = str(h.get("quarantined_until") or "")
            is_quarantined = raw_cb == "open" and not self._is_quarantine_expired(quar_until)
            if is_quarantined and not allow_quarantined:
                continue
            effective_cb = "half_open" if (raw_cb == "open" and not is_quarantined) else raw_cb

            alive_val = p["alive"] if "alive" in p else n.get("alive")
            fails = int(p.get("consecutive_fails") if "consecutive_fails" in p else (h.get("consecutive_fails") or 0))
            proto_ok = bool(p.get("protocol_ok") if "protocol_ok" in p else h.get("protocol_ok", 1))

            if is_quarantined:
                unhealthy_tier = 3
            elif alive_val is False or fails > 0 or not proto_ok:
                unhealthy_tier = 2
            elif effective_cb == "half_open":
                unhealthy_tier = 1
            else:
                unhealthy_tier = 0

            transport = str(n.get("transport") or n.get("protocol") or "")
            diff_transport_penalty = 0 if (not had_proto_block or transport != prev_transport) else 1

            raw_region = str(n.get("region") or "").strip().lower()
            region = (
                raw_region
                if raw_region and raw_region != "other"
                else infer_node_region(str(n.get("display_name") or tag), str(n.get("server") or ""))
            )
            is_ru_penalty = 1 if region == "ru" else 0
            try:
                priority = int(n.get("priority") if n.get("priority") is not None else 100)
            except (TypeError, ValueError):
                priority = 100

            raw_rtt = (
                p.get("ping_ms")
                if p.get("ping_ms") is not None
                else (n.get("ping_ms") if n.get("ping_ms") is not None else h.get("ewma_rtt_ms"))
            )
            rtt = float(raw_rtt) if raw_rtt is not None else 5000.0

            if clean_mode == "priority":
                key: tuple[Any, ...] = (
                    unhealthy_tier,
                    diff_transport_penalty,
                    0 if (pref and tag == pref) else 1,
                    priority,
                    is_ru_penalty if priority >= 100 else 0,
                    rtt,
                    idx,
                    tag,
                )
            else:
                key = (
                    unhealthy_tier,
                    diff_transport_penalty,
                    is_ru_penalty,
                    rtt,
                    priority,
                    idx,
                    tag,
                )
            scored.append((key, n))

        scored.sort(key=lambda item: item[0])
        return [item[1] for item in scored]

    async def _measure_clash_node_delay(
        self,
        clash_client: ClashApiClient,
        clash_tag: str,
        timeout: float,
    ) -> tuple[bool, float | None, str]:
        timeout_ms = int(max(timeout, 2.0) * 1000)
        delay_res = await clash_client.measure_node_delay(
            clash_tag,
            url="https://www.gstatic.com/generate_204",
            timeout_ms=timeout_ms,
        )
        if not delay_res.get("ok"):
            err_low = str(delay_res.get("error") or "").lower()
            if not any(m in err_low for m in ("not found", "no such host", "connection refused")):
                delay_res = await clash_client.measure_node_delay(
                    clash_tag,
                    url="https://cp.cloudflare.com/generate_204",
                    timeout_ms=timeout_ms,
                )
        if delay_res.get("ok") and delay_res.get("delay_ms") is not None:
            return True, round(float(delay_res["delay_ms"]), 1), "ok"
        return False, None, str(delay_res.get("error") or "timeout")

    async def probe_vpn_nodes(
        self,
        nodes: list[dict[str, Any]],
        timeout: float = 1.8,
        clash_client: ClashApiClient | None = None,
        storage: Storage | None = None,
    ) -> list[dict[str, Any]]:
        """Measure TCP handshake latency and, when Clash API is reachable, real in-tunnel delay + Circuit Breaker."""
        if not nodes:
            return []

        health_map = storage.get_vpn_node_health_map() if storage is not None else {}
        policy = (
            storage.get_vpn_selection_policy()
            if storage is not None
            else {
                "mode": (
                    "priority"
                    if any(int(n.get("priority") if n.get("priority") is not None else 100) != 100 for n in nodes)
                    else "auto"
                ),
                "priority_node": "",
            }
        )
        proxies: dict[str, Any] = {}
        clash_available = False
        if clash_client is not None:
            proxies = await clash_client.get_proxies()
            clash_available = bool(proxies)

        sem = asyncio.Semaphore(12)

        async def _probe_one(node: dict[str, Any]) -> dict[str, Any]:
            async with sem:
                raw_tag = str(node.get("tag") or "")
                clean_tag = raw_tag.strip()
                server = str(node.get("server") or "").strip()
                port = int(node.get("server_port") or 443)
                proto = str(node.get("protocol") or "").lower()
                is_udp_proto = proto in ("wireguard", "amneziawg", "hysteria", "hysteria2", "tuic")
                try:
                    prio = int(node.get("priority") if node.get("priority") is not None else 100)
                except (TypeError, ValueError):
                    prio = 100
                enabled = bool(node.get("enabled", True))
                builtin_auto = is_auto_select_node(node)

                enriched = dict(node)
                enriched["priority"] = prio
                enriched["enabled"] = enabled
                enriched["is_builtin_auto"] = builtin_auto

                if is_placeholder_node(node):
                    enriched.update(
                        alive=False,
                        ping_ms=None,
                        probe_result="placeholder",
                        cb_state="closed",
                        protocol_ok=True,
                        tunnel_verified=False,
                        is_placeholder=True,
                    )
                    return enriched

                enriched["is_placeholder"] = False
                if not enabled:
                    enriched.update(
                        alive=False,
                        ping_ms=None,
                        probe_result="disabled",
                        cb_state="closed",
                        protocol_ok=True,
                        tunnel_verified=False,
                    )
                    return enriched

                prev_health = health_map.get(raw_tag) or health_map.get(clean_tag) or {}
                prev_cb = str(prev_health.get("cb_state") or "closed")
                if prev_cb == "open" and self._is_quarantine_expired(str(prev_health.get("quarantined_until") or "")):
                    prev_cb = "half_open"

                if not server:
                    enriched.update(
                        alive=False,
                        ping_ms=None,
                        probe_result="invalid",
                        cb_state=prev_cb,
                        protocol_ok=False,
                        tunnel_verified=False,
                    )
                    return enriched

                clash_tag = raw_tag if raw_tag in proxies else (clean_tag if clean_tag in proxies else None)
                if clash_available and clash_tag:
                    ok, tunnel_rtt, err_msg = await self._measure_clash_node_delay(clash_client, clash_tag, timeout)  # type: ignore[arg-type]
                    if ok:
                        enriched["alive"] = True
                        enriched["ping_ms"] = tunnel_rtt
                        enriched["probe_result"] = "ok"
                        enriched["protocol_ok"] = True
                        enriched["tunnel_verified"] = True
                    else:
                        tcp_ok = False
                        if not is_udp_proto:
                            tcp_res = await probe_tcp(server, port=port, timeout=min(timeout, 1.0))
                            tcp_ok = tcp_res.result == "ok"
                        enriched["alive"] = False
                        enriched["ping_ms"] = None
                        enriched["probe_result"] = "protocol_block" if tcp_ok else err_msg
                        enriched["protocol_ok"] = False if tcp_ok else bool(prev_health.get("protocol_ok", 1))
                        enriched["tunnel_verified"] = True
                else:
                    tcp_res = await probe_tcp(server, port=port, timeout=timeout)
                    tcp_ok = tcp_res.result == "ok"
                    tcp_rtt = round(tcp_res.rtt_ms, 1) if tcp_res.rtt_ms is not None else None
                    enriched["alive"] = tcp_ok
                    enriched["ping_ms"] = tcp_rtt
                    enriched["probe_result"] = tcp_res.result
                    enriched["protocol_ok"] = True if tcp_ok else bool(prev_health.get("protocol_ok", 1))
                    enriched["tunnel_verified"] = False

                db_tag = clean_tag or raw_tag
                if storage is not None and db_tag:
                    if prev_cb == "half_open":
                        storage.conn.execute(
                            "UPDATE vpn_node_health SET cb_state = 'half_open' WHERE node_tag = ?",
                            (db_tag,),
                        )
                        storage.conn.commit()
                    node_for_db = dict(enriched)
                    node_for_db["tag"] = db_tag
                    rec = self.record_node_result(
                        storage,
                        node_for_db,
                        ok=bool(enriched["alive"]),
                        rtt_ms=enriched["ping_ms"],
                        protocol_ok=bool(enriched["protocol_ok"]),
                        error=str(enriched["probe_result"]),
                    )
                    enriched["cb_state"] = rec["cb_state"]
                    enriched["consecutive_fails"] = rec["consecutive_fails"]
                    enriched["ewma_rtt_ms"] = rec["ewma_rtt_ms"]
                else:
                    enriched["cb_state"] = prev_cb
                    enriched["ewma_rtt_ms"] = prev_health.get("ewma_rtt_ms")
                return enriched

        probed = await asyncio.gather(*(_probe_one(n) for n in nodes))
        sel_mode = str(policy.get("mode") or "auto")
        pref_node = str(policy.get("priority_node") or "").strip()

        def _probed_sort_key(n: dict[str, Any]) -> tuple[Any, ...]:
            tag = str(n.get("tag") or "").strip()
            ping = n["ping_ms"] if n.get("ping_ms") is not None else 99999.0
            prio = int(n.get("priority") if n.get("priority") is not None else 100)
            base = (
                1 if n.get("is_placeholder") else 0,
                0 if n.get("enabled", True) else 1,
                1 if n.get("cb_state") == "open" else 0,
                0 if n.get("alive") else 1,
            )
            if sel_mode == "priority":
                return (
                    *base,
                    0 if (pref_node and tag == pref_node) else 1,
                    prio,
                    ping,
                    tag,
                )
            return (*base, ping, prio, tag)

        probed.sort(key=_probed_sort_key)
        return probed

    def rotate_vpn_node(
        self,
        storage: Storage,
        nodes: list[dict[str, Any]],
        *,
        clash_client: ClashApiClient | None = None,
        target_tag: str | None = None,
        selector_tag: str = "vpn-select",
    ) -> dict[str, Any]:
        """Rotate to an explicit, auto-pool, or next healthy/priority VPN node via Clash API without TUN restart."""
        if not nodes:
            return {"ok": False, "error": "Нет настроенных VPN-узлов", "selected": None}

        policy = storage.get_vpn_selection_policy()
        health_map = storage.get_vpn_node_health_map()
        prev_selector_now: str | None = self._active_node_tag
        prev_leaf_tag: str | None = self._active_node_tag
        if clash_client is not None:
            proxies = clash_client.get_proxies_sync()
            sel_now, leaf_now, _ = ClashApiClient.resolve_active_proxy(proxies, selector_tag)
            if sel_now:
                prev_selector_now = sel_now
            if leaf_now:
                prev_leaf_tag = leaf_now

        prev_node = next(
            (n for n in nodes if str(n.get("tag") or "").strip() == (prev_leaf_tag or "")),
            None,
        )
        prev_health = health_map.get(prev_leaf_tag or "") or {}
        prev_transport = str((prev_node or {}).get("transport") or (prev_node or {}).get("protocol") or "")
        had_proto_block = prev_health.get("protocol_ok") == 0

        if target_tag:
            clean_target = target_tag.strip()
            if clean_target == "vpn-auto" or clean_target.startswith("ut-"):
                switched_live = False
                closed_sockets = 0
                if clash_client is not None:
                    switched_live = clash_client.select_outbound_sync(selector_tag, clean_target)
                    if prev_leaf_tag and prev_leaf_tag != clean_target and prev_leaf_tag not in ("vpn-auto", "direct"):
                        closed_sockets = clash_client.close_connections_by_node_sync(prev_leaf_tag)
                self._active_node_tag = clean_target
                self._last_switch_ts = time.monotonic()
                return {
                    "ok": True,
                    "previous": prev_leaf_tag or prev_selector_now,
                    "selected": clean_target,
                    "selector": selector_tag,
                    "switched_live": switched_live,
                    "closed_connections": closed_sockets,
                    "transport": "auto",
                    "region": "auto",
                }
            chosen = next((n for n in nodes if str(n.get("tag") or "").strip() == clean_target), None)
            if chosen is None:
                return {"ok": False, "error": f"Узел {clean_target} не найден", "selected": None}
            if is_placeholder_node(chosen):
                return {
                    "ok": False,
                    "error": f"Узел «{clean_target}» — служебный заголовок подписки, а не VPN-сервер",
                    "selected": None,
                }
        else:
            ranked = self.rank_candidates(
                nodes,
                health_map,
                mode=policy["mode"],
                preferred_tag=policy["priority_node"],
                exclude_tag=prev_leaf_tag,
                prev_transport=prev_transport,
                had_proto_block=had_proto_block,
                allow_quarantined=False,
            )
            if not ranked:
                ranked = self.rank_candidates(
                    nodes,
                    health_map,
                    mode=policy["mode"],
                    preferred_tag=policy["priority_node"],
                    exclude_tag=prev_leaf_tag,
                    prev_transport=prev_transport,
                    had_proto_block=had_proto_block,
                    allow_quarantined=True,
                )
            if not ranked:
                ranked = self.rank_candidates(
                    nodes,
                    health_map,
                    mode=policy["mode"],
                    preferred_tag=policy["priority_node"],
                    exclude_tag=None,
                    allow_quarantined=True,
                )
            if not ranked:
                return {
                    "ok": False,
                    "error": "Нет доступных реальных VPN-узлов (в подписке только служебные записи)",
                    "selected": None,
                }
            chosen = ranked[0]

        chosen_tag = str(chosen.get("tag") or "").strip()
        switched_live = False
        closed_sockets = 0
        if clash_client is not None:
            switched_live = clash_client.select_outbound_sync(selector_tag, chosen_tag)
            if prev_leaf_tag and prev_leaf_tag != chosen_tag and prev_leaf_tag not in ("vpn-auto", "direct"):
                closed_sockets = clash_client.close_connections_by_node_sync(prev_leaf_tag)

        self._active_node_tag = chosen_tag
        self._last_switch_ts = time.monotonic()
        return {
            "ok": True,
            "previous": prev_leaf_tag or prev_selector_now,
            "selected": chosen_tag,
            "selector": selector_tag,
            "switched_live": switched_live,
            "closed_connections": closed_sockets,
            "transport": chosen.get("transport"),
            "region": chosen.get("region"),
        }

    async def reconcile_active_node(
        self,
        storage: Storage,
        nodes: list[dict[str, Any]],
        *,
        clash_client: ClashApiClient,
        selector_tag: str = "vpn-select",
        timeout: float = 1.8,
        force: bool = False,
        failback_cooldown_sec: float = 60.0,
    ) -> dict[str, Any]:
        """Automatically verify active VPN node health via Clash API and perform failover or priority failback."""
        proxies = await clash_client.get_proxies()
        if not proxies:
            return {"ok": False, "action": "clash_unavailable", "selected": None, "probed": []}

        real_nodes = [n for n in nodes if n.get("enabled", True) and not is_placeholder_node(n)]
        if not real_nodes:
            return {"ok": True, "action": "no_nodes", "selected": None, "probed": []}

        policy = storage.get_vpn_selection_policy()
        health_map = storage.get_vpn_node_health_map()
        sel_now, active_leaf, _ = ClashApiClient.resolve_active_proxy(proxies, selector_tag)

        clash_conns: list[dict[str, Any]] = []
        get_conns_fn = getattr(clash_client, "get_connections", None)
        if callable(get_conns_fn):
            try:
                conn_payload = await get_conns_fn()
                raw_c = (conn_payload.get("connections") or []) if isinstance(conn_payload, dict) else []
                clash_conns = [c for c in raw_c if isinstance(c, dict)]
            except Exception:  # noqa: BLE001
                clash_conns = []
        active_has_live_traffic = bool(active_leaf and _node_has_healthy_connections(clash_conns, active_leaf))

        priority_node = str(policy.get("priority_node") or "").strip()
        has_custom_prio = bool(priority_node) or any(
            int(n.get("priority") if n.get("priority") is not None else 100) < 100 for n in real_nodes
        )
        effective_mode = "priority" if (policy.get("mode") == "priority" and has_custom_prio) else "auto"

        sem = asyncio.Semaphore(10)
        probed_results: dict[str, dict[str, Any]] = {}

        async def _probe_via_clash(node: dict[str, Any]) -> dict[str, Any]:
            tag = str(node.get("tag") or "").strip()
            if tag in probed_results:
                return probed_results[tag]
            async with sem:
                if tag in probed_results:
                    return probed_results[tag]
                if not tag or tag not in proxies:
                    res = {
                        "tag": tag,
                        "alive": False,
                        "ping_ms": None,
                        "probe_result": "not_in_clash",
                        "protocol_ok": True,
                        "cb_state": "closed",
                        "consecutive_fails": 0,
                        "ewma_rtt_ms": None,
                        "tunnel_verified": True,
                        "node": node,
                    }
                    if tag:
                        probed_results[tag] = res
                    return res

                prev_h = health_map.get(tag) or {}
                prev_cb = str(prev_h.get("cb_state") or "closed")
                if prev_cb == "open" and self._is_quarantine_expired(str(prev_h.get("quarantined_until") or "")):
                    storage.conn.execute(
                        "UPDATE vpn_node_health SET cb_state = 'half_open' WHERE node_tag = ?",
                        (tag,),
                    )
                    storage.conn.commit()

                ok, rtt, err = await self._measure_clash_node_delay(clash_client, tag, timeout)
                proto_ok = True
                probe_err = err
                if not ok:
                    proto = str(node.get("protocol") or "").lower()
                    is_udp = proto in ("wireguard", "amneziawg", "hysteria", "hysteria2", "tuic")
                    srv = str(node.get("server") or "").strip()
                    port = int(node.get("server_port") or 443)
                    if not is_udp and srv:
                        tcp_res = await probe_tcp(srv, port=port, timeout=min(timeout, 1.0))
                        if tcp_res.result == "ok":
                            proto_ok = False
                            probe_err = "protocol_block"
                        else:
                            proto_ok = bool(prev_h.get("protocol_ok", 1))
                    else:
                        proto_ok = bool(prev_h.get("protocol_ok", 1))

                node_for_db = dict(node)
                node_for_db["tag"] = tag
                rec = self.record_node_result(
                    storage,
                    node_for_db,
                    ok=ok,
                    rtt_ms=rtt,
                    protocol_ok=proto_ok,
                    error=probe_err,
                )
                res = {
                    "tag": tag,
                    "alive": ok,
                    "ping_ms": rtt,
                    "probe_result": probe_err,
                    "protocol_ok": proto_ok,
                    "cb_state": rec["cb_state"],
                    "consecutive_fails": rec["consecutive_fails"],
                    "ewma_rtt_ms": rec["ewma_rtt_ms"],
                    "tunnel_verified": True,
                    "node": node,
                }
                probed_results[tag] = res
                return res

        async def _probe_eligible_pool() -> None:
            eligible: list[dict[str, Any]] = []
            all_in_clash: list[dict[str, Any]] = []
            for n in real_nodes:
                t = str(n.get("tag") or "").strip()
                if not t or t not in proxies or t in probed_results:
                    continue
                all_in_clash.append(n)
                h = health_map.get(t) or {}
                cb = str(h.get("cb_state") or "closed")
                is_quar = cb == "open" and not self._is_quarantine_expired(str(h.get("quarantined_until") or ""))
                if not is_quar or force:
                    eligible.append(n)
            targets = eligible or all_in_clash
            if targets:
                await asyncio.gather(*(_probe_via_clash(n) for n in targets))

        def _is_quarantined_tag(t: str) -> bool:
            h = health_map.get(t) or {}
            return str(h.get("cb_state") or "closed") == "open" and not self._is_quarantine_expired(
                str(h.get("quarantined_until") or "")
            )

        async def _check_active_node_alive(node: dict[str, Any], active_tag: str) -> bool:
            probe = await _probe_via_clash(node)
            if probe.get("alive"):
                return True
            if not force and active_has_live_traffic:
                await asyncio.sleep(0.25)
                ok2, rtt2, err2 = await self._measure_clash_node_delay(clash_client, active_tag, timeout)
                if ok2:
                    node_for_db = dict(node)
                    node_for_db["tag"] = active_tag
                    rec = self.record_node_result(
                        storage,
                        node_for_db,
                        ok=True,
                        rtt_ms=rtt2,
                        protocol_ok=True,
                        error="",
                    )
                    probed_results[active_tag] = {
                        "tag": active_tag,
                        "alive": True,
                        "ping_ms": rtt2,
                        "probe_result": err2,
                        "protocol_ok": True,
                        "cb_state": rec["cb_state"],
                        "consecutive_fails": rec["consecutive_fails"],
                        "ewma_rtt_ms": rec["ewma_rtt_ms"],
                        "tunnel_verified": True,
                        "node": node,
                    }
                    return True
            return False

        if effective_mode == "priority":
            def _prio_sort_key(item: tuple[int, dict[str, Any]]) -> tuple[int, int, int, int]:
                idx, n = item
                t = str(n.get("tag") or "").strip()
                try:
                    pr = int(n.get("priority") if n.get("priority") is not None else 100)
                except (TypeError, ValueError):
                    pr = 100
                raw_reg = str(n.get("region") or "").strip().lower()
                reg = (
                    raw_reg
                    if raw_reg and raw_reg != "other"
                    else infer_node_region(str(n.get("display_name") or t), str(n.get("server") or ""))
                )
                is_ru = 1 if reg == "ru" else 0
                return (0 if (priority_node and t == priority_node) else 1, pr, is_ru if pr >= 100 else 0, idx)

            ordered = [n for _idx, n in sorted(enumerate(real_nodes), key=_prio_sort_key)]
            ordered_tags = [str(n.get("tag") or "").strip() for n in ordered]
            node_by_tag = {str(n.get("tag") or "").strip(): n for n in ordered if str(n.get("tag") or "").strip()}

            active_alive = False
            if active_leaf and active_leaf in node_by_tag and active_leaf in proxies:
                active_alive = await _check_active_node_alive(node_by_tag[active_leaf], active_leaf)

            if active_alive and ordered_tags and active_leaf == ordered_tags[0]:
                if sel_now != active_leaf:
                    await clash_client.select_outbound(selector_tag, active_leaf)
                self._active_node_tag = active_leaf
                self._pending_optimal_node = None
                return {
                    "ok": True,
                    "action": "keep_priority",
                    "selector": active_leaf,
                    "selected": active_leaf,
                    "previous": active_leaf,
                    "pending_node": None,
                    "probed": list(probed_results.values()),
                }

            if active_alive and active_leaf in ordered_tags:
                active_rank = ordered_tags.index(active_leaf)
                higher_candidates = [
                    n
                    for n in ordered[:active_rank]
                    if str(n.get("tag") or "").strip() in proxies
                    and (force or not _is_quarantined_tag(str(n.get("tag") or "").strip()))
                ]
                top_alive: dict[str, Any] | None = None
                if higher_candidates:
                    await asyncio.gather(*(_probe_via_clash(n) for n in higher_candidates))
                    top_alive = next(
                        (
                            n
                            for n in ordered[:active_rank]
                            if probed_results.get(str(n.get("tag") or "").strip(), {}).get("alive")
                        ),
                        None,
                    )
                top_tag = str(top_alive.get("tag") or "").strip() if top_alive is not None else None
                if not force and active_has_live_traffic:
                    self._active_node_tag = active_leaf
                    self._pending_optimal_node = top_tag
                    return {
                        "ok": True,
                        "action": "keep_active_session",
                        "selector": sel_now,
                        "selected": active_leaf,
                        "previous": active_leaf,
                        "pending_node": self._pending_optimal_node,
                        "probed": list(probed_results.values()),
                    }
                if top_tag:
                    cooldown_ok = (
                        force
                        or self._pending_optimal_node == top_tag
                        or self._last_switch_ts <= 0
                        or (time.monotonic() - self._last_switch_ts) >= failback_cooldown_sec
                        or sel_now in ("vpn-auto", "direct")
                    )
                    if cooldown_ok:
                        switched = await clash_client.select_outbound(selector_tag, top_tag)
                        self._active_node_tag = top_tag
                        self._pending_optimal_node = None
                        self._last_switch_ts = time.monotonic()
                        return {
                            "ok": True,
                            "action": "failback_priority",
                            "selector": top_tag,
                            "selected": top_tag,
                            "previous": active_leaf or sel_now,
                            "switched_live": switched,
                            "closed_connections": 0,
                            "pending_node": None,
                            "probed": list(probed_results.values()),
                        }
                self._active_node_tag = active_leaf
                self._pending_optimal_node = top_tag
                return {
                    "ok": True,
                    "action": "keep_fallback",
                    "selector": sel_now,
                    "selected": active_leaf,
                    "previous": active_leaf,
                    "pending_node": self._pending_optimal_node,
                    "probed": list(probed_results.values()),
                }

            await _probe_eligible_pool()
            fresh_health = storage.get_vpn_node_health_map()
            alive_nodes = [p["node"] for p in probed_results.values() if p.get("alive")]
            ranked = self.rank_candidates(
                alive_nodes,
                fresh_health,
                mode="priority",
                preferred_tag=priority_node,
                probed_map=probed_results,
            )
            if ranked:
                winner_tag = str(ranked[0].get("tag") or "").strip()
                switched = await clash_client.select_outbound(selector_tag, winner_tag)
                closed = 0
                if active_leaf and active_leaf != winner_tag and active_leaf not in ("vpn-auto", "direct"):
                    closed = await clash_client.close_connections_by_node(active_leaf)
                self._active_node_tag = winner_tag
                self._pending_optimal_node = None
                self._last_switch_ts = time.monotonic()
                return {
                    "ok": True,
                    "action": "failover_priority",
                    "selector": winner_tag,
                    "selected": winner_tag,
                    "previous": active_leaf or sel_now,
                    "switched_live": switched,
                    "closed_connections": closed,
                    "pending_node": None,
                    "probed": list(probed_results.values()),
                }

            if sel_now != "vpn-auto" and "vpn-auto" in proxies:
                await clash_client.select_outbound(selector_tag, "vpn-auto")
            self._pending_optimal_node = None
            return {
                "ok": False,
                "action": "all_unavailable",
                "selector": "vpn-auto" if "vpn-auto" in proxies else sel_now,
                "selected": None,
                "previous": active_leaf or sel_now,
                "pending_node": None,
                "probed": list(probed_results.values()),
            }

        # Auto mode
        node_by_tag = {str(n.get("tag") or "").strip(): n for n in real_nodes if str(n.get("tag") or "").strip()}
        auto_info = proxies.get("vpn-auto") if isinstance(proxies.get("vpn-auto"), dict) else None
        auto_leaf = str(auto_info["now"]).strip() if (auto_info and auto_info.get("now")) else None

        active_alive = False
        if active_leaf and active_leaf in node_by_tag and active_leaf in proxies:
            active_alive = await _check_active_node_alive(node_by_tag[active_leaf], active_leaf)
            if sel_now == "vpn-auto" and active_alive:
                self._active_node_tag = active_leaf
                self._pending_optimal_node = None
                return {
                    "ok": True,
                    "action": "keep_auto",
                    "selector": "vpn-auto",
                    "selected": active_leaf,
                    "previous": active_leaf,
                    "pending_node": None,
                    "probed": list(probed_results.values()),
                }

        if sel_now != "vpn-auto":
            auto_alive = False
            if auto_leaf and auto_leaf in node_by_tag and auto_leaf in proxies:
                auto_probe = await _probe_via_clash(node_by_tag[auto_leaf])
                auto_alive = bool(auto_probe.get("alive"))
            if active_alive and not force and active_has_live_traffic:
                self._active_node_tag = active_leaf
                self._pending_optimal_node = "vpn-auto" if auto_alive else None
                return {
                    "ok": True,
                    "action": "keep_active_session",
                    "selector": sel_now,
                    "selected": active_leaf,
                    "previous": active_leaf,
                    "pending_node": self._pending_optimal_node,
                    "probed": list(probed_results.values()),
                }
            cooldown_ok = (
                not active_alive
                or force
                or self._pending_optimal_node == "vpn-auto"
                or self._last_switch_ts <= 0
                or (time.monotonic() - self._last_switch_ts) >= failback_cooldown_sec
            )
            if auto_alive and cooldown_ok:
                switched = await clash_client.select_outbound(selector_tag, "vpn-auto")
                closed = 0
                if not active_alive and active_leaf and active_leaf != auto_leaf and active_leaf not in ("vpn-auto", "direct"):
                    closed = await clash_client.close_connections_by_node(active_leaf)
                self._active_node_tag = auto_leaf
                self._pending_optimal_node = None
                self._last_switch_ts = time.monotonic()
                return {
                    "ok": True,
                    "action": "return_to_auto",
                    "selector": "vpn-auto",
                    "selected": auto_leaf,
                    "previous": active_leaf or sel_now,
                    "switched_live": switched,
                    "closed_connections": closed,
                    "pending_node": None,
                    "probed": list(probed_results.values()),
                }
            if active_alive:
                self._active_node_tag = active_leaf
                self._pending_optimal_node = "vpn-auto" if auto_alive else None
                return {
                    "ok": True,
                    "action": "keep_failover",
                    "selector": sel_now,
                    "selected": active_leaf,
                    "previous": active_leaf,
                    "pending_node": self._pending_optimal_node,
                    "probed": list(probed_results.values()),
                }

        await _probe_eligible_pool()
        fresh_health = storage.get_vpn_node_health_map()
        alive_nodes = [p["node"] for p in probed_results.values() if p.get("alive")]
        ranked = self.rank_candidates(
            alive_nodes,
            fresh_health,
            mode="auto",
            probed_map=probed_results,
        )
        if ranked:
            winner_tag = str(ranked[0].get("tag") or "").strip()
            switched = await clash_client.select_outbound(selector_tag, winner_tag)
            closed = 0
            if active_leaf and active_leaf != winner_tag and active_leaf not in ("vpn-auto", "direct"):
                closed = await clash_client.close_connections_by_node(active_leaf)
            self._active_node_tag = winner_tag
            self._pending_optimal_node = None
            self._last_switch_ts = time.monotonic()
            return {
                "ok": True,
                "action": "failover",
                "selector": winner_tag,
                "selected": winner_tag,
                "previous": active_leaf or sel_now,
                "switched_live": switched,
                "closed_connections": closed,
                "pending_node": None,
                "probed": list(probed_results.values()),
            }

        self._pending_optimal_node = None
        return {
            "ok": False,
            "action": "all_unavailable",
            "selector": sel_now,
            "selected": None,
            "previous": active_leaf or sel_now,
            "pending_node": None,
            "probed": list(probed_results.values()),
        }

    async def check_tg_proxy(
        self,
        host: str = "127.0.0.1",
        port: int = 10808,
        timeout: float = 0.8,
    ) -> dict[str, Any]:
        """Verify local tg-ws-proxy TCP listener reachability."""
        res = await probe_tcp(host, port=port, timeout=timeout)
        return {
            "host": host,
            "port": port,
            "alive": res.result == "ok",
            "rtt_ms": round(res.rtt_ms, 1) if res.rtt_ms is not None else None,
        }

    async def check_health(
        self,
        nodes: list[dict[str, Any]],
        timeout: float = 1.8,
        tg_port: int = 10808,
        clash_client: ClashApiClient | None = None,
        storage: Storage | None = None,
    ) -> dict[str, Any]:
        """Probe all VPN pool nodes and tg-ws-proxy concurrently to pick fastest healthy node."""
        probed_nodes, tg_info = await asyncio.gather(
            self.probe_vpn_nodes(nodes, timeout=timeout, clash_client=clash_client, storage=storage),
            self.check_tg_proxy(port=tg_port, timeout=min(timeout, 0.8)),
        )
        alive_nodes = [n for n in probed_nodes if n.get("alive") and n.get("cb_state") != "open"]
        if not alive_nodes:
            alive_nodes = [n for n in probed_nodes if n.get("alive")]
        best = alive_nodes[0] if alive_nodes else None
        if not probed_nodes:
            status = "empty"
        elif alive_nodes:
            status = "ok"
        else:
            status = "degraded"
        return {
            "layer": "vpn",
            "status": status,
            "total_count": len(probed_nodes),
            "alive_count": len(alive_nodes),
            "best_node": best.get("tag") if best else None,
            "best_ping_ms": best.get("ping_ms") if best else None,
            "nodes": probed_nodes,
            "tg_proxy_alive": bool(tg_info.get("alive")),
        }

    def inspect_status(
        self,
        decisions: list[Decision],
        nodes: list[dict[str, Any]],
        processes: dict[str, Any] | None = None,
        clash_client: ClashApiClient | None = None,
        storage: Storage | None = None,
    ) -> dict[str, Any]:
        """Summarize Layer 4 sing-box/VPN and tg-ws-proxy state synchronously."""
        vpn_domains = sorted({d.domain for d in decisions if d.layer == "vpn"})
        sb_running = bool(((processes or {}).get("sing-box") or {}).get("running"))
        tg_running = bool(((processes or {}).get("tg-ws-proxy") or {}).get("running"))
        real_nodes = [n for n in nodes if not is_placeholder_node(n)]
        placeholder_count = len(nodes) - len(real_nodes)
        policy = storage.get_vpn_selection_policy() if storage is not None else {"mode": "auto", "priority_node": ""}
        selector_now: str | None = None
        best_ping_ms: float | None = None
        best_node = (
            self._active_node_tag
            or (str(real_nodes[0].get("tag")) if real_nodes else (str(nodes[0].get("tag")) if nodes else None))
        )
        if sb_running and clash_client is not None:
            proxies = clash_client.get_proxies_sync()
            sel_now, leaf_now, hist_delay = ClashApiClient.resolve_active_proxy(proxies, "vpn-select")
            if sel_now:
                selector_now = sel_now
            if leaf_now:
                best_node = leaf_now
                self._active_node_tag = leaf_now
            if hist_delay is not None:
                best_ping_ms = hist_delay
        return {
            "layer": "vpn",
            "status": "running" if sb_running else ("ready" if nodes else "empty"),
            "running": sb_running,
            "tg_proxy_running": tg_running,
            "total_count": len(nodes),
            "real_count": len(real_nodes),
            "placeholder_count": placeholder_count,
            "alive_count": None,
            "best_node": best_node,
            "best_ping_ms": best_ping_ms,
            "selector_now": selector_now,
            "selection_mode": policy["mode"],
            "priority_node": policy["priority_node"],
            "vpn_domains_count": len(vpn_domains),
        }


class RealtimeConnectionMonitor:
    """Real-time connection scanner & automatic per-domain strategy orchestrator."""

    def __init__(self, rdns_ttl_sec: float = 300.0, cooldown_sec: float = 12.0) -> None:
        self._lock = threading.RLock()
        self.rdns_ttl_sec = rdns_ttl_sec
        self.cooldown_sec = cooldown_sec
        self.ip_to_domain: dict[str, str] = {}
        self.rdns_cache: dict[str, tuple[str | None, float]] = {}
        self.rdns_inflight: set[str] = set()
        self.pid_names: dict[int, str] = {}
        self._pid_names_exp: dict[int, float] = {}
        self.domain_fail_counts: dict[str, int] = {}
        self.recent_events: deque[dict[str, Any]] = deque(maxlen=100)
        self.cooldown_until: dict[str, float] = {}
        self.auto_healed_count = 0
        self._rdns_sem = threading.Semaphore(4)
        self._verdicts_sig: tuple[str, int, str, int] | None = None
        self._verdicts_ip_map: dict[str, str] = {}
        self._log_ip_cache: dict[str, tuple[tuple[int, int], dict[str, str]]] = {}
        self._last_scan: tuple[float, str, list[dict[str, Any]]] | None = None

    def get_recent_connections(self, net_key: str, max_age_sec: float = 2.0) -> list[dict[str, Any]] | None:
        """Return shallow copy of recent scan_active_connections rows if fresh and matching network_key."""
        with self._lock:
            if self._last_scan is None:
                return None
            ts, scan_key, rows = self._last_scan
            if scan_key == net_key and (time.monotonic() - ts) <= max_age_sec:
                return [dict(r) for r in rows]
        return None

    def invalidate_scan_cache(self) -> None:
        """Clear cached connection scan result (e.g. after saving new decisions)."""
        with self._lock:
            self._last_scan = None

    def _schedule_rdns(self, ip_str: str) -> None:
        now = time.monotonic()
        with self._lock:
            cached = self.rdns_cache.get(ip_str)
            if cached and cached[1] > now:
                return
            if ip_str in self.rdns_inflight:
                return
            if not self._rdns_sem.acquire(blocking=False):
                return
            self.rdns_inflight.add(ip_str)

        def _lookup() -> None:
            host: str | None = None
            try:
                raw_host, _, _ = socket.gethostbyaddr(ip_str)
                if raw_host and "." in raw_host:
                    host = raw_host.lower().rstrip(".")
            except (OSError, socket.herror, socket.gaierror):
                host = None
            finally:
                with self._lock:
                    self.rdns_cache[ip_str] = (host, time.monotonic() + self.rdns_ttl_sec)
                    if host and ip_str not in self.ip_to_domain:
                        self.ip_to_domain[ip_str] = host
                    self.rdns_inflight.discard(ip_str)
                self._rdns_sem.release()

        threading.Thread(target=_lookup, name="netdoc-rdns", daemon=True).start()

    def _resolve_pid_name(self, pid: int | None) -> str:
        if not pid or pid <= 0:
            return "system"
        now = time.monotonic()
        with self._lock:
            if pid in self.pid_names and self._pid_names_exp.get(pid, now + 1.0) > now:
                return self.pid_names[pid]
        try:
            name = psutil.Process(pid).name() or f"pid:{pid}"
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            name = f"pid:{pid}"
        with self._lock:
            if len(self.pid_names) > 1024:
                self.pid_names.clear()
                self._pid_names_exp.clear()
            self.pid_names[pid] = name
            self._pid_names_exp[pid] = now + 15.0
        return name

    def update_ip_map_from_storage_and_logs(
        self,
        storage: Storage,
        logs_dir: Path,
        clash_client: ClashApiClient | None = None,
        clash_connections: list[dict[str, Any]] | None = None,
    ) -> None:
        """Populate ip->domain cache from DB verdicts/probes, sing-box/winws2 logs, and Clash API connections."""
        import json

        new_map: dict[str, str] = {}
        try:
            sig_row = storage.conn.execute(
                "SELECT COUNT(*), COALESCE(MAX(checked_at), ''), COALESCE(SUM(length(probes_json)), 0) FROM verdicts"
            ).fetchone()
            db_sig = (
                str(storage.db_path),
                int(sig_row[0]),
                str(sig_row[1]),
                int(sig_row[2]),
            )
            with self._lock:
                verdicts_cached = dict(self._verdicts_ip_map) if self._verdicts_sig == db_sig else None
            if verdicts_cached is not None:
                new_map.update(verdicts_cached)
            else:
                ip_to_domains: dict[str, set[str]] = {}
                rows = storage.conn.execute("SELECT domain, probes_json FROM verdicts").fetchall()
                for r in rows:
                    dom = str(r["domain"]).lower()
                    try:
                        probes = json.loads(r["probes_json"] or "{}")
                    except (json.JSONDecodeError, TypeError):
                        continue
                    dns = probes.get("dns") or {}
                    doh_ips = [str(x) for x in (dns.get("doh_ips") or []) if x]
                    doh_set = set(doh_ips)
                    candidate_ips: list[str] = list(doh_ips)
                    if dns.get("system") == "ok":
                        for ip_val in dns.get("system_ips") or []:
                            ip_s = str(ip_val)
                            if ip_s and (not doh_set or ip_s in doh_set):
                                candidate_ips.append(ip_s)
                    target_ip = (probes.get("tcp") or {}).get("target_ip")
                    if target_ip:
                        ip_s = str(target_ip)
                        if not doh_set or ip_s in doh_set:
                            candidate_ips.append(ip_s)
                    for ip_s in candidate_ips:
                        if _is_external_ip(ip_s) and not _is_shared_cdn_anycast_ip(ip_s):
                            ip_to_domains.setdefault(ip_s, set()).add(dom)
                verdicts_map = {
                    ip_s: next(iter(doms))
                    for ip_s, doms in ip_to_domains.items()
                    if len(doms) == 1
                }
                with self._lock:
                    self._verdicts_sig = db_sig
                    self._verdicts_ip_map = verdicts_map
                new_map.update(verdicts_map)
        except Exception:  # noqa: BLE001 - best-effort cache seeding
            pass

        for fname in ("sing-box.log", "winws2.log"):
            fpath = logs_dir / fname
            try:
                st = fpath.stat()
                fsig = (st.st_mtime_ns, st.st_size)
            except OSError:
                continue
            cache_key = str(fpath)
            with self._lock:
                cached_log = self._log_ip_cache.get(cache_key)
            if cached_log is not None and cached_log[0] == fsig:
                new_map.update(cached_log[1])
                continue
            text = _tail_text(fpath, max_bytes=131072)
            log_map: dict[str, str] = {}
            if text:
                for dom, ip_val in _LOG_DOMAIN_IP_RE.findall(text):
                    if _is_external_ip(ip_val):
                        log_map[ip_val] = dom.lower()
                for ip_val, dom in _WINWS2_IP_HOST_RE.findall(text):
                    if _is_external_ip(ip_val):
                        log_map[ip_val] = dom.lower()
            with self._lock:
                self._log_ip_cache[cache_key] = (fsig, log_map)
            new_map.update(log_map)

        raw_clash_conns: list[Any] = []
        if clash_connections is not None:
            raw_clash_conns = clash_connections
        elif clash_client is not None:
            try:
                conn_data = clash_client.get_connections_sync()
                if isinstance(conn_data, dict):
                    raw_clash_conns = conn_data.get("connections") or []
            except Exception:  # noqa: BLE001
                raw_clash_conns = []

        for c in raw_clash_conns:
            if not isinstance(c, dict):
                continue
            meta = c.get("metadata") or {}
            host = str(meta.get("host") or meta.get("sniffHost") or "").strip().lower().rstrip(".")
            dest_ip = str(meta.get("destinationIP") or "").strip()
            if host and not _is_ip_literal(host) and dest_ip and _is_external_ip(dest_ip):
                new_map[dest_ip] = host

        with self._lock:
            stale_cdn = [
                k
                for k in self.ip_to_domain
                if _is_shared_cdn_anycast_ip(k) and k not in new_map
            ]
            for k in stale_cdn:
                del self.ip_to_domain[k]
            self.ip_to_domain.update(new_map)

    @staticmethod
    def _read_inet_connections() -> list[Any]:
        try:
            return list(psutil.net_connections(kind="inet"))
        except psutil.Error:
            collected: list[Any] = []
            for proc in psutil.process_iter(["pid", "name"]):
                try:
                    collected.extend(proc.net_connections(kind="inet"))
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, psutil.Error):
                    continue
            return collected

    def scan_active_connections(
        self,
        storage: Storage,
        logs_dir: Path,
        net_key: str | None = None,
        targets_file: str | Path = "configs/targets.yaml",
        hosts_path: str | Path | None = None,
        clash_client: ClashApiClient | None = None,
    ) -> list[dict[str, Any]]:
        """Inspect active outbound sockets & Clash flows, resolve process/domain/strategy, and classify health."""
        clash_conns: list[dict[str, Any]] = []
        if clash_client is not None:
            try:
                conn_data = clash_client.get_connections_sync()
                raw_conns = (conn_data.get("connections") or []) if isinstance(conn_data, dict) else []
                clash_conns = [c for c in raw_conns if isinstance(c, dict)]
            except Exception:  # noqa: BLE001
                clash_conns = []

        self.update_ip_map_from_storage_and_logs(
            storage,
            logs_dir,
            clash_client=None,
            clash_connections=clash_conns,
        )
        guard = build_unlocker_protection_context(storage=storage, hosts_path=hosts_path)
        guard_enabled = bool(guard["enabled"])
        protected_procs_low = {p.lower() for p in guard["processes"]}
        protected_ips = set(guard["proxy_ips"])
        protected_domains = set(guard["domains"])

        resolved_key = net_key
        if resolved_key is None:
            row = storage.conn.execute(
                "SELECT network_key FROM networks ORDER BY last_seen DESC LIMIT 1"
            ).fetchone()
            resolved_key = str(row["network_key"]) if row else "AS12389:home:default"

        decisions = storage.get_decisions(resolved_key, active_only=False)
        decisions_map: dict[tuple[str, str], Decision] = {
            (d.domain.lower(), d.protocol.value): d for d in decisions
        }
        known_targets = {e["domain"].lower() for e in load_targets_from_yaml(targets_file) if e.get("domain")}

        # Tail logs rather than reading multi-MB logs completely on every 3s tick
        rotations = parse_circular_rotations(_tail_text(logs_dir / "winws2.log", max_bytes=131072))
        rotated_domains = {
            str(ev["domain"]).lower() for ev in rotations[-20:] if ev.get("domain")
        }
        sb_tail = _tail_text(logs_dir / "sing-box.log", max_bytes=131072)
        failed_ips = _parse_singbox_failed_ips(sb_tail)

        healthy_clash_endpoints: set[tuple[str, int]] = set()
        healthy_clash_domains: set[str] = set()
        stalled_clash_endpoints: set[tuple[str, int]] = set()
        clash_flows: list[dict[str, Any]] = []
        for c in clash_conns:
            meta = c.get("metadata") or {}
            rip = str(meta.get("destinationIP") or "").strip()
            try:
                rport = int(meta.get("destinationPort") or 0)
            except (TypeError, ValueError):
                rport = 0
            if not rip or not _is_external_ip(rip) or rport <= 0:
                continue

            raw_proc = str(meta.get("processPath") or "").strip()
            proc_name = Path(raw_proc.replace("\\", "/")).name if raw_proc else "sing-box"
            if not proc_name:
                proc_name = "sing-box"
            low_proc = proc_name.lower()
            if raw_proc and (
                low_proc in ("winws.exe", "winws2.exe", "ciadpi.exe", "tgwsproxy_windows.exe", "tg-ws-proxy.exe")
                or "tgwsproxy" in low_proc
            ):
                continue

            network = str(meta.get("network") or "tcp").strip().lower()
            if network == "udp":
                proto = "quic" if rport == 443 else "udp"
            else:
                proto = "tls" if rport in (443, 8443) else ("http" if rport == 80 else "tcp")

            host = str(meta.get("host") or meta.get("sniffHost") or "").strip().lower().rstrip(".")
            if host and _is_ip_literal(host):
                host = ""

            try:
                upload_b = int(c.get("upload") or 0)
            except (TypeError, ValueError):
                upload_b = 0
            try:
                download_b = int(c.get("download") or 0)
            except (TypeError, ValueError):
                download_b = 0
            age_sec = _parse_clash_conn_age_sec(c.get("start"))
            is_healthy = upload_b > 0 and download_b > 0
            is_stalled = (
                upload_b > 0
                and download_b == 0
                and proto in ("tls", "http", "tcp", "quic")
                and (age_sec is None or age_sec >= 3.0)
            )
            if is_healthy:
                healthy_clash_endpoints.add((rip, rport))
                if host:
                    healthy_clash_domains.add(host)
                    matched_h, _ = _match_decision_domain(host, decisions_map)
                    if matched_h:
                        healthy_clash_domains.add(matched_h)
            if is_stalled:
                stalled_clash_endpoints.add((rip, rport))

            clash_flows.append(
                {
                    "process": proc_name,
                    "rip": rip,
                    "rport": rport,
                    "proto": proto,
                    "host": host,
                    "is_healthy": is_healthy,
                    "is_stalled": is_stalled,
                }
            )

        def _build_conn_row(
            *,
            proc_name: str,
            pid: int | None,
            rip: str,
            rport: int,
            proto: str,
            sock_status: str,
            observed_host: str | None,
            active_healthy: bool = False,
        ) -> dict[str, Any]:
            matched_domain, dec = _match_decision_domain(observed_host, decisions_map)
            display_domain = matched_domain or observed_host or "—"

            layer = dec.layer if dec else "direct"
            strategy_id = dec.strategy_id if dec else None

            is_unlocker_conn = guard_enabled and (
                proc_name.lower() in protected_procs_low
                or rip in protected_ips
                or any(
                    display_domain == pd or display_domain.endswith("." + pd)
                    for pd in protected_domains
                    if display_domain != "—"
                )
            )
            endpoint_stalled = (rip, rport) in stalled_clash_endpoints or sock_status == "STALLED"
            is_healthy_conn = bool(
                (
                    active_healthy
                    or (rip, rport) in healthy_clash_endpoints
                    or (matched_domain and matched_domain in healthy_clash_domains)
                )
                and not endpoint_stalled
                and sock_status != "SYN_SENT"
            )
            is_telemetry = _is_telemetry_noise_domain(display_domain)

            if is_unlocker_conn:
                layer = "unlocker"
                strategy_id = "hosts/unlocker"
                health = "protected"
            elif is_healthy_conn:
                health = "protected" if (dec is not None and dec.layer in ("dpi", "vpn", "dns")) else "direct"
            elif is_telemetry:
                health = "protected" if (dec is not None and dec.layer in ("dpi", "vpn", "dns")) else "direct"
            elif sock_status in ("SYN_SENT", "STALLED") or endpoint_stalled or rip in failed_ips:
                health = "needs_fix"
            elif dec is not None and dec.status != "active":
                health = "needs_fix"
            elif matched_domain and matched_domain in rotated_domains and (dec is None or dec.layer == "dpi"):
                health = "needs_fix"
            elif dec is not None and dec.layer in ("dpi", "vpn", "dns"):
                health = "protected"
            else:
                health = "direct"

            return {
                "process": proc_name,
                "pid": pid,
                "remote_ip": rip,
                "remote_port": rport,
                "remote": f"{rip}:{rport}",
                "protocol": proto,
                "socket_status": sock_status,
                "domain": display_domain,
                "layer": layer,
                "strategy_id": strategy_id,
                "health": health,
                "active_healthy": is_healthy_conn,
            }

        conns = self._read_inet_connections()
        seen_keys: set[tuple[str, str, int, str]] = set()
        rows_out: list[dict[str, Any]] = []

        for c in conns:
            raddr = getattr(c, "raddr", None)
            if not raddr:
                continue
            rip = str(getattr(raddr, "ip", None) or (raddr[0] if len(raddr) >= 1 else ""))
            rport = int(getattr(raddr, "port", None) or (raddr[1] if len(raddr) >= 2 else 0))
            if not rip or not _is_external_ip(rip) or rport <= 0:
                continue

            sock_status = str(getattr(c, "status", "") or "NONE")
            if sock_status in ("LISTEN", "CLOSE_WAIT", "TIME_WAIT"):
                continue

            pid = getattr(c, "pid", None)
            proc_name = self._resolve_pid_name(pid)
            if proc_name.lower() in _INTERNAL_PROXY_PROCESSES:
                continue

            sock_type = getattr(c, "type", socket.SOCK_STREAM)
            if sock_type == socket.SOCK_DGRAM:
                proto = "quic" if rport == 443 else "udp"
            else:
                proto = "tls" if rport in (443, 8443) else ("http" if rport == 80 else "tcp")

            dedup_key = (proc_name, rip, rport, proto)
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            with self._lock:
                observed_host = self.ip_to_domain.get(rip)
            if not observed_host:
                self._schedule_rdns(rip)

            rows_out.append(
                _build_conn_row(
                    proc_name=proc_name,
                    pid=pid,
                    rip=rip,
                    rport=rport,
                    proto=proto,
                    sock_status=sock_status,
                    observed_host=observed_host,
                )
            )

        for flow in clash_flows:
            dedup_key = (flow["process"], flow["rip"], flow["rport"], flow["proto"])
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            with self._lock:
                observed_host = flow["host"] or self.ip_to_domain.get(flow["rip"])
            if not observed_host:
                self._schedule_rdns(flow["rip"])

            sock_status = (
                "STALLED"
                if (flow["is_stalled"] or (flow["rip"], flow["rport"]) in stalled_clash_endpoints)
                else "ESTABLISHED"
            )
            rows_out.append(
                _build_conn_row(
                    proc_name=flow["process"],
                    pid=None,
                    rip=flow["rip"],
                    rport=flow["rport"],
                    proto=flow["proto"],
                    sock_status=sock_status,
                    observed_host=observed_host,
                    active_healthy=bool(flow.get("is_healthy")),
                )
            )

        health_order = {"needs_fix": 0, "protected": 1, "direct": 2}
        rows_out.sort(key=lambda r: (health_order.get(r["health"], 9), r["process"].lower(), r["domain"]))
        with self._lock:
            self._last_scan = (time.monotonic(), resolved_key, [dict(r) for r in rows_out])
        return rows_out

    def record_event(self, domain: str, process: str, action: str, layer: str, strategy_id: str | None) -> None:
        stamp = datetime.now().strftime("%H:%M:%S")
        with self._lock:
            self.recent_events.appendleft(
                {
                    "timestamp": stamp,
                    "domain": domain,
                    "process": process,
                    "action": action,
                    "layer": layer,
                    "strategy_id": strategy_id,
                }
            )

    def _collect_fix_candidates(
        self,
        connections: list[dict[str, Any]],
        logs_dir: Path,
        max_domains: int,
        protected_domains: set[str] | None = None,
    ) -> list[tuple[str, str, str]]:
        """Return list of (domain, process_name, reason) eligible for real-time healing."""
        now = time.monotonic()
        candidates: list[tuple[str, str, str]] = []
        seen: set[str] = set()
        prot = protected_domains or set()

        with self._lock:
            cooldowns = dict(self.cooldown_until)

        healthy_domains = {
            str(c.get("domain") or "").lower()
            for c in connections
            if c.get("domain")
            and c.get("domain") != "—"
            and c.get("health") != "needs_fix"
            and (c.get("active_healthy") or c.get("socket_status") == "ESTABLISHED")
        }

        for conn in connections:
            dom = str(conn.get("domain") or "")
            if (
                conn.get("layer") == "unlocker"
                or conn.get("health") != "needs_fix"
                or not dom
                or dom == "—"
                or _is_rdns_ptr_hostname(dom)
                or _is_telemetry_noise_domain(dom)
                or dom.lower() in healthy_domains
            ):
                continue
            if dom in seen or cooldowns.get(dom, 0.0) > now:
                continue
            seen.add(dom)
            sock_st = str(conn.get("socket_status") or "")
            if sock_st == "SYN_SENT":
                reason = "SYN_SENT stall"
            elif sock_st == "STALLED":
                reason = "Clash stall"
            else:
                reason = "degraded/unprotected"
            candidates.append((dom, str(conn.get("process") or "system"), reason))
            if len(candidates) >= max_domains:
                return candidates

        for rot in reversed(parse_circular_rotations(_tail_text(logs_dir / "winws2.log", max_bytes=131072))):
            dom = str(rot.get("domain") or "").lower()
            if (
                not dom
                or dom in seen
                or dom in healthy_domains
                or cooldowns.get(dom, 0.0) > now
                or _is_rdns_ptr_hostname(dom)
                or _is_telemetry_noise_domain(dom)
            ):
                continue
            if any(dom == pd or dom.endswith("." + pd) for pd in prot):
                continue
            seen.add(dom)
            candidates.append((dom, "winws2", f"circular strategy={rot.get('strategy')}"))
            if len(candidates) >= max_domains:
                break
        return candidates

    async def auto_heal_connections(
        self,
        backend: Any,
        max_domains_per_tick: int = 2,
        timeout: float = 2.0,
    ) -> dict[str, Any]:
        """Scan live connections and automatically diagnose + assign working strategies for broken domains."""
        logs_dir = Path(backend.logs_dir)
        hosts_path = getattr(backend, "hosts_path", None)
        clash_client = None
        if hasattr(backend, "_collect_processes_state") and hasattr(backend, "clash_api"):
            try:
                proc_state = backend._collect_processes_state()
                if bool((proc_state.get("sing-box") or {}).get("running")):
                    clash_client = backend.clash_api
            except Exception:  # noqa: BLE001
                clash_client = None

        storage = Storage(backend.db_path)
        try:
            net_key, _, _, _ = backend._resolve_network_info(storage)
            active_preset_id = storage.get_setting("active_zapret_preset_id", "auto").strip()
            guard = build_unlocker_protection_context(storage=storage, hosts_path=hosts_path)
            connections = self.scan_active_connections(
                storage,
                logs_dir,
                net_key=net_key,
                hosts_path=hosts_path,
                clash_client=clash_client,
            )
            # When the user activated a fixed working Zapret2 preset, do NOT spin the DPI orchestrator
            # or overwrite/reload winws2 — just return live connections for monitoring!
            if active_preset_id and active_preset_id != "auto":
                with self._lock:
                    events = list(self.recent_events)
                return {"connections": connections, "healed": [], "events": events, "preset_locked": True}
            candidates = self._collect_fix_candidates(
                connections,
                logs_dir,
                max_domains_per_tick,
                protected_domains=set(guard["domains"]) if guard["enabled"] else None,
            )
        finally:
            storage.close()

        healed: list[dict[str, Any]] = []
        if not candidates:
            with self._lock:
                events = list(self.recent_events)
            return {"connections": connections, "healed": healed, "events": events}

        bypass = detect_bypass_active()
        net = await detect_network_fingerprint(timeout=timeout)
        dpi_orch = DpiLayerOrchestrator()
        any_saved = False
        dpi_or_vpn_changed = False
        winws2_changed = False
        singbox_changed = False
        has_new_domain = False
        bypass_fell = not bypass

        # Load DB state and filter pinned domains BEFORE awaiting network probes concurrently
        storage = Storage(backend.db_path)
        try:
            net_key = storage.upsert_network(net)
            backend._seed_default_strategies(storage)
            strategy_pool = storage.get_strategies()
            has_real_vpn = storage.has_usable_vpn()
            can_dns_bypass = storage.get_setting("stack_mode", "hybrid").strip().lower() != "dpi_only"
            active_decisions = {
                (d.domain.lower(), d.protocol): d for d in storage.get_decisions(net_key, active_only=False)
            }
            pinned_domains = {
                str(r[0]).lower()
                for r in storage.conn.execute("SELECT DISTINCT domain FROM decisions WHERE pinned = 1").fetchall()
            }
        finally:
            storage.close()

        eligible: list[tuple[str, str, str, Decision | None]] = []
        now_cd = time.monotonic()
        with self._lock:
            for dom, proc_name, reason in candidates:
                existing = active_decisions.get((dom.lower(), Protocol.TLS))
                if dom.lower() in pinned_domains or (existing is not None and getattr(existing, "pinned", False)):
                    # User explicitly pinned this working rule — never churn it automatically!
                    continue
                prev_fails = existing.consecutive_fails if existing is not None else 0
                cd_sec = min(300.0, self.cooldown_sec * (2 ** min(max(prev_fails, 0), 4)))
                self.cooldown_until[dom] = now_cd + cd_sec
                eligible.append((dom, proc_name, reason, existing))

        if not eligible:
            with self._lock:
                events = list(self.recent_events)
            return {"connections": connections, "healed": healed, "events": events}

        probes_list = await asyncio.gather(
            *(run_domain_probes(dom, timeout=timeout) for dom, _proc, _reason, _ex in eligible)
        )
        ordered_tls_ids = [s.id for s in _ordered_pool(strategy_pool, Protocol.TLS) if s.args_template]

        storage = Storage(backend.db_path)
        try:
            for (dom, proc_name, reason, existing), probes in zip(eligible, probes_list):
                report = classify_probes(domain=dom, probes=probes, network=net, bypass_active=bypass)
                storage.save_verdict(net_key, report, protocol=Protocol.TLS)

                ip = probes.tcp.target_ip or (
                    probes.dns.doh_ips[0]
                    if probes.dns.doh_ips
                    else (probes.dns.system_ips[0] if probes.dns.system_ips else "127.0.0.1")
                )

                # If bypass is already active and TLS actually failed (not just a QUIC-only timeout) -> promote fallback!
                tls_failed = any(
                    v in report.verdicts
                    for v in (VerdictClass.SNI_DPI, VerdictClass.THROTTLE, VerdictClass.IP_BLOCK, VerdictClass.UNKNOWN)
                )
                tls_broken = (tls_failed or "circular" in reason) and (
                    "SYN_SENT" in reason
                    or "Clash stall" in reason
                    or "circular" in reason
                    or (existing is not None and existing.layer == "dpi" and bypass)
                )
                wants_smart_dns = (
                    not has_real_vpn
                    and can_dns_bypass
                    and (VerdictClass.IP_BLOCK in report.verdicts or is_geoblock_or_ai_domain(dom))
                    and (tls_failed or existing is None or existing.layer != "dns")
                )
                if existing is not None and existing.layer == "dns" and bypass and tls_broken and can_dns_bypass:
                    if existing.fallback_strategies:
                        new_dec = promote_fallback_on_failure(storage, existing, vpn_available=has_real_vpn)
                        action = f"DNS fallback ({reason}) -> {new_dec.layer}/{new_dec.strategy_id or '—'}"
                    else:
                        new_dec = await DnsLayerOrchestrator().roll_dns_for_domain(
                            dom,
                            network_key=net_key,
                            storage=storage,
                            timeout=min(timeout, 1.5),
                        )
                        storage.save_decision(new_dec)
                        action = f"Подбор DNS ({reason}) -> {new_dec.layer}/{new_dec.strategy_id or '—'}"
                elif wants_smart_dns and (existing is None or existing.layer != "dns"):
                    new_dec = await DnsLayerOrchestrator().roll_dns_for_domain(
                        dom,
                        network_key=net_key,
                        storage=storage,
                        timeout=min(timeout, 1.5),
                    )
                    storage.save_decision(new_dec)
                    action = f"SmartDNS ({reason}) -> {new_dec.layer}/{new_dec.strategy_id or '—'}"
                elif existing is not None and existing.layer == "dpi" and bypass and tls_broken:
                    # If no fallbacks remain and no real VPN is configured, rotate to next untested ordered TLS strategies
                    if not existing.fallback_strategies and not has_real_vpn and ordered_tls_ids:
                        if existing.strategy_id in ordered_tls_ids:
                            idx = ordered_tls_ids.index(existing.strategy_id)
                            rotated = ordered_tls_ids[idx + 1 :] + ordered_tls_ids[:idx]
                        else:
                            rotated = [sid for sid in ordered_tls_ids if sid != existing.strategy_id]
                        if rotated:
                            existing.fallback_strategies = rotated[:3]
                    new_dec = promote_fallback_on_failure(storage, existing, vpn_available=has_real_vpn)
                    action = f"Fallback ({reason}) -> {new_dec.layer}/{new_dec.strategy_id or '—'}"
                else:
                    new_dec = await dpi_orch.evaluate_domain(
                        domain=dom,
                        ip=ip,
                        verdicts=report.verdicts,
                        network_key=net_key,
                        protocol=Protocol.TLS,
                        candidates=strategy_pool,
                        live_eval=True,
                        bin_dir=backend.bin_dir,
                        vpn_available=has_real_vpn,
                    )
                    if (
                        bypass
                        and new_dec.layer == "direct"
                        and existing is not None
                        and existing.status == "active"
                        and (
                            existing.layer in ("dpi", "dns")
                            or (
                                existing.layer == "vpn"
                                and (has_real_vpn or getattr(existing, "pinned", False))
                            )
                        )
                    ):
                        # Self-probe protection: preserve active bypass rules when probes succeed through them
                        continue
                    # Avoid blackholing into a fake/empty VPN when no real VPN node exists
                    if new_dec.layer == "vpn" and not has_real_vpn and ordered_tls_ids:
                        first_tls_id = ordered_tls_ids[0]
                        new_dec = Decision(
                            network_key=net_key,
                            domain=dom,
                            protocol=Protocol.TLS,
                            layer="dpi",
                            strategy_id=first_tls_id,
                            fallback_strategies=[sid for sid in ordered_tls_ids if sid != first_tls_id][:3],
                        )
                    storage.save_decision(new_dec)
                    action = f"Автоподбор ({reason}) -> {new_dec.layer}/{new_dec.strategy_id or '—'}"

                any_saved = True
                decision_changed = (
                    existing is None
                    or existing.layer != new_dec.layer
                    or existing.strategy_id != new_dec.strategy_id
                    or existing.status != new_dec.status
                )
                if decision_changed:
                    if existing is None:
                        has_new_domain = True
                    elif existing.layer == "dpi" and bypass and tls_broken:
                        bypass_fell = True
                    if new_dec.layer in ("dpi", "vpn", "dns"):
                        dpi_or_vpn_changed = True
                    if new_dec.layer == "dpi" or (
                        existing is not None and existing.layer == "dpi" and new_dec.layer != "dpi"
                    ):
                        winws2_changed = True
                    if new_dec.layer in ("vpn", "dns") or (
                        existing is not None and existing.layer in ("vpn", "dns") and new_dec.layer != existing.layer
                    ):
                        singbox_changed = True
                with self._lock:
                    self.auto_healed_count += 1
                self.record_event(dom, proc_name, action, new_dec.layer, new_dec.strategy_id)
                healed.append(
                    {
                        "domain": dom,
                        "process": proc_name,
                        "layer": new_dec.layer,
                        "strategy_id": new_dec.strategy_id,
                        "reason": reason,
                    }
                )
        finally:
            storage.close()

        if any_saved:
            self.invalidate_scan_cache()

        reload_deferred: list[str] = []
        if any_saved and (dpi_or_vpn_changed or winws2_changed or singbox_changed):
            procs = backend._collect_processes_state()
            is_adm = _is_admin()
            urgent_reload = bool(has_new_domain or bypass_fell)
            defer_active = bool(bypass)
            if ((procs.get("winws2") or {}).get("running")) and is_adm:
                if hasattr(backend, "reload_winws2_if_changed"):
                    w_res = backend.reload_winws2_if_changed(
                        min_interval_sec=0.0 if urgent_reload else 20.0,
                        defer_if_active=defer_active,
                    )
                    if isinstance(w_res, dict) and w_res.get("deferred"):
                        reload_deferred.append("winws2")
                else:
                    backend.reload_winws2()
            else:
                backend.trigger_apply_configs()

            if singbox_changed and ((procs.get("sing-box") or {}).get("running")) and is_adm:
                if hasattr(backend, "reload_singbox_if_changed"):
                    sb_res = backend.reload_singbox_if_changed(
                        min_interval_sec=0.0 if urgent_reload else 15.0,
                        defer_if_active=defer_active,
                    )
                    if isinstance(sb_res, dict) and sb_res.get("deferred"):
                        reload_deferred.append("sing-box")
                else:
                    backend.reload_singbox()

        if any_saved:
            # Re-scan after healing so returned connections reflect new strategies
            storage = Storage(backend.db_path)
            try:
                connections = self.scan_active_connections(
                    storage, logs_dir, net_key=net_key, hosts_path=hosts_path, clash_client=clash_client
                )
            finally:
                storage.close()

        with self._lock:
            events = list(self.recent_events)
        return {"connections": connections, "healed": healed, "events": events, "reload_deferred": reload_deferred}


class MasterRoutingOrchestrator:
    """Top-level coordinator combining DNS, DPI, VPN layer orchestrators and the Live Connection Radar."""

    def __init__(self) -> None:
        self.dns = DnsLayerOrchestrator()
        self.dpi = DpiLayerOrchestrator()
        self.vpn = VpnLayerOrchestrator()
        self.monitor = RealtimeConnectionMonitor()

    async def get_full_orchestrator_report(
        self,
        storage: Storage,
        logs_dir: Path,
        network_key: str,
        processes: dict[str, Any] | None = None,
        probe_live: bool = False,
        connections: list[dict[str, Any]] | None = None,
        hosts_path: str | Path | None = None,
        clash_client: ClashApiClient | None = None,
    ) -> dict[str, Any]:
        """Collect structured telemetry for all 4 orchestration layers (optionally probing live RTT/pings)."""
        decisions = storage.get_decisions(network_key, active_only=False)
        nodes = storage.get_all_subscription_nodes()
        verdict_rows_raw = storage.conn.execute(
            "SELECT verdicts_json FROM verdicts WHERE network_key = ?",
            (network_key,),
        ).fetchall()
        import json

        verdict_rows = [
            {"verdicts": json.loads(r["verdicts_json"] or "[]")} for r in verdict_rows_raw
        ]

        active_dns = self.dns.get_active_dns(storage)
        dns_summary = self.dns.inspect_status(decisions, verdict_rows, active_dns=active_dns)
        dpi_summary = self.dpi.inspect_status(decisions, logs_dir / "winws2.log", processes=processes)
        vpn_summary = self.vpn.inspect_status(
            decisions,
            nodes,
            processes=processes,
            clash_client=clash_client,
            storage=storage,
        )

        if probe_live:
            dns_live, vpn_live = await asyncio.gather(
                self.dns.check_health(),
                self.vpn.check_health(nodes, clash_client=clash_client, storage=storage),
            )
            dns_summary.update(dns_live)
            vpn_summary.update(
                {
                    "status": vpn_live["status"] if not vpn_summary["running"] else "running",
                    "alive_count": vpn_live["alive_count"],
                    "best_node": vpn_live["best_node"],
                    "best_ping_ms": vpn_live["best_ping_ms"],
                    "tg_proxy_alive": vpn_live["tg_proxy_alive"],
                    "nodes": vpn_live["nodes"],
                }
            )

        conns = (
            connections
            if connections is not None
            else self.monitor.scan_active_connections(
                storage, logs_dir, net_key=network_key, hosts_path=hosts_path, clash_client=clash_client
            )
        )
        apps = sorted({str(c.get("process") or "") for c in conns if c.get("process")})
        needs_fix_count = sum(1 for c in conns if c.get("health") == "needs_fix")
        with self.monitor._lock:
            auto_healed = self.monitor.auto_healed_count
            events_count = len(self.monitor.recent_events)

        realtime_summary = {
            "layer": "realtime",
            "active_connections": len(conns),
            "needs_fix_count": needs_fix_count,
            "apps_count": len(apps),
            "auto_healed_count": auto_healed,
            "events_count": events_count,
        }

        return {
            "dns": dns_summary,
            "dpi": dpi_summary,
            "vpn": vpn_summary,
            "realtime": realtime_summary,
        }
