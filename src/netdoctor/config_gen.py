"""Config generator for winws2 (profiles + hostlists + circular catch-all) and sing-box (TUN, DoH DNS, multi-VPN urltest/selector, tg-ws-proxy, Clash API)."""

from __future__ import annotations

import concurrent.futures
import ctypes
from ctypes import wintypes
import ipaddress
import json
import os
import re
import socket
import struct
import threading
import time
import urllib.parse
from pathlib import Path
from typing import Any, Iterable, NamedTuple

import dns.resolver

from netdoctor.models import Decision, Protocol, Strategy, VpnNode
from netdoctor.vpn import infer_node_region, is_placeholder_node

KNOWN_BLOBS: dict[str, str] = {
    "quic_google": "@files/quic_initial_www_google_com.bin",
    "tls_google": "@files/tls_clienthello_www_google_com.bin",
    "tls_max": "@files/tls_clienthello_max_ru.bin",
    "http_max": "@files/tls_clienthello_max_ru.bin",
    "tls_4pda": "@files/tls_clienthello_4pda_to.bin",
    "stun2": "@files/stun2.bin",
    "stun_pat": "@files/stun.bin",
    "fake_stun_as_tls": "@files/stun.bin",
    "discord_active": "@files/ACTIVE_DISCORD_UDP.bin",
    "game_active": "@files/ACTIVE_GAME_UDP.bin",
    "fake_dbankcloud": "@files/quic_initial_dbankcloud_ru.bin",
    "tls_vk": "@files/tls_clienthello_vk_com.bin",
    "tls_sber": "@files/tls_clienthello_sberbank_ru.bin",
    "tls_gosuslugi": "@files/tls_clienthello_gosuslugi_ru.bin",
    "tls_iana": "@files/tls_clienthello_iana_org.bin",
    "tls1": "@files/tls_clienthello_1.bin",
    "tls2": "@files/tls_clienthello_2.bin",
    "tls3": "@files/tls_clienthello_3.bin",
    "tls4": "@files/tls_clienthello_4.bin",
    "tls5": "@files/tls_clienthello_5.bin",
    "tls7": "@files/tls_clienthello_7.bin",
    "quic1": "@files/quic_1.bin",
    "quic6": "@files/quic_6.bin",
    "quic_test": "@files/quic_test_00.bin",
    "tls_sferum": "@files/tls_clienthello_www_sferum_ru.bin",
    "tls_sochi": "@files/tls_clienthello_sochi_park.bin",
    "tls_5ka": "@files/tls_clienthello_5ka_ru.bin",
    "tls_awswaf": "@files/tls_clienthello_awswaf_com.bin",
    "tls_steam": "@files/tls_clienthello_steamstatic_com.bin",
    "tls_steam_chat": "@files/tls_clienthello_steam_chat_com.bin",
    "tls_teamspeak": "@files/tls_clienthello_teamspeak_com.bin",
    "tls_vk_kyber": "@files/tls_clienthello_vk_com_kyber.bin",
    "tls_sber_v2": "@files/tls_clienthello_sberbank_ru_v2.bin",
    "quic_rutube": "@files/quic_initial_rutube_ru.bin",
    "quic_5ka": "@files/quic_initial_5ka_ru.bin",
    "quic_lemana": "@files/quic_initial_lemana_pro.bin",
    "quic_vk": "@files/quic_initial_vk_com.bin",
    "quic_4pda": "@files/quic_initial_4pda_to.bin",
    "zero256": "@files/zero_256.bin",
    "fake_unknown_256": "@files/zero_256.bin",
    "zero64": "0x" + ("00" * 64),
    "fake_zero64": "0x" + ("00" * 64),
    "fake_default_udp": "0x" + ("00" * 16),
}

QUIC_HOSTLIST_DOMAINS: tuple[str, ...] = (
    "youtube.com",
    "googlevideo.com",
    "instagram.com",
    "facebook.com",
)

TELEGRAM_CIDRS: tuple[str, ...] = (
    "91.108.4.0/22",
    "91.108.8.0/22",
    "91.108.12.0/22",
    "91.108.16.0/22",
    "91.108.20.0/22",
    "91.108.56.0/22",
    "91.105.192.0/23",
    "149.154.160.0/20",
    "185.76.151.0/24",
    "2001:b28:f23c::/48",
    "2001:b28:f23d::/48",
    "2001:b28:f23f::/48",
    "2001:67c:4e8::/48",
    "2a0a:f280::/32",
)

CDN_DOMAIN_EXPANSIONS: dict[str, tuple[str, ...]] = {
    "youtube.com": (
        "googlevideo.com",
        "ytimg.com",
        "i.ytimg.com",
        "youtu.be",
        "yt.be",
        "ggpht.com",
        "yt3.ggpht.com",
        "yt4.ggpht.com",
        "youtubei.googleapis.com",
        "youtube.googleapis.com",
        "youtube-nocookie.com",
        "yt3.googleusercontent.com",
        "lh3.googleusercontent.com",
        "jnn-pa.googleapis.com",
        "gvt1.com",
        "youtubekids.com",
        "wide-youtube.l.google.com",
    ),
    "discord.com": (
        "discord.gg",
        "discordapp.com",
        "discord.media",
        "discordapp.net",
        "discordcdn.com",
        "discordstatus.com",
        "discord.co",
        "dis.gd",
        "discord-attachments-uploads-prd.storage.googleapis.com",
    ),
    "telegram.org": (
        "t.me",
        "telegram.me",
        "telegram.dog",
        "telesco.pe",
        "tdesktop.com",
        "telegram-cdn.org",
        "web.telegram.org",
        "api.telegram.org",
    ),
    "instagram.com": ("cdninstagram.com", "ig.me"),
    "x.com": ("twimg.com", "twitter.com"),
}


def to_cygwin_safe_path(path: Path, base_dir: Path | None = None) -> str:
    """Return a Cygwin-safe path (relative inside base_dir without '..', else 8.3 short/absolute path)."""
    resolved = path.resolve()
    base_resolved = base_dir.resolve() if base_dir is not None else None
    if base_resolved is not None:
        try:
            rel = resolved.relative_to(base_resolved).as_posix()
            if rel.isascii() and " " not in rel:
                return rel
        except ValueError:
            pass
    raw = str(resolved)
    if os.name == "nt" and (not raw.isascii() or " " in raw) and resolved.exists():
        try:
            get_short = ctypes.windll.kernel32.GetShortPathNameW  # type: ignore[attr-defined]
            buf = ctypes.create_unicode_buffer(32768)
            n = get_short(raw, buf, len(buf))
            if n and buf.value:
                short_posix = Path(buf.value).as_posix()
                if short_posix.isascii() and " " not in short_posix:
                    return short_posix
        except Exception:  # noqa: BLE001
            pass
    # Fallback when 8.3 names are disabled on a non-ASCII volume: Cygwin mounts '<root>' as '/' when cygwin1.dll is in '<root>/bin'
    if (
        (not raw.isascii() or " " in raw)
        and base_resolved is not None
        and base_resolved.name.lower() == "bin"
        and (base_resolved / "cygwin1.dll").is_file()
    ):
        try:
            root_rel = resolved.relative_to(base_resolved.parent).as_posix()
            if root_rel.isascii() and " " not in root_rel:
                return f"/{root_rel}"
        except ValueError:
            pass
    return resolved.as_posix()


_VIRTUAL_IFACE_KEYWORDS: tuple[str, ...] = (
    "sing-tun",
    "wintun",
    "netdoctor-tun",
    "wireguard",
    "tap-windows",
    "openvpn",
    "radmin",
    "tailscale",
    "zerotier",
    "loopback",
    "bluetooth",
)


class _MIB_IPFORWARDROW(ctypes.Structure):
    _fields_ = [
        ("dwForwardDest", wintypes.DWORD),
        ("dwForwardMask", wintypes.DWORD),
        ("dwForwardPolicy", wintypes.DWORD),
        ("dwForwardNextHop", wintypes.DWORD),
        ("dwForwardIfIndex", wintypes.DWORD),
        ("dwForwardType", wintypes.DWORD),
        ("dwForwardProto", wintypes.DWORD),
        ("dwForwardAge", wintypes.DWORD),
        ("dwForwardNextHopAS", wintypes.DWORD),
        ("dwForwardMetric1", wintypes.DWORD),
        ("dwForwardMetric2", wintypes.DWORD),
        ("dwForwardMetric3", wintypes.DWORD),
        ("dwForwardMetric4", wintypes.DWORD),
        ("dwForwardMetric5", wintypes.DWORD),
    ]


class _MIB_IFROW(ctypes.Structure):
    _fields_ = [
        ("wszName", wintypes.WCHAR * 256),
        ("dwIndex", wintypes.DWORD),
        ("dwType", wintypes.DWORD),
        ("dwMtu", wintypes.DWORD),
        ("dwSpeed", wintypes.DWORD),
        ("dwPhysAddrLen", wintypes.DWORD),
        ("bPhysAddr", ctypes.c_ubyte * 8),
        ("dwAdminStatus", wintypes.DWORD),
        ("dwOperStatus", wintypes.DWORD),
        ("dwLastChange", wintypes.DWORD),
        ("dwInOctets", wintypes.DWORD),
        ("dwInUcastPkts", wintypes.DWORD),
        ("dwInNUcastPkts", wintypes.DWORD),
        ("dwInDiscards", wintypes.DWORD),
        ("dwInErrors", wintypes.DWORD),
        ("dwInUnknownProtos", wintypes.DWORD),
        ("dwOutOctets", wintypes.DWORD),
        ("dwOutUcastPkts", wintypes.DWORD),
        ("dwOutNUcastPkts", wintypes.DWORD),
        ("dwOutDiscards", wintypes.DWORD),
        ("dwOutErrors", wintypes.DWORD),
        ("dwOutQLen", wintypes.DWORD),
        ("dwDescrLen", wintypes.DWORD),
        ("bDescr", ctypes.c_char * 256),
    ]


def detect_physical_egress_route() -> tuple[int | None, str]:
    """Return (ifIndex, next_hop) of the active physical IPv4 default gateway, excluding TUN/virtual adapters."""
    if os.name != "nt":
        return None, ""
    try:
        iphlpapi = ctypes.windll.iphlpapi  # type: ignore[attr-defined]
        size = wintypes.DWORD(0)
        iphlpapi.GetIpForwardTable(None, ctypes.byref(size), True)
        if size.value < 4:
            return None, ""
        buf = (ctypes.c_byte * size.value)()
        if iphlpapi.GetIpForwardTable(buf, ctypes.byref(size), True) != 0:
            return None, ""

        num_entries = struct.unpack_from("<I", buf, 0)[0]
        row_size = ctypes.sizeof(_MIB_IPFORWARDROW)
        candidates: list[tuple[int, int, int, str]] = []
        for idx in range(num_entries):
            offset = 4 + idx * row_size
            if offset + row_size > size.value:
                break
            row = _MIB_IPFORWARDROW.from_buffer(buf, offset)
            if row.dwForwardDest != 0 or row.dwForwardMask != 0 or row.dwForwardNextHop == 0:
                continue
            if_idx = int(row.dwForwardIfIndex)
            if if_idx <= 0:
                continue
            nexthop = socket.inet_ntoa(struct.pack("<I", row.dwForwardNextHop))
            if nexthop.startswith(("0.", "127.", "172.19.0.")):
                continue

            if_row = _MIB_IFROW()
            if_row.dwIndex = if_idx
            if_rc = iphlpapi.GetIfEntry(ctypes.byref(if_row))
            if if_rc == 0:
                if int(if_row.dwType) in (24, 131) or int(if_row.dwOperStatus) < 4:
                    continue
                descr_len = min(int(if_row.dwDescrLen), 256)
                descr = bytes(if_row.bDescr[:descr_len]).rstrip(b"\x00").decode("mbcs", errors="replace").lower()
                if any(kw in descr for kw in _VIRTUAL_IFACE_KEYWORDS):
                    continue

            candidates.append((0 if if_rc == 0 else 1, int(row.dwForwardMetric1), if_idx, nexthop))

        if not candidates:
            return None, ""
        candidates.sort()
        _, _, best_if_idx, best_nexthop = candidates[0]
        return best_if_idx, best_nexthop
    except Exception:  # noqa: BLE001
        return None, ""


def detect_physical_egress_iface() -> int | None:
    """Return Windows interface index (ifIndex) of the primary physical uplink adapter."""
    return detect_physical_egress_route()[0]

_BLOB_REF_RE = re.compile(r"(?:blob|seqovl_pattern)=([A-Za-z0-9_]+)")


def _resolve_blob_value(name: str, files_dir: Path, validate_files: bool) -> str:
    val = KNOWN_BLOBS[name]
    if not (validate_files and val.startswith("@files/")):
        return val
    target = files_dir / val[len("@files/") :]
    if target.is_file() and target.stat().st_size > 0:
        return val

    if name.startswith(("tls", "http")):
        fallback = "@files/tls_clienthello_www_google_com.bin"
    elif name.startswith("quic") or name == "fake_dbankcloud":
        fallback = "@files/quic_initial_www_google_com.bin"
    elif name in ("discord_active", "game_active") or "stun" in name:
        fallback = "@files/stun.bin"
    else:
        fallback = "@files/zero_256.bin"

    fb_target = files_dir / fallback[len("@files/") :]
    if fb_target.is_file() and fb_target.stat().st_size > 0:
        return fallback
    return "0x" + ("00" * 64)


def extract_blob_args(args: list[str], bin_dir: str | Path | None = None) -> list[str]:
    """Return sorted --blob=... definitions for any KNOWN_BLOBS referenced in winws2 args."""
    needed: set[str] = set()
    for tok in args:
        if "--lua-desync=" in tok:
            for match in _BLOB_REF_RE.finditer(tok):
                name = match.group(1)
                if name in KNOWN_BLOBS:
                    needed.add(name)
    files_dir = (Path(bin_dir) if bin_dir is not None else Path("bin")) / "files"
    validate_files = files_dir.is_dir()
    return [f"--blob={name}:{_resolve_blob_value(name, files_dir, validate_files)}" for name in sorted(needed)]


def _uses_known_file_blob(strat: Strategy) -> bool:
    for tok in strat.args_template:
        for match in _BLOB_REF_RE.finditer(tok):
            name = match.group(1)
            if name in KNOWN_BLOBS and KNOWN_BLOBS[name].startswith("@"):
                return True
    return False


def _is_ip_address(value: str) -> bool:
    clean = (value or "").strip().strip("[]")
    if not clean:
        return False
    try:
        ipaddress.ip_address(clean)
        return True
    except ValueError:
        return False


_VPN_DNS_LOCK = threading.Lock()
_VPN_DNS_CACHE: dict[str, tuple[list[str], float]] = {}


def clear_vpn_dns_cache() -> None:
    """Invalidate cached VPN server hostname resolutions."""
    with _VPN_DNS_LOCK:
        _VPN_DNS_CACHE.clear()


def _resolve_single_hostname(srv: str) -> list[str]:
    if "." not in srv:
        ips: set[str] = set()
        try:
            infos = socket.getaddrinfo(srv, None)
            for _family, _type, _proto, _canonname, sockaddr in infos:
                ip_part = str(sockaddr[0]).split("%", 1)[0]
                ipaddress.ip_address(ip_part)
                ips.add(ip_part)
        except (socket.gaierror, OSError, ValueError):
            return []
        return sorted(ips)

    from netdoctor.probes import order_system_nameservers, record_system_nameserver_winner

    def _collect_v4_from_resolver(res: dns.resolver.Resolver) -> tuple[list[str], bool]:
        """Return (sorted_ipv4_list, nxdomain_hit)."""
        try:
            ans = res.resolve(srv, "A")
            ips = {
                r.address
                for r in ans
                if ipaddress.ip_address(r.address).version == 4
            }
            return sorted(ips), False
        except dns.resolver.NXDOMAIN:
            return [], True
        except (
            dns.resolver.NoAnswer,
            dns.resolver.LifetimeTimeout,
            dns.resolver.NoNameservers,
            OSError,
            ValueError,
        ):
            return [], False

    try:
        resolver = dns.resolver.Resolver()
        ordered_ns = order_system_nameservers([str(ns) for ns in (resolver.nameservers or [])])
        if ordered_ns:
            resolver.nameservers = ordered_ns
        resolver.timeout = 0.6
        resolver.lifetime = 1.5
        ans = resolver.resolve(srv, "A")
        if ordered_ns:
            record_system_nameserver_winner(ordered_ns, str(getattr(ans, "nameserver", "") or ""))
        ips = {
            r.address
            for r in ans
            if ipaddress.ip_address(r.address).version == 4
        }
        if ips:
            return sorted(ips)
    except dns.resolver.NXDOMAIN:
        return []
    except (
        dns.resolver.NoAnswer,
        dns.resolver.LifetimeTimeout,
        dns.resolver.NoNameservers,
        OSError,
        ValueError,
    ):
        pass

    # System DNS timed out or had no answer — fallback to public resolvers before giving up
    pub_resolver = dns.resolver.Resolver(configure=False)
    pub_resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
    pub_resolver.timeout = 0.6
    pub_resolver.lifetime = 1.5
    pub_ips, nx = _collect_v4_from_resolver(pub_resolver)
    if nx:
        return []
    if pub_ips:
        return pub_ips

    try:
        infos = socket.getaddrinfo(srv, None, socket.AF_INET)
        fallback_ips = {
            str(sockaddr[0]).split("%", 1)[0]
            for _f, _t, _p, _c, sockaddr in infos
            if _is_ip_address(str(sockaddr[0]).split("%", 1)[0])
        }
        return sorted(fallback_ips)
    except (socket.gaierror, OSError):
        return []


def resolve_vpn_ips(raw_servers: list[str] | None) -> list[str]:
    """Resolve VPN server entries (IPs, CIDRs, or hostnames) into deduplicated IP/CIDR strings."""
    resolved: set[str] = set()
    hostnames: list[str] = []
    seen_hosts: set[str] = set()
    for raw in raw_servers or []:
        srv = raw.strip()
        if not srv:
            continue
        try:
            ipaddress.ip_address(srv)
            resolved.add(srv)
            continue
        except ValueError:
            pass
        if "/" in srv:
            try:
                ipaddress.ip_network(srv, strict=False)
                resolved.add(srv)
                continue
            except ValueError:
                pass
        key = srv.lower()
        if key not in seen_hosts:
            seen_hosts.add(key)
            hostnames.append(srv)

    if not hostnames:
        return sorted(resolved)

    now = time.monotonic()
    to_resolve: list[str] = []
    with _VPN_DNS_LOCK:
        for host in hostnames:
            cached = _VPN_DNS_CACHE.get(host.lower())
            if cached is not None and cached[1] > now:
                resolved.update(cached[0])
            else:
                to_resolve.append(host)

    if to_resolve:
        if len(to_resolve) == 1:
            results = [_resolve_single_hostname(to_resolve[0])]
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(to_resolve))) as pool:
                results = list(pool.map(_resolve_single_hostname, to_resolve))
        done_now = time.monotonic()
        with _VPN_DNS_LOCK:
            if len(_VPN_DNS_CACHE) > 256:
                _VPN_DNS_CACHE.clear()
            for host, ips in zip(to_resolve, results):
                ttl = 300.0 if ips else 10.0
                _VPN_DNS_CACHE[host.lower()] = (list(ips), done_now + ttl)
                resolved.update(ips)

    return sorted(resolved)


def generate_winws2_config(
    decisions: list[Decision],
    strategies: dict[str, Strategy],
    lists_dir: str | Path = "lists",
    vpn_server_ips: list[str] | None = None,
    enable_circular_catchall: bool = True,
    iface: int | str | None = None,
    game_filter: bool = False,
    exclude_domains: list[str] | None = None,
    expand_cdn_domains: bool = False,
    enable_tcp_in: bool = False,
    enable_telegram_ipset: bool = True,
    isp_best_tls: str | None = None,
    bundle_pass_domains: list[str] | None = None,
    enable_game_udp_dpi: bool = False,
    dns_infra_ips: list[str] | None = None,
    dns_infra_domains: list[str] | None = None,
    bundle_dpi_domains: Iterable[str] | None = None,
    bin_dir: str | Path | None = None,
) -> tuple[list[str], dict[str, list[str]]]:
    """Generate winws2 command-line arguments and write hostlist files per winning strategy.

    Returns (args_list, hostlists_map).
    """
    lists_path = Path(lists_dir)
    lists_path.mkdir(parents=True, exist_ok=True)

    excluded_set = sorted(
        {
            d.strip().lower()
            for d in [*(exclude_domains or []), *(dns_infra_domains or [])]
            if d and d.strip()
        }
    )
    bundle_dpi_set = {d.strip().lower() for d in (bundle_dpi_domains or []) if d and d.strip()}
    bundle_pass_set = {d.strip().lower() for d in (bundle_pass_domains or []) if d and d.strip()} - bundle_dpi_set

    def _is_excluded_domain(dom: str) -> bool:
        low = dom.strip().lower()
        return any(low == ex or low.endswith("." + ex) for ex in excluded_set)

    # Group domains by (protocol, strategy_id), skipping unlocker/hosts-excluded domains and no-op strategies (e.g. quic_fallback_tcp)
    grouped: dict[tuple[Protocol, str], list[str]] = {}
    vpn_decided_domains: set[str] = set()
    dpi_tls_covered: set[str] = set()
    for d in decisions:
        if d.status == "active" and d.layer == "vpn" and d.domain:
            vpn_decided_domains.add(d.domain.strip().lower())
        if d.layer == "dpi" and d.strategy_id and d.strategy_id in strategies and not _is_excluded_domain(d.domain):
            strat = strategies[d.strategy_id]
            if not strat.args_template:
                continue
            key = (d.protocol, d.strategy_id)
            grouped.setdefault(key, []).append(d.domain)
            if d.protocol == Protocol.TLS:
                dpi_tls_covered.add(d.domain.strip().lower())

    def _pick_best_tls_strategy() -> str | None:
        if isp_best_tls and isp_best_tls in strategies and strategies[isp_best_tls].args_template:
            return isp_best_tls
        if "tls_alt1_199_fake_fakedsplit" in strategies and strategies["tls_alt1_199_fake_fakedsplit"].args_template:
            return "tls_alt1_199_fake_fakedsplit"
        if "tls_multisplit_pos2" in strategies and strategies["tls_multisplit_pos2"].args_template:
            return "tls_multisplit_pos2"
        return next((sid for sid, s in strategies.items() if s.protocol == Protocol.TLS and s.args_template), None)

    # Wire AppBundle direct_dpi auth_domains into active TLS DPI profile (never shadowed by pass_domains)
    pending_bundle_dpi = sorted(
        d
        for d in bundle_dpi_set
        if d not in dpi_tls_covered and d not in vpn_decided_domains and not _is_excluded_domain(d)
    )
    if pending_bundle_dpi:
        bundle_tls_id = _pick_best_tls_strategy()
        if bundle_tls_id is not None:
            grouped.setdefault((Protocol.TLS, bundle_tls_id), []).extend(pending_bundle_dpi)

    # Stage 1 fallback profile when DB has no active DPI decisions yet
    if not grouped:
        fallback_strat_id = _pick_best_tls_strategy()
        if fallback_strat_id is not None:
            grouped[(Protocol.TLS, fallback_strat_id)] = [
                "discord.com",
                "discordapp.com",
                "discord.gg",
                "discord.media",
                "discordapp.net",
                "youtube.com",
                "googlevideo.com",
                "ytimg.com",
            ]

    udp_dpi_active = bool(game_filter or enable_game_udp_dpi)
    args: list[str] = [
        "--lua-init=@lua/zapret-lib.lua",
        "--lua-init=@lua/zapret-antidpi.lua",
        "--lua-init=@lua/zapret-auto.lua",
        "--ctrack-disable=0",
        "--ipcache-lifetime=8400",
        "--ipcache-hostname=1",
        "--wf-tcp-out=80,443,2053,2083,2087,2096,5222,8443",
    ]
    if enable_tcp_in or enable_circular_catchall:
        args.append("--wf-tcp-in=80,443")
    args.append(
        "--wf-udp-out=443,19294-19344,50000-50100,1024-65535"
        if udp_dpi_active
        else "--wf-udp-out=443,19294-19344,50000-50100"
    )
    if iface is not None:
        args.append(f"--wf-iface={iface}")

    # Always generate exclude_vpn_ips.txt with resolved IP/CIDR entries (VPN servers + DNS infra)
    combined_exclude_ips = [*(vpn_server_ips or []), *(dns_infra_ips or [])]
    resolved_vpn_ips = resolve_vpn_ips(combined_exclude_ips)
    exclude_ipset_path = lists_path / "exclude_vpn_ips.txt"
    if resolved_vpn_ips:
        exclude_ipset_path.write_text("\n".join(resolved_vpn_ips) + "\n", encoding="utf-8")
    else:
        exclude_ipset_path.write_text("# No VPN server IPs configured\n", encoding="utf-8")

    vpn_hostnames: set[str] = set()
    for raw_srv in vpn_server_ips or []:
        srv_clean = (raw_srv or "").strip().lower()
        if srv_clean and "." in srv_clean and "/" not in srv_clean and not _is_ip_address(srv_clean):
            vpn_hostnames.add(srv_clean)

    dpi_domains = {
        d.domain.strip().lower()
        for d in decisions
        if d.layer == "dpi" and d.status == "active" and d.domain and d.domain.strip()
    }
    direct_domains = {
        d.domain.strip().lower()
        for d in decisions
        if d.layer == "direct" and d.status == "active" and d.domain and d.domain.strip()
    } - dpi_domains
    dns_domains = {
        d.domain.strip().lower()
        for d in decisions
        if d.layer == "dns" and d.status == "active" and d.domain and d.domain.strip()
    } - dpi_domains
    catchall_excluded_domains = sorted(
        (set(excluded_set) | vpn_hostnames | direct_domains | dns_domains | bundle_pass_set) - bundle_dpi_set
    )
    exclude_hostlist_path: Path | None = None
    if catchall_excluded_domains:
        exclude_hostlist_path = lists_path / "exclude_unlocker_domains.txt"
        exclude_hostlist_path.write_text("\n".join(catchall_excluded_domains) + "\n", encoding="utf-8")

    hostlists_map: dict[str, list[str]] = {}
    profile_count = 0

    # Explicit pass guard for direct_clean bundle auth domains, DNS infrastructure, and VPN servers
    pass_domains = sorted((set(excluded_set) | (bundle_pass_set - dpi_domains - bundle_dpi_set)) | vpn_hostnames)
    if pass_domains:
        pass_list_path = lists_path / "pass_domains.txt"
        pass_list_path.write_text("\n".join(pass_domains) + "\n", encoding="utf-8")
        args.extend(
            [
                "--filter-tcp=80,443,2053,2083,2087,2096,8443",
                f"--hostlist={pass_list_path.as_posix()}",
                "--lua-desync=pass",
            ]
        )
        profile_count += 1

    for (proto, strat_id), domains in sorted(grouped.items(), key=lambda x: x[0][1]):
        strat = strategies[strat_id]
        if not strat.args_template:
            continue

        expanded_domains: set[str] = set()
        for dom in domains:
            clean_dom = dom.strip()
            if not clean_dom:
                continue
            expanded_domains.add(clean_dom)
            if expand_cdn_domains:
                for extra_dom in CDN_DOMAIN_EXPANSIONS.get(clean_dom.lower(), ()):
                    if not _is_excluded_domain(extra_dom):
                        expanded_domains.add(extra_dom)

        unique_domains = sorted(expanded_domains)
        if not unique_domains:
            continue

        list_filename = f"{strat_id}.txt"
        list_file = lists_path / list_filename
        list_file.write_text("\n".join(unique_domains) + "\n", encoding="utf-8")
        hostlists_map[list_filename] = unique_domains

        if profile_count > 0:
            args.append("--new")

        has_custom_payload = any(tok.startswith("--payload=") for tok in strat.args_template)
        uses_syndata = any("syndata" in tok for tok in strat.args_template)

        if proto == Protocol.TLS:
            args.extend(
                [
                    "--filter-tcp=80,443,2053,2083,2087,2096,8443",
                    "--filter-l7=tls",
                    f"--hostlist={list_file.as_posix()}",
                ]
            )
            if not has_custom_payload:
                args.append("--payload=all" if uses_syndata else "--payload=tls_client_hello")
        elif proto == Protocol.QUIC:
            args.extend(
                [
                    "--filter-udp=443",
                    "--filter-l7=quic",
                    f"--hostlist={list_file.as_posix()}",
                ]
            )
        else:
            args.extend(
                [
                    "--filter-tcp=80",
                    "--filter-l7=http",
                    f"--hostlist={list_file.as_posix()}",
                ]
            )

        if resolved_vpn_ips:
            args.append(f"--ipset-exclude={exclude_ipset_path.as_posix()}")

        args.extend(strat.args_template)
        profile_count += 1

    tg_ipset_path = lists_path / "ipset-telegram.txt"
    if not tg_ipset_path.is_file() or tg_ipset_path.stat().st_size == 0:
        tg_ipset_path.write_text("\n".join(TELEGRAM_CIDRS) + "\n", encoding="utf-8")

    # Dedicated Telegram MTProto / Web IPSET profile (disabled when tg-ws-proxy MTProto mode is active)
    if enable_telegram_ipset:
        if profile_count > 0:
            args.append("--new")
        args.extend(
            [
                "--filter-tcp=80,443,5222",
                f"--ipset={tg_ipset_path.as_posix()}",
                "--payload=all",
            ]
        )
        if resolved_vpn_ips:
            args.append(f"--ipset-exclude={exclude_ipset_path.as_posix()}")
        args.extend(
            [
                "--lua-desync=fake:blob=fake_stun_as_tls:tcp_ts=-600000:repeats=6",
                "--lua-desync=fake:blob=tls_google:tcp_ts=-600000:repeats=6",
                "--lua-desync=fakedsplit:pattern=0x00:tcp_ts=-600000:repeats=6",
                "--lua-desync=fake:blob=tls_max:tcp_ts=-600000:repeats=6",
            ]
        )
        profile_count += 1

    # Add circular catch-all: strategy=1 is pass (zero harm for direct), strategy=2 is isp_best_tls, followed by diverse fallbacks
    if enable_circular_catchall:
        tls_candidates = [
            s
            for s in strategies.values()
            if s.protocol == Protocol.TLS
            and s.tier in (2, 3)
            and s.args_template
            and all(tok.startswith("--lua-desync=") for tok in s.args_template)
            and not _uses_known_file_blob(s)
        ]
        if tls_candidates:
            tls_candidates.sort(
                key=lambda s: (
                    0 if (isp_best_tls and s.id == isp_best_tls) else 1,
                    0 if ("fake" not in s.family and "fake" not in " ".join(s.args_template)) else 1,
                    s.tier,
                    s.id,
                )
            )
            chosen_cands: list[Strategy] = []
            seen_families: set[str] = set()
            if isp_best_tls and isp_best_tls in strategies:
                best_s = strategies[isp_best_tls]
                if best_s.protocol == Protocol.TLS and best_s.args_template and all(
                    tok.startswith("--lua-desync=") for tok in best_s.args_template
                ):
                    chosen_cands.append(best_s)
                    seen_families.add(best_s.family)
            for cand in tls_candidates:
                if any(c.id == cand.id for c in chosen_cands):
                    continue
                if len(chosen_cands) >= 1 and cand.family in seen_families and len(tls_candidates) > 3:
                    continue
                chosen_cands.append(cand)
                seen_families.add(cand.family)
                if len(chosen_cands) >= 3:
                    break
            for cand in tls_candidates:
                if len(chosen_cands) >= 3:
                    break
                if all(c.id != cand.id for c in chosen_cands):
                    chosen_cands.append(cand)

            if profile_count > 0:
                args.append("--new")
            args.extend(
                [
                    "--filter-tcp=443",
                    "--filter-l7=tls",
                    "--payload=tls_client_hello",
                ]
            )
            if resolved_vpn_ips:
                args.append(f"--ipset-exclude={exclude_ipset_path.as_posix()}")
            if not enable_telegram_ipset:
                args.append(f"--ipset-exclude={tg_ipset_path.as_posix()}")
            if exclude_hostlist_path is not None:
                args.append(f"--hostlist-exclude={exclude_hostlist_path.as_posix()}")
            args.append("--lua-desync=circular:fails=2:time=300:retrans=3:nld=2")
            args.append("--lua-desync=pass:strategy=1")
            total_steps = 1 + len(chosen_cands)
            for idx, cand in enumerate(chosen_cands, start=2):
                is_last = idx == total_steps
                suffix = f":strategy={idx}" + (":final" if is_last else "")
                for base_arg in cand.args_template:
                    args.append(f"{base_arg}{suffix}")
            profile_count += 1

    # Discord voice / STUN UDP profile — strictly bounded to voice ports (NEVER 1024-65535)
    if profile_count > 0:
        args.append("--new")
    args.extend(
        [
            "--filter-udp=19294-19344,50000-50100",
            "--filter-l7=discord,stun",
        ]
    )
    if resolved_vpn_ips:
        args.append(f"--ipset-exclude={exclude_ipset_path.as_posix()}")
    args.append("--lua-desync=fake:blob=discord_active:repeats=6")
    profile_count += 1

    # Separate Game Cloud UDP profile when a game bundle uses direct_dpi or game_filter is enabled
    if udp_dpi_active:
        args.append("--new")
        args.append("--filter-udp=1024-65535")
        cloud_ipsets = [
            lists_path / "zapret2" / fname
            for fname in ("ipset-amazon.txt", "ipset-ovh.txt", "ipset-cloudflare.txt", "ipset-azure.txt")
            if (lists_path / "zapret2" / fname).is_file() and (lists_path / "zapret2" / fname).stat().st_size > 0
        ]
        for ipset_f in cloud_ipsets:
            args.append(f"--ipset={ipset_f.as_posix()}")
        if resolved_vpn_ips:
            args.append(f"--ipset-exclude={exclude_ipset_path.as_posix()}")
        args.extend(
            [
                "--out-range=-d8",
                "--lua-desync=fake:blob=game_active:repeats=4",
            ]
        )
        profile_count += 1

    blob_args = extract_blob_args(args, bin_dir=bin_dir)
    if blob_args:
        insert_idx = sum(1 for a in args if a.startswith("--lua-init="))
        args[insert_idx:insert_idx] = blob_args

    return args, hostlists_map


_AMNEZIAWG_KEYS = ("jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4")


def _resolve_host_ipv4(host: str) -> str | None:
    clean = (host or "").strip().strip("[]")
    if not clean:
        return None
    if _is_ip_address(clean):
        return clean
    try:
        infos = socket.getaddrinfo(clean, None, socket.AF_INET)
        for _fam, _tp, _pr, _cn, sockaddr in infos:
            ip_part = str(sockaddr[0]).split("%", 1)[0]
            if _is_ip_address(ip_part):
                return ip_part
    except (socket.gaierror, OSError):
        pass
    ips = resolve_vpn_ips([clean])
    v4 = [ip for ip in ips if ":" not in ip]
    return v4[0] if v4 else (ips[0] if ips else None)


def _build_singbox_dns_server_entry(
    tag: str,
    server: str,
    dns_type: str = "https",
    doh_path: str = "/dns-query",
    tls_sni: str | None = None,
    server_port: int | None = None,
) -> dict[str, Any]:
    if dns_type == "udp":
        return {
            "type": "udp",
            "tag": tag,
            "server": server,
            "server_port": int(server_port or 53),
        }
    entry: dict[str, Any] = {
        "type": "https",
        "tag": tag,
        "server": server,
        "server_port": int(server_port or 443),
        "path": doh_path or "/dns-query",
    }
    if tls_sni and not _is_ip_address(tls_sni):
        entry["tls"] = {"enabled": True, "server_name": tls_sni}
    return entry


def _build_wireguard_endpoint(
    raw_outbound: dict[str, Any],
    node: VpnNode,
    extended_core: bool,
    domain_resolver: str = "dns-local",
) -> dict[str, Any]:
    """Convert a legacy WireGuard/AmneziaWG outbound dict into sing-box 1.12+/1.14+ endpoint schema."""
    ob = dict(raw_outbound)
    if isinstance(ob.get("peers"), list) and ob["peers"]:
        peers: list[dict[str, Any]] = []
        needs_domain_resolver = False
        for peer in ob["peers"]:
            if not isinstance(peer, dict):
                continue
            p_copy = dict(peer)
            if not p_copy.get("allowed_ips"):
                p_copy["allowed_ips"] = ["0.0.0.0/0", "::/0"]
            addr = str(p_copy.get("address") or "").strip()
            if addr and not _is_ip_address(addr):
                needs_domain_resolver = True
            peers.append(p_copy)
        ep: dict[str, Any] = {
            "type": "wireguard",
            "tag": str(ob.get("tag") or node.tag),
            "address": list(ob.get("address") or ob.get("local_address") or ["10.8.1.2/32"]),
            "private_key": str(ob.get("private_key") or ""),
            "peers": peers,
        }
    else:
        server = str(ob.get("server") or node.server or "").strip()
        port = int(ob.get("server_port") or node.server_port or 51820)
        peer_entry: dict[str, Any] = {
            "address": server,
            "port": port,
            "public_key": str(ob.get("peer_public_key") or ob.get("public_key") or ""),
            "allowed_ips": list(ob.get("allowed_ips") or ["0.0.0.0/0", "::/0"]),
        }
        if ob.get("reserved"):
            peer_entry["reserved"] = ob["reserved"]
        if ob.get("pre_shared_key"):
            peer_entry["pre_shared_key"] = ob["pre_shared_key"]
        ep = {
            "type": "wireguard",
            "tag": str(ob.get("tag") or node.tag),
            "address": list(ob.get("address") or ob.get("local_address") or ["10.8.1.2/32"]),
            "private_key": str(ob.get("private_key") or ""),
            "peers": [peer_entry],
        }
        needs_domain_resolver = bool(server and not _is_ip_address(server))

    if ob.get("mtu"):
        ep["mtu"] = int(ob["mtu"])
    if ob.get("listen_port"):
        ep["listen_port"] = int(ob["listen_port"])
    if ob.get("domain_resolver"):
        ep["domain_resolver"] = ob["domain_resolver"]
    elif needs_domain_resolver:
        ep["domain_resolver"] = domain_resolver

    if extended_core:
        for awg_key in _AMNEZIAWG_KEYS:
            if awg_key in ob:
                ep[awg_key] = ob[awg_key]

    return ep


def _build_tailscale_endpoint(raw_outbound: dict[str, Any], node: VpnNode) -> dict[str, Any]:
    ep = dict(raw_outbound)
    ep["type"] = "tailscale"
    ep["tag"] = str(ep.get("tag") or node.tag)
    return ep


def _sanitize_tag_part(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_-]+", "-", (value or "").strip()).strip("-")
    return cleaned or "default"


def _unique_tag(candidate: str, used_tags: set[str]) -> str:
    tag = candidate.strip() or "vpn-node"
    if tag not in used_tags:
        used_tags.add(tag)
        return tag
    suffix = 2
    while f"{tag}-{suffix}" in used_tags:
        suffix += 1
    unique = f"{tag}-{suffix}"
    used_tags.add(unique)
    return unique


DEFAULT_BYPASS_PROCESSES: tuple[str, ...] = (
    "winws2.exe",
    "winws.exe",
    "ciadpi.exe",
    "TgWsProxy_windows.exe",
    "tg-ws-proxy.exe",
    "python.exe",
    "pythonw.exe",
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

# Games whose non-web sockets bypass TUN/VPN for zero-drop stability while port 80/443 mod/API traffic keeps DPI/VPN.
DEFAULT_GAME_PROCESSES: tuple[str, ...] = (
    # Sandbox / Survival / Co-op
    "javaw.exe",
    "java.exe",
    "Minecraft.exe",
    "Minecraft.Windows.exe",
    "RobloxPlayerBeta.exe",
    "RobloxStudioBeta.exe",
    "RustClient.exe",
    "DayZ_x64.exe",
    "Terraria.exe",
    "ShooterGame.exe",
    "ArkAscended.exe",
    "valheim.exe",
    "Palworld-Win64-Shipping.exe",
    "dontstarve_steam_x64.exe",
    "factorio.exe",
    "FactoryGameSteam-Win64-Shipping.exe",
    "FactoryGame-Win64-Shipping.exe",
    "ProjectZomboid64.exe",
    "7DaysToDie.exe",
    "VRising.exe",
    "enshrouded.exe",
    "ONCE_HUMAN.exe",
    "SCUM.exe",
    "Unturned.exe",
    "SoTGame.exe",
    "NMS.exe",
    "Lethal Company.exe",
    "Content Warning.exe",
    "Phasmophobia.exe",
    "Among Us.exe",
    "Goose Goose Duck.exe",
    "gmod.exe",
    "hl2.exe",
    "SonsOfTheForest.exe",
    "TheForest.exe",
    "Maine-Win64-Shipping.exe",
    "Astro-Win64-Shipping.exe",
    "FSD-Win64-Shipping.exe",
    "Risk of Rain 2.exe",
    "CoreKeeper.exe",
    "Stardew Valley.exe",
    "raft.exe",
    "Subnautica.exe",
    "Barotrauma.exe",
    "REPO.exe",
    "Schedule I.exe",
    "Peak.exe",
    # FPS / TPS / Tactical Shooters
    "cs2.exe",
    "csgo.exe",
    "VALORANT-Win64-Shipping.exe",
    "VALORANT.exe",
    "RiotClientServices.exe",
    "RainbowSix.exe",
    "RainbowSix_DX12.exe",
    "RainbowSix_Vulkan.exe",
    "RainbowSix_BE.exe",
    "BEService.exe",
    "BEService_x64.exe",
    "r5apex.exe",
    "r5apex_dx12.exe",
    "FortniteClient-Win64-Shipping.exe",
    "TslGame.exe",
    "cod.exe",
    "ModernWarfare.exe",
    "BlackOpsColdWar.exe",
    "Overwatch.exe",
    "tf_win64.exe",
    "tf.exe",
    "EscapeFromTarkov.exe",
    "EscapeFromTarkov_BE.exe",
    "UAGame.exe",
    "HuntGame.exe",
    "Discovery.exe",
    "helldivers2.exe",
    "bf2042.exe",
    "bfv.exe",
    "bf1.exe",
    "bf4.exe",
    "destiny2.exe",
    "Warframe.x64.exe",
    "HaloInfinite.exe",
    "Marvel-Win64-Shipping.exe",
    "DeltaForceClient-Win64-Shipping.exe",
    "SquadGame.exe",
    "HLL-Win64-Shipping.exe",
    "arma3_x64.exe",
    "arma3.exe",
    "ArmaReforgerSteam.exe",
    "InsurgencyClient-Win64-Shipping.exe",
    "ReadyOrNot-Win64-Shipping.exe",
    "payday2_win32_release.exe",
    "PAYDAY3Client-Win64-Shipping.exe",
    "left4dead2.exe",
    "KFGame.exe",
    "stalcraftw.exe",
    "enlisted.exe",
    "Crossout.exe",
    "GZWClientSteam-Win64-Shipping.exe",
    "Bodycam-Win64-Shipping.exe",
    "BattleBit.exe",
    "XDefiant.exe",
    "PortalWars-Win64-Shipping.exe",
    "Paladins.exe",
    "QuakeChampions.exe",
    "FragPunk.exe",
    "Strinova-Win64-Shipping.exe",
    "SCPSL.exe",
    "Splitgate2-Win64-Shipping.exe",
    "TheFirstDescendant-Win64-Shipping.exe",
    "Remnant2-Win64-Shipping.exe",
    "Back4Blood.exe",
    "wwzRetailEgs.exe",
    "Darktide.exe",
    "vermintide2_dx12.exe",
    # MOBA / Strategy
    "dota2.exe",
    "League of Legends.exe",
    "LeagueClient.exe",
    "LeagueClientUx.exe",
    "deadlock.exe",
    "Smite.exe",
    "Hemingway-Win64-Shipping.exe",
    "HeroesOfTheStorm_x64.exe",
    "SC2_x64.exe",
    "AoE2DE_s.exe",
    "RelicCardinal.exe",
    "CivilizationVI.exe",
    "CivilizationVI_DX12.exe",
    "hoi4.exe",
    "eu4.exe",
    "stellaris.exe",
    "ck3.exe",
    "RelicCoH3.exe",
    "Warhammer3.exe",
    "Warcraft III.exe",
    "AgeOfMythologyRetold_s.exe",
    "BeyondAllReason.exe",
    # MMORPG / ARPG / Gacha / Vehicles
    "Wow.exe",
    "WowClassic.exe",
    "ffxiv_dx11.exe",
    "eso64.exe",
    "Gw2-64.exe",
    "BlackDesert64.exe",
    "LOSTARK.exe",
    "NewWorld.exe",
    "TL.exe",
    "Albion-Online.exe",
    "RuneLite.exe",
    "rs2client.exe",
    "L2.exe",
    "archeage.exe",
    "PathOfExile.exe",
    "PathOfExileSteam.exe",
    "PathOfExile_x64.exe",
    "PathOfExile2.exe",
    "PathOfExile2Steam.exe",
    "Diablo IV.exe",
    "Diablo III64.exe",
    "Last Epoch.exe",
    "GenshinImpact.exe",
    "StarRail.exe",
    "ZenlessZoneZero.exe",
    "Client-Win64-Shipping.exe",
    "QRSL.exe",
    "aces.exe",
    "WorldOfTanks.exe",
    "WorldOfWarships64.exe",
    "exefile.exe",
    "StarCitizen.exe",
    "EliteDangerous64.exe",
    "MapleStory.exe",
    "metin2client.exe",
    "elementclient_64.exe",
    "Neverwinter.exe",
    "swtor.exe",
    "lotroclient64.exe",
    "DDOClient64.exe",
    # Open World / Sports / Racing / Fighting / Social / Card
    "GTA5.exe",
    "GTA5_Enhanced.exe",
    "FiveM_GTAProcess.exe",
    "FiveM_b2802_GTAProcess.exe",
    "FiveM_b2944_GTAProcess.exe",
    "FiveM_b3095_GTAProcess.exe",
    "ragemp_v.exe",
    "altv-client.exe",
    "RDR2.exe",
    "RocketLeague.exe",
    "FC24.exe",
    "FC25.exe",
    "FIFA23.exe",
    "NBA2K24.exe",
    "NBA2K25.exe",
    "ForzaHorizon5.exe",
    "acs.exe",
    "AC2-Win64-Shipping.exe",
    "BeamNG.drive.x64.exe",
    "eurotrucks2.exe",
    "amtrucks.exe",
    "SnowRunner.exe",
    "iRacingSim64DX11.exe",
    "DeadByDaylight-Win64-Shipping.exe",
    "FallGuys_client_game.exe",
    "PartyAnimals.exe",
    "MonsterHunterWorld.exe",
    "MonsterHunterRise.exe",
    "MonsterHunterWilds.exe",
    "eldenring.exe",
    "bg3.exe",
    "bg3_dx11.exe",
    "Warhammer 40000 Space Marine 2 - Retail.exe",
    "Chivalry2-Win64-Shipping.exe",
    "Mordhau-Win64-Shipping.exe",
    "ForHonor.exe",
    "NarakaBladepoint.exe",
    "Polaris-Win64-Shipping.exe",
    "StreetFighter6.exe",
    "MK12.exe",
    "Brawlhalla.exe",
    "Hearthstone.exe",
    "MTGA.exe",
    "masterduel.exe",
    "VRChat.exe",
    "RecRoom.exe",
    "PaliaClient-Win64-Shipping.exe",
    "Sky.exe",
)

_GAME_PROCESS_EXACT_LOW: frozenset[str] = frozenset(p.lower() for p in DEFAULT_GAME_PROCESSES)
_GAME_PROCESS_SUBSTR_HINTS: tuple[str, ...] = (
    "rainbowsix",
    "beservice",
    "battleye",
    "valorant",
    "riotclient",
    "cs2.exe",
    "csgo.exe",
    "r5apex",
    "fortnite",
    "tslgame",
    "tarkov",
    "overwatch",
    "helldivers",
    "warframe",
    "dota2",
    "deadlock",
    "destiny2",
    "eldenring",
    "rustclient",
    "pubg",
    "roblox",
    "minecraft",
)


def parse_process_list(raw: str | None) -> list[str]:
    """Parse a comma/newline/semicolon-separated process list into unique executable names."""
    if not raw:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for part in re.split(r"[,;\r\n]+", str(raw)):
        name = Path(part.strip().replace("\\", "/")).name.strip()
        low = name.lower()
        if name and low not in seen:
            seen.add(low)
            out.append(name)
    return out


def is_game_process(proc_name: str, extra_processes: Iterable[str] = ()) -> bool:
    """Return True if proc_name matches a known game/anti-cheat process or launcher."""
    low = Path((proc_name or "").strip().replace("\\", "/")).name.lower()
    if not low:
        return False
    if low in _GAME_PROCESS_EXACT_LOW:
        return True
    if any(low == str(p).strip().lower() for p in extra_processes if p):
        return True
    return any(hint in low for hint in _GAME_PROCESS_SUBSTR_HINTS)


def needs_xray_bridge(node: VpnNode | dict[str, Any]) -> bool:
    """Return True if a VLESS node requires Xray-core sidecar bridging (Reality or xhttp/splithttp)."""
    if isinstance(node, VpnNode):
        enabled = bool(getattr(node, "enabled", True))
        proto = str(node.protocol or "").strip().lower()
        ob = node.raw_outbound if isinstance(node.raw_outbound, dict) else {}
    elif isinstance(node, dict):
        enabled = bool(node.get("enabled", True))
        proto = str(node.get("protocol") or "").strip().lower()
        ob = node.get("raw_outbound") if isinstance(node.get("raw_outbound"), dict) else {}
    else:
        return False

    if not enabled or proto != "vless" or is_placeholder_node(node):
        return False

    tls = ob.get("tls")
    if isinstance(tls, dict):
        reality = tls.get("reality")
        if isinstance(reality, dict) and reality.get("enabled"):
            return True

    tr = ob.get("transport")
    if isinstance(tr, dict):
        tr_type = str(tr.get("type") or "").strip().lower()
        if tr_type in ("xhttp", "splithttp"):
            return True
    return False


def generate_xray_bridge_config(
    vpn_nodes: list[VpnNode],
    *,
    output_path: str | Path | None = None,
    base_port: int = 18100,
    dns_server: str = "1.1.1.1",
    enable_byedpi: bool = False,
) -> tuple[dict[str, Any], dict[str, int]]:
    """Build Xray-core local SOCKS5 bridge config for VLESS Reality/xhttp nodes and return (config, {tag: port})."""
    used_tags: set[str] = {"direct", "vpn-auto", "vpn-select", "vpn-ai"}
    if enable_byedpi:
        used_tags.add("byedpi-out")

    inbounds: list[dict[str, Any]] = []
    xray_outbounds: list[dict[str, Any]] = []
    rules: list[dict[str, Any]] = []
    bridge_ports: dict[str, int] = {}

    for idx, node in enumerate(vpn_nodes):
        raw_tag = str(node.tag or node.raw_outbound.get("tag") or node.protocol or "vpn-node")
        unique_tag = _unique_tag(raw_tag, used_tags)
        if not needs_xray_bridge(node):
            continue

        ob = dict(node.raw_outbound) if isinstance(node.raw_outbound, dict) else {}
        server = str(ob.get("server") or node.server or "").strip()
        try:
            port = int(ob.get("server_port") or node.server_port or 443)
        except (TypeError, ValueError):
            port = 443
        uuid = str(ob.get("uuid") or "").strip()
        if not server or not uuid:
            continue

        socks_port = int(base_port) + len(bridge_ports)
        bridge_ports[unique_tag] = socks_port
        in_tag = f"in-{idx}"
        out_tag = f"out-{idx}"

        inbounds.append(
            {
                "tag": in_tag,
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True, "ip": "127.0.0.1"},
            }
        )

        user_entry: dict[str, Any] = {"id": uuid, "encryption": "none"}
        flow = str(ob.get("flow") or "").strip()
        if flow:
            user_entry["flow"] = flow

        tr = ob.get("transport") if isinstance(ob.get("transport"), dict) else {}
        tr_type = str(tr.get("type") or "tcp").strip().lower()
        net_map = {
            "http": "tcp",
            "h2": "h2",
            "ws": "ws",
            "grpc": "grpc",
            "httpupgrade": "httpupgrade",
            "xhttp": "xhttp",
            "splithttp": "splithttp",
        }
        xray_net = net_map.get(tr_type, "tcp")
        stream_settings: dict[str, Any] = {
            "network": xray_net,
            "sockopt": {"domainStrategy": "UseIPv4"},
        }
        if xray_net == "ws":
            ws_obj: dict[str, Any] = {"path": str(tr.get("path") or "/")}
            hdrs = tr.get("headers")
            if isinstance(hdrs, dict) and hdrs:
                ws_obj["headers"] = {str(k): str(v) for k, v in hdrs.items()}
            stream_settings["wsSettings"] = ws_obj
        elif xray_net == "grpc":
            stream_settings["grpcSettings"] = {"serviceName": str(tr.get("service_name") or "")}
        elif xray_net in ("httpupgrade", "xhttp", "splithttp"):
            key = f"{xray_net}Settings"
            tr_obj: dict[str, Any] = {"path": str(tr.get("path") or "/")}
            if tr.get("host"):
                h_val = tr["host"]
                tr_obj["host"] = str(h_val[0]) if isinstance(h_val, list) and h_val else str(h_val)
            stream_settings[key] = tr_obj

        tls = ob.get("tls") if isinstance(ob.get("tls"), dict) else {}
        reality = tls.get("reality") if isinstance(tls.get("reality"), dict) else {}
        fp = str((tls.get("utls") or {}).get("fingerprint") or "chrome").strip() or "chrome"
        sni = str(tls.get("server_name") or server).strip() or server

        if reality.get("enabled"):
            stream_settings["security"] = "reality"
            stream_settings["realitySettings"] = {
                "serverName": sni,
                "fingerprint": fp,
                "publicKey": str(reality.get("public_key") or ""),
                "shortId": str(reality.get("short_id") or ""),
                "spiderX": "",
            }
        elif tls.get("enabled"):
            stream_settings["security"] = "tls"
            tls_settings: dict[str, Any] = {"serverName": sni, "fingerprint": fp}
            alpn = tls.get("alpn")
            if isinstance(alpn, list) and alpn:
                tls_settings["alpn"] = [str(a) for a in alpn]
            if tls.get("insecure"):
                tls_settings["allowInsecure"] = True
            stream_settings["tlsSettings"] = tls_settings
        else:
            stream_settings["security"] = "none"

        xray_outbounds.append(
            {
                "tag": out_tag,
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": server,
                            "port": port,
                            "users": [user_entry],
                        }
                    ]
                },
                "streamSettings": stream_settings,
            }
        )
        rules.append({"type": "field", "inboundTag": [in_tag], "outboundTag": out_tag})

    xray_dns = list(
        dict.fromkeys(
            s
            for s in (
                "localhost",
                dns_server if _is_ip_address(dns_server) else "",
                "1.1.1.1",
                "8.8.8.8",
            )
            if s
        )
    )
    cfg: dict[str, Any] = {
        "log": {"loglevel": "warning"},
        "dns": {"servers": xray_dns},
        "inbounds": inbounds,
        "outbounds": [{"protocol": "freedom", "tag": "direct"}, *xray_outbounds],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {"type": "field", "port": 53, "outboundTag": "direct"},
                *rules,
            ],
        },
    }
    if output_path and bridge_ports:
        out_file = Path(output_path)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(json.dumps(cfg, indent=2, ensure_ascii=False), encoding="utf-8")
    return cfg, bridge_ports


def build_singbox_rulesets_payload(
    decisions: list[Decision],
    *,
    bypass_domains: list[str] | None = None,
    enable_byedpi: bool = False,
    smartdns_domains: list[str] | None = None,
    bundle_rules: dict[str, Any] | None = None,
    quic_blocked_domains: list[str] | None = None,
    vpn_processes: list[str] | None = None,
    telegram_mode: str = "mtproto",
) -> dict[str, list[dict[str, Any]]]:
    """Build JSON rule lists for sing-box remote HTTP rule_set endpoints (ETag zero-downtime updates)."""
    bypass_list = sorted({d.strip().lower() for d in (bypass_domains or []) if d and d.strip()})

    def _is_bypassed(dom: str) -> bool:
        low = dom.strip().lower()
        return any(low == b or low.endswith("." + b) for b in bypass_list)

    per_dns_override_hosts: set[str] = set()
    explicit_smartdns_hosts: set[str] = set()
    for d in decisions:
        if _is_bypassed(d.domain):
            continue
        if d.layer == "dns" and isinstance(d.strategy_id, str):
            if d.strategy_id == "smartdns":
                explicit_smartdns_hosts.add(d.domain.strip().lower().lstrip("."))
            elif d.strategy_id.startswith("dns:"):
                dns_id = d.strategy_id.split(":", 1)[1].strip()
                if dns_id:
                    per_dns_override_hosts.add(d.domain)

    vpn_select_set: set[str] = set()
    vpn_ai_set: set[str] = set()
    byedpi_set: set[str] = set()
    for d in decisions:
        if d.layer == "vpn" and not _is_bypassed(d.domain):
            expanded = [d.domain]
            expanded.extend(CDN_DOMAIN_EXPANSIONS.get(d.domain.strip().lower(), ()))
            if d.strategy_id == "vpn-ai":
                target_bucket = vpn_ai_set
            elif d.strategy_id == "byedpi-out" and enable_byedpi:
                target_bucket = byedpi_set
            else:
                target_bucket = vpn_select_set
            for dom_cand in expanded:
                if dom_cand and not _is_bypassed(dom_cand):
                    target_bucket.add(dom_cand)

    all_vpn_route_domains = vpn_select_set | vpn_ai_set | byedpi_set
    doh_domains = sorted(
        {
            d.domain
            for d in decisions
            if d.layer in ("dns", "dpi", "vpn")
            and d.domain not in per_dns_override_hosts
            and not _is_bypassed(d.domain)
        }
        | {
            dom
            for dom in all_vpn_route_domains
            if dom not in per_dns_override_hosts and not _is_bypassed(dom)
        }
    )
    smart_doms = sorted(
        {
            d.strip().lower().lstrip(".")
            for d in [*doh_domains, *(smartdns_domains or []), *explicit_smartdns_hosts]
            if d and d.strip()
        }
    )
    quic_reject_set = {
        d.domain
        for d in decisions
        if d.protocol == Protocol.QUIC
        and d.strategy_id == "quic_fallback_tcp"
        and not _is_bypassed(d.domain)
    }
    for qd in quic_blocked_domains or []:
        q_clean = str(qd or "").strip().lower()
        if q_clean and not _is_bypassed(q_clean):
            quic_reject_set.add(q_clean)

    br = bundle_rules or {}
    bundles_direct_rules: list[dict[str, Any]] = []
    if br.get("direct_processes"):
        bundles_direct_rules.append({"process_name": list(br["direct_processes"])})
    if br.get("direct_path_regexes"):
        bundles_direct_rules.append({"process_path_regex": list(br["direct_path_regexes"])})
    if br.get("direct_domains"):
        bundles_direct_rules.append({"domain_suffix": list(br["direct_domains"])})

    bundles_vpn_rules: list[dict[str, Any]] = []
    if br.get("vpn_processes"):
        bundles_vpn_rules.append({"process_name": list(br["vpn_processes"])})
    if br.get("vpn_path_regexes"):
        bundles_vpn_rules.append({"process_path_regex": list(br["vpn_path_regexes"])})
    if br.get("vpn_domains"):
        bundles_vpn_rules.append({"domain_suffix": list(br["vpn_domains"])})

    infra_low = {p.lower() for p in DEFAULT_BYPASS_PROCESSES} | {"sing-box", "sing-box.exe"}
    clean_vpn_procs = [
        p
        for p in (vpn_processes or [])
        if Path(str(p or "").strip().replace("\\", "/")).name.strip().lower() not in infra_low
    ]
    bundles_dns_vpn_rules: list[dict[str, Any]] = []
    dns_vpn_procs = list(dict.fromkeys([*clean_vpn_procs, *(br.get("vpn_processes") or [])]))
    if dns_vpn_procs:
        bundles_dns_vpn_rules.append({"process_name": dns_vpn_procs})
    if br.get("vpn_domains"):
        bundles_dns_vpn_rules.append({"domain_suffix": list(br["vpn_domains"])})

    rs_vpn_rules: list[dict[str, Any]] = []
    if vpn_select_set:
        rs_vpn_rules.append({"domain_suffix": sorted(vpn_select_set)})
    if str(telegram_mode or "mtproto").strip().lower() == "transparent" and (
        "telegram.org" in vpn_select_set or "t.me" in vpn_select_set
    ):
        rs_vpn_rules.append({"ip_cidr": list(TELEGRAM_CIDRS)})

    return {
        "rs-doh": [{"domain_suffix": doh_domains}] if doh_domains else [],
        "rs-smartdns": [{"domain_suffix": smart_doms}] if smart_doms else [],
        "rs-vpn": rs_vpn_rules,
        "rs-vpn-ai": [{"domain_suffix": sorted(vpn_ai_set)}] if vpn_ai_set else [],
        "rs-byedpi": [{"domain_suffix": sorted(byedpi_set)}] if byedpi_set else [],
        "rs-quic-reject": [{"domain_suffix": sorted(quic_reject_set)}] if quic_reject_set else [],
        "rs-bundles-direct": bundles_direct_rules,
        "rs-bundles-vpn": bundles_vpn_rules,
        "rs-bundles-dns-vpn": bundles_dns_vpn_rules,
    }


def generate_singbox_config(
    decisions: list[Decision],
    vpn_nodes: list[VpnNode] | None = None,
    output_path: str | Path | None = None,
    doh_server: str = "1.1.1.1",
    enable_tun: bool = True,
    extended_core: bool = False,
    dns_type: str = "https",
    doh_path: str = "/dns-query",
    dns_catalog: dict[str, dict[str, Any]] | None = None,
    bypass_domains: list[str] | None = None,
    extra_bypass_processes: list[str] | None = None,
    clash_api_addr: str | None = "127.0.0.1:19090",
    clash_api_secret: str = "",
    quarantined_tags: set[str] | None = None,
    enable_byedpi: bool = False,
    byedpi_port: int = 10809,
    use_wireguard_endpoints: bool = False,
    extra_dns_servers_sni: bool = True,
    doh_tls_sni: str | None = None,
    tun_stack: str = "mixed",
    vpn_selection_mode: str = "auto",
    preferred_vpn_node: str | None = None,
    xray_bridge_ports: dict[str, int] | None = None,
    vpn_processes: list[str] | None = None,
    bypass_ips: list[str] | None = None,
    primary_is_smartdns: bool = False,
    smartdns_domains: list[str] | None = None,
    base_dns: dict[str, Any] | None = None,
    bundle_rules: dict[str, Any] | None = None,
    ruleset_base_url: str | None = None,
    quic_blocked_domains: list[str] | None = None,
    telegram_mode: str = "mtproto",
) -> dict[str, Any]:
    """Generate sing-box 1.12+/1.14+ JSON configuration with safe mixed TUN, Split-DNS, AppBundles, and zero-downtime HTTP rule_sets."""
    vpn_nodes = vpn_nodes or []

    bypass_list = sorted({d.strip().lower() for d in (bypass_domains or []) if d and d.strip()})

    def _is_bypassed(dom: str) -> bool:
        low = dom.strip().lower()
        return any(low == b or low.endswith("." + b) for b in bypass_list)

    per_dns_domains: dict[str, list[str]] = {}
    per_dns_override_hosts: set[str] = set()
    explicit_smartdns_hosts: set[str] = set()
    for d in decisions:
        if _is_bypassed(d.domain):
            continue
        if d.layer == "dns" and isinstance(d.strategy_id, str):
            if d.strategy_id == "smartdns":
                explicit_smartdns_hosts.add(d.domain.strip().lower().lstrip("."))
            elif d.strategy_id.startswith("dns:"):
                dns_id = d.strategy_id.split(":", 1)[1].strip()
                if dns_id:
                    per_dns_domains.setdefault(dns_id, []).append(d.domain)
                    per_dns_override_hosts.add(d.domain)

    vpn_select_set: set[str] = set()
    vpn_ai_set: set[str] = set()
    byedpi_set: set[str] = set()
    for d in decisions:
        if d.layer == "vpn" and not _is_bypassed(d.domain):
            expanded = [d.domain]
            expanded.extend(CDN_DOMAIN_EXPANSIONS.get(d.domain.strip().lower(), ()))
            if d.strategy_id == "vpn-ai":
                target_bucket = vpn_ai_set
            elif d.strategy_id == "byedpi-out" and enable_byedpi:
                target_bucket = byedpi_set
            else:
                target_bucket = vpn_select_set
            for dom_cand in expanded:
                if dom_cand and not _is_bypassed(dom_cand):
                    target_bucket.add(dom_cand)

    vpn_select_domains = sorted(vpn_select_set)
    vpn_ai_domains = sorted(vpn_ai_set)
    byedpi_domains = sorted(byedpi_set)
    all_vpn_route_domains = vpn_select_set | vpn_ai_set | byedpi_set

    doh_domains = sorted(
        {
            d.domain
            for d in decisions
            if d.layer in ("dns", "dpi", "vpn")
            and d.domain not in per_dns_override_hosts
            and not _is_bypassed(d.domain)
        }
        | {
            dom
            for dom in all_vpn_route_domains
            if dom not in per_dns_override_hosts and not _is_bypassed(dom)
        }
    )
    quic_reject_set = {
        d.domain
        for d in decisions
        if d.protocol == Protocol.QUIC
        and d.strategy_id == "quic_fallback_tcp"
        and not _is_bypassed(d.domain)
    }
    for qd in quic_blocked_domains or []:
        q_clean = str(qd or "").strip().lower()
        if q_clean and not _is_bypassed(q_clean):
            quic_reject_set.add(q_clean)
    quic_reject_domains = sorted(quic_reject_set)

    catalog_map = dns_catalog
    if catalog_map is None and (per_dns_domains or (extra_dns_servers_sni and dns_type == "https") or not _is_ip_address(doh_server)):
        from netdoctor.orchestrators import BUILTIN_DNS_CATALOG

        catalog_map = {s["id"]: s for s in BUILTIN_DNS_CATALOG}

    primary_server = (doh_server or "1.1.1.1").strip()
    primary_path = doh_path or "/dns-query"
    primary_port: int | None = None
    primary_tls_sni: str | None = (
        doh_tls_sni.strip()
        if isinstance(doh_tls_sni, str) and doh_tls_sni.strip() and not _is_ip_address(doh_tls_sni)
        else None
    )

    if primary_server.startswith(("http://", "https://")):
        parsed_primary = urllib.parse.urlparse(primary_server)
        if parsed_primary.hostname:
            primary_server = parsed_primary.hostname
        if parsed_primary.path and primary_path == "/dns-query":
            primary_path = parsed_primary.path
        if parsed_primary.port:
            primary_port = parsed_primary.port

    if dns_type == "https":
        if not _is_ip_address(primary_server):
            if not primary_tls_sni:
                primary_tls_sni = primary_server
            resolved_ip: str | None = None
            if catalog_map:
                for srv in catalog_map.values():
                    cand_url = str(srv.get("doh_url") or "")
                    if cand_url.startswith("https://"):
                        parsed_cand = urllib.parse.urlparse(cand_url)
                        if (parsed_cand.hostname or "").lower() == primary_server.lower() and _is_ip_address(
                            str(srv.get("ip") or "")
                        ):
                            resolved_ip = str(srv["ip"]).strip()
                            break
            if not resolved_ip:
                resolved_ip = _resolve_host_ipv4(primary_server)
            if resolved_ip:
                primary_server = resolved_ip
        elif extra_dns_servers_sni and not primary_tls_sni and catalog_map:
            for srv in catalog_map.values():
                if str(srv.get("ip") or "").strip() == primary_server:
                    cand_url = str(srv.get("doh_url") or "")
                    if cand_url.startswith("https://"):
                        parsed_cand = urllib.parse.urlparse(cand_url)
                        cand_path = parsed_cand.path or "/dns-query"
                        if cand_path == primary_path and parsed_cand.hostname and not _is_ip_address(parsed_cand.hostname):
                            primary_tls_sni = parsed_cand.hostname
                            break

    infra_low = {p.lower() for p in DEFAULT_BYPASS_PROCESSES} | {"sing-box", "sing-box.exe"}
    vpn_proc_list: list[str] = []
    seen_vpn_procs: set[str] = set()
    for p in vpn_processes or []:
        clean_p = Path(str(p or "").strip().replace("\\", "/")).name.strip()
        low_p = clean_p.lower()
        if clean_p and low_p not in infra_low and low_p not in seen_vpn_procs:
            seen_vpn_procs.add(low_p)
            vpn_proc_list.append(clean_p)

    has_usable_vpn = any(getattr(n, "enabled", True) and not is_placeholder_node(n) for n in vpn_nodes)

    def _build_catalog_dns_entry(
        srv: dict[str, Any],
        tag: str,
        *,
        allow_broken_doh: bool = True,
    ) -> dict[str, Any] | None:
        badges = list(srv.get("badges") or [])
        doh_url = str(srv.get("doh_url") or "")
        srv_https = ("DoH" in badges) or doh_url.startswith("https://")
        if not allow_broken_doh and bool(srv.get("doh_broken")):
            srv_https = False
        srv_path = "/dns-query"
        srv_port: int | None = None
        srv_sni: str | None = None
        parsed_host: str | None = None
        if doh_url.startswith("https://"):
            parsed = urllib.parse.urlparse(doh_url)
            if parsed.path:
                srv_path = parsed.path
            if parsed.port:
                srv_port = parsed.port
            parsed_host = parsed.hostname
            if parsed_host and not _is_ip_address(parsed_host):
                srv_sni = parsed_host

        srv_ip = str(srv.get("ip") or "").strip()
        if not _is_ip_address(srv_ip):
            host_to_resolve = srv_ip or parsed_host
            if host_to_resolve:
                if _is_ip_address(host_to_resolve):
                    srv_ip = host_to_resolve
                else:
                    if srv_https and not srv_sni:
                        srv_sni = host_to_resolve
                    cat_ip: str | None = None
                    for cat_srv in (catalog_map or {}).values():
                        cat_url = str(cat_srv.get("doh_url") or "")
                        if cat_url.startswith("https://"):
                            parsed_cat = urllib.parse.urlparse(cat_url)
                            if (parsed_cat.hostname or "").lower() == host_to_resolve.lower() and _is_ip_address(
                                str(cat_srv.get("ip") or "")
                            ):
                                cat_ip = str(cat_srv["ip"]).strip()
                                break
                    srv_ip = cat_ip or _resolve_host_ipv4(host_to_resolve) or ""
        if not srv_ip:
            return None
        if not extra_dns_servers_sni and parsed_host is None:
            srv_sni = None
        return _build_singbox_dns_server_entry(
            tag=tag,
            server=srv_ip,
            dns_type="https" if srv_https else "udp",
            doh_path=srv_path,
            tls_sni=srv_sni if srv_https else None,
            server_port=srv_port,
        )

    # 1. DNS configuration (Split-DNS by default: dns.final == "dns-local")
    primary_dns_entry = _build_singbox_dns_server_entry(
        tag="dns-doh",
        server=primary_server,
        dns_type=dns_type,
        doh_path=primary_path,
        tls_sni=primary_tls_sni,
        server_port=primary_port,
    )
    dns_servers: list[dict[str, Any]] = [
        primary_dns_entry,
        {"type": "local", "tag": "dns-local"},
    ]
    vpn_dns_tag = "dns-doh"
    vpn_outbound_resolver = "dns-doh"
    base_entry: dict[str, Any] | None = None
    if isinstance(base_dns, dict) and str(base_dns.get("category") or "").strip().lower() != "ai_bypass":
        base_entry = _build_catalog_dns_entry(base_dns, "dns-base", allow_broken_doh=False)
    if base_entry is not None:
        dns_servers.append(base_entry)
        vpn_dns_tag = "dns-base"
        vpn_outbound_resolver = "dns-base"
    elif has_usable_vpn:
        dns_servers.append(
            {
                "type": "https",
                "tag": "dns-vpn",
                "server": "9.9.9.9",
                "path": "/dns-query",
                "tls": {"enabled": True, "server_name": "dns.quad9.net"},
                "detour": "vpn-select",
            }
        )
        vpn_dns_tag = "dns-vpn"
        vpn_outbound_resolver = "dns-local"
    else:
        vpn_dns_tag = "dns-local"
        vpn_outbound_resolver = "dns-local"

    dns_rules: list[dict[str, Any]] = []
    use_remote_rulesets = bool(ruleset_base_url and str(ruleset_base_url).strip())
    rs_base = str(ruleset_base_url or "").rstrip("/")

    if bypass_list:
        dns_rules.append(
            {
                "domain_suffix": bypass_list,
                "server": "dns-local",
            }
        )

    if use_remote_rulesets:
        dns_rules.append(
            {
                "rule_set": ["rs-bundles-dns-vpn"],
                "server": vpn_dns_tag,
            }
        )
    else:
        br_dns_procs = list(dict.fromkeys([*vpn_proc_list, *((bundle_rules or {}).get("vpn_processes") or [])]))
        if br_dns_procs:
            dns_rules.append(
                {
                    "process_name": br_dns_procs,
                    "server": vpn_dns_tag,
                }
            )
        if (bundle_rules or {}).get("vpn_domains"):
            dns_rules.append(
                {
                    "domain_suffix": list((bundle_rules or {})["vpn_domains"]),
                    "server": vpn_dns_tag,
                }
            )

    if per_dns_domains and catalog_map is not None:
        for dns_id in sorted(per_dns_domains):
            srv = catalog_map.get(dns_id)
            if not srv:
                doh_domains = sorted(set(doh_domains).union(per_dns_domains[dns_id]))
                continue
            tag = f"dns-{dns_id}"
            srv_entry = _build_catalog_dns_entry(srv, tag)
            if srv_entry is None:
                doh_domains = sorted(set(doh_domains).union(per_dns_domains[dns_id]))
                continue

            dns_servers.append(srv_entry)
            dns_rules.append(
                {
                    "domain_suffix": sorted(set(per_dns_domains[dns_id])),
                    "server": tag,
                }
            )

    if use_remote_rulesets:
        if primary_is_smartdns:
            if vpn_dns_tag != "dns-local":
                dns_rules.append({"rule_set": ["rs-vpn"], "server": vpn_dns_tag})
            dns_rules.append({"rule_set": ["rs-smartdns"], "server": "dns-doh"})
        else:
            dns_rules.append({"rule_set": ["rs-doh"], "server": "dns-doh"})
    elif primary_is_smartdns:
        smart_doms = sorted(
            {
                d.strip().lower().lstrip(".")
                for d in [*doh_domains, *(smartdns_domains or []), *explicit_smartdns_hosts]
                if d and d.strip()
            }
        )
        non_smart_vpn_doms = [d for d in vpn_select_domains if d not in smart_doms]
        if non_smart_vpn_doms and vpn_dns_tag != "dns-local":
            dns_rules.append(
                {
                    "domain_suffix": non_smart_vpn_doms,
                    "server": vpn_dns_tag,
                }
            )
        if smart_doms:
            dns_rules.append(
                {
                    "domain_suffix": smart_doms,
                    "server": "dns-doh",
                }
            )
    elif doh_domains:
        dns_rules.append(
            {
                "domain_suffix": doh_domains,
                "server": "dns-doh",
            }
        )

    dns_config: dict[str, Any] = {
        "servers": dns_servers,
        "rules": dns_rules,
        "final": "dns-local",
    }

    # 2. Inbounds (safe mixed TUN + MTU 1380 by default)
    resolved_stack = tun_stack if tun_stack in ("mixed", "gvisor", "system") else "mixed"
    inbounds: list[dict[str, Any]] = []
    if enable_tun:
        inbounds.append(
            {
                "type": "tun",
                "tag": "tun-in",
                "interface_name": "netdoctor-tun",
                "address": ["172.19.0.1/30"],
                "mtu": 1380,
                "auto_route": True,
                "strict_route": False,
                "endpoint_independent_nat": True,
                "stack": resolved_stack,
                "route_exclude_address": [
                    "127.0.0.0/8",
                    "10.0.0.0/8",
                    "172.16.0.0/12",
                    "192.168.0.0/16",
                    "169.254.0.0/16",
                ],
            }
        )
    inbounds.append(
        {
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "127.0.0.1",
            "listen_port": 2080,
        }
    )
    if has_usable_vpn:
        inbounds.append(
            {
                "type": "mixed",
                "tag": "vpn-probe-in",
                "listen": "127.0.0.1",
                "listen_port": 2081,
            }
        )

    # 3. Outbounds & WireGuard endpoints (no fake tg-ws-out direct stub)
    outbounds: list[dict[str, Any]] = [
        {"type": "direct", "tag": "direct"},
    ]
    used_tags: set[str] = {"direct", "vpn-auto", "vpn-select", "vpn-ai"}
    if enable_byedpi:
        used_tags.add("byedpi-out")
        outbounds.append(
            {
                "type": "socks",
                "tag": "byedpi-out",
                "server": "127.0.0.1",
                "server_port": int(byedpi_port),
            }
        )

    class _NodeEntry(NamedTuple):
        tag: str
        sub_id: str
        region: str
        priority: int
        enabled: bool
        is_placeholder: bool
        orig_idx: int

    endpoints: list[dict[str, Any]] = []
    node_entries: list[_NodeEntry] = []

    for orig_idx, node in enumerate(vpn_nodes):
        raw_tag = str(node.tag or node.raw_outbound.get("tag") or node.protocol or "vpn-node")
        unique_tag = _unique_tag(raw_tag, used_tags)
        sub_id = _sanitize_tag_part(node.subscription_id or "default")
        raw_region = getattr(node, "region", None)
        if raw_region and raw_region != "other":
            region = str(raw_region).lower()
        else:
            shown_name = getattr(node, "display_name", "") or node.tag
            region = infer_node_region(shown_name, node.server)

        ob = dict(node.raw_outbound)
        ob["tag"] = unique_tag
        is_wg = ob.get("type") == "wireguard" or node.protocol in ("wireguard", "amneziawg")
        is_ts = ob.get("type") == "tailscale" or node.protocol == "tailscale"

        if xray_bridge_ports and unique_tag in xray_bridge_ports:
            outbounds.append(
                {
                    "type": "socks",
                    "tag": unique_tag,
                    "server": "127.0.0.1",
                    "server_port": int(xray_bridge_ports[unique_tag]),
                    "version": "5",
                }
            )
        elif is_ts:
            endpoints.append(_build_tailscale_endpoint(ob, node))
        elif is_wg and use_wireguard_endpoints:
            endpoints.append(
                _build_wireguard_endpoint(
                    ob,
                    node,
                    extended_core=extended_core,
                    domain_resolver=vpn_outbound_resolver,
                )
            )
        else:
            if not extended_core and ob.get("type") == "wireguard":
                for awg_key in _AMNEZIAWG_KEYS:
                    ob.pop(awg_key, None)
            srv_host = str(ob.get("server") or node.server or "").strip()
            if srv_host and not _is_ip_address(srv_host) and "domain_resolver" not in ob:
                ob["domain_resolver"] = vpn_outbound_resolver
            if ob.get("type") == "vless" and "packet_encoding" not in ob:
                ob["packet_encoding"] = "xudp"
            outbounds.append(ob)

        raw_prio = getattr(node, "priority", 100)
        try:
            prio = int(raw_prio if raw_prio is not None else 100)
        except (TypeError, ValueError):
            prio = 100
        enabled = bool(getattr(node, "enabled", True))
        placeholder = is_placeholder_node(node)
        node_entries.append(_NodeEntry(unique_tag, sub_id, region, prio, enabled, placeholder, orig_idx))

    all_node_tags = [e.tag for e in node_entries]
    quarantined = set(quarantined_tags or ())
    eligible_entries = [e for e in node_entries if e.enabled and not e.is_placeholder]
    active_entries = [e for e in eligible_entries if e.tag not in quarantined]
    if not active_entries:
        active_entries = list(eligible_entries) if eligible_entries else list(node_entries)
    active_entries.sort(key=lambda e: (e.priority, e.orig_idx))
    active_tags = [e.tag for e in active_entries]

    if all_node_tags:
        grouped_ut: dict[tuple[str, str], list[str]] = {}
        for e in active_entries:
            grouped_ut.setdefault((e.sub_id, e.region), []).append(e.tag)

        ut_group_tags: list[str] = []
        non_ru_ut_tags: list[str] = []
        for (sub_id, region), g_tags in grouped_ut.items():
            ut_tag = _unique_tag(f"ut-{sub_id}-{region}", used_tags)
            outbounds.append(
                {
                    "type": "urltest",
                    "tag": ut_tag,
                    "outbounds": g_tags,
                    "url": "https://www.gstatic.com/generate_204",
                    "interval": "1m",
                    "tolerance": 100,
                    "idle_timeout": "30m",
                    "interrupt_exist_connections": False,
                }
            )
            ut_group_tags.append(ut_tag)
            if region != "ru":
                non_ru_ut_tags.append(ut_tag)

        non_ru_node_tags = [e.tag for e in active_entries if e.region != "ru"]
        outbounds.append(
            {
                "type": "urltest",
                "tag": "vpn-auto",
                "outbounds": non_ru_node_tags or active_tags,
                "url": "https://www.gstatic.com/generate_204",
                "interval": "1m",
                "tolerance": 100,
                "idle_timeout": "30m",
                "interrupt_exist_connections": False,
            }
        )

        ai_targets = list(dict.fromkeys([*non_ru_ut_tags, *non_ru_node_tags]))
        if not ai_targets:
            ai_targets = list(active_tags)
        outbounds.append(
            {
                "type": "urltest",
                "tag": "vpn-ai",
                "outbounds": ai_targets,
                "url": "https://www.gstatic.com/generate_204",
                "interval": "1m",
                "tolerance": 100,
                "idle_timeout": "30m",
                "interrupt_exist_connections": False,
            }
        )

        default_outbound = "vpn-auto"
        if (vpn_selection_mode or "auto").strip().lower() == "priority":
            non_quarantined_active = [e for e in active_entries if e.tag not in quarantined]
            non_quarantined_tags = {e.tag for e in non_quarantined_active}
            pref = (preferred_vpn_node or "").strip()
            if pref and pref in non_quarantined_tags:
                default_outbound = pref
            else:
                prio_match = next((e.tag for e in non_quarantined_active if e.priority < 100), None)
                if prio_match is not None:
                    default_outbound = prio_match

        outbounds.append(
            {
                "type": "selector",
                "tag": "vpn-select",
                "outbounds": ["vpn-auto", *ut_group_tags, *all_node_tags, "direct"],
                "default": default_outbound,
            }
        )
    else:
        outbounds.append(
            {
                "type": "selector",
                "tag": "vpn-ai",
                "outbounds": ["direct"],
                "default": "direct",
            }
        )
        outbounds.append(
            {
                "type": "selector",
                "tag": "vpn-select",
                "outbounds": ["direct"],
                "default": "direct",
            }
        )

    bypass_procs = list(dict.fromkeys([*DEFAULT_BYPASS_PROCESSES, *(extra_bypass_processes or [])]))

    # 4. Route rules: proc_bypass_rule strictly BEFORE sniff & hijack-dns!
    proc_bypass_rule: dict[str, Any] = {
        "process_name": bypass_procs,
        "outbound": "direct",
    }
    if enable_tun:
        proc_bypass_rule["inbound"] = ["tun-in"]

    normalized_bypass_cidrs: list[str] = []
    seen_cidrs: set[str] = set()
    for raw_ip in bypass_ips or []:
        cand = str(raw_ip or "").strip()
        if not cand:
            continue
        try:
            net_obj = ipaddress.ip_network(cand, strict=False)
            cidr = str(net_obj)
        except ValueError:
            continue
        if cidr not in seen_cidrs:
            seen_cidrs.add(cidr)
            normalized_bypass_cidrs.append(cidr)

    route_rules: list[dict[str, Any]] = [
        # 1. Bypass internal tools (python, winws2, tg-ws-proxy, xray) BEFORE hijack-dns/sniff
        proc_bypass_rule,
        # 2. Sniff web & DNS ports
        {"port": [53, 80, 443, 8080, 8443], "action": "sniff", "timeout": "100ms"},
        # 3. Hijack DNS into Split-DNS engine
        {"protocol": "dns", "action": "hijack-dns"},
    ]

    if normalized_bypass_cidrs:
        route_rules.append({"ip_cidr": normalized_bypass_cidrs, "outbound": "direct"})

    if bypass_list:
        route_rules.append({"domain_suffix": bypass_list, "outbound": "direct"})

    # 4. AppBundle rules (VPN bundle & process rules strictly BEFORE direct bundle rules)
    if use_remote_rulesets:
        rs_vpn_bundle_rule: dict[str, Any] = {"rule_set": ["rs-bundles-vpn"], "outbound": "vpn-select"}
        rs_direct_rule: dict[str, Any] = {"rule_set": ["rs-bundles-direct"], "outbound": "direct"}
        if enable_tun:
            rs_vpn_bundle_rule["inbound"] = ["tun-in"]
            rs_direct_rule["inbound"] = ["tun-in"]
        route_rules.append(rs_vpn_bundle_rule)
        if vpn_proc_list:
            vpn_proc_rule: dict[str, Any] = {
                "process_name": vpn_proc_list,
                "outbound": "vpn-select",
            }
            if enable_tun:
                vpn_proc_rule["inbound"] = ["tun-in"]
            route_rules.append(vpn_proc_rule)
        route_rules.append(rs_direct_rule)
    elif bundle_rules:
        if bundle_rules.get("vpn_processes"):
            r: dict[str, Any] = {"process_name": list(bundle_rules["vpn_processes"]), "outbound": "vpn-select"}
            if enable_tun:
                r["inbound"] = ["tun-in"]
            route_rules.append(r)
        if bundle_rules.get("vpn_path_regexes"):
            r = {"process_path_regex": list(bundle_rules["vpn_path_regexes"]), "outbound": "vpn-select"}
            if enable_tun:
                r["inbound"] = ["tun-in"]
            route_rules.append(r)
        if bundle_rules.get("vpn_domains"):
            route_rules.append({"domain_suffix": list(bundle_rules["vpn_domains"]), "outbound": "vpn-select"})

        if vpn_proc_list:
            vpn_proc_rule = {
                "process_name": vpn_proc_list,
                "outbound": "vpn-select",
            }
            if enable_tun:
                vpn_proc_rule["inbound"] = ["tun-in"]
            route_rules.append(vpn_proc_rule)

        if bundle_rules.get("direct_processes"):
            r = {"process_name": list(bundle_rules["direct_processes"]), "outbound": "direct"}
            if enable_tun:
                r["inbound"] = ["tun-in"]
            route_rules.append(r)
        if bundle_rules.get("direct_path_regexes"):
            r = {"process_path_regex": list(bundle_rules["direct_path_regexes"]), "outbound": "direct"}
            if enable_tun:
                r["inbound"] = ["tun-in"]
            route_rules.append(r)
        if bundle_rules.get("direct_domains"):
            route_rules.append({"domain_suffix": list(bundle_rules["direct_domains"]), "outbound": "direct"})
    elif vpn_proc_list:
        vpn_proc_rule = {
            "process_name": vpn_proc_list,
            "outbound": "vpn-select",
        }
        if enable_tun:
            vpn_proc_rule["inbound"] = ["tun-in"]
        route_rules.append(vpn_proc_rule)

    # 5. Dynamic domain rule_sets (or inline fallback when ruleset_base_url is None)
    route_rule_sets: list[dict[str, Any]] = []
    if use_remote_rulesets:
        rs_tags = [
            "rs-doh",
            "rs-smartdns",
            "rs-vpn",
            "rs-vpn-ai",
            "rs-quic-reject",
            "rs-bundles-direct",
            "rs-bundles-vpn",
            "rs-bundles-dns-vpn",
        ]
        if enable_byedpi:
            rs_tags.append("rs-byedpi")
        for rtag in rs_tags:
            route_rule_sets.append(
                {
                    "tag": rtag,
                    "type": "remote",
                    "format": "source",
                    "url": f"{rs_base}/{rtag}.json",
                    "update_interval": "15s",
                    "download_detour": "direct",
                }
            )
        route_rules.append({"rule_set": ["rs-vpn"], "outbound": "vpn-select"})
        if has_usable_vpn:
            route_rules.append({"inbound": ["vpn-probe-in"], "outbound": "vpn-select"})
        route_rules.append({"rule_set": ["rs-vpn-ai"], "outbound": "vpn-ai"})
        if enable_byedpi:
            route_rules.append({"rule_set": ["rs-byedpi"], "outbound": "byedpi-out"})
        route_rules.append(
            {
                "rule_set": ["rs-quic-reject"],
                "network": "udp",
                "port": 443,
                "action": "reject",
            }
        )
    else:
        if vpn_select_domains:
            route_rules.append({"domain_suffix": vpn_select_domains, "outbound": "vpn-select"})
        if str(telegram_mode or "mtproto").strip().lower() == "transparent" and (
            "telegram.org" in vpn_select_set or "t.me" in vpn_select_set
        ):
            route_rules.append({"ip_cidr": list(TELEGRAM_CIDRS), "outbound": "vpn-select"})
        if has_usable_vpn:
            route_rules.append({"inbound": ["vpn-probe-in"], "outbound": "vpn-select"})
        if vpn_ai_domains:
            route_rules.append({"domain_suffix": vpn_ai_domains, "outbound": "vpn-ai"})
        if byedpi_domains:
            route_rules.append({"domain_suffix": byedpi_domains, "outbound": "byedpi-out"})
        if quic_reject_domains:
            route_rules.append(
                {
                    "domain_suffix": quic_reject_domains,
                    "network": "udp",
                    "port": 443,
                    "action": "reject",
                }
            )

    route_block: dict[str, Any] = {
        "auto_detect_interface": True,
        "default_domain_resolver": "dns-local",
        "rules": route_rules,
        "final": "direct",
    }
    if route_rule_sets:
        route_block["rule_set"] = route_rule_sets

    config: dict[str, Any] = {
        "log": {"level": "info", "timestamp": True},
        "dns": dns_config,
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": route_block,
    }

    if endpoints:
        config["endpoints"] = endpoints

    if clash_api_addr:
        config["experimental"] = {
            "clash_api": {
                "external_controller": clash_api_addr,
                "secret": clash_api_secret,
                "default_mode": "rule",
            },
            "cache_file": {
                "enabled": True,
                "path": "singbox-cache.db",
            },
        }

    if output_path:
        out_file = Path(output_path)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8")

    return config
