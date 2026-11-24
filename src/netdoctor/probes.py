"""Async probes for DNS (System vs DoH), TCP, TLS (Real vs Neutral SNI), Stall/Throughput, and QUIC."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
from pathlib import Path
from typing import Any, Sequence

import dns.asyncresolver
import dns.message
import dns.name
import dns.rdatatype
import dns.resolver
import httpx
import psutil

_PROBE_CACHE_LOCK = threading.Lock()
_GW_MAC_CACHE: dict[str, tuple[str, float]] = {}
_NETWORK_FP_CACHE: tuple[str, float, Any] | None = None
_DEPRIORITIZED_SYSTEM_NS: dict[str, float] = {}


def clear_network_fingerprint_cache() -> None:
    """Invalidate cached gateway MAC and network fingerprint lookups."""
    global _NETWORK_FP_CACHE
    with _PROBE_CACHE_LOCK:
        _GW_MAC_CACHE.clear()
        _NETWORK_FP_CACHE = None


def clear_dns_probe_cache() -> None:
    """Invalidate deprioritized system DNS resolver cache."""
    with _PROBE_CACHE_LOCK:
        _DEPRIORITIZED_SYSTEM_NS.clear()

from netdoctor.models import (
    DnsProbeResult,
    NetworkFingerprint,
    NetworkKind,
    ProbesSummary,
    ProtocolBlockProbeResult,
    QuicProbeResult,
    StallProbeResult,
    TcpProbeResult,
    TlsProbeResult,
)

# Common ISP stub/sinkhole ranges or bogon IPs returned on DNS poisoning
KNOWN_STUB_IPS = {
    "0.0.0.0",
    "127.0.0.1",
    "::1",
}


def silence_proactor_connection_reset(loop: asyncio.AbstractEventLoop | None = None) -> None:
    """Suppress benign Windows ProactorEventLoop SSL/TCP WinError 10054 callback noise on TSPU RST."""
    try:
        active_loop = loop or asyncio.get_running_loop()
    except RuntimeError:
        return
    orig_handler = active_loop.get_exception_handler()
    if getattr(orig_handler, "_netdoctor_proactor_silenced", False):
        return

    def _handler(lp: asyncio.AbstractEventLoop, context: dict) -> None:
        exc = context.get("exception")
        msg = str(context.get("message") or "")
        if isinstance(exc, (ConnectionResetError, OSError, ssl.SSLError)) or "_ProactorBasePipeTransport" in msg:
            return
        if orig_handler is not None:
            orig_handler(lp, context)
        else:
            lp.default_exception_handler(context)

    setattr(_handler, "_netdoctor_proactor_silenced", True)
    active_loop.set_exception_handler(_handler)


def is_stub_ip(ip_str: str) -> bool:
    if ip_str in KNOWN_STUB_IPS:
        return True
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_loopback or addr.is_unspecified or addr.is_reserved or addr.is_private
    except ValueError:
        return True


def is_dns_ip_mismatch(dns_res: DnsProbeResult) -> bool:
    """Return True if system DNS and DoH both succeeded with non-empty IPs sharing no /24 IPv4 prefix."""
    if dns_res.system != "ok" or dns_res.doh != "ok":
        return False
    if not dns_res.system_ips or not dns_res.doh_ips:
        return False
    sys_prefixes = {".".join(ip.split(".")[:3]) for ip in dns_res.system_ips if "." in ip}
    doh_prefixes = {".".join(ip.split(".")[:3]) for ip in dns_res.doh_ips if "." in ip}
    if sys_prefixes and doh_prefixes:
        return sys_prefixes.isdisjoint(doh_prefixes)
    return set(dns_res.system_ips).isdisjoint(set(dns_res.doh_ips))


def detect_bypass_active() -> bool:
    """Check if winws/winws2, sing-box, ciadpi, or an active (UP) VPN/TUN adapter is running."""
    target_names = {
        "winws.exe",
        "winws2.exe",
        "sing-box.exe",
        "ciadpi.exe",
    }
    for proc in psutil.process_iter(["name"]):
        try:
            name = (proc.info.get("name") or "").lower()
            if name in target_names:
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    tun_keywords = (
        "happ-xray",
        "happ tunnel",
        "netdoctor-tun",
        "wintun",
        "xray",
        "amnezia",
        "wireguard",
    )
    try:
        for iface_name, stats in psutil.net_if_stats().items():
            if stats.isup:
                low_name = iface_name.lower()
                if any(kw in low_name for kw in tun_keywords):
                    return True
    except Exception:
        pass
    return False


def detect_external_bypass_active(logs_dir: str | Path = "logs") -> bool:
    """Return True only if bypass processes or VPN/TUN adapters are running outside netdoctor's own supervisor stack."""
    logs_path = Path(logs_dir)
    state_file = logs_path if logs_path.suffix.lower() == ".json" else (logs_path / "supervisor_state.json")

    owned_pids: set[int] = set()
    owns_singbox = False
    if state_file.is_file():
        try:
            data = json.loads(state_file.read_text(encoding="utf-8"))
            procs = data.get("processes") if isinstance(data, dict) else None
            if isinstance(procs, dict):
                for proc_key, info in procs.items():
                    if not isinstance(info, dict):
                        continue
                    pid = info.get("pid")
                    if isinstance(pid, int) and not isinstance(pid, bool) and pid > 0 and psutil.pid_exists(pid):
                        owned_pids.add(pid)
                        if str(proc_key) == "sing-box":
                            owns_singbox = True
        except Exception:
            pass

    target_names = {
        "winws.exe",
        "winws2.exe",
        "sing-box.exe",
        "ciadpi.exe",
    }
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            info = proc.info if isinstance(proc.info, dict) else {}
            name = str(info.get("name") or "").lower()
            if name in target_names:
                pid = info.get("pid")
                if pid is None:
                    pid = getattr(proc, "pid", None)
                if pid not in owned_pids:
                    return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    tun_keywords = (
        "happ-xray",
        "happ tunnel",
        "netdoctor-tun",
        "wintun",
        "xray",
        "amnezia",
        "wireguard",
    )
    try:
        for iface_name, stats in psutil.net_if_stats().items():
            if stats.isup:
                low_name = iface_name.lower()
                if any(kw in low_name for kw in tun_keywords):
                    if owns_singbox and "netdoctor-tun" in low_name:
                        continue
                    return True
    except Exception:
        pass
    return False


_MAC_RE = re.compile(r"\b([0-9a-f]{2}(?:[:-][0-9a-f]{2}){5})\b", re.IGNORECASE)


def _arp_mac_for_gateway(gw_ip: str) -> str:
    try:
        arp_proc = subprocess.run(
            ["arp", "-a", gw_ip],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=1.5,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (subprocess.SubprocessError, OSError):
        return ""
    for line in (arp_proc.stdout or "").splitlines():
        parts = line.split()
        if not parts or parts[0] != gw_ip:
            continue
        mac_match = _MAC_RE.search(line)
        if mac_match:
            return mac_match.group(1).replace("-", ":").lower()
    return ""


def _detect_default_gateway_mac(gw_ip: str | None = None) -> str:
    """Best-effort fast Windows helper returning the physical default gateway MAC address, or ''."""
    if sys.platform != "win32":
        return ""
    clean_gw = (gw_ip or "").strip()
    if clean_gw:
        try:
            if ipaddress.ip_address(clean_gw).version == 4:
                now = time.monotonic()
                with _PROBE_CACHE_LOCK:
                    cached = _GW_MAC_CACHE.get(clean_gw)
                if cached is not None and cached[1] > now:
                    return cached[0]
                mac = _arp_mac_for_gateway(clean_gw)
                with _PROBE_CACHE_LOCK:
                    _GW_MAC_CACHE[clean_gw] = (mac, time.monotonic() + (300.0 if mac else 30.0))
                return mac
        except ValueError:
            pass

    try:
        route_proc = subprocess.run(
            ["route", "print", "0.0.0.0"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=1.5,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (subprocess.SubprocessError, OSError):
        return ""

    candidates: list[tuple[int, str]] = []
    for line in (route_proc.stdout or "").splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        if parts[0] != "0.0.0.0" or parts[1] != "0.0.0.0":
            continue
        cand_gw = parts[2]
        try:
            addr = ipaddress.ip_address(cand_gw)
            if addr.version != 4:
                continue
        except ValueError:
            continue
        try:
            metric = int(parts[4]) if len(parts) >= 5 else 9999
        except ValueError:
            metric = 9999
        candidates.append((metric, cand_gw))

    if not candidates:
        return ""
    candidates.sort(key=lambda item: item[0])

    for _metric, cand_gw in candidates:
        mac = _arp_mac_for_gateway(cand_gw)
        if mac:
            with _PROBE_CACHE_LOCK:
                _GW_MAC_CACHE[cand_gw] = (mac, time.monotonic() + 300.0)
            return mac
    return ""


async def detect_network_fingerprint(timeout: float = 3.0, *, use_cache: bool = True) -> NetworkFingerprint:
    """Detect current network ASN and kind without leaking sensitive browsing data."""
    global _NETWORK_FP_CACHE
    from netdoctor.config_gen import detect_physical_egress_route

    phys_idx, phys_gw = detect_physical_egress_route()
    route_key = f"{phys_idx}:{phys_gw}" if phys_idx is not None else ""
    now = time.monotonic()
    if use_cache and route_key:
        with _PROBE_CACHE_LOCK:
            cached = _NETWORK_FP_CACHE
        if cached is not None and cached[0] == route_key and cached[1] > now:
            return cached[2].model_copy()

    gw_mac = await asyncio.to_thread(_detect_default_gateway_mac, phys_gw or None)
    default_fp = NetworkFingerprint(asn=0, kind=NetworkKind.HOME, isp="unknown", gateway_mac=gw_mac)
    fp = default_fp
    ttl_sec = 15.0
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(
                "https://speed.cloudflare.com/meta",
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                    "Referer": "https://speed.cloudflare.com/",
                },
            )
            if resp.status_code == 200:
                data = resp.json()
                asn = int(data.get("asn") or 0)
                isp = str(data.get("asOrganization") or "unknown")
                kind = (
                    NetworkKind.MOBILE
                    if any(m in isp.lower() for m in ("mobile", "mts", "megafon", "vimpelcom", "tele2", "yota"))
                    else NetworkKind.HOME
                )
                fp = NetworkFingerprint(asn=asn, kind=kind, isp=isp, gateway_mac=gw_mac)
                if asn > 0:
                    ttl_sec = 120.0
    except Exception:
        pass

    if use_cache and route_key:
        with _PROBE_CACHE_LOCK:
            _NETWORK_FP_CACHE = (route_key, time.monotonic() + ttl_sec, fp.model_copy())
    return fp


def order_system_nameservers(raw_ns: Sequence[str]) -> list[str]:
    """Partition system nameservers into healthy + currently deprioritized (dead-on-timeout) servers."""
    now_ns = time.monotonic()
    clean_ns = [str(ns) for ns in raw_ns if str(ns)]
    with _PROBE_CACHE_LOCK:
        dep = {k: v for k, v in _DEPRIORITIZED_SYSTEM_NS.items() if v > now_ns}
        if len(dep) != len(_DEPRIORITIZED_SYSTEM_NS):
            _DEPRIORITIZED_SYSTEM_NS.clear()
            _DEPRIORITIZED_SYSTEM_NS.update(dep)
        healthy = [ns for ns in clean_ns if ns not in dep]
        stale = [ns for ns in clean_ns if ns in dep]
    return healthy + stale


def record_system_nameserver_winner(ordered_ns: Sequence[str], winner_ns: str) -> None:
    """Clear winner from deprioritized cache and deprioritize any earlier nameservers it failed over past."""
    if not winner_ns or winner_ns not in ordered_ns:
        return
    idx = list(ordered_ns).index(winner_ns)
    with _PROBE_CACHE_LOCK:
        _DEPRIORITIZED_SYSTEM_NS.pop(winner_ns, None)
        if idx > 0:
            exp = time.monotonic() + 120.0
            for dead_ns in ordered_ns[:idx]:
                _DEPRIORITIZED_SYSTEM_NS[dead_ns] = exp


async def probe_dns(
    domain: str,
    doh_url: str = "https://1.1.1.1/dns-query",
    system_nameservers: Sequence[str] | None = None,
    system_port: int = 53,
    timeout: float = 3.0,
) -> DnsProbeResult:
    """Compare system DNS resolver against DoH resolver concurrently."""

    async def _query_system() -> tuple[str, list[str]]:
        ordered_ns: list[str] = []
        auto_order = system_nameservers is None
        try:
            resolver = dns.asyncresolver.Resolver()
            if system_nameservers:
                resolver.nameservers = list(system_nameservers)
            elif resolver.nameservers:
                ordered_ns = order_system_nameservers([str(ns) for ns in resolver.nameservers])
                resolver.nameservers = ordered_ns
                resolver.timeout = min(0.55, max(0.25, timeout / 3.0))
            resolver.port = system_port
            resolver.lifetime = timeout
            ans = await resolver.resolve(domain, "A")
            if auto_order and ordered_ns:
                record_system_nameserver_winner(ordered_ns, str(getattr(ans, "nameserver", "") or ""))
            sys_ips = [r.address for r in ans]
            if not sys_ips or any(is_stub_ip(ip) for ip in sys_ips):
                return "stub_ip", sys_ips
            return "ok", sys_ips
        except dns.resolver.NXDOMAIN:
            return "nxdomain", []
        except Exception:
            return "timeout", []

    async def _query_doh() -> tuple[str, list[str]]:
        doh_candidates = [doh_url]
        if doh_url == "https://1.1.1.1/dns-query":
            doh_candidates.append("https://8.8.8.8/dns-query")

        q = dns.message.make_query(domain, dns.rdatatype.A)
        wire = q.to_wire()
        doh_status = "timeout"
        for candidate_url in doh_candidates:
            try:
                async with httpx.AsyncClient(timeout=timeout) as client:
                    resp = await client.post(
                        candidate_url,
                        content=wire,
                        headers={
                            "Content-Type": "application/dns-message",
                            "Accept": "application/dns-message",
                        },
                    )
                    if resp.status_code == 200:
                        msg = dns.message.from_wire(resp.content)
                        ips: list[str] = []
                        for rrset in msg.answer:
                            if rrset.rdtype == dns.rdatatype.A:
                                for item in rrset:
                                    ips.append(item.address)
                        if ips:
                            valid_ips = [ip for ip in ips if not is_stub_ip(ip)]
                            if valid_ips:
                                return "ok", valid_ips
                            continue
                        doh_status = "nxdomain"
            except Exception:
                continue
        return doh_status, []

    (sys_status, sys_ips), (doh_status, doh_ips) = await asyncio.gather(_query_system(), _query_doh())

    return DnsProbeResult(
        system=sys_status,
        doh=doh_status,
        system_ips=sys_ips,
        doh_ips=doh_ips,
    )


async def probe_tcp(ip: str, port: int = 443, timeout: float = 3.0) -> TcpProbeResult:
    """Probe raw TCP connectivity to target IP:port."""
    t0 = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        rtt = (time.perf_counter() - t0) * 1000.0
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return TcpProbeResult(result="ok", rtt_ms=round(rtt, 2), target_ip=ip)
    except asyncio.TimeoutError:
        return TcpProbeResult(result="timeout", target_ip=ip)
    except ConnectionResetError:
        return TcpProbeResult(result="reset", target_ip=ip)
    except ConnectionRefusedError:
        return TcpProbeResult(result="refused", target_ip=ip)
    except OSError:
        return TcpProbeResult(result="reset", target_ip=ip)


async def _single_tls_handshake(ip: str, port: int, sni: str, verify: bool, timeout: float) -> tuple[str, float | None]:
    """Perform a single TLS handshake to ip:port with specified SNI.
    If verify=False (for neutral SNI probe), any TLS response from server (even alert/cert mismatch) counts as 'ok'
    because it proves TSPU did not drop/reset the ClientHello.
    """
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    t0 = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx, server_hostname=sni),
            timeout=timeout,
        )
        elapsed = round((time.perf_counter() - t0) * 1000.0, 2)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return "ok", elapsed
    except ssl.SSLCertVerificationError:
        # Certificate mismatch/verification error means ServerHello + Certificate arrived!
        elapsed = round((time.perf_counter() - t0) * 1000.0, 2)
        return ("cert_mismatch" if verify else "ok"), elapsed
    except ssl.SSLError as e:
        msg = str(e).lower()
        if "internal error" in msg or "eof" in msg or "reset" in msg:
            return "reset", None
        # A TLS alert (e.g. unrecognized_name) from the server on neutral SNI proves our ClientHello reached the server!
        if "alert" in msg or "tlsv1" in msg or "unrecognized_name" in msg:
            return "ok", round((time.perf_counter() - t0) * 1000.0, 2)
        return "reset", None
    except asyncio.TimeoutError:
        return "timeout", None
    except (ConnectionResetError, BrokenPipeError, OSError):
        return "reset", None


async def probe_tls(
    ip: str,
    real_sni: str,
    neutral_sni: str = "example.com",
    port: int = 443,
    timeout: float = 3.5,
) -> TlsProbeResult:
    """Compare TLS handshake with real SNI vs neutral SNI concurrently to the same IP."""
    silence_proactor_connection_reset()
    (real_res, ttfb), (neutral_res, _) = await asyncio.gather(
        _single_tls_handshake(ip, port, real_sni, verify=False, timeout=timeout),
        _single_tls_handshake(ip, port, neutral_sni, verify=False, timeout=timeout),
    )
    return TlsProbeResult(real_sni=real_res, neutral_sni=neutral_res, ttfb_ms=ttfb)


async def probe_stall(
    ip: str,
    sni: str,
    port: int = 443,
    path: str = "/",
    expected_min_bytes: int = 64,
    timeout: float = 4.0,
    url_path: str | None = None,
    min_kbps: float = 0.0,
) -> StallProbeResult:
    """Send an HTTPS GET after TLS handshake and check if data transfer stalls or resets (throttling / byte-counter block)."""
    silence_proactor_connection_reset()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    effective_path = path
    if url_path is not None:
        raw_up = url_path.strip()
        if raw_up.startswith(("http://", "https://")):
            parsed = urllib.parse.urlsplit(raw_up)
            effective_path = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")
        elif raw_up:
            effective_path = raw_up if raw_up.startswith("/") else f"/{raw_up}"

    t0 = time.perf_counter()
    deadline = t0 + timeout
    total_read = 0
    writer: asyncio.StreamWriter | None = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx, server_hostname=sni),
            timeout=max(0.1, deadline - time.perf_counter()),
        )
        req = (
            f"GET {effective_path} HTTP/1.1\r\n"
            f"Host: {sni}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("ascii")
        writer.write(req)
        await asyncio.wait_for(writer.drain(), timeout=max(0.1, deadline - time.perf_counter()))

        while total_read < 32768:
            rem = deadline - time.perf_counter()
            if rem <= 0:
                raise asyncio.TimeoutError
            chunk = await asyncio.wait_for(reader.read(4096), timeout=rem)
            if not chunk:
                break
            total_read += len(chunk)

        elapsed = max(time.perf_counter() - t0, 0.001)
        if total_read < expected_min_bytes:
            return StallProbeResult(result="stall", bytes_read=total_read)
        kbps = round((total_read * 8 / 1000.0) / elapsed, 2)
        if min_kbps > 0 and kbps < min_kbps:
            return StallProbeResult(result="stall", bytes_read=total_read, throughput_kbps=kbps)
        return StallProbeResult(result="ok", bytes_read=total_read, throughput_kbps=kbps)
    except asyncio.TimeoutError:
        return StallProbeResult(
            result="stall" if total_read > 0 else "timeout",
            bytes_read=total_read,
        )
    except (ConnectionResetError, ssl.SSLError, OSError):
        return StallProbeResult(result="reset", bytes_read=total_read)
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


def _build_quic_initial_packet(sni: str) -> bytes:
    """Build a synthetic UDP QUIC v1 Initial-like probe packet containing the SNI string (min 1200 bytes)."""
    # Long header (0xC0) + Version 1 (0x00000001) + DCID len 8 + SCID len 8 + SNI marker + padding to 1200 bytes
    header = b"\xc3" + struct.pack("!I", 1) + b"\x08" + b"\x11\x22\x33\x44\x55\x66\x77\x88" + b"\x00"
    sni_bytes = sni.encode("ascii", errors="ignore")
    payload = b"QUIC_INITIAL_SNI:" + sni_bytes
    pad_len = max(0, 1200 - len(header) - len(payload))
    return header + payload + (b"\x00" * pad_len)


class _QuicDatagramProtocol(asyncio.DatagramProtocol):
    def __init__(self, fut: asyncio.Future[bytes]) -> None:
        self.fut = fut

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if not self.fut.done():
            self.fut.set_result(data)

    def error_received(self, exc: Exception) -> None:
        if not self.fut.done():
            self.fut.set_exception(exc)


async def probe_quic(ip: str, sni: str, port: int = 443, timeout: float = 2.0) -> QuicProbeResult:
    """Send a UDP/443 QUIC Initial packet and check if a UDP response arrives."""
    loop = asyncio.get_running_loop()
    fut: asyncio.Future[bytes] = loop.create_future()
    t0 = time.perf_counter()
    transport = None
    try:
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _QuicDatagramProtocol(fut),
            remote_addr=(ip, port),
        )
        transport.sendto(_build_quic_initial_packet(sni))
        await asyncio.wait_for(fut, timeout=timeout)
        rtt = round((time.perf_counter() - t0) * 1000.0, 2)
        return QuicProbeResult(result="ok", rtt_ms=rtt)
    except asyncio.TimeoutError:
        return QuicProbeResult(result="timeout")
    except (ConnectionResetError, OSError):
        return QuicProbeResult(result="reset")
    finally:
        if transport is not None:
            transport.close()


async def probe_protocol_block(
    ip: str,
    port: int = 443,
    sni: str = "example.com",
    timeout: float = 3.0,
) -> ProtocolBlockProbeResult:
    """Probe whether a reachable endpoint permits post-handshake tunnel traffic or blocks the protocol."""
    tls_res, _ = await _single_tls_handshake(ip, port, sni, verify=False, timeout=timeout)
    if tls_res != "ok":
        return ProtocolBlockProbeResult(result="unreachable", detail="endpoint_tls_failed")

    stall_res = await probe_stall(ip, sni=sni, port=port, expected_min_bytes=64, timeout=timeout)
    if stall_res.result in ("reset", "stall", "timeout"):
        return ProtocolBlockProbeResult(result="protocol_block", detail=f"post_handshake_{stall_res.result}")
    return ProtocolBlockProbeResult(result="ok", detail="stream_healthy")


async def run_domain_probes(
    domain: str,
    target_ip: str | None = None,
    tcp_port: int = 443,
    udp_port: int = 443,
    doh_url: str = "https://1.1.1.1/dns-query",
    timeout: float = 3.0,
) -> ProbesSummary:
    """Run the full diagnostic ladder of probes for a domain."""
    silence_proactor_connection_reset()
    dns_res = await probe_dns(domain, doh_url=doh_url, timeout=timeout)
    ip = target_ip or (dns_res.doh_ips[0] if dns_res.doh_ips else (dns_res.system_ips[0] if dns_res.system_ips else None))
    if not ip:
        return ProbesSummary(dns=dns_res)

    tcp_res = await probe_tcp(ip, port=tcp_port, timeout=timeout)
    if tcp_res.result != "ok":
        return ProbesSummary(dns=dns_res, tcp=tcp_res)

    async def _tls_and_stall() -> tuple[TlsProbeResult, StallProbeResult]:
        tls_r = await probe_tls(ip, real_sni=domain, port=tcp_port, timeout=timeout)
        if tls_r.real_sni == "ok":
            stall_r = await probe_stall(ip, sni=domain, port=tcp_port, timeout=timeout)
        else:
            stall_r = StallProbeResult(result="skipped")
        return tls_r, stall_r

    (tls_res, stall_res), quic_res = await asyncio.gather(
        _tls_and_stall(),
        probe_quic(ip, sni=domain, port=udp_port, timeout=min(timeout, 1.5)),
    )
    return ProbesSummary(
        dns=dns_res,
        tcp=tcp_res,
        tls=tls_res,
        stall=stall_res,
        quic=quic_res,
    )


DEFAULT_SERVICE_TEST_TARGETS: tuple[dict[str, Any], ...] = (
    {
        "service_group": "youtube",
        "label": "YouTube",
        "domain": "youtube.com",
        "url": "https://www.youtube.com/generate_204",
    },
    {
        "service_group": "youtube",
        "label": "YouTube CDN (16KB+)",
        "domain": "i.ytimg.com",
        "url": "https://i.ytimg.com/vi/dQw4w9WgXcQ/hqdefault.jpg",
        "min_bytes": 16384,
    },
    {
        "service_group": "discord",
        "label": "Discord",
        "domain": "discord.com",
        "url": "https://discord.com/api/v10/gateway",
    },
    {
        "service_group": "discord",
        "label": "Discord Invite",
        "domain": "discord.gg",
        "url": "https://discord.gg/",
    },
    {
        "service_group": "telegram",
        "label": "Telegram Web",
        "domain": "telegram.org",
        "url": "https://telegram.org/",
    },
    {
        "service_group": "telegram",
        "label": "Telegram API",
        "domain": "api.telegram.org",
        "url": "https://api.telegram.org/",
    },
    {
        "service_group": "telegram",
        "label": "Telegram DC",
        "domain": "dc2.telegram.org",
        "url": "tcp://149.154.167.220:443",
    },
)


def infer_service_group(domain: str) -> str:
    low = (domain or "").strip().lower()
    if any(k in low for k in ("youtube", "googlevideo", "ytimg", "youtu.be", "ggpht")):
        return "youtube"
    if any(k in low for k in ("discord", "dis.gd")):
        return "discord"
    if any(k in low for k in ("telegram", "t.me", "telesco.pe", "tdesktop")):
        return "telegram"
    if any(k in low for k in ("chatgpt", "openai", "claude", "anthropic", "grok", "x.ai", "gemini")):
        return "ai"
    if any(k in low for k in ("instagram", "twimg", "twitter", "x.com", "facebook")):
        return "social"
    return "other"


_ISP_BLOCK_MARKERS: tuple[str, ...] = ("warning.rt.ru", "eais", "zapret-info", "доступ ограничен")


async def probe_domain_connectivity(
    domain: str,
    *,
    url: str | None = None,
    service_group: str = "",
    proxy_url: str | None = None,
    timeout: float = 3.5,
    verify_tls: bool = True,
    min_bytes: int = 0,
) -> dict[str, object]:
    """Run a real live end-to-end connectivity check (HTTPS GET/stream or TCP/443) for a domain/service."""
    silence_proactor_connection_reset()
    clean_dom = (domain or "").strip().lower()
    group = service_group or infer_service_group(clean_dom)
    target_url = (url or f"https://{clean_dom}/").strip()

    if target_url.startswith("tcp://"):
        parsed = urllib.parse.urlsplit(target_url)
        host = parsed.hostname or clean_dom
        port = int(parsed.port or 443)
        res = await probe_tcp(host, port=port, timeout=timeout)
        ok = res.result == "ok"
        return {
            "domain": clean_dom,
            "service_group": group,
            "url": target_url,
            "ok": ok,
            "status_code": 200 if ok else None,
            "latency_ms": round(res.rtt_ms, 1) if res.rtt_ms is not None else None,
            "stage": "tcp" if ok else res.result,
            "error": "" if ok else f"TCP {host}:{port} -> {res.result}",
        }

    t0 = time.perf_counter()
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
        ),
        "Accept": "*/*",
    }
    bytes_read = 0
    try:
        async with httpx.AsyncClient(
            proxy=proxy_url,
            timeout=timeout,
            follow_redirects=False,
            verify=verify_tls,
        ) as client:
            if min_bytes > 0:
                async with client.stream("GET", target_url, headers=headers) as resp:
                    status_code = int(resp.status_code)
                    loc = str(resp.headers.get("location") or "").lower()
                    ctype = str(resp.headers.get("content-type") or "").lower()
                    cl_raw = str(resp.headers.get("content-length") or "").strip()
                    content_length = int(cl_raw) if cl_raw.isdigit() else None
                    sample = bytearray()
                    try:
                        async for chunk in resp.aiter_bytes():
                            bytes_read += len(chunk)
                            if len(sample) < 4096:
                                sample.extend(chunk[: 4096 - len(sample)])
                            if bytes_read >= min_bytes:
                                break
                    except (httpx.TimeoutException, httpx.RemoteProtocolError, OSError):
                        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 1)
                        return {
                            "domain": clean_dom,
                            "service_group": group,
                            "url": target_url,
                            "ok": False,
                            "status_code": status_code,
                            "latency_ms": elapsed_ms,
                            "stage": "throttle_16kb",
                            "error": f"Обрыв/троттлинг потока ({bytes_read} из {min_bytes} байт)",
                        }
                    body_head = bytes(sample).decode("utf-8", errors="ignore").lower() if "html" in ctype else ""
            else:
                resp = await client.get(target_url, headers=headers)
                status_code = int(resp.status_code)
                loc = str(resp.headers.get("location") or "").lower()
                ctype = str(resp.headers.get("content-type") or "").lower()
                content_length = None
                bytes_read = len(resp.content or b"")
                body_head = (resp.content or b"")[:4096].decode("utf-8", errors="ignore").lower() if "html" in ctype else ""

        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 1)
        # Reject obvious Russian ISP DPI redirect/HTML block pages
        if any(marker in loc for marker in ("warning.rt.ru", "block.", "rkn", "forbidden", "eais")) or (
            body_head and any(marker in body_head for marker in _ISP_BLOCK_MARKERS)
        ):
            return {
                "domain": clean_dom,
                "service_group": group,
                "url": target_url,
                "ok": False,
                "status_code": status_code,
                "latency_ms": elapsed_ms,
                "stage": "dpi_redirect",
                "error": f"ISP block page -> {loc[:80] or clean_dom}",
            }
        if min_bytes > 0 and status_code < 500 and bytes_read < min_bytes and (
            content_length is None or content_length >= min_bytes
        ):
            return {
                "domain": clean_dom,
                "service_group": group,
                "url": target_url,
                "ok": False,
                "status_code": status_code,
                "latency_ms": elapsed_ms,
                "stage": "throttle_16kb",
                "error": f"Обрыв/троттлинг потока ({bytes_read} из {min_bytes} байт)",
            }
        ok = status_code < 500
        return {
            "domain": clean_dom,
            "service_group": group,
            "url": target_url,
            "ok": ok,
            "status_code": status_code,
            "latency_ms": elapsed_ms,
            "stage": "https" if ok else f"http_{status_code}",
            "error": "" if ok else f"HTTP {status_code}",
        }
    except httpx.ReadTimeout:
        return {
            "domain": clean_dom,
            "service_group": group,
            "url": target_url,
            "ok": False,
            "status_code": None,
            "latency_ms": None,
            "stage": "throttle_16kb" if min_bytes > 0 else "timeout",
            "error": (
                f"Обрыв/троттлинг потока ({bytes_read} из {min_bytes} байт)"
                if min_bytes > 0
                else "Таймаут чтения ответа (DPI/ТСПУ)"
            ),
        }
    except httpx.TimeoutException:
        return {
            "domain": clean_dom,
            "service_group": group,
            "url": target_url,
            "ok": False,
            "status_code": None,
            "latency_ms": None,
            "stage": "timeout",
            "error": "Таймаут соединения (блокировка DPI/IP)",
        }
    except (httpx.ConnectError, httpx.RemoteProtocolError, ssl.SSLError) as exc:
        msg = str(exc)
        low = msg.lower()
        if "getaddrinfo" in low or "name or service" in low or "dns" in low:
            stage = "dns"
        elif isinstance(exc, ssl.SSLError) or "ssl" in low or "tls" in low or "certificate" in low or "eof" in low:
            stage = "tls"
        elif min_bytes > 0 and bytes_read > 0:
            stage = "throttle_16kb"
        else:
            stage = "reset"
        return {
            "domain": clean_dom,
            "service_group": group,
            "url": target_url,
            "ok": False,
            "status_code": None,
            "latency_ms": None,
            "stage": stage,
            "error": msg[:120],
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "domain": clean_dom,
            "service_group": group,
            "url": target_url,
            "ok": False,
            "status_code": None,
            "latency_ms": None,
            "stage": "error",
            "error": str(exc)[:120],
        }
