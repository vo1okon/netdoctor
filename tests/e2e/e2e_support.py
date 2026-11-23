"""Pure-Python opaque-box support helpers for netdoctor 4-Tier E2E tests."""

from __future__ import annotations

import ctypes
import importlib.util
import ipaddress
import json
import os
import re
import shlex
import socket
import struct
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import psutil

MAX_WINWS2_CONFIG_FILE_BYTES = 16384

BYPASS_PROCESS_NAMES = {
    "winws.exe",
    "winws2.exe",
    "sing-box.exe",
    "ciadpi.exe",
}

TUN_ADAPTER_KEYWORDS = (
    "happ-xray",
    "happ tunnel",
    "netdoctor-tun",
    "wintun",
    "xray",
    "amnezia",
    "wireguard",
)


# ---------------------------------------------------------------------------
# PE & Manifest Inspection (Zero-execution / non-UAC checks)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PeInspection:
    exists: bool
    size: int
    is_mz: bool
    is_pe: bool
    machine: int | None
    subsystem: int | None  # 2=WINDOWS_GUI, 3=WINDOWS_CUI
    requested_execution_level: str | None


def inspect_pe_binary(path: Path) -> PeInspection:
    """Inspect a Windows PE binary (.exe/.dll/.sys) without executing it."""
    if not path.is_file():
        return PeInspection(False, 0, False, False, None, None, None)

    data = path.read_bytes()
    size = len(data)
    if size < 64 or data[:2] != b"MZ":
        return PeInspection(True, size, False, False, None, None, None)

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > size or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        return PeInspection(True, size, True, False, None, None, None)

    machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
    subsystem: int | None = None
    opt_header_off = e_lfanew + 24
    if opt_header_off + 70 <= size:
        subsystem = struct.unpack_from("<H", data, opt_header_off + 68)[0]

    match = re.search(rb'<requestedExecutionLevel\b[^>]*level=["\']([^"\']+)["\']', data)
    level = match.group(1).decode("ascii", errors="replace") if match else None
    return PeInspection(True, size, True, True, machine, subsystem, level)


def probe_winws2_nondestructive(bin_dir: Path, timeout: float = 5.0) -> dict[str, Any]:
    """Validate winws2.exe and companion files without triggering UAC GUI.

    Uses CreateProcessW (shell=False), which never pops up a blocking UAC dialog
    and immediately raises OSError(winerror=740) in non-elevated shells.
    """
    exe = bin_dir / "winws2.exe"
    pe = inspect_pe_binary(exe)
    lua_dir = bin_dir / "lua"
    files_dir = bin_dir / "files"
    wf_dir = bin_dir / "windivert.filter"

    companions: dict[str, Any] = {
        "WinDivert.dll": inspect_pe_binary(bin_dir / "WinDivert.dll"),
        "WinDivert64.sys": inspect_pe_binary(bin_dir / "WinDivert64.sys"),
        "cygwin1.dll": inspect_pe_binary(bin_dir / "cygwin1.dll"),
        "lua_scripts": sorted(lua_dir.glob("*.lua")) if lua_dir.is_dir() else [],
        "files_dir": files_dir.is_dir(),
        "files_entries": sorted(p for p in files_dir.iterdir()) if files_dir.is_dir() else [],
        "windivert_filter_dir": wf_dir.is_dir(),
        "windivert_filter_entries": sorted(p for p in wf_dir.iterdir()) if wf_dir.is_dir() else [],
    }

    winerror: int | None = None
    returncode: int | None = None
    output = ""
    if pe.is_pe:
        try:
            proc = subprocess.run(
                [str(exe), "--help"],
                cwd=str(bin_dir),
                shell=False,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
            )
            returncode = proc.returncode
            output = (proc.stdout or "") + (proc.stderr or "")
        except OSError as exc:
            winerror = getattr(exc, "winerror", None)

    return {
        "pe": pe,
        "companions": companions,
        "winerror": winerror,
        "returncode": returncode,
        "output": output,
    }


# ---------------------------------------------------------------------------
# Host Privilege, Process, Adapter & Route Inspection
# ---------------------------------------------------------------------------


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def get_best_interface_index(dest_ip: str = "1.1.1.1") -> int | None:
    try:
        dest_nbo = struct.unpack("I", socket.inet_aton(dest_ip))[0]
        best_if = ctypes.c_ulong(0)
        rc = ctypes.windll.iphlpapi.GetBestInterface(dest_nbo, ctypes.byref(best_if))
        return int(best_if.value) if rc == 0 else None
    except Exception:
        return None


def _ps_json(ps_script: str, timeout: float = 10.0) -> list[dict[str, Any]]:
    cmd = [
        "powershell",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        f"$ErrorActionPreference='SilentlyContinue'; @({ps_script}) | ConvertTo-Json -Compress",
    ]
    res = subprocess.run(
        cmd,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )
    raw = (res.stdout or "").strip()
    if not raw or raw == "null":
        return []
    parsed = json.loads(raw)
    return parsed if isinstance(parsed, list) else [parsed]


def get_net_adapters() -> list[dict[str, Any]]:
    return _ps_json("Get-NetAdapter | Select-Object Name, InterfaceDescription, ifIndex, Status")


def get_ipv4_default_and_split_routes() -> list[dict[str, Any]]:
    return _ps_json(
        "Get-NetRoute -AddressFamily IPv4 | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0','0.0.0.0/1','128.0.0.0/1') } | "
        "Select-Object ifIndex, InterfaceAlias, DestinationPrefix, NextHop, RouteMetric, InterfaceMetric"
    )


def detect_host_bypasses() -> dict[str, Any]:
    procs: list[dict[str, Any]] = []
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            name = (proc.info.get("name") or "").lower()
            if name in BYPASS_PROCESS_NAMES:
                procs.append({"pid": proc.info["pid"], "name": proc.info["name"]})
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    up_tun_adapters = [
        a
        for a in get_net_adapters()
        if str(a.get("Status", "")).lower() == "up"
        and any(
            k in f"{a.get('Name', '')} {a.get('InterfaceDescription', '')}".lower()
            for k in TUN_ADAPTER_KEYWORDS
        )
    ]
    split_routes = [
        r
        for r in get_ipv4_default_and_split_routes()
        if r.get("DestinationPrefix") in {"0.0.0.0/1", "128.0.0.0/1"}
    ]
    return {
        "processes": procs,
        "up_tun_adapters": up_tun_adapters,
        "split_routes": split_routes,
        "active": bool(procs or up_tun_adapters or split_routes),
    }


def get_physical_uplink_ifindex() -> int | None:
    """Return physical Up adapter ifIndex (non-virtual, non-TUN, with IPv4 default route)."""
    routes = get_ipv4_default_and_split_routes()
    route_ifs = {
        r["ifIndex"]
        for r in routes
        if r.get("DestinationPrefix") == "0.0.0.0/0" and r.get("NextHop") != "0.0.0.0"
    }
    for adapter in get_net_adapters():
        if str(adapter.get("Status", "")).lower() != "up":
            continue
        desc = f"{adapter.get('Name', '')} {adapter.get('InterfaceDescription', '')}".lower()
        if any(k in desc for k in TUN_ADAPTER_KEYWORDS + ("bluetooth", "loopback", "radmin")):
            continue
        if adapter.get("ifIndex") in route_ifs:
            return int(adapter["ifIndex"])
    return None


def wait_for_tun_and_split_routes(tun_name: str = "netdoctor-tun", timeout: float = 15.0) -> dict[str, Any]:
    """Poll until the TUN adapter is Up and 0.0.0.0/1 + 128.0.0.0/1 split routes point to it."""
    deadline = time.monotonic() + timeout
    last_adapters: list[dict[str, Any]] = []
    last_routes: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        last_adapters = get_net_adapters()
        last_routes = get_ipv4_default_and_split_routes()
        tun_matches = [
            a
            for a in last_adapters
            if tun_name.lower() in str(a.get("Name", "")).lower()
            and str(a.get("Status", "")).lower() == "up"
        ]
        if tun_matches:
            tun_ifidx = int(tun_matches[0]["ifIndex"])
            prefixes = {
                r.get("DestinationPrefix")
                for r in last_routes
                if r.get("ifIndex") == tun_ifidx
            }
            if {"0.0.0.0/1", "128.0.0.0/1"}.issubset(prefixes):
                return {
                    "tun_ifindex": tun_ifidx,
                    "adapter": tun_matches[0],
                    "routes": last_routes,
                }
        time.sleep(0.5)

    raise TimeoutError(
        f"Timed out waiting for '{tun_name}' Up + split routes; adapters={last_adapters}, routes={last_routes}"
    )


# ---------------------------------------------------------------------------
# sing-box check & JSON Helpers
# ---------------------------------------------------------------------------


def load_json_no_bom(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    assert not raw.startswith(b"\xef\xbb\xbf"), f"{path} contains forbidden UTF-8 BOM"
    return json.loads(raw.decode("utf-8"))


def run_singbox_check(
    singbox_exe: Path,
    config_path: Path,
    timeout: float = 10.0,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(singbox_exe), "check", "-c", str(config_path)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )


# ---------------------------------------------------------------------------
# tg-ws-proxy Dynamic Discovery & Protocol Helpers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TgWsProxyContract:
    kind: str  # "python_script" | "python_module" | "console_exe" | "gui_portable_exe"
    entrypoint: Path | str
    cmd_prefix: tuple[str, ...]
    is_gui_bundle: bool
    supports_headless_cli: bool
    help_text: str
    default_port: int
    protocol_mode: str  # "socks5" | "mtproto" | "hybrid"


def _infer_singbox_tg_ws_contract(singbox_cfg_path: Path | None) -> tuple[int, str]:
    if not singbox_cfg_path or not singbox_cfg_path.is_file():
        return 10808, "socks5"
    try:
        cfg = load_json_no_bom(singbox_cfg_path)
    except Exception:
        return 10808, "socks5"

    for ob in cfg.get("outbounds", []):
        if ob.get("tag") == "tg-ws-out":
            ob_type = str(ob.get("type", "")).lower()
            port = int(ob.get("server_port") or 10808)
            if ob_type == "socks":
                return port, "socks5"
            if ob_type == "direct":
                return port, "mtproto"
            return port, ob_type or "socks5"
    return 10808, "mtproto"


def discover_tg_ws_proxy(
    repo_root: Path,
    bin_dir: Path,
    venv_python: Path,
    singbox_cfg_path: Path | None = None,
) -> TgWsProxyContract | None:
    """Dynamically locate tg-ws-proxy entrypoint and infer its CLI/protocol contract."""
    cfg_path = singbox_cfg_path or (repo_root / "configs" / "sing-box.json")
    default_port, protocol_mode = _infer_singbox_tg_ws_contract(cfg_path)

    script_candidates = [
        bin_dir / "tg-ws-proxy" / "proxy" / "tg_ws_proxy.py",
        bin_dir / "tg-ws-proxy" / "tg_ws_proxy.py",
        bin_dir / "tg_ws_proxy.py",
        repo_root / "proxy" / "tg_ws_proxy.py",
    ]
    for script in script_candidates:
        if script.is_file():
            help_text = ""
            try:
                res = subprocess.run(
                    [str(venv_python), str(script), "--help"],
                    cwd=str(script.parent),
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=5.0,
                )
                help_text = (res.stdout or "") + (res.stderr or "")
            except Exception:
                pass
            mode = protocol_mode
            low = help_text.lower()
            if "socks" in low and "mtproto" in low:
                mode = "hybrid"
            elif "socks" in low and protocol_mode == "mtproto":
                mode = "socks5"
            elif "--secret" in low and "socks" not in low:
                mode = "mtproto"
            return TgWsProxyContract(
                kind="python_script",
                entrypoint=script,
                cmd_prefix=(str(venv_python), str(script)),
                is_gui_bundle=False,
                supports_headless_cli=True,
                help_text=help_text,
                default_port=default_port,
                protocol_mode=mode,
            )

    for mod_name in ("tg_ws_proxy", "proxy.tg_ws_proxy"):
        try:
            spec = importlib.util.find_spec(mod_name)
        except Exception:
            spec = None
        if spec is not None:
            help_text = ""
            try:
                res = subprocess.run(
                    [str(venv_python), "-m", mod_name, "--help"],
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=5.0,
                )
                help_text = (res.stdout or "") + (res.stderr or "")
            except Exception:
                pass
            return TgWsProxyContract(
                kind="python_module",
                entrypoint=mod_name,
                cmd_prefix=(str(venv_python), "-m", mod_name),
                is_gui_bundle=False,
                supports_headless_cli=True,
                help_text=help_text,
                default_port=default_port,
                protocol_mode=protocol_mode,
            )

    exe_candidates = [
        bin_dir / "tg-ws-proxy.exe",
        bin_dir / "tg-ws-proxy" / "tg-ws-proxy.exe",
        bin_dir / "TgWsProxy_windows.exe",
        bin_dir / "tg-ws-proxy" / "TgWsProxy_windows.exe",
    ]
    for exe in exe_candidates:
        pe = inspect_pe_binary(exe)
        if not pe.is_pe:
            continue
        is_gui = pe.subsystem == 2 or "tgwsproxy_windows" in exe.name.lower()
        if not is_gui:
            help_text = ""
            try:
                res = subprocess.run(
                    [str(exe), "--help"],
                    cwd=str(exe.parent),
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=5.0,
                )
                help_text = (res.stdout or "") + (res.stderr or "")
            except Exception:
                pass
            return TgWsProxyContract(
                kind="console_exe",
                entrypoint=exe,
                cmd_prefix=(str(exe),),
                is_gui_bundle=False,
                supports_headless_cli=True,
                help_text=help_text,
                default_port=default_port,
                protocol_mode=protocol_mode,
            )
        return TgWsProxyContract(
            kind="gui_portable_exe",
            entrypoint=exe,
            cmd_prefix=(str(exe),),
            is_gui_bundle=True,
            supports_headless_cli=False,
            help_text="",
            default_port=default_port,
            protocol_mode=protocol_mode,
        )

    return None


def build_tg_ws_launch_cmd(
    contract: TgWsProxyContract,
    host: str,
    port: int,
    secret: str = "0123456789abcdef0123456789abcdef",
    log_file: Path | None = None,
    portable_dir: Path | None = None,
) -> tuple[list[str], Path]:
    """Build a non-blocking launch command + CWD for tg-ws-proxy."""
    if contract.supports_headless_cli:
        cmd = list(contract.cmd_prefix)
        low_help = contract.help_text.lower()
        if "--host" in low_help:
            cmd.extend(["--host", host])
        elif "--listen" in low_help:
            cmd.extend(["--listen", host])
        if "--port" in low_help or not low_help:
            cmd.extend(["--port", str(port)])
        if "--secret" in low_help:
            cmd.extend(["--secret", secret])
        if log_file is not None and "--log-file" in low_help:
            cmd.extend(["--log-file", str(log_file)])
        cwd = Path(contract.entrypoint).parent if isinstance(contract.entrypoint, Path) else Path.cwd()
        return cmd, cwd

    if portable_dir is None:
        raise ValueError("portable_dir is required for GUI portable tg-ws-proxy bundle")
    portable_dir.mkdir(parents=True, exist_ok=True)
    cfg_file = portable_dir / "config.json"
    cfg_file.write_text(
        json.dumps(
            {
                "host": host,
                "port": port,
                "secret": secret,
                "autostart": False,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return [str(contract.entrypoint), "--portable"], portable_dir


def probe_tg_ws_handshake(host: str, port: int, mode: str, timeout: float = 2.5) -> None:
    """Verify local tg-ws-proxy accepts a protocol handshake aligned with its declared mode."""
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        low_mode = mode.lower()
        if low_mode in ("socks", "socks5", "hybrid"):
            sock.sendall(b"\x05\x01\x00")
            reply = sock.recv(2)
            assert reply == b"\x05\x00", f"Expected SOCKS5 no-auth reply b'\\x05\\x00', got {reply!r}"
        else:
            # MTProto obfuscated2 64-byte init header (must not immediately RST)
            init_pkt = bytearray(os.urandom(64))
            init_pkt[56:60] = b"\xef\xef\xef\xef"
            sock.sendall(bytes(init_pkt))
            time.sleep(0.15)


def wait_for_tcp_port(host: str, port: int, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.4):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def allocate_ephemeral_port(kind: str = "tcp") -> int:
    """Allocate a free ephemeral port on 127.0.0.1 without SO_REUSEADDR."""
    sock_type = socket.SOCK_STREAM if kind == "tcp" else socket.SOCK_DGRAM
    with socket.socket(socket.AF_INET, sock_type) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


# ---------------------------------------------------------------------------
# winws2_preset.txt Token & Path Resolver
# ---------------------------------------------------------------------------


def parse_winws2_tokens(preset_path: Path) -> list[str]:
    tokens: list[str] = []
    for raw_line in preset_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        tokens.extend(shlex.split(line, posix=True))
    return tokens


def resolve_winws2_references(
    tokens: list[str],
    bin_dir: Path,
    lists_dir: Path,
    workspace_root: Path | None = None,
) -> list[tuple[str, Path, bool]]:
    """Resolve file references inside winws2 args (@lua/..., --blob=..:@..., --hostlist=..., --ipset-exclude=...)."""
    refs: list[tuple[str, Path, bool]] = []
    roots = [r for r in (workspace_root, bin_dir, lists_dir) if r is not None]

    def _check_path(raw_ref: str, prefer_bin: bool) -> Path:
        p = Path(raw_ref)
        if p.is_absolute():
            return p
        search_order = [bin_dir, *(roots)] if prefer_bin else [*(roots)]
        for base in search_order:
            candidate = base / p
            if candidate.exists():
                return candidate
            if prefer_bin and p.parts and p.parts[0].lower() != "lua" and (bin_dir / "lua" / p).exists():
                return bin_dir / "lua" / p
        return (bin_dir / p) if prefer_bin else ((workspace_root or lists_dir) / p)

    for tok in tokens:
        if tok.startswith("--lua-init=@"):
            raw_ref = tok[len("--lua-init=@") :]
            resolved = _check_path(raw_ref, prefer_bin=True)
            refs.append((tok, resolved, resolved.is_file() and resolved.stat().st_size > 0))
        elif tok.startswith("--blob=") and ":@" in tok:
            raw_ref = tok.split(":@", 1)[1]
            resolved = _check_path(raw_ref, prefer_bin=True)
            refs.append((tok, resolved, resolved.is_file() and resolved.stat().st_size > 0))
        elif tok.startswith(("--hostlist=", "--hostlist-exclude=", "--ipset=", "--ipset-exclude=")):
            raw_ref = tok.split("=", 1)[1]
            p = Path(raw_ref)
            if p.is_absolute():
                resolved = p
            else:
                candidates = [
                    *( [workspace_root / p] if workspace_root else [] ),
                    lists_dir / p,
                    lists_dir / p.name,
                    bin_dir / p,
                ]
                resolved = next((c for c in candidates if c.exists()), candidates[0])
            refs.append((tok, resolved, resolved.is_file() and resolved.stat().st_size > 0))

    return refs


def validate_ip_only_file(path: Path) -> list[str]:
    """Return list of non-empty lines from path after asserting every line is a valid IP or CIDR."""
    assert path.is_file(), f"Missing IP list file: {path}"
    lines = [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip() and not ln.strip().startswith("#")]
    for line in lines:
        ipaddress.ip_network(line, strict=False)
    return lines


# ---------------------------------------------------------------------------
# pcapng Parser & winws2 --debug=1 Log Parser
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PcapngSummary:
    interfaces: list[dict[str, Any]]
    total_packets: int
    tcp_packets: int
    packets_by_iface: dict[int, int]
    port_443_packets_by_iface: dict[int, int]


def parse_pcapng_tcp_packets(pcapng_path: Path) -> PcapngSummary:
    """Minimal pure-Python PCAPNG parser reading SHB, IDB, and EPB/SPB TCP/443 counters."""
    data = pcapng_path.read_bytes()
    if len(data) < 28:
        return PcapngSummary([], 0, 0, {}, {})

    endian = "<"
    pos = 0
    interfaces: list[dict[str, Any]] = []
    total_packets = 0
    tcp_packets = 0
    packets_by_iface: dict[int, int] = {}
    port_443_by_iface: dict[int, int] = {}

    while pos + 12 <= len(data):
        block_type = struct.unpack_from(endian + "I", data, pos)[0]
        if block_type == 0x0A0D0D0A:
            # Byte-order magic at +8
            if data[pos + 8 : pos + 12] == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif data[pos + 8 : pos + 12] == b"\x1a\x2b\x3c\x4d":
                endian = ">"
        block_len = struct.unpack_from(endian + "I", data, pos + 4)[0]
        if block_len < 12 or pos + block_len > len(data):
            break

        body = data[pos + 8 : pos + block_len - 4]
        if block_type == 0x00000001 and len(body) >= 8:  # IDB
            link_type, _reserved, snaplen = struct.unpack_from(endian + "HHI", body, 0)
            interfaces.append({"index": len(interfaces), "link_type": link_type, "snaplen": snaplen})
        elif block_type == 0x00000006 and len(body) >= 20:  # EPB
            iface_id, _ts_hi, _ts_lo, cap_len, _orig_len = struct.unpack_from(endian + "IIIII", body, 0)
            pkt = body[20 : 20 + cap_len]
            total_packets += 1
            packets_by_iface[iface_id] = packets_by_iface.get(iface_id, 0) + 1
            if _is_tcp_port(pkt, 443):
                tcp_packets += 1
                port_443_by_iface[iface_id] = port_443_by_iface.get(iface_id, 0) + 1
            elif _is_tcp_packet(pkt):
                tcp_packets += 1
        elif block_type == 0x00000003 and len(body) >= 4:  # SPB
            total_packets += 1
            packets_by_iface[0] = packets_by_iface.get(0, 0) + 1
            pkt = body[4:]
            if _is_tcp_port(pkt, 443):
                tcp_packets += 1
                port_443_by_iface[0] = port_443_by_iface.get(0, 0) + 1
            elif _is_tcp_packet(pkt):
                tcp_packets += 1

        pos += block_len

    return PcapngSummary(
        interfaces=interfaces,
        total_packets=total_packets,
        tcp_packets=tcp_packets,
        packets_by_iface=packets_by_iface,
        port_443_packets_by_iface=port_443_by_iface,
    )


def _extract_ip_payload(pkt: bytes) -> tuple[int, bytes] | None:
    """Return (ip_proto, l4_payload) for Ethernet or Raw IP packets."""
    if len(pkt) >= 14:
        ethertype = struct.unpack_from("!H", pkt, 12)[0]
        if ethertype == 0x0800 and len(pkt) >= 34:
            ihl = (pkt[14] & 0x0F) * 4
            if ihl >= 20 and len(pkt) >= 14 + ihl:
                return pkt[14 + 9], pkt[14 + ihl :]
        if ethertype == 0x86DD and len(pkt) >= 54:
            return pkt[14 + 6], pkt[54:]
    if len(pkt) >= 20 and (pkt[0] >> 4) == 4:
        ihl = (pkt[0] & 0x0F) * 4
        if ihl >= 20 and len(pkt) >= ihl:
            return pkt[9], pkt[ihl:]
    return None


def _is_tcp_packet(pkt: bytes) -> bool:
    extracted = _extract_ip_payload(pkt)
    return extracted is not None and extracted[0] == 6


def _is_tcp_port(pkt: bytes, port: int) -> bool:
    extracted = _extract_ip_payload(pkt)
    if extracted is None or extracted[0] != 6 or len(extracted[1]) < 4:
        return False
    sport, dport = struct.unpack_from("!HH", extracted[1], 0)
    return sport == port or dport == port


def parse_winws2_debug_log(
    log_path: Path,
    expected_phys_ifidx: int | None = None,
    tun_ifidx: int | None = None,
    target_domain: str | None = None,
) -> dict[str, Any]:
    text = log_path.read_text(encoding="utf-8", errors="replace") if log_path.is_file() else ""
    low = text.lower()
    ifidx_matches = sorted({int(m.group(1)) for m in re.finditer(r"\bIfIdx\s*=\s*(\d+)", text, re.IGNORECASE)})
    has_windivert_error = "error opening filter" in low or "exit=34" in low or "windivert" in low and "error" in low
    has_desync_signal = any(
        kw in low for kw in ("tls_client_hello", "multisplit", "fakedsplit", "desync", "fake", "circular")
    )
    has_target_domain = (target_domain.lower() in low) if target_domain else True
    phys_matched = (expected_phys_ifidx in ifidx_matches) if expected_phys_ifidx is not None else bool(ifidx_matches)
    tun_matched = (tun_ifidx in ifidx_matches) if tun_ifidx is not None else False
    return {
        "text": text,
        "ifidx_matches": ifidx_matches,
        "has_windivert_error": has_windivert_error,
        "has_desync_signal": has_desync_signal,
        "has_target_domain": has_target_domain,
        "phys_matched": phys_matched,
        "tun_matched": tun_matched,
    }


def probe_https_target(url: str, timeout: float = 8.0) -> dict[str, Any]:
    """Probe an HTTPS URL via curl.exe and return status/output metrics."""
    res = subprocess.run(
        [
            "curl.exe",
            "-I",
            "-s",
            "-S",
            "--max-time",
            str(int(max(1, timeout))),
            "-o",
            "NUL",
            "-w",
            "%{http_code}",
            url,
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout + 4.0,
    )
    code_str = (res.stdout or "").strip()
    http_code = int(code_str) if code_str.isdigit() else 0
    return {
        "ok": res.returncode == 0 and 100 <= http_code < 600,
        "returncode": res.returncode,
        "http_code": http_code,
        "stderr": (res.stderr or "").strip(),
    }
