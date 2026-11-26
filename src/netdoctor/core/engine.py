"""Backend service layer for the netdoctor desktop GUI and headless controller."""

from __future__ import annotations

import asyncio
from collections import deque
import concurrent.futures
import ctypes
from ctypes import wintypes
import hashlib
import inspect
import ipaddress
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Coroutine, TypeVar

import psutil

from netdoctor import __version__
from netdoctor.clash_api import ClashApiClient
from netdoctor.classifier import classify_probes
from netdoctor.config_gen import (
    DEFAULT_BYPASS_PROCESSES,
    QUIC_HOSTLIST_DOMAINS,
    build_singbox_rulesets_payload,
    clear_vpn_dns_cache,
    detect_physical_egress_iface,
    detect_physical_egress_route,
    generate_singbox_config,
    generate_winws2_config,
    generate_xray_bridge_config,
    is_game_process,
    needs_xray_bridge,
    parse_process_list,
)
from netdoctor.core.bundles import (
    BUNDLE_MODES,
    CLOUD_GAMING_BEACONS,
    compile_bundle_rules,
    expand_running_bundle_processes,
    load_bundles,
    match_process_to_bundle,
)
from netdoctor.core.calibration import calibrate_network
from netdoctor.core.ruleset_server import DEFAULT_RULESET_PORT, RuleSetServer
from netdoctor.dynamics import promote_fallback_on_failure, run_canary_cycle
from netdoctor.models import Decision, Protocol, Strategy, VerdictClass, VpnNode
from netdoctor.orchestrators import (
    AI_GEOBLOCK_DOMAINS,
    ANTIGRAVITY_CRITICAL_DOMAINS,
    DNS_CATEGORIES,
    SERVICE_PRESETS,
    MasterRoutingOrchestrator,
    RealtimeConnectionMonitor,
    _INTERNAL_PROXY_PROCESSES,
    _is_external_ip,
    _node_has_healthy_connections,
    _parse_clash_conn_age_sec,
    build_unlocker_protection_context,
    is_dns_infra_domain,
)
from netdoctor.presets import (
    DEFAULT_EXTERNAL_ZAPRET_DIRS,
    DEFAULT_ZAPRET2_PRESETS_DIR,
    DEFAULT_ZDY_PRESETS_DIR,
    compile_zapret_preset,
    import_preset_from_file,
    import_presets_from_directory,
    list_all_zapret_presets,
    merge_winws2_base_preset,
    save_user_zapret_preset,
)
from netdoctor.probes import (
    DEFAULT_SERVICE_TEST_TARGETS,
    clear_network_fingerprint_cache,
    detect_bypass_active,
    detect_external_bypass_active,
    detect_network_fingerprint,
    infer_service_group,
    probe_domain_connectivity,
    run_domain_probes,
)
from netdoctor.selector import (
    DEFAULT_STRATEGIES,
    _diverse_fallbacks,
    _ordered_pool,
    evaluate_domains_live_batch,
    live_winws2_strategy_evaluator,
    load_targets_from_yaml,
    run_blockcheck2_for_domain,
    select_best_strategy,
)
from netdoctor.storage import Storage, normalize_domain_etld1
from netdoctor.supervisor import (
    ProcessSupervisor,
    _is_admin,
    fetch_all_bins,
    fetch_xray_binary,
    get_outdated_pinned_artifacts,
    inspect_supervisor_state,
    stop_persisted_supervisor,
    validate_singbox_config,
    validate_xray_config,
    verify_binaries,
)
from netdoctor.updater import (
    apply_app_update,
    check_for_updates,
    detect_install_mode,
    ensure_python_deps,
    find_missing_python_deps,
)
from netdoctor.tray import (
    _decode_process_output,
    get_autostart_status as tray_get_autostart_status,
    set_autostart_enabled as tray_set_autostart_enabled,
)
from netdoctor.vpn import (
    fetch_subscription,
    has_usable_vpn_nodes,
    is_auto_select_node,
    is_placeholder_node,
    refresh_all_subscriptions,
)

T = TypeVar("T")

MAX_PREVIEW_BYTES = 128 * 1024
DEFAULT_NETWORK_KEY = "AS12389:home:default"
LOG_FILENAMES: tuple[str, ...] = ("winws2.log", "sing-box.log", "tg-ws-proxy.log")


def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _safe_json_loads(raw: str | None, default: Any) -> Any:
    if not raw:
        return default() if callable(default) else default
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return default() if callable(default) else default


def _run_coro_sync(coro: Coroutine[Any, Any, T]) -> T:
    """Execute a coroutine synchronously, falling back to a worker thread if a loop is active."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


def _read_truncated_text(path: Path, max_bytes: int = MAX_PREVIEW_BYTES) -> str:
    if not path.is_file():
        return ""
    size = path.stat().st_size
    with path.open("rb") as f:
        raw = f.read(max_bytes)
    text = raw.decode("utf-8", errors="replace")
    if size > max_bytes:
        text += f"\n\n... [truncated: showing first {max_bytes // 1024} KB of {size // 1024} KB] ..."
    return text


def _read_tail_lines(path: Path, max_lines: int = 80) -> str:
    if max_lines <= 0 or not path.is_file():
        return ""
    chunk_size = 65536
    with path.open("rb") as f:
        f.seek(0, os.SEEK_END)
        pos = f.tell()
        if pos == 0:
            return ""
        chunks: list[bytes] = []
        newline_count = 0
        while pos > 0 and newline_count <= max_lines:
            read_len = min(chunk_size, pos)
            pos -= read_len
            f.seek(pos)
            block = f.read(read_len)
            chunks.append(block)
            newline_count += block.count(b"\n")
        data = b"".join(reversed(chunks))
    lines = data.decode("utf-8", errors="replace").splitlines()
    return "\n".join(lines[-max_lines:])


def _ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _build_gui_cli_args(
    *,
    db_path: str | Path = "netdoctor.db",
    configs_dir: str | Path = "configs",
    lists_dir: str | Path = "lists",
    logs_dir: str | Path = "logs",
    bin_dir: str | Path | None = None,
    replace_pid: int | None = None,
    auto_start: bool = False,
    minimized: bool = False,
    no_elevate: bool = False,
) -> list[str]:
    """Build resolved CLI flags passed to the GUI entry point."""
    args = [
        "--db",
        str(Path(db_path).resolve()),
        "--configs-dir",
        str(Path(configs_dir).resolve()),
        "--lists-dir",
        str(Path(lists_dir).resolve()),
        "--logs-dir",
        str(Path(logs_dir).resolve()),
    ]
    if bin_dir is not None:
        args.extend(["--bin-dir", str(Path(bin_dir).resolve())])
    if replace_pid is not None and replace_pid > 0:
        args.extend(["--replace-pid", str(int(replace_pid))])
    if auto_start:
        args.append("--auto-start")
    if minimized:
        args.append("--minimized")
    if no_elevate:
        args.append("--no-elevate")
    return args


def resolve_gui_launcher(python_exe: Path | None = None) -> tuple[str, list[str]]:
    """Resolve the preferred non-console Windows GUI executable and module prefix."""
    py_exe = (python_exe or Path(sys.executable)).resolve()
    gui_exe = py_exe.with_name("netdoctor-gui.exe")
    if gui_exe.is_file():
        return (str(gui_exe), [])
    pyw = py_exe.with_name("pythonw.exe")
    if pyw.is_file():
        return (str(pyw), ["-m", "netdoctor.gui"])
    return (str(py_exe), ["-m", "netdoctor.gui"])


def build_elevate_command(
    db_path: str | Path = "netdoctor.db",
    configs_dir: str | Path = "configs",
    lists_dir: str | Path = "lists",
    logs_dir: str | Path = "logs",
    working_dir: str | Path | None = None,
    bin_dir: str | Path | None = None,
    replace_pid: int | None = None,
    auto_start: bool = False,
) -> list[str]:
    """Build a PowerShell `Start-Process ... -Verb RunAs` command to relaunch the GUI elevated."""
    cwd = Path(working_dir).resolve() if working_dir is not None else Path.cwd().resolve()
    gui_args = [
        "-m",
        "netdoctor.cli",
        "gui",
        "--db",
        str(Path(db_path).resolve()),
        "--configs-dir",
        str(Path(configs_dir).resolve()),
        "--lists-dir",
        str(Path(lists_dir).resolve()),
        "--logs-dir",
        str(Path(logs_dir).resolve()),
    ]
    if bin_dir is not None:
        gui_args.extend(["--bin-dir", str(Path(bin_dir).resolve())])
    if replace_pid is not None and replace_pid > 0:
        gui_args.extend(["--replace-pid", str(int(replace_pid))])
    if auto_start:
        gui_args.append("--auto-start")

    py_exe = Path(sys.executable)
    pyw = py_exe.with_name("pythonw.exe")
    launcher = str(pyw if pyw.is_file() else py_exe)

    quoted_args = ", ".join(_ps_quote('"' + a.replace('"', '\\"') + '"') for a in gui_args)
    ps_script = (
        f"Start-Process -FilePath {_ps_quote(launcher)} "
        f"-ArgumentList @({quoted_args}) "
        f"-WorkingDirectory {_ps_quote(str(cwd))} "
        "-Verb RunAs"
    )
    return ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-Command", ps_script]


def elevate_gui(
    db_path: str | Path = "netdoctor.db",
    configs_dir: str | Path = "configs",
    lists_dir: str | Path = "lists",
    logs_dir: str | Path = "logs",
    working_dir: str | Path | None = None,
    bin_dir: str | Path | None = None,
    replace_pid: int | None = None,
    auto_start: bool = False,
    minimized: bool = False,
) -> dict[str, Any]:
    """Launch an elevated GUI instance natively via Win32 ShellExecuteW('runas') without a console."""
    cwd = Path(working_dir).resolve() if working_dir is not None else Path.cwd().resolve()
    if sys.platform == "win32":
        launcher, prefix_args = resolve_gui_launcher()
        all_args = [
            *prefix_args,
            *_build_gui_cli_args(
                db_path=db_path,
                configs_dir=configs_dir,
                lists_dir=lists_dir,
                logs_dir=logs_dir,
                bin_dir=bin_dir,
                replace_pid=replace_pid,
                auto_start=auto_start,
                minimized=minimized,
            ),
        ]
        params = subprocess.list2cmdline(all_args)
        try:
            shell32 = ctypes.WinDLL("shell32", use_last_error=True)
            shell32.ShellExecuteW.argtypes = [
                wintypes.HWND,
                wintypes.LPCWSTR,
                wintypes.LPCWSTR,
                wintypes.LPCWSTR,
                wintypes.LPCWSTR,
                ctypes.c_int,
            ]
            shell32.ShellExecuteW.restype = ctypes.c_void_p
            rc_ptr = shell32.ShellExecuteW(
                None,
                "runas",
                launcher,
                params,
                str(cwd),
                0 if minimized else 1,
            )
            raw_rc = getattr(rc_ptr, "value", rc_ptr)
            rc = int(raw_rc or 0)
            if rc > 32:
                return {
                    "ok": True,
                    "launched": True,
                    "pid": None,
                    "launcher": launcher,
                    "command": [launcher, *all_args],
                }
            err = ctypes.get_last_error()
            cancelled = rc == 5 or err == 1223
            return {
                "ok": False,
                "launched": False,
                "cancelled": cancelled,
                "error": (
                    "Запрос прав администратора отменён пользователем (UAC)"
                    if cancelled
                    else f"ShellExecuteW failed (code={rc}, winerr={err})"
                ),
                "command": [launcher, *all_args],
            }
        except Exception as exc:  # noqa: BLE001
            return {
                "ok": False,
                "launched": False,
                "cancelled": False,
                "error": str(exc),
                "command": [launcher, *all_args],
            }

    cmd = build_elevate_command(
        db_path=db_path,
        configs_dir=configs_dir,
        lists_dir=lists_dir,
        logs_dir=logs_dir,
        working_dir=cwd,
        bin_dir=bin_dir,
        replace_pid=replace_pid,
        auto_start=auto_start,
    )
    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return {"ok": True, "launched": True, "pid": proc.pid, "command": cmd}
    except OSError as exc:
        return {"ok": False, "launched": False, "error": str(exc), "command": cmd}


def launch_gui_detached(
    db_path: str | Path = "netdoctor.db",
    configs_dir: str | Path = "configs",
    lists_dir: str | Path = "lists",
    logs_dir: str | Path = "logs",
    working_dir: str | Path | None = None,
    bin_dir: str | Path | None = None,
    replace_pid: int | None = None,
    auto_start: bool = False,
    minimized: bool = False,
    no_elevate: bool = False,
) -> dict[str, Any]:
    """Spawn the non-console GUI process detached from the caller's console."""
    cwd = Path(working_dir).resolve() if working_dir is not None else Path.cwd().resolve()
    launcher, prefix_args = resolve_gui_launcher()
    cmd = [
        launcher,
        *prefix_args,
        *_build_gui_cli_args(
            db_path=db_path,
            configs_dir=configs_dir,
            lists_dir=lists_dir,
            logs_dir=logs_dir,
            bin_dir=bin_dir,
            replace_pid=replace_pid,
            auto_start=auto_start,
            minimized=minimized,
            no_elevate=no_elevate,
        ),
    ]
    flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(cwd),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            creationflags=flags,
        )
        return {"ok": True, "launched": True, "pid": proc.pid, "command": cmd}
    except OSError as exc:
        return {"ok": False, "launched": False, "error": str(exc), "command": cmd}


_WEB_KEEPALIVE_PORTS: frozenset[int] = frozenset({53, 80, 443, 8080, 8443})
_ACTIVE_FLOW_IDLE_SEC: float = 15.0
_ACTIVE_SESSION_GRACE_SEC: float = 60.0
_LOCAL_UDP_NOISE_PORTS: frozenset[int] = frozenset({137, 138, 1900, 5353, 5355})
_INFRA_VPN_PROC_EXCLUSIONS: frozenset[str] = frozenset(
    {p.lower() for p in DEFAULT_BYPASS_PROCESSES} | {"sing-box", "sing-box.exe"}
)


def _probe_socks5_udp_sync(proxy_host: str = "127.0.0.1", proxy_port: int = 2081, timeout: float = 1.5) -> bool:
    """Verify real UDP forwarding via sing-box mixed/SOCKS5 UDP ASSOCIATE + DNS query to 1.1.1.1:53."""
    import struct

    tcp_sock: socket.socket | None = None
    udp_sock: socket.socket | None = None
    try:
        tcp_sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
        tcp_sock.settimeout(timeout)
        tcp_sock.sendall(b"\x05\x01\x00")
        greeting = tcp_sock.recv(2)
        if len(greeting) < 2 or greeting[0] != 5 or greeting[1] != 0:
            return False
        tcp_sock.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        hdr = tcp_sock.recv(4)
        if len(hdr) < 4 or hdr[1] != 0:
            return False
        atyp = hdr[3]
        if atyp == 1:
            relay_ip = socket.inet_ntoa(tcp_sock.recv(4))
        elif atyp == 4:
            relay_ip = socket.inet_ntop(socket.AF_INET6, tcp_sock.recv(16))
        elif atyp == 3:
            alen = tcp_sock.recv(1)[0]
            relay_ip = tcp_sock.recv(alen).decode("ascii", errors="ignore")
        else:
            return False
        relay_port = struct.unpack("!H", tcp_sock.recv(2))[0]
        if relay_ip in ("0.0.0.0", "::", "") or relay_port <= 0:
            relay_ip = proxy_host

        dns_q = (
            b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x03one\x03one\x03one\x03one\x00\x00\x01\x00\x01"
        )
        socks_udp_hdr = b"\x00\x00\x00\x01" + socket.inet_aton("1.1.1.1") + struct.pack("!H", 53)
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.settimeout(timeout)
        udp_sock.sendto(socks_udp_hdr + dns_q, (relay_ip, relay_port))
        resp, _ = udp_sock.recvfrom(512)
        return len(resp) > len(socks_udp_hdr) + 12 and resp[len(socks_udp_hdr) : len(socks_udp_hdr) + 2] == b"\x12\x34"
    except OSError:
        return False
    finally:
        for s in (udp_sock, tcp_sock):
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass


def _is_tcp_port_open(port: int, host: str = "127.0.0.1", timeout: float = 0.25) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _sanitize_vpn_processes(procs: list[str]) -> list[str]:
    cleaned: list[str] = []
    seen: set[str] = set()
    for p in procs:
        name = Path(str(p or "").strip().replace("\\", "/")).name.strip()
        low = name.lower()
        if name and low not in _INFRA_VPN_PROC_EXCLUSIONS and low not in seen:
            seen.add(low)
            cleaned.append(name)
    return cleaned


class NetdoctorEngine:
    """Thread-safe core engine bridging netdoctor diagnostics, storage, configs, VPNs, and supervised processes."""

    def __init__(
        self,
        db_path: str | Path = "netdoctor.db",
        configs_dir: str | Path = "configs",
        lists_dir: str | Path = "lists",
        logs_dir: str | Path = "logs",
        bin_dir: str | Path = "bin",
        hosts_path: str | Path | None = None,
        clash_api_addr: str = "127.0.0.1:19090",
        presets_dir: str | Path | None = None,
        zdy_presets_dir: str | Path | None = None,
        ruleset_port: int = DEFAULT_RULESET_PORT,
        bundles_path: str | Path | None = None,
    ) -> None:
        self.db_path = Path(db_path)
        self.configs_dir = Path(configs_dir)
        self.lists_dir = Path(lists_dir)
        self.logs_dir = Path(logs_dir)
        self.bin_dir = Path(bin_dir)
        self.hosts_path = Path(hosts_path) if hosts_path is not None else None
        self.presets_dir = Path(presets_dir) if presets_dir is not None else DEFAULT_ZAPRET2_PRESETS_DIR
        self.zdy_presets_dir = Path(zdy_presets_dir) if zdy_presets_dir is not None else DEFAULT_ZDY_PRESETS_DIR
        self.bundles_path = Path(bundles_path) if bundles_path is not None else (self.configs_dir / "bundles.yaml")
        self._supervisor: ProcessSupervisor | None = None
        self._lock = threading.RLock()
        self._deps_lock = threading.Lock()
        self.orchestrator = MasterRoutingOrchestrator()
        self.clash_api = ClashApiClient(
            controller_addr=clash_api_addr,
            secret=secrets.token_urlsafe(24),
        )
        self.ruleset_server = RuleSetServer(preferred_port=ruleset_port)
        self._shutting_down: bool = False
        self._tun_interface_name: str = "netdoctor-tun"
        self._last_rulesets_payload_hash: str = ""
        self._last_pass_domains_sig: tuple[str, ...] = ()
        self._last_game_udp_dpi: bool = False
        self._cached_dns_health: dict[str, Any] = {}
        self._cached_dns_pings: dict[str, dict[str, Any]] = {}
        self._cached_vpn_health: dict[str, Any] = {}
        self._cached_vpn_nodes: dict[str, dict[str, Any]] = {}
        # Watchdog & safe hot-reload tracking (prevents winws2 WinDivert reload storms & silent crashes)
        self._last_winws2_hash: str = ""
        self._last_winws2_reload_ts: float = 0.0
        self._last_singbox_hash: str = ""
        self._last_singbox_reload_ts: float = 0.0
        self._last_xray_hash: str = ""
        self._pending_winws2_reload: bool = False
        self._pending_singbox_reload: bool = False
        self._clash_conn_traffic: dict[str, tuple[int, float]] = {}
        self._last_stateful_session_ts: float = 0.0
        self._desired_running: bool = False
        self._stopping: bool = False
        self._watchdog_restarts: int = 0
        self._watchdog_timestamps: deque[float] = deque(maxlen=20)
        self._watchdog_next_retry_ts: float = 0.0
        self._last_crash_at: str = ""
        self._last_crash_reason: str = ""
        self._last_preset_error: str = ""
        self._last_gateway_ip: str = ""
        self._gw_change_pending: str = ""
        self._service_retry_ts: dict[str, float] = {}
        self._service_fail_counts: dict[str, int] = {}
        self._strategies_seeded_sig: tuple[Any, ...] | None = None
        self._last_singbox_check: tuple[str, int] | None = None
        self._last_xray_check: tuple[str, int] | None = None
        self._last_xray_config_hash: str = ""
        self._sub_refresh_in_progress: bool = False
        self._last_vpn_reconcile_ts: float = 0.0
        self._vpn_reconciling: bool = False

    @staticmethod
    def _winws2_args_hash(winws_args: list[str]) -> str:
        hasher = hashlib.sha256("\n".join(winws_args).encode("utf-8", errors="ignore"))
        list_prefixes = ("--hostlist=", "--hostlist-exclude=", "--ipset=", "--ipset-exclude=")
        for arg in winws_args:
            for prefix in list_prefixes:
                if arg.startswith(prefix):
                    fpath = Path(arg[len(prefix) :].strip().strip('"'))
                    try:
                        if fpath.is_file():
                            hasher.update(b"\0")
                            hasher.update(arg.encode("utf-8", errors="ignore"))
                            hasher.update(b"\0")
                            hasher.update(fpath.read_bytes())
                    except OSError:
                        pass
                    break
        return hasher.hexdigest()

    def _resolve_active_zapret_preset(
        self,
        storage: Storage,
    ) -> tuple[str, str, dict[str, Any] | None]:
        pid = storage.get_setting("active_zapret_preset_id", "auto").strip()
        if not pid or pid == "auto":
            return "auto", "Авто-оркестратор (подбор по доменам)", None
        all_presets = list_all_zapret_presets(
            storage,
            presets_dir=self.presets_dir,
            zdy_dir=self.zdy_presets_dir,
        )
        match = next((p for p in all_presets if p["id"] == pid), None)
        if match is None:
            return "auto", "Авто-оркестратор (подбор по доменам)", None
        return str(match["id"]), str(match["name"]), match

    def _resolve_base_zapret_preset(
        self,
        storage: Storage,
    ) -> tuple[str, str, dict[str, Any] | None]:
        pid = storage.get_setting("base_zapret_preset_id", "").strip()
        if not pid or pid.lower() == "none":
            return "", "", None
        all_presets = list_all_zapret_presets(
            storage,
            presets_dir=self.presets_dir,
            zdy_dir=self.zdy_presets_dir,
        )
        match = next((p for p in all_presets if p["id"] == pid), None)
        if match is None:
            return "", "", None
        return str(match["id"]), str(match["name"]), match

    def _seed_default_strategies(self, storage: Storage) -> None:
        db_key = str(self.db_path)
        db_sig: tuple[Any, ...] | None = None
        if db_key != ":memory:":
            try:
                st = self.db_path.stat()
                db_sig = (str(self.db_path.resolve()), int(st.st_dev), int(st.st_ino), int(st.st_ctime_ns))
            except OSError:
                db_sig = None
        with self._lock:
            if db_sig is not None and self._strategies_seeded_sig == db_sig:
                return
        existing_args = {
            str(r[0]): str(r[1])
            for r in storage.conn.execute("SELECT id, args_json FROM strategies").fetchall()
        }
        to_upsert = [
            s for s in DEFAULT_STRATEGIES if existing_args.get(s.id) != json.dumps(s.args_template)
        ]
        if to_upsert:
            storage.upsert_strategies(to_upsert)
        if db_sig is not None:
            with self._lock:
                self._strategies_seeded_sig = db_sig

    def _resolve_network_info(
        self,
        storage: Storage,
        net_key: str | None = None,
    ) -> tuple[str, int, str, str]:
        if net_key is not None:
            row = storage.conn.execute(
                "SELECT network_key, asn, kind, isp FROM networks WHERE network_key = ?",
                (net_key,),
            ).fetchone()
            if row:
                return row["network_key"], int(row["asn"]), str(row["kind"]), str(row["isp"] or "")
            return net_key, 0, "home", ""

        row = storage.conn.execute(
            "SELECT network_key, asn, kind, isp FROM networks ORDER BY last_seen DESC LIMIT 1"
        ).fetchone()
        if row:
            return row["network_key"], int(row["asn"]), str(row["kind"]), str(row["isp"] or "")

        dec_row = storage.conn.execute(
            "SELECT network_key FROM decisions ORDER BY updated_at DESC LIMIT 1"
        ).fetchone()
        if dec_row:
            return str(dec_row["network_key"]), 12389, "home", ""

        return DEFAULT_NETWORK_KEY, 12389, "home", ""

    def _query_domain_rows(self, storage: Storage, net_key: str) -> list[dict[str, Any]]:
        self._seed_default_strategies(storage)
        rows = storage.conn.execute(
            """
            SELECT
                d.network_key,
                d.domain,
                d.protocol,
                d.layer,
                d.strategy_id,
                d.fallback_json,
                d.ttfb_ms,
                d.throughput_kbps,
                d.consecutive_fails,
                d.status,
                d.updated_at,
                d.ttl_sec,
                d.pinned,
                v.verdicts_json,
                v.confidence,
                v.probes_json,
                s.args_json,
                s.description AS strategy_description,
                s.tier
            FROM decisions d
            LEFT JOIN verdicts v
                ON v.network_key = d.network_key
                AND v.domain = d.domain
                AND v.protocol = d.protocol
            LEFT JOIN strategies s
                ON s.id = d.strategy_id
            WHERE d.network_key = ?
            ORDER BY d.domain ASC, d.protocol ASC
            """,
            (net_key,),
        ).fetchall()

        dns_map = {s["id"]: s for s in self.orchestrator.dns.get_all_dns_servers(storage)}
        test_stats = storage.get_domain_test_stats(net_key, window=10)

        result: list[dict[str, Any]] = []
        for r in rows:
            sid = r["strategy_id"]
            desc = str(r["strategy_description"] or "")
            tier = int(r["tier"]) if r["tier"] is not None else None
            if str(r["layer"]) == "dns" and isinstance(sid, str) and sid.startswith("dns:"):
                dns_id = sid.split(":", 1)[1]
                srv = dns_map.get(dns_id)
                if srv:
                    desc = f"Персональный DNS: {srv['name']} ({srv['ip']}) — {srv.get('description', '')}"
                else:
                    desc = f"Персональный DNS: {dns_id}"
                tier = 1
            dom_low = str(r["domain"]).lower()
            ts = test_stats.get(dom_low)
            result.append(
                {
                    "network_key": str(r["network_key"]),
                    "domain": str(r["domain"]),
                    "protocol": str(r["protocol"]),
                    "layer": str(r["layer"]),
                    "strategy_id": sid,
                    "fallback_strategies": list(_safe_json_loads(r["fallback_json"], list)),
                    "ttfb_ms": r["ttfb_ms"],
                    "throughput_kbps": r["throughput_kbps"],
                    "consecutive_fails": int(r["consecutive_fails"]),
                    "status": str(r["status"]),
                    "updated_at": str(r["updated_at"]),
                    "ttl_sec": int(r["ttl_sec"]),
                    "pinned": bool(r["pinned"]),
                    "verdicts": list(_safe_json_loads(r["verdicts_json"], list)),
                    "confidence": float(r["confidence"]) if r["confidence"] is not None else 0.0,
                    "probes": dict(_safe_json_loads(r["probes_json"], dict)),
                    "strategy_args": list(_safe_json_loads(r["args_json"], list)),
                    "strategy_description": desc,
                    "tier": tier,
                    "test_total": int(ts["total_runs"]) if ts else 0,
                    "test_passed": int(ts["passed_runs"]) if ts else 0,
                    "success_rate": ts["success_rate"] if ts else None,
                    "last_test_ok": ts["last_ok"] if ts else None,
                    "last_test_latency_ms": ts["last_latency_ms"] if ts else None,
                    "last_test_stage": ts["last_stage"] if ts else "",
                    "last_test_error": ts["last_error"] if ts else "",
                    "last_tested_at": ts["last_tested_at"] if ts else "",
                    "recent_tests": list(ts["recent"]) if ts else [],
                }
            )
        return result

    def _collect_processes_state(self) -> dict[str, dict[str, Any]]:
        processes = inspect_supervisor_state(logs_dir=self.logs_dir)
        if self._supervisor is not None:
            for name, info in self._supervisor.status().items():
                running = bool(info.get("running"))
                processes[name] = {
                    "pid": info.get("pid"),
                    "running": running,
                    "status": "running" if running else "stopped",
                    "exit_code": info.get("exit_code"),
                }
        return processes

    def get_status_snapshot(self) -> dict[str, Any]:
        """Return full system, network, decisions, domain rows, VPN nodes, and process status snapshot."""
        storage = Storage(self.db_path)
        try:
            with self._lock:
                self._seed_default_strategies(storage)
            net_key, net_asn, net_kind, net_isp = self._resolve_network_info(storage)
            decisions = storage.get_decisions(net_key, active_only=True)
            domain_rows = self._query_domain_rows(storage, net_key)
            vpn_nodes = storage.get_all_subscription_nodes()
            vpn_health_map = storage.get_vpn_node_health_map()
            vpn_policy = storage.get_vpn_selection_policy()
            active_dns = self.orchestrator.dns.get_active_dns(storage)
            base_dns = self.orchestrator.dns.get_base_dns(storage, net_key=net_key)
            all_dns = self.orchestrator.dns.get_all_dns_servers(storage)
            game_filter = storage.get_setting("game_filter", "0") == "1"
            auto_start_protection = storage.get_setting("auto_start_protection", "0") == "1"
            auto_heal_enabled = storage.get_setting("auto_heal_enabled", "1") != "0"
            byedpi_fallback = storage.get_setting("byedpi_fallback", "0") == "1"
            winws2_debug_log = storage.get_setting("winws2_debug_log", "0") == "1"
            vpn_processes = self.get_vpn_processes(storage, net_key=net_key)
            stack_mode = storage.get_setting("stack_mode", "hybrid").strip() or "hybrid"
            if stack_mode not in ("hybrid", "dpi_only"):
                stack_mode = "hybrid"
            tun_stack = storage.get_setting("tun_stack", "mixed").strip() or "mixed"
            if tun_stack not in ("gvisor", "mixed", "system"):
                tun_stack = "mixed"
            expert_mode = storage.get_setting("expert_mode", "0") == "1"
            telegram_mode = self.get_telegram_mode(storage)
            network_profile = storage.get_network_profile(net_key)
            bundles_status = self.get_bundles_status(storage=storage, net_key=net_key)
            tg_secret = self.get_tg_ws_secret(storage)
            unlocker_guard = build_unlocker_protection_context(storage=storage, hosts_path=self.hosts_path)
            all_zapret_presets = list_all_zapret_presets(
                storage,
                presets_dir=self.presets_dir,
                zdy_dir=self.zdy_presets_dir,
            )
            raw_preset_id = storage.get_setting("active_zapret_preset_id", "auto").strip()
            preset_match = next((p for p in all_zapret_presets if p["id"] == raw_preset_id), None) if raw_preset_id and raw_preset_id != "auto" else None
            if preset_match is not None:
                active_preset_id = str(preset_match["id"])
                active_preset_name = str(preset_match["name"])
            else:
                active_preset_id = "auto"
                active_preset_name = "Авто-оркестратор (подбор по доменам)"
            raw_base_id = storage.get_setting("base_zapret_preset_id", "").strip()
            base_match = (
                next((p for p in all_zapret_presets if p["id"] == raw_base_id), None)
                if raw_base_id and raw_base_id.lower() != "none"
                else None
            )
            base_preset_id = str(base_match["id"]) if base_match is not None else ""
            base_preset_name = str(base_match["name"]) if base_match is not None else ""
            test_summary = storage.get_overall_test_summary(net_key, window=10)
            desired_setting = storage.get_setting("stack_desired_running", "0") == "1"
        finally:
            storage.close()

        processes = self._collect_processes_state()
        recent_conns = self.orchestrator.monitor.get_recent_connections(net_key, max_age_sec=2.0)
        if getattr(self.get_orchestrators_summary, "__func__", None) is NetdoctorEngine.get_orchestrators_summary:
            orchestrators = self.get_orchestrators_summary(
                probe_live=False,
                processes=processes,
                connections=recent_conns,
            )
        else:
            orchestrators = self.get_orchestrators_summary(probe_live=False, processes=processes)
        enriched_vpn_nodes = self._merge_vpn_ping_cache(
            vpn_nodes,
            health_map=vpn_health_map,
            policy=vpn_policy,
            active_node_tag=(orchestrators.get("vpn") or {}).get("best_node"),
        )
        dns_alert: str | None = None
        sb_tail = _read_tail_lines(self.logs_dir / "sing-box.log", max_lines=60)
        m_doh = re.search(
            r"cannot validate certificate for ([0-9a-fA-F:.]+) because it doesn't contain any IP SANs",
            sb_tail,
            re.IGNORECASE,
        )
        if m_doh:
            bad_ip = m_doh.group(1)
            if str(active_dns.get("ip") or "") == bad_ip or str(active_dns.get("id") or "") == "zapret_dns":
                dns_alert = (
                    f"DoH-сервер {bad_ip} ({active_dns.get('name', 'DNS')}) отклоняет TLS-сертификат "
                    f"(нет IP SAN) — сайты не резолвятся. Переключитесь на Comss DNS или Cloudflare."
                )
        elif str(active_dns.get("id") or "") == "zapret_dns":
            dns_alert = (
                "Выбранный Zapret DNS (188.114.97.1) использует сертификат без IP SAN и ломает DoH в sing-box. "
                "Переключитесь на Comss DNS или Cloudflare."
            )

        with self._lock:
            watchdog_state = {
                "desired_running": bool(self._desired_running or desired_setting),
                "restarts_count": int(self._watchdog_restarts),
                "last_crash_at": self._last_crash_at,
                "last_crash_reason": self._last_crash_reason,
                "backoff_active": time.monotonic() < self._watchdog_next_retry_ts,
            }
            preset_compile_error = self._last_preset_error
            pending_vpn_node = getattr(self.orchestrator.vpn, "_pending_optimal_node", None)
            pending_changes = {
                "winws2": bool(self._pending_winws2_reload),
                "singbox": bool(self._pending_singbox_reload),
                "vpn_node": pending_vpn_node,
                "count": int(bool(self._pending_winws2_reload))
                + int(bool(self._pending_singbox_reload))
                + int(bool(pending_vpn_node)),
            }

        return {
            "network_key": net_key,
            "network_asn": net_asn,
            "network_kind": net_kind,
            "network_isp": net_isp,
            "is_admin": _is_admin(),
            "bypass_active": detect_bypass_active(),
            "external_bypass_active": detect_external_bypass_active(self.logs_dir),
            "decisions_count": len(decisions),
            "decisions": [d.model_dump(mode="json") for d in decisions],
            "domain_rows": domain_rows,
            "vpn_nodes_count": len(enriched_vpn_nodes),
            "vpn_nodes": enriched_vpn_nodes,
            "vpn_policy": vpn_policy,
            "processes": processes,
            "running": any(bool(p.get("running")) for p in processes.values()),
            "orchestrators": orchestrators,
            "live_connections_count": orchestrators["realtime"]["active_connections"],
            "active_dns": self._merge_dns_ping_cache([active_dns])[0],
            "active_dns_id": active_dns["id"],
            "base_dns": self._merge_dns_ping_cache([base_dns])[0] if base_dns else None,
            "base_dns_id": str(base_dns["id"]) if base_dns else "",
            "dns_alert": dns_alert,
            "dns_servers_count": len(all_dns),
            "game_filter": game_filter,
            "auto_start_protection": auto_start_protection,
            "auto_heal_enabled": auto_heal_enabled,
            "vpn_processes": ", ".join(vpn_processes),
            "byedpi_fallback": byedpi_fallback,
            "winws2_debug_log": winws2_debug_log,
            "stack_mode": stack_mode,
            "tun_stack": tun_stack,
            "telegram_proxy": self.get_telegram_proxy_info(processes=processes, secret=tg_secret),
            "unlocker_guard": unlocker_guard,
            "active_preset_id": active_preset_id,
            "active_preset_name": active_preset_name,
            "base_preset_id": base_preset_id,
            "base_preset_name": base_preset_name,
            "zapret_mode": "preset" if active_preset_id != "auto" else "auto",
            "zapret_presets_count": len(all_zapret_presets),
            "preset_compile_error": preset_compile_error,
            "pending_changes": pending_changes,
            "test_summary": test_summary,
            "watchdog": watchdog_state,
            "expert_mode": expert_mode,
            "telegram_mode": telegram_mode,
            "network_profile": network_profile,
            "bundles": bundles_status,
            "pending_bundle_alerts": self.get_pending_bundle_alerts(),
            "ruleset_server_url": self.ruleset_server.base_url if self.ruleset_server.is_running else "",
        }

    def _merge_dns_ping_cache(self, servers: list[dict[str, Any]]) -> list[dict[str, Any]]:
        with self._lock:
            cache = dict(self._cached_dns_pings)
        if not cache:
            return [dict(s) for s in servers]
        merged: list[dict[str, Any]] = []
        for s in servers:
            item = dict(s)
            cached = cache.get(str(s.get("id") or ""))
            if cached:
                item["ping_ms"] = cached.get("ping_ms")
                item["alive"] = cached.get("alive")
                item["probe_port"] = cached.get("probe_port")
            merged.append(item)
        return merged

    def _merge_vpn_ping_cache(
        self,
        nodes: list[dict[str, Any]],
        health_map: dict[str, dict[str, Any]] | None = None,
        policy: dict[str, Any] | None = None,
        active_node_tag: str | None = None,
    ) -> list[dict[str, Any]]:
        with self._lock:
            cache = dict(self._cached_vpn_nodes)
        hmap = health_map or {}
        pref_node = str((policy or {}).get("priority_node") or "").strip()
        active_clean = str(active_node_tag or "").strip()
        merged: list[dict[str, Any]] = []
        for n in nodes:
            tag = str(n.get("tag") or "").strip()
            item = dict(n)
            item["is_placeholder"] = is_placeholder_node(item)
            item["is_builtin_auto"] = is_auto_select_node(item)
            try:
                prio = int(item.get("priority") if item.get("priority") is not None else 100)
            except (TypeError, ValueError):
                prio = 100
            item["priority"] = prio
            item["enabled"] = bool(item.get("enabled", True))
            item["is_priority"] = bool((pref_node and tag == pref_node) or prio < 100)
            item["is_active"] = bool(active_clean and tag == active_clean)
            h = hmap.get(tag)
            if h:
                item["cb_state"] = h.get("cb_state", "closed")
                item["consecutive_fails"] = h.get("consecutive_fails", 0)
                item["protocol_ok"] = bool(h.get("protocol_ok", 1))
                if h.get("ewma_rtt_ms") is not None and "ping_ms" not in item:
                    item["ping_ms"] = h.get("ewma_rtt_ms")
            cached = cache.get(tag)
            if cached:
                item["ping_ms"] = cached.get("ping_ms")
                item["alive"] = cached.get("alive")
                item["probe_result"] = cached.get("probe_result")
                if "tunnel_verified" in cached:
                    item["tunnel_verified"] = cached["tunnel_verified"]
                if "cb_state" in cached:
                    item["cb_state"] = cached["cb_state"]
                if "protocol_ok" in cached:
                    item["protocol_ok"] = cached["protocol_ok"]
            merged.append(item)
        return merged

    def get_orchestrators_summary(
        self,
        probe_live: bool = False,
        processes: dict[str, Any] | None = None,
        connections: list[dict[str, Any]] | None = None,
        *,
        use_clash: bool = True,
    ) -> dict[str, Any]:
        """Return telemetry across all 4 orchestrator layers (DNS, DPI, VPN, Live Radar)."""
        proc_state = processes if processes is not None else self._collect_processes_state()
        sb_running = bool((proc_state.get("sing-box") or {}).get("running"))
        clash_client = self.clash_api if (sb_running and use_clash) else None
        storage = Storage(self.db_path)
        try:
            with self._lock:
                self._seed_default_strategies(storage)
            net_key, _, _, _ = self._resolve_network_info(storage)
            report = _run_coro_sync(
                self.orchestrator.get_full_orchestrator_report(
                    storage=storage,
                    logs_dir=self.logs_dir,
                    network_key=net_key,
                    processes=proc_state,
                    probe_live=probe_live,
                    connections=connections,
                    hosts_path=self.hosts_path,
                    clash_client=clash_client,
                )
            )
        finally:
            storage.close()

        with self._lock:
            if probe_live:
                self._cached_dns_health = {
                    k: report["dns"].get(k)
                    for k in ("status", "best_server", "best_name", "best_rtt_ms", "healthy_count", "total_count")
                    if k in report["dns"]
                }
                self._cached_vpn_health = {
                    k: report["vpn"].get(k)
                    for k in ("alive_count", "best_node", "best_ping_ms", "tg_proxy_alive")
                    if k in report["vpn"]
                }
                for n in report["vpn"].get("nodes") or []:
                    self._cached_vpn_nodes[str(n.get("tag") or "")] = n
            else:
                if self._cached_dns_health:
                    report["dns"].update(self._cached_dns_health)
                if self._cached_vpn_health:
                    for k, v in self._cached_vpn_health.items():
                        if v is None:
                            continue
                        if k == "best_node" and report["vpn"].get("running") and report["vpn"].get("best_node"):
                            continue
                        if k == "best_ping_ms" and report["vpn"].get("running"):
                            if report["vpn"].get("best_ping_ms") is not None:
                                continue
                            if (
                                report["vpn"].get("best_node")
                                and report["vpn"].get("best_node") != self._cached_vpn_health.get("best_node")
                            ):
                                continue
                        report["vpn"][k] = v
        return report

    def scan_live_connections(self) -> dict[str, Any]:
        """Scan active outbound host sockets and match them to domains and strategies."""
        proc_state = self._collect_processes_state()
        clash_client = self.clash_api if bool((proc_state.get("sing-box") or {}).get("running")) else None
        storage = Storage(self.db_path)
        try:
            net_key, _, _, _ = self._resolve_network_info(storage)
            connections = self.orchestrator.monitor.scan_active_connections(
                storage=storage,
                logs_dir=self.logs_dir,
                net_key=net_key,
                hosts_path=self.hosts_path,
                clash_client=clash_client,
            )
        finally:
            storage.close()
        with self.orchestrator.monitor._lock:
            events = list(self.orchestrator.monitor.recent_events)
        return {
            "network_key": net_key,
            "connections": connections,
            "events": events,
        }

    def run_realtime_auto_heal_tick(
        self,
        max_domains_per_tick: int = 2,
        *,
        require_running: bool = False,
    ) -> dict[str, Any]:
        """Inspect live connections/rotations and automatically pick working strategies for failing hosts."""
        if require_running:
            procs = self._collect_processes_state()
            stack_active = bool(
                (procs.get("winws2") or {}).get("running")
                or (procs.get("sing-box") or {}).get("running")
            )
            if not stack_active:
                scan = self.scan_live_connections()
                scan["healed"] = []
                scan["stack_stopped"] = True
                return scan
        return _run_coro_sync(
            self.orchestrator.monitor.auto_heal_connections(
                self,
                max_domains_per_tick=max_domains_per_tick,
            )
        )

    def probe_all_vpn_nodes(self) -> list[dict[str, Any]]:
        """Measure TCP + in-tunnel latency (when Clash API active) across VPN nodes, persist health, and steer away from dead/stale nodes."""
        proc_state = self._collect_processes_state()
        clash_client = self.clash_api if bool((proc_state.get("sing-box") or {}).get("running")) else None
        storage = Storage(self.db_path)
        try:
            nodes = storage.get_all_subscription_nodes()
            health = _run_coro_sync(
                self.orchestrator.vpn.check_health(nodes, clash_client=clash_client, storage=storage)
            )
            probed = list(health.get("nodes") or [])
            if clash_client is not None and probed:
                proxies = clash_client.get_proxies_sync()
                sel_now, active_leaf, _ = ClashApiClient.resolve_active_proxy(proxies, "vpn-select")
                policy = storage.get_vpn_selection_policy()
                probed_by_tag = {
                    str(n.get("tag") or "").strip(): n
                    for n in probed
                    if str(n.get("tag") or "").strip()
                }
                active_entry = probed_by_tag.get(active_leaf or "")
                active_alive = bool(
                    active_entry
                    and active_entry.get("alive")
                    and not active_entry.get("is_placeholder")
                    and active_entry.get("enabled", True)
                )
                alive_real = [
                    n
                    for n in probed
                    if n.get("alive") and not n.get("is_placeholder") and n.get("enabled", True)
                ]
                if alive_real:
                    top_cand = alive_real[0]
                    top_tag = str(top_cand.get("tag") or "").strip()
                    should_switch = (not active_alive) or (sel_now == "direct")
                    if policy["mode"] == "priority" and top_tag and active_leaf != top_tag:
                        should_switch = True
                    if should_switch and top_tag and top_tag in proxies:
                        clash_client.select_outbound_sync("vpn-select", top_tag)
                        if (
                            not active_alive
                            and active_leaf
                            and active_leaf != top_tag
                            and active_leaf not in ("vpn-auto", "direct")
                        ):
                            has_healthy_conns = False
                            try:
                                raw_c = (clash_client.get_connections_sync() or {}).get("connections") or []
                                has_healthy_conns = _node_has_healthy_connections(
                                    [c for c in raw_c if isinstance(c, dict)],
                                    active_leaf,
                                )
                            except Exception:  # noqa: BLE001
                                has_healthy_conns = False
                            is_quar = bool(active_entry and active_entry.get("cb_state") == "open")
                            if not has_healthy_conns or is_quar:
                                clash_client.close_connections_by_node_sync(active_leaf)
                        self.orchestrator.vpn._active_node_tag = top_tag
                        self.orchestrator.vpn._last_switch_ts = time.monotonic()
                        health["best_node"] = top_tag
                        health["best_ping_ms"] = top_cand.get("ping_ms")
        finally:
            storage.close()
        with self._lock:
            self._cached_vpn_nodes = {str(n.get("tag") or "").strip(): n for n in probed if str(n.get("tag") or "").strip()}
            self._cached_vpn_health = {
                "alive_count": health.get("alive_count"),
                "best_node": health.get("best_node"),
                "best_ping_ms": health.get("best_ping_ms"),
                "tg_proxy_alive": health.get("tg_proxy_alive"),
            }
        return probed

    def run_calibration_sync(
        self,
        *,
        timeout: float = 2.5,
        progress_cb: Any = None,
        apply_configs: bool = True,
    ) -> dict[str, Any]:
        """Run clean-network startup calibration (base DNS + ISP beacon probes + TSPU profile)."""
        async def _cal() -> dict[str, Any]:
            storage = Storage(self.db_path)
            try:
                self._seed_default_strategies(storage)
                return await calibrate_network(
                    storage,
                    dns_orch=self.orchestrator.dns,
                    bin_dir=self.bin_dir,
                    timeout=timeout,
                    progress_cb=progress_cb,
                )
            finally:
                storage.close()

        res = _run_coro_sync(_cal())
        if apply_configs:
            self.trigger_apply_configs()
        return res

    def start_autopilot(self, iface: int | None = None, force: bool = True) -> dict[str, Any]:
        """One-click workflow: check admin first, calibrate if uncalibrated/empty, generate configs, and start stack."""
        is_admin = _is_admin()
        storage = Storage(self.db_path)
        try:
            with self._lock:
                self._seed_default_strategies(storage)
            net_key, _, _, _ = self._resolve_network_info(storage)
            existing_decisions = storage.get_decisions(net_key, active_only=True)
            network_profile = storage.get_network_profile(net_key)
        finally:
            storage.close()

        diagnosed_now = False
        calibration_result: dict[str, Any] | None = None
        if network_profile is None or not existing_decisions:
            calibration_result = self.run_calibration_sync(apply_configs=False)
            diagnosed_now = True

        if self._stopping:
            return {
                "ok": False,
                "started_services": False,
                "requires_admin": not is_admin,
                "error": "stopping",
                "configs_ready": False,
            }
        if is_admin:
            srv_res = self.start_services(iface=iface, force=force)
            applied = srv_res.get("applied") or {}
        else:
            applied = self.trigger_apply_configs(iface=iface)
            srv_res = self.start_services(iface=iface, force=force)
        orchestrators = self.get_orchestrators_summary(probe_live=False, use_clash=False)

        storage = Storage(self.db_path)
        try:
            net_key, _, _, _ = self._resolve_network_info(storage)
            decisions_count = len(storage.get_decisions(net_key, active_only=True))
        finally:
            storage.close()

        return {
            "ok": bool(srv_res.get("ok")),
            "started_services": bool(srv_res.get("started")),
            "requires_admin": bool(srv_res.get("requires_admin")),
            "error": srv_res.get("error"),
            "configs_ready": True,
            "diagnosed_now": diagnosed_now,
            "calibration": calibration_result,
            "decisions_count": decisions_count,
            "applied": applied,
            "services": srv_res.get("services", []),
            "processes": srv_res.get("processes", self._collect_processes_state()),
            "live_connections": None,
            "orchestrators": orchestrators,
        }

    def get_expert_mode(self, storage: Storage | None = None) -> bool:
        """Return True if Expert Mode is enabled in UI settings (default False)."""
        own_st = storage is None
        st = storage if storage is not None else Storage(self.db_path)
        try:
            return st.get_setting("expert_mode", "0") == "1"
        finally:
            if own_st:
                st.close()

    def set_expert_mode(self, enabled: bool) -> dict[str, Any]:
        """Persist Expert Mode toggle across restarts."""
        st = Storage(self.db_path)
        try:
            st.set_setting("expert_mode", "1" if enabled else "0")
        finally:
            st.close()
        return {"expert_mode": bool(enabled)}

    def get_telegram_mode(self, storage: Storage | None = None) -> str:
        """Return Telegram bypass mode: 'mtproto' (built-in WS proxy) or 'transparent' (via TUN/DPI)."""
        own_st = storage is None
        st = storage if storage is not None else Storage(self.db_path)
        try:
            raw = st.get_setting("telegram_mode", "mtproto").strip().lower()
            return raw if raw in ("mtproto", "transparent") else "mtproto"
        finally:
            if own_st:
                st.close()

    def set_telegram_mode(self, mode: str) -> dict[str, Any]:
        """Switch Telegram bypass mode between 'mtproto' and 'transparent' cleanly."""
        clean = (mode or "").strip().lower()
        if clean not in ("mtproto", "transparent"):
            raise ValueError(f"Unsupported telegram_mode: {mode!r}")
        st = Storage(self.db_path)
        try:
            st.set_setting("telegram_mode", clean)
        finally:
            st.close()
        applied = self.trigger_apply_configs()
        if _is_admin():
            procs = self._collect_processes_state()
            if clean == "mtproto":
                if bool((procs.get("winws2") or {}).get("running")) and not bool((procs.get("tg-ws-proxy") or {}).get("running")):
                    self._restart_tg_ws_proxy()
            else:
                if self._supervisor is not None:
                    self._supervisor.stop_process("tg-ws-proxy")
            self._reload_running_services(winws2=True, singbox=True)
        return {"telegram_mode": clean, "applied": applied}

    def get_pending_bundle_alerts(self) -> list[dict[str, Any]]:
        """Return unresolved game/launcher connectivity alerts detected by Live-Radar."""
        with self.orchestrator.monitor._lock:
            return [dict(item) for item in self.orchestrator.monitor.pending_bundle_alerts]

    def dismiss_bundle_alert(self, key: str) -> bool:
        """Dismiss a pending bundle recommendation alert by bundle_id or process name."""
        low = (key or "").strip().lower()
        if not low:
            return False
        removed = False
        with self.orchestrator.monitor._lock:
            kept: list[dict[str, Any]] = []
            for item in self.orchestrator.monitor.pending_bundle_alerts:
                bid = str(item.get("bundle_id") or "").lower()
                proc = str(item.get("process") or "").lower()
                if bid == low or proc == low:
                    removed = True
                else:
                    kept.append(item)
            if removed:
                self.orchestrator.monitor.pending_bundle_alerts.clear()
                self.orchestrator.monitor.pending_bundle_alerts.extend(kept)
        return removed

    def check_vpn_udp_reachability(self, *, storage: Storage | None = None) -> dict[str, Any]:
        """Check whether an active/usable VPN node supports UDP gaming traffic and is reachable."""
        own_st = storage is None
        st = storage if storage is not None else Storage(self.db_path)
        try:
            raw_nodes = st.get_all_subscription_nodes()
            health_map = st.get_vpn_node_health_map()
        finally:
            if own_st:
                st.close()
        usable = [n for n in raw_nodes if not is_placeholder_node(n) and not is_auto_select_node(n) and n.get("enabled", True)]
        if not usable:
            return {"ok": False, "node": None, "protocol": "", "reason": "Нет настроенных VPN-узлов. Добавьте подписку на вкладке VPN."}
        udp_capable_protos = {
            "vless",
            "vmess",
            "trojan",
            "wireguard",
            "amneziawg",
            "hysteria",
            "hysteria2",
            "tuic",
            "shadowsocks",
            "ss",
        }
        cached = dict(self._cached_vpn_nodes)
        best_tag = str(self._cached_vpn_health.get("best_node") or "").strip()
        cand = next((n for n in usable if str(n.get("tag") or "") == best_tag), usable[0])
        tag = str(cand.get("tag") or "")
        proto = str(cand.get("protocol") or "").strip().lower()
        if proto and proto not in udp_capable_protos:
            return {"ok": False, "node": tag, "protocol": proto, "reason": f"Протокол VPN ({proto}) не поддерживает игровой UDP-трафик."}
        rec = cached.get(tag) or health_map.get(tag) or {}
        if rec and rec.get("alive") is False and str(rec.get("cb_state") or "") == "open":
            return {"ok": False, "node": tag, "protocol": proto, "reason": f"VPN-узел «{tag}» сейчас недоступен (quarantined). Проверьте подключение на вкладке VPN."}
        if _is_tcp_port_open(2081):
            if not _probe_socks5_udp_sync("127.0.0.1", 2081, timeout=1.5):
                return {"ok": False, "node": tag, "protocol": proto, "reason": f"VPN-узел «{tag}» не пропускает игровой UDP-трафик (SOCKS5 UDP тайм-аут)."}
        return {"ok": True, "node": tag, "protocol": proto, "reason": ""}

    def get_bundles_status(
        self,
        *,
        storage: Storage | None = None,
        net_key: str | None = None,
    ) -> dict[str, Any]:
        """Return all AppBundle ecosystems, active mode per bundle, running state, and alerts."""
        own_st = storage is None
        st = storage if storage is not None else Storage(self.db_path)
        try:
            nk = net_key or self._resolve_network_info(st)[0]
            bundles = load_bundles(self.bundles_path, storage=st)
            mode_map = st.get_bundle_modes(nk)
            raw_custom = _safe_json_loads(st.get_setting("custom_bundles", "[]"), list)
        finally:
            if own_st:
                st.close()

        custom_ids = {str(item.get("id") or "") for item in raw_custom if isinstance(item, dict)}
        running_map = expand_running_bundle_processes(bundles)
        items: list[dict[str, Any]] = []
        for b in bundles:
            rec = mode_map.get(b.id) or {}
            mode = str(rec.get("mode") or b.default_mode or "direct_clean")
            if mode not in BUNDLE_MODES:
                mode = b.default_mode if b.default_mode in BUNDLE_MODES else "direct_clean"
            extra_procs = list(rec.get("custom_processes") or [])
            merged_procs = list(dict.fromkeys([*b.processes, *extra_procs]))
            run_info = running_map.get(b.id) or {}
            items.append(
                {
                    "id": b.id,
                    "name": b.name,
                    "category": b.category,
                    "coupling": b.coupling,
                    "icon": "🔊" if b.category == "app" else "🎮",
                    "processes": merged_procs,
                    "auth_domains": list(b.auth_domains),
                    "download_cdn_domains": list(b.download_cdn_domains),
                    "default_mode": b.default_mode,
                    "mode": mode,
                    "pinned": bool(rec.get("pinned", False)),
                    "vpn_required": b.coupling == "tight" and b.category == "game",
                    "custom": (b.id in custom_ids) or (not b.builtin),
                    "running": bool(run_info.get("running")),
                    "running_processes": list(run_info.get("processes") or []),
                }
            )
        return {
            "network_key": nk,
            "bundles": items,
            "alerts": self.get_pending_bundle_alerts(),
        }

    def set_bundle_mode(
        self,
        bundle_id: str,
        mode: str,
        *,
        custom_processes: list[str] | None = None,
        pinned: bool | None = None,
    ) -> dict[str, Any]:
        """Set routing mode ('direct_clean'|'direct_dpi'|'vpn') for an AppBundle atomically."""
        clean_id = (bundle_id or "").strip()
        clean_mode = (mode or "").strip().lower()
        if clean_mode not in BUNDLE_MODES:
            raise ValueError(f"Unsupported bundle mode: {mode!r}")

        st = Storage(self.db_path)
        try:
            net_key, _, _, _ = self._resolve_network_info(st)
            bundles = load_bundles(self.bundles_path, storage=st)
            match = next((b for b in bundles if b.id == clean_id), None)
            if match is None:
                raise ValueError(f"Unknown bundle id: {clean_id}")
            saved = st.set_bundle_mode(
                net_key,
                clean_id,
                clean_mode,
                custom_processes=custom_processes,
                pinned=pinned,
            )
            if clean_mode != "vpn":
                bundle_procs_low = {p.lower() for p in [*match.processes, *(custom_processes or [])]}
                cur_vpn_procs = self.get_vpn_processes(st, net_key=net_key)
                filtered_vpn_procs = [p for p in cur_vpn_procs if p.lower() not in bundle_procs_low]
                if len(filtered_vpn_procs) != len(cur_vpn_procs):
                    st.set_setting(f"vpn_processes:{net_key}", ", ".join(filtered_vpn_procs))
            udp_check = self.check_vpn_udp_reachability(storage=st) if clean_mode == "vpn" else {"ok": True, "reason": ""}
        finally:
            st.close()

        self.dismiss_bundle_alert(clean_id)
        prev_pass = self._last_pass_domains_sig
        prev_game_udp = self._last_game_udp_dpi
        applied = self.trigger_apply_configs()
        if self.ruleset_server.is_running:
            self.sync_rulesets_live()
        need_winws = (
            self._last_pass_domains_sig != prev_pass
            or self._last_game_udp_dpi != prev_game_udp
        )
        if _is_admin():
            procs = self._collect_processes_state()
            if need_winws and bool((procs.get("winws2") or {}).get("running")):
                self.reload_winws2_if_changed(min_interval_sec=0.0, defer_if_active=True)
            if bool((procs.get("sing-box") or {}).get("running")):
                self.reload_singbox_if_changed(min_interval_sec=0.0, defer_if_active=True)
        return {
            "ok": True,
            "bundle_id": clean_id,
            "mode": clean_mode,
            "pinned": bool(saved.get("pinned", False)),
            "udp_warning": "" if udp_check.get("ok") else str(udp_check.get("reason") or ""),
            "applied": applied,
        }

    def set_bundle_pinned(self, bundle_id: str, pinned: bool) -> bool:
        """Pin or unpin the manual route override for an AppBundle."""
        clean_id = (bundle_id or "").strip().lower()
        if not clean_id:
            return False
        st = Storage(self.db_path)
        try:
            net_key, _, _, _ = self._resolve_network_info(st)
            return st.set_bundle_pinned(net_key, clean_id, pinned)
        finally:
            st.close()

    def add_custom_bundle(
        self,
        name: str,
        processes: list[str] | str,
        mode: str = "vpn",
    ) -> dict[str, Any]:
        """Create and persist a user-defined application/game bundle."""
        clean_name = name.strip()
        if not clean_name:
            raise ValueError("Введите название программы или игры")
        proc_list = (
            parse_process_list(processes)
            if isinstance(processes, str)
            else parse_process_list(", ".join(str(p) for p in processes))
        )
        if not proc_list:
            raise ValueError("Укажите хотя бы один .exe процесс")
        clean_mode = (mode or "vpn").strip().lower()
        if clean_mode not in BUNDLE_MODES:
            clean_mode = "vpn"
        slug = re.sub(r"[^a-z0-9]+", "_", clean_name.lower()).strip("_") or "app"
        bundle_id = f"custom_{slug}_{int(time.time() * 1000) % 100000}"
        entry = {
            "id": bundle_id,
            "name": clean_name,
            "category": "custom",
            "icon": "🎮",
            "processes": proc_list,
            "auth_domains": [],
            "game_domains": [],
            "default_mode": clean_mode,
            "vpn_required": False,
        }
        st = Storage(self.db_path)
        try:
            existing = _safe_json_loads(st.get_setting("custom_bundles", "[]"), list)
            items = [x for x in existing if isinstance(x, dict)]
            items.append(entry)
            st.set_setting("custom_bundles", json.dumps(items, ensure_ascii=False))
            net_key, _, _, _ = self._resolve_network_info(st)
            st.set_bundle_mode(net_key, bundle_id, clean_mode, custom_processes=proc_list)
        finally:
            st.close()
        self.trigger_apply_configs()
        if self.ruleset_server.is_running:
            self.sync_rulesets_live()
        if _is_admin() and bool((self._collect_processes_state().get("sing-box") or {}).get("running")):
            self.reload_singbox_if_changed(min_interval_sec=0.0, defer_if_active=True)
        return entry

    def remove_custom_bundle(self, bundle_id: str) -> bool:
        """Delete a user-defined custom bundle by ID."""
        clean_id = (bundle_id or "").strip()
        st = Storage(self.db_path)
        try:
            existing = _safe_json_loads(st.get_setting("custom_bundles", "[]"), list)
            kept = [x for x in existing if isinstance(x, dict) and str(x.get("id") or "") != clean_id]
            removed = len(kept) != len([x for x in existing if isinstance(x, dict)])
            if removed:
                st.set_setting("custom_bundles", json.dumps(kept, ensure_ascii=False))
                net_key, _, _, _ = self._resolve_network_info(st)
                st.delete_bundle_mode(net_key, clean_id)
        finally:
            st.close()
        if removed:
            self.trigger_apply_configs()
            if self.ruleset_server.is_running:
                self.sync_rulesets_live()
            if _is_admin() and bool((self._collect_processes_state().get("sing-box") or {}).get("running")):
                self.reload_singbox_if_changed(min_interval_sec=0.0, defer_if_active=True)
        return removed

    def sync_rulesets_live(self, *, storage: Storage | None = None) -> dict[str, Any]:
        """Update served JSON rule-sets in-place without regenerating or restarting sing-box."""
        own_st = storage is None
        st = storage if storage is not None else Storage(self.db_path)
        try:
            net_key, _, _, _ = self._resolve_network_info(st)
            decisions = st.get_decisions(net_key, active_only=True)
            raw_vpn = st.get_all_subscription_nodes()
            has_real_vpn = (
                st.get_setting("stack_mode", "hybrid").strip().lower() != "dpi_only"
                and has_usable_vpn_nodes([VpnNode(**n) for n in raw_vpn])
            )
            sb_decs = (
                decisions
                if has_real_vpn
                else [d for d in decisions if not (d.layer == "vpn" and not getattr(d, "pinned", False))]
            )
            byedpi_fallback = st.get_setting("byedpi_fallback", "0") == "1"
            guard = build_unlocker_protection_context(storage=st, hosts_path=self.hosts_path)
            bypass_domains = list(guard["domains"]) if guard["enabled"] else []
            bundles = load_bundles(self.bundles_path, storage=st)
            mode_map = st.get_bundle_modes(net_key)
            compiled = compile_bundle_rules(bundles, mode_map, running_map=expand_running_bundle_processes(bundles))
            profile = st.get_network_profile(net_key)
            quic_blocked_doms: list[str] = []
            if bool((profile or {}).get("quic_blocked")) or any(
                d.protocol == Protocol.QUIC and d.layer in ("dpi", "direct") for d in sb_decs
            ):
                quic_blocked_doms = sorted(
                    {*QUIC_HOSTLIST_DOMAINS, *(d.domain.lower() for d in sb_decs if d.protocol == Protocol.QUIC and d.layer in ("dpi", "direct"))}
                )
            vpn_procs = sorted({*self.get_vpn_processes(st, net_key=net_key), *compiled["vpn_processes"]}, key=str.lower)
            telegram_mode = self.get_telegram_mode(st)
            payload = build_singbox_rulesets_payload(
                sb_decs,
                bypass_domains=bypass_domains,
                enable_byedpi=byedpi_fallback,
                smartdns_domains=list(AI_GEOBLOCK_DOMAINS),
                bundle_rules=compiled,
                quic_blocked_domains=quic_blocked_doms,
                vpn_processes=vpn_procs,
                telegram_mode=telegram_mode,
            )
        finally:
            if own_st:
                st.close()
        etags = self.ruleset_server.update_rulesets(payload)
        self._last_rulesets_payload_hash = hashlib.sha256(
            json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        return {"ok": True, "tags": sorted(etags.keys()), "server_running": self.ruleset_server.is_running}

    # ---------------------------------------------------------------- DNS Catalog & Custom DNS

    def get_dns_catalog(self) -> dict[str, Any]:
        """Return all built-in + custom DNS servers, active selection, assigned domains, and categories."""
        storage = Storage(self.db_path)
        try:
            servers = self.orchestrator.dns.get_all_dns_servers(storage)
            active = self.orchestrator.dns.get_active_dns(storage)
            net_key, _, _, _ = self._resolve_network_info(storage)
            base_dns = self.orchestrator.dns.get_base_dns(storage, net_key=net_key)
            decisions = storage.get_decisions(net_key, active_only=True)
        finally:
            storage.close()

        assigned_map: dict[str, list[str]] = {}
        for d in decisions:
            if d.layer == "dns" and isinstance(d.strategy_id, str) and d.strategy_id.startswith("dns:"):
                did = d.strategy_id.split(":", 1)[1].strip()
                assigned_map.setdefault(did, []).append(d.domain)

        enriched = self._merge_dns_ping_cache(servers)
        for item in enriched:
            item["assigned_domains"] = sorted(set(assigned_map.get(str(item["id"]), [])))
        active_enriched = self._merge_dns_ping_cache([active])[0]
        active_enriched["assigned_domains"] = sorted(set(assigned_map.get(str(active_enriched["id"]), [])))
        base_enriched = self._merge_dns_ping_cache([base_dns])[0] if base_dns else None
        return {
            "active_dns_id": active_enriched["id"],
            "active_dns": active_enriched,
            "base_dns_id": str(base_enriched["id"]) if base_enriched else "",
            "base_dns": base_enriched,
            "categories": list(DNS_CATEGORIES),
            "servers": enriched,
        }

    def get_base_dns(self, storage: Storage | None = None, net_key: str | None = None) -> dict[str, Any] | None:
        """Return currently configured base non-SmartDNS resolver for the active or specified network."""
        own_st = storage is None
        st = storage if storage is not None else Storage(self.db_path)
        try:
            nk = net_key or self._resolve_network_info(st)[0]
            return self.orchestrator.dns.get_base_dns(st, net_key=nk)
        finally:
            if own_st:
                st.close()

    def select_dns_server(self, dns_id: str) -> dict[str, Any]:
        """Select a built-in or custom DNS server, persist it, and regenerate sing-box.json."""
        clean_id = dns_id.strip()
        storage = Storage(self.db_path)
        try:
            servers = self.orchestrator.dns.get_all_dns_servers(storage)
            match = next((s for s in servers if s["id"] == clean_id), None)
            if match is None:
                raise ValueError(f"Unknown DNS server ID: {clean_id}")
            storage.set_setting("active_dns_id", clean_id)
            if str(match.get("category") or "").strip().lower() != "ai_bypass":
                net_key, _, _, _ = self._resolve_network_info(storage)
                storage.set_setting(f"base_dns_id:{net_key}", clean_id)
        finally:
            storage.close()

        self.trigger_apply_configs()
        self._reload_running_services(singbox=True)
        self.flush_windows_dns_cache()
        return self._merge_dns_ping_cache([match])[0]

    def add_custom_dns(
        self,
        name: str,
        ip: str,
        description: str = "",
        doh_url: str = "",
    ) -> dict[str, Any]:
        """Validate and store a custom DNS server, select it as active, and regenerate configs."""
        clean_name = name.strip()
        clean_ip = ip.strip()
        clean_doh = doh_url.strip()
        if not clean_name:
            raise ValueError("Введите название DNS-сервера")
        if not clean_ip:
            raise ValueError("Введите IP-адрес DNS-сервера")
        try:
            ipaddress.ip_address(clean_ip)
        except ValueError:
            raise ValueError(f"Некорректный IP-адрес DNS: {clean_ip}") from None

        if clean_doh and not clean_doh.startswith("https://"):
            # Only https:// DoH URLs are valid for sing-box DoH; treat anything else as description if empty
            if not description and not clean_doh.startswith(("tls://", "http://")):
                description = clean_doh
            clean_doh = ""

        slug = re.sub(r"[^a-z0-9]+", "_", clean_name.lower()).strip("_") or "dns"
        dns_id = f"custom_{slug}_{int(time.time() * 1000) % 100000}"
        badges = ["Свой", "DoH"] if clean_doh else ["Свой", "DNS"]

        storage = Storage(self.db_path)
        try:
            saved = storage.save_custom_dns(
                {
                    "id": dns_id,
                    "name": clean_name,
                    "ip": clean_ip,
                    "doh_url": clean_doh,
                    "description": description.strip() or "Пользовательский DNS",
                    "category": "custom",
                    "badges": badges,
                }
            )
            storage.set_setting("active_dns_id", saved["id"])
        finally:
            storage.close()

        self.trigger_apply_configs()
        self._reload_running_services(singbox=True)
        return saved

    def remove_custom_dns(self, dns_id: str) -> bool:
        """Delete a user-defined custom DNS server and revert active DNS to Cloudflare if needed."""
        storage = Storage(self.db_path)
        try:
            deleted = storage.delete_custom_dns(dns_id)
            if deleted and storage.get_setting("active_dns_id", "cloudflare") == dns_id:
                storage.set_setting("active_dns_id", "cloudflare")
        finally:
            storage.close()
        if deleted:
            self.trigger_apply_configs()
            self._reload_running_services(singbox=True)
        return deleted

    def ping_dns_catalog(self, category: str | None = None) -> list[dict[str, Any]]:
        """Concurrently measure latency across all (or category-filtered) DNS servers and cache pings."""
        storage = Storage(self.db_path)
        try:
            all_servers = self.orchestrator.dns.get_all_dns_servers(storage)
        finally:
            storage.close()

        targets = [s for s in all_servers if not category or s.get("category") == category]
        probed = _run_coro_sync(self.orchestrator.dns.probe_dns_catalog(targets))
        with self._lock:
            for p in probed:
                self._cached_dns_pings[str(p["id"])] = p
        return self._merge_dns_ping_cache(all_servers)

    def auto_select_best_dns(self, category: str = "uncommon") -> dict[str, Any]:
        """Ping candidate DNS servers in a category and activate the lowest-latency healthy server."""
        all_probed = self.ping_dns_catalog(category=category)
        candidates = [
            s
            for s in all_probed
            if s.get("category") == category and s.get("alive") and not s.get("doh_broken")
        ]
        if not candidates:
            candidates = [s for s in all_probed if s.get("category") == category and s.get("alive")]
        if not candidates:
            candidates = [s for s in all_probed if s.get("category") == category]
        candidates.sort(key=lambda s: s["ping_ms"] if s.get("ping_ms") is not None else 99999.0)
        best = candidates[0] if candidates else all_probed[0]
        selected = self.select_dns_server(best["id"])
        selected["ping_ms"] = best.get("ping_ms")
        selected["alive"] = best.get("alive")
        return selected

    def roll_base_dns_sync(self, category: str | None = None) -> dict[str, Any]:
        """Probe ordinary non-SmartDNS resolvers via real DoH/DNS resolution and apply the fastest working one."""
        storage = Storage(self.db_path)
        try:
            net_key, _, _, _ = self._resolve_network_info(storage)
            if category is not None:
                roll_res = _run_coro_sync(self.orchestrator.dns.roll_base_dns(storage, category=category))
            else:
                roll_res = _run_coro_sync(self.orchestrator.dns.roll_base_dns(storage))
            selected = roll_res.get("selected")
            active_dns = self.orchestrator.dns.get_active_dns(storage)
            active_is_smart = str(active_dns.get("category") or "").strip().lower() == "ai_bypass"
            with self._lock:
                for item in (roll_res.get("all_results") or roll_res.get("results") or []):
                    srv = item.get("server")
                    sid = str(item.get("dns_id") or (srv.get("id") if isinstance(srv, dict) else "") or "")
                    if sid and isinstance(srv, dict):
                        cached = dict(srv)
                        cached["alive"] = bool(item.get("ok"))
                        cached["ping_ms"] = item.get("rtt_ms")
                        self._cached_dns_pings[sid] = cached
                if selected is not None:
                    self._cached_dns_pings[str(selected["id"])] = dict(selected)
            if selected is not None:
                sel_id = str(selected["id"])
                storage.set_setting(f"base_dns_id:{net_key}", sel_id)
                if not active_is_smart:
                    storage.set_setting("active_dns_id", sel_id)
        finally:
            storage.close()

        if not selected:
            return {
                "ok": False,
                "selected": None,
                "active_dns": active_dns,
                "tested": int(roll_res.get("tested") or 0),
                "alive": 0,
                "mode": "smartdns_split" if active_is_smart else "general",
                "error": "Ни один обычный DNS-сервер не ответил в текущей сети",
            }

        self.trigger_apply_configs()
        self._reload_running_services(singbox=True)
        self.flush_windows_dns_cache()
        return {
            "ok": True,
            "selected": selected,
            "active_dns": active_dns,
            "tested": int(roll_res.get("tested") or 0),
            "alive": int(roll_res.get("alive") or 0),
            "mode": "smartdns_split" if active_is_smart else "general",
            "network_key": net_key,
        }

    def roll_dns_for_domain_sync(self, domain: str) -> dict[str, Any]:
        """Roll all relevant bypass DNS servers for a specific domain, save best DNS decision, and apply configs."""
        clean_domain = domain.strip().lower()
        if not clean_domain:
            raise ValueError("Введите адрес сайта для подбора DNS")

        async def _roll() -> Decision:
            net = await detect_network_fingerprint(timeout=2.0)
            storage = Storage(self.db_path)
            try:
                net_key = storage.upsert_network(net)
                decision = await self.orchestrator.dns.roll_dns_for_domain(
                    clean_domain,
                    network_key=net_key,
                    storage=storage,
                )
                storage.save_decision(decision)
                return decision
            finally:
                storage.close()

        decision = _run_coro_sync(_roll())
        self.trigger_apply_configs()
        self._reload_running_services(winws2=True, singbox=True)
        dns_id = (decision.strategy_id or "").split(":", 1)[-1]
        cat = self.get_dns_catalog()
        srv = next((s for s in cat["servers"] if s["id"] == dns_id), None)
        return {
            "decision": decision.model_dump(mode="json"),
            "dns_id": dns_id,
            "dns_server": srv,
        }

    def roll_ai_dns_batch_sync(self, domains: list[str] | None = None) -> list[dict[str, Any]]:
        """Independently roll and assign the best working DNS server for each AI / geo-blocked domain."""
        target_domains = list(
            domains or ["chatgpt.com", "openai.com", "claude.ai", "grok.com", "notion.so", "spotify.com"]
        )

        async def _roll_all() -> list[Decision]:
            net = await detect_network_fingerprint(timeout=2.0)
            storage = Storage(self.db_path)
            try:
                net_key = storage.upsert_network(net)
                return await self.orchestrator.dns.roll_dns_for_domains_batch(
                    domains=target_domains,
                    network_key=net_key,
                    storage=storage,
                )
            finally:
                storage.close()

        decisions = _run_coro_sync(_roll_all())
        self.trigger_apply_configs()
        self._reload_running_services(winws2=True, singbox=True)
        return [d.model_dump(mode="json") for d in decisions]

    # ---------------------------------------------------------------- Everyday UX Helpers

    def set_game_filter(self, enabled: bool) -> dict[str, Any]:
        """Persist Game Filter setting (ports 1024-65535 for Discord voice & games) and rebuild configs."""
        storage = Storage(self.db_path)
        try:
            storage.set_setting("game_filter", "1" if enabled else "0")
        finally:
            storage.close()
        applied = self.trigger_apply_configs()
        self._reload_running_services(winws2=True, singbox=True)
        return {"game_filter": bool(enabled), "applied": applied}

    def apply_service_preset(self, preset_id: str) -> dict[str, Any]:
        """One-click everyday preset: rolls per-domain DNS for AI or configures DPI/DNS strategies for a service."""
        if preset_id not in SERVICE_PRESETS:
            raise ValueError(f"Unknown service preset: {preset_id}")
        preset = SERVICE_PRESETS[preset_id]

        if preset.get("enable_game_filter"):
            storage = Storage(self.db_path)
            try:
                storage.set_setting("game_filter", "1")
            finally:
                storage.close()

        selected_dns: dict[str, Any] | None = None
        if preset_id == "ai":
            # Roll per-domain AI bypass DNS for each AI/geoblock service
            ai_domains = ["chatgpt.com", "openai.com", "claude.ai", "grok.com", "notion.so", "spotify.com"]
            rolled = self.roll_ai_dns_batch_sync(ai_domains)
            probed = self.ping_dns_catalog(category="ai_bypass")
            alive_ai = [s for s in probed if s.get("category") == "ai_bypass" and s.get("alive")]
            if alive_ai:
                alive_ai.sort(key=lambda s: s["ping_ms"] if s.get("ping_ms") is not None else 99999.0)
                selected_dns = alive_ai[0]
            else:
                selected_dns = next(
                    (s for s in probed if s["id"] == preset["recommended_dns"]),
                    probed[0] if probed else None,
                )
            return {
                "preset": preset,
                "domains": ai_domains,
                "rows_count": len(rolled),
                "selected_dns": selected_dns,
                "rolled_decisions": rolled,
            }

        if preset.get("recommended_dns"):
            selected_dns = self.select_dns_server(str(preset["recommended_dns"]))

        rows = self.run_diag_sync(domains=list(preset["domains"]))
        self._reload_running_services(winws2=True, singbox=True)

        return {
            "preset": preset,
            "domains": list(preset["domains"]),
            "rows_count": len(rows),
            "selected_dns": selected_dns,
        }

    def set_unlocker_exclusions(self, raw_text: str, enabled: bool = True) -> dict[str, Any]:
        """Save Unlocker Guard toggle + custom process/domain/IP exclusions and rebuild configs cleanly."""
        storage = Storage(self.db_path)
        try:
            storage.set_setting("unlocker_guard", "1" if enabled else "0")
            storage.set_setting("unlocker_exclusions", raw_text.strip())
            guard = build_unlocker_protection_context(storage=storage, hosts_path=self.hosts_path)
        finally:
            storage.close()
        applied = self.trigger_apply_configs()
        self._reload_running_services(winws2=True, singbox=True)
        return {"guard": guard, "applied": applied}

    def get_vpn_processes(
        self,
        storage: Storage | None = None,
        net_key: str | None = None,
    ) -> list[str]:
        """Return list of `.exe` processes forced through `vpn-select` for the active or specified network."""
        own_st = storage is None
        st = storage if storage is not None else Storage(self.db_path)
        try:
            nk = net_key or self._resolve_network_info(st)[0]
            per_net = st.get_setting(f"vpn_processes:{nk}", None)
            raw = per_net if per_net is not None else st.get_setting("vpn_processes", "")
            return _sanitize_vpn_processes(parse_process_list(raw))
        finally:
            if own_st:
                st.close()

    def set_vpn_processes(
        self,
        raw_text: str,
        *,
        net_key: str | None = None,
    ) -> dict[str, Any]:
        """Persist `.exe` names routed via VPN for the current network, rebuild configs, and reload sing-box."""
        procs = _sanitize_vpn_processes(parse_process_list(raw_text))
        storage = Storage(self.db_path)
        try:
            nk = net_key or self._resolve_network_info(storage)[0]
            prev = self.get_vpn_processes(storage, net_key=nk)
            prev_low = {p.lower() for p in prev}
            new_low = {p.lower() for p in procs}
            with self.orchestrator.monitor._lock:
                self.orchestrator.monitor._manual_vpn_proc_optout.update(prev_low - new_low)
                self.orchestrator.monitor._manual_vpn_proc_optout.difference_update(new_low)
            storage.set_setting(f"vpn_processes:{nk}", ", ".join(procs))
            # Keep AppBundle modes synchronized so bundle direct_* rules never contradict vpn_processes
            bundles = load_bundles(self.bundles_path, storage=storage)
            bundle_modes = storage.get_bundle_modes(nk)
            for p_added in new_low - prev_low:
                matched = match_process_to_bundle(p_added, bundles)
                if matched is not None:
                    storage.set_bundle_mode(nk, matched.id, "vpn")
            for p_removed in prev_low - new_low:
                matched = match_process_to_bundle(p_removed, bundles)
                if matched is not None:
                    b_procs_low = {bp.lower() for bp in matched.processes}
                    cur_mode = str((bundle_modes.get(matched.id) or {}).get("mode") or matched.default_mode)
                    if cur_mode == "vpn" and not (b_procs_low & new_low):
                        storage.set_bundle_mode(nk, matched.id, "direct_dpi")
        finally:
            storage.close()
        applied = self.trigger_apply_configs()
        if self.ruleset_server.is_running:
            self.sync_rulesets_live()
        self._reload_running_services(singbox=True)
        return {"vpn_processes": procs, "network_key": nk, "applied": applied}

    def add_vpn_process(
        self,
        proc_name: str,
        *,
        net_key: str | None = None,
        apply: bool = False,
    ) -> list[str]:
        """Ensure `proc_name` is included in per-network `vpn_processes` (clear manual opt-out)."""
        parsed = parse_process_list(proc_name)
        if not parsed:
            return self.get_vpn_processes(net_key=net_key)
        clean = parsed[0]
        storage = Storage(self.db_path)
        try:
            nk = net_key or self._resolve_network_info(storage)[0]
            cur = self.get_vpn_processes(storage, net_key=nk)
            if all(p.lower() != clean.lower() for p in cur):
                cur.append(clean)
                storage.set_setting(f"vpn_processes:{nk}", ", ".join(cur))
            with self.orchestrator.monitor._lock:
                self.orchestrator.monitor._manual_vpn_proc_optout.discard(clean.lower())
        finally:
            storage.close()
        if apply:
            self.trigger_apply_configs()
            self._reload_running_services(singbox=True)
        return cur

    def toggle_vpn_process(self, proc_name: str) -> dict[str, Any]:
        """Toggle whether a process `.exe` routes via `vpn-select` in the active network."""
        parsed = parse_process_list(proc_name)
        if not parsed:
            raise ValueError("Не указано имя процесса (.exe)")
        clean = parsed[0]
        cur = self.get_vpn_processes()
        low = clean.lower()
        enabled_now = not any(p.lower() == low for p in cur)
        updated = [*cur, clean] if enabled_now else [p for p in cur if p.lower() != low]
        res = self.set_vpn_processes(", ".join(updated))
        return {
            "enabled": enabled_now,
            "process": clean,
            "vpn_processes": res["vpn_processes"],
            "network_key": res["network_key"],
            "applied": res["applied"],
        }

    def get_auto_heal_enabled(self, storage: Storage | None = None) -> bool:
        """Return True if Live-Radar real-time auto-heal is enabled."""
        own_st = storage is None
        st = storage if storage is not None else Storage(self.db_path)
        try:
            return st.get_setting("auto_heal_enabled", "1") != "0"
        finally:
            if own_st:
                st.close()

    def set_auto_heal_enabled(self, enabled: bool) -> dict[str, Any]:
        """Persist Live-Radar auto-heal toggle state across restarts."""
        storage = Storage(self.db_path)
        try:
            storage.set_setting("auto_heal_enabled", "1" if enabled else "0")
        finally:
            storage.close()
        return {"auto_heal_enabled": bool(enabled)}

    def flush_windows_dns_cache(self) -> dict[str, Any]:
        """Clear OS DNS resolver cache (`ipconfig /flushdns`) so DNS changes take effect immediately."""
        try:
            res = subprocess.run(
                ["ipconfig", "/flushdns"],
                capture_output=True,
                timeout=8,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            raw_out = res.stdout or res.stderr or ""
            out = _decode_process_output(raw_out) if isinstance(raw_out, bytes) else str(raw_out).strip()
            return {"ok": res.returncode == 0, "output": out or "DNS cache flushed"}
        except OSError as exc:
            return {"ok": False, "output": str(exc)}

    def cleanup_stale_db_rules(self) -> dict[str, Any]:
        """Remove stale unpinned direct/rDNS decisions for the active network and rebuild configs."""
        storage = Storage(self.db_path)
        try:
            net_key, _, _, _ = self._resolve_network_info(storage)
            removed = storage.cleanup_stale_decisions(net_key)
        finally:
            storage.close()
        applied = self.trigger_apply_configs()
        self._reload_running_services(winws2=True, singbox=True)
        return {"ok": True, "removed": removed, "network_key": net_key, "applied": applied}

    def auto_tune_all_sync(
        self,
        *,
        domains: list[str] | None = None,
        timeout: float = 2.0,
    ) -> dict[str, Any]:
        """One-click full-stack recovery & tuning: reset broken state, pick best DoH DNS, re-probe VPN, re-diagnose core domains, reload & test."""
        target_domains = list(
            domains
            or [
                "discord.com",
                "discord.gg",
                "discordapp.com",
                "youtube.com",
                "googlevideo.com",
                "telegram.org",
                "instagram.com",
                "x.com",
                "rutracker.org",
            ]
        )
        storage = Storage(self.db_path)
        try:
            net_key, _, _, _ = self._resolve_network_info(storage)
            reset = storage.reset_unhealthy_state(net_key)
            roll_res = _run_coro_sync(self.orchestrator.dns.roll_base_dns(storage, timeout=timeout))
            selected_dns = roll_res.get("selected")
            active_dns = self.orchestrator.dns.get_active_dns(storage)
            active_is_smart = str(active_dns.get("category") or "").strip().lower() == "ai_bypass"
            active_is_weak_non_doh = (
                not str(active_dns.get("doh_url") or "").strip().startswith("https://")
                or bool(active_dns.get("doh_broken"))
            )
            with self._lock:
                for item in (roll_res.get("all_results") or roll_res.get("results") or []):
                    srv = item.get("server")
                    sid = str(item.get("dns_id") or (srv.get("id") if isinstance(srv, dict) else "") or "")
                    if sid and isinstance(srv, dict):
                        cached = dict(srv)
                        cached["alive"] = bool(item.get("ok"))
                        cached["ping_ms"] = item.get("rtt_ms")
                        self._cached_dns_pings[sid] = cached
                if selected_dns is not None:
                    self._cached_dns_pings[str(selected_dns["id"])] = dict(selected_dns)
            if selected_dns is not None:
                sel_id = str(selected_dns["id"])
                storage.set_setting(f"base_dns_id:{net_key}", sel_id)
                if (not active_is_smart) or active_is_weak_non_doh:
                    storage.set_setting("active_dns_id", sel_id)
            has_vpn_nodes = bool(storage.get_all_subscription_nodes())
        finally:
            storage.close()

        vpn_alive = 0
        vpn_best: str | None = None
        if has_vpn_nodes:
            try:
                probed_vpn = self.probe_all_vpn_nodes()
                alive_vpn = [n for n in probed_vpn if n.get("alive") and not n.get("is_placeholder")]
                vpn_alive = len(alive_vpn)
                if alive_vpn:
                    vpn_best = str(alive_vpn[0].get("tag") or "") or None
            except Exception:  # noqa: BLE001
                pass

        diag_rows = self.run_diag_sync(domains=target_domains, live_eval=False, timeout=timeout)
        self._reload_running_services(winws2=True, singbox=True)
        self.flush_windows_dns_cache()

        proc_state = self._collect_processes_state()
        conn_report: dict[str, Any] | None = None
        if (proc_state.get("winws2") or {}).get("running") or (proc_state.get("sing-box") or {}).get("running"):
            conn_report = self.run_connectivity_tests(
                include_key_services=True,
                include_picked_domains=False,
                timeout=min(timeout + 1.0, 3.0),
            )
            failing_doms = list(
                dict.fromkeys(
                    str(r.get("domain") or "").strip().lower()
                    for r in (conn_report.get("results") or [])
                    if not r.get("ok") and str(r.get("domain") or "").strip()
                )
            )
            if failing_doms:
                for fail_dom in failing_doms[:4]:
                    try:
                        self.find_best_bypass_for_domain(fail_dom, timeout=min(timeout + 1.0, 3.0))
                    except Exception:  # noqa: BLE001
                        pass
                conn_report = self.run_connectivity_tests(
                    include_key_services=True,
                    include_picked_domains=False,
                    timeout=min(timeout + 1.0, 3.0),
                )

        return {
            "ok": True,
            "network_key": net_key,
            "reset": reset,
            "base_dns": selected_dns,
            "vpn_alive": vpn_alive,
            "vpn_best": vpn_best,
            "diagnosed_count": len(diag_rows),
            "connectivity": conn_report,
        }

    def get_domain_rows(self, net_key: str | None = None) -> list[dict[str, Any]]:
        """Query decisions joined with verdicts and strategies for the active or specified network."""
        storage = Storage(self.db_path)
        try:
            resolved_key, _, _, _ = self._resolve_network_info(storage, net_key=net_key)
            return self._query_domain_rows(storage, resolved_key)
        finally:
            storage.close()

    def get_strategies_catalog(self, protocol: str | None = None) -> list[dict[str, Any]]:
        """Return all strategies from Storage (seeded with DEFAULT_STRATEGIES), optionally filtered by protocol."""
        proto_filter: Protocol | None = None
        if protocol is not None and str(protocol).strip() and str(protocol).strip().lower() != "all":
            proto_filter = protocol if isinstance(protocol, Protocol) else Protocol(str(protocol).strip().lower())

        storage = Storage(self.db_path)
        try:
            self._seed_default_strategies(storage)
            strategies = storage.get_strategies(proto_filter)
        finally:
            storage.close()
        return [s.model_dump(mode="json") for s in strategies]

    def pin_domain_strategy(
        self,
        domain: str,
        protocol: str,
        layer: str,
        strategy_id: str | None,
        pinned: bool = True,
    ) -> dict[str, Any]:
        """Persist a manual domain routing/strategy override and regenerate configuration files."""
        clean_domain = domain.strip().lower()
        if not clean_domain:
            raise ValueError("Domain cannot be empty")
        proto = protocol if isinstance(protocol, Protocol) else Protocol(protocol.strip().lower())
        clean_layer = layer.strip().lower()
        clean_strategy_id = strategy_id.strip() if isinstance(strategy_id, str) and strategy_id.strip() else None

        storage = Storage(self.db_path)
        try:
            net_key, _, _, _ = self._resolve_network_info(storage)
            existing = storage.conn.execute(
                """
                SELECT fallback_json, ttfb_ms, throughput_kbps, ttl_sec
                FROM decisions
                WHERE network_key = ? AND domain = ? AND protocol = ?
                """,
                (net_key, clean_domain, proto.value),
            ).fetchone()

            decision = Decision(
                network_key=net_key,
                domain=clean_domain,
                protocol=proto,
                layer=clean_layer,
                strategy_id=clean_strategy_id,
                fallback_strategies=list(_safe_json_loads(existing["fallback_json"], list)) if existing else [],
                ttfb_ms=existing["ttfb_ms"] if existing else None,
                throughput_kbps=existing["throughput_kbps"] if existing else None,
                consecutive_fails=0,
                status="active",
                updated_at=_now_iso(),
                ttl_sec=int(existing["ttl_sec"]) if existing else 21600,
                pinned=bool(pinned),
            )
            storage.save_decision(decision)
        finally:
            storage.close()

        self.trigger_apply_configs()
        self._reload_running_services(winws2=True, singbox=True)
        return decision.model_dump(mode="json")

    def set_domain_pinned(self, domain: str, protocol: str, pinned: bool) -> dict[str, Any]:
        """Toggle the pinned lock on a picked domain strategy so auto-heal does not overwrite it."""
        clean_domain = domain.strip().lower()
        if not clean_domain:
            raise ValueError("Domain cannot be empty")
        proto = protocol if isinstance(protocol, Protocol) else Protocol(protocol.strip().lower())
        storage = Storage(self.db_path)
        try:
            net_key, _, _, _ = self._resolve_network_info(storage)
            updated = storage.set_decision_pinned(net_key, clean_domain, proto, bool(pinned))
        finally:
            storage.close()
        return {"ok": updated, "domain": clean_domain, "protocol": proto.value, "pinned": bool(pinned)}

    # ---------------------------------------------------------------- Zapret2 Presets & Working User Presets

    def get_zapret_presets(self) -> dict[str, Any]:
        """Return all user-saved and built-in Zapret2 presets plus active mode metadata."""
        storage = Storage(self.db_path)
        try:
            active_id, active_name, _ = self._resolve_active_zapret_preset(storage)
            base_id, base_name, _ = self._resolve_base_zapret_preset(storage)
            presets = list_all_zapret_presets(
                storage,
                presets_dir=self.presets_dir,
                zdy_dir=self.zdy_presets_dir,
            )
        finally:
            storage.close()

        external_dirs = [str(d) for d in DEFAULT_EXTERNAL_ZAPRET_DIRS if d.is_dir()]
        return {
            "active_preset_id": active_id,
            "active_preset_name": active_name,
            "base_preset_id": base_id,
            "base_preset_name": base_name,
            "zapret_mode": "preset" if active_id != "auto" else "auto",
            "presets": presets,
            "external_dirs": external_dirs,
        }

    def select_zapret_preset(self, preset_id: str) -> dict[str, Any]:
        """Activate a fixed Zapret2 preset (locking orchestrator churn) or return to 'auto' orchestrator."""
        clean_id = (preset_id or "").strip() or "auto"
        storage = Storage(self.db_path)
        try:
            if clean_id == "auto":
                storage.set_setting("active_zapret_preset_id", "auto")
                active_name = "Авто-оркестратор (подбор по доменам)"
            else:
                all_presets = list_all_zapret_presets(
                    storage,
                    presets_dir=self.presets_dir,
                    zdy_dir=self.zdy_presets_dir,
                )
                match = next((p for p in all_presets if p["id"] == clean_id), None)
                if match is None:
                    raise ValueError(f"Пресет Zapret2 не найден: {clean_id}")
                # Validate compilation before activating
                compile_zapret_preset(
                    str(match["content"]),
                    bin_dir=self.bin_dir,
                    lists_dir=self.lists_dir,
                    game_filter=storage.get_setting("game_filter", "0") == "1",
                )
                storage.set_setting("active_zapret_preset_id", clean_id)
                active_name = str(match["name"])
        finally:
            storage.close()

        applied = self.trigger_apply_configs()
        self._reload_running_services(winws2=True, singbox=True)
        return {
            "ok": True,
            "active_preset_id": clean_id,
            "active_preset_name": active_name,
            "zapret_mode": "preset" if clean_id != "auto" else "auto",
            "applied": applied,
        }

    def set_base_zapret_preset(self, preset_id: str | None) -> dict[str, Any]:
        """Set or clear the base Zapret2 preset used beneath Auto-Orchestrator per-domain rules."""
        clean_id = (preset_id or "").strip()
        storage = Storage(self.db_path)
        try:
            if not clean_id or clean_id.lower() in ("none", "auto"):
                clean_id = ""
                base_name = ""
                storage.set_setting("base_zapret_preset_id", "")
                storage.set_setting("active_zapret_preset_id", "auto")
            else:
                all_presets = list_all_zapret_presets(
                    storage,
                    presets_dir=self.presets_dir,
                    zdy_dir=self.zdy_presets_dir,
                )
                match = next((p for p in all_presets if p["id"] == clean_id), None)
                if match is None:
                    raise ValueError(f"Пресет Zapret2 не найден: {clean_id}")
                compile_zapret_preset(
                    str(match["content"]),
                    bin_dir=self.bin_dir,
                    lists_dir=self.lists_dir,
                    game_filter=storage.get_setting("game_filter", "0") == "1",
                )
                storage.set_setting("base_zapret_preset_id", clean_id)
                storage.set_setting("active_zapret_preset_id", "auto")
                base_name = str(match["name"])
        finally:
            storage.close()

        applied = self.trigger_apply_configs()
        self._reload_running_services(winws2=True, singbox=True)
        return {
            "ok": True,
            "active_preset_id": "auto",
            "active_preset_name": "Авто-оркестратор (подбор по доменам)",
            "base_preset_id": clean_id,
            "base_preset_name": base_name,
            "zapret_mode": "auto",
            "applied": applied,
        }

    def add_user_zapret_preset(
        self,
        name: str,
        content: str,
        description: str = "",
        is_working: bool = True,
        activate: bool = True,
        preset_id: str | None = None,
    ) -> dict[str, Any]:
        """Validate, compile-check, and store a user's working Zapret2 preset (full file, .bat, or --lua-desync)."""
        # Dry-run compile first so broken presets fail loudly with a clear message
        compile_zapret_preset(
            content,
            bin_dir=self.bin_dir,
            lists_dir=self.lists_dir,
            game_filter=True,
        )
        storage = Storage(self.db_path)
        try:
            saved = save_user_zapret_preset(
                storage,
                name=name,
                content=content,
                description=description,
                is_working=is_working,
                source="user",
                preset_id=preset_id,
            )
        finally:
            storage.close()

        selected: dict[str, Any] | None = None
        if activate:
            selected = self.select_zapret_preset(saved["id"])
        return {
            "ok": True,
            "preset": saved,
            "activated": bool(activate),
            "selected": selected,
        }

    def import_zapret_preset_file(
        self,
        file_path: str | Path,
        name: str | None = None,
        is_working: bool = True,
        activate: bool = True,
    ) -> dict[str, Any]:
        """Import a .txt (winws2) or .bat (zapret1) preset file into user presets and optionally activate."""
        p = Path(file_path)
        if not p.is_file():
            raise FileNotFoundError(f"Файл пресета не найден: {p}")
        storage = Storage(self.db_path)
        try:
            saved = import_preset_from_file(storage, p, name=name, is_working=is_working)
            try:
                compile_zapret_preset(
                    str(saved["content"]),
                    bin_dir=self.bin_dir,
                    lists_dir=self.lists_dir,
                    game_filter=True,
                )
            except Exception:
                storage.delete_zapret_preset(saved["id"])
                raise
        finally:
            storage.close()

        selected = self.select_zapret_preset(saved["id"]) if activate else None
        return {
            "ok": True,
            "preset": saved,
            "activated": bool(activate),
            "selected": selected,
        }

    def import_zapret_presets_from_dir(
        self,
        dir_path: str | Path | None = None,
        max_files: int = 25,
    ) -> dict[str, Any]:
        """Bulk-import Zapret2 presets from a user-selected directory."""
        target_dir: Path | None = Path(dir_path) if dir_path is not None and str(dir_path).strip() else None
        if target_dir is None:
            for cand in DEFAULT_EXTERNAL_ZAPRET_DIRS:
                if cand.is_dir():
                    target_dir = cand
                    break
        if target_dir is None or not target_dir.is_dir():
            raise FileNotFoundError(
                f"Папка пресетов не найдена: {target_dir or '<не указана>'}"
            )

        storage = Storage(self.db_path)
        try:
            imported = import_presets_from_directory(storage, target_dir, max_files=max_files)
        finally:
            storage.close()

        return {
            "ok": True,
            "dir_path": str(target_dir),
            "imported_count": len(imported),
            "imported": imported,
        }

    def delete_zapret_preset(self, preset_id: str) -> dict[str, Any]:
        """Delete a user-saved Zapret2 preset and return to 'auto' if it was active."""
        clean_id = (preset_id or "").strip()
        was_active = False
        storage = Storage(self.db_path)
        try:
            deleted = storage.delete_zapret_preset(clean_id)
            if deleted and storage.get_setting("active_zapret_preset_id", "auto") == clean_id:
                storage.set_setting("active_zapret_preset_id", "auto")
                was_active = True
        finally:
            storage.close()
        if was_active:
            self.trigger_apply_configs()
            self._reload_running_services(winws2=True, singbox=True)
        return {"ok": deleted, "deleted": deleted, "reset_to_auto": was_active}

    def _save_preset_test_rate(
        self,
        storage: Storage,
        preset_id: str,
        success_rate: float,
    ) -> None:
        if not preset_id or preset_id == "auto":
            return
        if storage.get_zapret_preset(preset_id) is not None:
            storage.update_zapret_preset_test_stats(
                preset_id,
                success_rate=success_rate,
                is_working=success_rate >= 60.0,
            )
            return
        raw_stats = storage.get_setting("builtin_preset_stats", "{}")
        stats_map = _safe_json_loads(raw_stats, dict)
        if not isinstance(stats_map, dict):
            stats_map = {}
        stats_map[preset_id] = {
            "success_rate": round(float(success_rate), 1),
            "last_tested_at": _now_iso(),
            "is_working": success_rate >= 60.0,
        }
        storage.set_setting("builtin_preset_stats", json.dumps(stats_map))

    # ---------------------------------------------------------------- Live Connectivity Tests & Success Tracking

    def run_connectivity_tests(
        self,
        domains: list[str] | None = None,
        *,
        include_key_services: bool = True,
        include_picked_domains: bool = False,
        timeout: float = 3.5,
        probe_fn: Any | None = None,
    ) -> dict[str, Any]:
        """Run real live HTTPS/TCP connectivity checks against YouTube/Discord/Telegram and/or picked domains."""
        proc_state = self._collect_processes_state()
        sb_running = bool((proc_state.get("sing-box") or {}).get("running"))

        storage = Storage(self.db_path)
        try:
            net_key, _, _, _ = self._resolve_network_info(storage)
            active_preset_id, active_preset_name, _ = self._resolve_active_zapret_preset(storage)
            decisions = storage.get_decisions(net_key, active_only=True)
        finally:
            storage.close()

        dec_by_dom: dict[str, Decision] = {}
        for d in decisions:
            low = d.domain.lower()
            if low not in dec_by_dom or d.protocol == Protocol.TLS:
                dec_by_dom[low] = d

        known_targets = {t["domain"].lower(): t for t in DEFAULT_SERVICE_TEST_TARGETS}
        targets: list[dict[str, Any]] = []
        seen_doms: set[str] = set()

        def _add_target(
            dom: str,
            *,
            label: str = "",
            url: str = "",
            service_group: str = "",
            min_bytes: int = 0,
        ) -> None:
            clean = dom.strip().lower()
            if not clean or clean in seen_doms:
                return
            seen_doms.add(clean)
            known = known_targets.get(clean)
            targets.append(
                {
                    "domain": clean,
                    "label": label or (str(known["label"]) if known else clean),
                    "url": url or (str(known["url"]) if known else f"https://{clean}/"),
                    "service_group": service_group or (str(known["service_group"]) if known else infer_service_group(clean)),
                    "min_bytes": int(min_bytes or (known.get("min_bytes", 0) if known else 0)),
                }
            )

        if domains:
            for d in domains:
                _add_target(d)
        else:
            if include_key_services:
                for item in DEFAULT_SERVICE_TEST_TARGETS:
                    _add_target(
                        str(item["domain"]),
                        label=str(item["label"]),
                        url=str(item["url"]),
                        service_group=str(item["service_group"]),
                        min_bytes=int(item.get("min_bytes") or 0),
                    )
            if include_picked_domains:
                picked_sorted = sorted(
                    dec_by_dom.values(),
                    key=lambda x: (0 if x.layer in ("dpi", "vpn", "dns") else 1, x.domain.lower()),
                )
                for dec in picked_sorted[:20]:
                    _add_target(dec.domain)

        probe_accepts_min_bytes = bool(
            probe_fn is not None and "min_bytes" in inspect.signature(probe_fn).parameters
        )

        async def _run_all() -> list[dict[str, Any]]:
            sem = asyncio.Semaphore(8)

            async def _one(t: dict[str, Any]) -> dict[str, Any]:
                async with sem:
                    dom = str(t["domain"])
                    dec = dec_by_dom.get(dom)
                    # Route via sing-box mixed HTTP proxy only when domain is explicitly assigned to VPN/DNS layer
                    proxy_url = (
                        "http://127.0.0.1:2080"
                        if (sb_running and dec is not None and dec.layer in ("vpn", "dns"))
                        else None
                    )
                    if probe_fn is not None:
                        if probe_accepts_min_bytes:
                            res = await probe_fn(
                                dom,
                                url=str(t["url"]),
                                service_group=str(t["service_group"]),
                                proxy_url=proxy_url,
                                timeout=timeout,
                                min_bytes=int(t.get("min_bytes") or 0),
                            )
                        else:
                            res = await probe_fn(
                                dom,
                                url=str(t["url"]),
                                service_group=str(t["service_group"]),
                                proxy_url=proxy_url,
                                timeout=timeout,
                            )
                    else:
                        res = await probe_domain_connectivity(
                            dom,
                            url=str(t["url"]),
                            service_group=str(t["service_group"]),
                            proxy_url=proxy_url,
                            timeout=timeout,
                            min_bytes=int(t.get("min_bytes") or 0),
                        )
                    item = dict(res)
                    item["label"] = str(t["label"])
                    item["layer"] = dec.layer if dec is not None else ("preset" if active_preset_id != "auto" else "direct")
                    item["strategy_id"] = (dec.strategy_id or "") if dec is not None else ""
                    return item

            return list(await asyncio.gather(*(_one(t) for t in targets)))

        results = _run_coro_sync(_run_all()) if targets else []
        passed = sum(1 for r in results if r.get("ok"))
        total = len(results)
        rate = round((passed / total) * 100.0, 1) if total else 0.0

        storage = Storage(self.db_path)
        try:
            for r in results:
                storage.record_domain_test(
                    net_key,
                    str(r["domain"]),
                    ok=bool(r.get("ok")),
                    service_group=str(r.get("service_group") or infer_service_group(str(r["domain"]))),
                    preset_id=active_preset_id,
                    strategy_id=str(r.get("strategy_id") or ""),
                    status_code=r.get("status_code"),
                    latency_ms=r.get("latency_ms"),
                    stage=str(r.get("stage") or "https"),
                    error=str(r.get("error") or ""),
                )
            if include_key_services and total > 0 and active_preset_id != "auto":
                self._save_preset_test_rate(storage, active_preset_id, rate)
            summary = storage.get_overall_test_summary(net_key, window=10)
        finally:
            storage.close()

        return {
            "ok": True,
            "network_key": net_key,
            "active_preset_id": active_preset_id,
            "active_preset_name": active_preset_name,
            "passed": passed,
            "total": total,
            "success_rate": rate,
            "results": results,
            "summary": summary,
        }

    def test_zapret_preset(
        self,
        preset_id: str | None = None,
        *,
        activate_if_needed: bool = False,
        timeout: float = 3.5,
        probe_fn: Any | None = None,
    ) -> dict[str, Any]:
        """Test a Zapret2 preset (or the currently active one) against YouTube/Discord/Telegram and save its % rate."""
        target_id = (preset_id or "").strip()
        if target_id and activate_if_needed:
            self.select_zapret_preset(target_id)
            time.sleep(0.3)

        report = self.run_connectivity_tests(
            include_key_services=True,
            include_picked_domains=False,
            timeout=timeout,
            probe_fn=probe_fn,
        )
        effective_id = target_id or str(report.get("active_preset_id") or "")
        if effective_id and effective_id != "auto" and report["total"] > 0:
            storage = Storage(self.db_path)
            try:
                self._save_preset_test_rate(storage, effective_id, float(report["success_rate"]))
            finally:
                storage.close()
        return report

    def run_diag_sync(
        self,
        domains: list[str] | None = None,
        live_eval: bool = True,
        timeout: float = 2.5,
        targets_file: str | Path = "configs/targets.yaml",
    ) -> list[dict[str, Any]]:
        """Run probe diagnostics, strategy selection, DB persistence, and config generation synchronously."""
        if domains:
            target_domains = list(dict.fromkeys(d.strip() for d in domains if d and d.strip()))
        else:
            effective_targets: str | Path = targets_file
            if str(targets_file).replace("\\", "/") == "configs/targets.yaml":
                cand = self.configs_dir / "targets.yaml"
                if cand.is_file():
                    effective_targets = cand
            entries = load_targets_from_yaml(effective_targets)
            target_domains = list(dict.fromkeys(e["domain"] for e in entries if e.get("domain")))

        if not target_domains:
            return self.get_domain_rows()

        async def _run() -> str:
            bypass = detect_bypass_active()
            net = await detect_network_fingerprint(timeout=timeout)
            can_live_eval = bool(live_eval and _is_admin() and not bypass)
            eval_fn = (
                (lambda d, ip, s: live_winws2_strategy_evaluator(d, ip, s, bin_dir=self.bin_dir))
                if can_live_eval
                else None
            )

            storage = Storage(self.db_path)
            try:
                net_key = storage.upsert_network(net)
                self._seed_default_strategies(storage)
                candidates: list[Strategy] = storage.get_strategies()
                vpn_available = storage.has_usable_vpn()
                existing_map = {
                    (d.domain.lower(), d.protocol): d
                    for d in storage.get_decisions(net_key, active_only=True)
                }

                probes_list = await asyncio.gather(
                    *(run_domain_probes(dom, timeout=timeout) for dom in target_domains)
                )
                reports = [
                    classify_probes(domain=dom, probes=probes, network=net, bypass_active=bypass)
                    for dom, probes in zip(target_domains, probes_list)
                ]

                domains_info: list[tuple[str, str, list[VerdictClass]]] = []
                for dom, probes, report in zip(target_domains, probes_list, reports):
                    storage.save_verdict(net_key, report, protocol=Protocol.TLS)
                    ip = probes.tcp.target_ip or (
                        probes.dns.doh_ips[0]
                        if probes.dns.doh_ips
                        else (probes.dns.system_ips[0] if probes.dns.system_ips else "127.0.0.1")
                    )
                    domains_info.append((dom, ip, report.verdicts))

                if len(target_domains) == 1:
                    dom0, ip0, v0 = domains_info[0]
                    decisions_map = {
                        dom0: await select_best_strategy(
                            network_key=net_key,
                            domain=dom0,
                            ip=ip0,
                            verdicts=v0,
                            candidates=candidates,
                            protocol=Protocol.TLS,
                            evaluator=eval_fn,
                            early_stop=True,
                            vpn_available=vpn_available,
                        )
                    }
                else:
                    decisions_map = await evaluate_domains_live_batch(
                        domains_info=domains_info,
                        network_key=net_key,
                        candidates=candidates,
                        bin_dir=self.bin_dir,
                        use_live_eval=can_live_eval,
                        vpn_available=vpn_available,
                    )

                quic_tasks = []
                for dom, ip, verdicts in domains_info:
                    cand_dec = decisions_map[dom]
                    prev_dec = (
                        existing_map.get((dom.lower(), Protocol.TLS))
                        or existing_map.get((normalize_domain_etld1(dom), Protocol.TLS))
                    )
                    # Self-probe protection: when bypass is already active and probes report OK,
                    # preserve the working active DPI/VPN/DNS rule instead of downgrading to direct.
                    if (
                        bypass
                        and cand_dec.layer == "direct"
                        and prev_dec is not None
                        and (
                            prev_dec.layer in ("dpi", "dns")
                            or (
                                prev_dec.layer == "vpn"
                                and (vpn_available or getattr(prev_dec, "pinned", False))
                            )
                        )
                    ):
                        continue
                    if (
                        bypass
                        and not can_live_eval
                        and prev_dec is not None
                        and prev_dec.layer == "dpi"
                        and cand_dec.layer == "dpi"
                        and cand_dec.strategy_id == prev_dec.strategy_id
                    ):
                        # Current DPI strategy still fails while bypass is active: rotate to next fallback instead of re-saving pool[0]
                        promote_fallback_on_failure(storage, prev_dec, vpn_available=vpn_available)
                    else:
                        storage.save_decision(cand_dec)
                    if VerdictClass.QUIC_BLOCK in verdicts:
                        report = next(r for r in reports if r.domain == dom)
                        storage.save_verdict(net_key, report, protocol=Protocol.QUIC)
                        quic_tasks.append(
                            select_best_strategy(
                                network_key=net_key,
                                domain=dom,
                                ip=ip,
                                verdicts=[VerdictClass.QUIC_BLOCK],
                                candidates=candidates,
                                protocol=Protocol.QUIC,
                                evaluator=eval_fn if len(target_domains) == 1 else None,
                                early_stop=True,
                                vpn_available=vpn_available,
                            )
                        )

                if quic_tasks:
                    quic_decisions = await asyncio.gather(*quic_tasks)
                    for qdec in quic_decisions:
                        storage.save_decision(qdec)

                return net_key
            finally:
                storage.close()

        net_key = _run_coro_sync(_run())
        self.trigger_apply_configs()
        self._reload_running_services(winws2=True, singbox=True)
        return self.get_domain_rows(net_key=net_key)

    def find_best_bypass_for_domain(
        self,
        domain: str,
        *,
        timeout: float = 3.0,
        probe_fn: Any | None = None,
        dns_roll_fn: Any | None = None,
    ) -> dict[str, Any]:
        """Force-test across layers (Direct -> diverse DPI families -> SmartDNS -> VPN) and persist the best working rule."""
        dom = (domain or "").strip().lower()
        if not dom:
            raise ValueError("Domain cannot be empty")

        procs = self._collect_processes_state()
        winws_running = bool((procs.get("winws2") or {}).get("running"))
        sb_running = bool((procs.get("sing-box") or {}).get("running"))
        is_adm = _is_admin()

        storage = Storage(self.db_path)
        try:
            self._seed_default_strategies(storage)
            net_key, _, _, _ = self._resolve_network_info(storage)
            strategies = storage.get_strategies()
            has_real_vpn = storage.has_usable_vpn()
            stack_mode = storage.get_setting("stack_mode", "hybrid").strip().lower() or "hybrid"
            can_dns = stack_mode != "dpi_only"
            norm_dom = normalize_domain_etld1(dom)
            existing = next(
                (
                    d
                    for d in storage.get_decisions(net_key, active_only=False)
                    if d.domain.lower() in (dom, norm_dom) and d.protocol == Protocol.TLS
                ),
                None,
            )
        finally:
            storage.close()

        def _test(proxy_url: str | None = None) -> dict[str, Any]:
            if probe_fn is not None:
                res = probe_fn(dom, proxy_url=proxy_url, timeout=timeout)
                if inspect.isawaitable(res):
                    return dict(_run_coro_sync(res))
                return dict(res)
            return dict(_run_coro_sync(probe_domain_connectivity(dom, proxy_url=proxy_url, timeout=timeout)))

        def _save_and_apply(dec: Decision, *, reload_winws: bool = False, reload_sb: bool = False) -> None:
            st = Storage(self.db_path)
            try:
                st.save_decision(dec)
            finally:
                st.close()
            self.trigger_apply_configs()
            if is_adm:
                if reload_winws and winws_running:
                    self.reload_winws2()
                if reload_sb and sb_running:
                    self.reload_singbox()

        tried: list[dict[str, Any]] = []
        winner: Decision | None = None
        winner_ms: float | None = None

        # Step A: Always test clean direct first (excluding domain from winws2 catch-all/preset/old DPI)
        direct_dec = Decision(
            network_key=net_key,
            domain=dom,
            protocol=Protocol.TLS,
            layer="direct",
            strategy_id=None,
            status="active",
            consecutive_fails=0,
        )
        if winws_running and is_adm and (existing is None or existing.layer != "direct"):
            _save_and_apply(
                direct_dec,
                reload_winws=True,
                reload_sb=(existing is not None and existing.layer in ("dns", "vpn")),
            )
            if probe_fn is None:
                time.sleep(0.25)

        res_direct = _test(proxy_url=None)
        tried.append(
            {
                "layer": "direct",
                "strategy_id": None,
                "ok": bool(res_direct.get("ok")),
                "latency_ms": res_direct.get("latency_ms"),
                "error": res_direct.get("error", ""),
            }
        )
        if res_direct.get("ok"):
            winner_ms = res_direct.get("latency_ms")
            direct_dec.ttfb_ms = winner_ms
            winner = direct_dec

        # Step B: Diverse DPI strategy families
        tls_pool = [s for s in _ordered_pool(strategies, Protocol.TLS) if s.args_template]
        if winner is None and tls_pool:
            diverse_cands: list[Strategy] = []
            seen_ids: set[str] = set()

            def _pick_first(pred: Any) -> None:
                for cand in tls_pool:
                    if cand.id not in seen_ids and pred(cand):
                        diverse_cands.append(cand)
                        seen_ids.add(cand.id)
                        return

            _pick_first(lambda s: s.family == "multisplit" and "fake" not in " ".join(s.args_template).lower())
            _pick_first(lambda s: s.family == "multidisorder" and "fake" not in " ".join(s.args_template).lower())
            _pick_first(lambda s: "fakedsplit" in s.family)
            _pick_first(lambda s: "hostfakesplit" in s.family)
            for cand in tls_pool:
                if len(diverse_cands) >= 4:
                    break
                if cand.id not in seen_ids:
                    diverse_cands.append(cand)
                    seen_ids.add(cand.id)

            for strat in diverse_cands[:4]:
                cand_dec = Decision(
                    network_key=net_key,
                    domain=dom,
                    protocol=Protocol.TLS,
                    layer="dpi",
                    strategy_id=strat.id,
                    fallback_strategies=_diverse_fallbacks(tls_pool, strat.id, strat.family),
                    status="active",
                    consecutive_fails=0,
                )
                if winws_running and is_adm:
                    _save_and_apply(cand_dec, reload_winws=True)
                    if probe_fn is None:
                        time.sleep(0.25)
                res_dpi = _test(proxy_url=None)
                tried.append(
                    {
                        "layer": "dpi",
                        "strategy_id": strat.id,
                        "ok": bool(res_dpi.get("ok")),
                        "latency_ms": res_dpi.get("latency_ms"),
                        "error": res_dpi.get("error", ""),
                    }
                )
                if res_dpi.get("ok"):
                    winner_ms = res_dpi.get("latency_ms")
                    cand_dec.ttfb_ms = winner_ms
                    winner = cand_dec
                    break

        # Step C: SmartDNS (when stack is not dpi_only)
        if winner is None and can_dns:
            if dns_roll_fn is not None:
                rolled = dns_roll_fn(dom, net_key)
                dns_dec = _run_coro_sync(rolled) if inspect.isawaitable(rolled) else rolled
            else:
                st_dns = Storage(self.db_path)
                try:
                    dns_dec = _run_coro_sync(
                        self.orchestrator.dns.roll_dns_for_domain(
                            dom,
                            network_key=net_key,
                            storage=st_dns,
                            timeout=min(timeout, 2.0),
                        )
                    )
                finally:
                    st_dns.close()

            if (
                isinstance(dns_dec, Decision)
                and dns_dec.layer == "dns"
                and (dns_dec.ttfb_ms is not None or dns_roll_fn is not None)
            ):
                _save_and_apply(dns_dec, reload_winws=True, reload_sb=True)
                res_dns = _test(proxy_url="http://127.0.0.1:2080" if sb_running else None)
                tried.append(
                    {
                        "layer": "dns",
                        "strategy_id": dns_dec.strategy_id,
                        "ok": bool(res_dns.get("ok")),
                        "latency_ms": res_dns.get("latency_ms"),
                        "error": res_dns.get("error", ""),
                    }
                )
                if res_dns.get("ok"):
                    winner_ms = res_dns.get("latency_ms")
                    dns_dec.ttfb_ms = winner_ms if winner_ms is not None else dns_dec.ttfb_ms
                    winner = dns_dec

        # Step D: VPN (only when usable VPN exists)
        if winner is None and has_real_vpn:
            vpn_dec = Decision(
                network_key=net_key,
                domain=dom,
                protocol=Protocol.TLS,
                layer="vpn",
                strategy_id="vpn-select",
                status="active",
                consecutive_fails=0,
            )
            _save_and_apply(vpn_dec, reload_winws=True, reload_sb=True)
            res_vpn = _test(proxy_url="http://127.0.0.1:2080" if sb_running else None)
            tried.append(
                {
                    "layer": "vpn",
                    "strategy_id": "vpn-select",
                    "ok": bool(res_vpn.get("ok")),
                    "latency_ms": res_vpn.get("latency_ms"),
                    "error": res_vpn.get("error", ""),
                }
            )
            if res_vpn.get("ok"):
                winner_ms = res_vpn.get("latency_ms")
                vpn_dec.ttfb_ms = winner_ms
                winner = vpn_dec

        if winner is not None:
            _save_and_apply(winner, reload_winws=True, reload_sb=(winner.layer in ("dns", "vpn")))
        elif existing is not None:
            _save_and_apply(existing, reload_winws=True, reload_sb=(existing.layer in ("dns", "vpn")))
        elif tls_pool:
            fb_strat = tls_pool[0]
            fallback_dec = Decision(
                network_key=net_key,
                domain=dom,
                protocol=Protocol.TLS,
                layer="dpi",
                strategy_id=fb_strat.id,
                fallback_strategies=_diverse_fallbacks(tls_pool, fb_strat.id, fb_strat.family),
                status="degraded",
            )
            _save_and_apply(fallback_dec, reload_winws=True)

        return {
            "ok": winner is not None,
            "domain": dom,
            "winner": (
                {"layer": winner.layer, "strategy_id": winner.strategy_id, "latency_ms": winner_ms}
                if winner is not None
                else None
            ),
            "tried": tried,
            "rows": self.get_domain_rows(net_key=net_key),
        }

    @staticmethod
    def _probe_cloud_32kb_sync(proxy_url: str | None = None, timeout: float = 3.5) -> bool:
        """Verify >32KB TCP stream completion (catches 16KB TSPU drops invisible to small TLS checks)."""
        try:
            import httpx

            with httpx.Client(proxy=proxy_url, timeout=timeout, follow_redirects=True) as client:
                resp = client.get("https://speed.cloudflare.com/__down?bytes=32768")
                return resp.status_code == 200 and len(resp.content) >= 32768
        except Exception:
            return False

    def find_best_bypass_for_bundle(
        self,
        bundle_id_or_exe: str,
        *,
        timeout: float = 3.0,
        probe_fn: Any | None = None,
        udp_check_fn: Any | None = None,
        allow_downshift: bool = True,
    ) -> dict[str, Any]:
        """Auto-select the best indivisible route for an AppBundle (`direct_clean -> direct_dpi -> vpn`)."""
        raw = (bundle_id_or_exe or "").strip()
        if not raw:
            raise ValueError("Укажите игру, программу или имя .exe процесса")

        st = Storage(self.db_path)
        try:
            net_key, _, _, _ = self._resolve_network_info(st)
            bundles = load_bundles(self.bundles_path, storage=st)
            raw_low = raw.lower()
            bundle = next((b for b in bundles if b.id.lower() == raw_low or b.name.lower() == raw_low), None)
            if bundle is None:
                bundle = match_process_to_bundle(raw, bundles, exe_path=raw)
            if bundle is None and (".exe" in raw_low or "/" in raw or "\\" in raw):
                exe_name = Path(raw.replace("\\", "/")).name
                if exe_name:
                    created = self.add_custom_bundle(Path(exe_name).stem or exe_name, exe_name, mode="direct_clean")
                    bundles = load_bundles(self.bundles_path, storage=st)
                    bundle = next((b for b in bundles if b.id == created.get("id")), None)
            if bundle is None:
                raise ValueError(f"Не найден профиль приложения или .exe: {raw}")

            mode_map = st.get_bundle_modes(net_key)
            rec = mode_map.get(bundle.id) or {}
            prev_mode = str(rec.get("mode") or bundle.default_mode or "direct_clean").strip().lower()
            if prev_mode not in BUNDLE_MODES:
                prev_mode = "direct_clean"
            has_real_vpn = st.has_usable_vpn()
            stack_mode = st.get_setting("stack_mode", "hybrid").strip().lower() or "hybrid"
        finally:
            st.close()

        running_map = expand_running_bundle_processes([bundle])
        is_running = bool((running_map.get(bundle.id) or {}).get("running"))
        procs = self._collect_processes_state()
        sb_running = bool((procs.get("sing-box") or {}).get("running"))

        probe_targets = list(dict.fromkeys([*bundle.auth_domains[:2], *CLOUD_GAMING_BEACONS[:2]]))
        if not probe_targets:
            probe_targets = list(CLOUD_GAMING_BEACONS[:2])

        def _probe_targets(proxy_url: str | None) -> tuple[bool, float | None, str]:
            latencies: list[float] = []
            for dom in probe_targets:
                if probe_fn is not None:
                    res = probe_fn(dom, proxy_url=proxy_url, timeout=timeout)
                    res_d = dict(_run_coro_sync(res)) if inspect.isawaitable(res) else dict(res)
                else:
                    res_d = dict(_run_coro_sync(probe_domain_connectivity(dom, proxy_url=proxy_url, timeout=timeout)))
                if not res_d.get("ok"):
                    return False, None, str(res_d.get("error") or f"failed:{dom}")
                if res_d.get("latency_ms") is not None:
                    latencies.append(float(res_d["latency_ms"]))
            avg_ms = round(sum(latencies) / len(latencies), 1) if latencies else None
            return True, avg_ms, ""

        bundle_procs_low = {p.lower() for p in bundle.processes}
        with self.orchestrator.monitor._lock:
            has_alert_16kb = any(
                bool(a.get("stalled_16kb"))
                and (
                    str(a.get("bundle_id") or "").lower() == bundle.id.lower()
                    or str(a.get("process") or "").lower() in bundle_procs_low
                )
                for a in self.orchestrator.monitor.pending_bundle_alerts
            )
            has_stat_16kb = any(
                int(cnt.get("stalled_16kb", 0)) > 0
                and (
                    p_name.lower() in bundle_procs_low
                    or match_process_to_bundle(p_name, [bundle]) is not None
                )
                for p_name, cnt in self.orchestrator.monitor._last_stalled_direct_procs.items()
            )
            has_alert_udp = any(
                bool(a.get("stalled_udp"))
                and (
                    str(a.get("bundle_id") or "").lower() == bundle.id.lower()
                    or str(a.get("process") or "").lower() in bundle_procs_low
                )
                for a in self.orchestrator.monitor.pending_bundle_alerts
            )
            has_stat_udp = any(
                int(cnt.get("stalled_udp", 0)) > 0
                and (
                    p_name.lower() in bundle_procs_low
                    or match_process_to_bundle(p_name, [bundle]) is not None
                )
                for p_name, cnt in self.orchestrator.monitor._last_stalled_direct_procs.items()
            )
        has_16kb_tcp_stall = has_alert_16kb or has_stat_16kb
        has_udp_stall = has_alert_udp or has_stat_udp

        ladder: list[str] = []
        if allow_downshift:
            ladder = ["direct_clean", "direct_dpi", "vpn"]
        else:
            start_idx = BUNDLE_MODES.index(prev_mode) if prev_mode in BUNDLE_MODES else 0
            ladder = list(BUNDLE_MODES[start_idx + 1 :]) or [prev_mode]

        tried: list[dict[str, Any]] = []
        winner_mode: str | None = None
        udp_check: dict[str, Any] = {"ok": True, "reason": ""}

        for cand_mode in ladder:
            if (
                cand_mode == "direct_dpi"
                and not allow_downshift
                and has_16kb_tcp_stall
                and has_real_vpn
                and stack_mode != "dpi_only"
            ):
                tried.append({"mode": "direct_dpi", "ok": False, "latency_ms": None, "error": "skipped_16kb_tcp_stall"})
                continue
            if (
                cand_mode == "direct_dpi"
                and not allow_downshift
                and has_udp_stall
                and bool(getattr(self, "_last_game_udp_dpi", False))
                and has_real_vpn
                and stack_mode != "dpi_only"
            ):
                tried.append({"mode": "direct_dpi", "ok": False, "latency_ms": None, "error": "skipped_udp_dpi_already_active"})
                continue

            if cand_mode == "vpn":
                if not has_real_vpn or stack_mode == "dpi_only":
                    tried.append({"mode": "vpn", "ok": False, "latency_ms": None, "error": "no_usable_vpn"})
                    continue
                udp_check = (
                    dict(udp_check_fn())
                    if udp_check_fn is not None
                    else self.check_vpn_udp_reachability()
                )
                if not udp_check.get("ok") and bundle.category == "game" and bundle.coupling == "tight":
                    tried.append(
                        {
                            "mode": "vpn",
                            "ok": False,
                            "latency_ms": None,
                            "error": str(udp_check.get("reason") or "udp_unavailable"),
                        }
                    )
                    continue

            self.set_bundle_mode(bundle.id, cand_mode, pinned=False)
            if cand_mode == "vpn" and sb_running:
                probe_port = 2081 if _is_tcp_port_open(2081) else 2080
                proxy_arg = f"http://127.0.0.1:{probe_port}"
            else:
                proxy_arg = None
            ok_step, step_ms, step_err = _probe_targets(proxy_arg)
            if ok_step and cand_mode == "direct_dpi" and not allow_downshift and probe_fn is None and bundle.category == "game":
                if not self._probe_cloud_32kb_sync(None, timeout=min(timeout, 3.5)):
                    ok_step, step_err = False, "cloud_32kb_stall"
            tried.append({"mode": cand_mode, "ok": ok_step, "latency_ms": step_ms, "error": step_err})
            if ok_step:
                winner_mode = cand_mode
                break

        final_mode = winner_mode or prev_mode
        self.set_bundle_mode(bundle.id, final_mode, pinned=False)
        self.dismiss_bundle_alert(bundle.id)
        exit_ip_changed = (winner_mode is not None) and ((prev_mode == "vpn") != (winner_mode == "vpn"))
        restart_hint = (
            "Перезапустите игру/программу, чтобы применить новый IP-маршрут."
            if exit_ip_changed
            else ""
        )
        return {
            "ok": winner_mode is not None,
            "bundle_id": bundle.id,
            "bundle_name": bundle.name,
            "prev_mode": prev_mode,
            "mode": final_mode,
            "winner": {"layer": winner_mode, "mode": winner_mode} if winner_mode else None,
            "exit_ip_changed": exit_ip_changed,
            "restart_hint": restart_hint,
            "udp_check": udp_check,
            "tried": tried,
            "running": is_running,
            "targets": probe_targets,
        }

    def trigger_apply_configs(
        self,
        iface: int | None = None,
        strategy_filter: str | None = None,
    ) -> dict[str, Any]:
        """Generate winws2 preset, hostlist files, and sing-box config from current DB decisions."""
        if iface is not None and (iface <= 0 or iface > 65535):
            raise ValueError(f"Invalid network interface index (iface={iface})")

        with self._lock:
            storage = Storage(self.db_path)
            try:
                self._seed_default_strategies(storage)
                strategies = {s.id: s for s in storage.get_strategies()}
                if strategy_filter is not None and strategy_filter not in strategies:
                    raise KeyError(f"Unknown strategy profile: {strategy_filter}")
                net_key, _, _, _ = self._resolve_network_info(storage)
                raw_vpn_nodes = storage.get_all_subscription_nodes()
                vpn_server_hosts = {
                    str(n.get("server") or "").strip().lower().rstrip(".")
                    for n in raw_vpn_nodes
                    if n.get("server")
                }

                def _is_stale_infra(domain: str) -> bool:
                    if is_dns_infra_domain(domain):
                        return True
                    low = (domain or "").strip().lower().rstrip(".")
                    return bool(
                        low
                        and any(
                            low == h or low.endswith("." + h) or low == normalize_domain_etld1(h)
                            for h in vpn_server_hosts
                        )
                    )

                stale_infra = [
                    d
                    for d in storage.get_decisions(net_key, active_only=False)
                    if _is_stale_infra(d.domain) and not getattr(d, "pinned", False)
                ]
                if stale_infra:
                    with storage.conn:
                        for d in stale_infra:
                            storage.conn.execute(
                                "DELETE FROM decisions WHERE network_key = ? AND domain = ? AND protocol = ?",
                                (net_key, d.domain, d.protocol.value),
                            )
                decisions = storage.get_decisions(net_key, active_only=True)
                if strategy_filter is not None:
                    decisions = [d for d in decisions if d.strategy_id == strategy_filter]
                vpn_nodes = [VpnNode(**n) for n in raw_vpn_nodes]
                game_filter = storage.get_setting("game_filter", "0") == "1"
                active_dns = self.orchestrator.dns.get_active_dns(storage)
                base_dns = self.orchestrator.dns.get_base_dns(storage, net_key=net_key)
                all_dns_servers = self.orchestrator.dns.get_all_dns_servers(storage)
                dns_catalog_map = {s["id"]: s for s in all_dns_servers}
                network_profile = storage.get_network_profile(net_key)
                bundles = load_bundles(self.bundles_path, storage=storage)
                bundle_mode_map = storage.get_bundle_modes(net_key)
                telegram_mode = self.get_telegram_mode(storage)
                byedpi_fallback = storage.get_setting("byedpi_fallback", "0") == "1"
                stack_mode = storage.get_setting("stack_mode", "hybrid").strip().lower() or "hybrid"
                if stack_mode not in ("hybrid", "dpi_only"):
                    stack_mode = "hybrid"
                tun_stack = storage.get_setting("tun_stack", "mixed").strip() or "mixed"
                if tun_stack not in ("gvisor", "mixed", "system"):
                    tun_stack = "mixed"
                active_preset_id, active_preset_name, active_preset = self._resolve_active_zapret_preset(storage)
                base_preset_id, base_preset_name, base_preset = self._resolve_base_zapret_preset(storage)
                vpn_processes = self.get_vpn_processes(storage, net_key=net_key)
                vpn_policy = storage.get_vpn_selection_policy()
                health_map = storage.get_vpn_node_health_map()
                quarantined_tags = {
                    tag
                    for tag, rec in health_map.items()
                    if str(rec.get("cb_state") or "") == "open"
                    and not self.orchestrator.vpn._is_quarantine_expired(str(rec.get("quarantined_until") or ""))
                }
                guard = build_unlocker_protection_context(storage=storage, hosts_path=self.hosts_path)
                if guard["enabled"]:
                    prot_doms = set(guard["domains"])
                    explicit_per_dns = {
                        d.domain.lower()
                        for d in decisions
                        if d.layer == "dns" and isinstance(d.strategy_id, str) and d.strategy_id.startswith("dns:")
                    }
                    # Purge non-pinned conflicting DPI/VPN overrides from DB for hosts/Antigravity-managed domains
                    cleaned_any = False
                    with storage.conn:
                        for d in decisions:
                            low = d.domain.lower()
                            if (
                                not getattr(d, "pinned", False)
                                and d.layer in ("dpi", "vpn")
                                and any(low == pd or low.endswith("." + pd) for pd in prot_doms)
                            ):
                                storage.conn.execute(
                                    "DELETE FROM decisions WHERE network_key = ? AND domain = ? AND protocol = ?",
                                    (net_key, d.domain, d.protocol.value),
                                )
                                cleaned_any = True
                    if cleaned_any:
                        decisions = storage.get_decisions(net_key, active_only=True)
                if strategy_filter is not None:
                    decisions = [d for d in decisions if d.strategy_id == strategy_filter]
                if guard["enabled"]:
                    exclude_domains = [
                        dom for dom in guard["domains"] if dom not in explicit_per_dns
                    ]
                    exclude_ips = list(guard["proxy_ips"])
                    extra_procs = list(guard["processes"])
                else:
                    exclude_domains = []
                    exclude_ips = []
                    extra_procs = []
            finally:
                storage.close()

            all_excluded_ips = [n.server for n in vpn_nodes if n.server] + exclude_ips
            compiled_bundles = compile_bundle_rules(
                bundles,
                bundle_mode_map,
                running_map=expand_running_bundle_processes(bundles),
            )
            dns_infra_ips: list[str] = []
            dns_infra_domains: list[str] = []
            for srv in all_dns_servers:
                ip_s = str(srv.get("ip") or "").strip()
                if ip_s:
                    dns_infra_ips.append(ip_s)
                doh_s = str(srv.get("doh_url") or "").strip()
                if doh_s.startswith("https://"):
                    host_s = (urllib.parse.urlparse(doh_s).hostname or "").strip().lower()
                    if host_s:
                        dns_infra_domains.append(host_s)
            isp_best_tls = str((network_profile or {}).get("best_tls_strategy") or "").strip() or None
            profile_quic_blocked = bool((network_profile or {}).get("quic_blocked"))
            bundle_pass_domains = list(compiled_bundles["pass_domains"])
            bundle_dpi_domains = list(compiled_bundles.get("dpi_auth_domains") or ())
            profile_meta = (network_profile or {}).get("meta") if isinstance(network_profile, dict) else {}
            if not isinstance(profile_meta, dict):
                profile_meta = {}
            isp_dpi_active = bool(
                profile_quic_blocked
                or profile_meta.get("sni_dpi_detected")
                or profile_meta.get("throttle_detected")
                or any(d.layer == "dpi" and d.status == "active" for d in decisions)
            )
            z2_lists = self.lists_dir / "zapret2"
            has_cloud_ipsets = any(
                (z2_lists / fname).is_file() and (z2_lists / fname).stat().st_size > 0
                for fname in ("ipset-amazon.txt", "ipset-ovh.txt", "ipset-cloudflare.txt", "ipset-hetzner.txt", "ipset-digitalocean.txt")
            )
            enable_game_udp_dpi = bool(compiled_bundles["enable_game_udp_dpi"] or (isp_dpi_active and has_cloud_ipsets))
            self._last_pass_domains_sig = tuple(bundle_pass_domains)
            self._last_game_udp_dpi = bool(enable_game_udp_dpi or game_filter)
            effective_iface = (
                iface
                if iface is not None
                else (detect_physical_egress_iface() if stack_mode != "dpi_only" else None)
            )
            hostlists: dict[str, list[str]] = {}
            winws_args: list[str] = []
            preset_error = ""
            enable_tg_ipset = (telegram_mode != "mtproto")
            if active_preset is not None and active_preset_id != "auto":
                try:
                    winws_args = compile_zapret_preset(
                        str(active_preset["content"]),
                        bin_dir=self.bin_dir,
                        lists_dir=self.lists_dir,
                        vpn_server_ips=all_excluded_ips,
                        exclude_domains=exclude_domains,
                        iface=effective_iface,
                        game_filter=game_filter,
                        enable_telegram_ipset=enable_tg_ipset,
                    )
                except Exception as exc:  # noqa: BLE001
                    preset_error = f"Ошибка пресета «{active_preset_name}»: {exc}"
                    active_preset_id = "auto"
                    active_preset_name = "Авто-оркестратор (подбор по доменам)"
                    winws_args = []
            self._last_preset_error = preset_error

            has_vpn_nodes = has_usable_vpn_nodes(vpn_nodes)
            has_real_vpn = stack_mode != "dpi_only" and has_vpn_nodes
            singbox_decisions = decisions
            winws_decisions = decisions
            if not has_real_vpn:
                # Never route non-pinned rules into sing-box VPN when no usable VPN exists;
                # persist vpn->dpi only when no usable VPN nodes exist at all so toggling dpi_only preserves DB rules.
                singbox_decisions = [
                    d for d in decisions if not (d.layer == "vpn" and not getattr(d, "pinned", False))
                ]
                if active_preset_id == "auto":
                    tls_pool = _ordered_pool(list(strategies.values()), Protocol.TLS)
                    quic_pool = _ordered_pool(list(strategies.values()), Protocol.QUIC)
                    pool_by_proto = {
                        Protocol.TLS: tls_pool,
                        Protocol.QUIC: quic_pool,
                    }
                    remapped: list[Decision] = []
                    to_persist: list[Decision] = []
                    for d in decisions:
                        if d.layer == "vpn" and not getattr(d, "pinned", False):
                            proto_pool = pool_by_proto.get(d.protocol, [])
                            fb_id = proto_pool[0].id if proto_pool else None
                            if fb_id:
                                converted = d.model_copy(
                                    update={
                                        "layer": "dpi",
                                        "strategy_id": fb_id,
                                        "fallback_strategies": [
                                            s.id for s in proto_pool if s.id != fb_id and s.args_template
                                        ][:2],
                                        "status": "active",
                                        "consecutive_fails": 0,
                                    }
                                )
                                remapped.append(converted)
                                if not has_vpn_nodes:
                                    to_persist.append(converted)
                            continue
                        remapped.append(d)
                    winws_decisions = remapped
                    if to_persist:
                        st = Storage(self.db_path)
                        try:
                            for dec in to_persist:
                                st.save_decision(dec)
                        finally:
                            st.close()

            if not winws_args:
                if active_preset_id == "auto" and base_preset is not None:
                    auto_args, hostlists = generate_winws2_config(
                        decisions=winws_decisions,
                        strategies=strategies,
                        lists_dir=self.lists_dir,
                        vpn_server_ips=all_excluded_ips,
                        enable_circular_catchall=False,
                        iface=effective_iface,
                        game_filter=game_filter,
                        exclude_domains=exclude_domains,
                        expand_cdn_domains=True,
                        enable_tcp_in=True,
                        enable_telegram_ipset=enable_tg_ipset,
                        isp_best_tls=isp_best_tls,
                        bundle_pass_domains=bundle_pass_domains,
                        bundle_dpi_domains=bundle_dpi_domains,
                        bin_dir=self.bin_dir,
                        enable_game_udp_dpi=enable_game_udp_dpi,
                        dns_infra_ips=dns_infra_ips,
                        dns_infra_domains=dns_infra_domains,
                    )
                    base_exclude = sorted(
                        set(exclude_domains)
                        | {
                            d.domain.lower()
                            for d in decisions
                            if d.domain and d.layer in ("dpi", "vpn")
                        }
                        | set(bundle_pass_domains)
                    )
                    try:
                        base_args = compile_zapret_preset(
                            str(base_preset["content"]),
                            bin_dir=self.bin_dir,
                            lists_dir=self.lists_dir,
                            vpn_server_ips=all_excluded_ips,
                            exclude_domains=base_exclude,
                            iface=effective_iface,
                            game_filter=game_filter,
                            exclude_filename="exclude_base_preset_domains.txt",
                            enable_telegram_ipset=enable_tg_ipset,
                        )
                        winws_args = merge_winws2_base_preset(auto_args, base_args)
                    except Exception as exc:  # noqa: BLE001
                        self._last_preset_error = f"Ошибка базового пресета «{base_preset_name}»: {exc}"
                        winws_args = []
                if not winws_args:
                    winws_args, hostlists = generate_winws2_config(
                        decisions=winws_decisions,
                        strategies=strategies,
                        lists_dir=self.lists_dir,
                        vpn_server_ips=all_excluded_ips,
                        iface=effective_iface,
                        game_filter=game_filter,
                        exclude_domains=exclude_domains,
                        expand_cdn_domains=True,
                        enable_tcp_in=True,
                        enable_telegram_ipset=enable_tg_ipset,
                        isp_best_tls=isp_best_tls,
                        bundle_pass_domains=bundle_pass_domains,
                        bundle_dpi_domains=bundle_dpi_domains,
                        bin_dir=self.bin_dir,
                        enable_game_udp_dpi=enable_game_udp_dpi,
                        dns_infra_ips=dns_infra_ips,
                        dns_infra_domains=dns_infra_domains,
                    )
            self.configs_dir.mkdir(parents=True, exist_ok=True)
            winws_file = self.configs_dir / "winws2_preset.txt"
            winws_file.write_text("\n".join(winws_args) + "\n", encoding="utf-8")

            badges = list(active_dns.get("badges") or [])
            doh_url = str(active_dns.get("doh_url") or "")
            use_https = ("DoH" in badges) or doh_url.startswith("https://")
            dns_type = "https" if use_https else "udp"
            doh_path = "/dns-query"
            doh_tls_sni: str | None = None
            if doh_url.startswith("https://"):
                parsed = urllib.parse.urlparse(doh_url)
                if parsed.path:
                    doh_path = parsed.path
                if parsed.hostname:
                    doh_tls_sni = parsed.hostname

            xray_file = self.configs_dir / "xray.json"
            xray_exe = self.bin_dir.resolve() / "xray.exe"
            xray_bridge_ports: dict[str, int] = {}
            xray_valid = True
            xray_err = ""
            if stack_mode != "dpi_only" and xray_exe.is_file() and any(needs_xray_bridge(n) for n in vpn_nodes):
                _xcfg, candidate_ports = generate_xray_bridge_config(
                    vpn_nodes,
                    output_path=xray_file,
                    dns_server=str(active_dns.get("ip") or "1.1.1.1"),
                    enable_byedpi=byedpi_fallback,
                )
                if candidate_ports:
                    xray_hash = hashlib.sha256(xray_file.read_bytes()).hexdigest()
                    try:
                        xray_mtime = int(xray_exe.stat().st_mtime_ns)
                    except OSError:
                        xray_mtime = 0
                    xray_sig = (xray_hash, xray_mtime)
                    if self._last_xray_check == xray_sig:
                        xray_valid, xray_err = True, ""
                    else:
                        xray_valid, xray_err = validate_xray_config(self.bin_dir, xray_file)
                        self._last_xray_check = xray_sig if xray_valid else None
                    if xray_valid:
                        xray_bridge_ports = candidate_ports
                        if xray_hash != self._last_xray_config_hash:
                            st_xray_heal = Storage(self.db_path)
                            try:
                                with st_xray_heal.conn:
                                    for tag_key in candidate_ports:
                                        st_xray_heal.conn.execute(
                                            """
                                            UPDATE vpn_node_health
                                            SET cb_state = 'half_open', consecutive_fails = 0, quarantined_until = ''
                                            WHERE node_tag = ? AND cb_state = 'open' AND last_error = 'protocol_block'
                                            """,
                                            (tag_key,),
                                        )
                            finally:
                                st_xray_heal.close()
                            self._last_xray_config_hash = xray_hash
                    else:
                        xray_file.unlink(missing_ok=True)
                else:
                    xray_file.unlink(missing_ok=True)
            else:
                xray_file.unlink(missing_ok=True)

            quic_blocked_domains = sorted(
                {
                    *(QUIC_HOSTLIST_DOMAINS if profile_quic_blocked else ()),
                    *(
                        d.domain.lower()
                        for d in singbox_decisions
                        if d.protocol == Protocol.QUIC and d.layer in ("dpi", "direct")
                    ),
                }
            )
            effective_vpn_procs = sorted({*vpn_processes, *compiled_bundles["vpn_processes"]}, key=str.lower)
            # Rule #0 contains only internal/unlocker infra processes — NEVER dump bundle direct_processes
            # here or Rule #0 will silently override rs-bundles-vpn / vpn_processes.
            effective_bypass_procs = sorted(set(extra_procs), key=str.lower)
            rulesets_payload = build_singbox_rulesets_payload(
                singbox_decisions,
                bypass_domains=exclude_domains,
                enable_byedpi=byedpi_fallback,
                smartdns_domains=list(AI_GEOBLOCK_DOMAINS),
                bundle_rules=compiled_bundles,
                quic_blocked_domains=quic_blocked_domains,
                vpn_processes=effective_vpn_procs,
                telegram_mode=telegram_mode,
            )
            self.ruleset_server.update_rulesets(rulesets_payload)
            self._last_rulesets_payload_hash = hashlib.sha256(
                json.dumps(rulesets_payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
            ).hexdigest()
            ruleset_base_url = self.ruleset_server.base_url if self.ruleset_server.is_running else None

            primary_is_smartdns = str(active_dns.get("category") or "").strip().lower() == "ai_bypass"
            singbox_file = self.configs_dir / "sing-box.json"
            generate_singbox_config(
                decisions=singbox_decisions,
                vpn_nodes=vpn_nodes,
                output_path=singbox_file,
                doh_server=str(active_dns.get("ip") or doh_tls_sni or "1.1.1.1"),
                dns_type=dns_type,
                doh_path=doh_path,
                dns_catalog=dns_catalog_map,
                bypass_domains=exclude_domains,
                extra_bypass_processes=effective_bypass_procs,
                clash_api_addr=self.clash_api.controller_addr,
                clash_api_secret=self.clash_api.secret,
                quarantined_tags=quarantined_tags,
                enable_byedpi=byedpi_fallback,
                use_wireguard_endpoints=True,
                doh_tls_sni=doh_tls_sni,
                tun_stack=tun_stack,
                vpn_selection_mode=vpn_policy["mode"],
                preferred_vpn_node=vpn_policy["priority_node"] or None,
                xray_bridge_ports=xray_bridge_ports or None,
                vpn_processes=effective_vpn_procs,
                bypass_ips=exclude_ips,
                primary_is_smartdns=primary_is_smartdns,
                smartdns_domains=list(AI_GEOBLOCK_DOMAINS),
                base_dns=base_dns,
                bundle_rules=compiled_bundles,
                ruleset_base_url=ruleset_base_url,
                quic_blocked_domains=quic_blocked_domains,
                telegram_mode=telegram_mode,
                tun_interface_name=self._tun_interface_name,
            )
            sb_hash = hashlib.sha256(singbox_file.read_bytes()).hexdigest()
            sb_exe = self.bin_dir.resolve() / "sing-box.exe"
            try:
                sb_mtime = int(sb_exe.stat().st_mtime_ns) if sb_exe.is_file() else 0
            except OSError:
                sb_mtime = 0
            sb_sig = (sb_hash, sb_mtime)
            if self._last_singbox_check == sb_sig:
                sb_valid, sb_err = True, ""
            else:
                sb_valid, sb_err = validate_singbox_config(self.bin_dir, singbox_file)
                self._last_singbox_check = sb_sig if sb_valid else None
            return {
                "winws2_preset": str(winws_file),
                "singbox_config": str(singbox_file),
                "singbox_valid": sb_valid,
                "singbox_check_error": sb_err,
                "xray_config": str(xray_file) if xray_bridge_ports else "",
                "xray_bridge_count": len(xray_bridge_ports),
                "xray_valid": xray_valid,
                "xray_check_error": xray_err,
                "hostlists_count": len(hostlists),
                "hostlists": sorted(hostlists.keys()),
                "vpn_nodes_count": len(vpn_nodes),
                "winws2_args": winws_args,
                "active_preset_id": active_preset_id,
                "active_preset_name": active_preset_name,
                "base_preset_id": base_preset_id,
                "base_preset_name": base_preset_name,
                "zapret_mode": "preset" if active_preset_id != "auto" else "auto",
                "preset_compile_error": preset_error,
                "tun_stack": tun_stack,
                "winws2_iface": effective_iface,
                "vpn_processes": effective_vpn_procs,
                "base_dns": base_dns,
                "telegram_mode": telegram_mode,
                "network_profile": network_profile,
                "bundles_count": len(bundles),
                "ruleset_url": ruleset_base_url or "",
            }

    def get_tg_ws_secret(self, storage: Storage | None = None) -> str:
        """Return (and lazily persist) a persistent 32-hex secret for the local Telegram MTProto proxy."""
        own_st = False
        st = storage
        if st is None:
            st = Storage(self.db_path)
            own_st = True
        try:
            raw = st.get_setting("tg_ws_secret", "").strip().lower()
            if len(raw) == 32:
                try:
                    bytes.fromhex(raw)
                    return raw
                except ValueError:
                    pass
            generated = secrets.token_hex(16)
            st.set_setting("tg_ws_secret", generated)
            return generated
        finally:
            if own_st:
                st.close()

    def get_telegram_proxy_info(
        self,
        processes: dict[str, Any] | None = None,
        secret: str | None = None,
    ) -> dict[str, Any]:
        """Build 1-click Telegram MTProto deep-link metadata (`tg://proxy?...`)."""
        clean_secret = (secret or "").strip().lower() or self.get_tg_ws_secret()
        dd_secret = f"dd{clean_secret}"
        procs = processes if processes is not None else self._collect_processes_state()
        running = bool((procs.get("tg-ws-proxy") or {}).get("running"))
        mode = self.get_telegram_mode()
        return {
            "host": "127.0.0.1",
            "port": 10808,
            "secret": clean_secret,
            "dd_secret": dd_secret,
            "url": f"tg://proxy?server=127.0.0.1&port=10808&secret={dd_secret}",
            "running": running,
            "mode": mode,
        }

    def get_stack_mode(self) -> str:
        storage = Storage(self.db_path)
        try:
            mode = storage.get_setting("stack_mode", "hybrid").strip().lower()
            return mode if mode in ("hybrid", "dpi_only") else "hybrid"
        finally:
            storage.close()

    def set_stack_mode(self, mode: str) -> dict[str, Any]:
        clean = (mode or "").strip().lower()
        if clean not in ("hybrid", "dpi_only"):
            raise ValueError(f"Unsupported stack_mode: {mode!r}")
        with self._lock:
            storage = Storage(self.db_path)
            try:
                storage.set_setting("stack_mode", clean)
            finally:
                storage.close()
            applied = self.trigger_apply_configs()
            procs = self._collect_processes_state()
            winws_running = bool((procs.get("winws2") or {}).get("running"))
            sb_running = bool((procs.get("sing-box") or {}).get("running"))
            if clean == "dpi_only":
                if self._supervisor is None:
                    self._supervisor = ProcessSupervisor(
                        bin_dir=self.bin_dir.resolve(),
                        logs_dir=self.logs_dir.resolve(),
                    )
                    self._supervisor.adopt_persisted_state()
                self._supervisor.stop_process("sing-box")
                self._supervisor.stop_process("xray")
                self.ruleset_server.stop()
                self._last_xray_hash = ""
                if _is_admin() and winws_running:
                    self.reload_winws2()
            else:
                # Reload winws2 with physical --wf-iface BEFORE starting sing-box TUN
                if _is_admin() and winws_running:
                    self.reload_winws2()
                if _is_admin() and (winws_running or self._desired_running) and not sb_running:
                    self.reload_singbox()
            return {"stack_mode": clean, "applied": applied}

    def set_tun_stack(self, stack: str) -> dict[str, Any]:
        clean = (stack or "").strip().lower()
        if clean not in ("gvisor", "mixed", "system"):
            raise ValueError(f"Unsupported tun_stack: {stack!r}")
        storage = Storage(self.db_path)
        try:
            storage.set_setting("tun_stack", clean)
        finally:
            storage.close()
        applied = self.trigger_apply_configs()
        self._reload_running_services(singbox=True)
        return {"tun_stack": clean, "applied": applied}

    @staticmethod
    def _detect_local_gateway_ip() -> str:
        """Fast (<1ms) physical uplink interface + gateway detection, falling back to UDP egress IP."""
        phys_idx, phys_gw = detect_physical_egress_route()
        if phys_idx is not None:
            return f"{phys_idx}:{phys_gw}"
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(0.2)
            sock.connect(("1.1.1.1", 53))
            return str(sock.getsockname()[0] or "")
        except OSError:
            return ""
        finally:
            sock.close()

    def _build_winws2_cmd(self, winws_args: list[str]) -> list[str]:
        from netdoctor.cli import _resolve_winws2_live_args, build_winws2_launch_cmd

        bin_path = self.bin_dir.resolve()
        lists_path = self.lists_dir.resolve()
        configs_path = self.configs_dir.resolve()
        winws2_exe = bin_path / "winws2.exe"
        debug_log = False
        try:
            st = Storage(self.db_path)
            try:
                debug_log = st.get_setting("winws2_debug_log", "0") == "1"
            finally:
                st.close()
        except Exception:  # noqa: BLE001
            debug_log = False
        live_args = _resolve_winws2_live_args(
            winws_args,
            lists_path,
            debug_log=debug_log,
            bin_path=bin_path,
        )
        return build_winws2_launch_cmd(
            winws2_exe,
            live_args,
            configs_dir=configs_path,
            bin_path=bin_path,
        )

    def _build_stack_specs(
        self,
        winws_args: list[str],
        singbox_file: Path,
        *,
        xray_file: Path | None = None,
        xray_bridge_count: int = 0,
    ) -> list[tuple[str, list[str], Path | None]]:
        bin_path = self.bin_dir.resolve()
        specs: list[tuple[str, list[str], Path | None]] = []

        byedpi_enabled = False
        stack_mode = "hybrid"
        telegram_mode = "mtproto"
        tg_secret = "0123456789abcdef0123456789abcdef"
        try:
            st = Storage(self.db_path)
            try:
                byedpi_enabled = st.get_setting("byedpi_fallback", "0") == "1"
                stack_mode = st.get_setting("stack_mode", "hybrid").strip().lower() or "hybrid"
                telegram_mode = self.get_telegram_mode(st)
                tg_secret = self.get_tg_ws_secret(st)
            finally:
                st.close()
        except Exception:  # noqa: BLE001
            byedpi_enabled = False

        if telegram_mode == "mtproto":
            tg_script = bin_path / "tg-ws-proxy" / "proxy" / "tg_ws_proxy.py"
            tg_exe = bin_path / "tg-ws-proxy" / "TgWsProxy_windows.exe"
            if tg_script.is_file():
                specs.append(
                    (
                        "tg-ws-proxy",
                        [
                            sys.executable,
                            "-u",
                            str(tg_script),
                            "--host",
                            "127.0.0.1",
                            "--port",
                            "10808",
                            "--secret",
                            tg_secret,
                        ],
                        tg_script.parent.parent,
                    )
                )
            elif tg_exe.is_file():
                specs.append(("tg-ws-proxy", [str(tg_exe)], tg_exe.parent))

        ciadpi_exe = bin_path / "ciadpi.exe"
        if byedpi_enabled and ciadpi_exe.is_file():
            specs.append(
                (
                    "byedpi",
                    [str(ciadpi_exe), "--ip", "127.0.0.1", "--port", "10809", "--disorder", "1", "--tlsrec", "1+s"],
                    bin_path,
                )
            )

        specs.append(("winws2", self._build_winws2_cmd(winws_args), bin_path))
        if stack_mode != "dpi_only":
            xray_exe = bin_path / "xray.exe"
            if xray_bridge_count > 0 and xray_exe.is_file() and xray_file is not None and xray_file.is_file():
                specs.append(("xray", [str(xray_exe), "run", "-c", str(xray_file.resolve())], bin_path))
            singbox_exe = bin_path / "sing-box.exe"
            specs.append(("sing-box", [str(singbox_exe), "run", "-c", str(singbox_file.resolve())], bin_path))
        return specs

    @staticmethod
    def _has_xray_inbounds(xray_file: Path) -> bool:
        if not xray_file.is_file():
            return False
        try:
            data = json.loads(xray_file.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            return False
        inbounds = data.get("inbounds") if isinstance(data, dict) else None
        return bool(isinstance(inbounds, list) and len(inbounds) > 0)

    def ensure_xray_binary(self, *, force: bool = False) -> Path | None:
        """Download official XTLS/Xray-core xray.exe into bin_dir if missing or forced."""
        with self._deps_lock:
            try:
                return _run_coro_sync(fetch_xray_binary(self.bin_dir, force=force))
            except Exception:  # noqa: BLE001
                return None

    def _refresh_stale_subscriptions_if_needed(self, max_age_sec: float = 3600.0) -> bool:
        """Refresh HTTP(S) VPN subscriptions on startup when cached nodes are older than max_age_sec."""
        try:
            storage = Storage(self.db_path)
        except Exception:  # noqa: BLE001
            return False
        try:
            subs = storage.get_subscriptions()
            if not subs:
                return False
            now_utc = datetime.now(timezone.utc)
            needs_refresh = False
            for sub in subs:
                url = str(sub.get("url_or_uri") or "").strip().lower()
                if not url.startswith(("http://", "https://")):
                    continue
                raw_ts = str(sub.get("updated_at") or "").strip()
                if not raw_ts:
                    needs_refresh = True
                    break
                try:
                    dt = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    age_sec = (now_utc - dt.astimezone(timezone.utc)).total_seconds()
                except ValueError:
                    age_sec = max_age_sec
                if age_sec >= max_age_sec:
                    needs_refresh = True
                    break
            if not needs_refresh:
                return False
            results = _run_coro_sync(refresh_all_subscriptions(storage, timeout=5.0))
            return any(count > 0 for count in results.values())
        except Exception:  # noqa: BLE001
            return False
        finally:
            storage.close()

    def _schedule_stale_subscription_refresh(self) -> None:
        """Refresh stale HTTP(S) subscriptions asynchronously after bypass startup."""
        if self._sub_refresh_in_progress:
            return
        self._sub_refresh_in_progress = True

        def _worker() -> None:
            try:
                if self._refresh_stale_subscriptions_if_needed() and self._desired_running and not self._stopping:
                    self.trigger_apply_configs()
                    self._reload_running_services(singbox=True)
            except Exception:  # noqa: BLE001
                pass
            finally:
                self._sub_refresh_in_progress = False

        threading.Thread(
            target=_worker,
            name="netdoctor-sub-refresh",
            daemon=True,
        ).start()

    def _restart_xray(self) -> dict[str, Any]:
        """Start or reload managed xray.exe SOCKS5 Reality bridge via ProcessSupervisor."""
        with self._lock:
            bin_path = self.bin_dir.resolve()
            xray_exe = bin_path / "xray.exe"
            xray_file = (self.configs_dir / "xray.json").resolve()
            if not xray_exe.is_file() or not self._has_xray_inbounds(xray_file):
                return {"ok": False, "reloaded": False, "error": "xray.exe or active xray.json not available"}
            if self._supervisor is None:
                self._supervisor = ProcessSupervisor(bin_dir=bin_path, logs_dir=self.logs_dir.resolve())
                self._supervisor.adopt_persisted_state()
            try:
                proc = self._supervisor.reload_process(
                    "xray",
                    [str(xray_exe), "run", "-c", str(xray_file)],
                    cwd=bin_path,
                )
                try:
                    self._last_xray_hash = hashlib.sha256(xray_file.read_bytes()).hexdigest()
                except OSError:
                    self._last_xray_hash = ""
                return {"ok": True, "reloaded": True, "pid": proc.pid}
            except OSError as exc:
                return {"ok": False, "reloaded": False, "error": str(exc)}

    def _restart_tg_ws_proxy(self) -> dict[str, Any]:
        """Restart tg-ws-proxy via ProcessSupervisor if crashed."""
        with self._lock:
            bin_path = self.bin_dir.resolve()
            tg_script = bin_path / "tg-ws-proxy" / "proxy" / "tg_ws_proxy.py"
            tg_exe = bin_path / "tg-ws-proxy" / "TgWsProxy_windows.exe"
            if tg_script.is_file():
                cmd = [
                    sys.executable,
                    "-u",
                    str(tg_script),
                    "--host",
                    "127.0.0.1",
                    "--port",
                    "10808",
                    "--secret",
                    self.get_tg_ws_secret(),
                ]
                cwd = tg_script.parent.parent
            elif tg_exe.is_file():
                cmd = [str(tg_exe)]
                cwd = tg_exe.parent
            else:
                return {"ok": False, "error": "tg-ws-proxy binary not found"}

            if self._supervisor is None:
                self._supervisor = ProcessSupervisor(bin_dir=bin_path, logs_dir=self.logs_dir.resolve())
                self._supervisor.adopt_persisted_state()
            try:
                proc = self._supervisor.reload_process("tg-ws-proxy", cmd, cwd=cwd)
                return {"ok": True, "reloaded": True, "pid": proc.pid}
            except OSError as exc:
                return {"ok": False, "reloaded": False, "error": str(exc)}

    def elevate_gui(self) -> dict[str, Any]:
        """Relaunch the GUI with Administrator privileges via UAC prompt and replace this process."""
        return elevate_gui(
            db_path=self.db_path,
            configs_dir=self.configs_dir,
            lists_dir=self.lists_dir,
            logs_dir=self.logs_dir,
            bin_dir=self.bin_dir,
            replace_pid=os.getpid(),
            auto_start=False,
        )

    _TUN_INTERFACE_CANDIDATES: tuple[str, ...] = ("netdoctor-tun", "netdoctor-tun2", "netdoctor-tun3")

    @staticmethod
    def _wait_wintun_gone(iface_name: str, timeout: float = 1.5) -> None:
        target = (iface_name or "netdoctor-tun").strip().lower()
        deadline = time.monotonic() + max(0.0, timeout)
        while time.monotonic() < deadline:
            try:
                ifaces = {k.lower() for k in psutil.net_if_addrs()}
            except Exception:  # noqa: BLE001
                break
            if target not in ifaces:
                break
            time.sleep(0.15)
        time.sleep(0.25)

    def _rotate_tun_interface_name(self) -> str:
        cands = self._TUN_INTERFACE_CANDIDATES
        cur = self._tun_interface_name
        idx = (cands.index(cur) + 1) % len(cands) if cur in cands else 0
        self._tun_interface_name = cands[idx]
        return self._tun_interface_name

    def _is_wintun_exists_error(self) -> bool:
        tail = _read_tail_lines(self.logs_dir / "sing-box.log", max_lines=12).lower()
        return "cannot create a file when that file already exists" in tail

    def _retry_singbox_after_wintun_collision(self, sup: ProcessSupervisor, iface: int | None) -> tuple[Any, dict[str, Any]]:
        time.sleep(0.6)
        self._rotate_tun_interface_name()
        applied = self.trigger_apply_configs(iface=iface)
        singbox_file = Path(applied["singbox_config"]).resolve()
        bin_path = self.bin_dir.resolve()
        cmd = [str(bin_path / "sing-box.exe"), "run", "-c", str(singbox_file)]
        proc = sup.reload_process("sing-box", cmd, cwd=bin_path)
        time.sleep(0.35)
        return proc, applied

    def start_services(self, iface: int | None = None, force: bool = False) -> dict[str, Any]:
        """Verify elevation and conflicts, regenerate configs, and start the supervised process stack."""
        if not _is_admin():
            return {
                "ok": False,
                "started": False,
                "requires_admin": True,
                "error": (
                    "Administrator privileges required (UAC elevation / WinError 740) "
                    "to start winws2 and sing-box TUN."
                ),
                "processes": self._collect_processes_state(),
            }

        if iface is not None and (iface <= 0 or iface > 65535):
            return {
                "ok": False,
                "started": False,
                "requires_admin": False,
                "error": f"Invalid network interface index (iface={iface})",
                "processes": self._collect_processes_state(),
            }

        stack_mode = self.get_stack_mode()
        deps_report: dict[str, Any] | None = None
        if not self.has_core_binaries(stack_mode):
            deps_report = self.ensure_deps(force=False)

        if (
            stack_mode != "dpi_only"
            and (self.bin_dir.resolve() / "sing-box.exe").is_file()
            and not (self.bin_dir.resolve() / "xray.exe").is_file()
        ):
            try:
                st_xray = Storage(self.db_path)
                try:
                    needs_xray = any(needs_xray_bridge(n) for n in st_xray.get_all_subscription_nodes())
                finally:
                    st_xray.close()
            except Exception:  # noqa: BLE001
                needs_xray = False
            if needs_xray:
                self.ensure_xray_binary()

        with self._lock:
            self.stop_services()
            self._stopping = False
            self._shutting_down = False

            if not force and detect_bypass_active():
                return {
                    "ok": False,
                    "started": False,
                    "requires_admin": False,
                    "conflict": True,
                    "error": "Conflicting host bypass or VPN adapter is already active. Stop it first or pass force=True.",
                    "processes": self._collect_processes_state(),
                }

            clear_vpn_dns_cache()
            if stack_mode != "dpi_only":
                self.ruleset_server.start()
            applied = self.trigger_apply_configs(iface=iface)
            bin_path = self.bin_dir.resolve()
            winws2_exe = bin_path / "winws2.exe"
            singbox_exe = bin_path / "sing-box.exe"
            stack_mode = self.get_stack_mode()
            missing_core = not winws2_exe.is_file() or (stack_mode != "dpi_only" and not singbox_exe.is_file())
            if missing_core:
                fetch_err = deps_report.get("fetch_error") if isinstance(deps_report, dict) else None
                detail = f": {fetch_err}" if fetch_err else ""
                return {
                    "ok": False,
                    "started": False,
                    "requires_admin": False,
                    "error": f"Missing required binaries in {bin_path} (auto-download failed{detail}).",
                    "applied": applied,
                    "processes": self._collect_processes_state(),
                }
            if stack_mode != "dpi_only" and not applied.get("singbox_valid", True):
                return {
                    "ok": False,
                    "started": False,
                    "requires_admin": False,
                    "error": f"Invalid sing-box.json: {applied.get('singbox_check_error')}",
                    "applied": applied,
                    "processes": self._collect_processes_state(),
                }

            xray_cfg_str = str(applied.get("xray_config") or "").strip()
            specs = self._build_stack_specs(
                winws_args=applied["winws2_args"],
                singbox_file=Path(applied["singbox_config"]),
                xray_file=Path(xray_cfg_str) if xray_cfg_str else None,
                xray_bridge_count=int(applied.get("xray_bridge_count") or 0),
            )
            sup = ProcessSupervisor(bin_dir=bin_path, logs_dir=self.logs_dir.resolve())
            try:
                sup.start_stack(specs, startup_wait=0.35, skip_stop=True)
            except OSError as exc:
                self._supervisor = None
                return {
                    "ok": False,
                    "started": False,
                    "requires_admin": getattr(exc, "winerror", None) == 740,
                    "error": str(exc),
                    "applied": applied,
                    "processes": self._collect_processes_state(),
                }
            except Exception as exc:
                self._supervisor = None
                return {
                    "ok": False,
                    "started": False,
                    "requires_admin": False,
                    "error": str(exc),
                    "applied": applied,
                    "processes": self._collect_processes_state(),
                }

            if stack_mode != "dpi_only":
                sb_proc = sup.processes.get("sing-box")
                if sb_proc is not None and sb_proc.poll() is not None and self._is_wintun_exists_error():
                    try:
                        sb_proc, applied = self._retry_singbox_after_wintun_collision(sup, iface)
                    except OSError as exc:
                        sup.stop_process("sing-box")
                        self._supervisor = sup
                        return {
                            "ok": False,
                            "started": False,
                            "requires_admin": getattr(exc, "winerror", None) == 740,
                            "error": str(exc),
                            "applied": applied,
                            "processes": self._collect_processes_state(),
                        }
                if sb_proc is not None and sb_proc.poll() is not None:
                    rc = sb_proc.poll()
                    sup.stop_process("sing-box")
                    log_tail = _read_tail_lines(self.logs_dir / "sing-box.log", max_lines=8).strip()
                    reason = f"sing-box exited prematurely on start with code {rc}"
                    if log_tail:
                        reason = f"{reason}: {log_tail.splitlines()[-1].strip()[:180]}"
                    self._supervisor = sup
                    return {
                        "ok": False,
                        "started": False,
                        "requires_admin": False,
                        "error": reason,
                        "applied": applied,
                        "processes": self._collect_processes_state(),
                    }

            self._supervisor = sup
            self._desired_running = True
            self._last_winws2_hash = self._winws2_args_hash(applied["winws2_args"])
            self._last_winws2_reload_ts = time.monotonic()
            self._pending_winws2_reload = False
            self._pending_singbox_reload = False
            self._clash_conn_traffic.clear()
            self._last_stateful_session_ts = 0.0
            try:
                sb_cfg_path = Path(applied["singbox_config"])
                self._last_singbox_hash = (
                    hashlib.sha256(sb_cfg_path.read_bytes()).hexdigest() if sb_cfg_path.is_file() else ""
                )
            except OSError:
                self._last_singbox_hash = ""
            try:
                xray_cfg_path = Path(xray_cfg_str) if xray_cfg_str else None
                self._last_xray_hash = (
                    hashlib.sha256(xray_cfg_path.read_bytes()).hexdigest()
                    if xray_cfg_path is not None and xray_cfg_path.is_file()
                    else ""
                )
            except OSError:
                self._last_xray_hash = ""
            self._last_singbox_reload_ts = time.monotonic()
            self._last_gateway_ip = self._detect_local_gateway_ip()
            self._gw_change_pending = ""
            self._watchdog_timestamps.clear()
            self._watchdog_next_retry_ts = 0.0
            self._service_retry_ts.clear()
            self._service_fail_counts.clear()
            try:
                st = Storage(self.db_path)
                try:
                    st.set_setting("stack_desired_running", "1")
                finally:
                    st.close()
            except Exception:  # noqa: BLE001
                pass
            if stack_mode != "dpi_only" and int(applied.get("vpn_nodes_count") or 0) > 0:
                threading.Thread(
                    target=self._sync_singbox_vpn_selector,
                    kwargs={"retries": 4},
                    name="netdoctor-vpn-sync",
                    daemon=True,
                ).start()
            self._schedule_stale_subscription_refresh()
            return {
                "ok": True,
                "started": True,
                "requires_admin": False,
                "services": [s[0] for s in specs],
                "processes": self._collect_processes_state(),
                "applied": applied,
            }

    def stop_services(self) -> list[str]:
        """Stop all active processes held by ProcessSupervisor and any persisted PIDs."""
        self._stopping = True
        self._shutting_down = True
        self._desired_running = False
        try:
            with self._lock:
                self._desired_running = False
                self._watchdog_next_retry_ts = 0.0
                self._pending_winws2_reload = False
                self._pending_singbox_reload = False
                self._clash_conn_traffic.clear()
                self._last_stateful_session_ts = 0.0
                self._gw_change_pending = ""
                self._last_xray_hash = ""
                self._service_retry_ts.clear()
                self._service_fail_counts.clear()
                try:
                    st = Storage(self.db_path)
                    try:
                        st.set_setting("stack_desired_running", "0")
                    finally:
                        st.close()
                except Exception:  # noqa: BLE001
                    pass
                stopped: list[str] = []
                if self._supervisor is not None:
                    self._supervisor.adopt_persisted_state()
                    all_names = list(
                        reversed(list(dict.fromkeys([*self._supervisor._adopted.keys(), *self._supervisor.processes.keys()])))
                    )
                    for name in all_names:
                        proc = self._supervisor.processes.get(name)
                        adopted = self._supervisor._adopted.get(name)
                        was_running = (proc is not None and proc.poll() is None) or bool(
                            adopted and adopted.get("running")
                        )
                        self._supervisor.stop_process(name)
                        if was_running:
                            stopped.append(name)
                    self._supervisor = None

                for name in stop_persisted_supervisor(logs_dir=self.logs_dir, bin_dir=self.bin_dir.resolve()):
                    if name not in stopped:
                        stopped.append(name)
                self.ruleset_server.stop()
                if "sing-box" in stopped:
                    self._wait_wintun_gone(self._tun_interface_name)
                return stopped
        finally:
            self._stopping = False
            self._shutting_down = False

    def reload_winws2(
        self,
        iface: int | None = None,
        *,
        applied: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Regenerate configs and hot-reload winws2 via ProcessSupervisor (or start if elevated)."""
        if iface is not None and (iface <= 0 or iface > 65535):
            return {
                "ok": False,
                "reloaded": False,
                "requires_admin": False,
                "error": f"Invalid network interface index (iface={iface})",
            }

        if _is_admin() and not (self.bin_dir.resolve() / "winws2.exe").is_file():
            self.ensure_deps(force=False)

        with self._lock:
            applied = applied if applied is not None else self.trigger_apply_configs(iface=iface)
            if not _is_admin():
                return {
                    "ok": False,
                    "reloaded": False,
                    "requires_admin": True,
                    "error": "Administrator privileges required (UAC) to start or reload winws2.",
                    "applied": applied,
                    "processes": self._collect_processes_state(),
                }

            bin_path = self.bin_dir.resolve()
            winws2_exe = bin_path / "winws2.exe"
            if not winws2_exe.is_file():
                return {
                    "ok": False,
                    "reloaded": False,
                    "requires_admin": False,
                    "error": f"winws2.exe not found in {bin_path}",
                    "applied": applied,
                    "processes": self._collect_processes_state(),
                }

            cmd = self._build_winws2_cmd(applied["winws2_args"])
            if self._supervisor is None:
                self._supervisor = ProcessSupervisor(bin_dir=bin_path, logs_dir=self.logs_dir.resolve())
                self._supervisor.adopt_persisted_state()

            try:
                proc = self._supervisor.reload_process("winws2", cmd, cwd=bin_path)
                time.sleep(0.35)
                rc = proc.poll()
                if rc is not None:
                    self._supervisor.stop_process("winws2")
                    log_tail = _read_tail_lines(self.logs_dir / "winws2.log", max_lines=8).strip()
                    reason = f"winws2 exited prematurely on reload with code {rc}"
                    if log_tail:
                        last_line = log_tail.splitlines()[-1].strip()
                        reason = f"{reason}: {last_line[:180]}"
                    self._last_crash_at = _now_iso()
                    self._last_crash_reason = reason
                    return {
                        "ok": False,
                        "reloaded": False,
                        "requires_admin": False,
                        "error": reason,
                        "applied": applied,
                        "processes": self._collect_processes_state(),
                    }
            except OSError as exc:
                return {
                    "ok": False,
                    "reloaded": False,
                    "requires_admin": getattr(exc, "winerror", None) == 740,
                    "error": str(exc),
                    "applied": applied,
                    "processes": self._collect_processes_state(),
                }

            self._last_winws2_hash = self._winws2_args_hash(applied["winws2_args"])
            self._last_winws2_reload_ts = time.monotonic()
            self._pending_winws2_reload = False
            return {
                "ok": True,
                "reloaded": True,
                "requires_admin": False,
                "pid": proc.pid,
                "applied": applied,
                "processes": self._collect_processes_state(),
            }

    def _scan_psutil_stateful_connections(self) -> list[dict[str, Any]]:
        """Inspect host TCP ESTABLISHED & UDP sockets via psutil for active game/voice/non-web traffic."""
        found: list[dict[str, Any]] = []
        vpn_procs = self.get_vpn_processes()
        for c in RealtimeConnectionMonitor._read_inet_connections():
            sock_type = getattr(c, "type", socket.SOCK_STREAM)
            is_tcp = sock_type == socket.SOCK_STREAM
            is_udp = sock_type == socket.SOCK_DGRAM
            if is_tcp:
                if str(getattr(c, "status", "") or "") != "ESTABLISHED":
                    continue
            elif not is_udp:
                continue

            pid = getattr(c, "pid", None)
            proc_name = self.orchestrator.monitor._resolve_pid_name(pid).lower()
            if (
                proc_name in _INTERNAL_PROXY_PROCESSES
                or proc_name in ("xray.exe", "tg-ws-proxy.exe")
                or "tgwsproxy" in proc_name
            ):
                continue

            is_game_proc = is_game_process(proc_name, extra_processes=vpn_procs)
            raddr = getattr(c, "raddr", None)
            if not raddr:
                # Windows games (Rainbow Six, Apex, etc.) typically use unconnected UDP sockets (raddr is empty)
                if is_udp and is_game_proc:
                    laddr = getattr(c, "laddr", None)
                    lport = int(getattr(laddr, "port", 0) if laddr else 0)
                    lip = str(getattr(laddr, "ip", "") or (laddr[0] if laddr and len(laddr) >= 1 else ""))
                    if lport > 0 and lport not in _LOCAL_UDP_NOISE_PORTS and lip not in ("127.0.0.1", "::1"):
                        found.append(
                            {
                                "process": proc_name,
                                "remote": f"*:{lport}",
                                "port": lport,
                                "stateful": True,
                                "flowing": True,
                            }
                        )
                continue
            rip = str(getattr(raddr, "ip", None) or (raddr[0] if len(raddr) >= 1 else ""))
            rport = int(getattr(raddr, "port", None) or (raddr[1] if len(raddr) >= 2 else 0))
            if not rip or not _is_external_ip(rip) or rport <= 0:
                continue

            if rport in _WEB_KEEPALIVE_PORTS and not is_game_proc:
                continue

            found.append(
                {
                    "process": proc_name,
                    "remote": f"{rip}:{rport}",
                    "port": rport,
                    "stateful": True,
                    "flowing": True,
                }
            )
        return found

    def _active_working_connections(self, *, service: str) -> list[dict[str, Any]]:
        """Return currently active working connections (stateful non-web/game sessions or actively flowing transfers)."""
        procs = self._collect_processes_state()
        sb_running = bool((procs.get("sing-box") or {}).get("running"))
        winws_running = bool((procs.get("winws2") or {}).get("running"))
        vpn_procs = self.get_vpn_processes()
        protected: list[dict[str, Any]] = []
        now = time.monotonic()

        def _grace_entry() -> list[dict[str, Any]]:
            with self._lock:
                last_ts = self._last_stateful_session_ts
            if last_ts > 0 and (now - last_ts) < _ACTIVE_SESSION_GRACE_SEC:
                return [
                    {
                        "process": "active_session_grace",
                        "remote": "grace",
                        "port": 0,
                        "stateful": True,
                        "flowing": False,
                    }
                ]
            return []

        if sb_running:
            try:
                conn_data = self.clash_api.get_connections_sync()
            except Exception:  # noqa: BLE001
                conn_data = {}
            raw_conns = conn_data.get("connections") if isinstance(conn_data, dict) else None
            if not isinstance(raw_conns, list):
                fallback = self._scan_psutil_stateful_connections()
                if fallback:
                    with self._lock:
                        self._last_stateful_session_ts = now
                    return fallback
                return _grace_entry()

            seen_ids: set[str] = set()
            with self._lock:
                for c in raw_conns:
                    if not isinstance(c, dict):
                        continue
                    meta = c.get("metadata") or {}
                    rip = str(meta.get("destinationIP") or "").strip()
                    try:
                        rport = int(meta.get("destinationPort") or 0)
                    except (TypeError, ValueError):
                        rport = 0
                    if not rip or not _is_external_ip(rip) or rport <= 0:
                        continue

                    raw_proc = str(meta.get("processPath") or "").strip()
                    proc_name = Path(raw_proc.replace("\\", "/")).name.lower() if raw_proc else ""
                    if proc_name and (
                        proc_name in _INTERNAL_PROXY_PROCESSES
                        or proc_name in ("xray.exe", "tg-ws-proxy.exe")
                        or "tgwsproxy" in proc_name
                    ):
                        continue

                    try:
                        up = int(c.get("upload") or 0)
                        dn = int(c.get("download") or 0)
                    except (TypeError, ValueError):
                        continue
                    is_game_proc = is_game_process(proc_name, extra_processes=vpn_procs)
                    if is_game_proc:
                        if up <= 0 and dn <= 0:
                            continue
                    elif up <= 0 or dn <= 0:
                        continue

                    total = up + dn
                    conn_id = str(c.get("id") or f"{proc_name}:{rip}:{rport}")
                    seen_ids.add(conn_id)
                    prev = self._clash_conn_traffic.get(conn_id)
                    if prev is not None:
                        prev_total, last_change_ts = prev
                        if total > prev_total:
                            self._clash_conn_traffic[conn_id] = (total, now)
                            actively_flowing = True
                        else:
                            actively_flowing = (now - last_change_ts) < _ACTIVE_FLOW_IDLE_SEC
                    else:
                        age_sec = _parse_clash_conn_age_sec(c.get("start"))
                        if age_sec is not None and age_sec >= _ACTIVE_FLOW_IDLE_SEC:
                            self._clash_conn_traffic[conn_id] = (total, now - _ACTIVE_FLOW_IDLE_SEC)
                            actively_flowing = False
                        else:
                            self._clash_conn_traffic[conn_id] = (total, now)
                            actively_flowing = True

                    is_stateful = (rport not in _WEB_KEEPALIVE_PORTS) or is_game_proc
                    if is_stateful:
                        self._last_stateful_session_ts = now
                    if is_stateful or actively_flowing:
                        protected.append(
                            {
                                "process": proc_name or "sing-box",
                                "remote": f"{rip}:{rport}",
                                "port": rport,
                                "stateful": is_stateful,
                                "flowing": actively_flowing,
                            }
                        )

                for stale_id in [k for k in self._clash_conn_traffic if k not in seen_ids]:
                    self._clash_conn_traffic.pop(stale_id, None)
            if protected:
                return protected
            return _grace_entry()

        if service == "winws2" and winws_running:
            found = self._scan_psutil_stateful_connections()
            if found:
                with self._lock:
                    self._last_stateful_session_ts = now
                return found
            return _grace_entry()

        return []

    def reload_winws2_if_changed(
        self,
        iface: int | None = None,
        min_interval_sec: float = 20.0,
        *,
        defer_if_active: bool = False,
    ) -> dict[str, Any]:
        """Hot-reload winws2 ONLY if its generated args changed AND cooldown interval elapsed."""
        with self._lock:
            applied = self.trigger_apply_configs(iface=iface)
            new_hash = self._winws2_args_hash(applied["winws2_args"])
            procs = self._collect_processes_state()
            winws_running = bool((procs.get("winws2") or {}).get("running"))
            if winws_running and self._last_winws2_hash and new_hash == self._last_winws2_hash:
                self._pending_winws2_reload = False
                return {
                    "ok": True,
                    "reloaded": False,
                    "skipped": "unchanged",
                    "applied": applied,
                    "processes": procs,
                }
            elapsed = time.monotonic() - self._last_winws2_reload_ts
            if winws_running and self._last_winws2_reload_ts > 0 and elapsed < min_interval_sec:
                return {
                    "ok": True,
                    "reloaded": False,
                    "skipped": "throttled",
                    "retry_after_sec": round(min_interval_sec - elapsed, 1),
                    "applied": applied,
                    "processes": procs,
                }
            if winws_running and defer_if_active:
                active_conns = self._active_working_connections(service="winws2")
                if active_conns:
                    self._pending_winws2_reload = True
                    return {
                        "ok": True,
                        "reloaded": False,
                        "deferred": True,
                        "skipped": "active_connections",
                        "active_connections": len(active_conns),
                        "applied": applied,
                        "processes": procs,
                    }
        if getattr(self.reload_winws2, "__func__", None) is NetdoctorEngine.reload_winws2:
            return self.reload_winws2(iface=iface, applied=applied)
        return self.reload_winws2(iface=iface)

    def ensure_services_healthy(
        self,
        *,
        max_restarts_window: int = 5,
        window_sec: float = 300.0,
    ) -> dict[str, Any]:
        """Watchdog: monitor winws2/sing-box/tg-ws-proxy, rollback bad presets on repeated crashes, and react to gateway changes."""
        if not _is_admin():
            return {"checked": True, "healthy": True, "restarted": [], "skipped": "not_admin"}
        if self._stopping:
            return {"checked": True, "healthy": True, "restarted": [], "skipped": "stopping"}

        procs = self._collect_processes_state()
        winws_running = bool((procs.get("winws2") or {}).get("running"))
        sb_running = bool((procs.get("sing-box") or {}).get("running"))
        tg_running = bool((procs.get("tg-ws-proxy") or {}).get("running"))

        raw_desired = ""
        stack_mode = "hybrid"
        telegram_mode = "mtproto"
        active_preset_id = "auto"
        try:
            st = Storage(self.db_path)
            try:
                raw_desired = st.get_setting("stack_desired_running", "").strip()
                stack_mode = st.get_setting("stack_mode", "hybrid").strip().lower() or "hybrid"
                telegram_mode = self.get_telegram_mode(st)
                active_preset_id = st.get_setting("active_zapret_preset_id", "auto").strip() or "auto"
            finally:
                st.close()
        except Exception:  # noqa: BLE001
            raw_desired = ""

        if raw_desired == "0" and not self._desired_running:
            return {"checked": True, "healthy": True, "restarted": [], "skipped": "idle"}

        should_be_running = bool(
            self._desired_running or raw_desired == "1" or (raw_desired == "" and (sb_running or tg_running))
        )
        if not should_be_running:
            return {"checked": True, "healthy": True, "restarted": [], "skipped": "idle"}

        def _aborted_by_stop() -> bool:
            if self._stopping:
                return True
            if self._desired_running:
                return False
            try:
                st_chk = Storage(self.db_path)
                try:
                    return st_chk.get_setting("stack_desired_running", "").strip() == "0"
                finally:
                    st_chk.close()
            except Exception:  # noqa: BLE001
                return False

        restarted: list[str] = []
        network_changed = False

        # Recover dead sing-box (when hybrid mode is desired) and tg-ws-proxy with failure backoff
        desired_stack_active = bool(self._desired_running or raw_desired == "1")
        now_svc = time.monotonic()

        def _try_recover_aux(svc_name: str, recover_fn: Any) -> bool:
            with self._lock:
                if _aborted_by_stop():
                    return False
                if now_svc < self._service_retry_ts.get(svc_name, 0.0):
                    return False
                res = recover_fn()
                if res.get("ok"):
                    self._service_fail_counts.pop(svc_name, None)
                    self._service_retry_ts.pop(svc_name, None)
                    return True
                fails = self._service_fail_counts.get(svc_name, 0) + 1
                self._service_fail_counts[svc_name] = fails
                self._service_retry_ts[svc_name] = now_svc + min(60.0, float(15 * (2 ** min(fails - 1, 2))))
                return False

        xray_running = bool((procs.get("xray") or {}).get("running"))
        xray_exe = self.bin_dir.resolve() / "xray.exe"
        xray_cfg = self.configs_dir / "xray.json"
        if xray_running:
            with self._lock:
                self._service_fail_counts.pop("xray", None)
                self._service_retry_ts.pop("xray", None)
        elif (
            desired_stack_active
            and stack_mode != "dpi_only"
            and xray_exe.is_file()
            and self._has_xray_inbounds(xray_cfg)
        ):
            if _try_recover_aux("xray", self._restart_xray):
                restarted.append("xray")
                xray_running = True

        if sb_running:
            with self._lock:
                self._service_fail_counts.pop("sing-box", None)
                self._service_retry_ts.pop("sing-box", None)
        elif desired_stack_active and stack_mode != "dpi_only":
            if _try_recover_aux("sing-box", self.reload_singbox):
                restarted.append("sing-box")
                sb_running = True

        tg_script = self.bin_dir.resolve() / "tg-ws-proxy" / "proxy" / "tg_ws_proxy.py"
        tg_exe = self.bin_dir.resolve() / "tg-ws-proxy" / "TgWsProxy_windows.exe"
        if tg_running:
            with self._lock:
                self._service_fail_counts.pop("tg-ws-proxy", None)
                self._service_retry_ts.pop("tg-ws-proxy", None)
        elif desired_stack_active and telegram_mode == "mtproto" and (tg_script.is_file() or tg_exe.is_file()):
            if _try_recover_aux("tg-ws-proxy", self._restart_tg_ws_proxy):
                restarted.append("tg-ws-proxy")
                tg_running = True

        if winws_running:
            cur_gw = self._detect_local_gateway_ip()
            prev_gw = self._last_gateway_ip
            if cur_gw:
                if not prev_gw:
                    self._last_gateway_ip = cur_gw
                    self._gw_change_pending = ""
                elif cur_gw == prev_gw:
                    self._gw_change_pending = ""
                elif self._gw_change_pending != cur_gw:
                    # Require 2 consecutive ticks seeing the new gateway to ignore transient adapter/VPN blips
                    self._gw_change_pending = cur_gw
                else:
                    if _aborted_by_stop():
                        return {"checked": True, "healthy": True, "restarted": restarted, "skipped": "stopping"}
                    self._gw_change_pending = ""
                    self._last_gateway_ip = cur_gw
                    network_changed = True
                    clear_vpn_dns_cache()
                    clear_network_fingerprint_cache()
                    self.flush_windows_dns_cache()
                    if sb_running and stack_mode != "dpi_only":
                        if _aborted_by_stop():
                            return {"checked": True, "healthy": True, "restarted": restarted, "skipped": "stopping"}
                        sb_net_res = self.reload_singbox()
                        if sb_net_res.get("ok") and "sing-box" not in restarted:
                            restarted.append("sing-box")
                    if _aborted_by_stop():
                        return {"checked": True, "healthy": True, "restarted": restarted, "skipped": "stopping"}
                    w_net_res = self.reload_winws2()
                    if w_net_res.get("ok"):
                        restarted.append("winws2")
            # Cap oversized runtime winws2.log when idle (start_process rotates >2MB to .prev.log)
            winws_log_file = self.logs_dir / "winws2.log"
            try:
                if (
                    not network_changed
                    and winws_log_file.is_file()
                    and winws_log_file.stat().st_size > 30 * 1024 * 1024
                    and not self._active_working_connections(service="winws2")
                    and not _aborted_by_stop()
                ):
                    w_rot = self.reload_winws2()
                    if w_rot.get("ok") and "winws2" not in restarted:
                        restarted.append("winws2")
            except OSError:
                pass
            if not network_changed:
                if self._pending_singbox_reload and sb_running and stack_mode != "dpi_only":
                    sb_pend = self.reload_singbox_if_changed(min_interval_sec=15.0, defer_if_active=True)
                    if sb_pend.get("reloaded") and "sing-box" not in restarted:
                        restarted.append("sing-box")
                if self._pending_winws2_reload:
                    w_pend = self.reload_winws2_if_changed(min_interval_sec=20.0, defer_if_active=True)
                    if w_pend.get("reloaded") and "winws2" not in restarted:
                        restarted.append("winws2")
                if sb_running and stack_mode != "dpi_only" and getattr(self.orchestrator.vpn, "_pending_optimal_node", None):
                    if not self._active_working_connections(service="sing-box"):
                        self.reconcile_vpn_health(min_interval_sec=0.0)
            return {
                "checked": True,
                "healthy": True,
                "restarted": restarted,
                "network_changed": network_changed,
            }

        now = time.monotonic()
        with self._lock:
            if _aborted_by_stop():
                return {"checked": True, "healthy": True, "restarted": restarted, "skipped": "stopping"}
            while self._watchdog_timestamps and (now - self._watchdog_timestamps[0]) > window_sec:
                self._watchdog_timestamps.popleft()
            recent_crashes = len(self._watchdog_timestamps)
            if recent_crashes >= max_restarts_window:
                return {
                    "checked": True,
                    "healthy": False,
                    "restarted": restarted,
                    "capped": True,
                    "restarts_count": self._watchdog_restarts,
                    "last_crash_reason": self._last_crash_reason,
                }
            if now < self._watchdog_next_retry_ts:
                return {
                    "checked": True,
                    "healthy": False,
                    "restarted": restarted,
                    "backoff": True,
                    "retry_after_sec": round(self._watchdog_next_retry_ts - now, 1),
                    "restarts_count": self._watchdog_restarts,
                }

        if _aborted_by_stop():
            return {"checked": True, "healthy": True, "restarted": restarted, "skipped": "stopping"}

        tail_cur = _read_tail_lines(self.logs_dir / "winws2.log", max_lines=6).strip()
        tail_prev = _read_tail_lines(self.logs_dir / "winws2.prev.log", max_lines=6).strip()
        snippet = tail_cur or tail_prev
        crash_reason = snippet.splitlines()[-1].strip()[:180] if snippet else "Процесс winws2.exe неожиданно завершился"

        fallback_switched_to: str | None = None
        with self._lock:
            if _aborted_by_stop():
                return {"checked": True, "healthy": True, "restarted": restarted, "skipped": "stopping"}
            res = self.reload_winws2()
        # Roll back incompatible custom/Zapret2 preset automatically after >=2 rapid crashes or immediate failure
        if active_preset_id != "auto" and (recent_crashes >= 2 or not res.get("ok")):
            fallback_id = "auto"
            try:
                st_fb = Storage(self.db_path)
                try:
                    all_presets = list_all_zapret_presets(
                        st_fb,
                        presets_dir=self.presets_dir,
                        zdy_dir=self.zdy_presets_dir,
                    )
                    safe_cand = next(
                        (
                            str(p["id"])
                            for p in all_presets
                            if p["id"] == "z2_general_alt1_1_9_9_game_filter" and p["id"] != active_preset_id
                        ),
                        None,
                    )
                    fallback_id = safe_cand or "auto"
                    st_fb.set_setting("active_zapret_preset_id", fallback_id)
                finally:
                    st_fb.close()
                if _aborted_by_stop():
                    return {"checked": True, "healthy": True, "restarted": restarted, "skipped": "stopping"}
                self.trigger_apply_configs()
                res = self.reload_winws2()
                fallback_switched_to = fallback_id
            except Exception:  # noqa: BLE001
                fallback_switched_to = None

        with self._lock:
            self._watchdog_restarts += 1
            self._watchdog_timestamps.append(now)
            self._last_crash_at = _now_iso()
            self._last_crash_reason = crash_reason if res.get("ok") else str(res.get("error") or crash_reason)
            backoff_sec = min(60.0, float(2 ** min(len(self._watchdog_timestamps), 6)))
            self._watchdog_next_retry_ts = now + (5.0 if res.get("ok") else backoff_sec)
            restarts_total = self._watchdog_restarts

        if res.get("ok"):
            restarted.append("winws2")
        out: dict[str, Any] = {
            "checked": True,
            "healthy": bool(res.get("ok")),
            "restarted": restarted,
            "crash_reason": crash_reason,
            "restarts_count": restarts_total,
            "reload_result": res,
        }
        if fallback_switched_to:
            out["fallback_switched_to"] = fallback_switched_to
        return out

    def reload_singbox(self, iface: int | None = None) -> dict[str, Any]:
        """Validate sing-box.json and reload sing-box.exe while preserving winws2 and tg-ws-proxy."""
        if _is_admin() and not (self.bin_dir.resolve() / "sing-box.exe").is_file():
            self.ensure_deps(force=False)

        with self._lock:
            if _is_admin() and self.get_stack_mode() != "dpi_only":
                self.ruleset_server.start()
            applied = self.trigger_apply_configs(iface=iface)
            if not _is_admin():
                return {
                    "ok": False,
                    "reloaded": False,
                    "requires_admin": True,
                    "error": "Administrator privileges required (UAC) to reload sing-box TUN.",
                    "applied": applied,
                    "processes": self._collect_processes_state(),
                }

            singbox_file = Path(applied["singbox_config"]).resolve()
            if not applied.get("singbox_valid", True):
                return {
                    "ok": False,
                    "reloaded": False,
                    "requires_admin": False,
                    "error": f"Invalid sing-box.json: {applied.get('singbox_check_error')}",
                    "applied": applied,
                    "processes": self._collect_processes_state(),
                }

            bin_path = self.bin_dir.resolve()
            singbox_exe = bin_path / "sing-box.exe"
            if not singbox_exe.is_file():
                return {
                    "ok": False,
                    "reloaded": False,
                    "requires_admin": False,
                    "error": f"sing-box.exe not found in {bin_path}",
                    "applied": applied,
                    "processes": self._collect_processes_state(),
                }

            if self._supervisor is None:
                self._supervisor = ProcessSupervisor(bin_dir=bin_path, logs_dir=self.logs_dir.resolve())
                self._supervisor.adopt_persisted_state()

            xray_exe = bin_path / "xray.exe"
            xray_cfg_raw = str(applied.get("xray_config") or "").strip()
            xray_bridge_count = int(applied.get("xray_bridge_count") or 0)
            cmd = [str(singbox_exe), "run", "-c", str(singbox_file)]
            try:
                if xray_bridge_count > 0 and xray_exe.is_file() and xray_cfg_raw:
                    xray_path = Path(xray_cfg_raw).resolve()
                    try:
                        new_xray_hash = (
                            hashlib.sha256(xray_path.read_bytes()).hexdigest() if xray_path.is_file() else ""
                        )
                    except OSError:
                        new_xray_hash = ""
                    xray_running = bool((self._collect_processes_state().get("xray") or {}).get("running"))
                    if not xray_running or new_xray_hash != self._last_xray_hash:
                        self._supervisor.reload_process(
                            "xray",
                            [str(xray_exe), "run", "-c", str(xray_path)],
                            cwd=bin_path,
                        )
                        time.sleep(0.2)
                        self._last_xray_hash = new_xray_hash
                else:
                    procs_now = self._collect_processes_state()
                    if bool((procs_now.get("xray") or {}).get("running")) or "xray" in self._supervisor.processes:
                        self._supervisor.stop_process("xray")
                    self._last_xray_hash = ""

                proc = self._supervisor.reload_process("sing-box", cmd, cwd=bin_path)
                time.sleep(0.35)
                rc = proc.poll()
                if rc is not None and self._is_wintun_exists_error():
                    proc, applied = self._retry_singbox_after_wintun_collision(self._supervisor, iface)
                    singbox_file = Path(applied["singbox_config"]).resolve()
                    rc = proc.poll()
                if rc is not None:
                    self._supervisor.stop_process("sing-box")
                    log_tail = _read_tail_lines(self.logs_dir / "sing-box.log", max_lines=8).strip()
                    reason = f"sing-box exited prematurely on reload with code {rc}"
                    if log_tail:
                        last_line = log_tail.splitlines()[-1].strip()
                        reason = f"{reason}: {last_line[:180]}"
                    return {
                        "ok": False,
                        "reloaded": False,
                        "requires_admin": False,
                        "error": reason,
                        "applied": applied,
                        "processes": self._collect_processes_state(),
                    }
            except OSError as exc:
                return {
                    "ok": False,
                    "reloaded": False,
                    "requires_admin": getattr(exc, "winerror", None) == 740,
                    "error": str(exc),
                    "applied": applied,
                    "processes": self._collect_processes_state(),
                }

            try:
                self._last_singbox_hash = (
                    hashlib.sha256(singbox_file.read_bytes()).hexdigest() if singbox_file.is_file() else ""
                )
            except OSError:
                self._last_singbox_hash = ""
            self._last_singbox_reload_ts = time.monotonic()
            self._pending_singbox_reload = False

        # Run Clash HTTP selector retries outside self._lock so UI snapshots and stop_services never stall.
        self._sync_singbox_vpn_selector()
        return {
            "ok": True,
            "reloaded": True,
            "requires_admin": False,
            "pid": proc.pid,
            "applied": applied,
            "processes": self._collect_processes_state(),
        }

    def reload_singbox_if_changed(
        self,
        iface: int | None = None,
        min_interval_sec: float = 15.0,
        *,
        defer_if_active: bool = False,
    ) -> dict[str, Any]:
        """Hot-reload sing-box (and xray bridge) ONLY if config changed AND cooldown interval elapsed."""
        with self._lock:
            applied = self.trigger_apply_configs(iface=iface)
            sb_path = Path(applied["singbox_config"]).resolve()
            try:
                new_hash = hashlib.sha256(sb_path.read_bytes()).hexdigest() if sb_path.is_file() else ""
            except OSError:
                new_hash = ""
            xray_cfg_raw = str(applied.get("xray_config") or "").strip()
            xray_path = Path(xray_cfg_raw).resolve() if xray_cfg_raw else None
            try:
                new_xray_hash = (
                    hashlib.sha256(xray_path.read_bytes()).hexdigest()
                    if xray_path is not None and xray_path.is_file()
                    else ""
                )
            except OSError:
                new_xray_hash = ""
            procs = self._collect_processes_state()
            sb_running = bool((procs.get("sing-box") or {}).get("running"))
            if (
                sb_running
                and self._last_singbox_hash
                and new_hash == self._last_singbox_hash
                and new_xray_hash == self._last_xray_hash
            ):
                self._pending_singbox_reload = False
                return {
                    "ok": True,
                    "reloaded": False,
                    "skipped": "unchanged",
                    "applied": applied,
                    "processes": procs,
                }
            elapsed = time.monotonic() - self._last_singbox_reload_ts
            if sb_running and self._last_singbox_reload_ts > 0 and elapsed < min_interval_sec:
                return {
                    "ok": True,
                    "reloaded": False,
                    "skipped": "throttled",
                    "retry_after_sec": round(min_interval_sec - elapsed, 1),
                    "applied": applied,
                    "processes": procs,
                }
            if sb_running and defer_if_active:
                active_conns = self._active_working_connections(service="sing-box")
                if active_conns:
                    self._pending_singbox_reload = True
                    return {
                        "ok": True,
                        "reloaded": False,
                        "deferred": True,
                        "skipped": "active_connections",
                        "active_connections": len(active_conns),
                        "applied": applied,
                        "processes": procs,
                    }
        return self.reload_singbox(iface=iface)

    def _reload_running_services(self, *, winws2: bool = False, singbox: bool = False) -> None:
        """Quietly hot-reload already-running elevated services when config/rules change."""
        if not _is_admin():
            return
        procs = self._collect_processes_state()
        if winws2 and bool((procs.get("winws2") or {}).get("running")):
            self.reload_winws2()
        if singbox and bool((procs.get("sing-box") or {}).get("running")):
            self.reload_singbox()

    def _sync_singbox_vpn_selector(self, *, retries: int = 2) -> None:
        """Align live `vpn-select` outbound with stored VPN selection policy (overcoming singbox-cache.db)."""
        try:
            storage = Storage(self.db_path)
            try:
                nodes = storage.get_all_subscription_nodes()
                if not nodes:
                    return
                vpn_policy = storage.get_vpn_selection_policy()
                health_map = storage.get_vpn_node_health_map()
            finally:
                storage.close()

            desired_target = "vpn-auto"
            if vpn_policy["mode"] == "priority":
                pref = str(vpn_policy.get("priority_node") or "").strip()
                eligible = self.orchestrator.vpn.rank_candidates(
                    nodes,
                    health_map,
                    mode="priority",
                    preferred_tag=pref,
                    allow_quarantined=False,
                )
                eligible_tags = {str(n.get("tag") or "").strip() for n in eligible}
                if pref and pref in eligible_tags:
                    desired_target = pref
                elif eligible:
                    top_prio = int(eligible[0].get("priority") if eligible[0].get("priority") is not None else 100)
                    if top_prio < 100:
                        desired_target = str(eligible[0].get("tag") or "").strip() or "vpn-auto"

            proxies: dict[str, Any] = {}
            for attempt in range(max(1, retries)):
                proxies = self.clash_api.get_proxies_sync()
                if proxies:
                    break
                if attempt + 1 < retries:
                    time.sleep(0.25)

            sel_info = proxies.get("vpn-select") if isinstance(proxies, dict) else None
            if isinstance(sel_info, dict) and str(sel_info.get("now") or "") != desired_target:
                if desired_target in proxies or desired_target == "vpn-auto":
                    self.clash_api.select_outbound_sync("vpn-select", desired_target)
        except Exception:  # noqa: BLE001
            pass

    def get_vpn_selection_policy(self) -> dict[str, Any]:
        """Return persisted VPN selection mode (`auto` | `priority`), preferred node tag, and priorities."""
        storage = Storage(self.db_path)
        try:
            return storage.get_vpn_selection_policy()
        finally:
            storage.close()

    def set_vpn_selection_mode(self, mode: str) -> dict[str, Any]:
        """Switch VPN selection mode (`auto` vs `priority`), rebuild configs, and reconcile live Clash selector."""
        clean_mode = "priority" if str(mode or "auto").strip().lower() == "priority" else "auto"
        storage = Storage(self.db_path)
        try:
            policy = storage.set_vpn_selection_policy(mode=clean_mode)
        finally:
            storage.close()

        applied = self.trigger_apply_configs()
        reconcile_res: dict[str, Any] | None = None
        sb_running = bool((self._collect_processes_state().get("sing-box") or {}).get("running"))
        if sb_running:
            if clean_mode == "auto":
                self.clash_api.select_outbound_sync("vpn-select", "vpn-auto")
                self.orchestrator.vpn._active_node_tag = None
            reconcile_res = self.reconcile_vpn_health(force=True)
        return {
            "ok": True,
            "policy": policy,
            "applied": applied,
            "reconcile": reconcile_res,
        }

    def set_vpn_priority_node(self, tag: str | None) -> dict[str, Any]:
        """Pin a real VPN node as Priority #1 (and switch to priority mode), or revert to auto mode."""
        clean_tag = str(tag or "").strip()
        if not clean_tag or clean_tag == "vpn-auto":
            return self.set_vpn_selection_mode("auto")

        storage = Storage(self.db_path)
        try:
            nodes = storage.get_all_subscription_nodes()
            match = next((n for n in nodes if str(n.get("tag") or "").strip() == clean_tag), None)
            if match is None:
                raise ValueError(f"VPN-узел не найден: {clean_tag}")
            if is_placeholder_node(match):
                raise ValueError(f"Узел «{clean_tag}» — служебная запись подписки, её нельзя выбрать приоритетной")
            policy = storage.get_vpn_selection_policy()
            priorities = dict(policy["priorities"])
            for n in nodes:
                n_tag = str(n.get("tag") or "").strip()
                if n_tag and n_tag != clean_tag and int(n.get("priority") if n.get("priority") is not None else 100) == 1:
                    priorities[n_tag] = 10
            for k, v in list(priorities.items()):
                if k != clean_tag and v == 1:
                    priorities[k] = 10
            priorities[clean_tag] = 1
            new_policy = storage.set_vpn_selection_policy(
                mode="priority",
                priority_node=clean_tag,
                priorities=priorities,
            )
        finally:
            storage.close()

        applied = self.trigger_apply_configs()
        reconcile_res: dict[str, Any] | None = None
        if bool((self._collect_processes_state().get("sing-box") or {}).get("running")):
            reconcile_res = self.reconcile_vpn_health(force=True)
        return {
            "ok": True,
            "policy": new_policy,
            "priority_node": clean_tag,
            "applied": applied,
            "reconcile": reconcile_res,
        }

    def move_vpn_node_priority(self, tag: str, delta: int) -> dict[str, Any]:
        """Shift a real VPN node up (`delta < 0`) or down (`delta > 0`) in priority ranking."""
        clean_tag = str(tag or "").strip()
        if not clean_tag:
            raise ValueError("Не выбран VPN-узел")

        storage = Storage(self.db_path)
        try:
            nodes = storage.get_all_subscription_nodes()
            real_nodes = [
                (idx, n)
                for idx, n in enumerate(nodes)
                if n.get("enabled", True) and not is_placeholder_node(n) and str(n.get("tag") or "").strip()
            ]
            real_nodes.sort(
                key=lambda item: (
                    int(item[1].get("priority") if item[1].get("priority") is not None else 100),
                    item[0],
                )
            )
            ordered_tags = [str(n.get("tag") or "").strip() for _idx, n in real_nodes]
            if clean_tag not in ordered_tags:
                raise ValueError(f"Реальный VPN-узел «{clean_tag}» не найден")
            idx = ordered_tags.index(clean_tag)
            step = -1 if delta < 0 else (1 if delta > 0 else 0)
            new_idx = max(0, min(len(ordered_tags) - 1, idx + step))
            if new_idx != idx:
                ordered_tags.pop(idx)
                ordered_tags.insert(new_idx, clean_tag)
            new_priorities = {t: (1 if i == 0 else i * 10) for i, t in enumerate(ordered_tags)}
            top_tag = ordered_tags[0]
            new_policy = storage.set_vpn_selection_policy(
                mode="priority",
                priority_node=top_tag,
                priorities=new_priorities,
            )
        finally:
            storage.close()

        applied = self.trigger_apply_configs()
        reconcile_res: dict[str, Any] | None = None
        if bool((self._collect_processes_state().get("sing-box") or {}).get("running")):
            reconcile_res = self.reconcile_vpn_health(force=True)
        return {
            "ok": True,
            "policy": new_policy,
            "priority_node": top_tag,
            "applied": applied,
            "reconcile": reconcile_res,
        }

    def reconcile_vpn_health(
        self,
        min_interval_sec: float = 30.0,
        force: bool = False,
    ) -> dict[str, Any]:
        """Run throttled, non-reentrant active VPN node health check and automatic failover/failback."""
        now = time.monotonic()
        with self._lock:
            if self._vpn_reconciling:
                return {"ok": True, "skipped": "busy"}
            if not force and self._last_vpn_reconcile_ts > 0 and (now - self._last_vpn_reconcile_ts) < min_interval_sec:
                return {"ok": True, "skipped": "throttled"}
            procs = self._collect_processes_state()
            if not bool((procs.get("sing-box") or {}).get("running")):
                return {"ok": True, "skipped": "singbox_stopped"}
            self._vpn_reconciling = True

        try:
            storage = Storage(self.db_path)
            try:
                nodes = storage.get_all_subscription_nodes()
                if not nodes:
                    return {"ok": True, "action": "no_nodes", "selected": None, "probed": []}
                res = _run_coro_sync(
                    self.orchestrator.vpn.reconcile_active_node(
                        storage,
                        nodes,
                        clash_client=self.clash_api,
                        timeout=1.8,
                        force=force,
                    )
                )
            finally:
                storage.close()

            probed_list = res.get("probed") or []
            with self._lock:
                self._last_vpn_reconcile_ts = time.monotonic()
                for p in probed_list:
                    tag = str(p.get("tag") or "").strip()
                    if tag:
                        cached_item = dict(self._cached_vpn_nodes.get(tag) or {})
                        cached_item.update(
                            {
                                "alive": p.get("alive"),
                                "ping_ms": p.get("ping_ms"),
                                "probe_result": p.get("probe_result"),
                                "cb_state": p.get("cb_state"),
                                "protocol_ok": p.get("protocol_ok"),
                                "tunnel_verified": p.get("tunnel_verified"),
                            }
                        )
                        self._cached_vpn_nodes[tag] = cached_item
                if res.get("selected"):
                    self._cached_vpn_health["best_node"] = res["selected"]
                    sel_p = next((p for p in probed_list if p.get("tag") == res["selected"]), None)
                    if sel_p is not None:
                        self._cached_vpn_health["best_ping_ms"] = sel_p.get("ping_ms")
                self._cached_vpn_health["pending_node"] = res.get("pending_node")
            return res
        finally:
            with self._lock:
                self._vpn_reconciling = False

    def rotate_vpn_node(self, target_tag: str | None = None, selector_tag: str = "vpn-select") -> dict[str, Any]:
        """Switch active VPN server via Clash API without TUN restart and persist selection."""
        proc_state = self._collect_processes_state()
        sb_running = bool((proc_state.get("sing-box") or {}).get("running"))
        clash_client = self.clash_api if sb_running else None
        storage = Storage(self.db_path)
        try:
            nodes = storage.get_all_subscription_nodes()
            res = self.orchestrator.vpn.rotate_vpn_node(
                storage,
                nodes,
                clash_client=clash_client,
                target_tag=target_tag,
                selector_tag=selector_tag,
            )
        finally:
            storage.close()
        with self._lock:
            if res.get("ok") and res.get("selected"):
                self._cached_vpn_health["best_node"] = res["selected"]
        return res

    def force_apply_pending_changes(self, iface: int | None = None) -> dict[str, Any]:
        """Rebuild configs and immediately hot-reload running services + pending VPN switches, ignoring deferral."""
        applied = self.trigger_apply_configs(iface=iface)
        procs = self._collect_processes_state()
        is_adm = _is_admin()
        reloaded: list[str] = []
        vpn_switched: str | None = None

        if bool((procs.get("winws2") or {}).get("running")) and is_adm:
            w_res = self.reload_winws2_if_changed(iface=iface, min_interval_sec=0.0, defer_if_active=False)
            if isinstance(w_res, dict) and w_res.get("reloaded"):
                reloaded.append("winws2")

        if bool((procs.get("sing-box") or {}).get("running")) and is_adm:
            sb_res = self.reload_singbox_if_changed(iface=iface, min_interval_sec=0.0, defer_if_active=False)
            if isinstance(sb_res, dict) and sb_res.get("reloaded"):
                reloaded.append("sing-box")
            if getattr(self.orchestrator.vpn, "_pending_optimal_node", None):
                vpn_res = self.reconcile_vpn_health(min_interval_sec=0.0, force=True)
                if isinstance(vpn_res, dict) and vpn_res.get("selected"):
                    vpn_switched = str(vpn_res["selected"])

        with self._lock:
            self._pending_winws2_reload = False
            self._pending_singbox_reload = False

        return {
            "ok": True,
            "reloaded": reloaded,
            "vpn_switched": vpn_switched,
            "applied": applied,
        }

    def set_byedpi_fallback(self, enabled: bool) -> dict[str, Any]:
        """Enable or disable ByeDPI (ciadpi.exe SOCKS5) fallback mode and rebuild configs."""
        storage = Storage(self.db_path)
        try:
            storage.set_setting("byedpi_fallback", "1" if enabled else "0")
        finally:
            storage.close()
        applied = self.trigger_apply_configs()
        procs = self._collect_processes_state()
        stack_active = bool(
            (procs.get("winws2") or {}).get("running")
            or (procs.get("sing-box") or {}).get("running")
        )
        if stack_active and _is_admin():
            with self._lock:
                if self._supervisor is None:
                    self._supervisor = ProcessSupervisor(bin_dir=self.bin_dir.resolve(), logs_dir=self.logs_dir.resolve())
                    self._supervisor.adopt_persisted_state()
                ciadpi_exe = self.bin_dir.resolve() / "ciadpi.exe"
                if enabled and ciadpi_exe.is_file():
                    if not bool((procs.get("byedpi") or {}).get("running")):
                        self._supervisor.start_process(
                            "byedpi",
                            [str(ciadpi_exe), "--ip", "127.0.0.1", "--port", "10809", "--disorder", "1", "--tlsrec", "1+s"],
                            cwd=self.bin_dir.resolve(),
                        )
                elif not enabled:
                    self._supervisor.stop_process("byedpi")
        self._reload_running_services(singbox=True)
        return {"byedpi_fallback": bool(enabled), "applied": applied}

    def set_winws2_debug_log(self, enabled: bool) -> dict[str, Any]:
        """Enable or disable verbose `--debug=1` logging in winws2 and hot-reload if active."""
        storage = Storage(self.db_path)
        try:
            storage.set_setting("winws2_debug_log", "1" if enabled else "0")
        finally:
            storage.close()
        self._reload_running_services(winws2=True)
        return {"winws2_debug_log": bool(enabled)}

    def run_blockcheck2_sync(self, domain: str) -> dict[str, Any]:
        """Run blockcheck2 deep discovery for a domain and merge found strategies into DB."""
        clean = domain.strip().lower()
        if not clean:
            raise ValueError("Введите домен для глубокого поиска blockcheck2")
        discovered = _run_coro_sync(run_blockcheck2_for_domain(clean, bin_dir=self.bin_dir))
        if discovered:
            storage = Storage(self.db_path)
            try:
                storage.upsert_strategies(discovered)
            finally:
                storage.close()
        return {
            "domain": clean,
            "discovered_count": len(discovered),
            "strategies": [s.model_dump(mode="json") for s in discovered],
        }

    def get_auto_start_protection(self) -> bool:
        """Return True when protection autopilot should start automatically right after GUI launch."""
        storage = Storage(self.db_path)
        try:
            return storage.get_setting("auto_start_protection", "0") == "1"
        finally:
            storage.close()

    def set_auto_start_protection(self, enabled: bool) -> dict[str, Any]:
        """Persist auto-start protection preference and refresh Task Scheduler entry if autostart is active."""
        storage = Storage(self.db_path)
        try:
            storage.set_setting("auto_start_protection", "1" if enabled else "0")
        finally:
            storage.close()

        cur_status = tray_get_autostart_status()
        autostart_updated = False
        task_res: dict[str, Any] | None = None
        if cur_status.get("enabled"):
            task_res = self.set_autostart(True, auto_start_protection=bool(enabled))
            autostart_updated = bool(task_res.get("ok"))
        return {
            "ok": True if task_res is None else bool(task_res.get("ok")),
            "auto_start_protection": bool(enabled),
            "autostart_updated": autostart_updated,
            "error": (task_res or {}).get("error", ""),
        }

    def get_autostart_status(self) -> dict[str, Any]:
        return {
            **tray_get_autostart_status(),
            "auto_start_protection": self.get_auto_start_protection(),
        }

    def set_autostart(self, enabled: bool, *, auto_start_protection: bool | None = None) -> dict[str, Any]:
        storage = Storage(self.db_path)
        try:
            if auto_start_protection is not None:
                storage.set_setting("auto_start_protection", "1" if auto_start_protection else "0")
            elif enabled and storage.get_setting("auto_start_protection", "") == "":
                storage.set_setting("auto_start_protection", "1")
            prot = storage.get_setting("auto_start_protection", "0") == "1"
        finally:
            storage.close()

        res = tray_set_autostart_enabled(
            enabled=enabled,
            working_dir=self.db_path.resolve().parent,
            db_path=self.db_path,
            configs_dir=self.configs_dir,
            lists_dir=self.lists_dir,
            logs_dir=self.logs_dir,
            bin_dir=self.bin_dir,
            auto_start_protection=prot,
        )
        res["auto_start_protection"] = prot
        return res

    def has_core_binaries(self, stack_mode: str | None = None) -> bool:
        """Return True when required core executables (`winws2.exe`, and `sing-box.exe` in hybrid mode) exist."""
        bin_path = self.bin_dir.resolve()
        mode = (stack_mode or self.get_stack_mode()).strip().lower()
        if not (bin_path / "winws2.exe").is_file():
            return False
        if mode != "dpi_only" and not (bin_path / "sing-box.exe").is_file():
            return False
        return True

    def ensure_deps(self, *, force: bool = False) -> dict[str, Any]:
        """Verify external binaries/lists/presets + Python packages and download missing or broken components."""
        with self._deps_lock:
            py_installed: list[str] = []
            py_error: str | None = None
            if force or find_missing_python_deps():
                py_ok, py_installed, py_err = ensure_python_deps(timeout=120.0)
                if not py_ok and py_err:
                    py_error = py_err

            if not force:
                pre = dict(verify_binaries(self.bin_dir, self.lists_dir))
                if pre.get("ok"):
                    pre["downloaded"] = bool(py_installed)
                    if py_installed:
                        pre["python_deps_installed"] = py_installed
                    if py_error is not None:
                        pre["fetch_error"] = py_error
                    return pre

            fetch_error: str | None = py_error
            try:
                _run_coro_sync(fetch_all_bins(self.bin_dir, self.lists_dir, force=force))
            except Exception as exc:  # noqa: BLE001
                fetch_error = str(exc)

            post = dict(verify_binaries(self.bin_dir, self.lists_dir))
            if fetch_error is None and not post.get("ok") and not force:
                try:
                    _run_coro_sync(fetch_all_bins(self.bin_dir, self.lists_dir, force=True))
                except Exception as exc:  # noqa: BLE001
                    fetch_error = str(exc)
                post = dict(verify_binaries(self.bin_dir, self.lists_dir))

            post["downloaded"] = (fetch_error is None) or bool(py_installed)
            if py_installed:
                post["python_deps_installed"] = py_installed
            if fetch_error is not None:
                post["fetch_error"] = fetch_error
            return post

    def get_install_mode(self) -> str:
        """Return `git` if running from a git clone or `portable` otherwise."""
        return detect_install_mode()

    def has_outdated_pinned_bins(self) -> bool:
        """Return True when bin/manifest.json records binary versions differing from pinned release tags."""
        return bool(get_outdated_pinned_artifacts(self.bin_dir))

    def check_updates(self, *, force: bool = False) -> dict[str, Any]:
        """Check GitHub Releases for a newer netdoctor version using SQLite cache when not forced."""
        storage = Storage(self.db_path)
        try:
            return _run_coro_sync(check_for_updates(storage=storage, force=force))
        finally:
            storage.close()

    def apply_update(self, *, download_url: str | None = None, target_version: str | None = None) -> dict[str, Any]:
        """Stop running bypass services, apply the app update, and sync pinned binaries."""
        try:
            self.stop_services()
        except Exception:  # noqa: BLE001
            pass
        storage = Storage(self.db_path)
        try:
            return _run_coro_sync(
                apply_app_update(
                    bin_dir=self.bin_dir,
                    lists_dir=self.lists_dir,
                    storage=storage,
                    download_url=download_url,
                    target_version=target_version,
                )
            )
        finally:
            storage.close()

    def restart_gui_process(self) -> dict[str, Any]:
        """Spawn a detached replacement GUI process to complete an in-app update."""
        return launch_gui_detached(
            db_path=self.db_path,
            configs_dir=self.configs_dir,
            lists_dir=self.lists_dir,
            logs_dir=self.logs_dir,
            bin_dir=self.bin_dir,
            replace_pid=os.getpid(),
        )

    def trigger_revalidate(self) -> dict[str, Any]:
        """Run one canary/TTL revalidation cycle against stored decisions."""
        storage = Storage(self.db_path)
        try:
            sig = inspect.signature(run_canary_cycle)
            if "winws2_log_path" in sig.parameters:
                coro = run_canary_cycle(storage, winws2_log_path=self.logs_dir / "winws2.log")
            else:
                coro = run_canary_cycle(storage)
            res = _run_coro_sync(coro)
        finally:
            storage.close()
        if res.get("promoted") or res.get("downshifted"):
            self.trigger_apply_configs()
            self._reload_running_services(winws2=True, singbox=True)
        return res

    def add_vpn_subscription(self, url_or_uri: str, sub_id: str = "default") -> int:
        """Fetch/parse a VPN subscription URL or URI, persist it, and regenerate sing-box/exclude configs."""
        clean_input = url_or_uri.strip()
        if not clean_input:
            return 0
        nodes = _run_coro_sync(fetch_subscription(clean_input, subscription_id=sub_id))
        if not nodes:
            return 0

        storage = Storage(self.db_path)
        try:
            had_nodes_before = len(storage.get_all_subscription_nodes())
            storage.save_subscription(
                sub_id=sub_id,
                url_or_uri=clean_input,
                nodes=[n.model_dump(mode="json") for n in nodes],
            )
        finally:
            storage.close()

        if had_nodes_before == 0:
            sb_running = bool((self._collect_processes_state().get("sing-box") or {}).get("running"))
            if not sb_running:
                (self.bin_dir.resolve() / "singbox-cache.db").unlink(missing_ok=True)

        clear_vpn_dns_cache()
        self.trigger_apply_configs()
        self._reload_running_services(winws2=True, singbox=True)
        return len(nodes)

    def refresh_vpn_subscriptions(self) -> dict[str, int]:
        """Refresh all stored VPN subscriptions and regenerate sing-box/exclude configs."""
        storage = Storage(self.db_path)
        try:
            results = _run_coro_sync(refresh_all_subscriptions(storage))
        finally:
            storage.close()

        if any(count > 0 for count in results.values()):
            clear_vpn_dns_cache()
            self.trigger_apply_configs()
            self._reload_running_services(winws2=True, singbox=True)
        return results

    def read_config_preview(self) -> dict[str, str]:
        """Read generated config files and hostlists safely (truncating files > 128 KB)."""
        previews: dict[str, str] = {}
        for rel_name in ("winws2_preset.txt", "sing-box.json"):
            fpath = self.configs_dir / rel_name
            if fpath.is_file():
                previews[f"configs/{rel_name}"] = _read_truncated_text(fpath)

        if self.lists_dir.is_dir():
            for lpath in sorted(self.lists_dir.glob("*.txt")):
                if lpath.is_file():
                    previews[f"lists/{lpath.name}"] = _read_truncated_text(lpath)
        return previews

    def read_logs_tail(self, max_lines: int = 80) -> dict[str, str]:
        """Return the last `max_lines` of winws2.log, sing-box.log, and tg-ws-proxy.log."""
        return {
            fname: _read_tail_lines(self.logs_dir / fname, max_lines=max_lines)
            for fname in LOG_FILENAMES
        }
