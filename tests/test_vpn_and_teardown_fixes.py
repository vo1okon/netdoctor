"""Regression tests for Telegram/VPN routing, winws2 VPN exclusions, and process-tree teardown."""

from __future__ import annotations

import asyncio
import json
import socket
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import dns.resolver
import psutil
import pytest

from netdoctor.config_gen import (
    DEFAULT_BYPASS_PROCESSES,
    _resolve_single_hostname,
    clear_vpn_dns_cache,
    generate_singbox_config,
    generate_winws2_config,
)
from netdoctor.gui_backend import GuiBackend
from netdoctor.models import (
    Decision,
    DnsProbeResult,
    NetworkFingerprint,
    NetworkKind,
    ProbesSummary,
    Protocol,
    Strategy,
    TcpProbeResult,
    TlsProbeResult,
    VpnNode,
)
from netdoctor.orchestrators import RealtimeConnectionMonitor
from netdoctor.presets import compile_zapret_preset
from netdoctor.storage import Storage
from netdoctor.supervisor import (
    ProcessSupervisor,
    is_local_port_busy,
    stop_persisted_supervisor,
    validate_singbox_config,
)
from netdoctor.vpn import parse_single_uri


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait_tcp_open(port: int, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def test_singbox_vpn_precedes_tg_ws_out_expands_cdn_scopes_tun_and_excludes_ru(tmp_path: Path) -> None:
    assert "pythonw.exe" in DEFAULT_BYPASS_PROCESSES

    vpn_nodes = [
        VpnNode(
            tag="🇷🇺RU-Fast",
            protocol="vless",
            server="ru1.example.com",
            server_port=443,
            region="ru",
            raw_outbound={"type": "vless", "tag": "🇷🇺RU-Fast", "server": "ru1.example.com", "server_port": 443, "uuid": "00000000-0000-0000-0000-000000000001"},
        ),
        VpnNode(
            tag="🇩🇪DE-Node",
            protocol="vless",
            server="de1.example.com",
            server_port=443,
            region="eu",
            raw_outbound={"type": "vless", "tag": "🇩🇪DE-Node", "server": "de1.example.com", "server_port": 443, "uuid": "00000000-0000-0000-0000-000000000002"},
        ),
    ]
    decisions = [
        Decision(network_key="net", domain="telegram.org", protocol=Protocol.TLS, layer="vpn", strategy_id="vpn-select"),
        Decision(network_key="net", domain="claude.ai", protocol=Protocol.TLS, layer="vpn", strategy_id="vpn-ai"),
        Decision(network_key="net", domain="rutracker.org", protocol=Protocol.TLS, layer="vpn", strategy_id="byedpi-out"),
    ]

    sb_path = tmp_path / "sing-box.json"
    cfg = generate_singbox_config(
        decisions=decisions,
        vpn_nodes=vpn_nodes,
        output_path=sb_path,
        enable_tun=True,
        enable_byedpi=True,
    )

    rules = cfg["route"]["rules"]
    proc_idx = next(i for i, r in enumerate(rules) if r.get("outbound") == "direct" and "process_name" in r)
    vpn_idx = next(i for i, r in enumerate(rules) if r.get("outbound") == "vpn-select")
    vpn_ai_idx = next(i for i, r in enumerate(rules) if r.get("outbound") == "vpn-ai")
    byedpi_idx = next(i for i, r in enumerate(rules) if r.get("outbound") == "byedpi-out")
    tg_idx = next(i for i, r in enumerate(rules) if r.get("outbound") == "tg-ws-out")

    assert rules[proc_idx]["inbound"] == ["tun-in"]
    assert "pythonw.exe" in rules[proc_idx]["process_name"]
    assert proc_idx < vpn_idx < tg_idx
    assert proc_idx < vpn_ai_idx < tg_idx
    assert proc_idx < byedpi_idx < tg_idx
    assert "telegram.org" in rules[vpn_idx]["domain_suffix"]
    assert "t.me" in rules[vpn_idx]["domain_suffix"]
    assert "claude.ai" in rules[vpn_ai_idx]["domain_suffix"]
    assert "rutracker.org" in rules[byedpi_idx]["domain_suffix"]

    # vpn-auto prefers non-RU nodes when available
    vpn_auto = next(o for o in cfg["outbounds"] if o["tag"] == "vpn-auto")
    assert vpn_auto["outbounds"] == ["🇩🇪DE-Node"]

    # Fallback: if only RU nodes exist, vpn-auto keeps them
    ru_only_cfg = generate_singbox_config(decisions=[], vpn_nodes=[vpn_nodes[0]], enable_tun=False)
    ru_auto = next(o for o in ru_only_cfg["outbounds"] if o["tag"] == "vpn-auto")
    assert ru_auto["outbounds"] == ["🇷🇺RU-Fast"]
    no_tun_proc = next(r for r in ru_only_cfg["route"]["rules"] if "process_name" in r)
    assert "inbound" not in no_tun_proc

    if (Path("bin") / "sing-box.exe").is_file():
        ok, err = validate_singbox_config("bin", sb_path)
        assert ok is True, f"sing-box check failed: {err}"


def test_vpn_dns_fallback_host_exclusions_udp_pass_and_tag_strip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clear_vpn_dns_cache()

    class _FakeAns:
        def __init__(self, ips: list[str]) -> None:
            self._ips = [SimpleNamespace(address=ip) for ip in ips]
            self.nameserver = "1.1.1.1"

        def __iter__(self):
            return iter(self._ips)

    def fake_resolve(self: dns.resolver.Resolver, qname: str, rdtype: str = "A") -> Any:
        if qname == "missing.example.invalid":
            raise dns.resolver.NXDOMAIN()
        if "1.1.1.1" in (getattr(self, "nameservers", []) or []):
            return _FakeAns(["203.0.113.55"])
        raise dns.resolver.LifetimeTimeout()

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", fake_resolve)
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_a, **_kw: (_ for _ in ()).throw(socket.gaierror("no local")),
    )

    assert _resolve_single_hostname("vpn-node.example.com") == ["203.0.113.55"]
    assert _resolve_single_hostname("missing.example.invalid") == []

    # generate_winws2_config excludes VPN server hostnames in circular --hostlist-exclude
    lists_dir = tmp_path / "lists"
    strategies = {
        "tls_s1": Strategy(
            id="tls_s1",
            family="multisplit",
            protocol=Protocol.TLS,
            tier=2,
            args_template=["--lua-desync=multisplit:pos=2"],
        )
    }
    args, _ = generate_winws2_config(
        decisions=[Decision(network_key="net", domain="discord.com", protocol=Protocol.TLS, layer="dpi", strategy_id="tls_s1")],
        strategies=strategies,
        lists_dir=lists_dir,
        vpn_server_ips=["vpn-node.example.com"],
    )
    assert any("--hostlist-exclude=" in a and "exclude_unlocker_domains.txt" in a for a in args)
    assert "vpn-node.example.com" in (lists_dir / "exclude_unlocker_domains.txt").read_text(encoding="utf-8")

    # compile_zapret_preset emits both TCP and UDP pass profiles for exclude_vpn_ips.txt
    compiled = compile_zapret_preset(
        "--filter-tcp=443\n--lua-desync=fake:blob=tls_google:repeats=4",
        bin_dir="bin",
        lists_dir=tmp_path / "preset_lists",
        vpn_server_ips=["203.0.113.55"],
    )
    assert any(tok.startswith("--filter-tcp=") for tok in compiled)
    assert any(tok.startswith("--filter-udp=443,1024-65535") for tok in compiled)

    # parse_single_uri strips trailing spaces from node fragment tag
    node = parse_single_uri("vless://11111111-2222-3333-4444-555555555555@198.51.100.1:443?security=tls#NL%20Node%20%20")
    assert node is not None
    assert node.tag == "NL Node"
    assert node.raw_outbound["tag"] == "NL Node"


def _spawn_parent_with_bound_child_script() -> str:
    return (
        "import os, socket, subprocess, sys, time\n"
        "mode = sys.argv[1]\n"
        "port = int(sys.argv[2])\n"
        "pid_file = sys.argv[3]\n"
        "if mode == 'child':\n"
        "    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "    s.bind(('127.0.0.1', port))\n"
        "    s.listen(1)\n"
        "    with open(pid_file, 'w', encoding='utf-8') as f:\n"
        "        f.write(str(os.getpid()))\n"
        "    while True:\n"
        "        time.sleep(0.2)\n"
        "else:\n"
        "    c = subprocess.Popen([sys.executable, '-c', sys.argv[4], 'child', str(port), pid_file, ''])\n"
        "    while True:\n"
        "        time.sleep(0.2)\n"
    )


def test_supervisor_stop_process_and_persisted_kill_child_tree_and_free_port(tmp_path: Path) -> None:
    script = _spawn_parent_with_bound_child_script()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    logs_dir = tmp_path / "logs"

    # 1. ProcessSupervisor.stop_process kills parent + child and releases port
    port1 = _find_free_port()
    pid_file1 = tmp_path / "child1.pid"
    sup = ProcessSupervisor(bin_dir=bin_dir, logs_dir=logs_dir)
    sup.start_process(
        "tg-ws-proxy",
        [sys.executable, "-c", script, "parent", str(port1), str(pid_file1), script],
        cwd=tmp_path,
    )
    assert _wait_tcp_open(port1, timeout=5.0)
    child_pid1 = int(pid_file1.read_text(encoding="utf-8").strip())
    assert psutil.pid_exists(child_pid1)

    sup.stop_process("tg-ws-proxy")
    assert not is_local_port_busy(port1)
    assert not psutil.pid_exists(child_pid1)

    # 2. adopt_persisted_state + stop_all stops adopted parent + child
    port2 = _find_free_port()
    pid_file2 = tmp_path / "child2.pid"
    sup_a = ProcessSupervisor(bin_dir=bin_dir, logs_dir=logs_dir)
    sup_a.start_process(
        "tg-ws-proxy",
        [sys.executable, "-c", script, "parent", str(port2), str(pid_file2), script],
        cwd=tmp_path,
    )
    assert _wait_tcp_open(port2, timeout=5.0)
    child_pid2 = int(pid_file2.read_text(encoding="utf-8").strip())

    sup_b = ProcessSupervisor(bin_dir=bin_dir, logs_dir=logs_dir)
    adopted = sup_b.adopt_persisted_state()
    assert "tg-ws-proxy" in adopted
    sup_b.stop_all()
    assert not is_local_port_busy(port2)
    assert not psutil.pid_exists(child_pid2)

    # 3. stop_persisted_supervisor kills parent + child and clears state file
    port3 = _find_free_port()
    pid_file3 = tmp_path / "child3.pid"
    sup_c = ProcessSupervisor(bin_dir=bin_dir, logs_dir=logs_dir)
    sup_c.start_process(
        "tg-ws-proxy",
        [sys.executable, "-c", script, "parent", str(port3), str(pid_file3), script],
        cwd=tmp_path,
    )
    assert _wait_tcp_open(port3, timeout=5.0)
    child_pid3 = int(pid_file3.read_text(encoding="utf-8").strip())

    stopped = stop_persisted_supervisor(logs_dir=logs_dir, bin_dir=bin_dir)
    assert "tg-ws-proxy" in stopped
    assert not is_local_port_busy(port3)
    assert not psutil.pid_exists(child_pid3)


def test_watchdog_idle_stopping_guards_and_auto_heal_reloads_singbox(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "wd.db"
    backend = GuiBackend(
        db_path=db_path,
        configs_dir=tmp_path / "configs",
        lists_dir=tmp_path / "lists",
        logs_dir=tmp_path / "logs",
        bin_dir=Path("bin").resolve(),
    )
    monkeypatch.setattr("netdoctor.gui_backend._is_admin", lambda: True)

    # Explicit stack_desired_running="0" stays idle even if a leftover tg-ws-proxy reports running
    st = Storage(db_path)
    try:
        st.set_setting("stack_desired_running", "0")
    finally:
        st.close()
    monkeypatch.setattr(
        backend,
        "_collect_processes_state",
        lambda: {"winws2": {"running": False}, "sing-box": {"running": False}, "tg-ws-proxy": {"running": True}},
    )
    res_idle = backend.ensure_services_healthy()
    assert res_idle["skipped"] == "idle"
    assert res_idle["restarted"] == []

    backend._stopping = True
    res_stopping = backend.ensure_services_healthy()
    assert res_stopping["skipped"] == "stopping"
    backend._stopping = False

    # Live auto-heal reloads sing-box when a failing domain escalates to layer="vpn"
    st = Storage(db_path)
    try:
        st.save_subscription(
            "sub1",
            "https://sub.example",
            [
                {
                    "tag": "DE-1",
                    "protocol": "vless",
                    "server": "198.51.100.44",
                    "server_port": 443,
                    "raw_outbound": {"type": "vless", "tag": "DE-1", "server": "198.51.100.44", "server_port": 443},
                }
            ],
        )
    finally:
        st.close()

    import netdoctor.orchestrators as orch_mod

    monkeypatch.setattr(orch_mod, "_is_admin", lambda: True)
    monkeypatch.setattr(orch_mod, "detect_bypass_active", lambda: True)
    monkeypatch.setattr(
        orch_mod,
        "detect_network_fingerprint",
        lambda timeout=2.0: asyncio.sleep(0, result=NetworkFingerprint(asn=8402, kind=NetworkKind.HOME, isp="ISP")),
    )
    monkeypatch.setattr(
        orch_mod,
        "run_domain_probes",
        lambda dom, timeout=2.0: asyncio.sleep(
            0,
            result=ProbesSummary(
                dns=DnsProbeResult(system="ok", doh="ok", system_ips=["198.51.100.99"], doh_ips=["198.51.100.99"]),
                tcp=TcpProbeResult(result="timeout", target_ip="198.51.100.99"),
                tls=TlsProbeResult(real_sni="timeout", neutral_sni="timeout"),
            ),
        ),
    )

    mon = RealtimeConnectionMonitor()
    monkeypatch.setattr(
        mon,
        "scan_active_connections",
        lambda *a, **kw: [
            {
                "process": "chrome.exe",
                "pid": 1111,
                "remote_ip": "198.51.100.99",
                "remote_port": 443,
                "remote": "198.51.100.99:443",
                "protocol": "tls",
                "socket_status": "SYN_SENT",
                "domain": "blocked-vpn.example",
                "layer": "direct",
                "strategy_id": None,
                "health": "needs_fix",
            }
        ],
    )
    monkeypatch.setattr(
        backend,
        "_collect_processes_state",
        lambda: {"winws2": {"running": True}, "sing-box": {"running": True}},
    )
    sb_reloads: list[str] = []
    winws_reloads: list[str] = []
    monkeypatch.setattr(backend, "reload_winws2_if_changed", lambda **_kw: (winws_reloads.append("winws2"), {"ok": True})[1])
    monkeypatch.setattr(backend, "reload_singbox_if_changed", lambda **_kw: (sb_reloads.append("sing-box"), {"ok": True})[1])

    out = asyncio.run(
        mon.auto_heal_connections(backend=backend, max_domains_per_tick=1)
    )
    assert out["healed"] and out["healed"][0]["layer"] == "vpn"
    assert sb_reloads == ["sing-box"]
    assert winws_reloads == ["winws2"]


def test_supervisor_reload_and_stop_under_pythonw_no_monotonic_systemerror(tmp_path: Path) -> None:
    if sys.platform != "win32":
        pytest.skip("Windows-only pythonw.exe consoleless test")
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    if not pythonw.is_file():
        pytest.skip("pythonw.exe not found next to sys.executable")

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    logs_dir = tmp_path / "logs"
    out_file = tmp_path / "pythonw_result.txt"
    script = tmp_path / "pythonw_worker.py"
    script.write_text(
        "\n".join(
            [
                "import pathlib, sys, time, traceback",
                "from netdoctor.supervisor import ProcessSupervisor",
                "",
                "out_file = pathlib.Path(sys.argv[1])",
                "bin_dir = pathlib.Path(sys.argv[2])",
                "logs_dir = pathlib.Path(sys.argv[3])",
                "sys_exe = sys.argv[4]",
                "sup = ProcessSupervisor(bin_dir=bin_dir, logs_dir=logs_dir)",
                "cmd = [sys_exe, '-c', 'import time; time.sleep(30)']",
                "try:",
                "    sup.start_process('winws2', cmd, cwd=bin_dir)",
                "    time.sleep(0.2)",
                "    sup.reload_process('winws2', cmd, cwd=bin_dir)",
                "    time.sleep(0.2)",
                "    sup.stop_all()",
                "    _ = time.monotonic()",
                "    out_file.write_text('OK', encoding='utf-8')",
                "except BaseException:",
                "    try:",
                "        sup.stop_all()",
                "    except BaseException:",
                "        pass",
                "    out_file.write_text(traceback.format_exc(), encoding='utf-8')",
            ]
        ),
        encoding="utf-8",
    )

    res = subprocess.run(
        [str(pythonw), str(script), str(out_file), str(bin_dir), str(logs_dir), sys.executable],
        timeout=20,
        check=False,
    )
    assert res.returncode == 0
    assert out_file.is_file()
    assert out_file.read_text(encoding="utf-8").strip() == "OK"
