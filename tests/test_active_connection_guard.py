"""Regression tests for protecting live active connections from unnecessary resets, strategy cycling, or reloads."""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import socket as sock_mod
import time
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import psutil
import pytest

import netdoctor.gui_backend as backend_mod
import netdoctor.orchestrators as orch_mod
from netdoctor.config_gen import (
    DEFAULT_GAME_PROCESSES,
    GAME_BYPASS_PORT_RANGES,
    GAME_BYPASS_PORTS,
    generate_singbox_config,
    generate_winws2_config,
    generate_xray_bridge_config,
    needs_xray_bridge,
)
from netdoctor.presets import compile_zapret_preset
from netdoctor.gui_backend import GuiBackend
from netdoctor.models import (
    Decision,
    DnsProbeResult,
    NetworkFingerprint,
    NetworkKind,
    ProbesSummary,
    Protocol,
    QuicProbeResult,
    StallProbeResult,
    Strategy,
    TcpProbeResult,
    TlsProbeResult,
    VpnNode,
)
from netdoctor.orchestrators import RealtimeConnectionMonitor, VpnLayerOrchestrator
from netdoctor.selector import DEFAULT_STRATEGIES
from netdoctor.storage import Storage
from netdoctor.supervisor import fetch_xray_binary, validate_singbox_config, validate_xray_config


def _seed_storage(db_path: Path, decisions: list[Decision] | None = None) -> tuple[Storage, str]:
    st = Storage(db_path)
    net_key = st.upsert_network(
        NetworkFingerprint(asn=12389, kind=NetworkKind.HOME, isp="TestISP", gateway_mac="aa:bb:cc:dd:ee:ff")
    )
    for d in decisions or []:
        st.save_decision(d)
    return st, net_key


def _rfc3339_ago(seconds: float, *, seven_digits: bool = False) -> str:
    dt = (datetime.now(timezone.utc) - timedelta(seconds=seconds)).astimezone()
    iso = dt.isoformat()
    if seven_digits and "." in iso:
        head, tail = iso.split(".", 1)
        frac = tail[:6]
        rest = tail[6:]
        return f"{head}.{frac}4{rest}"
    return iso


def test_healthy_connections_not_flagged_or_cycled(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db_path = tmp_path / "live_guard.db"
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    # Simulate stale circular rotation lines in winws2.log for domains that are actually healthy now
    (logs_dir / "winws2.log").write_text(
        "LUA: automate: host record key 'autostate.circular_8_1.edge.microsoft.com'\n"
        "LUA: circular: rotate strategy to 2\n"
        "LUA: automate: host record key 'autostate.circular_8_1.mc.hypixel.net'\n"
        "LUA: circular: rotate strategy to 2\n",
        encoding="utf-8",
    )

    st, net_key = _seed_storage(db_path)
    try:
        monkeypatch.setattr(psutil, "net_connections", lambda kind="inet": [])

        class _FakeClash:
            def get_connections_sync(self) -> dict[str, Any]:
                return {
                    "connections": [
                        # Active Minecraft game connection (stateful TCP:25565) with bidirectional traffic
                        {
                            "id": "c-mc",
                            "start": _rfc3339_ago(95.0, seven_digits=True),
                            "upload": 20480,
                            "download": 98304,
                            "chains": ["direct"],
                            "metadata": {
                                "network": "tcp",
                                "destinationIP": "172.65.236.31",
                                "destinationPort": 25565,
                                "host": "mc.hypixel.net",
                                "processPath": r"E:\mc\javaw.exe",
                            },
                        },
                        # Healthy HTTPS flow even with no explicit decision and older circular log rotation
                        {
                            "id": "c-edge",
                            "start": _rfc3339_ago(40.0),
                            "upload": 600,
                            "download": 2400,
                            "chains": ["direct"],
                            "metadata": {
                                "network": "tcp",
                                "destinationIP": "150.171.28.11",
                                "destinationPort": 443,
                                "host": "edge.microsoft.com",
                                "processPath": r"C:\Program Files\Microsoft\Edge\msedge.exe",
                            },
                        },
                        # Brand-new 0.5s TLS flow with upload>0, download=0 -> not yet stalled
                        {
                            "id": "c-fresh",
                            "start": _rfc3339_ago(0.5),
                            "upload": 120,
                            "download": 0,
                            "chains": ["direct"],
                            "metadata": {
                                "network": "tcp",
                                "destinationIP": "198.51.100.40",
                                "destinationPort": 443,
                                "host": "fresh.example",
                                "processPath": r"C:\Apps\browser.exe",
                            },
                        },
                        # Non-443 UDP (STUN 3478) -> never marked STALLED just because download == 0
                        {
                            "id": "c-stun",
                            "start": _rfc3339_ago(30.0),
                            "upload": 420,
                            "download": 0,
                            "chains": ["direct"],
                            "metadata": {
                                "network": "udp",
                                "destinationIP": "20.202.0.81",
                                "destinationPort": 3478,
                                "host": "",
                                "processPath": r"C:\Windows\CrossDeviceService.exe",
                            },
                        },
                        # Genuine stalled HTTPS connection (>3s old, upload>0, download=0)
                        {
                            "id": "c-stalled",
                            "start": _rfc3339_ago(6.0),
                            "upload": 512,
                            "download": 0,
                            "chains": ["direct"],
                            "metadata": {
                                "network": "tcp",
                                "destinationIP": "198.51.100.99",
                                "destinationPort": 443,
                                "host": "stalled-tcp.example",
                                "processPath": r"C:\Apps\browser.exe",
                            },
                        },
                    ]
                }

        mon = RealtimeConnectionMonitor()
        rows = mon.scan_active_connections(
            st,
            logs_dir,
            net_key=net_key,
            targets_file=tmp_path / "no_targets.yaml",
            clash_client=_FakeClash(),  # type: ignore[arg-type]
        )
        by_dom = {r["domain"]: r for r in rows}

        assert by_dom["mc.hypixel.net"]["health"] == "direct"
        assert by_dom["mc.hypixel.net"]["active_healthy"] is True
        assert by_dom["edge.microsoft.com"]["health"] == "direct"
        assert by_dom["edge.microsoft.com"]["active_healthy"] is True
        assert by_dom["fresh.example"]["socket_status"] == "ESTABLISHED"
        assert by_dom["fresh.example"]["health"] == "direct"
        stun_row = next(r for r in rows if r["remote_port"] == 3478)
        assert stun_row["socket_status"] == "ESTABLISHED"
        assert stun_row["health"] == "direct"
        assert by_dom["stalled-tcp.example"]["socket_status"] == "STALLED"
        assert by_dom["stalled-tcp.example"]["health"] == "needs_fix"

        cands = mon._collect_fix_candidates(rows, logs_dir, max_domains=5)
        cand_doms = [c[0] for c in cands]
        assert cand_doms == ["stalled-tcp.example"]
    finally:
        st.close()


def test_defer_reloads_while_active_connections_live_and_flush_on_idle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = tmp_path / "defer.db"
    configs_dir = tmp_path / "configs"
    lists_dir = tmp_path / "lists"
    logs_dir = tmp_path / "logs"
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    st, _nk = _seed_storage(db_path)
    st.set_setting("stack_desired_running", "1")
    st.close()

    backend = GuiBackend(
        db_path=db_path,
        configs_dir=configs_dir,
        lists_dir=lists_dir,
        logs_dir=logs_dir,
        bin_dir=bin_dir,
    )
    backend._desired_running = True
    backend._last_singbox_hash = "old-sb-hash"
    backend._last_winws2_hash = "old-winws-hash"
    backend._last_singbox_reload_ts = 0.0
    backend._last_winws2_reload_ts = 0.0

    monkeypatch.setattr(backend_mod, "_is_admin", lambda: True)
    monkeypatch.setattr(
        backend,
        "_collect_processes_state",
        lambda: {
            "winws2": {"running": True, "pid": 111},
            "sing-box": {"running": True, "pid": 222},
            "tg-ws-proxy": {"running": True, "pid": 333},
        },
    )
    monkeypatch.setattr(backend, "_detect_local_gateway_ip", lambda: "")

    sb_reloads = 0
    winws_reloads = 0

    def fake_reload_singbox(iface: int | None = None) -> dict[str, Any]:
        nonlocal sb_reloads
        sb_reloads += 1
        applied = backend.trigger_apply_configs(iface=iface)
        sb_path = Path(applied["singbox_config"])
        import hashlib

        backend._last_singbox_hash = hashlib.sha256(sb_path.read_bytes()).hexdigest()
        backend._last_singbox_reload_ts = 1e12
        backend._pending_singbox_reload = False
        return {"ok": True, "reloaded": True}

    def fake_reload_winws2(iface: int | None = None, *, applied: dict[str, Any] | None = None) -> dict[str, Any]:
        nonlocal winws_reloads
        winws_reloads += 1
        app = applied or backend.trigger_apply_configs(iface=iface)
        backend._last_winws2_hash = backend._winws2_args_hash(app["winws2_args"])
        backend._last_winws2_reload_ts = 1e12
        backend._pending_winws2_reload = False
        return {"ok": True, "reloaded": True}

    monkeypatch.setattr(backend, "reload_singbox", fake_reload_singbox)
    monkeypatch.setattr(backend, "reload_winws2", fake_reload_winws2)

    live_conns: list[dict[str, Any]] = [
        {
            "id": "mc-live",
            "start": _rfc3339_ago(120.0),
            "upload": 5000,
            "download": 25000,
            "chains": ["direct"],
            "metadata": {
                "network": "tcp",
                "destinationIP": "172.65.236.31",
                "destinationPort": 25565,
                "processPath": r"E:\mc\javaw.exe",
            },
        }
    ]
    monkeypatch.setattr(backend.clash_api, "get_connections_sync", lambda: {"connections": live_conns})

    # Active Hypixel session defers background reloads
    res_sb = backend.reload_singbox_if_changed(min_interval_sec=0.0, defer_if_active=True)
    res_w = backend.reload_winws2_if_changed(min_interval_sec=0.0, defer_if_active=True)
    assert res_sb["deferred"] is True and res_sb["reloaded"] is False
    assert res_w["deferred"] is True and res_w["reloaded"] is False
    assert backend._pending_singbox_reload is True
    assert backend._pending_winws2_reload is True
    assert sb_reloads == 0
    assert winws_reloads == 0

    # Manual explicit reload (defer_if_active=False) still applies immediately
    res_manual = backend.reload_singbox_if_changed(min_interval_sec=0.0, defer_if_active=False)
    assert res_manual["reloaded"] is True
    assert sb_reloads == 1

    # Actively flowing web transfer (fresh 443 socket) also defers, while old idle keep-alive flushes via watchdog
    backend._last_singbox_hash = "old-sb-hash"
    backend._last_singbox_reload_ts = 0.0
    backend._last_winws2_hash = "old-winws-hash"
    backend._last_winws2_reload_ts = 0.0
    backend._clash_conn_traffic.clear()
    live_conns[:] = [
        {
            "id": "web-active",
            "start": _rfc3339_ago(2.0),
            "upload": 800,
            "download": 16000,
            "chains": ["direct"],
            "metadata": {
                "network": "tcp",
                "destinationIP": "150.171.28.11",
                "destinationPort": 443,
                "processPath": r"C:\Apps\chrome.exe",
            },
        }
    ]
    assert backend.reload_singbox_if_changed(min_interval_sec=0.0, defer_if_active=True)["deferred"] is True
    assert backend.reload_winws2_if_changed(min_interval_sec=0.0, defer_if_active=True)["deferred"] is True
    assert sb_reloads == 1 and winws_reloads == 0

    # Simulate past session grace expiry with only an old idle keep-alive remaining
    backend._clash_conn_traffic.clear()
    backend._last_stateful_session_ts = 0.0
    live_conns[:] = [
        {
            "id": "web-idle",
            "start": _rfc3339_ago(30.0),
            "upload": 800,
            "download": 16000,
            "chains": ["direct"],
            "metadata": {
                "network": "tcp",
                "destinationIP": "150.171.28.11",
                "destinationPort": 443,
                "processPath": r"C:\Apps\chrome.exe",
            },
        }
    ]
    wd = backend.ensure_services_healthy()
    assert "sing-box" in wd["restarted"]
    assert "winws2" in wd["restarted"]
    assert sb_reloads == 2
    assert winws_reloads == 1
    assert backend._pending_singbox_reload is False
    assert backend._pending_winws2_reload is False


def test_vpn_reconciler_preserves_active_session_on_glitch_and_defers_failback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    st, _nk = _seed_storage(tmp_path / "vpn_guard.db")
    try:
        st.set_vpn_selection_policy(
            mode="priority",
            priority_node="Priority1",
            priorities={"Priority1": 1, "Fallback2": 10},
        )
        nodes = [
            {
                "tag": "Priority1",
                "display_name": "Priority 1",
                "protocol": "vless",
                "server": "198.51.100.1",
                "server_port": 443,
                "priority": 1,
                "enabled": True,
                "region": "eu",
            },
            {
                "tag": "Fallback2",
                "display_name": "Fallback 2",
                "protocol": "vless",
                "server": "198.51.100.2",
                "server_port": 443,
                "priority": 10,
                "enabled": True,
                "region": "eu",
            },
        ]

        class _FakeClash:
            def __init__(self) -> None:
                self.sel_now = "Fallback2"
                self.select_calls: list[tuple[str, str]] = []
                self.closed_nodes: list[str] = []
                self.conns: list[dict[str, Any]] = [
                    {
                        "id": "v-1",
                        "upload": 4096,
                        "download": 16384,
                        "chains": ["Fallback2", "vpn-select"],
                    }
                ]
                self.delay_plan: dict[str, list[dict[str, Any]]] = {}

            async def get_proxies(self) -> dict[str, Any]:
                return {
                    "vpn-select": {"type": "Selector", "now": self.sel_now, "all": ["vpn-auto", "Priority1", "Fallback2"]},
                    "vpn-auto": {"type": "URLTest", "now": "Priority1", "all": ["Priority1", "Fallback2"]},
                    "Priority1": {"type": "VLESS", "history": []},
                    "Fallback2": {"type": "VLESS", "history": []},
                }

            async def get_connections(self) -> dict[str, Any]:
                return {"connections": self.conns}

            async def measure_node_delay(self, tag: str, **_kw: Any) -> dict[str, Any]:
                q = self.delay_plan.get(tag)
                if q:
                    return q.pop(0) if len(q) > 1 else q[0]
                return {"ok": True, "delay_ms": 50.0, "error": None}

            async def select_outbound(self, sel: str, target: str) -> bool:
                self.sel_now = target
                self.select_calls.append((sel, target))
                return True

            async def close_connections_by_node(self, tag: str) -> int:
                self.closed_nodes.append(tag)
                return 1

        from netdoctor.models import TcpProbeResult

        async def _no_sleep(_sec: float) -> None:
            return None

        async def _fast_tcp_timeout(ip: str, port: int = 443, timeout: float = 1.0) -> TcpProbeResult:
            return TcpProbeResult(result="timeout", target_ip=ip)

        monkeypatch.setattr(orch_mod.asyncio, "sleep", _no_sleep)
        monkeypatch.setattr(orch_mod, "probe_tcp", _fast_tcp_timeout)
        orch = VpnLayerOrchestrator()
        clash = _FakeClash()

        # 1. Single transient timeout on active Fallback2 with live traffic -> retry succeeds -> stay put!
        clash.delay_plan = {
            "Fallback2": [{"ok": False, "delay_ms": None, "error": "timeout"}, {"ok": True, "delay_ms": 80.0, "error": None}],
            "Priority1": [{"ok": True, "delay_ms": 40.0, "error": None}],
        }
        res_glitch = asyncio.run(orch.reconcile_active_node(st, nodes, clash_client=clash, force=False))  # type: ignore[arg-type]
        assert res_glitch["ok"] is True
        assert res_glitch["action"] == "keep_active_session"
        assert res_glitch["selected"] == "Fallback2"
        assert clash.select_calls == []
        assert clash.closed_nodes == []

        # 2. Defers failback_priority while live traffic flows; force=True switches immediately
        clash.delay_plan = {
            "Fallback2": [{"ok": True, "delay_ms": 75.0, "error": None}],
            "Priority1": [{"ok": True, "delay_ms": 35.0, "error": None}],
        }
        res_defer = asyncio.run(orch.reconcile_active_node(st, nodes, clash_client=clash, force=False))  # type: ignore[arg-type]
        assert res_defer["action"] == "keep_active_session"
        assert clash.select_calls == []

        res_force = asyncio.run(orch.reconcile_active_node(st, nodes, clash_client=clash, force=True))  # type: ignore[arg-type]
        assert res_force["action"] == "failback_priority"
        assert res_force["selected"] == "Priority1"

        # 3. Auto mode with sel_now != vpn-auto defers return_to_auto while traffic runs on Fallback2
        st.set_vpn_selection_policy(mode="auto", priority_node="", priorities={"Priority1": 100, "Fallback2": 100})
        clash.sel_now = "Fallback2"
        clash.select_calls.clear()
        res_auto_keep = asyncio.run(orch.reconcile_active_node(st, nodes, clash_client=clash, force=False))  # type: ignore[arg-type]
        assert res_auto_keep["action"] == "keep_active_session"
        assert res_auto_keep["selected"] == "Fallback2"
        assert clash.select_calls == []

        # 4. Double failure on active Fallback2 -> genuinely fail over & close dead connections
        clash.delay_plan = {
            "Fallback2": [
                {"ok": False, "delay_ms": None, "error": "timeout"},
                {"ok": False, "delay_ms": None, "error": "timeout"},
                {"ok": False, "delay_ms": None, "error": "timeout"},
            ],
            "Priority1": [{"ok": True, "delay_ms": 35.0, "error": None}],
        }
        res_fail = asyncio.run(orch.reconcile_active_node(st, nodes, clash_client=clash, force=False))  # type: ignore[arg-type]
        assert res_fail["action"] in ("failover", "return_to_auto")
        assert res_fail["selected"] == "Priority1"
        assert clash.closed_nodes == ["Fallback2"]
    finally:
        st.close()


def test_winws2_tcp_filter_excludes_game_ports_and_active_direct_domains(tmp_path: Path) -> None:
    lists_dir = tmp_path / "lists"
    decisions = [
        Decision(
            network_key="AS12389:home:test",
            domain="api.hypixel.net",
            protocol=Protocol.TLS,
            layer="direct",
            status="active",
        ),
        Decision(
            network_key="AS12389:home:test",
            domain="stale.example",
            protocol=Protocol.TLS,
            layer="direct",
            status="degraded",
        ),
    ]
    strat_map: dict[str, Strategy] = {s.id: s for s in DEFAULT_STRATEGIES}
    args, _ = generate_winws2_config(
        decisions,
        strat_map,
        lists_dir=lists_dir,
        game_filter=True,
    )

    tcp_out = next(a for a in args if a.startswith("--wf-tcp-out="))
    udp_out = next(a for a in args if a.startswith("--wf-udp-out="))
    assert "1024-65535" not in tcp_out
    assert "1024-65535" in udp_out
    assert "--filter-udp=1024-65535" in args

    excl_text = (lists_dir / "exclude_unlocker_domains.txt").read_text(encoding="utf-8")
    excl_lines = {line.strip() for line in excl_text.splitlines() if line.strip()}
    assert "api.hypixel.net" in excl_lines
    assert "stale.example" not in excl_lines


def test_xray_bridge_config_and_singbox_mtu_and_scoped_sniff(tmp_path: Path) -> None:
    reality_node = VpnNode(
        tag="NL-Reality",
        protocol="vless",
        server="203.0.113.10",
        server_port=9443,
        region="eu",
        raw_outbound={
            "type": "vless",
            "tag": "NL-Reality",
            "server": "203.0.113.10",
            "server_port": 9443,
            "uuid": "11111111-2222-3333-4444-555555555555",
            "flow": "xtls-rprx-vision",
            "tls": {
                "enabled": True,
                "server_name": "yahoo.com",
                "utls": {"enabled": True, "fingerprint": "chrome"},
                "reality": {"enabled": True, "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "short_id": "abcd"},
            },
        },
    )
    xhttp_node = VpnNode(
        tag="DE-xhttp",
        protocol="vless",
        server="203.0.113.11",
        server_port=443,
        region="eu",
        raw_outbound={
            "type": "vless",
            "tag": "DE-xhttp",
            "server": "203.0.113.11",
            "server_port": 443,
            "uuid": "11111111-2222-3333-4444-555555555556",
            "transport": {"type": "xhttp", "path": "/xh"},
            "tls": {"enabled": True, "server_name": "cdn.example.com"},
        },
    )
    tls_node = VpnNode(
        tag="PL-TLS",
        protocol="vless",
        server="203.0.113.12",
        server_port=8443,
        region="eu",
        raw_outbound={
            "type": "vless",
            "tag": "PL-TLS",
            "server": "203.0.113.12",
            "server_port": 8443,
            "uuid": "11111111-2222-3333-4444-555555555557",
            "tls": {"enabled": True, "server_name": "cdn.example.net"},
        },
    )
    hy2_node = VpnNode(
        tag="FI-Hy2",
        protocol="hysteria2",
        server="203.0.113.13",
        server_port=443,
        region="eu",
        raw_outbound={
            "type": "hysteria2",
            "tag": "FI-Hy2",
            "server": "203.0.113.13",
            "server_port": 443,
            "password": "pw",
            "tls": {"enabled": True, "server_name": "cdn.hy2.example"},
        },
    )
    placeholder = VpnNode(
        tag="Автовыбор ⬇",
        protocol="vless",
        server="obid.obed",
        server_port=994,
        region="eu",
        raw_outbound={
            "type": "vless",
            "tag": "Автовыбор ⬇",
            "server": "obid.obed",
            "server_port": 994,
            "uuid": "00000000-0000-0000-0000-000000000000",
            "tls": {
                "enabled": True,
                "utls": {"enabled": True, "fingerprint": "chrome"},
                "reality": {"enabled": True, "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
            },
        },
    )
    nodes = [reality_node, xhttp_node, tls_node, hy2_node, placeholder]

    assert needs_xray_bridge(reality_node) is True
    assert needs_xray_bridge(xhttp_node) is True
    assert needs_xray_bridge(tls_node) is False
    assert needs_xray_bridge(hy2_node) is False
    assert needs_xray_bridge(placeholder) is False

    xray_path = tmp_path / "xray.json"
    xcfg, bridge_ports = generate_xray_bridge_config(nodes, output_path=xray_path)
    assert bridge_ports == {"NL-Reality": 18100, "DE-xhttp": 18101}
    assert xray_path.is_file()
    assert [ib["port"] for ib in xcfg["inbounds"]] == [18100, 18101]
    assert xcfg["outbounds"][0]["streamSettings"]["security"] == "reality"
    assert xcfg["outbounds"][1]["streamSettings"]["network"] == "xhttp"

    sb_path = tmp_path / "sing-box.json"
    sb_cfg = generate_singbox_config([], vpn_nodes=nodes, output_path=sb_path, xray_bridge_ports=bridge_ports)
    obs = {o["tag"]: o for o in sb_cfg["outbounds"] if isinstance(o, dict) and o.get("tag")}
    assert obs["NL-Reality"] == {"type": "socks", "tag": "NL-Reality", "server": "127.0.0.1", "server_port": 18100, "version": "5"}
    assert obs["DE-xhttp"] == {"type": "socks", "tag": "DE-xhttp", "server": "127.0.0.1", "server_port": 18101, "version": "5"}
    assert obs["PL-TLS"]["type"] == "vless"
    assert obs["FI-Hy2"]["type"] == "hysteria2"

    # TUN MTU & scoped sniff
    tun_in = next(i for i in sb_cfg["inbounds"] if i.get("type") == "tun")
    assert tun_in["mtu"] == 9000
    assert sb_cfg["route"]["rules"][0] == {
        "port": [53, 80, 443, 8080, 8443],
        "action": "sniff",
        "timeout": "100ms",
    }

    sb_exe = Path("bin") / "sing-box.exe"
    if sb_exe.is_file():
        ok, err = validate_singbox_config(Path("bin"), sb_path)
        assert ok, err

    # Without xray_bridge_ports, native VLESS-Reality outbound is preserved
    sb_native = generate_singbox_config([], vpn_nodes=[reality_node])
    native_ob = next(o for o in sb_native["outbounds"] if o.get("tag") == "NL-Reality")
    assert native_ob["type"] == "vless"
    assert native_ob["tls"]["reality"]["enabled"] is True


def test_storage_reinfer_other_regions(tmp_path: Path) -> None:
    st, _nk = _seed_storage(tmp_path / "regions.db")
    try:
        st.save_subscription(
            "sub1",
            "https://sub.example.com/1",
            [
                {
                    "tag": "bg-srv",
                    "display_name": "🇧🇬Болгария | WIFI",
                    "protocol": "vless",
                    "server": "198.51.100.20",
                    "server_port": 8443,
                    "region": "other",
                },
                {
                    "tag": "ca-srv",
                    "display_name": "🇨🇦Канада | WIFI",
                    "protocol": "vless",
                    "server": "198.51.100.21",
                    "server_port": 8443,
                    "region": "other",
                },
            ],
        )
        nodes = {n["tag"]: n for n in st.get_all_subscription_nodes()}
        assert nodes["bg-srv"]["region"] == "eu"
        assert nodes["ca-srv"]["region"] == "us"
    finally:
        st.close()


def test_active_working_connections_failsafe_and_grace_period(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = GuiBackend(
        db_path=tmp_path / "grace.db",
        configs_dir=tmp_path / "configs",
        lists_dir=tmp_path / "lists",
        logs_dir=tmp_path / "logs",
        bin_dir=tmp_path / "bin",
    )
    monkeypatch.setattr(backend, "_collect_processes_state", lambda: {"sing-box": {"running": True}, "winws2": {"running": True}})
    monkeypatch.setattr(backend.clash_api, "get_connections_sync", lambda: {})
    monkeypatch.setattr(
        backend.orchestrator.monitor,
        "_resolve_pid_name",
        lambda pid: {101: "xray.exe", 202: "javaw.exe", 303: "Discord.exe"}.get(pid, "other.exe"),
    )
    ps_conns = [
        # Internal xray bridge on 9443 must NOT trigger false lock
        SimpleNamespace(
            type=sock_mod.SOCK_STREAM,
            status="ESTABLISHED",
            raddr=SimpleNamespace(ip="203.0.113.10", port=9443),
            pid=101,
        ),
        # Active Minecraft javaw.exe TCP session even when Clash API returns {}
        SimpleNamespace(
            type=sock_mod.SOCK_STREAM,
            status="ESTABLISHED",
            raddr=SimpleNamespace(ip="172.65.236.31", port=25565),
            pid=202,
        ),
        # Connected UDP voice socket
        SimpleNamespace(
            type=sock_mod.SOCK_DGRAM,
            status="NONE",
            raddr=SimpleNamespace(ip="198.51.100.55", port=50005),
            pid=303,
        ),
    ]
    monkeypatch.setattr(RealtimeConnectionMonitor, "_read_inet_connections", staticmethod(lambda: ps_conns))

    active = backend._active_working_connections(service="sing-box")
    assert {c["process"] for c in active} == {"javaw.exe", "discord.exe"}

    # After sockets briefly drop during server warp/lobby change, 60s grace period protects reloads
    ps_conns.clear()
    grace = backend._active_working_connections(service="sing-box")
    assert len(grace) == 1
    assert grace[0]["process"] == "active_session_grace"

    # Once grace window (>60s) expires, reloads can proceed
    backend._last_stateful_session_ts = time.monotonic() - 65.0
    assert backend._active_working_connections(service="sing-box") == []


def test_watchdog_gateway_change_two_tick_debounce(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    st, _nk = _seed_storage(tmp_path / "gw.db")
    st.set_setting("stack_desired_running", "1")
    st.close()

    backend = GuiBackend(
        db_path=tmp_path / "gw.db",
        configs_dir=tmp_path / "configs",
        lists_dir=tmp_path / "lists",
        logs_dir=tmp_path / "logs",
        bin_dir=tmp_path / "bin",
    )
    backend._desired_running = True
    backend._last_gateway_ip = "10:192.168.1.1"
    monkeypatch.setattr(backend_mod, "_is_admin", lambda: True)
    monkeypatch.setattr(
        backend,
        "_collect_processes_state",
        lambda: {"winws2": {"running": True}, "sing-box": {"running": True}, "tg-ws-proxy": {"running": True}},
    )
    reloads: list[str] = []
    monkeypatch.setattr(backend, "reload_singbox", lambda iface=None: (reloads.append("sing-box"), {"ok": True})[1])
    monkeypatch.setattr(backend, "reload_winws2", lambda iface=None: (reloads.append("winws2"), {"ok": True})[1])

    cur_gw = "11:10.0.0.1"
    monkeypatch.setattr(backend, "_detect_local_gateway_ip", lambda: cur_gw)

    # Tick 1 sees transient new gateway -> records pending, does NOT restart
    r1 = backend.ensure_services_healthy()
    assert r1["network_changed"] is False
    assert r1["restarted"] == []
    assert reloads == []

    # Reverting back to original gateway clears pending without restart
    cur_gw = "10:192.168.1.1"
    r_revert = backend.ensure_services_healthy()
    assert r_revert["network_changed"] is False
    assert reloads == []

    # Two consecutive ticks on genuine new gateway trigger restart
    cur_gw = "11:10.0.0.1"
    r2 = backend.ensure_services_healthy()
    assert r2["network_changed"] is False
    assert reloads == []
    r3 = backend.ensure_services_healthy()
    assert r3["network_changed"] is True
    assert reloads == ["sing-box", "winws2"]


def test_auto_heal_noop_decision_does_not_reload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = tmp_path / "noop_heal.db"
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    st, net_key = _seed_storage(db_path)
    st.upsert_strategies(DEFAULT_STRATEGIES)
    st.save_subscription(
        "sub1",
        "vless://11111111-2222-3333-4444-555555555555@203.0.113.20:443?security=tls#PL-Node",
        [
            {
                "tag": "PL-Node",
                "protocol": "vless",
                "server": "203.0.113.20",
                "server_port": 443,
                "raw_outbound": {"type": "vless", "tag": "PL-Node", "server": "203.0.113.20", "server_port": 443},
            }
        ],
    )
    st.save_decision(
        Decision(
            network_key=net_key,
            domain="telegram.org",
            protocol=Protocol.TLS,
            layer="vpn",
            strategy_id="vpn-select",
            status="active",
        )
    )
    st.close()

    backend = GuiBackend(
        db_path=db_path,
        configs_dir=tmp_path / "configs",
        lists_dir=tmp_path / "lists",
        logs_dir=logs_dir,
        bin_dir=tmp_path / "bin",
    )
    monkeypatch.setattr(orch_mod, "_is_admin", lambda: True)
    monkeypatch.setattr(orch_mod, "detect_bypass_active", lambda: True)
    monkeypatch.setattr(
        backend,
        "_collect_processes_state",
        lambda: {"winws2": {"running": True}, "sing-box": {"running": True}},
    )
    monkeypatch.setattr(
        backend.orchestrator.monitor,
        "scan_active_connections",
        lambda *a, **kw: [
            {
                "process": "Telegram.exe",
                "pid": 1001,
                "remote_ip": "149.154.167.220",
                "remote_port": 443,
                "remote": "149.154.167.220:443",
                "protocol": "tls",
                "socket_status": "SYN_SENT",
                "domain": "telegram.org",
                "layer": "vpn",
                "strategy_id": "vpn-select",
                "health": "needs_fix",
            }
        ],
    )

    async def fake_net(timeout: float = 2.0) -> NetworkFingerprint:
        return NetworkFingerprint(asn=12389, kind=NetworkKind.HOME, isp="TestISP", gateway_mac="aa:bb:cc:dd:ee:ff")

    async def fake_probes(domain: str, timeout: float = 2.0) -> ProbesSummary:
        return ProbesSummary(
            dns=DnsProbeResult(system="ok", doh="ok", system_ips=["149.154.167.220"], doh_ips=["149.154.167.220"]),
            tcp=TcpProbeResult(result="timeout", target_ip="149.154.167.220"),
            tls=TlsProbeResult(real_sni="timeout", neutral_sni="timeout"),
            stall=StallProbeResult(result="ok"),
            quic=QuicProbeResult(result="ok"),
        )

    monkeypatch.setattr(orch_mod, "detect_network_fingerprint", fake_net)
    monkeypatch.setattr(orch_mod, "run_domain_probes", fake_probes)

    reloads: list[str] = []
    monkeypatch.setattr(backend, "reload_winws2_if_changed", lambda **_kw: (reloads.append("winws2"), {"ok": True})[1])
    monkeypatch.setattr(backend, "reload_singbox_if_changed", lambda **_kw: (reloads.append("sing-box"), {"ok": True})[1])
    monkeypatch.setattr(backend, "reload_winws2", lambda *_a, **_kw: (reloads.append("winws2"), {"ok": True})[1])
    monkeypatch.setattr(backend, "reload_singbox", lambda *_a, **_kw: (reloads.append("sing-box"), {"ok": True})[1])

    res = asyncio.run(backend.orchestrator.monitor.auto_heal_connections(backend, max_domains_per_tick=2))
    assert len(res["healed"]) == 1
    assert res["healed"][0]["layer"] == "vpn"
    assert reloads == []


def test_fetch_xray_binary_and_validate_xray_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bin_dir = tmp_path / "bin"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("xray.exe", b"MZ" + b"\x00" * 64)
    zip_bytes = buf.getvalue()

    def handler(request: httpx.Request) -> httpx.Response:
        if "api.github.com" in str(request.url):
            return httpx.Response(
                200,
                json={
                    "assets": [
                        {"name": "Xray-windows-64.zip.dgst", "browser_download_url": "https://dl.example/xray.zip.dgst"},
                        {"name": "Xray-windows-64.zip", "browser_download_url": "https://dl.example/Xray-windows-64.zip"},
                    ]
                },
            )
        return httpx.Response(200, content=zip_bytes)

    async def _run_fetch() -> Path:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await fetch_xray_binary(bin_dir, force=True, client=client)

    exe_path = asyncio.run(_run_fetch())
    assert exe_path == bin_dir / "xray.exe"
    assert exe_path.is_file() and exe_path.stat().st_size == 66

    # validate_xray_config invokes `<bin_dir>/xray.exe run -test -c <cfg>`
    cfg_path = tmp_path / "xray.json"
    cfg_path.write_text('{"inbounds": []}', encoding="utf-8")
    seen_cmds: list[list[str]] = []

    def fake_run(cmd: list[str], **_kw: Any) -> SimpleNamespace:
        seen_cmds.append(cmd)
        return SimpleNamespace(returncode=0, stdout="Configuration OK.", stderr="")

    monkeypatch.setattr("netdoctor.supervisor.subprocess.run", fake_run)
    ok, msg = validate_xray_config(bin_dir, cfg_path)
    assert ok is True
    assert "OK" in msg
    assert seen_cmds == [[str(exe_path), "run", "-test", "-c", str(cfg_path)]]


def test_singbox_game_bypass_rules_before_vpn_and_passes_check(tmp_path: Path) -> None:
    vpn_node = VpnNode(
        tag="PL-TLS",
        protocol="vless",
        server="203.0.113.12",
        server_port=8443,
        region="eu",
        raw_outbound={
            "type": "vless",
            "tag": "PL-TLS",
            "server": "203.0.113.12",
            "server_port": 8443,
            "uuid": "11111111-2222-3333-4444-555555555557",
            "tls": {"enabled": True, "server_name": "cdn.example.net"},
        },
    )
    decisions = [
        Decision(
            network_key="AS12389:home:test",
            domain="hypixel.net",
            protocol=Protocol.TLS,
            layer="vpn",
            strategy_id="vpn-select",
            status="active",
        ),
    ]
    sb_path = tmp_path / "sing-box-game.json"
    cfg = generate_singbox_config(decisions, vpn_nodes=[vpn_node], output_path=sb_path)
    rules = cfg["route"]["rules"]

    proc_idx = next(
        i
        for i, r in enumerate(rules)
        if r.get("type") == "logical"
        and r.get("mode") == "and"
        and r.get("outbound") == "direct"
        and any("javaw.exe" in sub.get("process_name", []) for sub in r.get("rules", []))
    )
    port_idx = next(
        i
        for i, r in enumerate(rules)
        if r.get("outbound") == "direct" and 25565 in r.get("port", [])
    )
    vpn_idx = next(i for i, r in enumerate(rules) if r.get("outbound") == "vpn-select")

    assert proc_idx < vpn_idx
    assert port_idx < vpn_idx

    logical_rule = rules[proc_idx]
    inv_port_sub = next(sub for sub in logical_rule["rules"] if sub.get("invert") is True)
    assert set(inv_port_sub["port"]) == {53, 80, 443, 8080, 8443}
    assert len(DEFAULT_GAME_PROCESSES) >= 120
    assert len(set(DEFAULT_GAME_PROCESSES)) == len(DEFAULT_GAME_PROCESSES)
    assert any(sub.get("process_name") == list(DEFAULT_GAME_PROCESSES) for sub in logical_rule["rules"])

    port_rule = rules[port_idx]
    assert port_rule["port"] == list(GAME_BYPASS_PORTS)
    assert port_rule["port_range"] == list(GAME_BYPASS_PORT_RANGES)
    assert "27015:27050" in port_rule["port_range"]
    # Discord voice range must stay outside game port bypass
    assert "50000:50100" not in port_rule["port_range"]

    sb_exe = Path("bin") / "sing-box.exe"
    if sb_exe.is_file():
        ok, err = validate_singbox_config(Path("bin"), sb_path)
        assert ok, err


def test_compile_zapret_preset_keeps_tcp_filter_off_game_ports(tmp_path: Path) -> None:
    compiled = compile_zapret_preset(
        "--lua-desync=fake:blob=tls_google:repeats=4",
        bin_dir="bin",
        lists_dir=tmp_path / "lists",
        game_filter=True,
    )
    tcp_out = next(tok for tok in compiled if tok.startswith("--wf-tcp-out="))
    udp_out = next(tok for tok in compiled if tok.startswith("--wf-udp-out="))
    assert "1024-65535" not in tcp_out
    assert "1024-65535" in udp_out


def test_reconcile_deferred_optimal_switch_in_priority_and_auto_modes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    st, _nk = _seed_storage(tmp_path / "deferred_switch.db")
    try:
        st.set_vpn_selection_policy(
            mode="priority",
            priority_node="Priority1",
            priorities={"Priority1": 1, "Fallback2": 10},
        )
        nodes = [
            {
                "tag": "Priority1",
                "display_name": "Priority 1",
                "protocol": "vless",
                "server": "198.51.100.1",
                "server_port": 443,
                "priority": 1,
                "enabled": True,
                "region": "eu",
            },
            {
                "tag": "Fallback2",
                "display_name": "Fallback 2",
                "protocol": "vless",
                "server": "198.51.100.2",
                "server_port": 443,
                "priority": 10,
                "enabled": True,
                "region": "eu",
            },
        ]

        class _FakeClash:
            def __init__(self) -> None:
                self.sel_now = "Fallback2"
                self.select_calls: list[tuple[str, str]] = []
                self.conns: list[dict[str, Any]] = [
                    {"id": "v-1", "upload": 4096, "download": 16384, "chains": ["Fallback2", "vpn-select"]}
                ]

            async def get_proxies(self) -> dict[str, Any]:
                return {
                    "vpn-select": {"type": "Selector", "now": self.sel_now, "all": ["vpn-auto", "Priority1", "Fallback2"]},
                    "vpn-auto": {"type": "URLTest", "now": "Priority1", "all": ["Priority1", "Fallback2"]},
                    "Priority1": {"type": "VLESS", "history": []},
                    "Fallback2": {"type": "VLESS", "history": []},
                }

            async def get_connections(self) -> dict[str, Any]:
                return {"connections": self.conns}

            async def measure_node_delay(self, tag: str, **_kw: Any) -> dict[str, Any]:
                return {"ok": True, "delay_ms": 30.0 if tag == "Priority1" else 90.0, "error": None}

            async def select_outbound(self, sel: str, target: str) -> bool:
                self.sel_now = target
                self.select_calls.append((sel, target))
                return True

            async def close_connections_by_node(self, tag: str) -> int:
                return 0

        orch = VpnLayerOrchestrator()
        orch._last_switch_ts = time.monotonic()  # inside failback_cooldown_sec
        clash = _FakeClash()

        # Priority mode: while traffic is active on Fallback2, probe Priority1 and record pending_node without switching
        res_active = asyncio.run(
            orch.reconcile_active_node(st, nodes, clash_client=clash, failback_cooldown_sec=300.0)  # type: ignore[arg-type]
        )
        assert res_active["action"] == "keep_active_session"
        assert res_active["selected"] == "Fallback2"
        assert res_active["pending_node"] == "Priority1"
        assert clash.select_calls == []
        assert any(p["tag"] == "Priority1" and p["alive"] for p in res_active["probed"])

        # Once active connections finish, switch immediately even if failback_cooldown_sec hasn't expired
        clash.conns = []
        res_idle = asyncio.run(
            orch.reconcile_active_node(st, nodes, clash_client=clash, failback_cooldown_sec=300.0)  # type: ignore[arg-type]
        )
        assert res_idle["action"] == "failback_priority"
        assert res_idle["selected"] == "Priority1"
        assert res_idle["pending_node"] is None
        assert clash.select_calls == [("vpn-select", "Priority1")]

        # Auto mode: failover Fallback2 holds while active traffic flows, queues pending_node == vpn-auto
        st.set_vpn_selection_policy(mode="auto", priority_node="", priorities={"Priority1": 100, "Fallback2": 100})
        clash.sel_now = "Fallback2"
        clash.select_calls.clear()
        clash.conns = [{"id": "v-2", "upload": 2048, "download": 4096, "chains": ["Fallback2", "vpn-select"]}]
        orch._last_switch_ts = time.monotonic()

        res_auto_active = asyncio.run(
            orch.reconcile_active_node(st, nodes, clash_client=clash, failback_cooldown_sec=300.0)  # type: ignore[arg-type]
        )
        assert res_auto_active["action"] == "keep_active_session"
        assert res_auto_active["pending_node"] == "vpn-auto"
        assert clash.select_calls == []
        assert any(p["tag"] == "Priority1" and p["alive"] for p in res_auto_active["probed"])

        # Auto mode: when traffic ends, switch back to vpn-auto immediately
        clash.conns = []
        res_auto_idle = asyncio.run(
            orch.reconcile_active_node(st, nodes, clash_client=clash, failback_cooldown_sec=300.0)  # type: ignore[arg-type]
        )
        assert res_auto_idle["action"] == "return_to_auto"
        assert res_auto_idle["selected"] == "Priority1"
        assert res_auto_idle["pending_node"] is None
        assert clash.select_calls == [("vpn-select", "vpn-auto")]
    finally:
        st.close()


def test_force_apply_pending_changes_and_snapshot_indicator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = tmp_path / "pending_force.db"
    st, _nk = _seed_storage(db_path)
    st.upsert_strategies(DEFAULT_STRATEGIES)
    st.close()

    backend = GuiBackend(
        db_path=db_path,
        configs_dir=tmp_path / "configs",
        lists_dir=tmp_path / "lists",
        logs_dir=tmp_path / "logs",
        bin_dir=tmp_path / "bin",
    )
    monkeypatch.setattr(backend_mod, "_is_admin", lambda: True)
    monkeypatch.setattr(
        backend,
        "_collect_processes_state",
        lambda: {"winws2": {"running": True}, "sing-box": {"running": True}},
    )
    monkeypatch.setattr(
        backend,
        "trigger_apply_configs",
        lambda **_kw: {"winws2_preset": "w.txt", "singbox_config": "s.json"},
    )

    backend._pending_winws2_reload = True
    backend._pending_singbox_reload = True
    backend.orchestrator.vpn._pending_optimal_node = "Priority1"

    snap_before = backend.get_status_snapshot()
    assert snap_before["pending_changes"] == {
        "winws2": True,
        "singbox": True,
        "vpn_node": "Priority1",
        "count": 3,
    }

    calls: list[tuple[str, Any]] = []

    def fake_w_reload(**kw: Any) -> dict[str, Any]:
        calls.append(("winws2", kw))
        backend._pending_winws2_reload = False
        return {"ok": True, "reloaded": True}

    def fake_sb_reload(**kw: Any) -> dict[str, Any]:
        calls.append(("sing-box", kw))
        backend._pending_singbox_reload = False
        return {"ok": True, "reloaded": True}

    def fake_vpn_rec(**kw: Any) -> dict[str, Any]:
        calls.append(("vpn", kw))
        backend.orchestrator.vpn._pending_optimal_node = None
        return {"ok": True, "selected": "Priority1", "pending_node": None}

    monkeypatch.setattr(backend, "reload_winws2_if_changed", fake_w_reload)
    monkeypatch.setattr(backend, "reload_singbox_if_changed", fake_sb_reload)
    monkeypatch.setattr(backend, "reconcile_vpn_health", fake_vpn_rec)

    res = backend.force_apply_pending_changes(iface=12)
    assert res["ok"] is True
    assert res["reloaded"] == ["winws2", "sing-box"]
    assert res["vpn_switched"] == "Priority1"
    assert ("winws2", {"iface": 12, "min_interval_sec": 0.0, "defer_if_active": False}) in calls
    assert ("sing-box", {"iface": 12, "min_interval_sec": 0.0, "defer_if_active": False}) in calls
    assert ("vpn", {"min_interval_sec": 0.0, "force": True}) in calls

    snap_after = backend.get_status_snapshot()
    assert snap_after["pending_changes"] == {
        "winws2": False,
        "singbox": False,
        "vpn_node": None,
        "count": 0,
    }


def test_auto_heal_immediate_on_new_domain_or_down_bypass(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = tmp_path / "urgent_heal.db"
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    st, nk = _seed_storage(db_path)
    st.upsert_strategies(DEFAULT_STRATEGIES)
    st.close()

    backend = GuiBackend(
        db_path=db_path,
        configs_dir=tmp_path / "configs",
        lists_dir=tmp_path / "lists",
        logs_dir=logs_dir,
        bin_dir=tmp_path / "bin",
    )
    monkeypatch.setattr(orch_mod, "_is_admin", lambda: True)
    monkeypatch.setattr(
        backend,
        "_collect_processes_state",
        lambda: {"winws2": {"running": True}, "sing-box": {"running": True}},
    )

    async def fake_net(timeout: float = 2.0) -> NetworkFingerprint:
        return NetworkFingerprint(asn=12389, kind=NetworkKind.HOME, isp="TestISP", gateway_mac="aa:bb:cc:dd:ee:ff")

    async def fake_probes(domain: str, timeout: float = 2.0) -> ProbesSummary:
        return ProbesSummary(
            dns=DnsProbeResult(system="ok", doh="ok", system_ips=["198.51.100.77"], doh_ips=["198.51.100.77"]),
            tcp=TcpProbeResult(result="ok", rtt_ms=15.0, target_ip="198.51.100.77"),
            tls=TlsProbeResult(real_sni="reset", neutral_sni="ok"),
            stall=StallProbeResult(result="ok"),
            quic=QuicProbeResult(result="ok"),
        )

    from netdoctor.selector import CandidateEvaluation

    async def fake_live_eval(domain: str, ip: str, strategy: Strategy, **_kw: Any) -> CandidateEvaluation:
        return CandidateEvaluation(strategy=strategy, success_rate=1.0, throughput_kbps=5000.0, ttfb_ms=25.0)

    monkeypatch.setattr(orch_mod, "detect_network_fingerprint", fake_net)
    monkeypatch.setattr(orch_mod, "run_domain_probes", fake_probes)
    monkeypatch.setattr(orch_mod, "live_winws2_strategy_evaluator", fake_live_eval)

    seen_w_calls: list[dict[str, Any]] = []
    monkeypatch.setattr(
        backend,
        "reload_winws2_if_changed",
        lambda **kw: (seen_w_calls.append(kw), {"ok": True, "reloaded": True})[1],
    )
    monkeypatch.setattr(
        backend,
        "reload_singbox_if_changed",
        lambda **kw: {"ok": True, "reloaded": True},
    )

    # 1. New domain while bypass is up -> urgent reload (min_interval_sec=0.0), defer_if_active=True
    monkeypatch.setattr(orch_mod, "detect_bypass_active", lambda: True)
    monkeypatch.setattr(
        backend.orchestrator.monitor,
        "scan_active_connections",
        lambda *a, **kw: [
            {
                "process": "chrome.exe",
                "pid": 2001,
                "remote_ip": "198.51.100.77",
                "remote_port": 443,
                "remote": "198.51.100.77:443",
                "protocol": "tls",
                "socket_status": "SYN_SENT",
                "domain": "brandnew.example",
                "layer": "direct",
                "strategy_id": None,
                "health": "needs_fix",
            }
        ],
    )
    asyncio.run(backend.orchestrator.monitor.auto_heal_connections(backend, max_domains_per_tick=2))
    assert seen_w_calls and all(c == {"min_interval_sec": 0.0, "defer_if_active": True} for c in seen_w_calls)

    # 2. Existing domain when bypass itself is down (detect_bypass_active == False) -> min_interval_sec=0.0 AND defer_if_active=False
    seen_w_calls.clear()
    backend.orchestrator.monitor.cooldown_until.clear()
    monkeypatch.setattr(orch_mod, "detect_bypass_active", lambda: False)
    monkeypatch.setattr(
        backend.orchestrator.monitor,
        "scan_active_connections",
        lambda *a, **kw: [
            {
                "process": "chrome.exe",
                "pid": 2002,
                "remote_ip": "198.51.100.78",
                "remote_port": 443,
                "remote": "198.51.100.78:443",
                "protocol": "tls",
                "socket_status": "SYN_SENT",
                "domain": "fellbypass.example",
                "layer": "direct",
                "strategy_id": None,
                "health": "needs_fix",
            }
        ],
    )
    st2 = Storage(db_path)
    try:
        st2.save_decision(
            Decision(
                network_key=nk,
                domain="fellbypass.example",
                protocol=Protocol.TLS,
                layer="direct",
                strategy_id=None,
                status="active",
            )
        )
    finally:
        st2.close()
    asyncio.run(backend.orchestrator.monitor.auto_heal_connections(backend, max_domains_per_tick=2))
    assert seen_w_calls == [{"min_interval_sec": 0.0, "defer_if_active": False}]



