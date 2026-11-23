"""Regression tests for protecting live active connections from unnecessary resets, strategy cycling, or reloads."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import psutil
import pytest

import netdoctor.gui_backend as backend_mod
import netdoctor.orchestrators as orch_mod
from netdoctor.config_gen import generate_winws2_config
from netdoctor.gui_backend import GuiBackend
from netdoctor.models import Decision, NetworkFingerprint, NetworkKind, Protocol, Strategy
from netdoctor.orchestrators import RealtimeConnectionMonitor, VpnLayerOrchestrator
from netdoctor.selector import DEFAULT_STRATEGIES
from netdoctor.storage import Storage


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

    # Simulate only an old idle keep-alive remaining (30s old, first seen now without advancing bytes)
    backend._clash_conn_traffic.clear()
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
