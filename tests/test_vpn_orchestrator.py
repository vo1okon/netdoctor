"""Tests for upgraded VPN orchestrator: placeholders, in-VPN auto-select, failover/failback, priority selection, Clash API unwrap, and GUI controls."""

from __future__ import annotations

import asyncio
import http.server
import json
import threading
import tkinter as tk
from pathlib import Path
from typing import Any

import pytest

import netdoctor.gui_backend as backend_mod
import netdoctor.orchestrators as orch_mod
import netdoctor.vpn as vpn_mod
from netdoctor.clash_api import ClashApiClient
from netdoctor.config_gen import generate_singbox_config
from netdoctor.gui import NetdoctorGuiApp
from netdoctor.gui_backend import GuiBackend
from netdoctor.models import TcpProbeResult, VpnNode
from netdoctor.orchestrators import VpnLayerOrchestrator
from netdoctor.storage import Storage
from netdoctor.supervisor import validate_singbox_config
from netdoctor.vpn import is_auto_select_node, is_placeholder_node, refresh_all_subscriptions


def _make_node(
    tag: str,
    server: str = "198.51.100.10",
    port: int = 443,
    *,
    protocol: str = "vless",
    region: str = "eu",
    priority: int = 100,
    enabled: bool = True,
    sni: str | None = None,
    transport: str = "reality",
) -> dict[str, Any]:
    tls_obj: dict[str, Any] = {"enabled": True, "server_name": sni or server}
    if transport == "reality":
        tls_obj["utls"] = {"enabled": True, "fingerprint": "chrome"}
        tls_obj["reality"] = {"enabled": True, "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "short_id": "a1b2"}
    raw_ob: dict[str, Any] = {
        "type": protocol,
        "tag": tag,
        "server": server,
        "server_port": port,
        "uuid": "00000000-0000-0000-0000-000000000001",
        "tls": tls_obj,
    }
    if transport == "ws":
        raw_ob["transport"] = {"type": "ws", "path": "/", "headers": {"Host": server}}
    return {
        "tag": tag,
        "protocol": protocol,
        "server": server,
        "server_port": port,
        "raw_outbound": raw_ob,
        "subscription_id": "default",
        "display_name": tag,
        "transport": transport,
        "region": region,
        "priority": priority,
        "enabled": enabled,
    }


def test_clash_api_unwrap_and_resolve_active_proxy() -> None:
    wrapped = {
        "proxies": {
            "vpn-select": {"type": "Selector", "now": "vpn-auto"},
            "vpn-auto": {"type": "URLTest", "now": "DE-Node"},
            "DE-Node": {
                "type": "VLESS",
                "history": [{"time": "t1", "delay": 0}, {"time": "t2", "delay": 142}],
            },
        }
    }
    unwrapped = ClashApiClient.unwrap_proxies(wrapped)
    assert "vpn-select" in unwrapped and "proxies" not in unwrapped
    assert ClashApiClient.unwrap_proxies(unwrapped) is unwrapped

    sel, leaf, delay = ClashApiClient.resolve_active_proxy(wrapped, "vpn-select")
    assert sel == "vpn-auto"
    assert leaf == "DE-Node"
    assert delay == 142.0

    # Guard against cyclical `now` references
    cyclic = {
        "vpn-select": {"now": "a"},
        "a": {"now": "b"},
        "b": {"now": "a"},
    }
    sel_c, leaf_c, delay_c = ClashApiClient.resolve_active_proxy(cyclic, "vpn-select")
    assert sel_c == "a"
    assert leaf_c in ("a", "b")
    assert delay_c is None

    # Real HTTP GET /proxies unwraps envelope transparently
    class _Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            return

        def do_GET(self) -> None:
            if self.path == "/proxies":
                body = json.dumps(wrapped).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(404)
                self.end_headers()

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        client = ClashApiClient(controller_addr=f"127.0.0.1:{srv.server_port}")
        sync_proxies = client.get_proxies_sync()
        async_proxies = asyncio.run(client.get_proxies())
        assert "vpn-select" in sync_proxies and "proxies" not in sync_proxies
        assert "vpn-select" in async_proxies and "proxies" not in async_proxies
    finally:
        srv.shutdown()
        srv.server_close()


def test_node_classifiers_and_tag_normalization_and_refresh_preservation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Auto-select & placeholder detection
    happ_dummy_auto = _make_node("🇪🇺📶 Автовыбор WIFI", server="rori.net", port=994, sni="exampl.com")
    divider_node = _make_node("Обход белых списков ↙", server="obid.obed", port=994, sni="exampl.com")
    banner_node = _make_node("Истекает: 12 дн.", server="127.0.0.1", port=443)
    real_provider_auto = _make_node("🇪🇺 Auto-Select Balance", server="auto.vpn.example", port=443, sni="auto.vpn.example")
    regular_node = _make_node("🇩🇪 Germany-1", server="198.51.100.11", port=443, sni="example.com")
    tailscale_node = _make_node("ts-exit", server="tailscale", port=443, protocol="tailscale")

    assert is_auto_select_node(happ_dummy_auto) is True
    assert is_auto_select_node(real_provider_auto) is True
    assert is_auto_select_node(regular_node) is False

    assert is_placeholder_node(happ_dummy_auto) is True
    assert is_placeholder_node(divider_node) is True
    assert is_placeholder_node(banner_node) is True
    assert is_placeholder_node(real_provider_auto) is False
    assert is_placeholder_node(regular_node) is False
    assert is_placeholder_node(tailscale_node) is False

    # Storage tag normalization + priority overlay + refresh_all_subscriptions preservation
    db_path = tmp_path / "norm.db"
    st = Storage(db_path)
    try:
        st.save_subscription(
            "default",
            "https://sub.example.test/list",
            [
                _make_node("🇳🇱Нидерланды | WIFI ", server="198.51.100.20", port=443, priority=5, enabled=False),
                _make_node("🇩🇪Германия | WIFI", server="198.51.100.21", port=443),
            ],
        )
        st.set_vpn_selection_policy(
            mode="priority",
            priority_node="🇩🇪Германия | WIFI",
            priorities={"🇩🇪Германия | WIFI": 1},
        )
        nodes = st.get_all_subscription_nodes()
        by_tag = {n["tag"]: n for n in nodes}
        assert "🇳🇱Нидерланды | WIFI" in by_tag
        assert by_tag["🇳🇱Нидерланды | WIFI"]["raw_outbound"]["tag"] == "🇳🇱Нидерланды | WIFI"
        assert by_tag["🇳🇱Нидерланды | WIFI"]["priority"] == 5
        assert by_tag["🇳🇱Нидерланды | WIFI"]["enabled"] is False
        assert by_tag["🇩🇪Германия | WIFI"]["priority"] == 1

        # Refresh subscription with stripped tag and default priority=100 -> must preserve priority & enabled
        async def fake_fetch(url_or_uri: str, subscription_id: str = "default", timeout: float = 10.0) -> list[VpnNode]:
            return [
                VpnNode(**_make_node("🇳🇱Нидерланды | WIFI", server="198.51.100.20", port=443, priority=100, enabled=True)),
                VpnNode(**_make_node("🇩🇪Германия | WIFI", server="198.51.100.21", port=443, priority=100, enabled=True)),
            ]

        monkeypatch.setattr(vpn_mod, "fetch_subscription", fake_fetch)
        res = asyncio.run(refresh_all_subscriptions(st))
        assert res["default"] == 2
        refreshed = {n["tag"]: n for n in st.get_all_subscription_nodes()}
        assert refreshed["🇳🇱Нидерланды | WIFI"]["priority"] == 5
        assert refreshed["🇳🇱Нидерланды | WIFI"]["enabled"] is False
        assert refreshed["🇩🇪Германия | WIFI"]["priority"] == 1
    finally:
        st.close()


def test_singbox_config_excludes_placeholders_respects_priority_and_validates(tmp_path: Path) -> None:
    nodes = [
        VpnNode(**_make_node("DummyAuto", server="rori.net", port=994, sni="exampl.com")),
        VpnNode(**_make_node("DisabledNode", server="198.51.100.30", port=443, enabled=False)),
        VpnNode(**_make_node("PriorityOne", server="198.51.100.31", port=443, priority=1)),
        VpnNode(**_make_node("BackupTwo", server="198.51.100.32", port=443, priority=10)),
        VpnNode(**_make_node("RU-Fallback", server="198.51.100.33", port=443, region="ru", priority=50)),
    ]

    sb_path = tmp_path / "sing-box-prio.json"
    cfg = generate_singbox_config(
        decisions=[],
        vpn_nodes=nodes,
        output_path=sb_path,
        vpn_selection_mode="priority",
        preferred_vpn_node="PriorityOne",
    )
    out_by_tag = {o["tag"]: o for o in cfg["outbounds"]}
    assert out_by_tag["vpn-auto"]["interval"] == "1m"
    assert out_by_tag["vpn-auto"]["tolerance"] == 100
    assert out_by_tag["vpn-auto"]["outbounds"] == ["PriorityOne", "BackupTwo"]
    assert "DummyAuto" not in out_by_tag["vpn-auto"]["outbounds"]
    assert "DisabledNode" not in out_by_tag["vpn-auto"]["outbounds"]
    assert out_by_tag["vpn-select"]["default"] == "PriorityOne"

    if (Path("bin") / "sing-box.exe").is_file():
        ok, err = validate_singbox_config("bin", sb_path)
        assert ok is True, f"sing-box check failed: {err}"

    # When PriorityOne is quarantined, default falls back to BackupTwo (#2)
    cfg_q1 = generate_singbox_config(
        decisions=[],
        vpn_nodes=nodes,
        quarantined_tags={"PriorityOne"},
        vpn_selection_mode="priority",
        preferred_vpn_node="PriorityOne",
    )
    q1_by_tag = {o["tag"]: o for o in cfg_q1["outbounds"]}
    assert q1_by_tag["vpn-select"]["default"] == "BackupTwo"

    # When all <100 priority nodes are quarantined, default falls back to vpn-auto
    cfg_q_all = generate_singbox_config(
        decisions=[],
        vpn_nodes=nodes,
        quarantined_tags={"PriorityOne", "BackupTwo", "RU-Fallback"},
        vpn_selection_mode="priority",
        preferred_vpn_node="PriorityOne",
    )
    q_all_by_tag = {o["tag"]: o for o in cfg_q_all["outbounds"]}
    assert q_all_by_tag["vpn-select"]["default"] == "vpn-auto"


class _MockClashController:
    def __init__(self, proxies: dict[str, Any], delays: dict[str, float | None], conns: list[dict[str, Any]] | None = None) -> None:
        self.controller_addr = "127.0.0.1:19090"
        self.secret = ""
        self.proxies = proxies
        self.delays = delays
        self.conns = list(conns or [])
        self.selected_history: list[tuple[str, str]] = []
        self.closed_nodes: list[str] = []

    async def get_proxies(self) -> dict[str, Any]:
        return ClashApiClient.unwrap_proxies(self.proxies)

    def get_proxies_sync(self) -> dict[str, Any]:
        return ClashApiClient.unwrap_proxies(self.proxies)

    async def measure_node_delay(self, tag: str, url: str = "", timeout_ms: int = 3500) -> dict[str, Any]:
        d = self.delays.get(tag)
        if d is not None:
            return {"ok": True, "delay_ms": d, "error": None}
        return {"ok": False, "delay_ms": None, "error": "timeout"}

    async def select_outbound(self, selector_tag: str, target_tag: str) -> bool:
        self.proxies.setdefault(selector_tag, {})["now"] = target_tag
        self.selected_history.append((selector_tag, target_tag))
        return True

    def select_outbound_sync(self, selector_tag: str, target_tag: str) -> bool:
        self.proxies.setdefault(selector_tag, {})["now"] = target_tag
        self.selected_history.append((selector_tag, target_tag))
        return True

    async def close_connections_by_node(self, node_tag: str) -> int:
        self.closed_nodes.append(node_tag)
        return sum(1 for c in self.conns if node_tag in (c.get("chains") or []))

    def close_connections_by_node_sync(self, node_tag: str) -> int:
        self.closed_nodes.append(node_tag)
        return sum(1 for c in self.conns if node_tag in (c.get("chains") or []))


@pytest.mark.asyncio
async def test_reconcile_active_node_auto_and_priority_modes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def dead_tcp(ip: str, port: int = 443, timeout: float = 1.0) -> TcpProbeResult:
        return TcpProbeResult(result="timeout", target_ip=ip)

    monkeypatch.setattr(orch_mod, "probe_tcp", dead_tcp)

    db_path = tmp_path / "reconcile.db"
    st = Storage(db_path)
    try:
        nodes = [
            _make_node("DummyAuto", server="rori.net", port=994, sni="exampl.com"),
            _make_node("DE-1", server="198.51.100.11", port=443, region="eu", priority=1),
            _make_node("NL-2", server="198.51.100.12", port=443, region="eu", priority=10),
            _make_node("RU-3", server="198.51.100.13", port=443, region="ru", priority=20),
        ]
        st.save_subscription("default", "https://sub.example", nodes)
        stored_nodes = st.get_all_subscription_nodes()

        # 1. Auto mode: keeps healthy vpn-auto
        proxies = {
            "vpn-select": {"type": "Selector", "now": "vpn-auto"},
            "vpn-auto": {"type": "URLTest", "now": "NL-2"},
            "DE-1": {"type": "VLESS"},
            "NL-2": {"type": "VLESS"},
            "RU-3": {"type": "VLESS"},
        }
        delays: dict[str, float | None] = {"DE-1": 180.0, "NL-2": 65.0, "RU-3": 35.0}
        conns = [{"id": "c1", "chains": ["vpn-select", "NL-2"]}]
        clash = _MockClashController(proxies, delays, conns)
        orch = VpnLayerOrchestrator()

        res_keep = await orch.reconcile_active_node(st, stored_nodes, clash_client=clash)  # type: ignore[arg-type]
        assert res_keep["action"] == "keep_auto"
        assert res_keep["selected"] == "NL-2"

        # 2. Auto mode: when NL-2 and DE-1 are down, fails over to alive RU-3 and closes dead NL-2 sockets
        delays["NL-2"] = None
        delays["DE-1"] = None
        res_ru = await orch.reconcile_active_node(st, stored_nodes, clash_client=clash)  # type: ignore[arg-type]
        assert res_ru["action"] == "failover"
        assert res_ru["selected"] == "RU-3"
        assert proxies["vpn-select"]["now"] == "RU-3"
        assert "NL-2" in clash.closed_nodes

        # 3. Auto mode: when vpn-auto recovers (NL-2 back alive), returns to vpn-auto after cooldown
        delays["NL-2"] = 55.0
        res_ret = await orch.reconcile_active_node(
            st,
            stored_nodes,
            clash_client=clash,  # type: ignore[arg-type]
            failback_cooldown_sec=0.0,
        )
        assert res_ret["action"] == "return_to_auto"
        assert proxies["vpn-select"]["now"] == "vpn-auto"

        # 4. Priority mode: selects #1 priority (DE-1) even when NL-2 is faster
        st.set_vpn_selection_policy(mode="priority", priority_node="DE-1", priorities={"DE-1": 1, "NL-2": 10})
        stored_nodes = st.get_all_subscription_nodes()
        delays["DE-1"] = 180.0
        delays["NL-2"] = 45.0
        proxies["vpn-select"]["now"] = "vpn-auto"
        proxies["vpn-auto"]["now"] = "NL-2"

        res_prio = await orch.reconcile_active_node(st, stored_nodes, clash_client=clash)  # type: ignore[arg-type]
        assert res_prio["action"] == "failback_priority"
        assert res_prio["selected"] == "DE-1"
        assert proxies["vpn-select"]["now"] == "DE-1"

        # 5. Priority mode: when DE-1 fails even on 1st failure (before quarantine), fails over to NL-2 immediately
        delays["DE-1"] = None
        res_failover = await orch.reconcile_active_node(st, stored_nodes, clash_client=clash)  # type: ignore[arg-type]
        assert res_failover["action"] == "failover_priority"
        assert res_failover["selected"] == "NL-2"
        assert proxies["vpn-select"]["now"] == "NL-2"

        # 6. Priority mode: once DE-1 recovers and cooldown expires, automatically fails back to DE-1
        delays["DE-1"] = 175.0
        res_back = await orch.reconcile_active_node(
            st,
            stored_nodes,
            clash_client=clash,  # type: ignore[arg-type]
            failback_cooldown_sec=0.0,
        )
        assert res_back["action"] == "failback_priority"
        assert res_back["selected"] == "DE-1"
        assert proxies["vpn-select"]["now"] == "DE-1"
    finally:
        st.close()


def test_rotate_vpn_node_supports_vpn_auto_rejects_placeholders_and_avoids_degraded(tmp_path: Path) -> None:
    db_path = tmp_path / "rotate.db"
    st = Storage(db_path)
    try:
        nodes = [
            _make_node("Divider ↙", server="obid.obed", port=994, sni="exampl.com"),
            _make_node("Node-A", server="198.51.100.41", port=443, region="eu"),
            _make_node("Node-B-Degraded", server="198.51.100.42", port=443, region="eu"),
            _make_node("Node-C-Healthy", server="198.51.100.43", port=443, region="eu"),
        ]
        st.save_subscription("default", "https://sub.example", nodes)
        stored = st.get_all_subscription_nodes()
        orch = VpnLayerOrchestrator()
        # Give Node-B-Degraded 1 fail (still closed, not quarantined, but degraded)
        orch.record_node_result(st, stored[2], ok=False, error="timeout")

        proxies = {
            "vpn-select": {"now": "Node-A"},
            "vpn-auto": {"now": "Node-C-Healthy"},
            "Node-A": {},
            "Node-B-Degraded": {},
            "Node-C-Healthy": {},
        }
        clash = _MockClashController(proxies, {"Node-A": 50.0, "Node-C-Healthy": 60.0})

        # Rejects placeholder tag
        bad_rot = orch.rotate_vpn_node(st, stored, clash_client=clash, target_tag="Divider ↙")  # type: ignore[arg-type]
        assert bad_rot["ok"] is False

        # Auto rotation skips degraded Node-B and chooses Node-C-Healthy
        rot = orch.rotate_vpn_node(st, stored, clash_client=clash)  # type: ignore[arg-type]
        assert rot["ok"] is True
        assert rot["selected"] == "Node-C-Healthy"

        # Supports explicit target_tag="vpn-auto"
        rot_auto = orch.rotate_vpn_node(st, stored, clash_client=clash, target_tag="vpn-auto")  # type: ignore[arg-type]
        assert rot_auto["ok"] is True
        assert rot_auto["selected"] == "vpn-auto"
        assert proxies["vpn-select"]["now"] == "vpn-auto"
    finally:
        st.close()


def test_gui_backend_priority_methods_startup_sync_and_gui_rendering(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "backend_vpn.db"
    st = Storage(db_path)
    try:
        nodes = [
            _make_node("🇪🇺📶 Автовыбор WIFI", server="rori.net", port=994, sni="exampl.com"),
            _make_node("DE-First", server="198.51.100.51", port=443, region="eu"),
            _make_node("NL-Second", server="198.51.100.52", port=443, region="eu"),
        ]
        st.save_subscription("default", "https://sub.example", nodes)
    finally:
        st.close()

    backend = GuiBackend(
        db_path=db_path,
        configs_dir=tmp_path / "configs",
        lists_dir=tmp_path / "lists",
        logs_dir=tmp_path / "logs",
        bin_dir=tmp_path / "bin",
    )
    monkeypatch.setattr(backend, "_collect_processes_state", lambda: {"sing-box": {"running": True}, "winws2": {"running": False}})

    proxies = {
        "vpn-select": {"type": "Selector", "now": "direct"},
        "vpn-auto": {"type": "URLTest", "now": "DE-First"},
        "DE-First": {"type": "VLESS", "history": [{"delay": 120}]},
        "NL-Second": {"type": "VLESS", "history": [{"delay": 45}]},
    }
    clash = _MockClashController(proxies, {"DE-First": 120.0, "NL-Second": 45.0})
    backend.clash_api = clash  # type: ignore[assignment]

    # Setting priority node persists policy, updates sing-box.json default, and switches live selector
    res_p = backend.set_vpn_priority_node("NL-Second")
    assert res_p["ok"] is True
    assert res_p["policy"]["mode"] == "priority"
    assert res_p["policy"]["priority_node"] == "NL-Second"
    assert proxies["vpn-select"]["now"] == "NL-Second"

    sb_cfg = json.loads((tmp_path / "configs" / "sing-box.json").read_text(encoding="utf-8"))
    sb_select = next(o for o in sb_cfg["outbounds"] if o["tag"] == "vpn-select")
    assert sb_select["default"] == "NL-Second"

    # Startup sync overrides stale singbox-cache.db selection ("direct") with priority node
    proxies["vpn-select"]["now"] = "direct"
    backend._sync_singbox_vpn_selector(retries=1)
    assert proxies["vpn-select"]["now"] == "NL-Second"

    # Move DE-First up (-1) -> promotes DE-First to #1
    res_m = backend.move_vpn_node_priority("DE-First", -1)
    assert res_m["priority_node"] == "DE-First"
    assert proxies["vpn-select"]["now"] == "DE-First"

    # probe_all_vpn_nodes auto-steers away from dead/wrong active node
    proxies["vpn-select"]["now"] = "direct"
    clash.delays["DE-First"] = None
    clash.delays["NL-Second"] = 48.0

    async def dead_tcp(ip: str, port: int = 443, timeout: float = 1.8) -> TcpProbeResult:
        return TcpProbeResult(result="timeout", target_ip=ip)

    monkeypatch.setattr(orch_mod, "probe_tcp", dead_tcp)
    monkeypatch.setattr(orch_mod.VpnLayerOrchestrator, "check_tg_proxy", lambda self, **kw: asyncio.sleep(0, result={"alive": False}))
    probed = backend.probe_all_vpn_nodes()
    assert any(n["tag"] == "🇪🇺📶 Автовыбор WIFI" and n["is_placeholder"] for n in probed)
    assert proxies["vpn-select"]["now"] == "NL-Second"

    # Switch back to auto mode -> returns selector to vpn-auto when vpn-auto points to an alive node
    proxies["vpn-auto"]["now"] = "NL-Second"
    res_auto = backend.set_vpn_selection_mode("auto")
    assert res_auto["policy"]["mode"] == "auto"
    assert proxies["vpn-select"]["now"] == "vpn-auto"

    # Verify GUI table rendering with priority, active, and placeholder indicators
    snap = backend.get_status_snapshot()
    assert snap["vpn_policy"]["mode"] == "auto"
    try:
        app = NetdoctorGuiApp(backend=backend, auto_start=False)
    except tk.TclError as exc:
        pytest.skip(f"Tcl/Tk display unavailable: {exc}")

    try:
        app.withdraw()
        app.update_idletasks()
        app.apply_snapshot(snap)
        children = app.vpn_tree.get_children()
        assert len(children) == 3
        all_vals = [app.vpn_tree.item(iid, "values") for iid in children]
        assert any("Служебный" in v[-1] for v in all_vals)
        assert any("▶" in v[1] for v in all_vals)
    finally:
        app.on_close()
