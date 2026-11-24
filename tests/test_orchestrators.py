"""Tests for per-layer orchestrators (DNS, DPI, VPN), real-time connection radar, and Autopilot backend."""

from __future__ import annotations

from collections import Counter
import asyncio
import json
import socket
import tkinter as tk
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import psutil
import pytest

import netdoctor.gui_backend as backend_mod
import netdoctor.orchestrators as orch_mod
from netdoctor.classifier import classify_probes
from netdoctor.gui import NetdoctorGuiApp
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
    TcpProbeResult,
    TlsProbeResult,
    VerdictClass,
)
from netdoctor.orchestrators import (
    BUILTIN_DNS_CATALOG,
    DnsLayerOrchestrator,
    DpiLayerOrchestrator,
    MasterRoutingOrchestrator,
    RealtimeConnectionMonitor,
    VpnLayerOrchestrator,
    _is_external_ip,
)
from netdoctor.selector import DEFAULT_STRATEGIES
from netdoctor.storage import Storage


def _seed_db(db_path: Path) -> str:
    st = Storage(db_path)
    try:
        net = NetworkFingerprint(asn=12389, kind=NetworkKind.HOME, isp="TestISP")
        net_key = st.upsert_network(net)
        st.upsert_strategies(DEFAULT_STRATEGIES)
        st.save_decision(
            Decision(
                network_key=net_key,
                domain="discord.com",
                protocol=Protocol.TLS,
                layer="dpi",
                strategy_id="tls_hostfakesplit_ozon",
                fallback_strategies=["tls_multisplit_pos2", "tls_fakedsplit_pos2"],
                status="active",
            )
        )
        st.save_subscription(
            "default",
            "https://example.com/sub",
            [
                {
                    "tag": "vless-fi",
                    "protocol": "vless",
                    "server": "198.51.100.11",
                    "server_port": 443,
                    "raw_outbound": {"type": "vless", "tag": "vless-fi", "server": "198.51.100.11", "server_port": 443},
                    "subscription_id": "default",
                },
                {
                    "tag": "vless-dead",
                    "protocol": "vless",
                    "server": "198.51.100.99",
                    "server_port": 443,
                    "raw_outbound": {"type": "vless", "tag": "vless-dead", "server": "198.51.100.99", "server_port": 443},
                    "subscription_id": "default",
                },
            ],
        )
        return net_key
    finally:
        st.close()


def test_external_ip_filter() -> None:
    assert _is_external_ip("127.0.0.1") is False
    assert _is_external_ip("192.168.1.50") is False
    assert _is_external_ip("10.0.0.2") is False
    assert _is_external_ip("172.19.0.1") is False
    assert _is_external_ip("169.254.1.1") is False
    assert _is_external_ip("1.1.1.1") is True
    assert _is_external_ip("198.51.100.11") is True


@pytest.mark.asyncio
async def test_dns_and_vpn_layer_orchestrators_pick_fastest(monkeypatch: pytest.MonkeyPatch) -> None:
    rtts = {
        ("1.1.1.1", 443): TcpProbeResult(result="ok", rtt_ms=28.0, target_ip="1.1.1.1"),
        ("8.8.8.8", 443): TcpProbeResult(result="ok", rtt_ms=14.2, target_ip="8.8.8.8"),
        ("9.9.9.9", 443): TcpProbeResult(result="timeout", rtt_ms=None, target_ip="9.9.9.9"),
        ("198.51.100.11", 443): TcpProbeResult(result="ok", rtt_ms=22.4, target_ip="198.51.100.11"),
        ("198.51.100.99", 443): TcpProbeResult(result="timeout", rtt_ms=None, target_ip="198.51.100.99"),
        ("127.0.0.1", 10808): TcpProbeResult(result="ok", rtt_ms=1.1, target_ip="127.0.0.1"),
    }

    async def fake_probe_tcp(ip: str, port: int = 443, timeout: float = 2.0) -> TcpProbeResult:
        return rtts.get((ip, port), TcpProbeResult(result="timeout", target_ip=ip))

    monkeypatch.setattr(orch_mod, "probe_tcp", fake_probe_tcp)

    dns_orch = DnsLayerOrchestrator()
    dns_health = await dns_orch.check_health()
    assert dns_health["status"] == "ok"
    assert dns_health["best_server"] == "8.8.8.8"
    assert dns_health["best_rtt_ms"] == 14.2
    assert dns_health["healthy_count"] == 2

    vpn_orch = VpnLayerOrchestrator()
    nodes = [
        {"tag": "vless-dead", "protocol": "vless", "server": "198.51.100.99", "server_port": 443},
        {"tag": "vless-fi", "protocol": "vless", "server": "198.51.100.11", "server_port": 443},
    ]
    vpn_health = await vpn_orch.check_health(nodes)
    assert vpn_health["status"] == "ok"
    assert vpn_health["alive_count"] == 1
    assert vpn_health["best_node"] == "vless-fi"
    assert vpn_health["best_ping_ms"] == 22.4
    assert vpn_health["tg_proxy_alive"] is True
    assert vpn_health["nodes"][0]["tag"] == "vless-fi"
    assert vpn_health["nodes"][1]["alive"] is False


@pytest.mark.asyncio
async def test_realtime_monitor_scans_and_auto_heals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "netdoc.db"
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    net_key = _seed_db(db_path)

    # Seed an active log line mapping youtube.com -> 203.0.113.55
    (logs_dir / "sing-box.log").write_text(
        "INFO outbound connected to youtube.com:203.0.113.55\n",
        encoding="utf-8",
    )

    fake_conns = [
        SimpleNamespace(
            fd=1,
            family=socket.AF_INET,
            type=socket.SOCK_STREAM,
            laddr=SimpleNamespace(ip="192.168.1.10", port=51000),
            raddr=SimpleNamespace(ip="203.0.113.55", port=443),
            status="SYN_SENT",
            pid=9991,
        ),
        SimpleNamespace(
            fd=2,
            family=socket.AF_INET,
            type=socket.SOCK_STREAM,
            laddr=SimpleNamespace(ip="192.168.1.10", port=51001),
            raddr=SimpleNamespace(ip="127.0.0.1", port=10808),
            status="ESTABLISHED",
            pid=9992,
        ),
    ]
    monkeypatch.setattr(psutil, "net_connections", lambda kind="inet": fake_conns)

    backend = GuiBackend(
        db_path=db_path,
        configs_dir=tmp_path / "configs",
        lists_dir=tmp_path / "lists",
        logs_dir=logs_dir,
        bin_dir=tmp_path / "bin",
    )
    monkeypatch.setattr(backend.orchestrator.monitor, "_resolve_pid_name", lambda pid: "chrome.exe")

    scan_res = backend.scan_live_connections()
    conns = scan_res["connections"]
    # Loopback filtered out; 203.0.113.55 mapped to youtube.com with SYN_SENT -> needs_fix
    assert len(conns) == 1
    assert conns[0]["process"] == "chrome.exe"
    assert conns[0]["domain"] == "youtube.com"
    assert conns[0]["health"] == "needs_fix"

    # Mock probes + network detection for auto-heal
    monkeypatch.setattr(orch_mod, "detect_bypass_active", lambda: False)
    monkeypatch.setattr(orch_mod, "_is_admin", lambda: False)

    async def fake_net(timeout: float = 2.0) -> NetworkFingerprint:
        return NetworkFingerprint(asn=12389, kind=NetworkKind.HOME, isp="TestISP")

    async def fake_probes(domain: str, timeout: float = 2.0) -> ProbesSummary:
        return ProbesSummary(
            dns=DnsProbeResult(system="ok", doh="ok", doh_ips=["203.0.113.55"]),
            tcp=TcpProbeResult(result="ok", rtt_ms=19.0, target_ip="203.0.113.55"),
            tls=TlsProbeResult(real_sni="reset", neutral_sni="ok", ttfb_ms=40.0),
            stall=StallProbeResult(result="ok", bytes_read=8192, throughput_kbps=2200.0),
            quic=QuicProbeResult(result="ok"),
        )

    monkeypatch.setattr(orch_mod, "detect_network_fingerprint", fake_net)
    monkeypatch.setattr(orch_mod, "run_domain_probes", fake_probes)

    heal_res = await backend.orchestrator.monitor.auto_heal_connections(backend, max_domains_per_tick=2)
    assert len(heal_res["healed"]) == 1
    assert heal_res["healed"][0]["domain"] == "youtube.com"
    assert heal_res["healed"][0]["layer"] == "dpi"
    assert heal_res["events"]

    # After healing, youtube.com decision exists in DB and live scan marks it protected
    st = Storage(db_path)
    try:
        dec = [d for d in st.get_decisions(net_key) if d.domain == "youtube.com"]
        assert len(dec) == 1
        assert dec[0].layer == "dpi"
    finally:
        st.close()

    # Replace SYN_SENT with ESTABLISHED and check status becomes protected
    fake_conns[0].status = "ESTABLISHED"
    after_scan = backend.scan_live_connections()["connections"]
    assert after_scan[0]["domain"] == "youtube.com"
    assert after_scan[0]["health"] == "protected"


def test_gui_backend_autopilot_and_orchestrator_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "auto.db"
    _seed_db(db_path)
    monkeypatch.setattr(psutil, "net_connections", lambda kind="inet": [])
    monkeypatch.setattr(backend_mod, "_is_admin", lambda: False)
    monkeypatch.setattr(backend_mod, "detect_bypass_active", lambda: False)

    backend = GuiBackend(
        db_path=db_path,
        configs_dir=tmp_path / "configs",
        lists_dir=tmp_path / "lists",
        logs_dir=tmp_path / "logs",
        bin_dir=tmp_path / "bin",
    )

    res = backend.start_autopilot()
    assert res["configs_ready"] is True
    assert res["requires_admin"] is True
    assert res["started_services"] is False
    assert (tmp_path / "configs" / "winws2_preset.txt").is_file()
    assert (tmp_path / "configs" / "sing-box.json").is_file()
    assert set(res["orchestrators"].keys()) == {"dns", "dpi", "vpn", "realtime"}

    try:
        app = NetdoctorGuiApp(backend=backend, auto_start=False)
    except tk.TclError as exc:
        pytest.skip(f"Tcl/Tk display unavailable: {exc}")

    try:
        app.withdraw()
        app.update_idletasks()
        snap = backend.get_status_snapshot()
        app.apply_snapshot(snap)
        assert "1.1.1.1" in app.card_dns_val.cget("text")
        assert "1 сайтов" in app.card_dpi_val.cget("text")

        app.populate_connections_table(
            [
                {
                    "process": "Discord.exe",
                    "domain": "discord.com",
                    "remote_ip": "162.159.135.232",
                    "remote_port": 443,
                    "remote": "162.159.135.232:443",
                    "protocol": "tls",
                    "socket_status": "ESTABLISHED",
                    "layer": "dpi",
                    "strategy_id": "tls_hostfakesplit_ozon",
                    "health": "protected",
                }
            ],
            events=[
                {
                    "timestamp": "22:30:00",
                    "process": "Discord.exe",
                    "domain": "discord.com",
                    "action": "Автоподбор -> dpi/tls_hostfakesplit_ozon",
                }
            ],
        )
        assert len(app.conn_tree.get_children()) == 1
        assert "discord.com" in app.realtime_feed.get("1.0", "end-1c")

        dns_data = backend.get_dns_catalog()
        app.render_dns_grid(dns_data["servers"], dns_data["active_dns_id"])
        assert app.dns_grid_frame.winfo_children()
    finally:
        app.on_close()


def test_builtin_36_dns_catalog_custom_dns_game_filter_and_presets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    counts = Counter(s["category"] for s in BUILTIN_DNS_CATALOG)
    assert len(BUILTIN_DNS_CATALOG) == 43
    assert counts["popular"] == 3
    assert counts["security"] == 12
    assert counts["uncommon"] == 16
    assert counts["ai_bypass"] == 12
    assert any(s["name"] == "Xbox DNS" and s["ip"] == "176.99.11.77" for s in BUILTIN_DNS_CATALOG)
    assert any(s["name"] == "LibreDNS" and s["ip"] == "116.202.176.26" for s in BUILTIN_DNS_CATALOG)
    assert any(s["name"] == "Bezmezhau" and s["ip"] == "143.20.64.55" for s in BUILTIN_DNS_CATALOG)
    assert any(s["name"] == "Zapret DNS" and s["ip"] == "188.114.97.1" for s in BUILTIN_DNS_CATALOG)

    db_path = tmp_path / "dns_test.db"
    _seed_db(db_path)
    monkeypatch.setattr(psutil, "net_connections", lambda kind="inet": [])
    monkeypatch.setattr(backend_mod, "_is_admin", lambda: False)
    monkeypatch.setattr(backend_mod, "detect_bypass_active", lambda: False)

    backend = GuiBackend(
        db_path=db_path,
        configs_dir=tmp_path / "configs",
        lists_dir=tmp_path / "lists",
        logs_dir=tmp_path / "logs",
        bin_dir=tmp_path / "bin",
    )

    # Custom DNS add + validation + sing-box config propagation + delete
    with pytest.raises(ValueError, match="IP-адрес"):
        backend.add_custom_dns("Bad", "not-an-ip")

    custom = backend.add_custom_dns("MyPrivateDNS", "203.0.113.77", description="Мой сервер")
    assert custom["category"] == "custom"
    assert custom["ip"] == "203.0.113.77"
    sb_cfg = json.loads((tmp_path / "configs" / "sing-box.json").read_text(encoding="utf-8"))
    assert sb_cfg["dns"]["servers"][0]["server"] == "203.0.113.77"
    assert sb_cfg["dns"]["servers"][0]["type"] == "udp"

    # Selecting DoH AI server updates sing-box to type=https
    bez = backend.select_dns_server("bezmezhau")
    assert bez["ip"] == "143.20.64.55"
    sb_cfg = json.loads((tmp_path / "configs" / "sing-box.json").read_text(encoding="utf-8"))
    assert sb_cfg["dns"]["servers"][0]["server"] == "143.20.64.55"
    assert sb_cfg["dns"]["servers"][0]["type"] == "https"

    assert backend.remove_custom_dns(custom["id"]) is True

    # Ping catalog & auto_select_best_dns with mocked probe_tcp
    async def fake_probe_tcp(ip: str, port: int = 443, timeout: float = 1.2) -> TcpProbeResult:
        if ip == "188.114.97.1":
            return TcpProbeResult(result="ok", rtt_ms=11.0, target_ip=ip)
        if ip in ("143.20.64.55", "185.222.222.222"):
            return TcpProbeResult(result="ok", rtt_ms=42.0, target_ip=ip)
        return TcpProbeResult(result="timeout", target_ip=ip)

    monkeypatch.setattr(orch_mod, "probe_tcp", fake_probe_tcp)
    best_ai = backend.auto_select_best_dns("ai_bypass")
    assert best_ai["id"] == "zapret_dns"
    assert best_ai["ping_ms"] == 11.0

    # Game filter toggle injects 1024-65535 into winws2_preset.txt
    gf = backend.set_game_filter(True)
    assert gf["game_filter"] is True
    preset_txt = (tmp_path / "configs" / "winws2_preset.txt").read_text(encoding="utf-8")
    assert "1024-65535" in preset_txt

    # AI Service Preset sets AI bypass DNS and runs diag for chatgpt/openai/claude
    async def fake_net(timeout: float = 2.5) -> NetworkFingerprint:
        return NetworkFingerprint(asn=12389, kind=NetworkKind.HOME, isp="TestISP")

    async def fake_probes(domain: str, timeout: float = 2.5) -> ProbesSummary:
        return ProbesSummary(
            dns=DnsProbeResult(system="ok", doh="ok", doh_ips=["198.51.100.55"]),
            tcp=TcpProbeResult(result="ok", rtt_ms=20.0, target_ip="198.51.100.55"),
            tls=TlsProbeResult(real_sni="reset", neutral_sni="ok", ttfb_ms=35.0),
            stall=StallProbeResult(result="ok", bytes_read=4096, throughput_kbps=1500.0),
            quic=QuicProbeResult(result="ok"),
        )

    monkeypatch.setattr(backend_mod, "detect_network_fingerprint", fake_net)
    monkeypatch.setattr(backend_mod, "run_domain_probes", fake_probes)

    async def fake_base_dns(domain: str, timeout: float = 1.2) -> DnsProbeResult:
        return DnsProbeResult(system="ok", doh="ok", system_ips=["198.51.100.1"])

    async def fake_domain_dns_probe(
        domain: str,
        srv: dict[str, Any],
        baseline_ips: set[str] | None = None,
        timeout: float = 1.8,
    ) -> dict[str, Any]:
        return {
            "dns_id": srv["id"],
            "name": srv["name"],
            "ip": srv["ip"],
            "category": srv.get("category"),
            "ok": srv["id"] == "bezmezhau",
            "resolved_ips": ["198.51.100.88"],
            "rtt_ms": 25.0,
            "is_proxy_ip": True,
        }

    monkeypatch.setattr(orch_mod, "probe_dns", fake_base_dns)
    monkeypatch.setattr(backend.orchestrator.dns, "probe_dns_server_for_domain", fake_domain_dns_probe)

    ai_res = backend.apply_service_preset("ai")
    assert ai_res["selected_dns"]["category"] == "ai_bypass"
    row_domains = {r["domain"] for r in backend.get_domain_rows()}
    assert {"chatgpt.com", "openai.com", "claude.ai"}.issubset(row_domains)

    # Mock flushdns subprocess safely
    monkeypatch.setattr(
        backend_mod.subprocess,
        "run",
        lambda *a, **kw: SimpleNamespace(returncode=0, stdout="Successfully flushed DNS Resolver Cache", stderr=""),
    )
    flush = backend.flush_windows_dns_cache()
    assert flush["ok"] is True
    assert "Successfully flushed" in flush["output"]


def test_per_domain_dns_rolling_and_singbox_rules(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "per_domain_dns.db"
    net_key = _seed_db(db_path)

    dns_orch = DnsLayerOrchestrator()
    st = Storage(db_path)
    try:
        async def fake_probe(domain: str, srv: dict[str, Any]) -> dict[str, Any]:
            winners = {
                "chatgpt.com": ("astracat", 18.0),
                "claude.ai": ("bezmezhau", 21.0),
                "grok.com": ("geohide", 19.5),
            }
            win_id, rtt = winners[domain]
            if srv["id"] == win_id:
                return {
                    "dns_id": srv["id"],
                    "name": srv["name"],
                    "ip": srv["ip"],
                    "category": srv.get("category"),
                    "ok": True,
                    "resolved_ips": ["203.0.113.10"],
                    "rtt_ms": rtt,
                    "is_proxy_ip": True,
                }
            if srv["id"] == "zapret_dns":
                return {
                    "dns_id": srv["id"],
                    "name": srv["name"],
                    "ip": srv["ip"],
                    "category": srv.get("category"),
                    "ok": True,
                    "resolved_ips": ["203.0.113.11"],
                    "rtt_ms": 95.0,
                    "is_proxy_ip": True,
                }
            return {
                "dns_id": srv["id"],
                "name": srv["name"],
                "ip": srv["ip"],
                "category": srv.get("category"),
                "ok": False,
                "resolved_ips": [],
                "rtt_ms": None,
                "is_proxy_ip": False,
            }

        decisions = asyncio.run(
            dns_orch.roll_dns_for_domains_batch(
                ["chatgpt.com", "claude.ai", "grok.com"],
                network_key=net_key,
                storage=st,
                probe_fn=fake_probe,
            )
        )
        by_dom = {d.domain: d for d in decisions}
        assert by_dom["chatgpt.com"].layer == "dns"
        assert by_dom["chatgpt.com"].strategy_id == "dns:astracat"
        assert "dns:zapret_dns" in by_dom["chatgpt.com"].fallback_strategies
        assert by_dom["claude.ai"].strategy_id == "dns:bezmezhau"
        assert by_dom["grok.com"].strategy_id == "dns:geohide"
    finally:
        st.close()

    monkeypatch.setattr(psutil, "net_connections", lambda kind="inet": [])
    backend = GuiBackend(
        db_path=db_path,
        configs_dir=tmp_path / "configs",
        lists_dir=tmp_path / "lists",
        logs_dir=tmp_path / "logs",
        bin_dir=tmp_path / "bin",
    )
    backend.trigger_apply_configs()
    sb_cfg = json.loads((tmp_path / "configs" / "sing-box.json").read_text(encoding="utf-8"))
    server_by_tag = {s["tag"]: s for s in sb_cfg["dns"]["servers"]}
    # Global default kept intact
    assert server_by_tag["dns-doh"]["server"] == "1.1.1.1"
    # Per-domain DNS entries generated cleanly (AstraCat=UDP, Bezmezhau/GeoHide=HTTPS DoH)
    assert server_by_tag["dns-astracat"]["server"] == "135.186.217.200"
    assert server_by_tag["dns-astracat"]["type"] == "udp"
    assert server_by_tag["dns-bezmezhau"]["server"] == "143.20.64.55"
    assert server_by_tag["dns-bezmezhau"]["type"] == "https"
    assert server_by_tag["dns-geohide"]["server"] == "193.233.112.67"

    rule_by_server = {r["server"]: r["domain_suffix"] for r in sb_cfg["dns"]["rules"]}
    assert rule_by_server["dns-astracat"] == ["chatgpt.com"]
    assert rule_by_server["dns-bezmezhau"] == ["claude.ai"]
    assert rule_by_server["dns-geohide"] == ["grok.com"]

    cat = backend.get_dns_catalog()
    by_id = {s["id"]: s for s in cat["servers"]}
    assert by_id["astracat"]["assigned_domains"] == ["chatgpt.com"]
    assert by_id["bezmezhau"]["assigned_domains"] == ["claude.ai"]

    try:
        app = NetdoctorGuiApp(backend=backend, auto_start=False)
    except tk.TclError as exc:
        pytest.skip(f"Tcl/Tk display unavailable: {exc}")

    try:
        app.withdraw()
        app.update_idletasks()
        app.render_dns_grid(cat["servers"], cat["active_dns_id"])
        # Verify <MouseWheel> bound recursively onto child widgets so scrolling works on Windows cards
        children = app.dns_grid_frame.winfo_children()
        assert children
        first_card_grid = next(w for w in children if w.winfo_children())
        card_child = first_card_grid.winfo_children()[0]
        assert bool(card_child.bind("<MouseWheel>"))
    finally:
        app.on_close()


def test_antigravity_unlocker_and_hosts_guard_protection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "unlocker_guard.db"
    hosts_file = tmp_path / "hosts"
    hosts_file.write_text(
        "# Antigravity Unlocker hosts block\n"
        "193.233.112.67 ai.google.dev\n"
        "193.233.112.67 daily-cloudcode-pa.googleapis.com\n"
        "161.104.89.59 openrouter.ai\n"
        "172.66.0.227 x.com\n"
        "127.0.0.1 max.ru\n",
        encoding="utf-8",
    )

    net_key = _seed_db(db_path)
    st = Storage(db_path)
    try:
        # Accidental DPI decision for ai.google.dev and normal DPI for x.com
        st.save_decision(
            Decision(
                network_key=net_key,
                domain="ai.google.dev",
                protocol=Protocol.TLS,
                layer="dpi",
                strategy_id="tls_hostfakesplit_ozon",
                status="active",
            )
        )
        st.save_decision(
            Decision(
                network_key=net_key,
                domain="x.com",
                protocol=Protocol.TLS,
                layer="dpi",
                strategy_id="tls_hostfakesplit_ozon",
                status="active",
            )
        )
    finally:
        st.close()

    backend = GuiBackend(
        db_path=db_path,
        configs_dir=tmp_path / "configs",
        lists_dir=tmp_path / "lists",
        logs_dir=tmp_path / "logs",
        bin_dir=tmp_path / "bin",
        hosts_path=hosts_file,
    )

    applied = backend.trigger_apply_configs()
    # Conflicting DPI decision for ai.google.dev is automatically purged, x.com remains
    domains_in_db = {r["domain"] for r in backend.get_domain_rows()}
    assert "ai.google.dev" not in domains_in_db
    assert "x.com" in domains_in_db

    # SNI proxy IPs from hosts are in exclude_vpn_ips.txt, while x.com's Cloudflare IP is NOT excluded
    excluded_ips = (tmp_path / "lists" / "exclude_vpn_ips.txt").read_text(encoding="utf-8")
    assert "193.233.112.67" in excluded_ips
    assert "161.104.89.59" in excluded_ips
    assert "172.66.0.227" not in excluded_ips

    # Exclude hostlist prevents circular catch-all from touching unlocker & Antigravity domains
    excluded_doms_txt = (tmp_path / "lists" / "exclude_unlocker_domains.txt").read_text(encoding="utf-8")
    assert "ai.google.dev" in excluded_doms_txt
    assert "daily-cloudcode-pa.googleapis.com" in excluded_doms_txt
    assert "openrouter.ai" in excluded_doms_txt
    assert "x.com" not in excluded_doms_txt

    preset_txt = (tmp_path / "configs" / "winws2_preset.txt").read_text(encoding="utf-8")
    assert "--hostlist-exclude=" in preset_txt

    # sing-box resolves hosts domains via dns-local and sends Antigravity.exe + xray.exe direct
    sb_cfg = json.loads((tmp_path / "configs" / "sing-box.json").read_text(encoding="utf-8"))
    assert sb_cfg["dns"]["rules"][0]["server"] == "dns-local"
    assert "ai.google.dev" in sb_cfg["dns"]["rules"][0]["domain_suffix"]
    assert "daily-cloudcode-pa.googleapis.com" in sb_cfg["dns"]["rules"][0]["domain_suffix"]

    route_rules = sb_cfg["route"]["rules"]
    proc_rule = next(r for r in route_rules if "process_name" in r)
    assert "Antigravity.exe" in proc_rule["process_name"]
    assert "xray.exe" in proc_rule["process_name"]
    assert proc_rule["outbound"] == "direct"

    # Live radar classifies Antigravity.exe socket as protected by unlocker and never auto-heals it
    fake_conns = [
        SimpleNamespace(
            fd=10,
            family=socket.AF_INET,
            type=socket.SOCK_STREAM,
            laddr=SimpleNamespace(ip="192.168.1.10", port=52000),
            raddr=SimpleNamespace(ip="193.233.112.67", port=443),
            status="SYN_SENT",
            pid=22100,
        ),
    ]
    monkeypatch.setattr(psutil, "net_connections", lambda kind="inet": fake_conns)
    monkeypatch.setattr(backend.orchestrator.monitor, "_resolve_pid_name", lambda pid: "Antigravity.exe")

    scan_res = backend.scan_live_connections()
    assert len(scan_res["connections"]) == 1
    assert scan_res["connections"][0]["layer"] == "unlocker"
    assert scan_res["connections"][0]["health"] == "protected"

    # Custom exclusions API works end-to-end
    custom_res = backend.set_unlocker_exclusions("MyCustomApp.exe, custom-unlocker.local, 203.0.113.200", enabled=True)
    assert "203.0.113.200" in (tmp_path / "lists" / "exclude_vpn_ips.txt").read_text(encoding="utf-8")
    assert "custom-unlocker.local" in (tmp_path / "lists" / "exclude_unlocker_domains.txt").read_text(encoding="utf-8")
    assert "MyCustomApp.exe" in custom_res["guard"]["protected_processes"]


def test_single_instance_and_supervisor_state_preservation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import os
    from netdoctor.gui_backend import build_elevate_command
    from netdoctor.supervisor import ProcessSupervisor, validate_singbox_config
    from netdoctor.tray import acquire_single_instance_mutex, build_autostart_command, release_single_instance_mutex

    db_path = tmp_path / "wal.db"
    st = Storage(db_path)
    try:
        mode = str(st.conn.execute("PRAGMA journal_mode").fetchone()[0]).lower()
        assert mode == "wal"
    finally:
        st.close()

    # Single-instance mutex rejects duplicate owner and succeeds again after release
    mutex_name = f"Local\\NetdoctorTestMutex_{os.getpid()}"
    ok1, h1 = acquire_single_instance_mutex(mutex_name)
    assert ok1 is True
    ok2, h2 = acquire_single_instance_mutex(mutex_name)
    assert ok2 is False and h2 is None
    release_single_instance_mutex(h1)
    ok3, h3 = acquire_single_instance_mutex(mutex_name)
    assert ok3 is True
    release_single_instance_mutex(h3)

    # Elevate command propagates --replace-pid and autostart command sets absolute paths
    cmd = build_elevate_command(
        db_path=db_path,
        configs_dir=tmp_path / "configs",
        lists_dir=tmp_path / "lists",
        logs_dir=tmp_path / "logs",
        bin_dir=tmp_path / "bin",
        replace_pid=4242,
        auto_start=True,
    )
    assert cmd[0] == "powershell.exe"
    assert "--replace-pid" in cmd[-1] and "4242" in cmd[-1] and "--auto-start" in cmd[-1]

    as_cmd = build_autostart_command(tmp_path, db_path=db_path)
    assert "--minimized" in as_cmd and "--auto-start" in as_cmd

    # ProcessSupervisor._save_state preserves adopted live sing-box & tg-ws-proxy PIDs on partial winws2 reload
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    alive_pid = os.getpid()
    (logs_dir / "supervisor_state.json").write_text(
        json.dumps(
            {
                "updated_at": "2026-11-18T00:00:00Z",
                "processes": {
                    "sing-box": {"pid": alive_pid, "running": True, "cmd": ["sing-box.exe"]},
                    "tg-ws-proxy": {"pid": alive_pid, "running": True, "cmd": ["tg.exe"]},
                },
            }
        ),
        encoding="utf-8",
    )
    sup = ProcessSupervisor(bin_dir=tmp_path / "bin", logs_dir=logs_dir)
    adopted = sup.adopt_persisted_state()
    assert "sing-box" in adopted and "tg-ws-proxy" in adopted
    sup._save_state()
    saved = json.loads((logs_dir / "supervisor_state.json").read_text(encoding="utf-8"))
    assert "sing-box" in saved["processes"]
    assert "tg-ws-proxy" in saved["processes"]

    # validate_singbox_config validates real configs when bin/sing-box.exe is present
    real_bin = Path("bin")
    if (real_bin / "sing-box.exe").is_file():
        bad_cfg = tmp_path / "bad_sb.json"
        bad_cfg.write_text('{"outbounds":[{"type":"invalid_outbound_xyz","tag":"x"}]}', encoding="utf-8")
        ok_bad, err_bad = validate_singbox_config(real_bin, bad_cfg)
        assert ok_bad is False and err_bad


def test_vpn_rotation_clash_api_circuit_breaker_and_wireguard_endpoints(tmp_path: Path) -> None:
    import http.server
    import threading
    from netdoctor.clash_api import ClashApiClient
    from netdoctor.config_gen import generate_singbox_config
    from netdoctor.supervisor import validate_singbox_config
    from netdoctor.vpn import infer_node_region, infer_node_transport, parse_subscription_payload

    assert infer_node_region("🇩🇪 Germany-Reality") == "eu"
    assert infer_node_region("🇺🇸 USA-WS") == "us"
    assert infer_node_region("🇷🇺 Moscow-Relay") == "ru"

    db_path = tmp_path / "vpn_rot.db"
    st = Storage(db_path)
    try:
        # Cross-subscription tag collision deduplicates second Germany-1 cleanly
        n_sub1 = parse_subscription_payload(
            "vless://11111111-2222-3333-4444-555555555555@198.51.100.10:443?security=reality&sni=yahoo.com&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=abcd#Germany-1\n"
            "trojan://pass@198.51.100.11:443?security=tls&sni=example.com#USA-WS\n",
            subscription_id="sub1",
        )
        n_sub2 = parse_subscription_payload(
            "vless://11111111-2222-3333-4444-555555555555@198.51.100.12:443?security=tls#Germany-1\n",
            subscription_id="sub2",
        )
        assert infer_node_transport(n_sub1[0].raw_outbound, n_sub1[0].protocol) == "reality"
        st.save_subscription("sub1", "https://sub1.example", [n.model_dump(mode="json") for n in n_sub1])
        st.save_subscription("sub2", "https://sub2.example", [n.model_dump(mode="json") for n in n_sub2])

        all_nodes = st.get_all_subscription_nodes()
        assert len(all_nodes) == 3
        assert len({n["tag"] for n in all_nodes}) == 3
        assert any(n["tag"] == "sub2__Germany-1" for n in all_nodes)

        # Config with WireGuard endpoint + Clash API + hierarchical ut-* pools passes sing-box check
        awg = parse_subscription_payload(
            '{"outbounds":[{"type":"wireguard","tag":"AWG-NL","server":"198.51.100.30","server_port":51820,"local_address":["10.0.0.2/32"],"private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","peer_public_key":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="}]}',
            subscription_id="awg",
        )
        from netdoctor.models import VpnNode

        vpn_models = [VpnNode(**n) for n in all_nodes] + awg
        sb_path = tmp_path / "sing-box.json"
        sb_cfg = generate_singbox_config(
            decisions=[],
            vpn_nodes=vpn_models,
            output_path=sb_path,
            use_wireguard_endpoints=True,
            clash_api_addr="127.0.0.1:19090",
        )
        assert "endpoints" in sb_cfg
        assert any(ep["tag"] == "AWG-NL" for ep in sb_cfg["endpoints"])
        out_tags = {o["tag"] for o in sb_cfg["outbounds"]}
        assert "vpn-auto" in out_tags and "vpn-select" in out_tags and "vpn-ai" in out_tags
        assert any(t.startswith("ut-sub1-") for t in out_tags)
        assert "experimental" in sb_cfg and "clash_api" in sb_cfg["experimental"]
        if (Path("bin") / "sing-box.exe").is_file():
            valid, err = validate_singbox_config("bin", sb_path)
            assert valid is True, f"sing-box check failed: {err}"

        # Circuit Breaker transitions closed -> open on 2 fails, and Sticky Hysteresis resists jitter
        vpn_orch = VpnLayerOrchestrator()
        r1 = vpn_orch.record_node_result(st, all_nodes[0], ok=False, protocol_ok=False, error="protocol_block")
        assert r1["cb_state"] == "closed"
        r2 = vpn_orch.record_node_result(st, all_nodes[0], ok=False, protocol_ok=False, error="protocol_block")
        assert r2["cb_state"] == "open" and r2["quarantined_until"]

        assert vpn_orch.should_switch_active_node(
            {"tag": "a", "alive": True, "cb_state": "closed", "ping_ms": 180},
            {"tag": "b", "alive": True, "cb_state": "closed", "ping_ms": 150},
            last_switch_ts=0.0,
            now_ts=500.0,
        ) is False
        assert vpn_orch.should_switch_active_node(
            {"tag": "a", "alive": True, "cb_state": "closed", "ping_ms": 350},
            {"tag": "b", "alive": True, "cb_state": "closed", "ping_ms": 90},
            last_switch_ts=0.0,
            now_ts=500.0,
        ) is True

        # Mock Clash API server verifies rotate_vpn_node selects healthy node & closes failing sockets
        state = {"selected": None, "deleted": []}

        class _ClashHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:
                return

            def do_GET(self) -> None:
                if self.path == "/proxies":
                    body = json.dumps({"vpn-select": {"now": all_nodes[0]["tag"]}}).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(body)
                elif self.path == "/connections":
                    body = json.dumps(
                        {
                            "connections": [
                                {"id": "c1", "chains": ["vpn-select", all_nodes[0]["tag"]], "metadata": {"host": "instagram.com", "destinationIP": "157.240.1.1"}},
                                {"id": "c2", "chains": ["direct"], "metadata": {"host": "ya.ru", "destinationIP": "77.88.55.242"}},
                            ]
                        }
                    ).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_response(404)
                    self.end_headers()

            def do_PUT(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
                state["selected"] = payload.get("name")
                self.send_response(204)
                self.end_headers()

            def do_DELETE(self) -> None:
                state["deleted"].append(self.path.rsplit("/", 1)[-1])
                self.send_response(204)
                self.end_headers()

        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _ClashHandler)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            client = ClashApiClient(controller_addr=f"127.0.0.1:{srv.server_port}")
            rot = vpn_orch.rotate_vpn_node(st, all_nodes, clash_client=client)
            assert rot["ok"] is True
            assert rot["switched_live"] is True
            assert state["selected"] == rot["selected"]
            assert rot["selected"] != all_nodes[0]["tag"]
            assert state["deleted"] == ["c1"]
        finally:
            srv.shutdown()
            srv.server_close()
    finally:
        st.close()


@pytest.mark.asyncio
async def test_tier3_batch_eval_circular_parser_and_byedpi_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from netdoctor.config_gen import generate_singbox_config, generate_winws2_config
    from netdoctor.dynamics import parse_circular_rotations, run_canary_cycle
    from netdoctor.selector import evaluate_domains_live_batch
    import netdoctor.selector as sel_mod

    # 1. evaluate_domains_live_batch evaluates beyond pool[:6] so Tier 3 strategies can win
    monkeypatch.setattr(sel_mod, "_is_admin", lambda: True)
    monkeypatch.setattr(sel_mod, "detect_bypass_active", lambda: False)
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir(parents=True, exist_ok=True)
    (fake_bin / "winws2.exe").write_bytes(b"MZ")

    class _FakeProc:
        def poll(self) -> None:
            return None

        def terminate(self) -> None:
            return None

        def wait(self, timeout: float = 1.0) -> int:
            return 0

        def kill(self) -> None:
            return None

    monkeypatch.setattr(sel_mod.subprocess, "Popen", lambda *a, **kw: _FakeProc())
    tested_ids: list[str] = []

    async def fake_eval(dom: str, ip: str, strat: Any, repeats: int = 1, timeout: float = 1.8) -> sel_mod.CandidateEvaluation:
        tested_ids.append(strat.id)
        ok = strat.tier >= 3
        return sel_mod.CandidateEvaluation(strat, success_rate=1.0 if ok else 0.0, throughput_kbps=3200.0 if ok else 0.0, ttfb_ms=40.0 if ok else 9999.0)

    monkeypatch.setattr(sel_mod, "default_strategy_evaluator", fake_eval)
    decs = await evaluate_domains_live_batch(
        domains_info=[("youtube.com", "142.250.1.1", [VerdictClass.SNI_DPI])],
        network_key="AS12389:home:default",
        candidates=DEFAULT_STRATEGIES,
        bin_dir=fake_bin,
        use_live_eval=True,
    )
    assert any(sid.startswith("tls_alt9_") or sid.startswith("tls_fake") for sid in tested_ids)
    assert decs["youtube.com"].layer == "dpi"

    # 2. quic_fallback_tcp produces NO empty winws2 hostlist/profile, while byedpi-out appears in sing-box
    strat_map = {s.id: s for s in DEFAULT_STRATEGIES}
    winws_args, hostlists = generate_winws2_config(
        decisions=[
            Decision(network_key="AS12389:home:default", domain="youtube.com", protocol=Protocol.QUIC, layer="dpi", strategy_id="quic_fallback_tcp"),
        ],
        strategies=strat_map,
        lists_dir=tmp_path / "lists",
        enable_tcp_in=True,
    )
    assert "quic_fallback_tcp.txt" not in hostlists
    assert "--wf-tcp-in=80,443" in winws_args

    sb_cfg = generate_singbox_config(decisions=[], vpn_nodes=[], enable_byedpi=True, byedpi_port=10809)
    assert any(o["tag"] == "byedpi-out" and o["type"] == "socks" for o in sb_cfg["outbounds"])

    # 3. parse_circular_rotations ignores startup messages and captures real `rotate strategy to N` + autostate host
    sample_log = (
        "LUA: circular: start from strategy 1\n"
        "LUA: circular: current strategy 1\n"
        "autostate.circular_4_1.youtube.com\n"
        "LUA: circular: rotate strategy to 2\n"
    )
    rots = parse_circular_rotations(sample_log)
    assert len(rots) == 1
    assert rots[0]["strategy"] == 2
    assert rots[0]["domain"] == "youtube.com"

    # 4. Self-probe bypass_active guard preserves active DPI decision during run_diag_sync
    db_path = tmp_path / "bypass_guard.db"
    nk = _seed_db(db_path)
    backend = GuiBackend(
        db_path=db_path,
        configs_dir=tmp_path / "configs",
        lists_dir=tmp_path / "lists",
        logs_dir=tmp_path / "logs",
        bin_dir=fake_bin,
    )
    monkeypatch.setattr(backend_mod, "detect_bypass_active", lambda: True)
    monkeypatch.setattr(backend_mod, "detect_network_fingerprint", lambda timeout=2.5: asyncio.sleep(0, result=NetworkFingerprint(asn=12389, kind=NetworkKind.HOME, isp="TestISP")))

    async def fake_ok_probes(dom: str, timeout: float = 2.5) -> ProbesSummary:
        return ProbesSummary(
            dns=DnsProbeResult(system="ok", doh="ok", doh_ips=["162.159.135.232"]),
            tcp=TcpProbeResult(result="ok", rtt_ms=20.0, target_ip="162.159.135.232"),
            tls=TlsProbeResult(real_sni="ok", neutral_sni="ok", ttfb_ms=25.0),
            stall=StallProbeResult(result="ok", bytes_read=8192, throughput_kbps=5000.0),
            quic=QuicProbeResult(result="ok"),
        )

    monkeypatch.setattr(backend_mod, "run_domain_probes", fake_ok_probes)
    rows = backend.run_diag_sync(domains=["discord.com"], live_eval=False)
    disc_tls = next(r for r in rows if r["domain"] == "discord.com" and r["protocol"] == "tls")
    assert disc_tls["layer"] == "dpi"
    assert disc_tls["strategy_id"] == "tls_hostfakesplit_ozon"


def test_live_radar_clash_connections_and_winws2_hostname_regex(tmp_path: Path) -> None:
    db_path = tmp_path / "radar.db"
    _seed_db(db_path)
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    (logs_dir / "winws2.log").write_text(
        "packet: ip=198.51.100.77 port=443 hostname='api.discord.com' desync=1\n",
        encoding="utf-8",
    )

    class _FakeClash:
        def get_connections_sync(self) -> dict[str, Any]:
            return {
                "connections": [
                    {"metadata": {"host": "cdn.openai.com", "destinationIP": "198.51.100.88"}},
                ]
            }

    mon = RealtimeConnectionMonitor()
    st = Storage(db_path)
    try:
        mon.update_ip_map_from_storage_and_logs(st, logs_dir, clash_client=_FakeClash())  # type: ignore[arg-type]
    finally:
        st.close()

    assert mon.ip_to_domain["198.51.100.77"] == "api.discord.com"
    assert mon.ip_to_domain["198.51.100.88"] == "cdn.openai.com"


def test_youtube_cdn_ag_dns_protection_and_doh_probe_fix(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import netdoctor.orchestrators as orch_mod
    from netdoctor.config_gen import CDN_DOMAIN_EXPANSIONS, DEFAULT_BYPASS_PROCESSES
    from netdoctor.orchestrators import (
        PROTECTED_UNLOCKER_PROCESSES,
        SERVICE_PRESETS,
        DnsLayerOrchestrator,
    )

    assert "ag_dns.exe" in PROTECTED_UNLOCKER_PROCESSES
    assert "ag_dns.exe" in DEFAULT_BYPASS_PROCESSES
    assert SERVICE_PRESETS["music"]["recommended_dns"] == "comss_dns"

    yt_expected = {
        "youtubei.googleapis.com",
        "youtube.googleapis.com",
        "youtube-nocookie.com",
        "yt3.googleusercontent.com",
    }
    assert yt_expected.issubset(set(CDN_DOMAIN_EXPANSIONS["youtube.com"]))
    yt_aliases = next(aliases for aliases, canon in orch_mod._DOMAIN_ALIASES if canon == "youtube.com")
    assert yt_expected.issubset(set(yt_aliases))

    import dns.asyncresolver
    from netdoctor.models import DnsProbeResult, TcpProbeResult

    async def fake_probe_dns(domain: str, doh_url: str | None = None, timeout: float = 1.8) -> DnsProbeResult:
        if doh_url and "dns.comss.one" in doh_url:
            return DnsProbeResult(system="ok", doh="ok", system_ips=[], doh_ips=["104.21.1.1"])
        return DnsProbeResult(system="ok", doh="reset", system_ips=["1.2.3.4"], doh_ips=[])

    async def fake_probe_tcp(ip: str, port: int = 443, timeout: float = 1.8) -> TcpProbeResult:
        return TcpProbeResult(result="ok", rtt_ms=12.0, target_ip=ip)

    async def fake_udp_resolve(self: Any, qname: str, rdtype: str = "A") -> list[Any]:
        # zapret_dns resolves via UDP even though its DoH endpoint has a bad cert
        class _Ans:
            def __init__(self, addr: str) -> None:
                self.address = addr

        if "188.114.97.1" in (getattr(self, "nameservers", []) or []):
            return [_Ans("104.21.1.2")]
        raise TimeoutError("no udp")

    async def fake_tls_ok(ip: str, port: int, sni: str, verify: bool = False, timeout: float = 2.0) -> tuple[str, float | None]:
        return "ok", 18.0

    monkeypatch.setattr(orch_mod, "probe_dns", fake_probe_dns)
    monkeypatch.setattr(orch_mod, "probe_tcp", fake_probe_tcp)
    monkeypatch.setattr(orch_mod, "_single_tls_handshake", fake_tls_ok)
    monkeypatch.setattr(dns.asyncresolver.Resolver, "resolve", fake_udp_resolve)

    orch = DnsLayerOrchestrator()
    dec = asyncio.run(orch.roll_dns_for_domain("chatgpt.com", "AS12389:home:default"))
    assert dec.layer == "dns"
    assert dec.strategy_id == "dns:comss_dns"

    # auto_heal_connections passes clash_client from backend when sing-box is running
    from netdoctor.gui_backend import GuiBackend

    heal_db = tmp_path / "heal.db"
    _seed_db(heal_db)
    heal_backend = GuiBackend(
        db_path=heal_db,
        configs_dir=tmp_path / "configs",
        lists_dir=tmp_path / "lists",
        logs_dir=tmp_path / "logs",
        bin_dir=tmp_path / "bin",
    )
    captured: dict[str, Any] = {}

    class _FakeClash:
        pass

    heal_backend.clash_api = _FakeClash()  # type: ignore[assignment]
    monkeypatch.setattr(heal_backend, "_collect_processes_state", lambda: {"sing-box": {"running": True}})

    mon = RealtimeConnectionMonitor()

    def fake_scan(
        storage: Any,
        logs_dir: Any,
        net_key: str = "",
        hosts_path: Any = None,
        clash_client: Any = None,
    ) -> list[dict[str, Any]]:
        captured["clash_client"] = clash_client
        return []

    monkeypatch.setattr(mon, "scan_active_connections", fake_scan)
    heal_res = asyncio.run(mon.auto_heal_connections(backend=heal_backend))
    assert heal_res["healed"] == []
    assert isinstance(captured["clash_client"], _FakeClash)


def test_clash_synthesis_stalled_singbox_log_failures_and_unknown_domain_auto_heal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "realtime_full.db"
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    net_key = _seed_db(db_path)

    # Seed an already-verified direct site (github.com) and a direct site that stalls in Clash
    st = Storage(db_path)
    try:
        st.save_decision(
            Decision(
                network_key=net_key,
                domain="github.com",
                protocol=Protocol.TLS,
                layer="direct",
                strategy_id=None,
                status="active",
            )
        )
        st.save_decision(
            Decision(
                network_key=net_key,
                domain="stalled-direct.example",
                protocol=Protocol.TLS,
                layer="direct",
                strategy_id=None,
                status="active",
            )
        )
    finally:
        st.close()

    # sing-box.log has an i/o timeout for 203.0.113.77 (github.com) -> must flip to needs_fix despite direct decision
    (logs_dir / "sing-box.log").write_text(
        "+0300 2026-11-18 22:20:03 ERROR [111 5.0s] connection: open connection to 203.0.113.77:443 "
        "using outbound/direct[direct]: dial tcp 203.0.113.77:443: i/o timeout\n"
        "INFO outbound connected to github.com:203.0.113.77\n",
        encoding="utf-8",
    )

    # One psutil socket: chrome.exe -> github.com (ESTABLISHED, 203.0.113.77:443)
    # Plus one psutil socket already matching Clash flow so dedup is verified
    fake_conns = [
        SimpleNamespace(
            fd=1,
            family=socket.AF_INET,
            type=socket.SOCK_STREAM,
            laddr=SimpleNamespace(ip="192.168.1.10", port=51100),
            raddr=SimpleNamespace(ip="203.0.113.77", port=443),
            status="ESTABLISHED",
            pid=1001,
        ),
        SimpleNamespace(
            fd=2,
            family=socket.AF_INET,
            type=socket.SOCK_STREAM,
            laddr=SimpleNamespace(ip="192.168.1.10", port=51101),
            raddr=SimpleNamespace(ip="198.51.100.30", port=443),
            status="ESTABLISHED",
            pid=1002,
        ),
    ]
    monkeypatch.setattr(psutil, "net_connections", lambda kind="inet": fake_conns)

    clash_calls = {"count": 0}

    class _FakeClash:
        def get_connections_sync(self) -> dict[str, Any]:
            clash_calls["count"] += 1
            return {
                "connections": [
                    # Already seen from psutil (chrome.exe, 198.51.100.30, 443, tls) -> must NOT duplicate
                    {
                        "metadata": {
                            "network": "tcp",
                            "destinationIP": "198.51.100.30",
                            "destinationPort": "443",
                            "host": "healthy-unknown.example",
                            "processPath": r"C:\Program Files\Chrome\chrome.exe",
                        },
                        "upload": 200,
                        "download": 4096,
                    },
                    # Stalled Clash flow (upload > 0, download == 0) not in psutil -> synthesized + needs_fix
                    {
                        "metadata": {
                            "network": "tcp",
                            "destinationIP": "198.51.100.31",
                            "destinationPort": "443",
                            "host": "stalled-direct.example",
                            "processPath": r"C:\Apps\myapp.exe",
                        },
                        "upload": 517,
                        "download": 0,
                    },
                    # Empty processPath falls back to "sing-box"; UDP:443 -> "quic"; known discord.com -> protected
                    {
                        "metadata": {
                            "network": "udp",
                            "destinationIP": "198.51.100.32",
                            "destinationPort": 443,
                            "sniffHost": "discord.com",
                            "processPath": "",
                        },
                        "upload": 1024,
                        "download": 8192,
                    },
                    # Internal proxy binary must be skipped
                    {
                        "metadata": {
                            "network": "tcp",
                            "destinationIP": "198.51.100.33",
                            "destinationPort": 443,
                            "host": "skip-proxy.example",
                            "processPath": r"C:\netdoctor\bin\winws2.exe",
                        },
                        "upload": 100,
                        "download": 0,
                    },
                ]
            }

    mon = RealtimeConnectionMonitor()
    monkeypatch.setattr(mon, "_resolve_pid_name", lambda pid: "chrome.exe")

    st = Storage(db_path)
    try:
        rows = mon.scan_active_connections(
            st,
            logs_dir,
            net_key=net_key,
            targets_file=tmp_path / "no_targets.yaml",
            clash_client=_FakeClash(),  # type: ignore[arg-type]
        )
    finally:
        st.close()

    # Clash API fetched exactly once per scan
    assert clash_calls["count"] == 1
    assert all(r["domain"] != "skip-proxy.example" for r in rows)

    by_dom = {r["domain"]: r for r in rows}
    assert len([r for r in rows if r["domain"] == "healthy-unknown.example"]) == 1

    # (b) sing-box.log i/o timeout flips github.com (even active direct) to needs_fix
    assert by_dom["github.com"]["health"] == "needs_fix"
    # (a) Clash stalled upload>0, download==0 row synthesized & marked needs_fix
    assert by_dom["stalled-direct.example"]["process"] == "myapp.exe"
    assert by_dom["stalled-direct.example"]["socket_status"] == "STALLED"
    assert by_dom["stalled-direct.example"]["health"] == "needs_fix"
    # (a) Empty processPath fallback to sing-box + UDP:443 -> quic + protected by discord.com DPI rule
    assert by_dom["discord.com"]["process"] == "sing-box"
    assert by_dom["discord.com"]["protocol"] == "quic"
    assert by_dom["discord.com"]["health"] == "protected"
    # (c) Healthy ESTABLISHED unknown domain outside targets.yaml with bidirectional Clash traffic stays direct (not disrupted!)
    assert by_dom["healthy-unknown.example"]["health"] == "direct"
    assert by_dom["healthy-unknown.example"]["active_healthy"] is True

    # Now verify auto-heal leaves healthy ESTABLISHED unknown domain alone and only probes/heals failing domain
    heal_db = tmp_path / "unknown_heal.db"
    heal_logs = tmp_path / "heal_logs"
    heal_logs.mkdir(parents=True, exist_ok=True)
    heal_nk = _seed_db(heal_db)
    (heal_logs / "sing-box.log").write_text(
        "INFO outbound connected to ok-outside.example:203.0.113.80\n"
        "INFO outbound connected to blocked-outside.example:203.0.113.81\n",
        encoding="utf-8",
    )
    heal_conns = [
        SimpleNamespace(
            fd=11,
            family=socket.AF_INET,
            type=socket.SOCK_STREAM,
            laddr=SimpleNamespace(ip="192.168.1.10", port=52001),
            raddr=SimpleNamespace(ip="203.0.113.80", port=443),
            status="ESTABLISHED",
            pid=3001,
        ),
        SimpleNamespace(
            fd=12,
            family=socket.AF_INET,
            type=socket.SOCK_STREAM,
            laddr=SimpleNamespace(ip="192.168.1.10", port=52002),
            raddr=SimpleNamespace(ip="203.0.113.81", port=443),
            status="SYN_SENT",
            pid=3002,
        ),
    ]
    monkeypatch.setattr(psutil, "net_connections", lambda kind="inet": heal_conns)
    monkeypatch.setattr(orch_mod, "detect_bypass_active", lambda: False)
    monkeypatch.setattr(orch_mod, "_is_admin", lambda: False)

    async def fake_net(timeout: float = 2.0) -> NetworkFingerprint:
        return NetworkFingerprint(asn=12389, kind=NetworkKind.HOME, isp="TestISP")

    probed_domains: list[str] = []

    async def fake_probes(domain: str, timeout: float = 2.0) -> ProbesSummary:
        probed_domains.append(domain)
        if domain == "ok-outside.example":
            return ProbesSummary(
                dns=DnsProbeResult(system="ok", doh="ok", doh_ips=["203.0.113.80"]),
                tcp=TcpProbeResult(result="ok", rtt_ms=15.0, target_ip="203.0.113.80"),
                tls=TlsProbeResult(real_sni="ok", neutral_sni="ok", ttfb_ms=22.0),
                stall=StallProbeResult(result="ok", bytes_read=4096, throughput_kbps=4000.0),
                quic=QuicProbeResult(result="ok"),
            )
        return ProbesSummary(
            dns=DnsProbeResult(system="ok", doh="ok", doh_ips=["203.0.113.81"]),
            tcp=TcpProbeResult(result="ok", rtt_ms=18.0, target_ip="203.0.113.81"),
            tls=TlsProbeResult(real_sni="reset", neutral_sni="ok", ttfb_ms=40.0),
            stall=StallProbeResult(result="ok", bytes_read=4096, throughput_kbps=2500.0),
            quic=QuicProbeResult(result="ok"),
        )

    monkeypatch.setattr(orch_mod, "detect_network_fingerprint", fake_net)
    monkeypatch.setattr(orch_mod, "run_domain_probes", fake_probes)

    heal_backend = GuiBackend(
        db_path=heal_db,
        configs_dir=tmp_path / "heal_configs",
        lists_dir=tmp_path / "heal_lists",
        logs_dir=heal_logs,
        bin_dir=tmp_path / "bin",
    )
    monkeypatch.setattr(heal_backend.orchestrator.monitor, "_resolve_pid_name", lambda pid: "browser.exe")

    res1 = asyncio.run(heal_backend.orchestrator.monitor.auto_heal_connections(heal_backend, max_domains_per_tick=5))
    assert set(probed_domains) == {"blocked-outside.example"}
    healed_by_dom = {h["domain"]: h for h in res1["healed"]}
    assert healed_by_dom["blocked-outside.example"]["layer"] == "dpi"

    res1_conns = {c["domain"]: c for c in res1["connections"]}
    assert res1_conns["ok-outside.example"]["health"] == "direct"
    assert res1_conns["blocked-outside.example"]["layer"] == "dpi"

    # Once the healed socket connects cleanly (ESTABLISHED), it shows as protected and tick 2 does NOT re-probe
    heal_conns[1].status = "ESTABLISHED"
    heal_backend.orchestrator.monitor.cooldown_until.clear()
    probed_domains.clear()
    res2 = asyncio.run(heal_backend.orchestrator.monitor.auto_heal_connections(heal_backend, max_domains_per_tick=5))
    assert res2["healed"] == []
    assert probed_domains == []
    res2_conns = {c["domain"]: c for c in res2["connections"]}
    assert res2_conns["blocked-outside.example"]["health"] == "protected"


def test_comss_dns_ip_ai_preset_and_singbox_doh_sni_resolution() -> None:
    from netdoctor.config_gen import generate_singbox_config
    from netdoctor.orchestrators import SERVICE_PRESETS

    comss = next(s for s in BUILTIN_DNS_CATALOG if s["id"] == "comss_dns")
    assert comss["ip"] == "141.133.184.24"
    assert comss["doh_url"] == "https://dns.comss.one/dns-query"
    assert SERVICE_PRESETS["ai"]["recommended_dns"] == "comss_dns"

    # Both primary doh_server (IP or domain) and per_dns_domains set tls.server_name + catalog IP
    decs = [
        Decision(
            network_key="AS12389:home:default",
            domain="chatgpt.com",
            protocol=Protocol.TLS,
            layer="dns",
            strategy_id="dns:comss_dns",
        )
    ]
    cfg_by_ip = generate_singbox_config(
        decisions=decs,
        doh_server="141.133.184.24",
        dns_type="https",
        doh_path="/dns-query",
    )
    servers_ip = {s["tag"]: s for s in cfg_by_ip["dns"]["servers"]}
    assert servers_ip["dns-doh"]["server"] == "141.133.184.24"
    assert servers_ip["dns-doh"]["tls"] == {"enabled": True, "server_name": "dns.comss.one"}
    assert servers_ip["dns-comss_dns"]["server"] == "141.133.184.24"
    assert servers_ip["dns-comss_dns"]["tls"] == {"enabled": True, "server_name": "dns.comss.one"}

    cfg_by_host = generate_singbox_config(
        decisions=[],
        doh_server="https://dns.comss.one/dns-query",
        dns_type="https",
    )
    primary = cfg_by_host["dns"]["servers"][0]
    assert primary["server"] == "141.133.184.24"
    assert primary["tls"] == {"enabled": True, "server_name": "dns.comss.one"}


def test_singbox_doh_sni_edge_cases() -> None:
    from netdoctor.config_gen import generate_singbox_config

    # Domain-based doh_url always preserves tls.server_name and custom port even when extra_dns_servers_sni=False
    cfg_url = generate_singbox_config(
        decisions=[],
        doh_server="https://dns.comss.one:8443/dns-query",
        dns_type="https",
        extra_dns_servers_sni=False,
    )
    primary = cfg_url["dns"]["servers"][0]
    assert primary["server"] == "141.133.184.24"
    assert primary["server_port"] == 8443
    assert primary["tls"] == {"enabled": True, "server_name": "dns.comss.one"}

    # per_dns_domains entry with empty IP resolves via catalog_map and preserves tls.server_name
    custom_catalog = {
        "comss_dns": {
            "id": "comss_dns",
            "ip": "141.133.184.24",
            "doh_url": "https://dns.comss.one/dns-query",
            "badges": ["DoH"],
        },
        "custom_comss": {
            "id": "custom_comss",
            "ip": "",
            "doh_url": "https://dns.comss.one/dns-query",
            "badges": ["DoH"],
        },
    }
    decs = [
        Decision(
            network_key="AS12389:home:default",
            domain="chatgpt.com",
            protocol=Protocol.TLS,
            layer="dns",
            strategy_id="dns:custom_comss",
        )
    ]
    cfg_custom = generate_singbox_config(
        decisions=decs,
        dns_catalog=custom_catalog,
        extra_dns_servers_sni=False,
    )
    servers = {s["tag"]: s for s in cfg_custom["dns"]["servers"]}
    assert servers["dns-custom_comss"]["server"] == "141.133.184.24"
    assert servers["dns-custom_comss"]["tls"] == {"enabled": True, "server_name": "dns.comss.one"}


def test_auto_heal_self_probe_guard_and_singbox_log_edge_cases(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from netdoctor.orchestrators import _parse_singbox_failed_ips

    # 1. _parse_singbox_failed_ips handles ANSI escapes, dial tcp4, ->ip:port, forcibly closed, and domain errors
    raw_log = (
        "\x1b[31mERROR\x1b[0m connection: open connection to example.com:443 "
        "using outbound/direct[direct]: dial tcp4 203.0.113.41:443: i/o timeout\n"
        "ERROR connection: open connection to foo.example:443: read tcp 172.19.0.1:50000->203.0.113.42:443: "
        "wsarecv: An existing connection was forcibly closed by the remote host.\n"
        "ERROR connection: open connection to 127.0.0.1:443: connection refused\n"
    )
    parsed_ips = _parse_singbox_failed_ips(raw_log)
    assert parsed_ips == {"203.0.113.41", "203.0.113.42"}

    # 2. Self-probe protection preserves active dpi decision when bypass=True and probes succeed
    db_path = tmp_path / "self_probe_heal.db"
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    net_key = _seed_db(db_path)

    (logs_dir / "sing-box.log").write_text(
        "ERROR connection: open connection to 162.159.135.232:443 using outbound/direct[direct]: "
        "dial tcp 162.159.135.232:443: i/o timeout\n"
        "INFO outbound connected to discord.com:162.159.135.232\n",
        encoding="utf-8",
    )
    fake_conns = [
        SimpleNamespace(
            fd=1,
            family=socket.AF_INET,
            type=socket.SOCK_STREAM,
            laddr=SimpleNamespace(ip="192.168.1.10", port=53001),
            raddr=SimpleNamespace(ip="162.159.135.232", port=443),
            status="ESTABLISHED",
            pid=4001,
        )
    ]
    monkeypatch.setattr(psutil, "net_connections", lambda kind="inet": fake_conns)
    monkeypatch.setattr(orch_mod, "detect_bypass_active", lambda: True)
    monkeypatch.setattr(orch_mod, "_is_admin", lambda: False)

    async def fake_net(timeout: float = 2.0) -> NetworkFingerprint:
        return NetworkFingerprint(asn=12389, kind=NetworkKind.HOME, isp="TestISP")

    probe_mode = {"ok": True}

    async def fake_probes(domain: str, timeout: float = 2.0) -> ProbesSummary:
        return ProbesSummary(
            dns=DnsProbeResult(system="ok", doh="ok", doh_ips=["162.159.135.232"]),
            tcp=TcpProbeResult(result="ok", rtt_ms=14.0, target_ip="162.159.135.232"),
            tls=TlsProbeResult(real_sni="ok" if probe_mode["ok"] else "reset", neutral_sni="ok", ttfb_ms=20.0),
            stall=StallProbeResult(result="ok", bytes_read=4096, throughput_kbps=3500.0),
            quic=QuicProbeResult(result="ok"),
        )

    monkeypatch.setattr(orch_mod, "detect_network_fingerprint", fake_net)
    monkeypatch.setattr(orch_mod, "run_domain_probes", fake_probes)

    backend = GuiBackend(
        db_path=db_path,
        configs_dir=tmp_path / "configs",
        lists_dir=tmp_path / "lists",
        logs_dir=logs_dir,
        bin_dir=tmp_path / "bin",
    )
    monkeypatch.setattr(backend.orchestrator.monitor, "_resolve_pid_name", lambda pid: "Discord.exe")

    res_ok = asyncio.run(backend.orchestrator.monitor.auto_heal_connections(backend, max_domains_per_tick=2))
    assert res_ok["healed"] == []
    st = Storage(db_path)
    try:
        dec = next(d for d in st.get_decisions(net_key) if d.domain == "discord.com")
        assert dec.layer == "dpi"
        assert dec.strategy_id == "tls_hostfakesplit_ozon"
    finally:
        st.close()

    # 3. When bypass=True and probe genuinely fails despite active DPI rule, fallback is promoted
    backend.orchestrator.monitor.cooldown_until.clear()
    probe_mode["ok"] = False
    res_fb = asyncio.run(backend.orchestrator.monitor.auto_heal_connections(backend, max_domains_per_tick=2))
    assert len(res_fb["healed"]) == 1
    assert res_fb["healed"][0]["strategy_id"] == "tls_multisplit_pos2"
    st = Storage(db_path)
    try:
        dec = next(d for d in st.get_decisions(net_key) if d.domain == "discord.com")
        assert dec.layer == "dpi"
        assert dec.strategy_id == "tls_multisplit_pos2"
    finally:
        st.close()


def test_realtime_ip_map_ignores_shared_cdn_and_stub_verdict_ips(tmp_path: Path) -> None:
    db_path = tmp_path / "cdn_ip_map.db"
    _seed_db(db_path)
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    st = Storage(db_path)
    try:
        net = NetworkFingerprint(asn=12389, kind=NetworkKind.HOME)
        net_key = st.upsert_network(net)

        def _save(domain: str, doh_ips: list[str], sys_ips: list[str], target_ip: str, sys_status: str = "ok") -> None:
            probes = ProbesSummary(
                dns=DnsProbeResult(system=sys_status, doh="ok", system_ips=sys_ips, doh_ips=doh_ips),
                tcp=TcpProbeResult(result="ok", target_ip=target_ip),
                tls=TlsProbeResult(real_sni="ok", neutral_sni="ok"),
                stall=StallProbeResult(result="ok"),
                quic=QuicProbeResult(result="timeout"),
            )
            st.save_verdict(net_key, classify_probes(domain, probes, net), protocol=Protocol.TLS)

        # Shared Cloudflare IPs + ISP stub IP (143.20.64.55) from historical rutracker verdict
        _save("rutracker.org", ["104.21.32.39", "172.67.182.196"], ["143.20.64.55"], "172.67.182.196")
        # Ambiguous non-CDN IP shared across 2 distinct domains
        _save("alpha.example", ["203.0.113.10"], ["203.0.113.10"], "203.0.113.10")
        _save("beta.example", ["203.0.113.10"], ["203.0.113.10"], "203.0.113.10")
        # Unique dedicated non-CDN IP
        _save("unique.example", ["203.0.113.55"], ["203.0.113.55"], "203.0.113.55")

        mon = RealtimeConnectionMonitor()

        class _LiveClash:
            def __init__(self, active: bool) -> None:
                self.active = active

            def get_connections_sync(self) -> dict[str, Any]:
                if not self.active:
                    return {"connections": []}
                return {
                    "connections": [
                        {"metadata": {"host": "example.com", "destinationIP": "104.21.32.39"}},
                    ]
                }

        # Tick 1: Live Clash attributes 104.21.32.39 -> example.com; stub & ambiguous IPs ignored; unique IP kept
        mon.update_ip_map_from_storage_and_logs(st, logs_dir, clash_client=_LiveClash(True))  # type: ignore[arg-type]
        assert "172.67.182.196" not in mon.ip_to_domain
        assert "143.20.64.55" not in mon.ip_to_domain
        assert "203.0.113.10" not in mon.ip_to_domain
        assert mon.ip_to_domain["203.0.113.55"] == "unique.example"
        assert mon.ip_to_domain["104.21.32.39"] == "example.com"

        # Tick 2: Once Clash flow disappears, shared CDN IP is purged and never falls back to rutracker.org
        mon.update_ip_map_from_storage_and_logs(st, logs_dir, clash_client=_LiveClash(False))  # type: ignore[arg-type]
        assert "104.21.32.39" not in mon.ip_to_domain
        assert mon.ip_to_domain["203.0.113.55"] == "unique.example"
    finally:
        st.close()


def test_auto_heal_no_vpn_uses_smart_dns_for_login_live(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Without VPN, IP-blocked Microsoft/Xbox auth (login.live.com) uses SmartDNS and rotates DNS fallbacks."""
    import netdoctor.orchestrators as orch_mod
    from netdoctor.models import (
        DnsProbeResult,
        NetworkFingerprint,
        NetworkKind,
        ProbesSummary,
        QuicProbeResult,
        StallProbeResult,
        TcpProbeResult,
        TlsProbeResult,
    )

    assert orch_mod.is_geoblock_or_ai_domain("login.live.com")
    assert orch_mod.is_geoblock_or_ai_domain("xsts.auth.xboxlive.com")

    db_path = tmp_path / "live_dns.db"
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    backend = GuiBackend(
        db_path=db_path,
        configs_dir=tmp_path / "configs",
        lists_dir=tmp_path / "lists",
        logs_dir=logs_dir,
        bin_dir=tmp_path / "bin",
    )
    net = NetworkFingerprint(asn=12389, kind=NetworkKind.HOME, isp="TestISP")

    monkeypatch.setattr(orch_mod, "detect_bypass_active", lambda: True)
    monkeypatch.setattr(orch_mod, "_is_admin", lambda: True)

    async def fake_net(timeout: float = 2.0) -> NetworkFingerprint:
        return net

    async def fake_probes(domain: str, timeout: float = 2.0) -> ProbesSummary:
        return ProbesSummary(
            dns=DnsProbeResult(system="ok", doh="ok", doh_ips=["20.190.159.130"]),
            tcp=TcpProbeResult(result="timeout", target_ip="20.190.159.130"),
            tls=TlsProbeResult(real_sni="timeout", neutral_sni="timeout"),
            stall=StallProbeResult(result="skipped"),
            quic=QuicProbeResult(result="timeout"),
        )

    async def fake_roll_dns(
        self: Any,
        domain: str,
        network_key: str,
        storage: Any = None,
        timeout: float = 1.8,
    ) -> Decision:
        return Decision(
            network_key=network_key,
            domain=domain,
            protocol=Protocol.TLS,
            layer="dns",
            strategy_id="dns:xbox_dns",
            fallback_strategies=["dns:comss_dns"],
        )

    monkeypatch.setattr(orch_mod, "detect_network_fingerprint", fake_net)
    monkeypatch.setattr(orch_mod, "run_domain_probes", fake_probes)
    monkeypatch.setattr(orch_mod.DnsLayerOrchestrator, "roll_dns_for_domain", fake_roll_dns)
    monkeypatch.setattr(
        backend.orchestrator.monitor,
        "scan_active_connections",
        lambda *a, **kw: [
            {
                "process": "prismlauncher.exe",
                "domain": "login.live.com",
                "layer": "direct",
                "health": "needs_fix",
                "socket_status": "SYN_SENT",
                "active_healthy": False,
            }
        ],
    )
    monkeypatch.setattr(backend, "_collect_processes_state", lambda: {"winws2": {"running": True}, "sing-box": {"running": True}})
    monkeypatch.setattr(backend, "reload_winws2_if_changed", lambda **kw: {"ok": True, "reloaded": False})
    monkeypatch.setattr(backend, "reload_singbox_if_changed", lambda **kw: {"ok": True, "reloaded": True})

    # Tick 1: assigns SmartDNS instead of useless DPI for IP-blocked login.live.com without VPN
    res1 = asyncio.run(backend.orchestrator.monitor.auto_heal_connections(backend, max_domains_per_tick=2))
    assert res1["healed"] and res1["healed"][0]["layer"] == "dns"
    assert res1["healed"][0]["strategy_id"] == "dns:xbox_dns"

    # Tick 2 (after cooldown expires): promotes DNS fallback instead of wiping DNS rule back to DPI
    backend.orchestrator.monitor.cooldown_until.clear()
    res2 = asyncio.run(backend.orchestrator.monitor.auto_heal_connections(backend, max_domains_per_tick=2))
    assert res2["healed"] and res2["healed"][0]["layer"] == "dns"
    assert res2["healed"][0]["strategy_id"] == "dns:comss_dns"


def test_run_diag_sync_rotates_fallback_when_bypass_active_and_dpi_still_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pressing 'Подбор DPI' while bypass is active must advance to fallback instead of re-saving broken pool[0]."""
    import netdoctor.gui_backend as gb_mod
    from netdoctor.models import (
        DnsProbeResult,
        NetworkFingerprint,
        NetworkKind,
        ProbesSummary,
        QuicProbeResult,
        StallProbeResult,
        TcpProbeResult,
        TlsProbeResult,
    )

    db_path = tmp_path / "diag_rotate.db"
    backend = GuiBackend(
        db_path=db_path,
        configs_dir=tmp_path / "configs",
        lists_dir=tmp_path / "lists",
        logs_dir=tmp_path / "logs",
        bin_dir=tmp_path / "bin",
    )
    net = NetworkFingerprint(asn=12389, kind=NetworkKind.HOME, isp="TestISP")
    st = Storage(db_path)
    try:
        nk = st.upsert_network(net)
        st.upsert_strategies(DEFAULT_STRATEGIES)
        st.save_decision(
            Decision(
                network_key=nk,
                domain="login.live.com",
                protocol=Protocol.TLS,
                layer="dpi",
                strategy_id="tls_alt1_199_fake_fakedsplit",
                fallback_strategies=["tls_alt12_1104_sferum_seqovl", "tls_alt13_1104_sochi_hostfakesplit"],
            )
        )
    finally:
        st.close()

    async def fake_net(timeout: float = 2.5) -> NetworkFingerprint:
        return net

    async def fake_probes(domain: str, timeout: float = 2.5) -> ProbesSummary:
        return ProbesSummary(
            dns=DnsProbeResult(system="ok", doh="ok", doh_ips=["20.190.147.10"]),
            tcp=TcpProbeResult(result="ok", rtt_ms=1085.2, target_ip="20.190.147.10"),
            tls=TlsProbeResult(real_sni="timeout", neutral_sni="ok"),
            stall=StallProbeResult(result="skipped"),
            quic=QuicProbeResult(result="timeout"),
        )

    monkeypatch.setattr(gb_mod, "detect_bypass_active", lambda: True)
    monkeypatch.setattr(gb_mod, "detect_network_fingerprint", fake_net)
    monkeypatch.setattr(gb_mod, "run_domain_probes", fake_probes)
    monkeypatch.setattr(backend, "trigger_apply_configs", lambda iface=None: {})
    monkeypatch.setattr(backend, "_reload_running_services", lambda **kw: None)

    rows = backend.run_diag_sync(["login.live.com"])
    tls_row = next(r for r in rows if r["domain"] == "login.live.com" and r["protocol"] == "tls")
    assert tls_row["strategy_id"] == "tls_alt12_1104_sferum_seqovl"
    assert tls_row["consecutive_fails"] == 1


def test_roll_dns_rejects_tcp_ok_tls_blocked_and_excludes_dns_from_catchall(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SmartDNS roll must reject DNS servers returning TCP-ok/TLS-blocked IPs (like xbox_dns -> Azure)
    and winws2 catch-all must exclude layer='dns' domains."""
    import dns.asyncresolver
    import netdoctor.orchestrators as orch_mod
    from netdoctor.config_gen import generate_winws2_config
    from netdoctor.models import DnsProbeResult, TcpProbeResult

    async def fake_probe_dns(domain: str, doh_url: str = "https://1.1.1.1/dns-query", timeout: float = 3.0, **_kw: Any) -> DnsProbeResult:
        if "comss.one" in doh_url:
            return DnsProbeResult(system="ok", doh="ok", system_ips=["20.190.159.10"], doh_ips=["176.12.72.184"])
        if "176.99.11.77" in doh_url:
            return DnsProbeResult(system="ok", doh="timeout", system_ips=["20.190.159.10"], doh_ips=[])
        return DnsProbeResult(system="ok", doh="timeout", system_ips=["20.190.159.10"], doh_ips=[])

    async def fake_udp_resolve(self: Any, qname: str, rdtype: str = "A") -> list[Any]:
        class _Ans:
            def __init__(self, addr: str) -> None:
                self.address = addr

        ns = getattr(self, "nameservers", []) or []
        if "176.99.11.77" in ns:
            return [_Ans("40.126.53.10")]
        if "141.133.184.24" in ns:
            return [_Ans("176.12.72.184")]
        raise TimeoutError("no udp")

    async def fake_probe_tcp(ip: str, port: int = 443, timeout: float = 1.8) -> TcpProbeResult:
        return TcpProbeResult(result="ok", rtt_ms=25.0, target_ip=ip)

    async def fake_tls(ip: str, port: int, sni: str, verify: bool = False, timeout: float = 2.0) -> tuple[str, float | None]:
        if ip == "176.12.72.184":
            return "ok", 200.0
        return "reset", None

    monkeypatch.setattr(orch_mod, "probe_dns", fake_probe_dns)
    monkeypatch.setattr(orch_mod, "probe_tcp", fake_probe_tcp)
    monkeypatch.setattr(orch_mod, "_single_tls_handshake", fake_tls)
    monkeypatch.setattr(dns.asyncresolver.Resolver, "resolve", fake_udp_resolve)

    orch = DnsLayerOrchestrator()
    dec = asyncio.run(orch.roll_dns_for_domain("login.live.com", "AS12389:home:default"))
    assert dec.layer == "dns"
    assert dec.strategy_id == "dns:comss_dns"

    lists_dir = tmp_path / "lists"
    args, _ = generate_winws2_config(
        decisions=[dec],
        strategies={s.id: s for s in DEFAULT_STRATEGIES},
        lists_dir=lists_dir,
    )
    excl_file = lists_dir / "exclude_unlocker_domains.txt"
    assert excl_file.is_file()
    assert "login.live.com" in excl_file.read_text(encoding="utf-8").splitlines()
    assert f"--hostlist-exclude={excl_file.as_posix()}" in args


def test_apply_configs_persists_vpn_to_dpi_when_no_vpn(tmp_path: Path) -> None:
    """In dpi_only / no-VPN mode, non-pinned VPN rules in DB are persisted to DPI while pinned VPN rules stay intact."""
    from netdoctor.models import NetworkFingerprint, NetworkKind

    db_path = tmp_path / "no_vpn_persist.db"
    backend = GuiBackend(
        db_path=db_path,
        configs_dir=tmp_path / "configs",
        lists_dir=tmp_path / "lists",
        logs_dir=tmp_path / "logs",
        bin_dir=tmp_path / "bin",
    )
    net = NetworkFingerprint(asn=12389, kind=NetworkKind.HOME, isp="TestISP")
    st = Storage(db_path)
    try:
        nk = st.upsert_network(net)
        st.set_setting("stack_mode", "dpi_only")
        st.upsert_strategies(DEFAULT_STRATEGIES)
        st.save_decision(
            Decision(
                network_key=nk,
                domain="instagram.com",
                protocol=Protocol.TLS,
                layer="vpn",
                strategy_id="vpn-select",
            )
        )
        st.save_decision(
            Decision(
                network_key=nk,
                domain="pinned.example",
                protocol=Protocol.TLS,
                layer="vpn",
                strategy_id="vpn-select",
                pinned=True,
            )
        )
    finally:
        st.close()

    backend.trigger_apply_configs()

    st2 = Storage(db_path)
    try:
        saved = {(d.domain, d.protocol): d for d in st2.get_decisions(nk, active_only=True)}
        insta = saved[("instagram.com", Protocol.TLS)]
        assert insta.layer == "dpi"
        assert insta.strategy_id
        pinned = saved[("pinned.example", Protocol.TLS)]
        assert pinned.layer == "vpn"
    finally:
        st2.close()


def test_singbox_dns_log_discovery_and_short_lived_failure_healing(tmp_path: Path) -> None:
    """sing-box DNS A/CNAME log lines populate ip_to_domain and short-lived connection resets trigger healing."""
    (tmp_path / "sing-box.log").write_text(
        "\n".join(
            [
                "+0300 2026-11-24 18:45:25 INFO [3260571114 8ms] dns: exchanged CNAME login.live.com. 300 IN CNAME ms-pool.comss.one.",
                "+0300 2026-11-24 18:45:25 INFO [3260571114 8ms] dns: exchanged A ms-pool.comss.one. 300 IN A 176.12.72.184",
                "+0300 2026-11-24 18:45:30 INFO [1001 12ms] dns: exchanged A api.minecraftservices.com. 300 IN A 20.190.159.10",
                "+0300 2026-11-24 18:45:31 INFO [1002 10ms] dns: exchanged A normal.example.com. 300 IN A 203.0.113.44",
                "+0300 2026-11-24 18:45:34 ERROR [1003 55ms] connection: connection download closed: close tcp 172.19.0.1:50001->20.190.159.10:443: read tcp: connection reset by peer",
                "+0300 2026-11-24 18:45:35 ERROR [1004 80ms] connection: connection download closed: close tcp 172.19.0.1:50002->203.0.113.44:443: endpoint not connected",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    st = Storage(tmp_path / "sb_disc.db")
    try:
        mon = RealtimeConnectionMonitor()
        mon.update_ip_map_from_storage_and_logs(st, tmp_path)
        assert mon.ip_to_domain["176.12.72.184"] == "login.live.com"
        assert mon.ip_to_domain["20.190.159.10"] == "api.minecraftservices.com"

        cands = mon._collect_fix_candidates([], tmp_path, max_domains=3)
        assert [c[0] for c in cands] == ["api.minecraftservices.com"]
    finally:
        st.close()


def test_scan_active_connections_ignores_self_probes_fin_wait_and_quic_stalls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Live-Radar must exclude Netdoctor's own probe sockets, FIN_WAIT2 sockets, and QUIC UDP/443 no-reply."""
    import os
    import socket as sock_mod
    import sys
    from types import SimpleNamespace
    from netdoctor.models import NetworkFingerprint, NetworkKind

    fake_conns = [
        SimpleNamespace(
            fd=1,
            family=sock_mod.AF_INET,
            type=sock_mod.SOCK_STREAM,
            laddr=SimpleNamespace(ip="192.168.1.10", port=51001),
            raddr=SimpleNamespace(ip="203.0.113.10", port=443),
            status="ESTABLISHED",
            pid=os.getpid(),
        ),
        SimpleNamespace(
            fd=2,
            family=sock_mod.AF_INET,
            type=sock_mod.SOCK_STREAM,
            laddr=SimpleNamespace(ip="192.168.1.10", port=51002),
            raddr=SimpleNamespace(ip="203.0.113.11", port=443),
            status="FIN_WAIT2",
            pid=99999,
        ),
        SimpleNamespace(
            fd=3,
            family=sock_mod.AF_INET,
            type=sock_mod.SOCK_STREAM,
            laddr=SimpleNamespace(ip="192.168.1.10", port=51003),
            raddr=SimpleNamespace(ip="13.107.137.11", port=443),
            status="ESTABLISHED",
            pid=88888,
        ),
    ]
    monkeypatch.setattr(psutil, "net_connections", lambda kind="inet": fake_conns)

    class _MockClash:
        def get_connections_sync(self) -> dict[str, Any]:
            return {
                "connections": [
                    {
                        "id": "self-flow",
                        "upload": 200,
                        "download": 0,
                        "start": "2026-11-24T19:00:00Z",
                        "metadata": {
                            "processPath": sys.executable,
                            "destinationIP": "203.0.113.20",
                            "destinationPort": "443",
                            "network": "tcp",
                            "host": "self-probe.example",
                        },
                    },
                    {
                        "id": "quic-noreply",
                        "upload": 1200,
                        "download": 0,
                        "start": "2026-11-24T19:00:00Z",
                        "metadata": {
                            "processPath": r"C:\Users\Test\OneDrive.exe",
                            "destinationIP": "13.107.137.11",
                            "destinationPort": "443",
                            "network": "udp",
                            "host": "sharepoint.example",
                        },
                    },
                ]
            }

    st = Storage(tmp_path / "radar_filter.db")
    try:
        nk = st.upsert_network(NetworkFingerprint(asn=12389, kind=NetworkKind.HOME, isp="TestISP"))
        mon = RealtimeConnectionMonitor()
        monkeypatch.setattr(mon, "_resolve_pid_name", lambda pid: "OneDrive.exe" if pid == 88888 else "other.exe")

        rows = mon.scan_active_connections(st, tmp_path, net_key=nk, clash_client=_MockClash())  # type: ignore[arg-type]
        assert all(r["pid"] != os.getpid() for r in rows)
        assert all(r["domain"] != "self-probe.example" for r in rows)
        assert all(r["socket_status"] != "FIN_WAIT2" for r in rows)
        assert all(r["socket_status"] != "STALLED" for r in rows)
        onedrive_tls = next(r for r in rows if r["process"] == "OneDrive.exe" and r["protocol"] == "tls")
        assert onedrive_tls["health"] != "needs_fix"
    finally:
        st.close()


def test_singbox_dns_cname_underscore_and_tls_unrecognized_name_alert(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CNAME chains with underscores map to original domain and TLS alerts fail real_sni while passing neutral_sni."""
    import ssl
    import netdoctor.orchestrators as orch_mod
    import netdoctor.probes as probes_mod

    sb_log = "\n".join(
        [
            "+0300 2026-11-24 22:41:19 INFO [1048385708 6ms] dns: exchanged CNAME account.ubisoft.com. 8182 IN CNAME account.ubisoft.akadns.net.",
            "+0300 2026-11-24 22:41:19 INFO [1048385708 6ms] dns: exchanged CNAME account.ubisoft.akadns.net. 8182 IN CNAME lb-prod-acc_ount-pdc.ubisoft.com.",
            "+0300 2026-11-24 22:41:19 INFO [1048385708 6ms] dns: exchanged A lb-prod-acc_ount-pdc.ubisoft.com. 8182 IN A 130.254.91.66",
        ]
    )
    parsed = orch_mod._parse_singbox_dns_ip_map(sb_log)
    assert parsed["130.254.91.66"] == "account.ubisoft.com"

    async def fake_open_conn(*_args: Any, **_kwargs: Any) -> tuple[Any, Any]:
        raise ssl.SSLError("[SSL: TLSV1_ALERT_UNRECOGNIZED_NAME] tlsv1 alert unrecognized name")

    monkeypatch.setattr(asyncio, "open_connection", fake_open_conn)
    tls_res = asyncio.run(probes_mod.probe_tls("130.254.91.66", real_sni="account.ubisoft.com"))
    assert tls_res.real_sni == "reset"
    assert tls_res.neutral_sni == "ok"


def test_diverse_fallbacks_pick_different_families(tmp_path: Path) -> None:
    """Fallbacks must span distinct strategy families, and winws2 catch-all must put non-fake splits first."""
    from netdoctor.config_gen import generate_winws2_config
    from netdoctor.models import Strategy, VerdictClass
    from netdoctor.selector import select_best_strategy

    cands = [
        Strategy(id="fake_1", family="fake_fakedsplit", protocol=Protocol.TLS, tier=2, args_template=["--lua-desync=fake:blob=x"]),
        Strategy(id="fake_2", family="fake_fakedsplit", protocol=Protocol.TLS, tier=2, args_template=["--lua-desync=fake:blob=y"]),
        Strategy(id="fake_3", family="fake_fakedsplit", protocol=Protocol.TLS, tier=2, args_template=["--lua-desync=fake:blob=z"]),
        Strategy(id="split_1", family="multisplit", protocol=Protocol.TLS, tier=2, args_template=["--lua-desync=multisplit:pos=2"]),
        Strategy(id="disorder_1", family="multidisorder", protocol=Protocol.TLS, tier=2, args_template=["--lua-desync=multidisorder:pos=1,midsld"]),
    ]

    dec = asyncio.run(
        select_best_strategy(
            network_key="AS12389:home:default",
            domain="ubisoft.com",
            ip="130.254.91.66",
            verdicts=[VerdictClass.SNI_DPI],
            candidates=cands,
            evaluator=None,
            early_stop=True,
        )
    )
    assert dec.layer == "dpi"
    strat_map = {s.id: s for s in cands}
    win_family = strat_map[dec.strategy_id].family if dec.strategy_id else ""
    fb_families = [strat_map[sid].family for sid in dec.fallback_strategies]
    assert len(set([win_family, *fb_families])) == 1 + len(dec.fallback_strategies)

    args, _ = generate_winws2_config(
        decisions=[],
        strategies=strat_map,
        lists_dir=tmp_path / "lists",
        enable_circular_catchall=True,
    )
    circ_idx = next(i for i, tok in enumerate(args) if tok.startswith("--lua-desync=circular"))
    first_catchall_strat = args[circ_idx + 1]
    assert "fake" not in first_catchall_strat


def test_find_best_bypass_for_domain_cascade_dpi_dns_vpn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """find_best_bypass_for_domain cascades Direct -> diverse DPI -> SmartDNS -> VPN and stops at first working."""
    from netdoctor.models import NetworkFingerprint, NetworkKind

    db_path = tmp_path / "best_cascade.db"
    backend = GuiBackend(
        db_path=db_path,
        configs_dir=tmp_path / "configs",
        lists_dir=tmp_path / "lists",
        logs_dir=tmp_path / "logs",
        bin_dir=tmp_path / "bin",
    )
    st = Storage(db_path)
    try:
        nk = st.upsert_network(NetworkFingerprint(asn=12389, kind=NetworkKind.HOME, isp="TestISP"))
        st.set_setting("stack_mode", "hybrid")
        st.save_subscription(
            "default",
            "vless://test",
            [
                {
                    "tag": "nl-1",
                    "protocol": "vless",
                    "server": "198.51.100.1",
                    "server_port": 443,
                    "enabled": True,
                    "raw_outbound": {
                        "type": "vless",
                        "tag": "nl-1",
                        "server": "198.51.100.1",
                        "server_port": 443,
                        "uuid": "00000000-0000-0000-0000-000000000001",
                    },
                }
            ],
        )
    finally:
        st.close()

    monkeypatch.setattr(backend, "_collect_processes_state", lambda: {"winws2": {"running": False}, "sing-box": {"running": False}})

    # Scenario 1: direct fails, 1st DPI fails, 2nd DPI (different family) succeeds -> picks 2nd DPI
    calls_1: list[str] = []

    def probe_1(dom: str, *, proxy_url: str | None = None, timeout: float = 3.0) -> dict[str, Any]:
        calls_1.append(proxy_url or "direct_or_dpi")
        if len(calls_1) <= 2:
            return {"ok": False, "error": "reset"}
        return {"ok": True, "latency_ms": 42.0}

    res1 = backend.find_best_bypass_for_domain("site1.example", probe_fn=probe_1)
    assert res1["ok"] is True
    assert res1["winner"]["layer"] == "dpi"
    assert res1["winner"]["latency_ms"] == 42.0
    assert len([t for t in res1["tried"] if t["layer"] == "dpi"]) == 2
    assert all(t["layer"] != "vpn" for t in res1["tried"])

    # Scenario 2: direct + all DPI fail, SmartDNS succeeds -> picks dns
    def probe_2(dom: str, *, proxy_url: str | None = None, timeout: float = 3.0) -> dict[str, Any]:
        # Step C runs after dpi candidates fail
        st_chk = Storage(db_path)
        try:
            cur = next((d for d in st_chk.get_decisions(nk, active_only=False) if d.domain == dom), None)
            if cur is not None and cur.layer == "dns":
                return {"ok": True, "latency_ms": 55.0}
        finally:
            st_chk.close()
        return {"ok": False, "error": "timeout"}

    def fake_dns_roll(dom: str, net_k: str) -> Decision:
        return Decision(network_key=net_k, domain=dom, protocol=Protocol.TLS, layer="dns", strategy_id="dns:comss_dns", ttfb_ms=30.0)

    res2 = backend.find_best_bypass_for_domain("site2.example", probe_fn=probe_2, dns_roll_fn=fake_dns_roll)
    assert res2["ok"] is True
    assert res2["winner"]["layer"] == "dns"
    assert res2["winner"]["strategy_id"] == "dns:comss_dns"

    # Scenario 3: direct + DPI + DNS fail, VPN succeeds -> picks vpn
    def probe_3(dom: str, *, proxy_url: str | None = None, timeout: float = 3.0) -> dict[str, Any]:
        st_chk = Storage(db_path)
        try:
            cur = next((d for d in st_chk.get_decisions(nk, active_only=False) if d.domain == dom), None)
            if cur is not None and cur.layer == "vpn":
                return {"ok": True, "latency_ms": 88.0}
        finally:
            st_chk.close()
        return {"ok": False, "error": "blocked"}

    res3 = backend.find_best_bypass_for_domain("site3.example", probe_fn=probe_3, dns_roll_fn=fake_dns_roll)
    assert res3["ok"] is True
    assert res3["winner"]["layer"] == "vpn"
    assert res3["winner"]["strategy_id"] == "vpn-select"


def test_collect_fix_candidates_prioritizes_new_domains_without_decision(tmp_path: Path) -> None:
    """Brand-new domains without a DB decision must be healed before existing failing domains."""
    mon = RealtimeConnectionMonitor()
    connections = [
        {
            "process": "chrome.exe",
            "domain": "aaa-old.example",
            "layer": "dpi",
            "health": "needs_fix",
            "socket_status": "SYN_SENT",
            "active_healthy": False,
            "has_decision": True,
        },
        {
            "process": "upc.exe",
            "domain": "ubisoft.com",
            "layer": "direct",
            "health": "needs_fix",
            "socket_status": "SYN_SENT",
            "active_healthy": False,
            "has_decision": False,
        },
    ]
    cands = mon._collect_fix_candidates(connections, tmp_path, max_domains=1)
    assert cands == [("ubisoft.com", "upc.exe", "SYN_SENT stall")]


def test_find_best_bypass_tests_clean_direct_excluding_winws2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from netdoctor.models import NetworkFingerprint, NetworkKind

    db_path = tmp_path / "netdoctor.db"
    backend = GuiBackend(
        db_path=db_path,
        configs_dir=tmp_path / "configs",
        lists_dir=tmp_path / "lists",
        logs_dir=tmp_path / "logs",
        bin_dir=tmp_path / "bin",
    )
    storage = Storage(db_path)
    try:
        net_key = storage.upsert_network(
            NetworkFingerprint(asn=12389, kind=NetworkKind.HOME, isp="TestISP")
        )
        storage.save_decision(
            Decision(
                network_key=net_key,
                domain="account.ubisoft.com",
                protocol=Protocol.TLS,
                layer="dpi",
                strategy_id="tls_alt1_199_fake_fakedsplit",
                status="active",
                consecutive_fails=0,
            )
        )
    finally:
        storage.close()

    monkeypatch.setattr(
        backend,
        "_collect_processes_state",
        lambda: {"winws2": {"running": True}, "sing-box": {"running": False}},
    )
    monkeypatch.setattr("netdoctor.gui_backend._is_admin", lambda: True)
    reloaded: list[bool] = []
    monkeypatch.setattr(
        backend,
        "reload_winws2",
        lambda: (reloaded.append(True), {"ok": True})[1],
    )

    reloaded_before_probe: list[int] = []

    def fake_probe(
        _domain: str, *, proxy_url: str | None = None, timeout: float = 3.0
    ) -> dict[str, Any]:
        assert proxy_url is None
        reloaded_before_probe.append(len(reloaded))
        st_check = Storage(db_path)
        try:
            cur = next(
                (
                    d
                    for d in st_check.get_decisions(net_key, active_only=False)
                    if d.domain == "account.ubisoft.com" and d.protocol == Protocol.TLS
                ),
                None,
            )
        finally:
            st_check.close()
        if cur is not None and cur.layer == "direct":
            return {"ok": True, "latency_ms": 35.0}
        return {"ok": False, "error": "reset"}

    res = backend.find_best_bypass_for_domain("account.ubisoft.com", probe_fn=fake_probe)
    assert res["ok"] is True
    assert res["winner"]["layer"] == "direct"
    assert reloaded_before_probe == [1]
    assert all(t["layer"] == "direct" for t in res["tried"])

