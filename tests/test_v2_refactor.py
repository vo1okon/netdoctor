"""Comprehensive v2 refactoring verification suite (Section 9.1)."""

from __future__ import annotations

import json
import sqlite3
import subprocess
import tkinter as tk
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import MagicMock

import psutil
import pytest

from netdoctor.classifier import classify_probes
from netdoctor.config_gen import (
    QUIC_HOSTLIST_DOMAINS,
    build_singbox_rulesets_payload,
    generate_singbox_config,
    generate_winws2_config,
    generate_xray_bridge_config,
)
from netdoctor.core.bundles import compile_bundle_rules, expand_running_bundle_processes, load_bundles
from netdoctor.core.engine import NetdoctorEngine
from netdoctor.core.ruleset_server import RuleSetServer
from netdoctor.gui import NetdoctorGuiApp
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
    VpnNode,
)
from netdoctor.orchestrators import RealtimeConnectionMonitor, _is_shared_cdn_anycast_ip
from netdoctor.selector import DEFAULT_STRATEGIES, _quick_non_dpi_decision
from netdoctor.storage import CURRENT_DB_VERSION, Storage, normalize_domain_etld1


def _has_tk_descendant(widget: tk.Misc, cls: type[tk.Widget]) -> bool:
    for child in widget.winfo_children():
        if isinstance(child, cls) or _has_tk_descendant(child, cls):
            return True
    return False


def test_singbox_v2_config_and_live_ruleset_server_check(tmp_path: Path) -> None:
    bundles = load_bundles(Path("configs/bundles.yaml"))
    compiled = compile_bundle_rules(bundles, {"ubisoft": {"mode": "vpn"}})
    decs = [
        Decision(network_key="AS1:home:default", domain="youtube.com", protocol=Protocol.TLS, layer="dpi", strategy_id="tls_alt1_199_fake_fakedsplit"),
        Decision(network_key="AS1:home:default", domain="instagram.com", protocol=Protocol.TLS, layer="vpn", strategy_id="vpn-select"),
        Decision(network_key="AS1:home:default", domain="chatgpt.com", protocol=Protocol.TLS, layer="dns", strategy_id="dns:xbox_dns"),
    ]
    vpn_nodes = [
        VpnNode(
            tag="vless-fi",
            protocol="vless",
            server="198.51.100.11",
            server_port=443,
            raw_outbound={"type": "vless", "tag": "vless-fi", "server": "198.51.100.11", "server_port": 443},
        )
    ]
    payload = build_singbox_rulesets_payload(
        decs,
        bundle_rules=compiled,
        quic_blocked_domains=list(QUIC_HOSTLIST_DOMAINS),
        vpn_processes=["customgame.exe"],
    )

    srv = RuleSetServer(preferred_port=0)
    base_url = srv.start()
    try:
        srv.update_rulesets(payload)
        out_path = tmp_path / "sing-box.json"
        cfg = generate_singbox_config(
            decs,
            vpn_nodes,
            output_path=out_path,
            ruleset_base_url=base_url,
            bundle_rules=compiled,
            quic_blocked_domains=list(QUIC_HOSTLIST_DOMAINS),
            vpn_processes=["customgame.exe"],
        )

        tun_in = next(ib for ib in cfg["inbounds"] if ib.get("type") == "tun")
        assert tun_in["stack"] == "mixed"
        assert tun_in["mtu"] == 1380
        assert cfg["dns"]["final"] == "dns-local"

        ob_tags = {ob.get("tag") for ob in cfg["outbounds"]}
        assert "tg-ws-out" not in ob_tags

        rules = cfg["route"]["rules"]
        # Ensure no blanket 1024:65535 GAME_BYPASS_PORTS rule exists
        assert not any("1024:65535" in str(r.get("port_range") or "") for r in rules)

        # proc_bypass_rule must precede sniff and hijack-dns
        idx_proc_bypass = next(
            i for i, r in enumerate(rules) if r.get("outbound") == "direct" and r.get("process_name")
        )
        idx_sniff = next(i for i, r in enumerate(rules) if r.get("action") == "sniff")
        idx_hijack = next(i for i, r in enumerate(rules) if r.get("action") == "hijack-dns")
        assert idx_proc_bypass < idx_sniff < idx_hijack

        # Remote HTTP rule_sets present
        rule_sets = cfg["route"]["rule_set"]
        assert rule_sets
        assert all(rs["type"] == "remote" and rs["format"] == "source" for rs in rule_sets)
        assert any(rs["tag"] == "rs-quic-reject" for rs in rule_sets)

        # Verify RuleSetServer serves ETag & 304 Not Modified & live hot updates
        rs_url = srv.url_for("rs-bundles-vpn")
        with urllib.request.urlopen(rs_url, timeout=3) as resp:
            assert resp.status == 200
            etag = resp.headers.get("ETag")
            assert etag
            body = json.loads(resp.read().decode("utf-8"))
            assert body["version"] == 3
            assert any("upc.exe" in p for r in body["rules"] for p in (r.get("process_name") or []))

        dns_vpn_url = srv.url_for("rs-bundles-dns-vpn")
        with urllib.request.urlopen(dns_vpn_url, timeout=3) as resp_d:
            body_d = json.loads(resp_d.read().decode("utf-8"))
            assert any("ubisoft" in d for r in body_d["rules"] for d in (r.get("domain_suffix") or []))

        req_304 = urllib.request.Request(rs_url, headers={"If-None-Match": etag})
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req_304, timeout=3)
        assert exc_info.value.code == 304

        payload["rs-bundles-vpn"] = [{"domain_suffix": ["hot-reloaded-domain.example"]}]
        srv.update_rulesets(payload)
        with urllib.request.urlopen(rs_url, timeout=3) as resp2:
            assert resp2.status == 200
            body2 = json.loads(resp2.read().decode("utf-8"))
            assert body2["rules"][0]["domain_suffix"] == ["hot-reloaded-domain.example"]

        sb_exe = Path("bin/sing-box.exe")
        if sb_exe.is_file():
            proc = subprocess.run([str(sb_exe), "check", "-c", str(out_path)], capture_output=True, text=True, timeout=15)
            assert proc.returncode == 0, f"sing-box check failed: {proc.stderr}\n{proc.stdout}"
    finally:
        srv.stop()


def test_winws2_v2_circular_pass_discord_lock_and_game_cloud(tmp_path: Path) -> None:
    strategies = {s.id: s for s in DEFAULT_STRATEGIES}
    decs = [
        Decision(network_key="AS1:home:default", domain="youtube.com", protocol=Protocol.TLS, layer="dpi", strategy_id="tls_alt1_199_fake_fakedsplit"),
        Decision(network_key="AS1:home:default", domain="discord.com", protocol=Protocol.TLS, layer="dpi", strategy_id="tls_alt1_199_fake_fakedsplit"),
    ]
    args, _ = generate_winws2_config(
        decisions=decs,
        strategies=strategies,
        lists_dir=tmp_path / "lists",
        enable_circular_catchall=True,
        enable_tcp_in=True,
        isp_best_tls="tls_alt1_199_fake_fakedsplit",
        bundle_pass_domains=["connect.ubisoft.com"],
        enable_game_udp_dpi=True,
        dns_infra_ips=["9.9.9.9"],
        dns_infra_domains=["dns.quad9.net"],
    )
    joined = "\n".join(args)

    assert "--wf-tcp-in=80,443" in args
    assert "--lua-desync=pass:strategy=1" in joined
    assert ":strategy=2" in joined
    assert "--filter-l7=discord,stun" in joined
    # discord,stun must stay locked to its voice ports, never 1024-65535
    discord_idx = args.index("--filter-l7=discord,stun")
    discord_slice = args[max(0, discord_idx - 3) : discord_idx + 4]
    assert "--filter-udp=19294-19344,50000-50100" in discord_slice
    assert "--filter-udp=1024-65535" not in discord_slice

    # Separate Game Cloud UDP profile exists with 1024-65535 & game_active:repeats=4
    assert "--filter-udp=1024-65535" in args
    assert "game_active:repeats=4" in joined

    # pass_domains.txt & dns infra use --lua-desync=pass
    pass_file = tmp_path / "lists" / "pass_domains.txt"
    assert pass_file.is_file()
    pass_txt = pass_file.read_text(encoding="utf-8")
    assert "connect.ubisoft.com" in pass_txt
    assert "dns.quad9.net" in pass_txt


def test_app_bundles_and_child_inheritance(monkeypatch: pytest.MonkeyPatch) -> None:
    bundles = load_bundles(Path("configs/bundles.yaml"))
    ids = {b.id for b in bundles}
    assert {"ubisoft", "riot", "ea", "battlenet", "rockstar", "steam", "epic", "hoyoverse", "minecraft", "roblox", "tarkov", "discord"} <= ids

    compiled = compile_bundle_rules(
        bundles,
        {
            "ubisoft": {"mode": "vpn"},
            "steam": {"mode": "direct_clean"},
            "hoyoverse": {"mode": "direct_dpi"},
        },
    )
    assert "upc.exe" in compiled["vpn_processes"]
    assert "ubisoft.com" in compiled["vpn_domains"]
    assert "steam.exe" in compiled["direct_processes"]
    assert "steampowered.com" in compiled["pass_domains"]
    assert "hoyoverse.com" in compiled["dpi_auth_domains"]
    assert compiled["enable_game_udp_dpi"] is True

    # Mock parent -> child process tree inheritance (e.g. upc.exe -> childgame.exe)
    p_parent = MagicMock()
    p_parent.info = {"pid": 100, "ppid": 0, "name": "upc.exe", "exe": ""}
    p_child = MagicMock()
    p_child.info = {"pid": 101, "ppid": 100, "name": "AcMirage_Child.exe", "exe": ""}
    monkeypatch.setattr(psutil, "process_iter", lambda attrs=None: [p_parent, p_child])
    running = expand_running_bundle_processes(bundles)
    assert running["ubisoft"]["running"] is True
    assert "AcMirage_Child.exe" in running["ubisoft"]["processes"]


def test_storage_db_v2_to_v3_migration_and_etld1(tmp_path: Path) -> None:
    db_file = tmp_path / "v2.db"
    conn = sqlite3.connect(db_file)
    conn.executescript(
        """
        PRAGMA user_version = 2;
        CREATE TABLE networks (
            network_key TEXT PRIMARY KEY,
            asn INTEGER NOT NULL,
            kind TEXT NOT NULL,
            isp TEXT DEFAULT '',
            last_seen TEXT NOT NULL
        );
        INSERT INTO networks VALUES ('AS1:home:default', 1, 'home', 'Test', '2026-01-01T00:00:00Z');
        """
    )
    conn.commit()
    conn.close()

    st = Storage(db_file)
    try:
        ver = st.conn.execute("PRAGMA user_version").fetchone()[0]
        assert ver == CURRENT_DB_VERSION == 3
        tables = {r[0] for r in st.conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        assert {"network_profiles", "bundle_modes"} <= tables
        assert st.conn.execute("SELECT isp FROM networks WHERE network_key='AS1:home:default'").fetchone()[0] == "Test"

        st.save_network_profile("AS1:home:default", base_dns_id="quad9", best_tls_strategy="tls_alt1_199_fake_fakedsplit", quic_blocked=True)
        prof = st.get_network_profile("AS1:home:default")
        assert prof is not None and prof["base_dns_id"] == "quad9" and prof["quic_blocked"] is True

        st.set_bundle_mode("AS1:home:default", "ubisoft", "vpn", custom_processes=["extra.exe"])
        modes = st.get_bundle_modes("AS1:home:default")
        assert modes["ubisoft"]["mode"] == "vpn"
        assert modes["ubisoft"]["custom_processes"] == ["extra.exe"]
        assert st.delete_bundle_mode("AS1:home:default", "ubisoft") is True
    finally:
        st.close()

    assert normalize_domain_etld1("rr3---sn-4g5e6nsz.googlevideo.com") == "googlevideo.com"
    assert normalize_domain_etld1("cdn.discord.com") == "discord.com"
    assert normalize_domain_etld1("1.2.3.4.in-addr.arpa") == "1.2.3.4.in-addr.arpa"
    assert normalize_domain_etld1("10.0.0.1") == "10.0.0.1"


def test_geo_block_classification_and_routing() -> None:
    bundle = ProbesSummary(
        dns=DnsProbeResult(system="ok", doh="ok", doh_ips=["104.18.1.1"]),
        tcp=TcpProbeResult(result="ok", rtt_ms=18.0, target_ip="104.18.1.1"),
        tls=TlsProbeResult(real_sni="ok", neutral_sni="ok", ttfb_ms=40.0),
        stall=StallProbeResult(result="ok", bytes_read=512, throughput_kbps=100.0, http_status=403),
        quic=QuicProbeResult(result="ok", rtt_ms=20.0),
    )
    report = classify_probes(
        domain="claude.ai",
        probes=bundle,
        network=NetworkFingerprint(asn=1, kind=NetworkKind.HOME, isp="Test"),
    )
    assert VerdictClass.GEO_BLOCK in report.verdicts
    assert any(a.layer == "dns" and a.action == "smartdns" for a in report.recommended)

    dec = _quick_non_dpi_decision("AS1:home:default", "claude.ai", report.verdicts, Protocol.TLS, vpn_available=True)
    assert dec is not None
    assert dec.layer == "dns" and dec.strategy_id == "smartdns"


def test_orchestrator_16kb_stall_cdn_guard_and_bundle_alert(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(psutil, "net_connections", lambda kind="inet": [])
    # Shared CDN anycast IPs must NEVER be cached as domain IPs
    assert _is_shared_cdn_anycast_ip("104.16.123.96") is True
    assert _is_shared_cdn_anycast_ip("13.32.10.5") is True
    assert _is_shared_cdn_anycast_ip("151.101.1.69") is True
    assert _is_shared_cdn_anycast_ip("149.154.167.51") is False

    mon = RealtimeConnectionMonitor()
    # 16KB TCP stall detection + Bundle alert instead of silent auto_vpn_procs
    mock_clash = MagicMock()
    mock_clash.get_connections_sync.return_value = {
        "connections": [
            {
                "id": "c1",
                "metadata": {
                    "host": "connect.ubisoft.com",
                    "destinationIP": "104.16.123.96",
                    "destinationPort": 443,
                    "network": "tcp",
                    "process": "upc.exe",
                },
                "download": 16384,
                "upload": 512,
                "start": "2020-01-01T00:00:00Z",
                "chains": ["direct"],
            },
            {
                "id": "g1",
                "metadata": {
                    "destinationIP": "198.51.100.71",
                    "destinationPort": 6015,
                    "network": "udp",
                    "process": "upc.exe",
                },
                "download": 0,
                "upload": 1500,
                "start": "2020-01-01T00:00:00Z",
                "chains": ["direct"],
            },
            {
                "id": "g2",
                "metadata": {
                    "destinationIP": "198.51.100.72",
                    "destinationPort": 6016,
                    "network": "udp",
                    "process": "upc.exe",
                },
                "download": 0,
                "upload": 1500,
                "start": "2020-01-01T00:00:00Z",
                "chains": ["direct"],
            },
        ]
    }
    eng = NetdoctorEngine(
        db_path=tmp_path / "mon.db",
        configs_dir=tmp_path / "configs",
        lists_dir=tmp_path / "lists",
        logs_dir=tmp_path / "logs",
        bin_dir=tmp_path / "bin",
        ruleset_port=0,
    )
    monkeypatch.setattr(eng, "_collect_processes_state", lambda: {"winws2": {"running": True}, "sing-box": {"running": True}})
    monkeypatch.setattr(eng.clash_api, "get_connections_sync", mock_clash.get_connections_sync)
    st = Storage(eng.db_path)
    try:
        conns = mon.scan_active_connections(storage=st, logs_dir=tmp_path / "logs", net_key="AS1:home:default", clash_client=mock_clash)
    finally:
        st.close()

    assert len(conns) == 3
    assert any(c.get("domain") == "connect.ubisoft.com" and c.get("health") == "needs_fix" for c in conns)

    import asyncio

    import netdoctor.orchestrators as orch_mod

    monkeypatch.setattr(orch_mod, "detect_bypass_active", lambda: True)
    monkeypatch.setattr(orch_mod, "_is_admin", lambda: False)
    res = asyncio.run(eng.orchestrator.monitor.auto_heal_connections(eng, max_domains_per_tick=0))
    assert any(a.get("bundle_id") == "ubisoft" for a in eng.orchestrator.monitor.pending_bundle_alerts)
    assert any(e.get("layer") == "recommend" for e in res["events"])
    assert not hasattr(mon, "auto_vpn_procs")


def test_start_autopilot_triggers_calibration_when_uncalibrated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import netdoctor.core.engine as engine_mod

    monkeypatch.setattr(engine_mod, "_is_admin", lambda: False)
    monkeypatch.setattr(psutil, "net_connections", lambda kind="inet": [])
    called: list[bool] = []

    async def fake_cal(storage: Storage, **_kw):
        called.append(True)
        net = NetworkFingerprint(asn=12389, kind=NetworkKind.HOME, isp="Test")
        nk = storage.upsert_network(net)
        storage.save_network_profile(nk, base_dns_id="quad9", best_tls_strategy="tls_alt1_199_fake_fakedsplit", quic_blocked=False)
        return {"network_key": nk, "base_dns": {"id": "quad9", "name": "Quad9"}}

    monkeypatch.setattr(engine_mod, "calibrate_network", fake_cal)
    eng = NetdoctorEngine(
        db_path=tmp_path / "ap.db",
        configs_dir=tmp_path / "configs",
        lists_dir=tmp_path / "lists",
        logs_dir=tmp_path / "logs",
        bin_dir=tmp_path / "bin",
        ruleset_port=0,
    )
    res = eng.start_autopilot()
    assert called == [True]
    assert res["diagnosed_now"] is True


def test_gui_progressive_disclosure_and_cleanliness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    eng = NetdoctorEngine(
        db_path=tmp_path / "gui.db",
        configs_dir=tmp_path / "configs",
        lists_dir=tmp_path / "lists",
        logs_dir=tmp_path / "logs",
        bin_dir=tmp_path / "bin",
        ruleset_port=0,
    )
    try:
        app = NetdoctorGuiApp(backend=eng, auto_start=False)
    except tk.TclError as exc:
        pytest.skip(f"Tcl/Tk display unavailable: {exc}")

    try:
        app.withdraw()
        app.update_idletasks()
        assert app._expert_mode is False
        assert not hasattr(app, "tab_apps")
        # Basic mode: strictly 3 tabs (Главная, VPN, Настройки)
        visible_basic = app.get_visible_nav_tabs()
        assert visible_basic == [app.tab_home, app.tab_vpn, app.tab_settings]
        assert len(visible_basic) == 3
        assert _has_tk_descendant(app.tab_vpn, tk.Text) is False

        # Screenshot 2/3 regression fix: log_console uses datetime cleanly
        app.log_console("Тестовое сообщение в консоль")
        assert "Тестовое сообщение" in app.console.get("1.0", "end-1c")

        # Unified «Что-то не открывается?» block handles both domain and bundle/exe targets
        calls: list[tuple[str, str]] = []
        monkeypatch.setattr(app, "run_bg", lambda _title, fn, cb=None: cb(fn()) if cb else fn())
        monkeypatch.setattr(
            eng,
            "find_best_bypass_for_domain",
            lambda dom, **_kw: (
                calls.append(("domain", dom)),
                {"ok": True, "domain": dom, "winner": {"layer": "dpi", "strategy_id": "tls_multisplit_pos2", "latency_ms": 22.0}},
            )[1],
        )
        monkeypatch.setattr(
            eng,
            "find_best_bypass_for_bundle",
            lambda bid, **_kw: (
                calls.append(("bundle", bid)),
                {"ok": True, "bundle_id": bid, "bundle_name": "Ubisoft Connect", "mode": "direct_dpi", "restart_hint": ""},
            )[1],
        )

        app.set_home_fix_kind("domain")
        app.home_fix_domain_var.set("rutracker.org")
        app.on_home_fix_target()
        assert ("domain", "rutracker.org") in calls
        assert "rutracker.org" in app.home_fix_result_lbl.cget("text")

        app.set_home_fix_kind("bundle")
        app.home_fix_bundle_var.set("upc.exe")
        app.on_home_fix_target()
        assert ("bundle", "upc.exe") in calls
        assert "DPI" in app.home_fix_result_lbl.cget("text")

        # Expert mode: 7 tabs + Bundles live inside Monitor subview
        app.set_expert_mode(True, persist=False)
        app.update_idletasks()
        assert app._expert_mode is True
        assert len(app.get_visible_nav_tabs()) == 7
        app._open_domains_subview("bundles")
        assert app._domains_subview_mode == "bundles"
    finally:
        app.on_close()

    # Cleanliness assertions across src/
    assert not Path("src/netdoctor/ui/tab_apps.py").exists()
    cli_src = Path("src/netdoctor/cli.py").read_text(encoding="utf-8")
    assert "GuiBackend" not in cli_src
    assert "gui_backend" not in cli_src
    for pyf in Path("src").rglob("*.py"):
        src_txt = pyf.read_text(encoding="utf-8", errors="ignore")
        assert "C:\\vso\\Dev" not in src_txt, f"Hardcoded path in {pyf}"
        assert "tab_apps" not in src_txt, f"Dead tab_apps reference in {pyf}"


def test_find_best_bypass_for_bundle_and_xray_dns_fix(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio
    import netdoctor.core.calibration as cal_mod
    from netdoctor.models import VpnNode

    # 1. Xray bridge config puts direct freedom FIRST and localhost DNS FIRST (no DNS deadlock)
    vless_reality = VpnNode(
        tag="DE-Reality",
        protocol="vless",
        server="api-bacx.kaneki.cfd",
        server_port=443,
        raw_outbound={
            "type": "vless",
            "tag": "DE-Reality",
            "server": "api-bacx.kaneki.cfd",
            "server_port": 443,
            "uuid": "11111111-2222-3333-4444-555555555555",
            "flow": "xtls-rprx-vision",
            "tls": {
                "enabled": True,
                "server_name": "api-bacx.kaneki.cfd",
                "reality": {"enabled": True, "public_key": "pub", "short_id": "1234"},
            },
        },
    )
    xcfg, bridge_ports = generate_xray_bridge_config([vless_reality], dns_server="1.1.1.2")
    assert "DE-Reality" in bridge_ports
    assert xcfg["outbounds"][0] == {"protocol": "freedom", "tag": "direct"}
    assert xcfg["dns"]["servers"][0] == "localhost"
    assert xcfg["routing"]["rules"][0] == {"type": "field", "port": 53, "outboundTag": "direct"}

    # 2. winws2 passes VPN server hostnames via pass_domains.txt but never swallows active DPI domains (discord.com)
    strategies = {s.id: s for s in DEFAULT_STRATEGIES}
    decs = [
        Decision(network_key="AS1:home:default", domain="discord.com", protocol=Protocol.TLS, layer="dpi", strategy_id="tls_alt1_199_fake_fakedsplit"),
    ]
    _, _ = generate_winws2_config(
        decisions=decs,
        strategies=strategies,
        lists_dir=tmp_path / "lists_w2",
        vpn_server_ips=["api-bacx.kaneki.cfd"],
        bundle_pass_domains=["discord.com", "ubi.com"],
    )
    pass_txt = (tmp_path / "lists_w2" / "pass_domains.txt").read_text(encoding="utf-8")
    assert "api-bacx.kaneki.cfd" in pass_txt
    assert "ubi.com" in pass_txt
    assert "discord.com" not in pass_txt.splitlines()

    # 3. find_best_bypass_for_bundle escalates direct_clean -> direct_dpi -> vpn & persists to SQLite
    db_path = tmp_path / "bundle_ladder.db"
    st = Storage(db_path)
    try:
        nk = st.upsert_network(NetworkFingerprint(asn=1, kind=NetworkKind.HOME, isp="Test"))
        st.save_subscription(
            "default",
            "https://example.com/sub",
            [
                {
                    "tag": "wg-eu",
                    "protocol": "wireguard",
                    "server": "198.51.100.55",
                    "server_port": 51820,
                    "raw_outbound": {"type": "wireguard", "tag": "wg-eu", "server": "198.51.100.55", "server_port": 51820},
                }
            ],
        )
    finally:
        st.close()

    eng = NetdoctorEngine(
        db_path=db_path,
        configs_dir=tmp_path / "configs",
        lists_dir=tmp_path / "lists",
        logs_dir=tmp_path / "logs",
        bin_dir=tmp_path / "bin",
        ruleset_port=0,
    )
    monkeypatch.setattr(eng, "trigger_apply_configs", lambda iface=None: {"ok": True})
    monkeypatch.setattr(eng, "_collect_processes_state", lambda: {"winws2": {"running": False}, "sing-box": {"running": False}})

    seen_modes: list[str] = []

    def _probe_vpn_wins(_dom: str, *, proxy_url: str | None = None, timeout: float = 3.0) -> dict[str, Any]:
        cur_mode = eng.get_bundles_status()["bundles"]
        ub_mode = next(b["mode"] for b in cur_mode if b["id"] == "ubisoft")
        seen_modes.append(ub_mode)
        if ub_mode == "vpn":
            return {"ok": True, "latency_ms": 42.0}
        return {"ok": False, "error": "blocked"}

    res = eng.find_best_bypass_for_bundle(
        "ubisoft",
        probe_fn=_probe_vpn_wins,
        udp_check_fn=lambda: {"ok": True, "reason": ""},
    )
    assert res["ok"] is True
    assert res["mode"] == "vpn"
    assert res["exit_ip_changed"] is True
    assert res["restart_hint"]
    assert "direct_clean" in seen_modes and "direct_dpi" in seen_modes and "vpn" in seen_modes

    # Downshift back to direct_clean when direct becomes clean
    res_down = eng.find_best_bypass_for_bundle(
        "ubisoft",
        probe_fn=lambda _d, **_kw: {"ok": True, "latency_ms": 15.0},
    )
    assert res_down["ok"] is True
    assert res_down["mode"] == "direct_clean"
    assert res_down["exit_ip_changed"] is True

    # Unknown .exe creates a custom bundle and solves via ladder
    res_exe = eng.find_best_bypass_for_bundle(
        "CustomGame.exe",
        probe_fn=lambda _d, **_kw: {"ok": True, "latency_ms": 18.0},
    )
    assert res_exe["ok"] is True
    assert res_exe["mode"] == "direct_clean"
    assert any(b["id"] == res_exe["bundle_id"] for b in eng.get_bundles_status()["bundles"])

    # 4. Calibration assigns bundle modes based on ISP profile without overwriting pinned manual choices
    st_c = Storage(db_path)
    try:
        st_c.set_bundle_mode(nk, "ubisoft", "vpn", pinned=True)
        st_c.set_bundle_mode(nk, "discord", "direct_clean", pinned=False)

        async def _fake_net(timeout: float = 2.5) -> NetworkFingerprint:
            return NetworkFingerprint(asn=1, kind=NetworkKind.HOME, isp="Test")

        async def _fake_beacon_probe(dom: str, timeout: float = 2.5) -> ProbesSummary:
            tls_res = "reset" if dom in ("discord.com", "cloudflare.com") else "ok"
            return ProbesSummary(
                dns=DnsProbeResult(system="ok", doh="ok", doh_ips=["162.159.135.232"]),
                tcp=TcpProbeResult(result="ok", rtt_ms=15.0, target_ip="162.159.135.232"),
                tls=TlsProbeResult(real_sni=tls_res, neutral_sni="ok", ttfb_ms=20.0),
                stall=StallProbeResult(result="ok", bytes_read=4096, throughput_kbps=5000.0),
                quic=QuicProbeResult(result="ok", rtt_ms=15.0),
            )

        monkeypatch.setattr(cal_mod, "detect_network_fingerprint", _fake_net)
        asyncio.run(
            cal_mod.calibrate_network(
                st_c,
                probe_fn=_fake_beacon_probe,
                base_dns_probe_fn=lambda s: asyncio.sleep(0, result={"ok": True, "latency_ms": 10.0, "ip": s["ip"]}),
            )
        )
        modes_after = st_c.get_bundle_modes(nk)
        assert modes_after["ubisoft"]["mode"] == "vpn"
        assert modes_after["ubisoft"]["pinned"] is True
        assert modes_after["discord"]["mode"] == "direct_dpi"
    finally:
        st_c.close()


def test_telegram_two_layer_mode_winws2_singbox_and_settings_ui(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from netdoctor.config_gen import TELEGRAM_CIDRS
    from netdoctor.orchestrators import RealtimeConnectionMonitor
    from netdoctor.presets import compile_zapret_preset

    strategies = {s.id: s for s in DEFAULT_STRATEGIES}
    decs = [
        Decision(network_key="AS1:home:default", domain="telegram.org", protocol=Protocol.TLS, layer="vpn", strategy_id="vpn-select"),
        Decision(network_key="AS1:home:default", domain="t.me", protocol=Protocol.TLS, layer="vpn", strategy_id="vpn-select"),
        Decision(network_key="AS1:home:default", domain="telesco.pe", protocol=Protocol.TLS, layer="dpi", strategy_id="tls_multisplit_pos2"),
    ]

    # 1. mtproto mode: NO ipset-telegram desync profile; circular & presets exclude ipset-telegram.txt; no TELEGRAM_CIDRS in vpn-select
    args_mt, _ = generate_winws2_config(
        decisions=decs,
        strategies=strategies,
        lists_dir=tmp_path / "lists_mt",
        enable_telegram_ipset=False,
    )
    assert not any(a.startswith("--ipset=") and "ipset-telegram" in a for a in args_mt)
    assert any(a.startswith("--ipset-exclude=") and "ipset-telegram" in a for a in args_mt)

    preset_txt = (
        "--wf-tcp-out=80,443,5222\n"
        "--filter-tcp=80,443,5222 --ipset=ipset-telegram.txt --payload=all --lua-desync=multisplit:pos=1\n"
        "--new\n"
        "--filter-tcp=80,443 --ipset=ipset-all.txt --payload=tls_client_hello --lua-desync=multisplit:pos=1\n"
    )
    compiled_mt = compile_zapret_preset(
        preset_txt,
        bin_dir=tmp_path / "bin",
        lists_dir=tmp_path / "lists_p",
        enable_telegram_ipset=False,
    )
    assert not any(a.startswith("--ipset=") and "ipset-telegram" in a for a in compiled_mt)
    assert any(a.startswith("--ipset-exclude=") and "ipset-telegram" in a for a in compiled_mt)

    payload_mt = build_singbox_rulesets_payload(decs, telegram_mode="mtproto")
    assert all("ip_cidr" not in r for r in payload_mt["rs-vpn"])
    assert any("telegram.org" in (r.get("domain_suffix") or []) for r in payload_mt["rs-vpn"])

    # 2. transparent mode: ipset-telegram enabled in winws2/presets & TELEGRAM_CIDRS fallback in vpn-select
    args_tr, _ = generate_winws2_config(
        decisions=decs,
        strategies=strategies,
        lists_dir=tmp_path / "lists_tr",
        enable_telegram_ipset=True,
    )
    assert any(a.startswith("--ipset=") and "ipset-telegram" in a for a in args_tr)
    payload_tr = build_singbox_rulesets_payload(decs, telegram_mode="transparent")
    assert any(set(TELEGRAM_CIDRS) <= set(r.get("ip_cidr") or []) for r in payload_tr["rs-vpn"])

    # 3. Orchestrator ignores tg-ws-proxy fronting domains (kws*.web.telegram.org, kws*.cakeisalie.co.uk)
    mon = RealtimeConnectionMonitor()
    conns = [
        {"domain": "kws2.web.telegram.org", "process": "python.exe", "health": "needs_fix", "layer": "direct", "socket_status": "SYN_SENT"},
        {"domain": "kws1.cakeisalie.co.uk", "process": "python.exe", "health": "needs_fix", "layer": "direct", "socket_status": "SYN_SENT"},
        {"domain": "t.me", "process": "Telegram.exe", "health": "needs_fix", "layer": "direct", "socket_status": "SYN_SENT"},
    ]
    cands = mon._collect_fix_candidates(conns, tmp_path / "logs", max_domains=5)
    assert [c[0] for c in cands] == ["t.me"]

    # 4. Settings UI & Engine wiring: selecting Telegram mode in Настройки invokes set_telegram_mode and updates config
    eng = NetdoctorEngine(
        db_path=tmp_path / "tg.db",
        configs_dir=tmp_path / "configs",
        lists_dir=tmp_path / "lists",
        logs_dir=tmp_path / "logs",
        bin_dir=tmp_path / "bin",
        ruleset_port=0,
    )
    # Verify engine defaults to mtproto & writes no --ipset=ipset-telegram.txt
    eng.trigger_apply_configs()
    w2_mt = (tmp_path / "configs" / "winws2_preset.txt").read_text(encoding="utf-8")
    assert "--ipset=" + (tmp_path / "lists" / "ipset-telegram.txt").resolve().as_posix() not in w2_mt

    eng.set_telegram_mode("transparent")
    w2_tr = (tmp_path / "configs" / "winws2_preset.txt").read_text(encoding="utf-8")
    assert "ipset-telegram.txt" in w2_tr
    assert "--ipset=" in w2_tr

    try:
        app = NetdoctorGuiApp(backend=eng, auto_start=False)
    except tk.TclError as exc:
        pytest.skip(f"Tcl/Tk display unavailable: {exc}")

    try:
        app.withdraw()
        app.update_idletasks()
        assert hasattr(app, "settings_tg_mode_cb")
        assert app.telegram_mode_var.get() == "transparent"
        monkeypatch.setattr(app, "run_bg", lambda _t, fn, cb=None: cb(fn()) if cb else fn())
        set_calls: list[str] = []
        monkeypatch.setattr(eng, "set_telegram_mode", lambda m: (set_calls.append(m), {"telegram_mode": m, "applied": {}})[1])

        app.settings_tg_mode_var.set(app._settings_tg_labels[0])
        app.on_settings_telegram_mode_selected()
        assert set_calls == ["mtproto"]
        assert app.telegram_mode_var.get() == "mtproto"

        app.settings_tg_mode_var.set(app._settings_tg_labels[1])
        app.on_settings_telegram_mode_selected()
        assert set_calls == ["mtproto", "transparent"]
        assert app.telegram_mode_var.get() == "transparent"
    finally:
        app.on_close()
