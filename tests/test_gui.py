"""Comprehensive unit and integration tests for GuiBackend, NetdoctorController, and NetdoctorGuiApp."""

from __future__ import annotations

import base64
import json
import struct
import subprocess
import sys
import tkinter as tk
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import netdoctor.gui as gui_mod
import netdoctor.gui_backend as backend_mod
from netdoctor.classifier import classify_probes
from netdoctor.gui import (
    NetdoctorController,
    NetdoctorGuiApp,
    format_probe_lines,
    launch_gui,
    normalize_domain,
    row_iid,
    row_matches,
    row_tag,
)
from netdoctor.gui_backend import MAX_PREVIEW_BYTES, GuiBackend, build_elevate_command
from netdoctor.models import (
    Decision,
    DnsProbeResult,
    NetworkFingerprint,
    NetworkKind,
    ProbesSummary,
    Protocol,
    ProtocolBlockProbeResult,
    QuicProbeResult,
    StallProbeResult,
    TcpProbeResult,
    TlsProbeResult,
    VerdictClass,
)
from netdoctor.selector import DEFAULT_STRATEGIES
from netdoctor.storage import Storage


def _seed_sample_db(db_path: Path) -> str:
    """Populate a temporary database with network, verdicts, strategies, and decisions."""
    storage = Storage(db_path)
    try:
        net = NetworkFingerprint(asn=12389, kind=NetworkKind.HOME, isp="TestISP")
        net_key = storage.upsert_network(net)
        storage.upsert_strategies(DEFAULT_STRATEGIES)

        discord_probes = ProbesSummary(
            dns=DnsProbeResult(system="ok", doh="ok", system_ips=["162.159.135.232"], doh_ips=["162.159.135.232"]),
            tcp=TcpProbeResult(result="ok", rtt_ms=18.5, target_ip="162.159.135.232"),
            tls=TlsProbeResult(real_sni="reset", neutral_sni="ok", ttfb_ms=42.0),
            stall=StallProbeResult(result="ok", bytes_read=65536, throughput_kbps=4100.0),
            quic=QuicProbeResult(result="timeout", rtt_ms=None),
            protocol_tunnel=ProtocolBlockProbeResult(result="skipped"),
        )
        discord_report = classify_probes("discord.com", discord_probes, net)
        storage.save_verdict(net_key, discord_report, protocol=Protocol.TLS)
        storage.save_verdict(net_key, discord_report, protocol=Protocol.QUIC)

        storage.save_decision(
            Decision(
                network_key=net_key,
                domain="discord.com",
                protocol=Protocol.TLS,
                layer="dpi",
                strategy_id="tls_multisplit_pos2",
                fallback_strategies=["tls_fakedsplit_pos2", "tls_hostfakesplit_google"],
                ttfb_ms=42.0,
                throughput_kbps=4100.0,
                consecutive_fails=0,
                status="active",
            )
        )
        storage.save_decision(
            Decision(
                network_key=net_key,
                domain="discord.com",
                protocol=Protocol.QUIC,
                layer="dpi",
                strategy_id="quic_fake_repeats6",
                fallback_strategies=["quic_fake_google_autottl"],
                ttfb_ms=25.0,
                throughput_kbps=2500.0,
                consecutive_fails=0,
                status="active",
            )
        )

        vpn_probes = ProbesSummary(
            dns=DnsProbeResult(system="ok", doh="ok", doh_ips=["198.51.100.10"]),
            tcp=TcpProbeResult(result="timeout", target_ip="198.51.100.10"),
        )
        vpn_report = classify_probes("blocked-ip.example", vpn_probes, net)
        storage.save_verdict(net_key, vpn_report, protocol=Protocol.TLS)
        storage.save_decision(
            Decision(
                network_key=net_key,
                domain="blocked-ip.example",
                protocol=Protocol.TLS,
                layer="vpn",
                strategy_id=None,
                fallback_strategies=[],
                status="active",
            )
        )
        return net_key
    finally:
        storage.close()


def test_gui_backend_get_domain_rows_join(tmp_path: Path) -> None:
    db_path = tmp_path / "netdoctor.db"
    net_key = _seed_sample_db(db_path)
    backend = GuiBackend(
        db_path=db_path,
        configs_dir=tmp_path / "configs",
        lists_dir=tmp_path / "lists",
        logs_dir=tmp_path / "logs",
        bin_dir=tmp_path / "bin",
    )

    rows = backend.get_domain_rows()
    assert len(rows) == 3

    by_key = {(r["domain"], r["protocol"]): r for r in rows}

    tls_row = by_key[("discord.com", "tls")]
    assert tls_row["network_key"] == net_key
    assert tls_row["layer"] == "dpi"
    assert tls_row["strategy_id"] == "tls_multisplit_pos2"
    assert tls_row["fallback_strategies"] == ["tls_fakedsplit_pos2", "tls_hostfakesplit_google"]
    assert tls_row["verdicts"] == [VerdictClass.SNI_DPI.value, VerdictClass.QUIC_BLOCK.value]
    assert tls_row["confidence"] > 0.0
    assert tls_row["ttfb_ms"] == 42.0
    assert tls_row["throughput_kbps"] == 4100.0
    assert tls_row["probes"]["dns"]["system"] == "ok"
    assert tls_row["probes"]["tcp"]["target_ip"] == "162.159.135.232"
    assert tls_row["probes"]["tls"]["real_sni"] == "reset"
    assert tls_row["probes"]["stall"]["throughput_kbps"] == 4100.0
    assert tls_row["probes"]["quic"]["result"] == "timeout"
    assert "protocol_tunnel" in tls_row["probes"]
    expected_tls_strat = next(s for s in DEFAULT_STRATEGIES if s.id == "tls_multisplit_pos2")
    assert tls_row["strategy_args"] == expected_tls_strat.args_template
    assert tls_row["strategy_description"] == expected_tls_strat.description
    assert tls_row["tier"] == expected_tls_strat.tier

    quic_row = by_key[("discord.com", "quic")]
    assert quic_row["strategy_id"] == "quic_fake_repeats6"
    expected_quic_strat = next(s for s in DEFAULT_STRATEGIES if s.id == "quic_fake_repeats6")
    assert quic_row["strategy_args"] == expected_quic_strat.args_template
    assert quic_row["tier"] == expected_quic_strat.tier

    vpn_row = by_key[("blocked-ip.example", "tls")]
    assert vpn_row["layer"] == "vpn"
    assert vpn_row["strategy_id"] is None
    assert vpn_row["strategy_args"] == []
    assert vpn_row["strategy_description"] == ""
    assert vpn_row["tier"] is None
    assert vpn_row["verdicts"] == [VerdictClass.IP_BLOCK.value]

    # Explicit network filter returns empty list for unknown network key
    assert backend.get_domain_rows(net_key="AS99999:mobile:none") == []


def test_gui_backend_pin_domain_strategy_and_regenerate_configs(tmp_path: Path) -> None:
    db_path = tmp_path / "netdoctor.db"
    configs_dir = tmp_path / "configs"
    lists_dir = tmp_path / "lists"
    _seed_sample_db(db_path)

    # Mark discord.com TLS degraded with fails before pinning to confirm pin restores active state
    st = Storage(db_path)
    try:
        st.conn.execute(
            "UPDATE decisions SET status = 'degraded', consecutive_fails = 4 WHERE domain = 'discord.com' AND protocol = 'tls'"
        )
        st.conn.commit()
    finally:
        st.close()

    backend = GuiBackend(
        db_path=db_path,
        configs_dir=configs_dir,
        lists_dir=lists_dir,
        logs_dir=tmp_path / "logs",
        bin_dir=tmp_path / "bin",
    )

    pinned = backend.pin_domain_strategy(
        domain=" DISCORD.COM ",
        protocol="tls",
        layer="dpi",
        strategy_id="tls_hostfakesplit_google",
    )
    assert pinned["domain"] == "discord.com"
    assert pinned["protocol"] == "tls"
    assert pinned["layer"] == "dpi"
    assert pinned["strategy_id"] == "tls_hostfakesplit_google"
    assert pinned["status"] == "active"
    assert pinned["consecutive_fails"] == 0
    assert pinned["fallback_strategies"] == ["tls_fakedsplit_pos2", "tls_hostfakesplit_google"]

    rows = {(r["domain"], r["protocol"]): r for r in backend.get_domain_rows()}
    assert rows[("discord.com", "tls")]["strategy_id"] == "tls_hostfakesplit_google"
    assert rows[("discord.com", "tls")]["status"] == "active"

    preset_file = configs_dir / "winws2_preset.txt"
    singbox_file = configs_dir / "sing-box.json"
    hostlist_file = lists_dir / "tls_hostfakesplit_google.txt"
    assert preset_file.is_file()
    assert singbox_file.is_file()
    assert hostlist_file.is_file()
    assert "discord.com" in hostlist_file.read_text(encoding="utf-8").splitlines()
    assert "tls_hostfakesplit_google.txt" in preset_file.read_text(encoding="utf-8")

    # Pin a new domain directly to VPN and confirm sing-box routing updates
    vpn_pinned = backend.pin_domain_strategy(
        domain="youtube.com",
        protocol="tls",
        layer="vpn",
        strategy_id=None,
    )
    assert vpn_pinned["layer"] == "vpn"
    assert vpn_pinned["strategy_id"] is None
    sb_cfg = json.loads(singbox_file.read_text(encoding="utf-8"))
    rules = sb_cfg["route"]["rules"]
    assert any(
        "youtube.com" in rule.get("domain_suffix", []) and rule.get("outbound") == "vpn-select"
        for rule in rules
    )


def test_gui_backend_read_config_preview_and_read_logs_tail(tmp_path: Path) -> None:
    configs_dir = tmp_path / "configs"
    lists_dir = tmp_path / "lists"
    logs_dir = tmp_path / "logs"
    backend = GuiBackend(
        db_path=tmp_path / "netdoctor.db",
        configs_dir=configs_dir,
        lists_dir=lists_dir,
        logs_dir=logs_dir,
        bin_dir=tmp_path / "bin",
    )

    applied = backend.trigger_apply_configs()
    assert Path(applied["winws2_preset"]).is_file()
    assert Path(applied["singbox_config"]).is_file()

    # Add a huge hostlist (> 128 KB) to verify safe preview truncation
    huge_file = lists_dir / "huge_domains.txt"
    huge_content = ("example.org\n" * 15000).encode("utf-8")
    assert len(huge_content) > MAX_PREVIEW_BYTES
    huge_file.write_bytes(huge_content)

    previews = backend.read_config_preview()
    assert "configs/winws2_preset.txt" in previews
    assert "configs/sing-box.json" in previews
    assert "lists/exclude_vpn_ips.txt" in previews
    assert "lists/huge_domains.txt" in previews
    assert "[truncated:" in previews["lists/huge_domains.txt"]
    assert len(previews["lists/huge_domains.txt"].encode("utf-8")) < len(huge_content)

    # Logs tail test: 120 lines in winws2.log, 2 lines in sing-box.log, missing tg-ws-proxy.log
    logs_dir.mkdir(parents=True, exist_ok=True)
    (logs_dir / "winws2.log").write_text(
        "\n".join(f"winws-line-{i}" for i in range(120)) + "\n",
        encoding="utf-8",
    )
    (logs_dir / "sing-box.log").write_text("sb-1\nsb-2\n", encoding="utf-8")

    tails = backend.read_logs_tail(max_lines=5)
    assert set(tails.keys()) == {"winws2.log", "sing-box.log", "tg-ws-proxy.log"}
    assert tails["winws2.log"].splitlines() == [f"winws-line-{i}" for i in range(115, 120)]
    assert tails["sing-box.log"].splitlines() == ["sb-1", "sb-2"]
    assert tails["tg-ws-proxy.log"] == ""


def test_gui_backend_catalog_diag_sync_and_uac_guards(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db_path = tmp_path / "netdoctor.db"
    backend = GuiBackend(
        db_path=db_path,
        configs_dir=tmp_path / "configs",
        lists_dir=tmp_path / "lists",
        logs_dir=tmp_path / "logs",
        bin_dir=tmp_path / "bin",
    )

    all_strats = backend.get_strategies_catalog()
    assert len(all_strats) >= len(DEFAULT_STRATEGIES)
    assert {"id", "family", "protocol", "tier", "args_template", "description"}.issubset(all_strats[0].keys())
    quic_strats = backend.get_strategies_catalog(protocol="quic")
    assert quic_strats and all(s["protocol"] == "quic" for s in quic_strats)

    # UAC guard when not admin
    monkeypatch.setattr(backend_mod, "_is_admin", lambda: False)
    monkeypatch.setattr(backend_mod, "detect_bypass_active", lambda: False)
    start_res = backend.start_services()
    assert start_res["ok"] is False
    assert start_res["requires_admin"] is True

    reload_res = backend.reload_winws2()
    assert reload_res["ok"] is False
    assert reload_res["requires_admin"] is True

    cmd = build_elevate_command(
        db_path=db_path,
        configs_dir=tmp_path / "configs",
        lists_dir=tmp_path / "lists",
        logs_dir=tmp_path / "logs",
    )
    assert cmd[0] == "powershell.exe"
    assert "-Verb RunAs" in cmd[-1]

    # Conflict guard when admin + bypass active
    monkeypatch.setattr(backend_mod, "_is_admin", lambda: True)
    monkeypatch.setattr(backend_mod, "detect_bypass_active", lambda: True)
    conflict_res = backend.start_services(force=False)
    assert conflict_res["ok"] is False
    assert conflict_res["conflict"] is True

    # Offline mocked run_diag_sync (covers DPI + QUIC_BLOCK persistence and config generation)
    monkeypatch.setattr(backend_mod, "detect_bypass_active", lambda: False)

    async def fake_detect_net(timeout: float = 2.5) -> NetworkFingerprint:
        return NetworkFingerprint(asn=25513, kind=NetworkKind.HOME, isp="MockNet")

    async def fake_probes(domain: str, timeout: float = 2.5) -> ProbesSummary:
        return ProbesSummary(
            dns=DnsProbeResult(system="ok", doh="ok", doh_ips=["1.1.1.1"]),
            tcp=TcpProbeResult(result="ok", rtt_ms=12.0, target_ip="1.1.1.1"),
            tls=TlsProbeResult(real_sni="reset", neutral_sni="ok", ttfb_ms=30.0),
            stall=StallProbeResult(result="ok", bytes_read=32768, throughput_kbps=3000.0),
            quic=QuicProbeResult(result="timeout"),
        )

    monkeypatch.setattr(backend_mod, "detect_network_fingerprint", fake_detect_net)
    monkeypatch.setattr(backend_mod, "run_domain_probes", fake_probes)

    rows = backend.run_diag_sync(domains=["example.org"], live_eval=False, timeout=1.0)
    assert {(r["domain"], r["protocol"]) for r in rows} == {
        ("example.org", "tls"),
        ("example.org", "quic"),
    }
    assert (tmp_path / "configs" / "winws2_preset.txt").is_file()
    assert (tmp_path / "configs" / "sing-box.json").is_file()


def test_controller_backward_compatibility_and_headless_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "ctrl.db"
    configs_dir = tmp_path / "configs"
    lists_dir = tmp_path / "lists"
    logs_dir = tmp_path / "logs"
    _seed_sample_db(db_path)

    # Ensure headless_check=True never creates NetdoctorGuiApp
    def fail_if_called(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("NetdoctorGuiApp must not be instantiated when headless_check=True")

    monkeypatch.setattr(gui_mod, "NetdoctorGuiApp", fail_if_called)
    snap = launch_gui(
        db_path=str(db_path),
        logs_dir=str(logs_dir),
        configs_dir=str(configs_dir),
        lists_dir=str(lists_dir),
        headless_check=True,
    )
    assert snap["decisions_count"] == 3
    assert len(snap["domain_rows"]) == 3
    assert snap["running"] is False
    assert "network_key" in snap

    ctrl = NetdoctorController(
        db_path=db_path,
        configs_dir=configs_dir,
        lists_dir=lists_dir,
        logs_dir=logs_dir,
    )
    assert isinstance(ctrl.backend, GuiBackend)
    ctrl_snap = ctrl.get_status_snapshot()
    assert ctrl_snap["decisions_count"] == 3

    applied = ctrl.trigger_apply_configs()
    assert Path(applied["winws2_preset"]).is_file()
    assert Path(applied["singbox_config"]).is_file()

    stopped = ctrl.trigger_stop()
    assert stopped == []

    reval = ctrl.trigger_revalidate()
    assert "network_key" in reval and "rotations" in reval


def test_gui_pure_helpers() -> None:
    assert normalize_domain("  HTTPS://Discord.COM:443/channels/@me?foo=1 ") == "discord.com"
    assert row_iid({"domain": "discord.com", "protocol": "tls"}) == "discord.com|tls"
    assert row_matches({"domain": "discord.com", "layer": "dpi"}, "disc", "ALL") is True
    assert row_matches({"domain": "discord.com", "layer": "dpi"}, "disc", "vpn") is False
    assert row_tag({"status": "expired", "layer": "dpi"}) == "expired"
    assert row_tag({"status": "active", "consecutive_fails": 2, "layer": "dpi"}) == "degraded"
    assert row_tag({"status": "active", "consecutive_fails": 0, "layer": "vpn"}) == "vpn"

    lines = format_probe_lines(
        {
            "dns": {"system": "ok", "doh": "ok", "doh_ips": ["1.2.3.4"]},
            "tcp": {"result": "ok", "rtt_ms": 15.2, "target_ip": "1.2.3.4"},
            "tls": {"real_sni": "reset", "neutral_sni": "ok", "ttfb_ms": 40.0},
            "stall": {"result": "ok", "bytes_read": 1024, "throughput_kbps": 2000.0},
            "quic": {"result": "timeout", "rtt_ms": None},
            "protocol_tunnel": {"result": "skipped"},
        }
    )
    labels = [lbl for lbl, _txt, _st in lines]
    assert labels == ["DNS", "TCP", "TLS", "Stall", "QUIC"]


def test_netdoctor_gui_app_withdrawn_table_filter_and_selection(tmp_path: Path) -> None:
    db_path = tmp_path / "app.db"
    _seed_sample_db(db_path)
    backend = GuiBackend(
        db_path=db_path,
        configs_dir=tmp_path / "configs",
        lists_dir=tmp_path / "lists",
        logs_dir=tmp_path / "logs",
        bin_dir=tmp_path / "bin",
    )

    try:
        app = NetdoctorGuiApp(backend=backend, auto_start=False)
    except tk.TclError as exc:
        pytest.skip(f"Tcl/Tk display unavailable: {exc}")

    try:
        app.withdraw()
        app.update_idletasks()

        app.catalog = backend.get_strategies_catalog()
        snap = backend.get_status_snapshot()
        app.apply_snapshot(snap)

        assert list(app.domain_tree.get_children()) == [
            "blocked-ip.example|tls",
            "discord.com|quic",
            "discord.com|tls",
        ]
        assert set(app.rows_by_iid.keys()) == {
            "blocked-ip.example|tls",
            "discord.com|quic",
            "discord.com|tls",
        }
        assert f"AS{snap['network_asn']}" in app.network_label.cget("text")

        # Select a domain row and verify inspector + override comboboxes update
        app.domain_tree.selection_set("discord.com|tls")
        app.on_domain_select()
        assert app.selected_row is not None
        assert app.selected_row["domain"] == "discord.com"
        assert app.selected_row["protocol"] == "tls"
        assert app.override_layer_var.get() == "dpi"
        assert app.override_strategy_var.get() == "tls_multisplit_pos2"
        inspector_text = app.inspector.get("1.0", "end-1c")
        assert "sni_dpi" in inspector_text
        assert "tls_multisplit_pos2" in inspector_text
        assert "--lua-desync=" in inspector_text

        # Filter by search query matching selected row keeps selection intact
        app.search_var.set("discord")
        app.update_idletasks()
        assert list(app.domain_tree.get_children()) == ["discord.com|quic", "discord.com|tls"]
        assert app.selected_row is not None
        assert app.selected_row["domain"] == "discord.com"

        # Filter by layer that excludes selected row clears selection cleanly
        app.search_var.set("")
        app.layer_filter_var.set("vpn")
        app.populate_domain_table()
        assert list(app.domain_tree.get_children()) == ["blocked-ip.example|tls"]
        assert app.selected_row is None

        # Verify VPN table & config preview setter work cleanly
        app.populate_vpn_table([{"tag": "vless-eu", "protocol": "vless", "server": "198.51.100.5", "server_port": 443}])
        assert list(app.vpn_tree.get_children()) == ["n0"]
        app.set_previews({"configs/winws2_preset.txt": "--filter-tcp=443\n"})
        assert app.file_var.get() == "configs/winws2_preset.txt"
        assert "--filter-tcp=443" in app.preview.get("1.0", "end-1c")
    finally:
        app.on_close()


def test_gui_redesign_pure_helpers() -> None:
    assert gui_mod.strip_ansi("\x1b[36mINFO\x1b[0m \x1b[31mERROR\x1b[0m ok") == "INFO ERROR ok"
    assert gui_mod.strip_ansi("") == ""
    assert "sni_dpi" in gui_mod.verdict_human_label("sni_dpi")
    assert gui_mod.verdict_human_label("custom_code") == "custom_code"

    alert = gui_mod.detect_log_alert(
        "sing-box.log",
        "ERROR router: process DNS packet: tls: failed to verify certificate: "
        "x509: cannot validate certificate for 188.114.97.1 because it doesn't contain any IP SANs",
    )
    assert alert is not None and "188.114.97.1" in alert
    assert gui_mod.detect_log_alert("winws2.log", "x509: cannot validate certificate for 188.114.97.1 because it doesn't contain any IP SANs") is None
    assert gui_mod.detect_log_alert("sing-box.log", "") is None


def test_gui_redesign_interactive_behaviors(tmp_path: Path) -> None:
    db_path = tmp_path / "redesign.db"
    _seed_sample_db(db_path)
    backend = GuiBackend(
        db_path=db_path,
        configs_dir=tmp_path / "configs",
        lists_dir=tmp_path / "lists",
        logs_dir=tmp_path / "logs",
        bin_dir=tmp_path / "bin",
    )

    try:
        app = NetdoctorGuiApp(backend=backend, auto_start=False)
    except tk.TclError as exc:
        pytest.skip(f"Tcl/Tk display unavailable: {exc}")

    try:
        app.withdraw()
        app.update_idletasks()
        snap = backend.get_status_snapshot()
        app.catalog = backend.get_strategies_catalog()
        app.apply_snapshot(snap)

        # Sidebar navigation sync & count badges (both direct _select_tab and notebook.select + event pump)
        assert app._nav_items[str(app.tab_domains)][4].cget("text") == "3/3"
        app._select_tab(app.tab_dns)
        assert app._nav_items[str(app.tab_dns)][1].cget("bg") == gui_mod.ACCENT
        app.notebook.select(app.tab_service)
        app.update()
        assert app._nav_items[str(app.tab_service)][1].cget("bg") == gui_mod.ACCENT

        # Domain layer filter pills stay synced with layer_filter_var
        app._set_domain_layer_filter("dpi")
        assert app.layer_filter_var.get() == "dpi"
        assert list(app.domain_tree.get_children()) == ["discord.com|quic", "discord.com|tls"]
        app._set_domain_layer_filter("ALL")
        assert len(app.domain_tree.get_children()) == 3

        # Sorting direction toggles cleanly and preserves all items
        app.sort_domains("domain")
        desc_children = list(app.domain_tree.get_children())
        assert desc_children == ["discord.com|tls", "discord.com|quic", "blocked-ip.example|tls"]

        # Connections health filter pills filter & restore cleanly
        conns = [
            {
                "process": "chrome.exe",
                "domain": "youtube.com",
                "remote": "142.250.1.1:443",
                "protocol": "tls",
                "socket_status": "SYN_SENT",
                "layer": "direct",
                "strategy_id": None,
                "health": "needs_fix",
            },
            {
                "process": "Discord.exe",
                "domain": "discord.com",
                "remote": "162.159.135.232:443",
                "protocol": "tls",
                "socket_status": "ESTABLISHED",
                "layer": "dpi",
                "strategy_id": "tls_multisplit_pos2",
                "health": "protected",
            },
        ]
        app.populate_connections_table(conns, events=[])
        assert len(app.conn_tree.get_children()) == 2
        app._set_conn_health_filter("needs_fix")
        assert len(app.conn_tree.get_children()) == 1
        app._set_conn_health_filter("ALL")
        assert len(app.conn_tree.get_children()) == 2

        # ANSI log cleaning & DoH cert alert bar show/hide
        app.log_var.set("sing-box.log")
        app._apply_log(
            "sing-box.log",
            "\x1b[31mERROR\x1b[0m router: cannot validate certificate for 188.114.97.1 because it doesn't contain any IP SANs\n",
        )
        log_txt = app.log_view.get("1.0", "end-1c")
        assert "\x1b" not in log_txt
        assert "188.114.97.1" in log_txt
        assert bool(app._log_alert_bar.winfo_manager()) is True

        app._apply_log("sing-box.log", "\x1b[36mINFO\x1b[0m sing-box started cleanly\n")
        assert bool(app._log_alert_bar.winfo_manager()) is False

        # Quick-start guide bar can be dismissed
        assert app._guide_visible is True
        app._toggle_home_guide()
        assert app._guide_visible is False
    finally:
        app.on_close()


def test_gui_minsize_layout_no_clipping_and_dns_alert(tmp_path: Path) -> None:
    from netdoctor.orchestrators import BUILTIN_DNS_CATALOG

    db_path = tmp_path / "minsize.db"
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    _seed_sample_db(db_path)

    backend = GuiBackend(
        db_path=db_path,
        configs_dir=tmp_path / "configs",
        lists_dir=tmp_path / "lists",
        logs_dir=logs_dir,
        bin_dir=tmp_path / "bin",
    )

    # Active broken DoH server (zapret_dns) triggers snapshot dns_alert; switching to comss_dns clears it
    backend.select_dns_server("zapret_dns")
    (logs_dir / "sing-box.log").write_text(
        "ERROR router: tls: failed to verify certificate: "
        "x509: cannot validate certificate for 188.114.97.1 because it doesn't contain any IP SANs\n",
        encoding="utf-8",
    )
    snap_with_alert = backend.get_status_snapshot()
    assert snap_with_alert.get("dns_alert")
    assert "188.114.97.1" in str(snap_with_alert["dns_alert"])

    try:
        app = NetdoctorGuiApp(backend=backend, auto_start=False)
    except tk.TclError as exc:
        pytest.fail(f"Tk initialization must succeed cleanly on Windows/desktop: {exc}")

    try:
        app.geometry("1040x700+40+40")
        app.attributes("-alpha", 0.0)
        app.deiconify()
        app.update_idletasks()
        app.update()

        snap_with_alert["network_isp"] = "Very Long Super Rostelecom Macroregional South ISP Name"
        snap_with_alert["external_bypass_active"] = True
        app.apply_snapshot(snap_with_alert)
        app.render_dns_grid([dict(s, alive=True, ping_ms=34.0) for s in BUILTIN_DNS_CATALOG[:12]], "comss_dns")

        app._select_tab(app.tab_home)
        app.update_idletasks()
        app.update()

        assert bool(app._home_alert_frame.winfo_manager()) is True
        assert bool(app.bypass_label.winfo_manager()) is True
        assert app.bypass_label.winfo_height() >= 18
        assert app.network_label.winfo_width() >= app.network_label.winfo_reqwidth()

        tools_card = app.unlocker_status_label.master.master
        assert tools_card.winfo_height() >= tools_card.winfo_reqheight() - 2
        assert app.unlocker_status_label.winfo_height() >= 14

        app._select_tab(app.tab_dns)
        app.update_idletasks()
        app.update()
        assert app.dns_grid_frame.winfo_reqwidth() <= app.dns_canvas.winfo_width() + 5

        app._select_tab(app.tab_service)
        app.update_idletasks()
        app.update()
        assert app.tab_service.winfo_reqheight() <= app.tab_service.winfo_height() + 5

        # Domains inspector rule management panel scales responsively and supports vertical scrolling
        app._select_tab(app.tab_domains)
        app.update_idletasks()
        app.update()
        assert app.rule_canvas.winfo_width() >= 295
        assert app._rule_form_frame.winfo_width() == app.rule_canvas.winfo_width()
        bbox = app.rule_canvas.bbox("all")
        assert bbox is not None and bbox[3] >= app._rule_form_frame.winfo_reqheight() - 2
        assert app.pin_btn.winfo_height() >= 22
        assert app.unpin_btn.winfo_height() >= 22
        # Verify vertical scrolling works when rule form exceeds canvas height or on mousewheel
        app.rule_canvas.yview_moveto(1.0)
        app.update_idletasks()
        assert app.rule_canvas.yview()[1] >= 0.99
        app.rule_canvas.yview_moveto(0.0)
        app.update_idletasks()

        # Clearing alert removes dashboard alert banner
        (logs_dir / "sing-box.log").write_text("INFO started cleanly\n", encoding="utf-8")
        backend.select_dns_server("comss_dns")
        clean_snap = backend.get_status_snapshot()
        clean_snap["external_bypass_active"] = False
        assert clean_snap.get("dns_alert") is None
        app.apply_snapshot(clean_snap)
        app._select_tab(app.tab_home)
        app.update_idletasks()
        assert bool(app._home_alert_frame.winfo_manager()) is False
        assert bool(app.bypass_label.winfo_manager()) is False

        # Inspector preserves state cleanly across unchanged snapshot ticks
        app.domain_tree.selection_set("discord.com|tls")
        app.on_domain_select()
        sig_before = app._inspector_sig
        app.show_inspector(app.selected_row, sync_controls=False)
        assert app._inspector_sig == sig_before
    finally:
        app.on_close()


def test_elevate_gui_shellexecute_and_detached_launcher(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[Any, ...]] = []
    return_codes = iter([42, 5])

    class FakeShellExecute:
        argtypes: list[Any] = []
        restype: Any = None

        def __call__(self, *args: Any) -> int:
            calls.append(args)
            return next(return_codes)

    fake_shell32 = SimpleNamespace(ShellExecuteW=FakeShellExecute())
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(backend_mod.ctypes, "WinDLL", lambda name, **_kw: fake_shell32)
    monkeypatch.setattr(backend_mod.ctypes, "get_last_error", lambda: 1223)

    ok_res = backend_mod.elevate_gui(
        db_path=tmp_path / "net.db",
        configs_dir=tmp_path / "configs",
        lists_dir=tmp_path / "lists",
        logs_dir=tmp_path / "logs",
        working_dir=tmp_path,
        replace_pid=1234,
        auto_start=True,
    )
    assert ok_res["ok"] is True
    assert ok_res["launched"] is True
    hwnd, op, target_exe, params, cwd, show_cmd = calls[0]
    assert hwnd is None
    assert op == "runas"
    assert Path(target_exe).name.lower() in {"netdoctor-gui.exe", "pythonw.exe", "python.exe"}
    assert "--replace-pid 1234" in params
    assert "--auto-start" in params
    assert cwd == str(tmp_path.resolve())
    assert show_cmd == 1

    cancel_res = backend_mod.elevate_gui(
        db_path=tmp_path / "net.db",
        working_dir=tmp_path,
        minimized=True,
    )
    assert cancel_res["ok"] is False
    assert cancel_res["cancelled"] is True
    assert calls[1][5] == 0

    popen_calls: list[tuple[list[str], dict[str, Any]]] = []

    def fake_popen(cmd: list[str], **kwargs: Any) -> Any:
        popen_calls.append((list(cmd), dict(kwargs)))
        return SimpleNamespace(pid=9999)

    monkeypatch.setattr(backend_mod.subprocess, "Popen", fake_popen)
    det = backend_mod.launch_gui_detached(
        db_path=tmp_path / "net.db",
        configs_dir=tmp_path / "configs",
        lists_dir=tmp_path / "lists",
        logs_dir=tmp_path / "logs",
        working_dir=tmp_path,
        auto_start=True,
        minimized=True,
        no_elevate=True,
    )
    assert det["ok"] is True and det["pid"] == 9999
    det_cmd, det_kwargs = popen_calls[0]
    assert "--auto-start" in det_cmd and "--minimized" in det_cmd and "--no-elevate" in det_cmd
    assert det_kwargs["cwd"] == str(tmp_path.resolve())
    no_win = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    if no_win:
        assert (det_kwargs["creationflags"] & no_win) == no_win


def test_gui_main_auto_elevate_no_elevate_and_headless(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    elev_calls: list[dict[str, Any]] = []
    launch_calls: list[dict[str, Any]] = []
    terminated: list[int] = []

    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(gui_mod, "elevate_gui", lambda **kw: elev_calls.append(kw) or {"ok": True, "launched": True})
    monkeypatch.setattr(
        gui_mod,
        "launch_gui",
        lambda **kw: launch_calls.append(kw) or {"network_key": "AS123:home:default", "running": False},
    )
    monkeypatch.setattr(gui_mod, "terminate_pid_gracefully", lambda pid: terminated.append(pid) or True)

    # 1. Non-admin triggers elevate_gui automatically and does not start Tk loop in non-admin process
    monkeypatch.setattr(gui_mod, "_is_admin", lambda: False)
    rc1 = gui_mod.main(["--db", str(tmp_path / "a.db"), "--minimized"])
    assert rc1 == 0
    assert len(elev_calls) == 1
    assert elev_calls[0]["minimized"] is True
    assert len(launch_calls) == 0

    # 2. --no-elevate skips elevation and launches directly
    rc2 = gui_mod.main(["--db", str(tmp_path / "a.db"), "--no-elevate"])
    assert rc2 == 0
    assert len(elev_calls) == 1
    assert len(launch_calls) == 1 and launch_calls[0]["headless_check"] is False

    # 3. Admin + --replace-pid terminates old PID before launch_gui
    monkeypatch.setattr(gui_mod, "_is_admin", lambda: True)
    rc3 = gui_mod.main(["--db", str(tmp_path / "a.db"), "--replace-pid", "777"])
    assert rc3 == 0
    assert terminated == [777]
    assert len(launch_calls) == 2

    # 4. --headless-check prints JSON snapshot without elevation
    monkeypatch.setattr(gui_mod, "_is_admin", lambda: False)
    rc4 = gui_mod.main(["--db", str(tmp_path / "a.db"), "--headless-check"])
    assert rc4 == 0
    out = capsys.readouterr().out
    assert json.loads(out)["network_key"] == "AS123:home:default"


def test_cli_cmd_gui_elevate_detach_and_headless(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import netdoctor.cli as cli_mod

    elev_calls: list[dict[str, Any]] = []
    det_calls: list[dict[str, Any]] = []
    launch_calls: list[dict[str, Any]] = []

    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(cli_mod, "elevate_gui", lambda **kw: elev_calls.append(kw) or {"ok": True, "launched": True})
    monkeypatch.setattr(cli_mod, "launch_gui_detached", lambda **kw: det_calls.append(kw) or {"ok": True, "pid": 555})
    monkeypatch.setattr(
        cli_mod,
        "launch_gui",
        lambda **kw: launch_calls.append(kw) or {"network_key": "AS123:home:default", "decisions_count": 0},
    )

    # 1. Non-admin elevates without blocking console
    monkeypatch.setattr(cli_mod, "_is_admin", lambda: False)
    cli_mod.cmd_gui(db_path=str(tmp_path / "c.db"), headless_check=False, no_elevate=False, foreground=False)
    assert len(elev_calls) == 1
    assert len(det_calls) == 0 and len(launch_calls) == 0

    # 2. Admin with console detaches cleanly
    monkeypatch.setattr(cli_mod, "_is_admin", lambda: True)
    monkeypatch.setattr(cli_mod, "_has_console_window", lambda: True)
    cli_mod.cmd_gui(db_path=str(tmp_path / "c.db"), headless_check=False, no_elevate=False, foreground=False)
    assert len(det_calls) == 1
    assert len(launch_calls) == 0

    # 3. --headless-check runs synchronously and prints JSON
    cli_mod.cmd_gui(db_path=str(tmp_path / "c.db"), headless_check=True)
    assert len(launch_calls) == 1 and launch_calls[0]["headless_check"] is True
    assert "network_key" in json.loads(capsys.readouterr().out)


def test_app_icon_and_elevated_shortcut_unicode(tmp_path: Path) -> None:
    from netdoctor.tray import create_gui_shortcut, write_app_icon

    ico_file = write_app_icon(tmp_path / "netdoctor.ico")
    raw_ico = ico_file.read_bytes()
    assert raw_ico[:6] == b"\x00\x00\x01\x00\x01\x00"
    assert len(raw_ico) == 4286
    assert raw_ico[6] == 32 and raw_ico[7] == 32

    if sys.platform != "win32":
        pytest.skip("Windows .lnk creation only supported on Windows")

    uni_dir = tmp_path / "Максим тест"
    uni_dir.mkdir(parents=True, exist_ok=True)
    fake_exe = uni_dir / "netdoctor-gui.exe"
    fake_exe.write_bytes(b"MZ")
    lnk_path = uni_dir / "Netdoctor.lnk"

    res = create_gui_shortcut(
        lnk_path,
        fake_exe,
        working_dir=uni_dir,
        icon_path=ico_file,
        run_as_admin=True,
    )
    assert res["ok"] is True and lnk_path.is_file()

    raw_lnk = lnk_path.read_bytes()
    link_flags = struct.unpack_from("<I", raw_lnk, 20)[0]
    assert (link_flags & 0x00002000) == 0x00002000

    ps_script = (
        "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
        f"$s=(New-Object -ComObject WScript.Shell).CreateShortcut('{str(lnk_path).replace(chr(39), chr(39)*2)}'); "
        "Write-Output ($s.TargetPath + '|' + $s.WorkingDirectory)"
    )
    encoded = base64.b64encode(ps_script.encode("utf-16le")).decode("ascii")
    readback = subprocess.run(
        ["powershell.exe", "-NoProfile", "-EncodedCommand", encoded],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=15,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    assert readback.returncode == 0
    t_path, w_dir = readback.stdout.strip().split("|", 1)
    assert t_path == str(fake_exe.resolve())
    assert w_dir == str(uni_dir.resolve())


def test_subprocess_calls_use_create_no_window(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import netdoctor.supervisor as sup_mod

    no_win = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    if not no_win:
        pytest.skip("CREATE_NO_WINDOW only exists on Windows")

    bin_dir = tmp_path / "bin"
    logs_dir = tmp_path / "logs"
    bin_dir.mkdir(parents=True, exist_ok=True)
    dummy_exe = bin_dir / "dummy.exe"
    dummy_exe.write_bytes(b"MZ")

    sup_popen_flags: list[int] = []

    class FakeProc:
        pid = 4321

        def poll(self) -> None:
            return None

    def fake_sup_popen(*_args: Any, **kwargs: Any) -> FakeProc:
        sup_popen_flags.append(int(kwargs.get("creationflags", 0)))
        return FakeProc()

    monkeypatch.setattr(sup_mod.subprocess, "Popen", fake_sup_popen)
    sup = sup_mod.ProcessSupervisor(bin_dir=bin_dir, logs_dir=logs_dir)
    sup.start_process("dummy", [str(dummy_exe)], cwd=bin_dir)
    assert sup_popen_flags and (sup_popen_flags[0] & no_win) == no_win

    run_flags: list[int] = []

    def fake_run(*_args: Any, **kwargs: Any) -> Any:
        run_flags.append(int(kwargs.get("creationflags", 0)))
        return SimpleNamespace(returncode=0, stdout="Successfully flushed", stderr="")

    monkeypatch.setattr(backend_mod.subprocess, "run", fake_run)
    backend = GuiBackend(
        db_path=tmp_path / "nw.db",
        configs_dir=tmp_path / "configs",
        lists_dir=tmp_path / "lists",
        logs_dir=logs_dir,
        bin_dir=bin_dir,
    )
    flush_res = backend.flush_windows_dns_cache()
    assert flush_res["ok"] is True
    assert run_flags and (run_flags[0] & no_win) == no_win
