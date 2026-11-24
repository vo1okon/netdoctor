"""Comprehensive tests for Zapret2 presets, Telegram/QUIC fixes, connectivity tests, watchdog, and unified GUI."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import time
import tkinter as tk
from pathlib import Path
from typing import Any

import httpx
import psutil
import pytest

from netdoctor.cli import _resolve_winws2_live_args, build_winws2_launch_cmd
from netdoctor.config_gen import generate_singbox_config, generate_winws2_config, to_cygwin_safe_path
from netdoctor.gui import NetdoctorGuiApp
from netdoctor.gui_backend import GuiBackend
from netdoctor.models import Decision, Protocol, VerdictClass
from netdoctor.orchestrators import RealtimeConnectionMonitor, _is_telemetry_noise_domain, parse_windows_hosts_file
from netdoctor.presets import (
    clear_builtin_presets_cache,
    compile_zapret_preset,
    discover_builtin_zapret_presets,
    import_preset_from_file,
    parse_bat_to_winws2_text,
    save_user_zapret_preset,
    slugify_preset_id,
)
from netdoctor.probes import probe_domain_connectivity
from netdoctor.selector import DEFAULT_STRATEGIES, select_best_strategy
from netdoctor.storage import Storage
from netdoctor.supervisor import ProcessSupervisor

BUILTIN_WINWS2_BLOBS = {"fake_default_tls", "fake_default_http", "fake_default_quic"}
BLOB_REF_RE = re.compile(r"(?:blob|pattern|seqovl_pattern)=([A-Za-z0-9_]+)")


def test_builtin_zapret2_presets_discovery_and_zero_error_compilation() -> None:
    bin_path = Path("bin").resolve()
    lists_path = Path("lists").resolve()
    presets = discover_builtin_zapret_presets()
    z2_presets = [p for p in presets if p["source"] == "builtin_zapret2"]
    assert len(z2_presets) >= 30, f"Expected >=30 Zapret2 presets from C:\\vso\\Dev, got {len(z2_presets)}"

    names = {p["name"] for p in z2_presets}
    assert "general ALT1 1.9.9 (game filter)" in names
    assert "general FAKE TLS AUTO ALT2 1.10.3 (game filter)" in names
    assert "general ALT9 1.9.9 (game filter)" in names

    for p in presets:
        args = compile_zapret_preset(
            p["content"],
            bin_dir=bin_path,
            lists_dir=lists_path,
            vpn_server_ips=["1.2.3.4"],
            exclude_domains=["antigravity.google"],
        )
        assert len(args) >= 6, f"Compiled preset too short: {p['name']}"
        defined_blobs = set(BUILTIN_WINWS2_BLOBS)
        for tok in args:
            # No leaked positional tokens from unquoted `--name=YouTube · видео` lines
            assert tok.startswith("-"), f"Unexpected positional token {tok!r} in {p['name']}"
            if tok.startswith("--blob="):
                bname, bval = tok[len("--blob=") :].split(":", 1)
                defined_blobs.add(bname)
                if bval.startswith("@"):
                    ref = bval[1:]
                    fp = Path(ref) if Path(ref).is_absolute() else (bin_path / ref)
                    assert fp.is_file() and fp.stat().st_size > 0, f"Missing blob {tok} in {p['name']}"
            elif tok.startswith("--lua-init=@"):
                ref = tok[len("--lua-init=@") :]
                fp = Path(ref) if Path(ref).is_absolute() else (bin_path / ref)
                assert fp.is_file(), f"Missing lua {tok} in {p['name']}"
            elif tok.startswith("--wf-raw-part=@"):
                ref = tok[len("--wf-raw-part=@") :]
                fp = Path(ref) if Path(ref).is_absolute() else (bin_path / ref)
                assert fp.is_file(), f"Missing wf-raw-part {tok} in {p['name']}"
            elif tok.startswith(("--hostlist=", "--ipset=", "--hostlist-exclude=", "--ipset-exclude=")):
                _, ref = tok.split("=", 1)
                fp = Path(ref) if Path(ref).is_absolute() else (lists_path / ref)
                assert fp.is_file(), f"Missing list file {tok} in {p['name']}"
            elif tok.startswith("--lua-desync="):
                for m in BLOB_REF_RE.finditer(tok):
                    bref = m.group(1)
                    if bref.startswith("0x") or bref.isdigit():
                        continue
                    assert bref in defined_blobs, f"Undefined blob '{bref}' in {p['name']} ({tok})"

        live_args = _resolve_winws2_live_args(args, lists_path, bin_path=bin_path)
        for tok in live_args:
            assert all(ord(ch) < 128 for ch in tok), f"Non-ASCII Cygwin path leak in {p['name']}: {tok}"


def test_user_working_preset_snippet_bat_and_at_file_launch(tmp_path: Path) -> None:
    bin_path = Path("bin").resolve()
    lists_path = tmp_path / "lists"
    configs_path = tmp_path / "configs"

    # Empty / invalid inputs raise ValueError cleanly
    with pytest.raises(ValueError):
        compile_zapret_preset("", bin_dir=bin_path, lists_dir=lists_path)
    with pytest.raises(ValueError):
        compile_zapret_preset("# only comments\n", bin_dir=bin_path, lists_dir=lists_path)

    # Raw --lua-desync snippet is auto-wrapped into full TLS + Telegram + Discord UDP profiles
    snippet = "--lua-desync=fake:blob=tls_google:tcp_ts=-600000:repeats=6\n--lua-desync=fakedsplit:pattern=0x00:tcp_ts=-600000:repeats=6"
    wrapped = compile_zapret_preset(snippet, bin_dir=bin_path, lists_dir=lists_path, game_filter=True)
    assert "--ctrack-disable=0" in wrapped
    assert any(a.startswith("--blob=tls_google:") for a in wrapped)
    assert any("ipset-telegram.txt" in a for a in wrapped)
    assert (lists_path / "ipset-telegram.txt").is_file()
    assert any("--filter-l7=quic,discord,stun" in a for a in wrapped)

    # Zapret1 .bat conversion
    bat_text = (
        '@echo off\n'
        'start "" /min "%BIN%winws.exe" --wf-tcp=80,443 --wf-udp=443 ^\n'
        '--filter-tcp=443 --dpi-desync=fake,multisplit --dpi-desync-repeats=6 ^\n'
        '--dpi-desync-fooling=badseq --dpi-desync-fake-tls="%BIN%tls_clienthello_www_google_com.bin"\n'
    )
    converted = parse_bat_to_winws2_text(bat_text, preset_name="My Working Bat")
    assert "--lua-desync=fake:blob=tls_google" in converted
    assert "--lua-desync=multisplit:" in converted

    # Save & import .bat file into Storage
    st = Storage(tmp_path / "p.db")
    try:
        bat_file = tmp_path / "my_working.bat"
        bat_file.write_text(bat_text, encoding="utf-8")
        imported = import_preset_from_file(st, bat_file)
        assert imported["name"] == "my_working"
        assert imported["is_working"] is True
        assert "--lua-desync=" in imported["content"]

        with pytest.raises(ValueError):
            save_user_zapret_preset(st, name="Broken", content="--filter-tcp=443")
    finally:
        st.close()

    # Large args (> threshold) switch transparently to @winws2_live_at.txt
    small_cmd = build_winws2_launch_cmd(
        bin_path / "winws2.exe",
        ["--ctrack-disable=0", "--wf-tcp-out=443"],
        configs_dir=configs_path,
        bin_path=bin_path,
        at_file_threshold=500,
    )
    assert len(small_cmd) == 3

    big_args = ["--lua-desync=fake:blob=tls_google:repeats=6"] * 40
    big_cmd = build_winws2_launch_cmd(
        bin_path / "winws2.exe",
        big_args,
        configs_dir=configs_path,
        bin_path=bin_path,
        at_file_threshold=200,
    )
    assert len(big_cmd) == 2
    assert big_cmd[1].startswith("@")
    assert (configs_path / "winws2_live_at.txt").is_file()
    assert all(ord(ch) < 128 for ch in to_cygwin_safe_path(configs_path / "winws2_live_at.txt", base_dir=bin_path))


def test_telegram_hosts_not_excluded_and_winws2_config_has_telegram_ipset(tmp_path: Path) -> None:
    hosts_file = tmp_path / "hosts"
    hosts_file.write_text(
        "# --- Telegram Proxy ---\n"
        "149.154.167.220 t.me\n"
        "149.154.167.220 telegram.org\n"
        "149.154.167.220 api.telegram.org\n"
        "# Antigravity Unlocker\n"
        "45.10.20.30 antigravity.google\n"
        "45.10.20.30 cloudcode-pa.googleapis.com\n",
        encoding="utf-8",
    )
    parsed = parse_windows_hosts_file(hosts_file)
    assert "antigravity.google" in parsed["domains"]
    assert "45.10.20.30" in parsed["proxy_ips"]
    # Telegram domains & DC2 IP must NEVER be put into Unlocker Guard exclusions!
    assert "t.me" not in parsed["domains"]
    assert "telegram.org" not in parsed["domains"]
    assert "api.telegram.org" not in parsed["domains"]
    assert "149.154.167.220" not in parsed["proxy_ips"]

    lists_dir = tmp_path / "lists"
    strategies = {s.id: s for s in DEFAULT_STRATEGIES}
    dec = Decision(
        network_key="AS12389:home:test",
        domain="youtube.com",
        protocol=Protocol.TLS,
        layer="dpi",
        strategy_id="tls_alt1_199_fake_fakedsplit",
    )
    args, _hostlists = generate_winws2_config(
        decisions=[dec],
        strategies=strategies,
        lists_dir=lists_dir,
        vpn_server_ips=["45.10.20.30"],
        game_filter=True,
        enable_telegram_ipset=True,
    )
    assert "--ctrack-disable=0" in args
    assert "--ipcache-lifetime=8400" in args
    assert "--ipcache-hostname=1" in args
    assert any("ipset-telegram.txt" in a for a in args)
    assert (lists_dir / "ipset-telegram.txt").is_file()
    assert any("--filter-l7=discord,stun" in a for a in args)


@pytest.mark.asyncio
async def test_selector_quic_block_does_not_false_positive_tls_and_expanded_catalog() -> None:
    assert len(DEFAULT_STRATEGIES) >= 35
    ids = {s.id for s in DEFAULT_STRATEGIES}
    for orig in (
        "tls_multisplit_pos2",
        "tls_multisplit_sni",
        "tls_fakedsplit_pos2",
        "tls_fake_repeats6",
        "tls_multidisorder_seqovl",
        "tls_hostfakesplit_ozon",
        "tls_hostfakesplit_google",
        "tls_alt1_199_fake_fakedsplit",
        "tls_fake_tls_auto_alt2_1103",
        "quic_fake_repeats6",
        "quic_fallback_tcp",
    ):
        assert orig in ids

    # QUIC_BLOCK alone must NOT force TLS DPI desync on healthy HTTPS sites
    tls_dec = await select_best_strategy(
        network_key="AS12389:home:test",
        domain="assets.msn.com",
        ip="13.107.21.200",
        verdicts=[VerdictClass.QUIC_BLOCK],
        candidates=DEFAULT_STRATEGIES,
        protocol=Protocol.TLS,
    )
    assert tls_dec.layer == "direct"
    assert tls_dec.strategy_id is None

    # QUIC protocol itself still gets a QUIC strategy when QUIC_BLOCK is reported
    quic_dec = await select_best_strategy(
        network_key="AS12389:home:test",
        domain="youtube.com",
        ip="142.250.74.78",
        verdicts=[VerdictClass.QUIC_BLOCK],
        candidates=DEFAULT_STRATEGIES,
        protocol=Protocol.QUIC,
    )
    assert quic_dec.layer == "dpi"
    assert quic_dec.strategy_id is not None


def test_preset_lock_pinned_protection_and_demo_vpn_unblackhole(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = tmp_path / "lock.db"
    backend = GuiBackend(
        db_path=db_path,
        configs_dir=tmp_path / "configs",
        lists_dir=tmp_path / "lists",
        logs_dir=tmp_path / "logs",
        bin_dir=Path("bin").resolve(),
    )

    # Seed a demo-happ placeholder VPN node and stale non-pinned youtube.com -> vpn decision
    st = Storage(db_path)
    try:
        st.save_subscription(
            "demo-happ",
            "vless://11111111-2222-3333-4444-555555555555@de1.example.com:443#Demo",
            [
                {
                    "tag": "Demo-DE",
                    "protocol": "vless",
                    "server": "de1.example.com",
                    "server_port": 443,
                    "raw_outbound": {"type": "vless", "tag": "Demo-DE", "server": "de1.example.com", "server_port": 443},
                }
            ],
        )
        st.save_decision(
            Decision(
                network_key="AS12389:home:default",
                domain="youtube.com",
                protocol=Protocol.TLS,
                layer="vpn",
                strategy_id="vpn-select",
                pinned=False,
            )
        )
    finally:
        st.close()

    # Add and activate user working preset
    add_res = backend.add_user_zapret_preset(
        name="My Working ALT1",
        content="--lua-desync=fake:blob=tls_google:tcp_ts=-600000:repeats=6\n--lua-desync=fakedsplit:pattern=0x00:tcp_ts=-600000:repeats=6",
        description="Tested working",
        is_working=True,
        activate=True,
    )
    assert add_res["ok"] is True
    assert add_res["activated"] is True

    # Verify sing-box.json did NOT blackhole non-pinned youtube.com into demo de1.example.com VPN!
    sb_cfg = json.loads((tmp_path / "configs" / "sing-box.json").read_text(encoding="utf-8"))
    vpn_rules = [r for r in sb_cfg["route"]["rules"] if r.get("outbound") == "vpn-select"]
    for vr in vpn_rules:
        assert "youtube.com" not in (vr.get("domain_suffix") or [])

    # Mock a failing live connection -> auto_heal_connections must NOT spin when fixed preset is locked!
    monkeypatch.setattr(
        backend.orchestrator.monitor,
        "scan_active_connections",
        lambda *a, **kw: [
            {
                "process": "chrome.exe",
                "pid": 1234,
                "remote_ip": "142.250.74.78",
                "remote_port": 443,
                "remote": "142.250.74.78:443",
                "protocol": "tls",
                "socket_status": "SYN_SENT",
                "domain": "youtube.com",
                "layer": "direct",
                "strategy_id": None,
                "health": "needs_fix",
            }
        ],
    )
    tick = backend.run_realtime_auto_heal_tick(max_domains_per_tick=2)
    assert tick.get("preset_locked") is True
    assert tick["healed"] == []

    # Switch back to auto & pin youtube.com -> auto_heal must skip pinned decision without probing!
    backend.select_zapret_preset("auto")
    backend.pin_domain_strategy("youtube.com", "tls", "dpi", "tls_alt1_199_fake_fakedsplit", pinned=True)
    probed: list[str] = []

    async def _fail_if_probed(dom: str, *a: Any, **kw: Any) -> Any:
        probed.append(dom)
        raise AssertionError(f"Pinned domain {dom} should never be re-probed by auto-heal!")

    monkeypatch.setattr("netdoctor.orchestrators.run_domain_probes", _fail_if_probed)
    tick2 = backend.run_realtime_auto_heal_tick(max_domains_per_tick=2)
    assert tick2["healed"] == []
    assert probed == []


def test_connectivity_tests_success_rate_and_preset_scoring(tmp_path: Path) -> None:
    db_path = tmp_path / "tests.db"
    backend = GuiBackend(
        db_path=db_path,
        configs_dir=tmp_path / "configs",
        lists_dir=tmp_path / "lists",
        logs_dir=tmp_path / "logs",
        bin_dir=Path("bin").resolve(),
    )
    add_res = backend.add_user_zapret_preset(
        name="Working Preset",
        content="--lua-desync=fake:blob=tls_google:tcp_ts=-600000:repeats=6",
        activate=True,
    )
    pid = add_res["preset"]["id"]
    backend.pin_domain_strategy("youtube.com", "tls", "dpi", "tls_alt1_199_fake_fakedsplit")

    async def fake_probe(domain: str, *, url: str, service_group: str, proxy_url: str | None, timeout: float) -> dict[str, Any]:
        ok = "discord" not in domain  # YouTube & Telegram pass, Discord fails
        return {
            "domain": domain,
            "service_group": service_group,
            "url": url,
            "ok": ok,
            "status_code": 200 if ok else None,
            "latency_ms": 42.5 if ok else None,
            "stage": "https" if ok else "timeout",
            "error": "" if ok else "Timeout",
        }

    report = backend.run_connectivity_tests(include_key_services=True, probe_fn=fake_probe)
    assert report["ok"] is True
    assert report["total"] == 7
    assert report["passed"] == 5
    assert report["success_rate"] == pytest.approx(71.4, abs=0.2)

    summary = report["summary"]
    assert summary["by_service"]["youtube"]["ok"] is True
    assert summary["by_service"]["telegram"]["ok"] is True
    assert summary["by_service"]["discord"]["ok"] is False

    # Check enriched domain rows carry test metrics
    rows = backend.get_domain_rows()
    yt_row = next(r for r in rows if r["domain"] == "youtube.com")
    assert yt_row["pinned"] is True
    assert yt_row["test_total"] == 1
    assert yt_row["test_passed"] == 1
    assert yt_row["success_rate"] == 100.0
    assert yt_row["last_test_ok"] is True
    assert yt_row["last_test_latency_ms"] == 42.5

    # Active preset received the scored success_rate
    presets_info = backend.get_zapret_presets()
    saved_p = next(p for p in presets_info["presets"] if p["id"] == pid)
    assert saved_p["success_rate"] == pytest.approx(71.4, abs=0.2)


def test_winws2_watchdog_auto_restart_backoff_and_reload_dedup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    (logs_dir / "winws2.log").write_text("winws2 startup\nWinDivert error 577\n", encoding="utf-8")

    backend = GuiBackend(
        db_path=tmp_path / "wd.db",
        configs_dir=tmp_path / "configs",
        lists_dir=tmp_path / "lists",
        logs_dir=logs_dir,
        bin_dir=Path("bin").resolve(),
    )

    monkeypatch.setattr("netdoctor.gui_backend._is_admin", lambda: True)
    state = {
        "winws2": {"running": False, "pid": None, "status": "stopped"},
        "sing-box": {"running": True, "pid": 9999, "status": "running"},
        "tg-ws-proxy": {"running": True, "pid": 9998, "status": "running"},
    }
    monkeypatch.setattr(backend, "_collect_processes_state", lambda: dict(state))

    reloads: list[int] = []

    def fake_reload(iface: int | None = None) -> dict[str, Any]:
        reloads.append(1)
        state["winws2"] = {"running": True, "pid": 4321, "status": "running"}
        backend._last_winws2_hash = backend._winws2_args_hash(backend.trigger_apply_configs()["winws2_args"])
        backend._last_winws2_reload_ts = time.monotonic()
        return {"ok": True, "reloaded": True, "pid": 4321}

    monkeypatch.setattr(backend, "reload_winws2", fake_reload)

    # Watchdog detects dead winws2 while sing-box is running -> restarts it!
    res1 = backend.ensure_services_healthy(max_restarts_window=3, window_sec=300.0)
    assert res1["healthy"] is True
    assert res1["restarted"] == ["winws2"]
    assert "WinDivert error 577" in res1["crash_reason"]
    assert res1["restarts_count"] == 1
    assert len(reloads) == 1

    # While healthy, next tick does nothing
    res2 = backend.ensure_services_healthy()
    assert res2["healthy"] is True
    assert res2["restarted"] == []
    assert len(reloads) == 1

    # reload_winws2_if_changed skips when config args hash is unchanged!
    skip_res = backend.reload_winws2_if_changed(min_interval_sec=20.0)
    assert skip_res["reloaded"] is False
    assert skip_res["skipped"] == "unchanged"
    assert len(reloads) == 1

    # Repeated immediate crash triggers backoff; exceeding max_restarts_window caps restarts
    state["winws2"] = {"running": False, "pid": None, "status": "stopped"}
    res_backoff = backend.ensure_services_healthy(max_restarts_window=3, window_sec=300.0)
    assert res_backoff.get("backoff") is True
    assert len(reloads) == 1

    # Simulate window full -> capped=True
    now = time.monotonic()
    backend._watchdog_timestamps.clear()
    backend._watchdog_timestamps.extend([now - 5, now - 3, now - 1])
    backend._watchdog_next_retry_ts = 0.0
    res_cap = backend.ensure_services_healthy(max_restarts_window=3, window_sec=300.0)
    assert res_cap.get("capped") is True
    assert res_cap["healthy"] is False


def test_gui_unified_tab_presets_tab_and_home_layout_no_clipping(tmp_path: Path) -> None:
    db_path = tmp_path / "gui_new.db"
    backend = GuiBackend(
        db_path=db_path,
        configs_dir=tmp_path / "configs",
        lists_dir=tmp_path / "lists",
        logs_dir=tmp_path / "logs",
        bin_dir=Path("bin").resolve(),
    )
    backend.pin_domain_strategy("youtube.com", "tls", "dpi", "tls_alt1_199_fake_fakedsplit", pinned=True)
    backend.add_user_zapret_preset(
        name="User Best ALT1",
        content="--lua-desync=fake:blob=tls_google:tcp_ts=-600000:repeats=6",
        activate=True,
    )

    async def ok_probe(domain: str, *, url: str, service_group: str, proxy_url: str | None, timeout: float) -> dict[str, Any]:
        return {
            "domain": domain,
            "service_group": service_group,
            "url": url,
            "ok": True,
            "status_code": 200,
            "latency_ms": 38.0,
            "stage": "https",
            "error": "",
        }

    backend.run_connectivity_tests(include_key_services=True, probe_fn=ok_probe)

    try:
        app = NetdoctorGuiApp(backend=backend, auto_start=False)
    except tk.TclError as exc:
        pytest.skip(f"Tcl/Tk display unavailable: {exc}")

    try:
        app.geometry("1040x700+40+40")
        app.attributes("-alpha", 0.0)
        app.deiconify()
        app.update_idletasks()
        app.update()

        # Unified Domains + Live Connections tab (no duplicate tab!)
        assert app.tab_realtime is app.tab_domains

        snap = backend.get_status_snapshot()
        snap["external_bypass_active"] = True
        snap["dns_alert"] = "Test DNS alert banner to verify zero clipping at 1040x700"
        app.apply_snapshot(snap)
        presets_data = backend.get_zapret_presets()
        app.populate_presets_table(presets_data["presets"])

        app._select_tab(app.tab_home)
        app.update_idletasks()
        app.update()

        # Home page has active preset bar & service test pills with zero clipping at 1040x700
        assert "YouTube: 100%" in app._home_service_pills["youtube"].cget("text")
        assert "100%" in app.home_test_rate_pill.cget("text")
        assert "User Best ALT1" in app.home_preset_mode_pill.cget("text")
        tools_card = app.unlocker_status_label.master.master
        assert tools_card.winfo_height() >= tools_card.winfo_reqheight() - 2

        # Unified Domains tab: switch subviews cleanly and verify pinned + test % + inline socket count
        app.populate_connections_table(
            [
                {
                    "process": "chrome.exe",
                    "domain": "youtube.com",
                    "remote": "142.250.74.78:443",
                    "protocol": "tls",
                    "socket_status": "ESTABLISHED",
                    "layer": "dpi",
                    "strategy_id": "tls_alt1_199_fake_fakedsplit",
                    "health": "protected",
                }
            ],
            events=[],
        )
        yt_vals = app.domain_tree.item("youtube.com|tls", "values")
        assert "📌" in yt_vals[0]
        assert "✔" in yt_vals[5]
        assert "100%" in yt_vals[6]
        assert "⚡ 1" in yt_vals[7]

        app._switch_domains_subview("connections")
        assert app._domains_subview_mode == "connections"
        assert bool(app._conns_subview.winfo_manager()) is True
        app._switch_domains_subview("domains")
        assert app._domains_subview_mode == "domains"
        assert bool(app._domains_subview.winfo_manager()) is True

        # Presets tab lists user preset + >=30 built-in presets and filters cleanly
        assert len(app.presets_tree.get_children()) >= 30
        app._set_preset_filter("user")
        assert len(app.presets_tree.get_children()) == 1
        app._set_preset_filter("ALL")
        assert len(app.presets_tree.get_children()) >= 30
    finally:
        app.on_close()


def test_audit_fixes_deterministic_slugs_lua_guard_udp_pass_and_preset_cache(tmp_path: Path) -> None:
    expected_digest = hashlib.sha1("Ростелеком".encode("utf-8")).hexdigest()[:10]
    id1 = slugify_preset_id("Ростелеком", prefix="z2")
    id2 = slugify_preset_id("Ростелеком", prefix="z2")
    assert id1 == id2 == f"z2_{expected_digest}"

    bin_path = Path("bin").resolve()
    lists_path = tmp_path / "lists"

    # Unlocker Guard injects both TCP and UDP/443 pass profiles in full-preset mode,
    # and --hostlist-exclude on both TCP and QUIC/UDP profiles in snippet mode.
    full_args = compile_zapret_preset(
        "--filter-tcp=443\n--lua-desync=fake:blob=tls_google:repeats=6",
        bin_dir=bin_path,
        lists_dir=lists_path,
        exclude_domains=["antigravity.google"],
    )
    assert any(a == "--filter-udp=443" for a in full_args)
    assert any("exclude_unlocker_domains.txt" in a for a in full_args)

    snippet_args = compile_zapret_preset(
        "--lua-desync=fake:blob=tls_google:repeats=6",
        bin_dir=bin_path,
        lists_dir=lists_path,
        exclude_domains=["antigravity.google"],
    )
    udp_idx = snippet_args.index("--filter-l7=quic,discord,stun")
    udp_tail = snippet_args[udp_idx:]
    assert any(a.startswith("--hostlist-exclude=") and "exclude_unlocker_domains.txt" in a for a in udp_tail)

    # Missing Lua module + undefined custom function raises ValueError cleanly at compile time
    broken_preset = "\n".join(
        [
            "--lua-init=@lua/zapret-lib.lua",
            "--lua-init=@lua/nonexistent_module_16kb.lua",
            "--filter-tcp=443",
            "--lua-desync=undefined_custom_desync_fn:repeats=4",
        ]
    )
    with pytest.raises(ValueError, match="undefined_custom_desync_fn"):
        compile_zapret_preset(broken_preset, bin_dir=bin_path, lists_dir=lists_path)

    # Preset discovery cache returns independent shallow dicts (mutation-safe)
    clear_builtin_presets_cache()
    first = discover_builtin_zapret_presets()
    assert first
    first[0]["success_rate"] = 12.3
    second = discover_builtin_zapret_presets()
    assert second[0]["success_rate"] != 12.3


def test_audit_fixes_telegram_link_stack_modes_and_multi_service_watchdog(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = GuiBackend(
        db_path=tmp_path / "stack.db",
        configs_dir=tmp_path / "configs",
        lists_dir=tmp_path / "lists",
        logs_dir=tmp_path / "logs",
        bin_dir=Path("bin").resolve(),
    )

    # Persistent 32-hex secret & deep link format
    tg1 = backend.get_telegram_proxy_info()
    tg2 = backend.get_telegram_proxy_info()
    assert tg1["secret"] == tg2["secret"]
    assert len(tg1["secret"]) == 32
    assert tg1["dd_secret"] == f"dd{tg1['secret']}"
    assert tg1["url"] == f"tg://proxy?server=127.0.0.1&port=10808&secret=dd{tg1['secret']}"

    # Default tun_stack stays gvisor, set_tun_stack("mixed") propagates into sing-box.json
    applied_default = backend.trigger_apply_configs()
    assert applied_default["tun_stack"] == "gvisor"
    cfg_default = json.loads((tmp_path / "configs" / "sing-box.json").read_text(encoding="utf-8"))
    assert next(i for i in cfg_default["inbounds"] if i["type"] == "tun")["stack"] == "gvisor"

    backend.set_tun_stack("mixed")
    cfg_mixed = json.loads((tmp_path / "configs" / "sing-box.json").read_text(encoding="utf-8"))
    assert next(i for i in cfg_mixed["inbounds"] if i["type"] == "tun")["stack"] == "mixed"

    # dpi_only mode omits sing-box from process launch specs
    hybrid_names = [s[0] for s in backend._build_stack_specs(["--ctrack-disable=0"], tmp_path / "configs" / "sing-box.json")]
    assert "sing-box" in hybrid_names
    assert "winws2" in hybrid_names

    backend.set_stack_mode("dpi_only")
    dpi_only_names = [
        s[0] for s in backend._build_stack_specs(["--ctrack-disable=0"], tmp_path / "configs" / "sing-box.json")
    ]
    assert "sing-box" not in dpi_only_names
    assert "winws2" in dpi_only_names

    # Multi-service Watchdog: restarts dead sing-box & tg-ws-proxy, and rolls back broken preset on failure
    backend.set_stack_mode("hybrid")
    backend.add_user_zapret_preset(
        name="Unstable Custom",
        content="--lua-desync=fake:blob=tls_google:repeats=4",
        activate=True,
    )
    backend._desired_running = True
    monkeypatch.setattr("netdoctor.gui_backend._is_admin", lambda: True)
    proc_state = {
        "winws2": {"running": False, "pid": None, "status": "stopped"},
        "sing-box": {"running": False, "pid": None, "status": "stopped"},
        "tg-ws-proxy": {"running": False, "pid": None, "status": "stopped"},
    }
    monkeypatch.setattr(backend, "_collect_processes_state", lambda: dict(proc_state))
    monkeypatch.setattr(backend, "reload_singbox", lambda: {"ok": True, "reloaded": True, "pid": 111})
    monkeypatch.setattr(backend, "_restart_tg_ws_proxy", lambda: {"ok": True, "reloaded": True, "pid": 222})

    winws_attempts: list[str] = []

    def fake_winws_reload(iface: int | None = None) -> dict[str, Any]:
        st = Storage(backend.db_path)
        try:
            cur_pid = st.get_setting("active_zapret_preset_id", "auto")
        finally:
            st.close()
        winws_attempts.append(cur_pid)
        if len(winws_attempts) == 1:
            return {"ok": False, "reloaded": False, "error": "crash on custom preset"}
        proc_state["winws2"] = {"running": True, "pid": 333, "status": "running"}
        return {"ok": True, "reloaded": True, "pid": 333}

    monkeypatch.setattr(backend, "reload_winws2", fake_winws_reload)

    wd = backend.ensure_services_healthy()
    assert wd["healthy"] is True
    assert set(wd["restarted"]) == {"sing-box", "tg-ws-proxy", "winws2"}
    assert wd.get("fallback_switched_to") == "z2_general_alt1_1_9_9_game_filter"
    assert len(winws_attempts) == 2

    # Clean config check passes with generate_singbox_config mixed stack
    sb_mixed_cfg = generate_singbox_config([], tun_stack="system")
    assert next(i for i in sb_mixed_cfg["inbounds"] if i["type"] == "tun")["stack"] == "system"


def test_audit_fixes_telemetry_noise_filter_and_strict_16kb_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert _is_telemetry_noise_domain("aka.ms") is True
    assert _is_telemetry_noise_domain("a.nel.cloudflare.com") is True
    assert _is_telemetry_noise_domain("ocsp.digicert.com") is True
    assert _is_telemetry_noise_domain("healthy-unknown.example") is False
    assert _is_telemetry_noise_domain("youtube.com") is False

    # Scan keeps healthy ESTABLISHED connections direct and keeps failing telemetry noise out of needs_fix
    st = Storage(tmp_path / "noise.db")
    try:
        mon = RealtimeConnectionMonitor()
        mon.ip_to_domain["203.0.113.10"] = "aka.ms"
        mon.ip_to_domain["203.0.113.11"] = "healthy-unknown.example"

        class _Sock:
            def __init__(self, ip: str, port: int = 443, status: str = "ESTABLISHED") -> None:
                self.raddr = (ip, port)
                self.status = status
                self.pid = 4242
                self.type = 1

        monkeypatch.setattr(psutil, "net_connections", lambda kind="inet": [_Sock("203.0.113.10"), _Sock("203.0.113.11")])
        monkeypatch.setattr(mon, "_resolve_pid_name", lambda pid: "chrome.exe")

        rows_ok = mon.scan_active_connections(st, tmp_path / "logs", net_key="AS12389:home:test")
        by_dom_ok = {r["domain"]: r for r in rows_ok}
        assert by_dom_ok["aka.ms"]["health"] == "direct"
        assert by_dom_ok["healthy-unknown.example"]["health"] == "direct"

        monkeypatch.setattr(
            psutil,
            "net_connections",
            lambda kind="inet": [_Sock("203.0.113.10", status="SYN_SENT"), _Sock("203.0.113.11", status="SYN_SENT")],
        )
        rows_fail = mon.scan_active_connections(st, tmp_path / "logs", net_key="AS12389:home:test")
        by_dom_fail = {r["domain"]: r for r in rows_fail}
        assert by_dom_fail["aka.ms"]["health"] == "direct"
        assert by_dom_fail["healthy-unknown.example"]["health"] == "needs_fix"
    finally:
        st.close()

    # probe_domain_connectivity verifies TLS by default and flags <16KB stream cutoff as throttle_16kb
    captured_verify: list[Any] = []

    class _FakeStreamResp:
        def __init__(self) -> None:
            self.status_code = 200
            self.headers = {"content-type": "image/jpeg", "content-length": "65536"}

        async def __aenter__(self) -> "_FakeStreamResp":
            return self

        async def __aexit__(self, *args: Any) -> bool:
            return False

        async def aiter_bytes(self):
            yield b"a" * 8192

    class _FakeClient:
        def __init__(self, *, verify: Any = True, **kwargs: Any) -> None:
            captured_verify.append(verify)

        async def __aenter__(self) -> "_FakeClient":
            return self

        async def __aexit__(self, *args: Any) -> bool:
            return False

        def stream(self, method: str, url: str, headers: Any = None) -> _FakeStreamResp:
            return _FakeStreamResp()

    monkeypatch.setattr(httpx, "AsyncClient", _FakeClient)
    import asyncio

    probe_res = asyncio.run(
        probe_domain_connectivity(
            "i.ytimg.com",
            url="https://i.ytimg.com/vi/dQw4w9WgXcQ/hqdefault.jpg",
            min_bytes=16384,
        )
    )
    assert captured_verify == [True]
    assert probe_res["ok"] is False
    assert probe_res["stage"] == "throttle_16kb"


def test_cygwin_paths_never_emit_parent_traversal_and_work_from_usr_bin(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    lists_dir = tmp_path / "lists"
    configs_dir = tmp_path / "configs"
    (bin_dir / "files").mkdir(parents=True, exist_ok=True)
    lists_dir.mkdir(parents=True, exist_ok=True)

    blob_file = bin_dir / "files" / "stun.bin"
    blob_file.write_bytes(b"\x00\x01")
    hostlist_file = lists_dir / "tls_alt1_1103_fake_fakedsplit.txt"
    hostlist_file.write_text("discord.com\n", encoding="utf-8")

    # Files strictly inside bin_dir stay relative; sibling lists/ & configs/ NEVER emit '..'
    assert to_cygwin_safe_path(blob_file, base_dir=bin_dir) == "files/stun.bin"
    safe_list = to_cygwin_safe_path(hostlist_file, base_dir=bin_dir)
    assert ".." not in Path(safe_list).parts
    assert safe_list.isascii()

    live_args = _resolve_winws2_live_args(
        [
            f"--blob=stun:@{blob_file}",
            f"--hostlist={hostlist_file}",
            "--lua-desync=fake:blob=stun",
        ]
        + ["--lua-desync=fakedsplit:pos=2"] * 20,
        lists_dir,
        bin_path=bin_dir,
    )
    for tok in live_args:
        assert ".." not in tok, f"Unexpected parent traversal in winws2 live arg: {tok}"

    cmd = build_winws2_launch_cmd(
        bin_dir / "winws2.exe",
        live_args,
        configs_dir=configs_dir,
        bin_path=bin_dir,
        at_file_threshold=200,
    )
    assert len(cmd) == 2 and cmd[1].startswith("@")
    assert ".." not in cmd[1]

    # Verify against real bundled Cygwin runtime from /usr/bin (cwd = bin/cygwin/bin)
    cyg_bash = Path("bin/cygwin/bin/bash.exe").resolve()
    real_bin = Path("bin").resolve()
    real_list = Path("lists/tls_alt1_1103_fake_fakedsplit.txt")
    target_list = real_list.resolve() if real_list.is_file() else hostlist_file
    if cyg_bash.is_file():
        cyg_path = to_cygwin_safe_path(target_list, base_dir=real_bin)
        assert ".." not in Path(cyg_path).parts
        res = subprocess.run(
            [str(cyg_bash), "-c", 'test -r "$1" && echo OK', "_", cyg_path],
            cwd=str(cyg_bash.parent),
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert res.returncode == 0 and res.stdout.strip() == "OK", (
            f"Cygwin /usr/bin failed to read {cyg_path!r}: rc={res.returncode} err={res.stderr!r}"
        )


def test_realtime_auto_heal_tick_skips_when_stack_stopped_and_runs_when_active(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = GuiBackend(
        db_path=tmp_path / "rt.db",
        configs_dir=tmp_path / "configs",
        lists_dir=tmp_path / "lists",
        logs_dir=tmp_path / "logs",
        bin_dir=tmp_path / "bin",
    )

    monkeypatch.setattr(backend, "_collect_processes_state", lambda: {"winws2": {"running": False}, "sing-box": {"running": False}})
    monkeypatch.setattr(
        backend.orchestrator.monitor,
        "scan_active_connections",
        lambda *a, **kw: [
            {
                "process": "chrome.exe",
                "pid": 101,
                "remote_ip": "162.159.135.232",
                "remote_port": 443,
                "remote": "162.159.135.232:443",
                "protocol": "tls",
                "socket_status": "SYN_SENT",
                "domain": "discord.com",
                "layer": "direct",
                "strategy_id": None,
                "health": "needs_fix",
            }
        ],
    )

    probed_domains: list[str] = []

    async def fake_probes(dom: str, *a: Any, **kw: Any) -> Any:
        probed_domains.append(dom)
        raise AssertionError("run_domain_probes should not be called when stack is stopped")

    monkeypatch.setattr("netdoctor.orchestrators.run_domain_probes", fake_probes)

    stopped_res = backend.run_realtime_auto_heal_tick(max_domains_per_tick=2, require_running=True)
    assert stopped_res["stack_stopped"] is True
    assert stopped_res["healed"] == []
    assert probed_domains == []

    # When winws2 is reported running, auto_heal_connections proceeds normally
    monkeypatch.setattr(backend, "_collect_processes_state", lambda: {"winws2": {"running": True}, "sing-box": {"running": False}})
    auto_heal_calls: list[int] = []

    async def fake_auto_heal(_backend: Any, max_domains_per_tick: int = 2, timeout: float = 2.0) -> dict[str, Any]:
        auto_heal_calls.append(max_domains_per_tick)
        return {"connections": [], "healed": [{"domain": "discord.com", "layer": "dpi", "strategy_id": "tls_multisplit_pos2"}], "events": []}

    monkeypatch.setattr(backend.orchestrator.monitor, "auto_heal_connections", fake_auto_heal)

    active_res = backend.run_realtime_auto_heal_tick(max_domains_per_tick=2, require_running=True)
    assert auto_heal_calls == [2]
    assert len(active_res["healed"]) == 1


def test_supervisor_start_stack_surfaces_crash_log_tail(tmp_path: Path) -> None:
    sup = ProcessSupervisor(bin_dir=tmp_path, logs_dir=tmp_path / "logs")
    crash_cmd = [
        sys.executable,
        "-c",
        "import sys; sys.stderr.write('cannot access hostlist file missing.txt\\n'); sys.exit(1)",
    ]
    with pytest.raises(RuntimeError) as exc_info:
        sup.start_stack([("winws2", crash_cmd, tmp_path)], startup_wait=1.5)

    msg = str(exc_info.value)
    assert "Service 'winws2' exited prematurely on startup with code 1" in msg
    assert "cannot access hostlist file missing.txt" in msg


def test_physical_egress_iface_auto_bound_in_hybrid_mode_and_skipped_in_dpi_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from netdoctor.config_gen import detect_physical_egress_iface, detect_physical_egress_route

    phys_idx, phys_gw = detect_physical_egress_route()
    if phys_idx is not None:
        assert phys_idx > 0
        assert phys_gw and not phys_gw.startswith(("0.", "127.", "172.19.0."))
        assert detect_physical_egress_iface() == phys_idx

    backend = GuiBackend(
        db_path=tmp_path / "iface.db",
        configs_dir=tmp_path / "configs",
        lists_dir=tmp_path / "lists",
        logs_dir=tmp_path / "logs",
        bin_dir=Path("bin").resolve(),
    )
    monkeypatch.setattr("netdoctor.gui_backend.detect_physical_egress_iface", lambda: 10)
    monkeypatch.setattr("netdoctor.gui_backend.detect_physical_egress_route", lambda: (10, "192.168.50.1"))

    # Hybrid mode (auto orchestrator) -> auto-binds --wf-iface=10
    applied_auto = backend.trigger_apply_configs()
    assert applied_auto["winws2_iface"] == 10
    assert "--wf-iface=10" in applied_auto["winws2_args"]
    assert backend._detect_local_gateway_ip() == "10:192.168.50.1"

    # Hybrid mode (fixed Zapret2 preset) -> auto-binds --wf-iface=10
    backend.add_user_zapret_preset(
        name="Simple Test Preset",
        content="--lua-desync=fake:blob=tls_google:tcp_ts=-600000:repeats=6",
        activate=True,
    )
    applied_preset = backend.trigger_apply_configs()
    assert applied_preset["winws2_iface"] == 10
    assert "--wf-iface=10" in applied_preset["winws2_args"]

    # dpi_only mode (no TUN) -> does NOT force --wf-iface unless explicit iface is passed
    backend.set_stack_mode("dpi_only")
    applied_dpi_only = backend.trigger_apply_configs()
    assert applied_dpi_only["winws2_iface"] is None
    assert not any(a.startswith("--wf-iface=") for a in applied_dpi_only["winws2_args"])

    # Explicit iface always overrides in both modes
    applied_explicit = backend.trigger_apply_configs(iface=15)
    assert applied_explicit["winws2_iface"] == 15
    assert "--wf-iface=15" in applied_explicit["winws2_args"]


def test_default_tls_fake_strategies_have_fooling_and_eval_cmd_binds_iface() -> None:
    from netdoctor.selector import _build_winws2_eval_cmd

    fooling_tokens = ("tcp_ts=", "tcp_ack=", "tcp_md5", "badsum", "ip_autottl=", "ip_ttl=", "tcp_flags_unset=")
    for strat in DEFAULT_STRATEGIES:
        if strat.protocol != Protocol.TLS:
            continue
        for tok in strat.args_template:
            if any(fn in tok for fn in ("--lua-desync=fake:", "--lua-desync=fakedsplit:", "--lua-desync=hostfakesplit:")):
                assert any(ft in tok for ft in fooling_tokens), (
                    f"TLS fake strategy {strat.id} lacks fooling and would corrupt real streams: {tok}"
                )

    eval_cmd = _build_winws2_eval_cmd(
        Path("bin/winws2.exe"),
        DEFAULT_STRATEGIES[0],
        "youtube.com,www.youtube.com",
        iface=10,
    )
    assert "--wf-iface=10" in eval_cmd


def test_seed_default_strategies_syncs_updated_builtin_and_preserves_custom(tmp_path: Path) -> None:
    from netdoctor.models import Strategy

    db_path = tmp_path / "seed_sync.db"
    backend = GuiBackend(
        db_path=db_path,
        configs_dir=tmp_path / "configs",
        lists_dir=tmp_path / "lists",
        logs_dir=tmp_path / "logs",
        bin_dir=tmp_path / "bin",
    )
    st = Storage(db_path)
    try:
        st.upsert_strategies(
            [
                Strategy(
                    id="tls_fakedsplit_pos2",
                    family="fakedsplit",
                    protocol=Protocol.TLS,
                    tier=2,
                    args_template=["--lua-desync=fakedsplit:pos=2"],
                    description="stale built-in",
                ),
                Strategy(
                    id="bc2_tls_99",
                    family="fake",
                    protocol=Protocol.TLS,
                    tier=2,
                    args_template=["--lua-desync=fake:blob=tls_google:repeats=3"],
                    description="custom blockcheck strategy",
                ),
            ]
        )
        backend._seed_default_strategies(st)
        by_id = {s.id: s for s in st.get_strategies()}
        expected = next(s for s in DEFAULT_STRATEGIES if s.id == "tls_fakedsplit_pos2")
        assert by_id["tls_fakedsplit_pos2"].args_template == expected.args_template
        assert by_id["bc2_tls_99"].args_template == ["--lua-desync=fake:blob=tls_google:repeats=3"]
    finally:
        st.close()


def test_rdns_ptr_and_telemetry_noise_filtering_and_tail_rotation_parser(tmp_path: Path) -> None:
    from netdoctor.dynamics import parse_circular_rotations
    from netdoctor.orchestrators import _is_rdns_ptr_hostname

    for noisy in (
        "a2-18-121-68.deploy.static.akamaitechnologies.com",
        "ec2-184-198-67-230.compute-1.amazonaws.com",
        "server-18-244-146-86.waw51.r.cloudfront.net",
        "lcarnb-ac-in-f1.1e100.net",
        "34.224.186.35.bc.googleusercontent.com",
        "array811.prod.do.dsp.mp.microsoft.com",
        "spo-ring.msedge.net",
        "update.googleapis.com",
    ):
        assert _is_telemetry_noise_domain(noisy) is True, f"Expected noise domain: {noisy}"

    assert _is_rdns_ptr_hostname("yt3.googleusercontent.com") is False
    assert _is_telemetry_noise_domain("yt3.googleusercontent.com") is False
    assert _is_telemetry_noise_domain("youtube.com") is False

    mon = RealtimeConnectionMonitor()
    cands = mon._collect_fix_candidates(
        [
            {"domain": "a2-18-121-68.deploy.static.akamaitechnologies.com", "layer": "direct", "health": "needs_fix", "socket_status": "SYN_SENT", "process": "chrome.exe"},
            {"domain": "server-18-244-146-86.waw51.r.cloudfront.net", "layer": "direct", "health": "needs_fix", "socket_status": "SYN_SENT", "process": "chrome.exe"},
            {"domain": "youtube.com", "layer": "direct", "health": "needs_fix", "socket_status": "SYN_SENT", "process": "chrome.exe"},
        ],
        logs_dir=tmp_path / "logs",
        max_domains=5,
    )
    assert [c[0] for c in cands] == ["youtube.com"]

    large_log = tmp_path / "winws2_big.log"
    filler = ("packet: id=1 len=40 unmodified filler line\n" * 600)
    tail_block = (
        "hostname='old.example.com'\n"
        "circular: switching to strategy 2\n"
    )
    large_log.write_text(filler + tail_block, encoding="utf-8")
    rotations = parse_circular_rotations(large_log, max_bytes=4096)
    assert len(rotations) == 1
    assert rotations[0]["domain"] == "old.example.com"
    assert rotations[0]["strategy"] == 2


def test_supervisor_rejects_recycled_pid_on_create_time_mismatch(tmp_path: Path) -> None:
    import os
    from netdoctor.supervisor import inspect_supervisor_state, stop_persisted_supervisor

    logs_dir = tmp_path / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    live_pid = os.getpid()
    state_path = logs_dir / "supervisor_state.json"
    state_path.write_text(
        json.dumps(
            {
                "updated_at": "2026-11-23T00:00:00Z",
                "processes": {
                    "winws2": {
                        "pid": live_pid,
                        "running": True,
                        "create_time": 1000.0,  # Guaranteed mismatch with current test process create_time
                        "cmd": ["winws2.exe"],
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    inspected = inspect_supervisor_state(state_path=state_path)
    assert inspected["winws2"]["running"] is False

    sup = ProcessSupervisor(bin_dir=tmp_path / "bin", logs_dir=logs_dir, state_path=state_path)
    assert sup.adopt_persisted_state() == {}

    # Must NOT kill current live PID when create_time does not match!
    stopped = stop_persisted_supervisor(state_path=state_path)
    assert stopped == []
    assert psutil.pid_exists(live_pid)


def test_stack_mode_order_invalid_singbox_guard_backoff_and_unbuffered_tg(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bin_dir = tmp_path / "bin"
    tg_dir = bin_dir / "tg-ws-proxy" / "proxy"
    tg_dir.mkdir(parents=True, exist_ok=True)
    (tg_dir / "tg_ws_proxy.py").write_text("print('tg')\n", encoding="utf-8")
    (bin_dir / "winws2.exe").write_bytes(b"MZ")
    (bin_dir / "sing-box.exe").write_bytes(b"MZ")

    backend = GuiBackend(
        db_path=tmp_path / "stack.db",
        configs_dir=tmp_path / "configs",
        lists_dir=tmp_path / "lists",
        logs_dir=tmp_path / "logs",
        bin_dir=bin_dir,
    )

    # 1. _build_stack_specs launches tg_ws_proxy.py with -u (unbuffered)
    specs = backend._build_stack_specs(["--ctrack-disable=0"], tmp_path / "configs" / "sing-box.json")
    tg_spec = next(s for s in specs if s[0] == "tg-ws-proxy")
    assert "-u" in tg_spec[1]

    # 2. start_services rejects invalid sing-box.json before spawning any process
    monkeypatch.setattr("netdoctor.gui_backend._is_admin", lambda: True)
    monkeypatch.setattr("netdoctor.gui_backend.detect_bypass_active", lambda: False)
    monkeypatch.setattr(
        backend,
        "trigger_apply_configs",
        lambda iface=None: {
            "winws2_args": ["--ctrack-disable=0"],
            "singbox_config": str(tmp_path / "configs" / "sing-box.json"),
            "singbox_valid": False,
            "singbox_check_error": "syntax error in sing-box.json",
        },
    )
    bad_res = backend.start_services(force=True)
    assert bad_res["ok"] is False
    assert "Invalid sing-box.json" in str(bad_res["error"])

    # 3. Switching to hybrid reloads winws2 BEFORE starting sing-box TUN
    monkeypatch.setattr(backend, "trigger_apply_configs", lambda iface=None: {"winws2_args": ["--wf-iface=10"], "singbox_config": str(tmp_path / "configs" / "sing-box.json"), "singbox_valid": True})
    monkeypatch.setattr(backend, "_collect_processes_state", lambda: {"winws2": {"running": True}, "sing-box": {"running": False}, "tg-ws-proxy": {"running": True}})
    order: list[str] = []
    monkeypatch.setattr(backend, "reload_winws2", lambda iface=None: (order.append("winws2"), {"ok": True})[1])
    monkeypatch.setattr(backend, "reload_singbox", lambda iface=None: (order.append("sing-box"), {"ok": True})[1])
    backend.set_stack_mode("hybrid")
    assert order == ["winws2", "sing-box"]

    # 4. Watchdog backs off failed sing-box restart rather than hammering every tick
    backend._desired_running = True
    sb_calls = 0

    def failing_sb(iface: int | None = None) -> dict[str, Any]:
        nonlocal sb_calls
        sb_calls += 1
        return {"ok": False, "error": "tun start failed"}

    monkeypatch.setattr(backend, "reload_singbox", failing_sb)
    monkeypatch.setattr(backend, "_detect_local_gateway_ip", lambda: "10:192.168.50.1")
    backend.ensure_services_healthy()
    backend.ensure_services_healthy()
    assert sb_calls == 1


@pytest.mark.asyncio
async def test_orchestrator_dns_poison_plus_quic_does_not_assign_dpi() -> None:
    from netdoctor.models import (
        DiagnosticReport,
        DnsProbeResult,
        ProbesSummary,
        TcpProbeResult,
    )
    from netdoctor.orchestrators import DnsLayerOrchestrator
    from netdoctor.selector import _quick_non_dpi_decision

    verdicts = [VerdictClass.DNS_POISON, VerdictClass.QUIC_BLOCK]
    quick = _quick_non_dpi_decision("AS12389:home:test", "sprinthost.ru", verdicts, Protocol.TLS)
    assert quick is not None
    assert quick.layer == "dns"
    assert quick.strategy_id == "doh"

    sel_dec = await select_best_strategy(
        network_key="AS12389:home:test",
        domain="sprinthost.ru",
        ip="141.8.192.1",
        verdicts=verdicts,
        candidates=DEFAULT_STRATEGIES,
        protocol=Protocol.TLS,
    )
    assert sel_dec.layer == "dns"
    assert sel_dec.strategy_id == "doh"

    report = DiagnosticReport(
        domain="sprinthost.ru",
        network={"asn": 12389, "kind": "home"},
        bypass_active=False,
        probes=ProbesSummary(
            dns=DnsProbeResult(system="timeout", doh="ok", doh_ips=["141.8.192.1"]),
            tcp=TcpProbeResult(result="ok", rtt_ms=15.0, target_ip="141.8.192.1"),
        ),
        verdicts=verdicts,
        confidence=0.85,
        recommended=[],
    )
    dns_dec = await DnsLayerOrchestrator().evaluate_domain("sprinthost.ru", report, "AS12389:home:test")
    assert dns_dec is not None
    assert dns_dec.layer == "dns"
    assert dns_dec.strategy_id == "doh"


@pytest.mark.asyncio
async def test_select_best_strategy_skips_redundant_probes_without_live_evaluator(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import netdoctor.selector as sel_mod

    probe_calls = 0

    async def boom_probe(*_args: Any, **_kwargs: Any) -> Any:
        nonlocal probe_calls
        probe_calls += 1
        raise AssertionError("default_strategy_evaluator must not loop 29x when evaluator is None")

    monkeypatch.setattr(sel_mod, "probe_stall", boom_probe)
    dec = await select_best_strategy(
        network_key="AS12389:home:test",
        domain="discord.com",
        ip="162.159.135.232",
        verdicts=[VerdictClass.SNI_DPI],
        candidates=DEFAULT_STRATEGIES,
        protocol=Protocol.TLS,
        evaluator=None,
    )
    assert probe_calls == 0
    assert dec.layer == "dpi"
    assert dec.strategy_id == "tls_alt1_199_fake_fakedsplit"
    assert len(dec.fallback_strategies) == 2


@pytest.mark.asyncio
async def test_evaluate_domains_live_batch_auto_detects_iface_and_skips_dead_proc(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import netdoctor.selector as sel_mod
    from netdoctor.selector import evaluate_domains_live_batch

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir(parents=True, exist_ok=True)
    (fake_bin / "winws2.exe").write_bytes(b"MZ")

    monkeypatch.setattr(sel_mod, "_is_admin", lambda: True)
    monkeypatch.setattr(sel_mod, "detect_bypass_active", lambda: False)
    monkeypatch.setattr(sel_mod, "detect_physical_egress_iface", lambda: 10)

    seen_cmds: list[list[str]] = []

    class _DeadProc:
        def poll(self) -> int:
            return 1

        def terminate(self) -> None:
            return None

        def wait(self, timeout: float = 1.0) -> int:
            return 1

        def kill(self) -> None:
            return None

    def fake_popen(cmd: list[str], **_kw: Any) -> _DeadProc:
        seen_cmds.append(list(cmd))
        return _DeadProc()

    eval_calls = 0

    async def fail_if_called(*_args: Any, **_kwargs: Any) -> Any:
        nonlocal eval_calls
        eval_calls += 1
        raise AssertionError("Should skip default_strategy_evaluator when winws2 exited prematurely")

    monkeypatch.setattr(sel_mod.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(sel_mod, "default_strategy_evaluator", fail_if_called)

    # Use 2 strategies for speed (sleeping 0.25s twice = 0.5s total)
    decs = await evaluate_domains_live_batch(
        domains_info=[("discord.com", "162.159.135.232", [VerdictClass.SNI_DPI])],
        network_key="AS12389:home:test",
        candidates=DEFAULT_STRATEGIES[:2],
        bin_dir=fake_bin,
        use_live_eval=True,
        iface=None,
    )
    assert eval_calls == 0
    assert seen_cmds and all("--wf-iface=10" in c for c in seen_cmds)
    assert decs["discord.com"].layer == "vpn"


def test_resolve_vpn_ips_caches_and_clears(monkeypatch: pytest.MonkeyPatch) -> None:
    import netdoctor.config_gen as cg_mod
    from netdoctor.config_gen import clear_vpn_dns_cache, resolve_vpn_ips

    clear_vpn_dns_cache()
    calls: list[str] = []

    def fake_resolve(host: str) -> list[str]:
        calls.append(host)
        if host == "node1.example":
            return ["198.51.100.11"]
        return []

    monkeypatch.setattr(cg_mod, "_resolve_single_hostname", fake_resolve)
    ips1 = resolve_vpn_ips(["198.51.100.1", "node1.example", "bad.example", "node1.example"])
    assert ips1 == ["198.51.100.1", "198.51.100.11"]
    assert sorted(calls) == ["bad.example", "node1.example"]

    # Second call uses cached positive + negative results -> zero DNS lookups
    calls.clear()
    ips2 = resolve_vpn_ips(["node1.example", "bad.example"])
    assert ips2 == ["198.51.100.11"]
    assert calls == []

    clear_vpn_dns_cache()
    resolve_vpn_ips(["node1.example"])
    assert calls == ["node1.example"]
    clear_vpn_dns_cache()


@pytest.mark.asyncio
async def test_auto_heal_single_apply_parallel_probes_and_exponential_cooldown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import asyncio
    import socket as sock_mod
    from types import SimpleNamespace
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

    db_path = tmp_path / "heal_perf.db"
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    st = Storage(db_path)
    try:
        net = NetworkFingerprint(asn=12389, kind=NetworkKind.HOME, isp="TestISP")
        nk = st.upsert_network(net)
        st.upsert_strategies(DEFAULT_STRATEGIES)
        st.save_decision(
            Decision(
                network_key=nk,
                domain="fail1.example",
                protocol=Protocol.TLS,
                layer="dpi",
                strategy_id="tls_alt1_199_fake_fakedsplit",
                fallback_strategies=["tls_multisplit_pos2"],
                consecutive_fails=1,
            )
        )
    finally:
        st.close()

    (logs_dir / "sing-box.log").write_text(
        "INFO outbound connected to fail1.example:203.0.113.10\n"
        "INFO outbound connected to fail2.example:203.0.113.11\n",
        encoding="utf-8",
    )
    fake_conns = [
        SimpleNamespace(
            fd=1,
            family=sock_mod.AF_INET,
            type=sock_mod.SOCK_STREAM,
            laddr=SimpleNamespace(ip="192.168.1.10", port=50001),
            raddr=SimpleNamespace(ip="203.0.113.10", port=443),
            status="SYN_SENT",
            pid=101,
        ),
        SimpleNamespace(
            fd=2,
            family=sock_mod.AF_INET,
            type=sock_mod.SOCK_STREAM,
            laddr=SimpleNamespace(ip="192.168.1.10", port=50002),
            raddr=SimpleNamespace(ip="203.0.113.11", port=443),
            status="SYN_SENT",
            pid=102,
        ),
    ]
    monkeypatch.setattr(psutil, "net_connections", lambda kind="inet": fake_conns)
    monkeypatch.setattr(orch_mod, "detect_bypass_active", lambda: True)
    monkeypatch.setattr(orch_mod, "_is_admin", lambda: True)

    async def fake_net(timeout: float = 2.0) -> NetworkFingerprint:
        return NetworkFingerprint(asn=12389, kind=NetworkKind.HOME, isp="TestISP")

    inflight = {"cur": 0, "max": 0}

    async def fake_probes(domain: str, timeout: float = 2.0) -> ProbesSummary:
        inflight["cur"] += 1
        inflight["max"] = max(inflight["max"], inflight["cur"])
        await asyncio.sleep(0.05)
        inflight["cur"] -= 1
        return ProbesSummary(
            dns=DnsProbeResult(system="ok", doh="ok", doh_ips=["203.0.113.10"]),
            tcp=TcpProbeResult(result="ok", rtt_ms=10.0, target_ip="203.0.113.10"),
            tls=TlsProbeResult(real_sni="reset", neutral_sni="ok", ttfb_ms=25.0),
            stall=StallProbeResult(result="ok", bytes_read=4096, throughput_kbps=1500.0),
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
    monkeypatch.setattr(backend.orchestrator.monitor, "_resolve_pid_name", lambda pid: "app.exe")
    monkeypatch.setattr(backend, "_collect_processes_state", lambda: {"winws2": {"running": True}})

    apply_calls = 0
    orig_apply = backend.trigger_apply_configs

    def counting_apply(iface: int | None = None) -> dict[str, Any]:
        nonlocal apply_calls
        apply_calls += 1
        return orig_apply(iface=iface)

    monkeypatch.setattr(backend, "trigger_apply_configs", counting_apply)
    monkeypatch.setattr(backend, "reload_winws2", lambda iface=None, applied=None: {"ok": True, "reloaded": True})

    t_before = time.monotonic()
    res = await backend.orchestrator.monitor.auto_heal_connections(backend, max_domains_per_tick=2)
    assert len(res["healed"]) == 2
    assert inflight["max"] == 2
    assert apply_calls == 1
    # Exponential cooldown: fail1 had consecutive_fails=1 -> 2*12s=24s cooldown, fail2 had 0 -> 12s cooldown
    cd1 = backend.orchestrator.monitor.cooldown_until["fail1.example"] - t_before
    cd2 = backend.orchestrator.monitor.cooldown_until["fail2.example"] - t_before
    assert cd1 > cd2 + 8.0

    # Tick with no eligible candidates (on cooldown) skips second scan_active_connections
    scan_calls = 0
    orig_scan = backend.orchestrator.monitor.scan_active_connections

    def counting_scan(*a: Any, **kw: Any) -> list[dict[str, Any]]:
        nonlocal scan_calls
        scan_calls += 1
        return orig_scan(*a, **kw)

    monkeypatch.setattr(backend.orchestrator.monitor, "scan_active_connections", counting_scan)
    res_idle = await backend.orchestrator.monitor.auto_heal_connections(backend, max_domains_per_tick=2)
    assert res_idle["healed"] == []
    assert scan_calls == 1


def test_storage_upsert_network_migrates_clean_as0_rules(tmp_path: Path) -> None:
    from netdoctor.models import (
        DiagnosticReport,
        DnsProbeResult,
        NetworkFingerprint,
        NetworkKind,
        ProbesSummary,
        TcpProbeResult,
    )

    st = Storage(tmp_path / "migrate.db")
    try:
        legacy_net = NetworkFingerprint(asn=0, kind=NetworkKind.HOME, isp="unknown", gateway_mac="aa:bb:cc:dd:ee:ff")
        legacy_key = st.upsert_network(legacy_net)

        def _save_v(dom: str, verdicts: list[VerdictClass]) -> None:
            st.save_verdict(
                legacy_key,
                DiagnosticReport(
                    domain=dom,
                    network={"asn": 0, "kind": "home", "gateway_mac": "aa:bb:cc:dd:ee:ff"},
                    probes=ProbesSummary(dns=DnsProbeResult(), tcp=TcpProbeResult()),
                    verdicts=verdicts,
                    confidence=0.8,
                ),
            )

        _save_v("bogus-dns-quic.ru", [VerdictClass.DNS_POISON, VerdictClass.QUIC_BLOCK])
        _save_v("real-dpi.com", [VerdictClass.SNI_DPI, VerdictClass.QUIC_BLOCK])
        _save_v("user-pinned.ru", [VerdictClass.QUIC_BLOCK])

        st.save_decision(
            Decision(
                network_key=legacy_key,
                domain="bogus-dns-quic.ru",
                protocol=Protocol.TLS,
                layer="dpi",
                strategy_id="tls_alt1_199_fake_fakedsplit",
            )
        )
        st.save_decision(
            Decision(
                network_key=legacy_key,
                domain="real-dpi.com",
                protocol=Protocol.TLS,
                layer="dpi",
                strategy_id="tls_hostfakesplit_ozon",
            )
        )
        st.save_decision(
            Decision(
                network_key=legacy_key,
                domain="chatgpt.com",
                protocol=Protocol.TLS,
                layer="dns",
                strategy_id="dns:comss_dns",
            )
        )
        st.save_decision(
            Decision(
                network_key=legacy_key,
                domain="user-pinned.ru",
                protocol=Protocol.TLS,
                layer="dpi",
                strategy_id="tls_multisplit_pos2",
                pinned=True,
            )
        )

        new_net = NetworkFingerprint(asn=8402, kind=NetworkKind.HOME, isp="Vimpelcom", gateway_mac="aa:bb:cc:dd:ee:ff")
        new_key = st.upsert_network(new_net)
        migrated = {d.domain: d for d in st.get_decisions(new_key, active_only=False)}
        assert "real-dpi.com" in migrated
        assert "chatgpt.com" in migrated
        assert "user-pinned.ru" in migrated
        assert "bogus-dns-quic.ru" not in migrated
    finally:
        st.close()


def test_gui_russian_layout_clipboard_and_edit_shortcuts(tmp_path: Path) -> None:
    from types import SimpleNamespace

    backend = GuiBackend(
        db_path=tmp_path / "gui_ru.db",
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

        # 1. Paste into Entry under Russian layout (keysym="Cyrillic_em", keycode=86)
        entry = app.user_preset_name_entry
        app.clipboard_clear()
        app.clipboard_append("Тест_ДНС\nстрока")
        app.update()
        ru_paste = app._on_ctrl_keypress_non_ascii(
            SimpleNamespace(widget=entry, keysym="Cyrillic_em", keycode=86, state=0x4)
        )
        assert ru_paste == "break"
        assert entry.get() == "Тест_ДНС строка"

        # 2. English ASCII keysym="v" returns None (no double paste)
        en_noop = app._on_ctrl_keypress_non_ascii(
            SimpleNamespace(widget=entry, keysym="v", keycode=86, state=0x4)
        )
        assert en_noop is None

        # 3. SelectAll (65) + Copy (67) + Cut (88) on Entry under Cyrillic keysyms
        assert app._on_ctrl_keypress_non_ascii(
            SimpleNamespace(widget=entry, keysym="Cyrillic_ef", keycode=65, state=0x4)
        ) == "break"
        assert entry.selection_present()
        app.clipboard_clear()
        assert app._on_ctrl_keypress_non_ascii(
            SimpleNamespace(widget=entry, keysym="Cyrillic_es", keycode=67, state=0x4)
        ) == "break"
        assert app.clipboard_get() == "Тест_ДНС строка"
        assert app._on_ctrl_keypress_non_ascii(
            SimpleNamespace(widget=entry, keysym="Cyrillic_che", keycode=88, state=0x4)
        ) == "break"
        assert entry.get() == ""

        # 4. Paste + Undo (90) on editable tk.Text (preset editor)
        txt = app.user_preset_text
        txt.delete("1.0", "end")
        txt.edit_reset()
        app.clipboard_clear()
        app.clipboard_append("строка1\nстрока2")
        app.update()
        assert app._on_ctrl_keypress_non_ascii(
            SimpleNamespace(widget=txt, keysym="Cyrillic_em", keycode=86, state=0x4)
        ) == "break"
        assert txt.get("1.0", "end-1c") == "строка1\nстрока2"
        txt.edit_separator()
        assert app._on_ctrl_keypress_non_ascii(
            SimpleNamespace(widget=txt, keysym="Cyrillic_ya", keycode=90, state=0x4)
        ) == "break"
        assert txt.get("1.0", "end-1c") == ""

        # 5. Disabled tk.Text (log_view) allows SelectAll + Copy but ignores Paste
        app._set_text(app.log_view, "readonly log line")
        assert app._on_ctrl_keypress_non_ascii(
            SimpleNamespace(widget=app.log_view, keysym="Cyrillic_em", keycode=86, state=0x4)
        ) == "break"
        assert app.log_view.get("1.0", "end-1c") == "readonly log line"
        assert app._on_ctrl_keypress_non_ascii(
            SimpleNamespace(widget=app.log_view, keysym="Cyrillic_ef", keycode=65, state=0x4)
        ) == "break"
        app.clipboard_clear()
        assert app._on_ctrl_keypress_non_ascii(
            SimpleNamespace(widget=app.log_view, keysym="Cyrillic_es", keycode=67, state=0x4)
        ) == "break"
        assert app.clipboard_get() == "readonly log line"

        # 6. Ctrl+F under Russian layout (Cyrillic_a, keycode=70) switches to Domains search
        assert app._on_ctrl_keypress_non_ascii(
            SimpleNamespace(widget=app, keysym="Cyrillic_a", keycode=70, state=0x4)
        ) == "break"
        assert app.notebook.select() == str(app.tab_domains)
    finally:
        app.on_close()


def test_audit_fixes_start_stack_exception_rollback_autostart_len_and_nonroot_cwd(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from netdoctor.selector import load_targets_from_yaml
    from netdoctor.tray import build_autostart_command

    # 1. ProcessSupervisor.start_stack stops already-started process if a later start_process raises
    sup = ProcessSupervisor(bin_dir=tmp_path / "bin", logs_dir=tmp_path / "logs")
    long_sleep_cmd = [sys.executable, "-c", "import time; time.sleep(30)"]
    missing_cmd = [str(tmp_path / "bin" / "nonexistent_winws2.exe")]
    with pytest.raises(FileNotFoundError):
        sup.start_stack(
            [
                ("tg-ws-proxy", long_sleep_cmd, tmp_path),
                ("winws2", missing_cmd, tmp_path),
            ],
            startup_wait=0.1,
        )
    assert sup.processes == {}
    assert sup._log_files == {}

    # 2. build_autostart_command stays under schtasks 261-char limit even on deep Cyrillic paths
    deep_root = Path.cwd().resolve()
    autostart_cmd = build_autostart_command(deep_root)
    assert len(autostart_cmd) <= 260, f"Autostart cmd exceeded 260 chars ({len(autostart_cmd)}): {autostart_cmd}"
    assert "--minimized" in autostart_cmd and "--auto-start" in autostart_cmd

    # 3. Built-in presets and targets.yaml still resolve when CWD is outside repo root (e.g. Task Scheduler System32)
    monkeypatch.chdir(tmp_path)
    clear_builtin_presets_cache()
    presets_from_other_cwd = discover_builtin_zapret_presets()
    assert len(presets_from_other_cwd) >= 30
    targets_from_other_cwd = load_targets_from_yaml("configs/targets.yaml")
    assert len(targets_from_other_cwd) >= 6

    # 4. flush_windows_dns_cache decodes OEM CP866 Russian output without mojibake or UnicodeDecodeError
    backend = GuiBackend(
        db_path=tmp_path / "flush.db",
        configs_dir=tmp_path / "configs",
        lists_dir=tmp_path / "lists",
        logs_dir=tmp_path / "logs",
        bin_dir=tmp_path / "bin",
    )
    cp866_bytes = "Кэш сопоставителя DNS успешно очищен.".encode("cp866")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: subprocess.CompletedProcess(a[0], 0, stdout=cp866_bytes, stderr=b""),
    )
    flush_res = backend.flush_windows_dns_cache()
    assert flush_res["ok"] is True
    assert "успешно очищен" in flush_res["output"]


def test_supervisor_start_stack_shared_wait_and_crash_rollback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import netdoctor.supervisor as sup_mod

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    sup = ProcessSupervisor(bin_dir=bin_dir, logs_dir=tmp_path / "logs")
    sleep_cmd = [sys.executable, "-c", "import time; time.sleep(30)"]
    specs = [
        ("tg-ws-proxy", sleep_cmd, tmp_path),
        ("byedpi", sleep_cmd, tmp_path),
        ("xray", sleep_cmd, tmp_path),
    ]

    recorded_sleeps: list[float] = []
    real_sleep = sup_mod.time.sleep

    def spy_sleep(secs: float) -> None:
        recorded_sleeps.append(float(secs))
        real_sleep(secs)

    monkeypatch.setattr(sup_mod.time, "sleep", spy_sleep)
    # Isolate unit test from real host processes listening on default ports (e.g. 10808/18100)
    monkeypatch.setattr(sup_mod, "SERVICE_PORTS", {})

    try:
        sup.start_stack(specs, startup_wait=0.4, skip_stop=True)
        total_slept = sum(recorded_sleeps)
        # Shared wait across 3 services must sleep ~0.4s total, not 3 * 0.4s = 1.2s sequential delay
        assert 0.35 <= total_slept < 0.7, f"Expected single shared ~0.4s wait, slept {total_slept:.3f}s"
        assert set(sup.processes.keys()) == {"tg-ws-proxy", "byedpi", "xray"}
    finally:
        sup.stop_all()

    crash_cmd = [sys.executable, "-c", "import sys; sys.stderr.write('boom\\n'); sys.exit(1)"]
    try:
        with pytest.raises(RuntimeError) as exc_info:
            sup.start_stack(
                [
                    ("tg-ws-proxy", sleep_cmd, tmp_path),
                    ("winws2", crash_cmd, tmp_path),
                ],
                startup_wait=3.0,
                skip_stop=True,
            )
    finally:
        sup.stop_all()
    assert "Service 'winws2' exited prematurely on startup with code 1: boom" in str(exc_info.value)
    assert sup.processes == {}


def test_start_autopilot_admin_single_apply_and_nonblocking_vpn_tasks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import threading
    import netdoctor.gui_backend as backend_mod
    from netdoctor.storage import Storage

    bin_dir = tmp_path / "bin"
    lists_dir = tmp_path / "lists"
    cfg_dir = tmp_path / "configs"
    logs_dir = tmp_path / "logs"
    bin_dir.mkdir(parents=True, exist_ok=True)
    (bin_dir / "winws2.exe").write_bytes(b"MZ" + b"\x00" * 64)
    (bin_dir / "sing-box.exe").write_bytes(b"MZ" + b"\x00" * 64)

    db_path = tmp_path / "fast_start.db"
    backend = GuiBackend(
        db_path=db_path,
        configs_dir=cfg_dir,
        lists_dir=lists_dir,
        logs_dir=logs_dir,
        bin_dir=bin_dir,
    )

    st = Storage(db_path)
    try:
        net_key, _, _, _ = backend._resolve_network_info(st)
        st.save_decision(
            Decision(
                network_key=net_key,
                domain="youtube.com",
                protocol=Protocol.TLS,
                layer="dpi",
                strategy_id="z2_multisplit_sni",
            )
        )
        st.save_subscription(
            "fast-sub",
            "https://example.com/sub",
            [
                {
                    "tag": "nl-1",
                    "protocol": "vless",
                    "server": "1.2.3.4",
                    "server_port": 443,
                    "raw_outbound": {
                        "type": "vless",
                        "tag": "nl-1",
                        "server": "1.2.3.4",
                        "server_port": 443,
                        "uuid": "00000000-0000-0000-0000-000000000000",
                    },
                    "enabled": True,
                }
            ],
        )
    finally:
        st.close()

    monkeypatch.setattr(backend_mod, "_is_admin", lambda: True)
    monkeypatch.setattr(backend_mod, "detect_bypass_active", lambda: False)
    monkeypatch.setattr(backend_mod, "detect_physical_egress_iface", lambda: 1)
    monkeypatch.setattr(backend_mod, "validate_singbox_config", lambda *_a, **_kw: (True, ""))
    monkeypatch.setattr(backend_mod, "stop_persisted_supervisor", lambda **_kw: [])

    start_stack_calls: list[dict[str, Any]] = []

    class FakeSupervisor:
        def __init__(self, **_kw: Any) -> None:
            self.processes: dict[str, Any] = {}
            self._adopted: dict[str, Any] = {}

        def adopt_persisted_state(self) -> dict[str, Any]:
            return {}

        def start_stack(self, specs: Any, **kw: Any) -> None:
            start_stack_calls.append({"specs": [s[0] for s in specs], **kw})

        def status(self) -> dict[str, Any]:
            return {"winws2": {"running": True, "pid": 123}, "sing-box": {"running": True, "pid": 456}}

        def stop_process(self, _name: str) -> None:
            pass

    monkeypatch.setattr(backend_mod, "ProcessSupervisor", FakeSupervisor)

    apply_count = 0
    orig_apply = backend.trigger_apply_configs

    def wrapped_apply(*args: Any, **kwargs: Any) -> dict[str, Any]:
        nonlocal apply_count
        apply_count += 1
        return orig_apply(*args, **kwargs)

    monkeypatch.setattr(backend, "trigger_apply_configs", wrapped_apply)

    sub_started = threading.Event()
    vpn_sync_started = threading.Event()
    release_bg = threading.Event()

    def slow_sub_refresh(*_a: Any, **_kw: Any) -> bool:
        sub_started.set()
        release_bg.wait(timeout=2.0)
        return False

    def slow_vpn_sync(*_a: Any, **_kw: Any) -> None:
        vpn_sync_started.set()
        release_bg.wait(timeout=2.0)

    monkeypatch.setattr(backend, "_refresh_stale_subscriptions_if_needed", slow_sub_refresh)
    monkeypatch.setattr(backend, "_sync_singbox_vpn_selector", slow_vpn_sync)
    monkeypatch.setattr(
        backend,
        "scan_live_connections",
        lambda: (_ for _ in ()).throw(AssertionError("start_autopilot should not scan live connections synchronously")),
    )

    try:
        t0 = time.monotonic()
        res = backend.start_autopilot(iface=1)
        elapsed = time.monotonic() - t0
    finally:
        release_bg.set()

    assert res["ok"] is True
    assert res["started_services"] is True
    assert res["live_connections"] is None
    assert apply_count == 1
    assert elapsed < 0.8
    assert start_stack_calls and start_stack_calls[0]["skip_stop"] is True
    assert start_stack_calls[0]["startup_wait"] == 0.35
    assert sub_started.wait(timeout=1.0)
    assert vpn_sync_started.wait(timeout=1.0)


def test_base_zapret_preset_merges_with_auto_orchestrator_decisions(tmp_path: Path) -> None:
    """Base Zapret2 preset sits beneath Auto-Orchestrator DB decisions and excludes already-managed domains."""
    from netdoctor.models import NetworkFingerprint, NetworkKind

    bin_dir = tmp_path / "bin"
    (bin_dir / "lua").mkdir(parents=True)
    for fname in ("zapret-lib.lua", "zapret-antidpi.lua", "zapret-auto.lua"):
        (bin_dir / "lua" / fname).write_text("function multisplit() end\nfunction fake() end\n", encoding="utf-8")

    db_path = tmp_path / "base_preset.db"
    lists_dir = tmp_path / "lists"
    backend = GuiBackend(
        db_path=db_path,
        configs_dir=tmp_path / "configs",
        lists_dir=lists_dir,
        logs_dir=tmp_path / "logs",
        bin_dir=bin_dir,
        presets_dir=tmp_path / "presets_z2",
        zdy_presets_dir=tmp_path / "presets_zdy",
    )

    st = Storage(db_path)
    try:
        nk = st.upsert_network(NetworkFingerprint(asn=12389, kind=NetworkKind.HOME, isp="TestISP"))
        st.upsert_strategies(DEFAULT_STRATEGIES)
        st.save_decision(
            Decision(
                network_key=nk,
                domain="custom-site.example",
                protocol=Protocol.TLS,
                layer="dpi",
                strategy_id="tls_multisplit_pos2",
            )
        )
        st.save_decision(
            Decision(
                network_key=nk,
                domain="vpn-site.example",
                protocol=Protocol.TLS,
                layer="vpn",
                strategy_id="vpn-select",
                pinned=True,
            )
        )
    finally:
        st.close()

    saved = backend.add_user_zapret_preset(
        name="My Base Preset",
        content="--lua-desync=multisplit:pos=1",
        activate=False,
    )
    preset_id = str(saved["preset"]["id"])

    res = backend.set_base_zapret_preset(preset_id)
    assert res["ok"] is True
    assert res["active_preset_id"] == "auto"
    assert res["base_preset_id"] == preset_id

    args = res["applied"]["winws2_args"]
    # DB per-domain hostlist profile must precede the base preset profiles (separated by --new)
    custom_hostlist_idx = next(i for i, tok in enumerate(args) if tok.startswith("--hostlist=") and "custom-site" not in tok and "exclude_unlocker" not in tok)
    new_after_idx = next(i for i, tok in enumerate(args[custom_hostlist_idx + 1 :], start=custom_hostlist_idx + 1) if tok == "--new")
    base_desync_idx = next(i for i, tok in enumerate(args) if tok == "--lua-desync=multisplit:pos=1")
    assert custom_hostlist_idx < new_after_idx < base_desync_idx

    excl = (lists_dir / "exclude_unlocker_domains.txt").read_text(encoding="utf-8").splitlines()
    assert "custom-site.example" in excl
    assert "vpn-site.example" in excl






