"""Tier 4 E2E Tests: Real-world end-to-end application scenarios (6 scenarios: 4 non-elevated + 2 @elevated)."""

from __future__ import annotations

import inspect
import json
import signal
import socket
import subprocess
import time
from pathlib import Path
from typing import Any

import psutil
import pytest

import e2e_support
from conftest import E2EWorkspace
from netdoctor.classifier import classify_probes
from netdoctor.models import (
    DnsProbeResult,
    NetworkFingerprint,
    NetworkKind,
    ProbesSummary,
    Protocol,
)
from netdoctor.probes import probe_quic, probe_tcp, probe_tls
from netdoctor.selector import DEFAULT_STRATEGIES, select_best_strategy
from netdoctor.storage import Storage
from netdoctor.supervisor import ProcessSupervisor


def _make_supervisor(ws: E2EWorkspace, bin_dir: Path) -> ProcessSupervisor:
    sig = inspect.signature(ProcessSupervisor.__init__)
    kwargs: dict[str, Any] = {"bin_dir": bin_dir}
    if "logs_dir" in sig.parameters:
        kwargs["logs_dir"] = ws.logs_dir
    if "state_path" in sig.parameters:
        kwargs["state_path"] = ws.state_file
    return ProcessSupervisor(**kwargs)


def test_t4_01_scenario_zero_to_ready_setup_and_verification(
    e2e_workspace: E2EWorkspace,
    repo_root: Path,
    bin_dir: Path,
    lists_dir: Path,
    presets_dir: Path,
    venv_python: Path,
    run_netdoctor,
) -> None:
    """Scenario 1: Audit R1 binaries/lists/presets -> .venv pip check & baseline pytest -> apply --no-start -> sing-box check."""
    from netdoctor import supervisor

    assert hasattr(supervisor, "verify_binaries"), "netdoctor.supervisor.verify_binaries missing (M1)"
    ver_res = supervisor.verify_binaries(bin_dir, lists_dir)
    assert ver_res.get("ok") is True, f"verify_binaries failed: {ver_res}"

    assert (bin_dir / "sing-box.exe").is_file()
    assert (bin_dir / "winws2.exe").is_file()
    assert (bin_dir / "ciadpi.exe").is_file()
    assert (bin_dir / "blockcheck" / "blockcheck2.cmd").is_file()
    assert e2e_support.discover_tg_ws_proxy(repo_root, bin_dir, venv_python) is not None
    assert presets_dir.is_dir() and list(presets_dir.rglob("general*.bat"))

    pip_chk = subprocess.run(
        [str(venv_python), "-m", "pip", "check"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=15.0,
    )
    assert pip_chk.returncode == 0

    base_pytest = subprocess.run(
        [str(venv_python), "-m", "pytest", "tests/test_netdoctor.py", "-q"],
        cwd=str(repo_root),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=60.0,
    )
    assert base_pytest.returncode == 0

    res = run_netdoctor(
        [
            "apply",
            "--no-start",
            "--db",
            str(e2e_workspace.db_path),
            "--configs-dir",
            str(e2e_workspace.configs_dir),
            "--lists-dir",
            str(e2e_workspace.lists_dir),
        ],
        cwd=e2e_workspace.root,
    )
    assert res.returncode == 0, f"apply --no-start failed: {res.stderr}"

    sb_path = e2e_workspace.configs_dir / "sing-box.json"
    e2e_support.load_json_no_bom(sb_path)
    chk = e2e_support.run_singbox_check(bin_dir / "sing-box.exe", sb_path)
    assert chk.returncode == 0, f"sing-box check failed: {chk.stdout} {chk.stderr}"

    tokens = e2e_support.parse_winws2_tokens(e2e_workspace.configs_dir / "winws2_preset.txt")
    for tok, resolved, ok in e2e_support.resolve_winws2_references(
        tokens, bin_dir=bin_dir, lists_dir=e2e_workspace.lists_dir, workspace_root=e2e_workspace.root
    ):
        assert ok, f"Unresolved winws2 reference {tok} -> {resolved}"


async def test_t4_02_scenario_diagnostic_to_config_pipeline(
    e2e_workspace: E2EWorkspace,
    bin_dir: Path,
    fake_censor_factory,
    run_netdoctor,
) -> None:
    """Scenario 2: FakeCensorServer(sni_dpi + quic_block) -> DB verdict/decision -> sub-add -> apply --no-start."""
    censor_dpi = await fake_censor_factory(mode="sni_dpi", blocked_sni="discord.com")
    censor_qb = await fake_censor_factory(mode="quic_block", blocked_sni="discord.com")

    tcp_res = await probe_tcp("127.0.0.1", port=censor_dpi.tcp_port, timeout=1.5)
    tls_res = await probe_tls("127.0.0.1", real_sni="discord.com", port=censor_dpi.tcp_port, timeout=1.5)
    quic_res = await probe_quic("127.0.0.1", sni="discord.com", port=censor_qb.udp_port, timeout=0.6)
    p_tls = ProbesSummary(
        dns=DnsProbeResult(system="ok", doh="ok", system_ips=["127.0.0.1"], doh_ips=["127.0.0.1"]),
        tcp=tcp_res,
        tls=tls_res,
        quic=quic_res,
    )
    net = NetworkFingerprint(asn=12389, kind=NetworkKind.HOME, isp="e2e-scenario2")
    report = classify_probes("discord.com", p_tls, net)
    verdict_vals = {v.value for v in report.verdicts}
    assert "sni_dpi" in verdict_vals and "quic_block" in verdict_vals

    storage = Storage(e2e_workspace.db_path)
    try:
        net_key = storage.upsert_network(net)
        storage.upsert_strategies(DEFAULT_STRATEGIES)
        storage.save_verdict(net_key, report, protocol=Protocol.TLS)
        decision = await select_best_strategy(
            network_key=net_key,
            domain="discord.com",
            ip="127.0.0.1",
            verdicts=report.verdicts,
            candidates=DEFAULT_STRATEGIES,
            protocol=Protocol.TLS,
        )
        storage.save_decision(decision)
    finally:
        storage.close()

    sub_payload = (
        "vless://11111111-2222-3333-4444-555555555555@198.51.100.88:443?security=tls#S2-IP\n"
        "trojan://secret@localhost:443?sni=localhost#S2-Host"
    )
    assert (
        run_netdoctor(
            ["sub-add", sub_payload, "--id", "s2", "--db", str(e2e_workspace.db_path)],
            cwd=e2e_workspace.root,
        ).returncode
        == 0
    )

    apply_res = run_netdoctor(
        [
            "apply",
            "--no-start",
            "--db",
            str(e2e_workspace.db_path),
            "--configs-dir",
            str(e2e_workspace.configs_dir),
            "--lists-dir",
            str(e2e_workspace.lists_dir),
        ],
        cwd=e2e_workspace.root,
    )
    assert apply_res.returncode == 0, f"apply --no-start failed: {apply_res.stderr}"

    ip_entries = e2e_support.validate_ip_only_file(e2e_workspace.lists_dir / "exclude_vpn_ips.txt")
    assert "198.51.100.88" in ip_entries and "localhost" not in ip_entries

    tokens = e2e_support.parse_winws2_tokens(e2e_workspace.configs_dir / "winws2_preset.txt")
    assert any(t.startswith("--wf-tcp-out=") for t in tokens)
    assert any(t.startswith("--lua-init=@lua/") for t in tokens)

    sb_path = e2e_workspace.configs_dir / "sing-box.json"
    sb_cfg = e2e_support.load_json_no_bom(sb_path)
    tun_in = next(i for i in sb_cfg["inbounds"] if i["type"] == "tun")
    assert tun_in["stack"] == "gvisor"
    assert tun_in.get("route_exclude_address")
    assert any("process_name" in r and r.get("outbound") == "direct" for r in sb_cfg["route"]["rules"])
    out_tags = {o["tag"] for o in sb_cfg["outbounds"]}
    assert {"vpn-auto", "vpn-select", "S2-IP", "S2-Host"}.issubset(out_tags)
    assert e2e_support.run_singbox_check(bin_dir / "sing-box.exe", sb_path).returncode == 0


def test_t4_03_scenario_local_tg_ws_proxy_stage1_launch_and_shutdown(
    e2e_workspace: E2EWorkspace,
    repo_root: Path,
    bin_dir: Path,
    venv_python: Path,
    free_tcp_port: int,
    run_netdoctor,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Scenario 3: Launch tg-ws-proxy under ProcessSupervisor -> log & state -> port & handshake -> status -> stop."""
    monkeypatch.chdir(e2e_workspace.root)
    contract = e2e_support.discover_tg_ws_proxy(repo_root, bin_dir, venv_python)
    assert contract is not None, "tg-ws-proxy artifact not found (M1)"

    sup = _make_supervisor(e2e_workspace, bin_dir)
    try:
        log_path = e2e_workspace.logs_dir / "tg-ws-proxy.log"
        cmd, cwd = e2e_support.build_tg_ws_launch_cmd(
            contract,
            host="127.0.0.1",
            port=free_tcp_port,
            log_file=log_path,
            portable_dir=e2e_workspace.root / "tg_portable",
        )
        proc = sup.start_process("tg-ws-proxy", cmd, cwd=cwd)
        assert e2e_support.wait_for_tcp_port("127.0.0.1", free_tcp_port, timeout=6.0)
        e2e_support.probe_tg_ws_handshake("127.0.0.1", free_tcp_port, contract.protocol_mode)

        assert log_path.is_file() and log_path.stat().st_size > 0
        assert e2e_workspace.state_file.is_file(), f"Missing {e2e_workspace.state_file} (M2)"
        assert str(proc.pid) in e2e_workspace.state_file.read_text(encoding="utf-8")

        st_res = run_netdoctor(["status", "--db", str(e2e_workspace.db_path)], cwd=e2e_workspace.root)
        assert st_res.returncode == 0
        assert "tg-ws-proxy" in st_res.stdout

        stop_res = run_netdoctor(["stop"], cwd=e2e_workspace.root)
        assert stop_res.returncode == 0
        with pytest.raises(OSError):
            with socket.create_connection(("127.0.0.1", free_tcp_port), timeout=1.0):
                pass
    finally:
        sup.stop_all()


def test_t4_04_scenario_non_elevated_preflight_and_status_stop_safety(
    e2e_workspace: E2EWorkspace, run_netdoctor
) -> None:
    """Scenario 4: Non-Admin apply preflight refusal + stale/idle status & stop safety."""
    if e2e_support.is_admin():
        pytest.skip("Requires non-Admin shell for preflight refusal verification")

    res = run_netdoctor(
        [
            "apply",
            "--db",
            str(e2e_workspace.db_path),
            "--configs-dir",
            str(e2e_workspace.configs_dir),
            "--lists-dir",
            str(e2e_workspace.lists_dir),
        ],
        cwd=e2e_workspace.root,
        timeout=15.0,
    )
    assert res.returncode != 0, "Live apply must fail preflight in non-Admin shell (M2)"
    combined = (res.stdout + "\n" + res.stderr).lower()
    assert any(w in combined for w in ("admin", "elevat", "privilege", "740"))

    # Stale supervisor_state.json safety
    e2e_workspace.state_file.write_text(
        json.dumps({"processes": {"sing-box": {"pid": 999999}, "winws2": {"pid": 999998}}}),
        encoding="utf-8",
    )
    st_res = run_netdoctor(["status", "--db", str(e2e_workspace.db_path)], cwd=e2e_workspace.root)
    assert st_res.returncode == 0

    stop_stale = run_netdoctor(["stop"], cwd=e2e_workspace.root)
    assert stop_stale.returncode == 0
    stop_idle = run_netdoctor(["stop"], cwd=e2e_workspace.root)
    assert stop_idle.returncode == 0


@pytest.mark.elevated
def test_t4_05_scenario_live_elevated_r2_tun_winws2_clienthello_proof(
    elevated_clean_host: dict[str, Any],
    live_apply_guard,
    pktmon_capture,
    repo_root: Path,
) -> None:
    """Scenario 5: Live elevated Stage 1 apply + R2 ClientHello proof via winws2 --debug=1 and pktmon."""
    phys_ifidx = int(elevated_clean_host["phys_ifidx"])
    with pktmon_capture(port=443) as cap:
        with live_apply_guard(extra_args=["--iface", str(phys_ifidx)]) as ctx:
            tun_ifidx = int(ctx["tun_info"]["tun_ifindex"])
            time.sleep(2.0)

            running = {(p.info.get("name") or "").lower() for p in psutil.process_iter(["name"])}
            assert {"sing-box.exe", "winws2.exe"}.issubset(running)

            discord_probe = e2e_support.probe_https_target("https://discord.com", timeout=8.0)
            assert discord_probe["ok"], f"Discord failed under live Stage 1 stack: {discord_probe}"

            ctrl_ok = e2e_support.probe_https_target("https://example.com", timeout=8.0)["ok"] or (
                e2e_support.probe_https_target("https://ya.ru", timeout=8.0)["ok"]
            )
            assert ctrl_ok, "Non-target HTTPS broken under live Stage 1 stack"

            parsed = e2e_support.parse_winws2_debug_log(
                repo_root / "logs" / "winws2.log",
                expected_phys_ifidx=phys_ifidx,
                tun_ifidx=tun_ifidx,
                target_domain="discord.com",
            )
            assert not parsed["has_windivert_error"]
            assert parsed["phys_matched"] and not parsed["tun_matched"]
            assert parsed["has_desync_signal"]

    summary = e2e_support.parse_pcapng_tcp_packets(cap["pcapng"])
    assert summary.total_packets > 0 and summary.tcp_packets > 0


@pytest.mark.elevated
def test_t4_06_scenario_live_elevated_clean_teardown_and_route_restoration(
    elevated_clean_host: dict[str, Any],
    live_apply_guard,
    run_netdoctor,
    repo_root: Path,
) -> None:
    """Scenario 6: Active elevated apply -> graceful stop -> netdoctor-tun removed & physical default route restored."""
    phys_ifidx = int(elevated_clean_host["phys_ifidx"])
    with live_apply_guard(extra_args=["--iface", str(phys_ifidx)]) as ctx:
        proc = ctx["proc"]
        assert ctx["tun_info"]["tun_ifindex"] is not None
        proc.send_signal(getattr(signal, "CTRL_BREAK_EVENT", signal.SIGTERM))
        try:
            proc.wait(timeout=8.0)
        except subprocess.TimeoutExpired:
            run_netdoctor(["stop"], cwd=repo_root, timeout=10.0)

    byp_after = e2e_support.detect_host_bypasses()
    assert not byp_after["active"], f"Leftover bypasses after clean teardown: {byp_after}"
    assert e2e_support.get_best_interface_index("1.1.1.1") == phys_ifidx
    assert e2e_support.probe_https_target("https://example.com", timeout=8.0)["ok"]
