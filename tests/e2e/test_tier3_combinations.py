"""Tier 3 E2E Tests: Cross-feature pairwise combinations (10 tests: 8 non-elevated + 2 @elevated)."""

from __future__ import annotations

import inspect
import json
import signal
import socket
import subprocess
import time
from pathlib import Path
from typing import Any

import httpx
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


# ---------------------------------------------------------------------------
# Non-Elevated Pairwise Combinations (T3-01 .. T3-08)
# ---------------------------------------------------------------------------


def test_t3_01_f1_x_f3_binaries_and_generated_configs_cross_validate(
    e2e_workspace: E2EWorkspace, bin_dir: Path, lists_dir: Path, run_netdoctor
) -> None:
    from netdoctor import supervisor

    assert hasattr(supervisor, "verify_binaries"), "verify_binaries missing (M1)"
    ver_res = supervisor.verify_binaries(bin_dir, lists_dir)
    assert ver_res.get("ok") is True, f"verify_binaries failed: {ver_res}"

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
    chk = e2e_support.run_singbox_check(bin_dir / "sing-box.exe", sb_path)
    assert chk.returncode == 0, f"sing-box check failed: {chk.stdout} {chk.stderr}"

    tokens = e2e_support.parse_winws2_tokens(e2e_workspace.configs_dir / "winws2_preset.txt")
    refs = e2e_support.resolve_winws2_references(
        tokens, bin_dir=bin_dir, lists_dir=e2e_workspace.lists_dir, workspace_root=e2e_workspace.root
    )
    assert refs
    for tok, resolved, ok in refs:
        assert ok, f"Unresolved winws2 reference {tok} -> {resolved}"


async def test_t3_02_f2_x_f3_fake_censor_diag_and_sub_add_propagate_to_configs(
    e2e_workspace: E2EWorkspace, bin_dir: Path, fake_censor_factory, run_netdoctor
) -> None:
    censor = await fake_censor_factory(mode="sni_dpi", blocked_sni="discord.com")
    tcp_res = await probe_tcp("127.0.0.1", port=censor.tcp_port, timeout=1.5)
    tls_res = await probe_tls("127.0.0.1", real_sni="discord.com", port=censor.tcp_port, timeout=1.5)
    quic_res = await probe_quic("127.0.0.1", sni="discord.com", port=censor.udp_port, timeout=1.0)
    probes = ProbesSummary(
        dns=DnsProbeResult(system="ok", doh="ok", system_ips=["127.0.0.1"], doh_ips=["127.0.0.1"]),
        tcp=tcp_res,
        tls=tls_res,
        quic=quic_res,
    )
    net = NetworkFingerprint(asn=12389, kind=NetworkKind.HOME, isp="e2e-censor")
    report = classify_probes("discord.com", probes, net)
    assert any(v.value == "sni_dpi" for v in report.verdicts), f"Expected sni_dpi verdict, got {report.verdicts}"

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

    sub_uris = (
        "vless://11111111-2222-3333-4444-555555555555@198.51.100.77:443?security=tls#IP-Node\n"
        "trojan://pass@localhost:443?sni=localhost#Host-Node"
    )
    assert (
        run_netdoctor(
            ["sub-add", sub_uris, "--id", "censor-sub", "--db", str(e2e_workspace.db_path)],
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
    assert "198.51.100.77" in ip_entries and "localhost" not in ip_entries

    sb_cfg = e2e_support.load_json_no_bom(e2e_workspace.configs_dir / "sing-box.json")
    out_tags = {o["tag"] for o in sb_cfg["outbounds"]}
    assert {"IP-Node", "Host-Node", "vpn-auto", "vpn-select"}.issubset(out_tags)
    chk = e2e_support.run_singbox_check(bin_dir / "sing-box.exe", e2e_workspace.configs_dir / "sing-box.json")
    assert chk.returncode == 0

    hostlist_files = list(e2e_workspace.lists_dir.glob("*.txt"))
    assert any("discord.com" in f.read_text(encoding="utf-8", errors="replace") for f in hostlist_files)


def test_t3_03_f1_x_f4_tg_ws_proxy_lifecycle_and_handshake(
    e2e_workspace: E2EWorkspace,
    repo_root: Path,
    bin_dir: Path,
    venv_python: Path,
    free_tcp_port: int,
    spawn_supervised_process,
) -> None:
    contract = e2e_support.discover_tg_ws_proxy(repo_root, bin_dir, venv_python)
    assert contract is not None, "tg-ws-proxy artifact not found (M1)"

    cmd, cwd = e2e_support.build_tg_ws_launch_cmd(
        contract,
        host="127.0.0.1",
        port=free_tcp_port,
        portable_dir=e2e_workspace.root / "tg_portable",
    )
    proc = spawn_supervised_process(cmd, cwd=cwd)
    assert e2e_support.wait_for_tcp_port("127.0.0.1", free_tcp_port, timeout=6.0)
    e2e_support.probe_tg_ws_handshake("127.0.0.1", free_tcp_port, contract.protocol_mode)

    try:
        proc.send_signal(getattr(signal, "CTRL_BREAK_EVENT", signal.SIGTERM))
        proc.wait(timeout=5.0)
    except subprocess.TimeoutExpired:
        proc.terminate()
        proc.wait(timeout=5.0)

    with pytest.raises(OSError):
        with socket.create_connection(("127.0.0.1", free_tcp_port), timeout=1.0):
            pass


def test_t3_04_f3_x_f4_singbox_tg_ws_out_matches_live_proxy(
    e2e_workspace: E2EWorkspace,
    repo_root: Path,
    bin_dir: Path,
    venv_python: Path,
    free_tcp_port: int,
    run_netdoctor,
    spawn_supervised_process,
) -> None:
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
    assert res.returncode == 0

    sb_path = e2e_workspace.configs_dir / "sing-box.json"
    cfg = e2e_support.load_json_no_bom(sb_path)
    chk = e2e_support.run_singbox_check(bin_dir / "sing-box.exe", sb_path)
    assert chk.returncode == 0

    contract = e2e_support.discover_tg_ws_proxy(repo_root, bin_dir, venv_python, sb_path)
    assert contract is not None, "tg-ws-proxy artifact not found (M1)"

    tg_out = next((o for o in cfg["outbounds"] if o.get("tag") == "tg-ws-out"), None)
    if tg_out and tg_out.get("type") == "socks":
        assert contract.protocol_mode in ("socks5", "socks", "hybrid")

    cmd, cwd = e2e_support.build_tg_ws_launch_cmd(
        contract,
        host="127.0.0.1",
        port=free_tcp_port,
        portable_dir=e2e_workspace.root / "tg_portable",
    )
    spawn_supervised_process(cmd, cwd=cwd)
    assert e2e_support.wait_for_tcp_port("127.0.0.1", free_tcp_port, timeout=6.0)
    e2e_support.probe_tg_ws_handshake("127.0.0.1", free_tcp_port, contract.protocol_mode)


def test_t3_05_f3_x_f5_apply_no_start_then_supervisor_and_stop(
    e2e_workspace: E2EWorkspace,
    bin_dir: Path,
    venv_python: Path,
    run_netdoctor,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(e2e_workspace.root)
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
    assert res.returncode == 0

    sup = _make_supervisor(e2e_workspace, bin_dir)
    try:
        sb_cfg = e2e_workspace.configs_dir / "sing-box.json"
        sup.start_process(
            "sing-box",
            [str(venv_python), "-c", "import sys, time; print(sys.argv[1], flush=True); time.sleep(30)", str(sb_cfg)],
            cwd=e2e_workspace.root,
        )
        time.sleep(0.3)
        assert e2e_workspace.state_file.is_file(), f"Missing {e2e_workspace.state_file} (M2)"
        st_res = run_netdoctor(["status", "--db", str(e2e_workspace.db_path)], cwd=e2e_workspace.root)
        assert st_res.returncode == 0 and "sing-box" in st_res.stdout

        stop_res = run_netdoctor(["stop"], cwd=e2e_workspace.root)
        assert stop_res.returncode == 0
        if e2e_workspace.state_file.is_file():
            state = json.loads(e2e_workspace.state_file.read_text(encoding="utf-8"))
            assert not state.get("processes")
    finally:
        sup.stop_all()


def test_t3_06_f2_x_f5_status_combines_db_and_live_supervisor_state(
    e2e_workspace: E2EWorkspace,
    bin_dir: Path,
    venv_python: Path,
    run_netdoctor,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(e2e_workspace.root)
    assert (
        run_netdoctor(
            [
                "sub-add",
                "vless://11111111-2222-3333-4444-555555555555@198.51.100.10:443?security=tls#StatusNode",
                "--id",
                "s1",
                "--db",
                str(e2e_workspace.db_path),
            ],
            cwd=e2e_workspace.root,
        ).returncode
        == 0
    )

    sup = _make_supervisor(e2e_workspace, bin_dir)
    try:
        sup.start_process("tg-ws-proxy", [str(venv_python), "-c", "import time; time.sleep(30)"], cwd=e2e_workspace.root)
        time.sleep(0.3)
        assert e2e_workspace.state_file.is_file(), f"Missing {e2e_workspace.state_file} (M2)"
        st_res = run_netdoctor(["status", "--db", str(e2e_workspace.db_path)], cwd=e2e_workspace.root)
        assert st_res.returncode == 0
        assert "1" in st_res.stdout
        assert "tg-ws-proxy" in st_res.stdout and "running" in st_res.stdout.lower()
    finally:
        sup.stop_all()


async def test_t3_07_f1_x_f2_httpx_socks_through_ciadpi_to_fake_censor(
    bin_dir: Path,
    free_tcp_port: int,
    fake_censor_factory,
    spawn_supervised_process,
) -> None:
    ciadpi = bin_dir / "ciadpi.exe"
    assert ciadpi.is_file(), f"Missing {ciadpi} (M1)"

    censor = await fake_censor_factory(mode="ok", blocked_sni="example.com")
    proc = spawn_supervised_process(
        [str(ciadpi), "-i", "127.0.0.1", "-p", str(free_tcp_port)],
        cwd=bin_dir,
    )
    assert e2e_support.wait_for_tcp_port("127.0.0.1", free_tcp_port, timeout=4.0)
    assert proc.poll() is None

    async with httpx.AsyncClient(
        proxy=f"socks5://127.0.0.1:{free_tcp_port}",
        verify=False,
        timeout=5.0,
    ) as client:
        resp = await client.get(f"https://127.0.0.1:{censor.tcp_port}/")
        assert resp.status_code == 200
        assert len(resp.content) == 4096


def test_t3_08_f4_x_f5_readiness_gated_startup_and_reverse_teardown(
    e2e_workspace: E2EWorkspace,
    repo_root: Path,
    bin_dir: Path,
    venv_python: Path,
    free_tcp_port: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(e2e_workspace.root)
    contract = e2e_support.discover_tg_ws_proxy(repo_root, bin_dir, venv_python)
    assert contract is not None, "tg-ws-proxy artifact not found (M1)"

    order_file = e2e_workspace.root / "teardown.txt"
    sup = _make_supervisor(e2e_workspace, bin_dir)
    try:
        cmd, cwd = e2e_support.build_tg_ws_launch_cmd(
            contract,
            host="127.0.0.1",
            port=free_tcp_port,
            portable_dir=e2e_workspace.root / "tg_portable",
        )
        sup.start_process("tg-ws-proxy", cmd, cwd=cwd)
        assert e2e_support.wait_for_tcp_port("127.0.0.1", free_tcp_port, timeout=6.0)

        downstream = (
            "import pathlib, signal, sys, time\n"
            "out = pathlib.Path(sys.argv[1])\n"
            "def _stop(s, f):\n"
            "    out.write_text('downstream_stopped\\n', encoding='utf-8')\n"
            "    sys.exit(0)\n"
            "for s in ('SIGTERM', 'SIGBREAK', 'SIGINT'):\n"
            "    if hasattr(signal, s): signal.signal(getattr(signal, s), _stop)\n"
            "while True: time.sleep(0.1)\n"
        )
        sup.start_process("sing-box", [str(venv_python), "-c", downstream, str(order_file)], cwd=e2e_workspace.root)
        time.sleep(0.2)
        sup.stop_all()

        assert order_file.is_file() and "downstream_stopped" in order_file.read_text(encoding="utf-8")
        with pytest.raises(OSError):
            with socket.create_connection(("127.0.0.1", free_tcp_port), timeout=1.0):
                pass
    finally:
        sup.stop_all()


# ---------------------------------------------------------------------------
# Elevated Pairwise Combinations (T3-09 .. T3-10)
# ---------------------------------------------------------------------------


@pytest.mark.elevated
def test_t3_09_f3_x_f6_wf_iface_and_gvisor_tun_coexist_without_double_desync(
    live_apply_guard, repo_root: Path
) -> None:
    phys_ifidx = e2e_support.get_physical_uplink_ifindex()
    assert phys_ifidx is not None
    with live_apply_guard(extra_args=["--iface", str(phys_ifidx)]) as ctx:
        tun_ifidx = int(ctx["tun_info"]["tun_ifindex"])
        probe = e2e_support.probe_https_target("https://discord.com", timeout=8.0)
        assert probe["ok"], f"Discord probe failed: {probe}"
        parsed = e2e_support.parse_winws2_debug_log(
            repo_root / "logs" / "winws2.log",
            expected_phys_ifidx=phys_ifidx,
            tun_ifidx=tun_ifidx,
        )
        assert parsed["phys_matched"] and not parsed["tun_matched"]


@pytest.mark.elevated
def test_t3_10_f4_x_f6_tg_ws_proxy_process_name_bypass_over_live_tun(
    live_apply_guard, repo_root: Path
) -> None:
    phys_ifidx = e2e_support.get_physical_uplink_ifindex()
    assert phys_ifidx is not None
    with live_apply_guard(extra_args=["--iface", str(phys_ifidx)]):
        sb_cfg = e2e_support.load_json_no_bom(repo_root / "configs" / "sing-box.json")
        tg_out = next((o for o in sb_cfg["outbounds"] if o.get("tag") == "tg-ws-out"), None)
        if tg_out and tg_out.get("server_port"):
            assert e2e_support.wait_for_tcp_port("127.0.0.1", int(tg_out["server_port"]), timeout=5.0)
        sb_log = (repo_root / "logs" / "sing-box.log").read_text(encoding="utf-8", errors="replace")
        assert "loop" not in sb_log.lower()
