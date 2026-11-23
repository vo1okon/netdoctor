"""Tier 1 E2E Tests: Isolated happy-path feature coverage (36 tests: 6 per Feature F1-F6)."""

from __future__ import annotations

import base64
import inspect
import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import psutil
import pytest

import e2e_support
from conftest import E2EWorkspace
from netdoctor.models import Decision, NetworkFingerprint, NetworkKind, Protocol
from netdoctor.probes import detect_bypass_active
from netdoctor.selector import DEFAULT_STRATEGIES
from netdoctor.storage import Storage
from netdoctor.supervisor import ProcessSupervisor


def _seed_stage1_db(
    db_path: Path,
    *,
    with_dpi_decision: bool = True,
    with_vpn_nodes: bool = True,
    vpn_servers: list[str] | None = None,
) -> None:
    storage = Storage(db_path)
    try:
        net = NetworkFingerprint(asn=12389, kind=NetworkKind.HOME, isp="e2e-isp")
        net_key = storage.upsert_network(net)
        storage.upsert_strategies(DEFAULT_STRATEGIES)
        if with_dpi_decision:
            storage.save_decision(
                Decision(
                    network_key=net_key,
                    domain="discord.com",
                    protocol=Protocol.TLS,
                    layer="dpi",
                    strategy_id="tls_multisplit_pos2",
                )
            )
            storage.save_decision(
                Decision(
                    network_key=net_key,
                    domain="instagram.com",
                    protocol=Protocol.TLS,
                    layer="vpn",
                    strategy_id="vpn-select",
                )
            )
        if with_vpn_nodes:
            servers = vpn_servers or ["198.51.100.42", "localhost"]
            nodes = [
                {
                    "tag": f"e2e-node-{idx}",
                    "protocol": "vless",
                    "server": srv,
                    "server_port": 443,
                    "raw_outbound": {
                        "type": "vless",
                        "tag": f"e2e-node-{idx}",
                        "server": srv,
                        "server_port": 443,
                        "uuid": "11111111-2222-3333-4444-555555555555",
                    },
                    "subscription_id": "e2e",
                }
                for idx, srv in enumerate(servers)
            ]
            storage.save_subscription("e2e", "vless://e2e", nodes)
    finally:
        storage.close()


def _make_supervisor(ws: E2EWorkspace, bin_dir: Path) -> ProcessSupervisor:
    sig = inspect.signature(ProcessSupervisor.__init__)
    kwargs: dict[str, Any] = {"bin_dir": bin_dir}
    if "logs_dir" in sig.parameters:
        kwargs["logs_dir"] = ws.logs_dir
    if "state_path" in sig.parameters:
        kwargs["state_path"] = ws.state_file
    return ProcessSupervisor(**kwargs)


# ===========================================================================
# F1: External Tools & Binary Assets (R1) — 6 Tests
# ===========================================================================


def test_t1_f1_01_singbox_version_and_check(repo_root: Path, bin_dir: Path) -> None:
    singbox = bin_dir / "sing-box.exe"
    assert singbox.is_file(), f"Missing {singbox}"

    ver = subprocess.run(
        [str(singbox), "version"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=10.0,
    )
    assert ver.returncode == 0, f"sing-box version failed: {ver.stderr}"
    assert "sing-box version 1.14" in ver.stdout
    assert "with_gvisor" in ver.stdout
    assert "with_quic" in ver.stdout

    chk = e2e_support.run_singbox_check(singbox, repo_root / "configs" / "sing-box.json")
    assert chk.returncode == 0, f"sing-box check failed: {chk.stdout} {chk.stderr}"


def test_t1_f1_02_winws2_bundle_and_verify_binaries(bin_dir: Path, lists_dir: Path) -> None:
    probe = e2e_support.probe_winws2_nondestructive(bin_dir)
    pe: e2e_support.PeInspection = probe["pe"]
    assert pe.exists and pe.is_mz and pe.is_pe, f"Invalid winws2.exe PE: {pe}"

    comp = probe["companions"]
    for dll_name in ("WinDivert.dll", "WinDivert64.sys", "cygwin1.dll"):
        dll_pe: e2e_support.PeInspection = comp[dll_name]
        assert dll_pe.exists and dll_pe.size > 0 and dll_pe.is_mz, f"Invalid {dll_name}: {dll_pe}"

    lua_names = {p.name for p in comp["lua_scripts"]}
    for required_lua in ("zapret-lib.lua", "zapret-antidpi.lua", "zapret-auto.lua"):
        assert required_lua in lua_names, f"Missing {required_lua} under {bin_dir / 'lua'}"
        assert (bin_dir / "lua" / required_lua).stat().st_size > 0

    assert comp["files_dir"] and comp["files_entries"], f"Missing/empty {bin_dir / 'files'}"
    assert comp["windivert_filter_dir"] and comp["windivert_filter_entries"], (
        f"Missing/empty {bin_dir / 'windivert.filter'}"
    )
    if not e2e_support.is_admin():
        assert probe["winerror"] == 740 or probe["returncode"] in (0, 1), (
            f"Unexpected non-Admin probe result: {probe}"
        )

    from netdoctor import supervisor

    assert hasattr(supervisor, "verify_binaries"), "netdoctor.supervisor.verify_binaries missing (M1)"
    status = supervisor.verify_binaries(bin_dir, lists_dir)
    assert isinstance(status, dict)
    winws_entry = status.get("winws2") or status.get("winws2.exe") or status
    if isinstance(winws_entry, dict) and "ok" in winws_entry:
        assert winws_entry["ok"] is True, f"verify_binaries reported winws2 invalid: {status}"
    else:
        assert status.get("ok") is True, f"verify_binaries failed: {status}"


def test_t1_f1_03_blockcheck2_bundle_present(bin_dir: Path) -> None:
    bc_dir = bin_dir / "blockcheck"
    assert bc_dir.is_dir(), f"Missing blockcheck directory: {bc_dir}"
    cmd_file = bc_dir / "blockcheck2.cmd"
    assert cmd_file.is_file() and cmd_file.stat().st_size > 0, f"Missing {cmd_file}"

    zapret2_dir = bc_dir / "zapret2"
    assert zapret2_dir.is_dir(), f"Missing {zapret2_dir}"
    sh_files = list(zapret2_dir.rglob("*.sh"))
    assert sh_files and all(p.stat().st_size > 0 for p in sh_files), "No non-empty zapret2 .sh scripts"

    bin_blobs = list(bc_dir.rglob("*.bin"))
    assert bin_blobs and all(p.stat().st_size > 0 for p in bin_blobs), "No non-empty blockcheck .bin blobs"


def test_t1_f1_04_ciadpi_help_runs(bin_dir: Path) -> None:
    ciadpi = bin_dir / "ciadpi.exe"
    assert ciadpi.is_file(), f"Missing {ciadpi}"
    res = subprocess.run(
        [str(ciadpi), "--help"],
        cwd=str(bin_dir),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=5.0,
    )
    assert res.returncode == 0, f"ciadpi --help exited {res.returncode}: {res.stderr}"
    out = (res.stdout or "") + (res.stderr or "")
    assert "-i" in out and "-p" in out
    assert any(flag in out for flag in ("-s", "-d", "-f"))


def test_t1_f1_05_tg_ws_proxy_bundle_and_help(
    repo_root: Path, bin_dir: Path, venv_python: Path
) -> None:
    contract = e2e_support.discover_tg_ws_proxy(repo_root, bin_dir, venv_python)
    assert contract is not None, "tg-ws-proxy entrypoint/bundle not found in bin/ or .venv (M1)"
    if contract.supports_headless_cli:
        low = contract.help_text.lower()
        assert any(tok in low for tok in ("--port", "--host", "--secret", "proxy")), (
            f"Unexpected tg-ws-proxy --help output: {contract.help_text!r}"
        )
    else:
        pe = e2e_support.inspect_pe_binary(Path(contract.entrypoint))
        assert pe.is_pe and pe.size > 0, f"Invalid tg-ws-proxy PE bundle: {pe}"


def test_t1_f1_06_zapret_lists_presets_and_fetch_bins_help(
    repo_root: Path,
    bin_dir: Path,
    lists_dir: Path,
    presets_dir: Path,
    run_netdoctor,
) -> None:
    required_lists = (
        "list-general.txt",
        "list-google.txt",
        "list-exclude.txt",
        "ipset-exclude.txt",
        "ipset-all.txt",
        "ipset-all.txt.backup",
    )
    for name in required_lists:
        fpath = lists_dir / name
        assert fpath.is_file() and fpath.stat().st_size > 0, f"Missing or empty list: {fpath}"

    backup_lines = (lists_dir / "ipset-all.txt.backup").read_text(encoding="utf-8", errors="replace").splitlines()
    assert len(backup_lines) > 1000, f"Expected >1000 lines in ipset-all.txt.backup, got {len(backup_lines)}"

    bin_blobs = list(bin_dir.rglob("*.bin"))
    assert bin_blobs, f"Expected fake .bin blobs under {bin_dir}"

    assert presets_dir.is_dir(), f"Missing presets directory: {presets_dir}"
    bat_presets = list(presets_dir.rglob("general*.bat"))
    assert bat_presets, f"No general*.bat presets found under {presets_dir}"
    targets_candidates = list(presets_dir.rglob("targets.txt")) + list((repo_root / "lists").rglob("targets.txt"))
    assert targets_candidates, "Missing zapret-discord-youtube utils/targets.txt"

    res = run_netdoctor(["fetch-bins", "--help"])
    assert res.returncode == 0
    assert "--bin-dir" in res.stdout
    assert "--lists-dir" in res.stdout, "fetch-bins missing --lists-dir option (M1)"


# ===========================================================================
# F2: Python .venv & Baseline CLI/Tests — 6 Tests
# ===========================================================================


def test_t1_f2_01_venv_python_and_pip_check(venv_python: Path) -> None:
    ver = subprocess.run(
        [str(venv_python), "--version"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=5.0,
    )
    assert ver.returncode == 0
    assert "Python 3.1" in ver.stdout
    minor = int(ver.stdout.strip().split()[1].split(".")[1])
    assert minor >= 11

    pip_chk = subprocess.run(
        [str(venv_python), "-m", "pip", "check"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=15.0,
    )
    assert pip_chk.returncode == 0, f"pip check failed: {pip_chk.stdout} {pip_chk.stderr}"
    assert "No broken requirements found." in pip_chk.stdout


def test_t1_f2_02_pyproject_runtime_and_dev_imports(venv_python: Path) -> None:
    mods = "httpx, dns, yaml, pydantic, typer, rich, aioquic, psutil, pytest, pytest_asyncio, netdoctor"
    res = subprocess.run(
        [str(venv_python), "-c", f"import {mods}; print('IMPORTS_OK')"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=15.0,
    )
    assert res.returncode == 0, f"Import failure: {res.stderr}"
    assert "IMPORTS_OK" in res.stdout


def test_t1_f2_03_netdoctor_cli_entrypoints_and_commands(
    run_netdoctor, venv_python: Path, repo_root: Path
) -> None:
    r1 = run_netdoctor(["--help"])
    assert r1.returncode == 0
    for subcmd in ("diag", "sub-add", "apply", "stop", "fetch-bins", "status"):
        assert subcmd in r1.stdout, f"CLI --help missing subcommand '{subcmd}'"

    r2 = subprocess.run(
        [str(venv_python), "-m", "netdoctor.cli", "--help"],
        cwd=str(repo_root),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=10.0,
    )
    assert r2.returncode == 0
    assert "netdoctor" in r2.stdout


def test_t1_f2_04_baseline_unit_suite_passes(venv_python: Path, repo_root: Path) -> None:
    res = subprocess.run(
        [str(venv_python), "-m", "pytest", "tests/test_netdoctor.py", "-q"],
        cwd=str(repo_root),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=60.0,
    )
    assert res.returncode == 0, f"Baseline unit tests failed:\n{res.stdout}\n{res.stderr}"
    assert "10 passed" in res.stdout


def test_t1_f2_05_diag_cli_json_and_db_creation(e2e_workspace: E2EWorkspace, run_netdoctor) -> None:
    res = run_netdoctor(
        ["diag", "example.com", "--db", str(e2e_workspace.db_path), "--json", "--timeout", "1.5"],
        cwd=e2e_workspace.root,
        timeout=25.0,
    )
    assert res.returncode == 0, f"diag failed: {res.stderr}"
    payload = json.loads(res.stdout)
    for key in ("domain", "network", "probes", "verdicts", "checked_at"):
        assert key in payload, f"Missing '{key}' in diag JSON output"
    assert payload["domain"] == "example.com"
    assert e2e_workspace.db_path.is_file()


def test_t1_f2_06_sub_add_and_status_cli(e2e_workspace: E2EWorkspace, run_netdoctor) -> None:
    raw_uris = "\n".join(
        [
            "vless://11111111-2222-3333-4444-555555555555@198.51.100.10:443?security=tls#E2E-VLESS",
            "trojan://pass123@198.51.100.11:443?sni=example.com#E2E-Trojan",
        ]
    )
    b64_payload = base64.b64encode(raw_uris.encode("utf-8")).decode("ascii")
    res = run_netdoctor(
        ["sub-add", b64_payload, "--id", "e2e", "--db", str(e2e_workspace.db_path)],
        cwd=e2e_workspace.root,
    )
    assert res.returncode == 0, f"sub-add failed: {res.stderr}"
    assert "2" in res.stdout

    st = run_netdoctor(["status", "--db", str(e2e_workspace.db_path)], cwd=e2e_workspace.root)
    assert st.returncode == 0
    assert "2" in st.stdout


# ===========================================================================
# F3: Stage 1 Config Generation & Validation — 6 Tests
# ===========================================================================


def test_t1_f3_01_apply_no_start_generates_stage1_files(
    e2e_workspace: E2EWorkspace, run_netdoctor
) -> None:
    _seed_stage1_db(e2e_workspace.db_path)
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
    assert res.returncode == 0, f"apply --no-start failed: {res.stdout} {res.stderr}"
    assert (e2e_workspace.configs_dir / "sing-box.json").is_file()
    assert (e2e_workspace.configs_dir / "winws2_preset.txt").is_file()
    assert (e2e_workspace.lists_dir / "exclude_vpn_ips.txt").is_file()
    assert (e2e_workspace.lists_dir / "tls_multisplit_pos2.txt").is_file()


def test_t1_f3_02_singbox_json_no_bom_and_passes_check(
    e2e_workspace: E2EWorkspace, bin_dir: Path, run_netdoctor
) -> None:
    _seed_stage1_db(e2e_workspace.db_path)
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
    cfg = e2e_support.load_json_no_bom(sb_path)
    assert "inbounds" in cfg and "outbounds" in cfg and "route" in cfg

    chk = e2e_support.run_singbox_check(bin_dir / "sing-box.exe", sb_path)
    assert chk.returncode == 0, f"sing-box check failed: {chk.stdout} {chk.stderr}"


def test_t1_f3_03_singbox_json_gvisor_and_loop_exclusions(
    e2e_workspace: E2EWorkspace, run_netdoctor
) -> None:
    _seed_stage1_db(e2e_workspace.db_path)
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

    cfg = e2e_support.load_json_no_bom(e2e_workspace.configs_dir / "sing-box.json")
    tun_in = next((i for i in cfg["inbounds"] if i.get("type") == "tun"), None)
    assert tun_in is not None, "Missing tun inbound"
    assert tun_in.get("interface_name") == "netdoctor-tun"
    assert tun_in.get("stack") == "gvisor", f"Expected stack='gvisor', got {tun_in.get('stack')!r}"
    assert tun_in.get("auto_route") is True

    excluded = tun_in.get("route_exclude_address") or []
    assert any("127.0.0.0/8" in str(x) for x in excluded), (
        f"route_exclude_address missing loopback CIDR: {excluded}"
    )
    assert any(prefix in str(x) for x in excluded for prefix in ("10.0.0.0/8", "192.168.0.0/16")), (
        f"route_exclude_address missing RFC1918 CIDR: {excluded}"
    )

    rules = cfg["route"]["rules"]
    proc_idx = next(
        (
            idx
            for idx, r in enumerate(rules)
            if r.get("outbound") == "direct" and "process_name" in r
        ),
        None,
    )
    tg_idx = next(
        (idx for idx, r in enumerate(rules) if r.get("outbound") == "tg-ws-out"),
        None,
    )
    assert proc_idx is not None, f"Missing process_name -> direct loop-exclusion rule: {rules}"
    proc_names = {p.lower() for p in rules[proc_idx]["process_name"]}
    assert any("winws2" in p for p in proc_names), f"winws2.exe missing from process_name rule: {proc_names}"
    assert any("tg" in p for p in proc_names), f"tg-ws-proxy missing from process_name rule: {proc_names}"
    if tg_idx is not None:
        assert proc_idx < tg_idx, "process_name direct rule must precede tg-ws-out rules"


def test_t1_f3_04_singbox_tg_ws_out_alignment(
    e2e_workspace: E2EWorkspace,
    repo_root: Path,
    bin_dir: Path,
    venv_python: Path,
    run_netdoctor,
) -> None:
    _seed_stage1_db(e2e_workspace.db_path)
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
    cfg = e2e_support.load_json_no_bom(sb_path)
    outbounds = {o["tag"]: o for o in cfg["outbounds"]}
    for rule in cfg["route"]["rules"]:
        if "outbound" in rule:
            assert rule["outbound"] in outbounds, f"Dangling outbound tag: {rule['outbound']}"

    contract = e2e_support.discover_tg_ws_proxy(repo_root, bin_dir, venv_python, sb_path)
    assert contract is not None, "tg-ws-proxy missing for contract alignment check (M1)"
    if "tg-ws-out" in outbounds:
        tg_out = outbounds["tg-ws-out"]
        if contract.protocol_mode == "mtproto":
            assert tg_out.get("type") != "socks", (
                "sing-box tg-ws-out uses type='socks' while tg-ws-proxy is MTProto-only"
            )
        else:
            assert tg_out.get("type") == "socks"
            assert int(tg_out.get("server_port", 0)) == contract.default_port


def test_t1_f3_05_winws2_preset_flags_lua_and_size(
    e2e_workspace: E2EWorkspace, bin_dir: Path, run_netdoctor
) -> None:
    # Seed empty DPI decisions to verify Stage 1 Discord fallback profile as well
    _seed_stage1_db(e2e_workspace.db_path, with_dpi_decision=False)
    res = run_netdoctor(
        [
            "apply",
            "--no-start",
            "--iface",
            "10",
            "--db",
            str(e2e_workspace.db_path),
            "--configs-dir",
            str(e2e_workspace.configs_dir),
            "--lists-dir",
            str(e2e_workspace.lists_dir),
        ],
        cwd=e2e_workspace.root,
    )
    assert res.returncode == 0, f"apply --no-start --iface 10 failed: {res.stderr}"

    preset_path = e2e_workspace.configs_dir / "winws2_preset.txt"
    raw_text = preset_path.read_text(encoding="utf-8")
    assert len(raw_text.encode("utf-8")) < e2e_support.MAX_WINWS2_CONFIG_FILE_BYTES
    tokens = e2e_support.parse_winws2_tokens(preset_path)

    assert any(t.startswith("--wf-tcp-out=") for t in tokens), f"Missing --wf-tcp-out in {tokens}"
    assert any(t.startswith("--wf-iface=10") for t in tokens), f"Missing --wf-iface=10 in {tokens}"
    assert any(t.startswith("--lua-init=@lua/") for t in tokens), (
        f"Expected @lua/ prefix in --lua-init tokens: {tokens}"
    )

    refs = e2e_support.resolve_winws2_references(
        tokens, bin_dir=bin_dir, lists_dir=e2e_workspace.lists_dir, workspace_root=e2e_workspace.root
    )
    assert refs, "Expected file references in winws2_preset.txt"
    for tok, resolved, ok in refs:
        assert ok, f"Unresolved winws2 reference {tok} -> {resolved}"


def test_t1_f3_06_exclude_vpn_ips_resolved_no_raw_hostnames(
    e2e_workspace: E2EWorkspace, run_netdoctor
) -> None:
    _seed_stage1_db(e2e_workspace.db_path, vpn_servers=["198.51.100.42", "localhost"])
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

    ip_file = e2e_workspace.lists_dir / "exclude_vpn_ips.txt"
    entries = e2e_support.validate_ip_only_file(ip_file)
    assert "198.51.100.42" in entries
    assert "localhost" not in entries
    assert any(ip in entries for ip in ("127.0.0.1", "::1")), (
        f"Expected resolved localhost IP in exclude_vpn_ips.txt, got {entries}"
    )


# ===========================================================================
# F4: tg-ws-proxy Launch & Local Port/Protocol Check — 6 Tests
# ===========================================================================


def _start_tg_ws_proxy(
    e2e_workspace: E2EWorkspace,
    repo_root: Path,
    bin_dir: Path,
    venv_python: Path,
    port: int,
    spawn_supervised_process,
):
    contract = e2e_support.discover_tg_ws_proxy(repo_root, bin_dir, venv_python)
    assert contract is not None, "tg-ws-proxy artifact not found in bin/ or .venv (M1 pending)"
    log_path = e2e_workspace.logs_dir / "tg-ws-proxy.log"
    cmd, cwd = e2e_support.build_tg_ws_launch_cmd(
        contract,
        host="127.0.0.1",
        port=port,
        log_file=log_path,
        portable_dir=e2e_workspace.root / "tg_portable",
    )
    log_fp = log_path.open("wb")
    proc = spawn_supervised_process(cmd, cwd=cwd, stdout=log_fp, stderr=subprocess.STDOUT)
    return contract, proc, log_path, log_fp


def test_t1_f4_01_tg_ws_proxy_stays_alive(
    e2e_workspace: E2EWorkspace,
    repo_root: Path,
    bin_dir: Path,
    venv_python: Path,
    free_tcp_port: int,
    spawn_supervised_process,
) -> None:
    _contract, proc, _log_path, log_fp = _start_tg_ws_proxy(
        e2e_workspace, repo_root, bin_dir, venv_python, free_tcp_port, spawn_supervised_process
    )
    try:
        time.sleep(1.5)
        assert proc.poll() is None, f"tg-ws-proxy exited early with code {proc.poll()}"
    finally:
        log_fp.close()


def test_t1_f4_02_tg_ws_proxy_accepts_tcp_connection(
    e2e_workspace: E2EWorkspace,
    repo_root: Path,
    bin_dir: Path,
    venv_python: Path,
    free_tcp_port: int,
    spawn_supervised_process,
) -> None:
    _contract, proc, log_path, log_fp = _start_tg_ws_proxy(
        e2e_workspace, repo_root, bin_dir, venv_python, free_tcp_port, spawn_supervised_process
    )
    try:
        assert e2e_support.wait_for_tcp_port("127.0.0.1", free_tcp_port, timeout=6.0), (
            f"tg-ws-proxy did not listen on 127.0.0.1:{free_tcp_port}; log={log_path.read_text(errors='replace')}"
        )
        with socket.create_connection(("127.0.0.1", free_tcp_port), timeout=2.0):
            pass
        assert proc.poll() is None
    finally:
        log_fp.close()


def test_t1_f4_03_tg_ws_proxy_protocol_handshake(
    e2e_workspace: E2EWorkspace,
    repo_root: Path,
    bin_dir: Path,
    venv_python: Path,
    free_tcp_port: int,
    spawn_supervised_process,
) -> None:
    contract, proc, log_path, log_fp = _start_tg_ws_proxy(
        e2e_workspace, repo_root, bin_dir, venv_python, free_tcp_port, spawn_supervised_process
    )
    try:
        assert e2e_support.wait_for_tcp_port("127.0.0.1", free_tcp_port, timeout=6.0), (
            f"Port not listening; log={log_path.read_text(errors='replace')}"
        )
        e2e_support.probe_tg_ws_handshake("127.0.0.1", free_tcp_port, contract.protocol_mode)
        assert proc.poll() is None
    finally:
        log_fp.close()


def test_t1_f4_04_tg_ws_proxy_startup_log_clean(
    e2e_workspace: E2EWorkspace,
    repo_root: Path,
    bin_dir: Path,
    venv_python: Path,
    free_tcp_port: int,
    spawn_supervised_process,
) -> None:
    _contract, _proc, log_path, log_fp = _start_tg_ws_proxy(
        e2e_workspace, repo_root, bin_dir, venv_python, free_tcp_port, spawn_supervised_process
    )
    try:
        assert e2e_support.wait_for_tcp_port("127.0.0.1", free_tcp_port, timeout=6.0)
        time.sleep(0.3)
        log_fp.flush()
        text = log_path.read_text(encoding="utf-8", errors="replace")
        assert str(free_tcp_port) in text or "127.0.0.1" in text, f"Missing listen log in: {text!r}"
        assert "Traceback (most recent call last)" not in text
    finally:
        log_fp.close()


def test_t1_f4_05_tg_ws_proxy_multiple_connections(
    e2e_workspace: E2EWorkspace,
    repo_root: Path,
    bin_dir: Path,
    venv_python: Path,
    free_tcp_port: int,
    spawn_supervised_process,
) -> None:
    _contract, proc, _log_path, log_fp = _start_tg_ws_proxy(
        e2e_workspace, repo_root, bin_dir, venv_python, free_tcp_port, spawn_supervised_process
    )
    try:
        assert e2e_support.wait_for_tcp_port("127.0.0.1", free_tcp_port, timeout=6.0)
        for _ in range(5):
            with socket.create_connection(("127.0.0.1", free_tcp_port), timeout=2.0):
                pass
        assert proc.poll() is None
    finally:
        log_fp.close()


def test_t1_f4_06_tg_ws_proxy_clean_shutdown_releases_port(
    e2e_workspace: E2EWorkspace,
    repo_root: Path,
    bin_dir: Path,
    venv_python: Path,
    free_tcp_port: int,
    spawn_supervised_process,
) -> None:
    _contract, proc, _log_path, log_fp = _start_tg_ws_proxy(
        e2e_workspace, repo_root, bin_dir, venv_python, free_tcp_port, spawn_supervised_process
    )
    try:
        assert e2e_support.wait_for_tcp_port("127.0.0.1", free_tcp_port, timeout=6.0)
        try:
            proc.send_signal(getattr(signal, "CTRL_BREAK_EVENT", signal.SIGTERM))
            proc.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            proc.terminate()
            proc.wait(timeout=5.0)

        with pytest.raises(OSError):
            with socket.create_connection(("127.0.0.1", free_tcp_port), timeout=1.0):
                pass
    finally:
        log_fp.close()


# ===========================================================================
# F5: Process Supervision & CLI Lifecycle — 6 Tests
# ===========================================================================


def test_t1_f5_01_status_cli_idle_workspace(e2e_workspace: E2EWorkspace, run_netdoctor) -> None:
    _seed_stage1_db(e2e_workspace.db_path)
    res = run_netdoctor(["status", "--db", str(e2e_workspace.db_path)], cwd=e2e_workspace.root)
    assert res.returncode == 0
    assert "discord.com" in res.stdout
    assert "2" in res.stdout
    low = res.stdout.lower()
    assert any(word in low for word in ("stopped", "idle", "not running", "inactive")), (
        f"status output missing process lifecycle state (M2): {res.stdout}"
    )


def test_t1_f5_02_apply_no_start_non_admin_no_processes(
    e2e_workspace: E2EWorkspace, run_netdoctor
) -> None:
    _seed_stage1_db(e2e_workspace.db_path)
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
    if e2e_workspace.state_file.is_file():
        state = json.loads(e2e_workspace.state_file.read_text(encoding="utf-8"))
        assert not state.get("processes"), "apply --no-start must not launch/record running PIDs"


def test_t1_f5_03_process_supervisor_logs_and_status(
    e2e_workspace: E2EWorkspace, bin_dir: Path, venv_python: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(e2e_workspace.root)
    sup = _make_supervisor(e2e_workspace, bin_dir)
    try:
        worker_code = "import sys, time; print(sys.argv[1], flush=True); print('ERR_' + sys.argv[1], file=sys.stderr, flush=True); time.sleep(30)"
        sup.start_process("w1", [str(venv_python), "-c", worker_code, "ALPHA"], cwd=e2e_workspace.root)
        sup.start_process("w2", [str(venv_python), "-c", worker_code, "BETA"], cwd=e2e_workspace.root)
        time.sleep(0.5)

        st = sup.status()
        assert st["w1"]["running"] is True
        assert st["w2"]["running"] is True

        log1 = e2e_workspace.logs_dir / "w1.log"
        log2 = e2e_workspace.logs_dir / "w2.log"
        assert log1.is_file() and "ALPHA" in log1.read_text(encoding="utf-8", errors="replace")
        assert log2.is_file() and "BETA" in log2.read_text(encoding="utf-8", errors="replace")
    finally:
        sup.stop_all()


def test_t1_f5_04_supervisor_state_json_and_status_cli(
    e2e_workspace: E2EWorkspace,
    bin_dir: Path,
    venv_python: Path,
    run_netdoctor,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(e2e_workspace.root)
    _seed_stage1_db(e2e_workspace.db_path)
    sup = _make_supervisor(e2e_workspace, bin_dir)
    try:
        proc = sup.start_process(
            "tg-ws-proxy",
            [str(venv_python), "-c", "import time; time.sleep(30)"],
            cwd=e2e_workspace.root,
        )
        time.sleep(0.3)
        assert e2e_workspace.state_file.is_file(), f"Missing {e2e_workspace.state_file} (M2)"
        state_data = json.loads(e2e_workspace.state_file.read_text(encoding="utf-8"))
        assert str(proc.pid) in json.dumps(state_data)

        st_cli = run_netdoctor(["status", "--db", str(e2e_workspace.db_path)], cwd=e2e_workspace.root)
        assert st_cli.returncode == 0
        assert "tg-ws-proxy" in st_cli.stdout and "running" in st_cli.stdout.lower()
    finally:
        sup.stop_all()


def test_t1_f5_05_reverse_order_shutdown_and_stop(
    e2e_workspace: E2EWorkspace,
    bin_dir: Path,
    venv_python: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(e2e_workspace.root)
    order_log = e2e_workspace.root / "shutdown_order.txt"
    worker_script = (
        "import pathlib, signal, sys, time\n"
        "name, out = sys.argv[1], pathlib.Path(sys.argv[2])\n"
        "def _on_sig(signum, frame):\n"
        "    with out.open('a', encoding='utf-8') as f: f.write(name + '\\n')\n"
        "    sys.exit(0)\n"
        "for s in ('SIGTERM', 'SIGBREAK', 'SIGINT'):\n"
        "    if hasattr(signal, s): signal.signal(getattr(signal, s), _on_sig)\n"
        "while True: time.sleep(0.1)\n"
    )
    sup = _make_supervisor(e2e_workspace, bin_dir)
    try:
        for svc in ("tg-ws-proxy", "winws2", "sing-box"):
            sup.start_process(svc, [str(venv_python), "-c", worker_script, svc, str(order_log)], cwd=e2e_workspace.root)
            time.sleep(0.1)
        sup.stop_all()
        recorded = [ln.strip() for ln in order_log.read_text(encoding="utf-8").splitlines() if ln.strip()]
        assert recorded == ["sing-box", "winws2", "tg-ws-proxy"], f"Expected reverse teardown order, got {recorded}"
    finally:
        sup.stop_all()


def test_t1_f5_06_detect_bypass_active_lifecycle(
    bin_dir: Path, free_tcp_port: int, spawn_supervised_process
) -> None:
    host_bypasses = e2e_support.detect_host_bypasses()
    if host_bypasses["active"]:
        # Host already runs Happ/Zapret/winws2: detect_bypass_active() must detect it (M2 extended check).
        assert detect_bypass_active() is True, (
            f"detect_bypass_active() returned False despite active host bypasses: {host_bypasses}"
        )
        return

    assert detect_bypass_active() is False
    ciadpi = bin_dir / "ciadpi.exe"
    assert ciadpi.is_file(), f"Missing {ciadpi}"
    proc = spawn_supervised_process([str(ciadpi), "-i", "127.0.0.1", "-p", str(free_tcp_port)], cwd=bin_dir)
    assert e2e_support.wait_for_tcp_port("127.0.0.1", free_tcp_port, timeout=4.0)
    assert detect_bypass_active() is True
    proc.terminate()
    proc.wait(timeout=4.0)
    assert detect_bypass_active() is False


# ===========================================================================
# F6: Live Elevated sing-box TUN + winws2 R2 Experiment — 6 Tests (@elevated)
# ===========================================================================


@pytest.mark.elevated
def test_t1_f6_01_elevated_preflight_and_physical_nic(elevated_clean_host: dict[str, Any]) -> None:
    assert elevated_clean_host["admin"] is True
    assert detect_bypass_active() is False
    assert isinstance(elevated_clean_host["phys_ifidx"], int)


@pytest.mark.elevated
def test_t1_f6_02_live_apply_processes_tun_and_ports(
    live_apply_guard, repo_root: Path
) -> None:
    with live_apply_guard(extra_args=["--iface", str(e2e_support.get_physical_uplink_ifindex())]) as ctx:
        time.sleep(5.5)
        assert ctx["proc"].poll() is None, "netdoctor apply exited prematurely"
        running = {p.info["name"].lower() for p in psutil.process_iter(["name"]) if p.info.get("name")}
        assert "sing-box.exe" in running
        assert "winws2.exe" in running
        assert e2e_support.wait_for_tcp_port("127.0.0.1", 2080, timeout=5.0)
        assert (repo_root / "logs" / "sing-box.log").is_file()
        assert (repo_root / "logs" / "winws2.log").is_file()


@pytest.mark.elevated
def test_t1_f6_03_winws2_debug_clienthello_on_physical_nic(
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
            target_domain="discord.com",
        )
        assert not parsed["has_windivert_error"], f"WinDivert error in log: {parsed['text']}"
        assert parsed["phys_matched"], f"No physical IfIdx={phys_ifidx} in winws2.log: {parsed['ifidx_matches']}"
        assert not parsed["tun_matched"], f"winws2 double-intercepted TUN IfIdx={tun_ifidx}"
        assert parsed["has_desync_signal"]


@pytest.mark.elevated
def test_t1_f6_04_pktmon_capture_physical_nic_no_tun_loop(
    live_apply_guard, pktmon_capture
) -> None:
    phys_ifidx = e2e_support.get_physical_uplink_ifindex()
    with live_apply_guard(extra_args=["--iface", str(phys_ifidx)]):
        with pktmon_capture(port=443) as cap:
            probe = e2e_support.probe_https_target("https://discord.com", timeout=8.0)
            assert probe["ok"], f"Discord probe failed: {probe}"
        summary = e2e_support.parse_pcapng_tcp_packets(cap["pcapng"])
        assert summary.total_packets > 0, "No packets captured by pktmon"
        assert summary.tcp_packets > 0, "No TCP/443 packets parsed from pcapng"


@pytest.mark.elevated
def test_t1_f6_05_discord_https_succeeds_under_stage1_profile(live_apply_guard) -> None:
    phys_ifidx = e2e_support.get_physical_uplink_ifindex()
    with live_apply_guard(extra_args=["--iface", str(phys_ifidx)]):
        probe = e2e_support.probe_https_target("https://discord.com", timeout=8.0)
        assert probe["ok"], f"Expected discord.com HTTPS success, got {probe}"


@pytest.mark.elevated
def test_t1_f6_06_nontarget_https_remains_healthy(live_apply_guard) -> None:
    phys_ifidx = e2e_support.get_physical_uplink_ifindex()
    with live_apply_guard(extra_args=["--iface", str(phys_ifidx)]):
        p1 = e2e_support.probe_https_target("https://example.com", timeout=8.0)
        p2 = e2e_support.probe_https_target("https://ya.ru", timeout=8.0)
        assert p1["ok"] or p2["ok"], f"Non-target HTTPS failed: example.com={p1}, ya.ru={p2}"
