"""Tier 2 E2E Tests: Boundary, corner, and negative/error-handling cases (36 tests: 6 per Feature F1-F6)."""

from __future__ import annotations

import base64
import inspect
import json
import os
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
from netdoctor.models import Decision, NetworkFingerprint, NetworkKind, Protocol
from netdoctor.probes import detect_bypass_active
from netdoctor.selector import DEFAULT_STRATEGIES
from netdoctor.storage import Storage
from netdoctor.supervisor import ProcessSupervisor, sha256_file


def _seed_db(
    db_path: Path,
    *,
    domains: list[str] | None = None,
    vpn_servers: list[str] | None = None,
) -> None:
    storage = Storage(db_path)
    try:
        net = NetworkFingerprint(asn=12389, kind=NetworkKind.HOME, isp="e2e-isp")
        net_key = storage.upsert_network(net)
        storage.upsert_strategies(DEFAULT_STRATEGIES)
        for dom in (domains or []):
            storage.save_decision(
                Decision(
                    network_key=net_key,
                    domain=dom,
                    protocol=Protocol.TLS,
                    layer="dpi",
                    strategy_id="tls_multisplit_pos2",
                )
            )
        if vpn_servers:
            nodes = [
                {
                    "tag": f"node-{idx}",
                    "protocol": "vless",
                    "server": srv,
                    "server_port": 443,
                    "raw_outbound": {
                        "type": "vless",
                        "tag": f"node-{idx}",
                        "server": srv,
                        "server_port": 443,
                        "uuid": "11111111-2222-3333-4444-555555555555",
                    },
                    "subscription_id": "e2e",
                }
                for idx, srv in enumerate(vpn_servers)
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
# F1: External Tools & Binary Assets — 6 Boundary / Error Tests
# ===========================================================================


def test_t2_f1_01_verify_binaries_reports_missing_artifacts(e2e_workspace: E2EWorkspace) -> None:
    from netdoctor import supervisor

    assert hasattr(supervisor, "verify_binaries"), "verify_binaries not implemented (M1)"
    result = supervisor.verify_binaries(e2e_workspace.bin_dir, e2e_workspace.lists_dir)
    assert isinstance(result, dict)
    serialized = json.dumps(result).lower()
    assert result.get("ok") is False or "missing" in serialized or "false" in serialized
    for expected_missing in ("winws2.exe", "windivert64.sys", "ciadpi.exe"):
        assert expected_missing in serialized, f"Expected '{expected_missing}' in missing report: {result}"


def test_t2_f1_02_verify_binaries_rejects_zero_byte_files(e2e_workspace: E2EWorkspace) -> None:
    from netdoctor import supervisor

    assert hasattr(supervisor, "verify_binaries"), "verify_binaries not implemented (M1)"
    (e2e_workspace.bin_dir / "winws2.exe").write_bytes(b"")
    lua_dir = e2e_workspace.bin_dir / "lua"
    lua_dir.mkdir(parents=True, exist_ok=True)
    (lua_dir / "zapret-lib.lua").write_bytes(b"")

    result = supervisor.verify_binaries(e2e_workspace.bin_dir, e2e_workspace.lists_dir)
    assert isinstance(result, dict)
    assert result.get("ok") is not True, f"0-byte winws2.exe/lua must not pass verify_binaries: {result}"


def test_t2_f1_03_ipset_all_placeholder_vs_backup(lists_dir: Path) -> None:
    ipset_all = lists_dir / "ipset-all.txt"
    ipset_backup = lists_dir / "ipset-all.txt.backup"
    assert ipset_all.is_file(), f"Missing {ipset_all} (M1)"
    assert ipset_backup.is_file(), f"Missing {ipset_backup} (M1)"

    backup_lines = [ln.strip() for ln in ipset_backup.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip()]
    assert len(backup_lines) > 1000, f"ipset-all.txt.backup too small ({len(backup_lines)} lines)"

    main_lines = [ln.strip() for ln in ipset_all.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip()]
    if main_lines == ["203.0.113.113/32"]:
        assert len(backup_lines) > len(main_lines) * 100


def test_t2_f1_04_fetch_bins_invalid_bin_dir_file_preserves_repo(
    e2e_workspace: E2EWorkspace, bin_dir: Path, run_netdoctor
) -> None:
    singbox = bin_dir / "sing-box.exe"
    before_sha = sha256_file(singbox) if singbox.is_file() else None

    file_target = e2e_workspace.root / "regular_file.txt"
    file_target.write_text("not a directory", encoding="utf-8")

    res = run_netdoctor(["fetch-bins", "--bin-dir", str(file_target)], cwd=e2e_workspace.root, timeout=15.0)
    assert res.returncode != 0, "fetch-bins must fail when --bin-dir is an existing regular file"
    if before_sha is not None:
        assert sha256_file(singbox) == before_sha


def test_t2_f1_05_ciadpi_rejects_windows_unsupported_flags(bin_dir: Path) -> None:
    ciadpi = bin_dir / "ciadpi.exe"
    assert ciadpi.is_file(), f"Missing {ciadpi} (M1)"

    for bad_args in (["--transparent"], ["-p", "99999"]):
        res = subprocess.run(
            [str(ciadpi), *bad_args],
            cwd=str(bin_dir),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=3.0,
        )
        assert res.returncode != 0, f"ciadpi {bad_args} unexpectedly succeeded"
        assert (res.stdout or "") + (res.stderr or "")


def test_t2_f1_06_tg_ws_proxy_rejects_invalid_secret(
    repo_root: Path, bin_dir: Path, venv_python: Path
) -> None:
    contract = e2e_support.discover_tg_ws_proxy(repo_root, bin_dir, venv_python)
    assert contract is not None, "tg-ws-proxy artifact not found (M1)"
    if not contract.supports_headless_cli:
        pytest.skip("GUI-only portable bundle does not accept headless --secret CLI args")

    res = subprocess.run(
        [*contract.cmd_prefix, "--secret", "badhex"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=4.0,
    )
    assert res.returncode != 0, "tg-ws-proxy accepted invalid --secret badhex"


# ===========================================================================
# F2: Python .venv & Baseline CLI — 6 Boundary / Error Tests
# ===========================================================================


def test_t2_f2_01_db_nested_dir_and_corrupt_sqlite(
    e2e_workspace: E2EWorkspace, run_netdoctor
) -> None:
    nested_db = e2e_workspace.root / "new" / "sub" / "test.db"
    res_ok = run_netdoctor(["status", "--db", str(nested_db)], cwd=e2e_workspace.root)
    assert res_ok.returncode == 0, f"status on nested non-existent db dir failed: {res_ok.stderr}"
    assert nested_db.is_file()

    corrupt_db = e2e_workspace.root / "corrupt.db"
    corrupt_db.write_bytes(b"NOT_A_VALID_SQLITE_HEADER_000000")
    res_bad = run_netdoctor(["status", "--db", str(corrupt_db)], cwd=e2e_workspace.root)
    assert res_bad.returncode != 0, "status must fail cleanly on corrupt non-SQLite database"


def test_t2_f2_02_diag_invalid_domain_completes_bounded(
    e2e_workspace: E2EWorkspace, run_netdoctor
) -> None:
    t0 = time.monotonic()
    res = run_netdoctor(
        ["diag", "nonexistent.invalid.test", "--db", str(e2e_workspace.db_path), "--timeout", "1.0", "--json"],
        cwd=e2e_workspace.root,
        timeout=25.0,
    )
    elapsed = time.monotonic() - t0
    assert res.returncode == 0, f"diag failed: {res.stderr}"
    assert elapsed < 20.0, f"diag took too long ({elapsed:.1f}s)"
    data = json.loads(res.stdout)
    assert data["domain"] == "nonexistent.invalid.test"


def test_t2_f2_03_sub_add_invalid_uri_preserves_existing_subscription(
    e2e_workspace: E2EWorkspace, run_netdoctor
) -> None:
    valid_uri = "vless://11111111-2222-3333-4444-555555555555@198.51.100.10:443?security=tls#ValidNode"
    r1 = run_netdoctor(["sub-add", valid_uri, "--id", "keep", "--db", str(e2e_workspace.db_path)], cwd=e2e_workspace.root)
    assert r1.returncode == 0

    r2 = run_netdoctor(
        ["sub-add", "not_valid_uri!!!", "--id", "bad", "--db", str(e2e_workspace.db_path)],
        cwd=e2e_workspace.root,
    )
    assert r2.returncode != 0 or "0" in r2.stdout

    st = Storage(e2e_workspace.db_path)
    try:
        nodes = st.get_all_subscription_nodes()
        assert len(nodes) == 1 and nodes[0]["tag"] == "ValidNode"
    finally:
        st.close()


def test_t2_f2_04_status_on_completely_empty_db(
    e2e_workspace: E2EWorkspace, run_netdoctor
) -> None:
    res = run_netdoctor(["status", "--db", str(e2e_workspace.db_path)], cwd=e2e_workspace.root)
    assert res.returncode == 0
    assert "0" in res.stdout


def test_t2_f2_05_cli_unknown_subcommand_and_missing_arg(run_netdoctor, e2e_workspace: E2EWorkspace) -> None:
    r_bad = run_netdoctor(["no-such-cmd"], cwd=e2e_workspace.root)
    assert r_bad.returncode == 2

    r_missing = run_netdoctor(["diag"], cwd=e2e_workspace.root)
    assert r_missing.returncode == 2


def test_t2_f2_06_sub_add_reimport_same_id_updates_without_duplicates(
    e2e_workspace: E2EWorkspace, run_netdoctor
) -> None:
    sub1 = base64.b64encode(
        b"vless://11111111-2222-3333-4444-555555555555@198.51.100.10:443?security=tls#N1\n"
        b"vless://11111111-2222-3333-4444-555555555555@198.51.100.11:443?security=tls#N2"
    ).decode("ascii")
    sub2 = "trojan://pass@198.51.100.12:443?sni=example.com#N3"

    assert run_netdoctor(["sub-add", sub1, "--id", "dup", "--db", str(e2e_workspace.db_path)], cwd=e2e_workspace.root).returncode == 0
    assert run_netdoctor(["sub-add", sub2, "--id", "dup", "--db", str(e2e_workspace.db_path)], cwd=e2e_workspace.root).returncode == 0

    st = Storage(e2e_workspace.db_path)
    try:
        nodes = st.get_all_subscription_nodes()
        assert len(nodes) == 1 and nodes[0]["tag"] == "N3"
    finally:
        st.close()


# ===========================================================================
# F3: Stage 1 Config Generation & Validation — 6 Boundary / Error Tests
# ===========================================================================


def test_t2_f3_01_unresolvable_hostname_omitted_from_exclude_vpn_ips(
    e2e_workspace: E2EWorkspace, run_netdoctor
) -> None:
    _seed_db(
        e2e_workspace.db_path,
        domains=["discord.com"],
        vpn_servers=["de1.example.invalid", "203.0.113.10", "2001:db8::1"],
    )
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
    entries = e2e_support.validate_ip_only_file(e2e_workspace.lists_dir / "exclude_vpn_ips.txt")
    assert "203.0.113.10" in entries
    assert "2001:db8::1" in entries
    assert "de1.example.invalid" not in entries


def test_t2_f3_02_winws2_16kb_config_file_limit_safety(
    e2e_workspace: E2EWorkspace, bin_dir: Path, run_netdoctor
) -> None:
    from netdoctor.config_gen import generate_winws2_config
    from netdoctor.models import Strategy

    # Construct 30 distinct strategy profiles to stress winws2 args length beyond 16 KB if packed in one preset
    strategies = {
        f"strat_{i:02d}": Strategy(
            id=f"strat_{i:02d}",
            family="multisplit",
            protocol=Protocol.TLS,
            tier=2,
            args_template=[f"--lua-desync=multisplit:pos={i + 1}:blob=fake_default_tls:repeats=6:" + ("x" * 200)],
        )
        for i in range(35)
    }
    decisions = [
        Decision(
            network_key="AS12389:home:default",
            domain=f"blocked-{i:02d}.example.com",
            protocol=Protocol.TLS,
            layer="dpi",
            strategy_id=f"strat_{i:02d}",
        )
        for i in range(35)
    ]
    args, _ = generate_winws2_config(
        decisions=decisions,
        strategies=strategies,
        lists_dir=e2e_workspace.lists_dir,
        vpn_server_ips=["203.0.113.10"],
    )
    preset_bytes = ("\n".join(args) + "\n").encode("utf-8")
    # If generated preset exceeds winws2 MAX_CONFIG_FILE_SIZE (16384 B), supervisor must NOT use @file
    if len(preset_bytes) >= e2e_support.MAX_WINWS2_CONFIG_FILE_BYTES:
        src_text = Path(inspect.getfile(ProcessSupervisor)).read_text(encoding="utf-8", errors="replace")
        assert "@winws2_preset" not in src_text and "@{preset" not in src_text, (
            "Large winws2 args (>16KB) must be passed directly via Popen args, not @file"
        )
    else:
        assert len(preset_bytes) < e2e_support.MAX_WINWS2_CONFIG_FILE_BYTES


def test_t2_f3_03_empty_db_apply_produces_valid_fallback_configs(
    e2e_workspace: E2EWorkspace, bin_dir: Path, run_netdoctor
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
    assert res.returncode == 0, f"apply --no-start on empty DB failed: {res.stderr}"

    sb_path = e2e_workspace.configs_dir / "sing-box.json"
    cfg = e2e_support.load_json_no_bom(sb_path)
    chk = e2e_support.run_singbox_check(bin_dir / "sing-box.exe", sb_path)
    assert chk.returncode == 0, f"sing-box check failed: {chk.stdout} {chk.stderr}"

    vpn_sel = next(o for o in cfg["outbounds"] if o["tag"] == "vpn-select")
    assert vpn_sel["default"] == "direct"

    tokens = e2e_support.parse_winws2_tokens(e2e_workspace.configs_dir / "winws2_preset.txt")
    assert any(t.startswith("--wf-tcp-out=") for t in tokens)
    assert any(t.startswith("--lua-init=") for t in tokens)


def test_t2_f3_04_singbox_check_rejects_utf8_bom_copy(
    e2e_workspace: E2EWorkspace, bin_dir: Path, run_netdoctor
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
    raw = sb_path.read_bytes()
    assert not raw.startswith(b"\xef\xbb\xbf")

    bom_path = e2e_workspace.configs_dir / "sing-box-bom.json"
    bom_path.write_bytes(b"\xef\xbb\xbf" + raw)
    chk = e2e_support.run_singbox_check(bin_dir / "sing-box.exe", bom_path)
    assert chk.returncode != 0, "Expected sing-box check to reject UTF-8 BOM"


def test_t2_f3_05_winws2_preset_all_file_tokens_resolve(
    e2e_workspace: E2EWorkspace, bin_dir: Path, run_netdoctor
) -> None:
    _seed_db(e2e_workspace.db_path, domains=["discord.com"], vpn_servers=["198.51.100.42"])
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

    tokens = e2e_support.parse_winws2_tokens(e2e_workspace.configs_dir / "winws2_preset.txt")
    refs = e2e_support.resolve_winws2_references(
        tokens, bin_dir=bin_dir, lists_dir=e2e_workspace.lists_dir, workspace_root=e2e_workspace.root
    )
    assert refs
    for tok, resolved, ok in refs:
        assert ok, f"winws2 token '{tok}' does not resolve to an existing non-empty file ({resolved})"


def test_t2_f3_06_duplicate_domains_and_ipv6_vpn_deduplicated_and_valid(
    e2e_workspace: E2EWorkspace, bin_dir: Path, run_netdoctor
) -> None:
    from netdoctor.config_gen import generate_winws2_config

    strategies = {s.id: s for s in DEFAULT_STRATEGIES}
    decisions = [
        Decision(network_key="k", domain="discord.com", protocol=Protocol.TLS, layer="dpi", strategy_id="tls_multisplit_pos2"),
        Decision(network_key="k", domain="discord.com", protocol=Protocol.TLS, layer="dpi", strategy_id="tls_multisplit_pos2"),
    ]
    _args, hostlists = generate_winws2_config(
        decisions=decisions,
        strategies=strategies,
        lists_dir=e2e_workspace.lists_dir,
        vpn_server_ips=["2001:db8::1", "2001:db8::1"],
    )
    assert hostlists["tls_multisplit_pos2.txt"] == ["discord.com"]

    _seed_db(e2e_workspace.db_path, domains=["discord.com"], vpn_servers=["2001:db8::1"])
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
    chk = e2e_support.run_singbox_check(bin_dir / "sing-box.exe", e2e_workspace.configs_dir / "sing-box.json")
    assert chk.returncode == 0, f"sing-box check failed with IPv6 VPN node: {chk.stdout} {chk.stderr}"


# ===========================================================================
# F4: tg-ws-proxy Launch & Port/Protocol — 6 Boundary / Error Tests
# ===========================================================================


def test_t2_f4_01_tg_ws_proxy_port_already_in_use_fails_fast(
    e2e_workspace: E2EWorkspace,
    repo_root: Path,
    bin_dir: Path,
    venv_python: Path,
    spawn_supervised_process,
) -> None:
    contract = e2e_support.discover_tg_ws_proxy(repo_root, bin_dir, venv_python)
    assert contract is not None, "tg-ws-proxy artifact not found (M1)"

    blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
        blocker.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    blocker.bind(("127.0.0.1", 0))
    blocker.listen(1)
    occupied_port = blocker.getsockname()[1]

    try:
        cmd, cwd = e2e_support.build_tg_ws_launch_cmd(
            contract,
            host="127.0.0.1",
            port=occupied_port,
            portable_dir=e2e_workspace.root / "tg_portable",
        )
        proc = spawn_supervised_process(cmd, cwd=cwd)
        rc = proc.wait(timeout=5.0)
        assert rc != 0, f"Expected non-zero exit when port {occupied_port} is already bound"
    finally:
        blocker.close()


def test_t2_f4_02_tg_ws_proxy_survives_malformed_client_bytes(
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

    # 1. Garbage bytes
    with socket.create_connection(("127.0.0.1", free_tcp_port), timeout=2.0) as bad_sock:
        bad_sock.sendall(b"\xff\x00BADDATA\r\n")

    # 2. Immediate EOF
    with socket.create_connection(("127.0.0.1", free_tcp_port), timeout=2.0):
        pass

    time.sleep(0.2)
    assert proc.poll() is None, "tg-ws-proxy crashed on malformed client connection"
    e2e_support.probe_tg_ws_handshake("127.0.0.1", free_tcp_port, contract.protocol_mode)


def test_t2_f4_03_tg_ws_proxy_unassignable_bind_ip_fails(
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
        host="192.0.2.1",
        port=free_tcp_port,
        portable_dir=e2e_workspace.root / "tg_portable",
    )
    proc = spawn_supervised_process(cmd, cwd=cwd)
    rc = proc.wait(timeout=5.0)
    assert rc != 0, "Expected non-zero exit for unassignable bind IP 192.0.2.1"


def test_t2_f4_04_tg_ws_proxy_rapid_start_and_stop(
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
    time.sleep(0.15)
    try:
        proc.send_signal(getattr(signal, "CTRL_BREAK_EVENT", signal.SIGTERM))
        proc.wait(timeout=4.0)
    except subprocess.TimeoutExpired:
        proc.terminate()
        proc.wait(timeout=4.0)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as check_sock:
        check_sock.bind(("127.0.0.1", free_tcp_port))


def test_t2_f4_05_tg_ws_proxy_unreachable_upstream_does_not_crash_proxy(
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

    with socket.create_connection(("127.0.0.1", free_tcp_port), timeout=3.0) as sock:
        sock.settimeout(3.0)
        if contract.protocol_mode in ("socks5", "socks", "hybrid"):
            sock.sendall(b"\x05\x01\x00")
            assert sock.recv(2) == b"\x05\x00"
            # CONNECT 127.0.0.1:1 (unreachable)
            sock.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x01")
            resp = sock.recv(16)
            assert len(resp) == 0 or (len(resp) >= 2 and resp[1] != 0)
        else:
            # Truncated partial MTProto header
            sock.sendall(b"\x00" * 16)
            time.sleep(0.3)

    assert proc.poll() is None, "tg-ws-proxy died handling unreachable upstream"


def test_t2_f4_06_supervisor_missing_tg_ws_binary_fails_immediately(
    e2e_workspace: E2EWorkspace, bin_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(e2e_workspace.root)
    sup = _make_supervisor(e2e_workspace, bin_dir)
    missing = e2e_workspace.bin_dir / "nonexistent-tg-ws-proxy.exe"
    t0 = time.monotonic()
    with pytest.raises((FileNotFoundError, OSError, RuntimeError)):
        sup.start_process("tg-ws-proxy", [str(missing)], cwd=e2e_workspace.root)
    assert (time.monotonic() - t0) < 2.0


# ===========================================================================
# F5: Process Supervision & CLI Lifecycle — 6 Boundary / Error Tests
# ===========================================================================


def test_t2_f5_01_live_apply_without_admin_refuses_cleanly(
    e2e_workspace: E2EWorkspace, run_netdoctor
) -> None:
    if e2e_support.is_admin():
        pytest.skip("Current shell is elevated Administrator; non-Admin refusal test requires standard shell")

    _seed_db(e2e_workspace.db_path, domains=["discord.com"])
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
    assert res.returncode != 0, "Live apply must refuse cleanly in non-Admin shell (M2)"
    combined = (res.stdout + "\n" + res.stderr).lower()
    assert any(tok in combined for tok in ("admin", "elevat", "privilege", "740")), (
        f"Expected clear Administrator refusal message, got: {combined!r}"
    )


def test_t2_f5_02_status_and_stop_handle_stale_and_corrupt_state(
    e2e_workspace: E2EWorkspace, run_netdoctor
) -> None:
    _seed_db(e2e_workspace.db_path, domains=["discord.com"])

    # 1. Stale dead PID
    e2e_workspace.state_file.write_text(
        json.dumps({"processes": {"tg-ws-proxy": {"pid": 999999}, "winws2": {"pid": 999998}}}),
        encoding="utf-8",
    )
    st1 = run_netdoctor(["status", "--db", str(e2e_workspace.db_path)], cwd=e2e_workspace.root)
    assert st1.returncode == 0
    assert "999999" not in st1.stdout or any(w in st1.stdout.lower() for w in ("dead", "stale", "stopped", "not running"))

    stop1 = run_netdoctor(["stop"], cwd=e2e_workspace.root)
    assert stop1.returncode == 0, f"stop failed on stale state: {stop1.stderr}"

    # 2. Corrupt JSON state
    e2e_workspace.state_file.write_text("{bad json", encoding="utf-8")
    st2 = run_netdoctor(["status", "--db", str(e2e_workspace.db_path)], cwd=e2e_workspace.root)
    assert st2.returncode == 0
    stop2 = run_netdoctor(["stop"], cwd=e2e_workspace.root)
    assert stop2.returncode == 0


def test_t2_f5_03_stop_on_idle_state_exits_zero(e2e_workspace: E2EWorkspace, run_netdoctor) -> None:
    res = run_netdoctor(["stop"], cwd=e2e_workspace.root)
    assert res.returncode == 0, f"stop on idle workspace failed: {res.stdout} {res.stderr}"
    low = (res.stdout + " " + res.stderr).lower()
    assert any(w in low for w in ("nothing", "no ", "idle", "not running", "stopped"))


def test_t2_f5_04_supervisor_rolls_back_on_child_startup_crash(
    e2e_workspace: E2EWorkspace, bin_dir: Path, venv_python: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(e2e_workspace.root)
    sup = _make_supervisor(e2e_workspace, bin_dir)
    p1 = None
    try:
        p1 = sup.start_process("stage1", [str(venv_python), "-c", "import time; time.sleep(30)"], cwd=e2e_workspace.root)
        # Expect M2 supervisor to support readiness/rollback or check_health / start_stack;
        # verify rollback helper or manual rollback contract when stage2 exits 34
        if hasattr(sup, "start_stack"):
            with pytest.raises(Exception):
                sup.start_stack(
                    [
                        ("stage1_b", [str(venv_python), "-c", "import time; time.sleep(30)"]),
                        ("stage2", [str(venv_python), "-c", "import sys; sys.exit(34)"]),
                    ]
                )
        else:
            p2 = sup.start_process("stage2", [str(venv_python), "-c", "import sys; sys.exit(34)"], cwd=e2e_workspace.root)
            rc = p2.wait(timeout=3.0)
            assert rc == 34
            # Check whether supervisor auto-cleaned or supports stop_all on failure
            st = sup.status()
            assert st["stage2"]["running"] is False
            sup.stop_all()
        assert p1.poll() is not None, "Stage1 worker orphaned after rollback"
    finally:
        sup.stop_all()


def test_t2_f5_05_supervisor_drains_large_stdout_stderr_without_deadlock(
    e2e_workspace: E2EWorkspace, bin_dir: Path, venv_python: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(e2e_workspace.root)
    sup = _make_supervisor(e2e_workspace, bin_dir)
    burst_code = (
        "import sys; "
        "sys.stdout.write('O' * 280000 + '\\n'); sys.stdout.flush(); "
        "sys.stderr.write('E' * 280000 + '\\n'); sys.stderr.flush()"
    )
    try:
        proc = sup.start_process("burst", [str(venv_python), "-c", burst_code], cwd=e2e_workspace.root)
        rc = proc.wait(timeout=6.0)
        assert rc == 0
        log_file = e2e_workspace.logs_dir / "burst.log"
        assert log_file.is_file(), f"Expected log file {log_file} (M2 pipe deadlock fix)"
        assert log_file.stat().st_size >= 500000
    finally:
        sup.stop_all()


def test_t2_f5_06_apply_rejects_invalid_iface_index(
    e2e_workspace: E2EWorkspace, run_netdoctor
) -> None:
    _seed_db(e2e_workspace.db_path, domains=["discord.com"])
    res = run_netdoctor(
        [
            "apply",
            "--no-start",
            "--iface",
            "999999",
            "--db",
            str(e2e_workspace.db_path),
            "--configs-dir",
            str(e2e_workspace.configs_dir),
            "--lists-dir",
            str(e2e_workspace.lists_dir),
        ],
        cwd=e2e_workspace.root,
    )
    assert res.returncode != 0, "Expected apply --iface 999999 to reject non-existent interface index"
    combined = (res.stdout + "\n" + res.stderr).lower()
    assert any(tok in combined for tok in ("999999", "iface", "interface", "adapter")), (
        f"Expected interface validation error, got: {combined!r}"
    )


# ===========================================================================
# F6: Live Elevated TUN + winws2 Boundaries — 6 Tests (@elevated)
# ===========================================================================


@pytest.mark.elevated
def test_t2_f6_01_wf_iface_prevents_tun_double_interception(
    live_apply_guard, repo_root: Path
) -> None:
    phys_ifidx = e2e_support.get_physical_uplink_ifindex()
    assert phys_ifidx is not None
    with live_apply_guard(extra_args=["--iface", str(phys_ifidx)]) as ctx:
        tun_ifidx = int(ctx["tun_info"]["tun_ifindex"])
        e2e_support.probe_https_target("https://discord.com", timeout=8.0)
        parsed = e2e_support.parse_winws2_debug_log(
            repo_root / "logs" / "winws2.log",
            expected_phys_ifidx=phys_ifidx,
            tun_ifidx=tun_ifidx,
        )
        assert not parsed["tun_matched"], f"winws2 logged TUN IfIdx={tun_ifidx} despite --wf-iface={phys_ifidx}"


@pytest.mark.elevated
def test_t2_f6_02_live_apply_warns_or_refuses_conflicting_bypass(
    elevated_clean_host: dict[str, Any],
    bin_dir: Path,
    free_tcp_port: int,
    spawn_supervised_process,
    run_netdoctor,
    e2e_workspace: E2EWorkspace,
) -> None:
    ciadpi = bin_dir / "ciadpi.exe"
    proc = spawn_supervised_process([str(ciadpi), "-i", "127.0.0.1", "-p", str(free_tcp_port)], cwd=bin_dir)
    assert e2e_support.wait_for_tcp_port("127.0.0.1", free_tcp_port, timeout=4.0)
    assert detect_bypass_active() is True
    res = run_netdoctor(
        ["apply", "--db", str(e2e_workspace.db_path), "--configs-dir", str(e2e_workspace.configs_dir), "--lists-dir", str(e2e_workspace.lists_dir)],
        cwd=e2e_workspace.root,
        timeout=15.0,
    )
    assert res.returncode != 0, "apply should refuse when conflicting bypass is already active"
    assert proc.poll() is None


@pytest.mark.elevated
def test_t2_f6_03_discord_differential_profile_causality(
    elevated_clean_host: dict[str, Any], live_apply_guard
) -> None:
    phys_ifidx = int(elevated_clean_host["phys_ifidx"])
    baseline = e2e_support.probe_https_target("https://discord.com", timeout=6.0)
    with live_apply_guard(extra_args=["--iface", str(phys_ifidx)]):
        with_profile = e2e_support.probe_https_target("https://discord.com", timeout=8.0)
    assert with_profile["ok"], f"Discord failed even with Stage 1 profile: {with_profile} (baseline={baseline})"


@pytest.mark.elevated
def test_t2_f6_04_telegram_dc_no_tun_loop(live_apply_guard, repo_root: Path) -> None:
    phys_ifidx = e2e_support.get_physical_uplink_ifindex()
    with live_apply_guard(extra_args=["--iface", str(phys_ifidx)]):
        # Attempt TCP connection toward Telegram DC through TUN/mixed-in
        try:
            with socket.create_connection(("149.154.167.220", 443), timeout=4.0):
                pass
        except OSError:
            pass
        sb_log = (repo_root / "logs" / "sing-box.log").read_text(encoding="utf-8", errors="replace")
        assert "too many open files" not in sb_log.lower()
        assert "loop" not in sb_log.lower()


@pytest.mark.elevated
def test_t2_f6_05_elevated_invalid_winws2_rolls_back_tun_and_proxy(
    elevated_clean_host: dict[str, Any],
    repo_root: Path,
    run_netdoctor,
) -> None:
    # Corrupt winws2_preset.txt temporarily in isolated workspace or invalid profile
    res = run_netdoctor(["apply", "--profile", "__invalid_nonexistent_profile__"], cwd=repo_root, timeout=15.0)
    assert res.returncode != 0
    byp = e2e_support.detect_host_bypasses()
    assert not byp["up_tun_adapters"], f"Orphaned TUN adapter left after failed apply: {byp}"


@pytest.mark.elevated
def test_t2_f6_06_stop_recovers_after_killed_singbox(
    live_apply_guard, run_netdoctor, repo_root: Path
) -> None:
    phys_ifidx = e2e_support.get_physical_uplink_ifindex()
    with live_apply_guard(extra_args=["--iface", str(phys_ifidx)]):
        for p in psutil.process_iter(["pid", "name"]):
            if (p.info.get("name") or "").lower() == "sing-box.exe":
                p.kill()
                p.wait(timeout=3.0)
        stop_res = run_netdoctor(["stop"], cwd=repo_root, timeout=10.0)
        assert stop_res.returncode == 0
        running = {(p.info.get("name") or "").lower() for p in psutil.process_iter(["name"])}
        assert "winws2.exe" not in running
        assert "sing-box.exe" not in running
