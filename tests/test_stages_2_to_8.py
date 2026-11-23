"""Unit and integration tests covering netdoctor Stages 2 through 8."""

from __future__ import annotations

import base64
import json
import struct
import subprocess
import sys
import zlib
from pathlib import Path

import pytest

from netdoctor.classifier import classify_probes
from netdoctor.config_gen import generate_singbox_config, generate_winws2_config
from netdoctor.dynamics import (
    get_downshift_candidates,
    parse_circular_rotations,
    run_canary_cycle,
)
from netdoctor.gui import NetdoctorController, launch_gui
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
from netdoctor.probes import probe_protocol_block
from netdoctor.selector import (
    DEFAULT_STRATEGIES,
    live_winws2_strategy_evaluator,
    load_strategies_from_yaml,
    load_targets_from_yaml,
    parse_blockcheck2_output,
    select_best_strategy,
)
from netdoctor.storage import Storage
from netdoctor.vpn import parse_subscription_payload, refresh_all_subscriptions
from tests.fake_censor import FakeCensorServer


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_alt9_strategies_and_blob_injection(tmp_path: Path) -> None:
    yaml_strats = load_strategies_from_yaml(REPO_ROOT / "configs" / "strategies.yaml")
    yaml_ids = {s.id for s in yaml_strats}
    default_ids = {s.id for s in DEFAULT_STRATEGIES}
    expected_alt9 = {
        "tls_hostfakesplit_ozon",
        "tls_hostfakesplit_google",
        "tls_fakedsplit_autottl",
        "tls_alt9_youtube_video",
        "tls_alt9_discord",
        "quic_fake_google_autottl",
    }
    assert expected_alt9.issubset(yaml_ids)
    assert expected_alt9.issubset(default_ids)

    strat_map = {s.id: s for s in DEFAULT_STRATEGIES}
    decisions = [
        Decision(
            network_key="AS12389:home:default",
            domain="googlevideo.com",
            protocol=Protocol.TLS,
            layer="dpi",
            strategy_id="tls_alt9_youtube_video",
        ),
        Decision(
            network_key="AS12389:home:default",
            domain="youtube.com",
            protocol=Protocol.QUIC,
            layer="dpi",
            strategy_id="quic_fake_google_autottl",
        ),
    ]
    args, hostlists = generate_winws2_config(
        decisions=decisions,
        strategies=strat_map,
        lists_dir=tmp_path / "lists",
    )
    assert "--blob=tls_google:@files/tls_clienthello_www_google_com.bin" in args
    assert "--blob=quic_google:@files/quic_initial_www_google_com.bin" in args
    assert "tls_alt9_youtube_video.txt" in hostlists
    assert "quic_fake_google_autottl.txt" in hostlists


def test_targets_yaml_loader_and_dual_protocol_diag_storage(tmp_path: Path) -> None:
    targets = load_targets_from_yaml(REPO_ROOT / "configs" / "targets.yaml")
    assert len(targets) >= 6
    assert any(t["domain"] == "discord.com" for t in targets)

    db_path = tmp_path / "dual.db"
    st = Storage(db_path)
    try:
        net = NetworkFingerprint(asn=12389, kind=NetworkKind.HOME)
        net_key = st.upsert_network(net)
        st.upsert_strategies(DEFAULT_STRATEGIES)
        probes = ProbesSummary(
            dns=DnsProbeResult(system="ok", doh="ok"),
            tcp=TcpProbeResult(result="ok"),
            tls=TlsProbeResult(real_sni="reset", neutral_sni="ok"),
            stall=StallProbeResult(result="ok"),
            quic=QuicProbeResult(result="timeout"),
        )
        report = classify_probes("discord.com", probes, net)
        assert VerdictClass.SNI_DPI in report.verdicts
        assert VerdictClass.QUIC_BLOCK in report.verdicts

        st.save_verdict(net_key, report, protocol=Protocol.TLS)
        st.save_verdict(net_key, report, protocol=Protocol.QUIC)
        st.save_decision(
            Decision(
                network_key=net_key,
                domain="discord.com",
                protocol=Protocol.TLS,
                layer="dpi",
                strategy_id="tls_multisplit_pos2",
            )
        )
        st.save_decision(
            Decision(
                network_key=net_key,
                domain="discord.com",
                protocol=Protocol.QUIC,
                layer="dpi",
                strategy_id="quic_fake_repeats6",
            )
        )
        decs = st.get_decisions(net_key)
        assert {(d.domain, d.protocol) for d in decs} == {
            ("discord.com", Protocol.TLS),
            ("discord.com", Protocol.QUIC),
        }
    finally:
        st.close()


async def test_blockcheck2_parser_and_live_evaluator_fallback(tmp_path: Path) -> None:
    sample_bc2 = """
    testing ipv4 discord.com
    * WORKING: --lua-desync=multisplit:pos=1:seqovl=5 --lua-desync=fake:blob=fake_default_tls:repeats=4
    * WORKING: --lua-desync=fakedsplit:pos=2
    """
    parsed = parse_blockcheck2_output(sample_bc2, protocol=Protocol.TLS)
    assert len(parsed) == 2
    assert parsed[0].family == "multisplit"
    assert len(parsed[0].args_template) == 2
    assert parsed[1].args_template == ["--lua-desync=fakedsplit:pos=2"]

    censor = FakeCensorServer(mode="ok", blocked_sni="example.com")
    await censor.start()
    try:
        # Missing bin_dir triggers safe fallback to default_strategy_evaluator
        ev = await live_winws2_strategy_evaluator(
            domain="example.com",
            ip="127.0.0.1",
            strategy=DEFAULT_STRATEGIES[0],
            port=censor.tcp_port,
            repeats=1,
            bin_dir=tmp_path / "no_bin",
        )
        assert ev.success_rate == 1.0
        assert ev.throughput_kbps > 0
    finally:
        await censor.stop()


async def test_protocol_block_probe_and_classifier_escalation() -> None:
    censor_ok = FakeCensorServer(mode="ok", blocked_sni="vpn.example.com")
    await censor_ok.start()
    try:
        res_ok = await probe_protocol_block("127.0.0.1", port=censor_ok.tcp_port, sni="vpn.example.com", timeout=1.5)
        assert res_ok.result == "ok"
    finally:
        await censor_ok.stop()

    censor_th = FakeCensorServer(mode="throttle", blocked_sni="vpn.example.com")
    await censor_th.start()
    try:
        res_blk = await probe_protocol_block("127.0.0.1", port=censor_th.tcp_port, sni="vpn.example.com", timeout=1.0)
        assert res_blk.result == "protocol_block"
    finally:
        await censor_th.stop()

    probes = ProbesSummary(
        dns=DnsProbeResult(system="ok", doh="ok"),
        tcp=TcpProbeResult(result="ok"),
        tls=TlsProbeResult(real_sni="ok", neutral_sni="ok"),
        stall=StallProbeResult(result="ok"),
        quic=QuicProbeResult(result="ok"),
        protocol_tunnel=ProtocolBlockProbeResult(result="protocol_block", detail="post_handshake_stall"),
    )
    report = classify_probes("vpn.example.com", probes, NetworkFingerprint(asn=12389, kind=NetworkKind.HOME))
    assert VerdictClass.PROTOCOL_BLOCK in report.verdicts
    assert any(r.action == "change_obfuscation" for r in report.recommended)

    decision = await select_best_strategy(
        network_key="AS12389:home:default",
        domain="vpn.example.com",
        ip="1.2.3.4",
        verdicts=report.verdicts,
    )
    assert decision.layer == "vpn"
    assert decision.strategy_id == "vpn-select"


async def test_subscription_refresh_and_amnezia_extended_core(tmp_path: Path) -> None:
    amnezia_cfg = {
        "hostName": "198.51.100.42",
        "description": "AwgNode",
        "containers": [
            {
                "container": "amnezia-awg",
                "awg": {
                    "port": 51820,
                    "client_priv_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                    "server_pub_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                    "Jc": 4,
                    "Jmin": 40,
                    "Jmax": 70,
                },
            }
        ],
    }
    raw_json = json.dumps(amnezia_cfg).encode("utf-8")
    qt_compressed = struct.pack("!I", len(raw_json)) + zlib.compress(raw_json)
    vpn_uri = "vpn://" + base64.urlsafe_b64encode(qt_compressed).decode("ascii").rstrip("=")

    db_path = tmp_path / "sub.db"
    st = Storage(db_path)
    try:
        nodes = parse_subscription_payload(vpn_uri, subscription_id="awg-sub")
        st.save_subscription("awg-sub", vpn_uri, [n.model_dump(mode="json") for n in nodes])
        refreshed = await refresh_all_subscriptions(st)
        assert refreshed == {"awg-sub": 1}
    finally:
        st.close()

    std_cfg = generate_singbox_config(decisions=[], vpn_nodes=nodes, extended_core=False)
    std_wg = next(o for o in std_cfg["outbounds"] if o["type"] == "wireguard")
    assert "jc" not in std_wg and "jmin" not in std_wg

    ext_cfg = generate_singbox_config(decisions=[], vpn_nodes=nodes, extended_core=True)
    ext_wg = next(o for o in ext_cfg["outbounds"] if o["type"] == "wireguard")
    assert ext_wg["jc"] == 4 and ext_wg["jmin"] == 40


async def test_dynamics_circular_downshift_and_canary_cycle(tmp_path: Path) -> None:
    log_sample = (
        "[winws2] circular host=discord.com switching to strategy=2\n"
        "[winws2] ordinary packet log\n"
        "[winws2] circular sni=youtube.com strategy:3\n"
    )
    rotations = parse_circular_rotations(log_sample)
    assert len(rotations) == 2
    assert rotations[0]["domain"] == "discord.com" and rotations[0]["strategy"] == 2
    assert rotations[1]["domain"] == "youtube.com" and rotations[1]["strategy"] == 3

    heavy_dec = Decision(
        network_key="AS12389:home:default",
        domain="discord.com",
        protocol=Protocol.TLS,
        layer="dpi",
        strategy_id="tls_fake_repeats6",
        fallback_strategies=["tls_fakedsplit_pos2"],
    )
    downshift = get_downshift_candidates(heavy_dec)
    assert downshift and all(s.tier < 3 for s in downshift)

    db_path = tmp_path / "dyn.db"
    st = Storage(db_path)
    try:
        net = NetworkFingerprint(asn=12389, kind=NetworkKind.HOME)
        net_key = st.upsert_network(net)
        d1 = Decision(
            network_key=net_key,
            domain="transient.example.com",
            protocol=Protocol.TLS,
            layer="dpi",
            strategy_id="tls_multisplit_pos2",
            fallback_strategies=["tls_fakedsplit_pos2"],
        )
        d2 = Decision(
            network_key=net_key,
            domain="broken.example.com",
            protocol=Protocol.TLS,
            layer="dpi",
            strategy_id="tls_multisplit_pos2",
            fallback_strategies=["tls_fakedsplit_pos2"],
        )
        st.save_decision(d1)
        st.save_decision(d2)

        attempts = {"transient.example.com": 0, "broken.example.com": 0}

        async def fake_probe(dom: str) -> bool:
            attempts[dom] += 1
            if dom == "transient.example.com":
                # Fails first check, passes immediate confirmation retry
                return attempts[dom] > 1
            return False

        summary = await run_canary_cycle(st, network=net, probe_fn=fake_probe)
        assert summary["promoted"] == ["broken.example.com"]
        decs = {d.domain: d for d in st.get_decisions(net_key)}
        assert decs["transient.example.com"].strategy_id == "tls_multisplit_pos2"
        assert decs["broken.example.com"].strategy_id == "tls_fakedsplit_pos2"
    finally:
        st.close()


def test_gui_controller_cli_daemon_and_licenses(tmp_path: Path) -> None:
    assert (REPO_ROOT / "LICENSES.md").is_file()

    db_path = tmp_path / "gui.db"
    ctrl = NetdoctorController(
        db_path=db_path,
        configs_dir=tmp_path / "configs",
        lists_dir=tmp_path / "lists",
        logs_dir=tmp_path / "logs",
    )
    snap = launch_gui(
        db_path=str(db_path),
        configs_dir=str(tmp_path / "configs"),
        lists_dir=str(tmp_path / "lists"),
        logs_dir=str(tmp_path / "logs"),
        headless_check=True,
    )
    assert snap["decisions_count"] == 0
    assert snap["running"] is False

    gen = ctrl.trigger_apply_configs()
    assert Path(gen["winws2_preset"]).is_file()
    assert Path(gen["singbox_config"]).is_file()

    reval = ctrl.trigger_revalidate()
    assert "network_key" in reval and "rotations" in reval

    res_gui = subprocess.run(
        [
            sys.executable,
            "-m",
            "netdoctor.cli",
            "gui",
            "--db",
            str(db_path),
            "--configs-dir",
            str(tmp_path / "configs"),
            "--lists-dir",
            str(tmp_path / "lists"),
            "--logs-dir",
            str(tmp_path / "logs"),
            "--headless-check",
        ],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=15.0,
    )
    assert res_gui.returncode == 0, res_gui.stderr
    gui_json = json.loads(res_gui.stdout)
    assert "network_key" in gui_json

    res_daemon = subprocess.run(
        [
            sys.executable,
            "-m",
            "netdoctor.cli",
            "daemon",
            "--db",
            str(db_path),
            "--iterations",
            "1",
        ],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=15.0,
    )
    assert res_daemon.returncode == 0, res_daemon.stderr
    assert "Canary cycle 1" in res_daemon.stdout
