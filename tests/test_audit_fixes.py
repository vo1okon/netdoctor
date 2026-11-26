"""Targeted regression tests verifying fixes across the ponytail audit checklist (Items 1-16 + blobs + strategies)."""

from __future__ import annotations

import asyncio
import hashlib
import json
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml

from netdoctor.clash_api import ClashApiClient
from netdoctor.config_gen import (
    build_singbox_rulesets_payload,
    extract_blob_args,
    generate_singbox_config,
    generate_winws2_config,
    needs_xray_bridge,
)
from netdoctor.core.engine import NetdoctorEngine
from netdoctor.core.ruleset_server import RuleSetServer
from netdoctor.models import Decision, NetworkFingerprint, NetworkKind, Protocol, VerdictClass, VpnNode
from netdoctor.orchestrators import VpnLayerOrchestrator
from netdoctor.probes import _build_quic_initial_packet
from netdoctor.selector import DEFAULT_STRATEGIES, ORTHOGONAL_CORE_TLS, CandidateEvaluation, select_best_strategy
from netdoctor.storage import Storage
from netdoctor.supervisor import ProcessSupervisor, _download_bytes
from netdoctor.tray import terminate_pid_gracefully
from netdoctor.vpn import parse_single_uri, parse_subscription_payload


def _make_engine(tmp_path: Path) -> NetdoctorEngine:
    eng = NetdoctorEngine(
        db_path=tmp_path / "test.db",
        configs_dir=tmp_path / "configs",
        lists_dir=tmp_path / "lists",
        logs_dir=tmp_path / "logs",
        bin_dir=tmp_path / "bin",
        bundles_path=Path("configs/bundles.yaml"),
        ruleset_port=0,
    )
    st = Storage(eng.db_path)
    try:
        st.upsert_network(NetworkFingerprint(asn=8402, kind=NetworkKind.HOME, isp="Beeline", gateway_mac="aa:bb:cc:dd:ee:ff"))
        st.save_subscription(
            "sub1",
            "https://example.com/sub",
            [
                VpnNode(
                    tag="FI-VLESS",
                    protocol="vless",
                    server="198.51.100.11",
                    server_port=443,
                    raw_outbound={"type": "vless", "tag": "FI-VLESS", "server": "198.51.100.11", "server_port": 443},
                ).model_dump(mode="json")
            ],
        )
    finally:
        st.close()
    return eng


def test_siege_bundle_never_in_rule0_and_vpn_order_and_sanitize(tmp_path: Path) -> None:
    eng = _make_engine(tmp_path)
    st = Storage(eng.db_path)
    try:
        nk = eng._resolve_network_info(st)[0]
        # Simulate polluted legacy vpn_processes + default direct_clean ubisoft bundle
        st.set_setting(f"vpn_processes:{nk}", "RainbowSix.exe, upc.exe, python.exe, sing-box, CustomApp.exe")
        st.set_bundle_mode(nk, "ubisoft", "direct_clean")
    finally:
        st.close()

    assert eng.get_vpn_processes() == ["RainbowSix.exe", "upc.exe", "CustomApp.exe"]

    eng.ruleset_server.start()
    try:
        # Toggle RainbowSix.exe ON -> synchronizes ubisoft bundle to vpn
        res = eng.toggle_vpn_process("RainbowSix.exe")
        if not res["enabled"]:
            # Was present, so first toggle removed it; toggle back ON to test add sync
            res = eng.toggle_vpn_process("RainbowSix.exe")
        assert res["enabled"] is True

        sb_cfg = json.loads((eng.configs_dir / "sing-box.json").read_text(encoding="utf-8"))
        rules = sb_cfg["route"]["rules"]
        rule0_procs = {p.lower() for p in (rules[0].get("process_name") or [])}
        assert "rainbowsix.exe" not in rule0_procs
        assert "upc.exe" not in rule0_procs
        assert "beservice.exe" not in rule0_procs

        rs_vpn_idx = next(i for i, r in enumerate(rules) if r.get("rule_set") == ["rs-bundles-vpn"])
        vpn_proc_idx = next(i for i, r in enumerate(rules) if r.get("outbound") == "vpn-select" and r.get("process_name"))
        rs_direct_idx = next(i for i, r in enumerate(rules) if r.get("rule_set") == ["rs-bundles-direct"])
        assert rs_vpn_idx < rs_direct_idx
        assert vpn_proc_idx < rs_direct_idx

        # Switching ubisoft bundle away from vpn strips its processes from vpn_processes AND hot-updates RuleSetServer
        eng.set_bundle_mode("ubisoft", "direct_dpi")
        assert "RainbowSix.exe" not in eng.get_vpn_processes()
        assert "CustomApp.exe" in eng.get_vpn_processes()
        body = json.loads(urllib.request.urlopen(eng.ruleset_server.url_for("rs-bundles-vpn"), timeout=3).read().decode("utf-8"))
        vpn_procs_served = [p.lower() for r in body["rules"] for p in (r.get("process_name") or ())]
        assert "rainbowsix.exe" not in vpn_procs_served
    finally:
        eng.ruleset_server.stop()


def test_winws2_base_exclude_dpi_auth_domains_and_base_preset_merge(tmp_path: Path) -> None:
    eng = _make_engine(tmp_path)
    st = Storage(eng.db_path)
    try:
        nk = eng._resolve_network_info(st)[0]
        st.save_decision(Decision(network_key=nk, domain="ubi.com", protocol=Protocol.TLS, layer="direct"))
        st.save_decision(
            Decision(network_key=nk, domain="public-ubiservices.ubi.com", protocol=Protocol.TLS, layer="dns", strategy_id="doh")
        )
        st.save_decision(
            Decision(
                network_key=nk,
                domain="blocked.example",
                protocol=Protocol.TLS,
                layer="dpi",
                strategy_id="tls_alt1_199_fake_fakedsplit",
            )
        )
        st.save_decision(Decision(network_key=nk, domain="vpn.example", protocol=Protocol.TLS, layer="vpn", strategy_id="vpn-select"))
        st.set_bundle_mode(nk, "ubisoft", "direct_dpi")
        st.set_setting("game_filter", "1")
        st.set_setting("active_zapret_preset_id", "auto")
        # Seed a base Zapret2 preset with game cloud UDP & Ubisoft hostlist
        (eng.lists_dir / "zapret2").mkdir(parents=True, exist_ok=True)
        (eng.lists_dir / "zapret2" / "ubisoft.txt").write_text("ubi.com\nubisoft.com\n", encoding="utf-8")
        (eng.lists_dir / "zapret2" / "ipset-amazon.txt").write_text("18.0.0.0/8\n", encoding="utf-8")
        (eng.bin_dir / "lua").mkdir(parents=True, exist_ok=True)
        for lua_name in ("zapret-lib.lua", "zapret-antidpi.lua", "zapret-auto.lua"):
            (eng.bin_dir / "lua" / lua_name).write_text("function pass(ctx) end\nfunction fake(ctx) end\n", encoding="utf-8")
        st.save_zapret_preset(
            {
                "id": "z2_test_base",
                "name": "Base Test (game filter)",
                "content": (
                    "--wf-tcp-out=80,443,1024-65535\n"
                    "--wf-udp-out=443,1024-65535\n"
                    "--filter-tcp=80,443-65535\n"
                    "--hostlist=lists/ubisoft.txt\n"
                    "--payload=tls_client_hello\n"
                    "--lua-desync=fake:tcp_ts=-600000:repeats=6\n"
                    "--new\n"
                    "--filter-udp=1024-65535\n"
                    "--ipset=lists/ipset-amazon.txt\n"
                    "--lua-desync=fake:blob=game_active:repeats=12\n"
                ),
                "source": "builtin_z2",
            }
        )
        st.set_setting("base_zapret_preset_id", "z2_test_base")
    finally:
        st.close()

    applied = eng.trigger_apply_configs()
    args = applied["winws2_args"]
    joined = "\n".join(args)

    base_excl = (eng.lists_dir / "exclude_base_preset_domains.txt").read_text(encoding="utf-8").splitlines()
    assert "blocked.example" in base_excl
    assert "vpn.example" in base_excl
    assert "ubi.com" not in base_excl
    assert "public-ubiservices.ubi.com" not in base_excl

    pass_txt = (eng.lists_dir / "pass_domains.txt").read_text(encoding="utf-8").splitlines()
    assert "ubisoft.com" not in pass_txt

    wf_tcp_line = next(a for a in args if a.startswith("--wf-tcp-out="))
    assert "1024-65535" in wf_tcp_line
    assert "game_active:repeats=4" not in joined
    assert "game_active:repeats=12" in joined


def test_blobs_and_tiered_selector_compromise(tmp_path: Path) -> None:
    yaml_raw = yaml.safe_load(Path("configs/strategies.yaml").read_text(encoding="utf-8"))["strategies"]
    yaml_clone = next(s for s in yaml_raw if s["id"] == "tls_clone_multisplit_sni")
    code_clone = next(s for s in DEFAULT_STRATEGIES if s.id == "tls_clone_multisplit_sni")
    assert any("blob=" in t for t in yaml_clone["args_template"])
    assert any("blob=" in t for t in code_clone.args_template)

    files_dir = tmp_path / "bin" / "files"
    files_dir.mkdir(parents=True)
    (files_dir / "tls_clienthello_www_google_com.bin").write_bytes(b"CH_TEST")
    blob_args = extract_blob_args(["--lua-desync=fake:blob=tls_google"], bin_dir=tmp_path / "bin")
    assert blob_args == ["--blob=tls_google:@files/tls_clienthello_www_google_com.bin"]

    evaluated: list[str] = []

    async def fake_eval(dom: str, ip: str, strat) -> CandidateEvaluation:
        evaluated.append(strat.id)
        ok = strat.id == ORTHOGONAL_CORE_TLS[0]
        return CandidateEvaluation(strat, success_rate=1.0 if ok else 0.0, throughput_kbps=5000.0 if ok else 0.0, ttfb_ms=30.0 if ok else 9999.0)

    dec = asyncio.run(
        select_best_strategy(
            "AS8402:home:test",
            "blocked.example",
            "203.0.113.10",
            [VerdictClass.SNI_DPI],
            evaluator=fake_eval,
        )
    )
    assert dec.strategy_id == ORTHOGONAL_CORE_TLS[0]
    assert len(evaluated) <= len(ORTHOGONAL_CORE_TLS)


def test_vpn_xhttp_smartdns_dns_vpn_subscription_and_bridge_unavailable(tmp_path: Path) -> None:
    node = parse_single_uri("vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443?type=xhttp&path=/xp#xh")
    assert node is not None and node.raw_outbound["transport"]["type"] == "xhttp"
    assert needs_xray_bridge(node) is True

    sub_nodes = parse_subscription_payload(
        "vmess://!!!not_base64!!!\n"
        "vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443?security=none#good"
    )
    assert len(sub_nodes) == 1 and sub_nodes[0].tag == "good"

    rs_payload = build_singbox_rulesets_payload(
        [Decision(network_key="AS1:home:d", domain="ai-one.example", protocol=Protocol.TLS, layer="dns", strategy_id="smartdns")]
    )
    assert "ai-one.example" in rs_payload["rs-smartdns"][0]["domain_suffix"]

    srv = RuleSetServer(preferred_port=0)
    base_url = srv.start()
    try:
        sb_path = tmp_path / "sing-box.json"
        sb_cfg = generate_singbox_config(
            decisions=[],
            vpn_nodes=[node],
            output_path=sb_path,
            base_dns=None,
            primary_is_smartdns=False,
            ruleset_base_url=base_url,
            clash_api_secret="test-secret-123",
            xray_bridge_ports={node.tag: 18100},
        )
        assert any(s["tag"] == "dns-vpn" and s.get("detour") == "vpn-select" for s in sb_cfg["dns"]["servers"])
        assert any(ib.get("tag") == "vpn-probe-in" and ib.get("listen_port") == 2081 for ib in sb_cfg["inbounds"])
        assert {"inbound": ["vpn-probe-in"], "outbound": "vpn-select"} in sb_cfg["route"]["rules"]
        sb_exe = Path("bin/sing-box.exe")
        if sb_exe.is_file():
            proc = subprocess.run([str(sb_exe), "check", "-c", str(sb_path)], capture_output=True, text=True, timeout=15)
            assert proc.returncode == 0, f"sing-box check failed: {proc.stderr}\n{proc.stdout}"
    finally:
        srv.stop()

    vpn_orch = VpnLayerOrchestrator()
    fake_clash = MagicMock(spec=ClashApiClient)

    async def _fake_proxies():
        return {"NL-Bridge": {"type": "Socks", "now": ""}}

    async def _fake_delay(_client, _tag: str, timeout: float):
        return False, None, 'Get "https://www.gstatic.com/generate_204": dial tcp 127.0.0.1:18100: connectex: connection refused'

    fake_clash.get_proxies = _fake_proxies
    vpn_orch._measure_clash_node_delay = _fake_delay  # type: ignore[method-assign]
    probed = asyncio.run(
        vpn_orch.probe_vpn_nodes(
            [{"tag": "NL-Bridge", "protocol": "vless", "server": "198.51.100.22", "server_port": 443}],
            clash_client=fake_clash,
        )
    )
    assert probed[0]["probe_result"] == "bridge_unavailable"
    assert probed[0]["protocol_ok"] is True


def test_security_localhost_auth_download_guards_and_ui_fixes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    eng = _make_engine(tmp_path)
    assert len(eng.clash_api.secret) >= 20
    applied = eng.trigger_apply_configs()
    sb_cfg = json.loads(Path(applied["singbox_config"]).read_text(encoding="utf-8"))
    assert sb_cfg["experimental"]["clash_api"]["secret"] == eng.clash_api.secret

    srv = RuleSetServer(preferred_port=0)
    srv.start()
    try:
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(f"http://127.0.0.1:{srv.port}/rs-vpn.json", timeout=2)
        assert exc.value.code == 403
        with urllib.request.urlopen(srv.url_for("rs-vpn"), timeout=2) as ok_resp:
            assert ok_resp.status == 200
    finally:
        srv.stop()

    with pytest.raises(ValueError, match="SHA-256"):
        asyncio.run(
            _download_bytes(
                "https://example.com/a.bin",
                timeout=2.0,
                client=_FakeBytesClient(b"hello"),
                expected_sha256="0" * 64,
            )
        )
    with pytest.raises(ValueError, match="exceeds"):
        asyncio.run(
            _download_bytes(
                "https://example.com/big.bin",
                timeout=2.0,
                client=_FakeBytesClient(b"0123456789"),
                max_bytes=5,
            )
        )

    sup = ProcessSupervisor(bin_dir=tmp_path / "bin", logs_dir=tmp_path / "logs")
    fake_proc = MagicMock()
    fake_proc.poll.return_value = None
    fake_proc.pid = 424242
    sup.processes["tg-ws-proxy"] = fake_proc
    sup._cmds["tg-ws-proxy"] = [sys.executable, "tg_ws_proxy.py", "--secret", "supersecretvalue123"]
    sup._save_state()
    saved_txt = sup.state_path.read_text(encoding="utf-8")
    assert "supersecretvalue123" not in saved_txt
    assert "***" in saved_txt

    unrelated = MagicMock()
    unrelated.name.return_value = "notepad.exe"
    monkeypatch.setattr("netdoctor.tray.psutil.Process", lambda _pid: unrelated)
    assert terminate_pid_gracefully(99999) is False

    pkt = _build_quic_initial_packet("example.com")
    assert len(pkt) >= 1200
    assert (pkt[0] & 0xC0) == 0xC0
    assert pkt[1:5] == b"\x00\x00\x00\x01"
    assert hashlib.sha256(b"hello").hexdigest()  # sanity import check


class _FakeBytesResp:
    def __init__(self, data: bytes) -> None:
        self.content = data

    def raise_for_status(self) -> None:
        return None


class _FakeBytesClient:
    def __init__(self, data: bytes) -> None:
        self._data = data

    async def get(self, _url: str) -> _FakeBytesResp:
        return _FakeBytesResp(self._data)


def test_xray_heal_closed_db_and_start_after_stop_fixes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import netdoctor.core.engine as engine_mod

    eng = _make_engine(tmp_path)
    xhttp_node = parse_single_uri("vless://11111111-1111-1111-1111-111111111111@198.51.100.12:443?type=xhttp&path=/xp#xh")
    assert xhttp_node is not None
    st = Storage(eng.db_path)
    try:
        st.save_subscription("sub-xh", "https://example.com/xh", [xhttp_node.model_dump(mode="json")])
    finally:
        st.close()

    (eng.bin_dir).mkdir(parents=True, exist_ok=True)
    (eng.bin_dir / "xray.exe").write_bytes(b"MZ")
    monkeypatch.setattr(engine_mod, "validate_xray_config", lambda *_a, **_kw: (True, ""))
    monkeypatch.setattr(engine_mod, "_is_admin", lambda: False)

    # Previously raised sqlite3.ProgrammingError: Cannot operate on a closed database
    applied = eng.trigger_apply_configs()
    assert applied.get("xray_bridge_count", 0) >= 1

    # Calling start_autopilot right after stop_services must never stick on "stopping"
    eng.stop_services()
    assert eng._shutting_down is False
    res = eng.start_autopilot()
    assert res.get("error") != "stopping"


def test_smartdns_fallback_rules_and_tun_interface_rotation(tmp_path: Path) -> None:
    from netdoctor.orchestrators import AI_GEOBLOCK_DOMAINS, DnsLayerOrchestrator

    cat_map = {s["id"]: s for s in DnsLayerOrchestrator().get_all_dns_servers()}
    srv = RuleSetServer(preferred_port=0)
    base_url = srv.start()
    try:
        sb_path = tmp_path / "sing-box.json"
        decs = [
            Decision(network_key="AS1:home:d", domain="chatgpt.com", protocol=Protocol.TLS, layer="dns", strategy_id="smartdns"),
            Decision(network_key="AS1:home:d", domain="discord.com", protocol=Protocol.TLS, layer="vpn", strategy_id="vpn-select"),
        ]
        sb_cfg = generate_singbox_config(
            decisions=decs,
            vpn_nodes=[
                VpnNode(
                    tag="FI-1",
                    protocol="vless",
                    server="198.51.100.11",
                    server_port=443,
                    raw_outbound={"type": "vless", "tag": "FI-1", "server": "198.51.100.11", "server_port": 443},
                )
            ],
            output_path=sb_path,
            doh_server="1.1.1.1",
            dns_catalog=cat_map,
            base_dns=cat_map["cf_security"],
            primary_is_smartdns=False,
            smartdns_domains=list(AI_GEOBLOCK_DOMAINS),
            ruleset_base_url=base_url,
            tun_interface_name="netdoctor-tun2",
        )
        assert any(s["tag"] == "dns-smartdns" for s in sb_cfg["dns"]["servers"])
        assert {"rule_set": ["rs-smartdns"], "server": "dns-smartdns"} in sb_cfg["dns"]["rules"]
        assert any(r.get("rule_set") == ["rs-vpn"] for r in sb_cfg["dns"]["rules"])
        tun_ib = next(ib for ib in sb_cfg["inbounds"] if ib.get("tag") == "tun-in")
        assert tun_ib["interface_name"] == "netdoctor-tun2"
        sb_exe = Path("bin/sing-box.exe")
        if sb_exe.is_file():
            proc = subprocess.run([str(sb_exe), "check", "-c", str(sb_path)], capture_output=True, text=True, timeout=15)
            assert proc.returncode == 0, f"sing-box check failed: {proc.stderr}\n{proc.stdout}"
    finally:
        srv.stop()


def test_calibration_clean_ubisoft_mojang_pass_guard_and_cryptography_dep(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import netdoctor.core.calibration as cal_mod
    from netdoctor.config_gen import generate_winws2_config
    from netdoctor.core.bundles import load_bundles
    from netdoctor.models import DnsProbeResult, ProbesSummary, QuicProbeResult, StallProbeResult, TcpProbeResult, TlsProbeResult

    st = Storage(tmp_path / "cal.db")
    try:
        async def _fake_net(timeout: float = 2.5) -> NetworkFingerprint:
            return NetworkFingerprint(asn=1, kind=NetworkKind.HOME, isp="CleanGameISP")

        async def _fake_beacon(dom: str, timeout: float = 2.5) -> ProbesSummary:
            # Only discord.com has SNI DPI; cloudflare.com is clean -> ubisoft must stay direct_clean
            tls_res = "reset" if dom == "discord.com" else "ok"
            return ProbesSummary(
                dns=DnsProbeResult(system="ok", doh="ok", doh_ips=["162.159.135.232"]),
                tcp=TcpProbeResult(result="ok", rtt_ms=12.0, target_ip="162.159.135.232"),
                tls=TlsProbeResult(real_sni=tls_res, neutral_sni="ok", ttfb_ms=15.0),
                stall=StallProbeResult(result="ok", bytes_read=4096, throughput_kbps=5000.0),
                quic=QuicProbeResult(result="ok", rtt_ms=10.0),
            )

        monkeypatch.setattr(cal_mod, "detect_network_fingerprint", _fake_net)
        res = asyncio.run(
            cal_mod.calibrate_network(
                st,
                probe_fn=_fake_beacon,
                base_dns_probe_fn=lambda s: asyncio.sleep(0, result={"ok": True, "latency_ms": 10.0, "ip": s["ip"]}),
            )
        )
        modes = st.get_bundle_modes(res["network_key"])
        assert modes["ubisoft"]["mode"] == "direct_clean"
        assert modes["discord"]["mode"] == "direct_dpi"
    finally:
        st.close()

    # Subdomain DPI decision prevents parent domain from entering pass_domains.txt
    lists_dir = tmp_path / "lists"
    generate_winws2_config(
        decisions=[
            Decision(
                network_key="AS1:home:d",
                domain="sessionserver.mojang.com",
                protocol=Protocol.TLS,
                layer="dpi",
                strategy_id="tls_hostfakesplit_ozon",
            )
        ],
        strategies={s.id: s for s in DEFAULT_STRATEGIES},
        lists_dir=lists_dir,
        bundle_pass_domains=["mojang.com", "minecraft.net"],
    )
    pass_lines = (lists_dir / "pass_domains.txt").read_text(encoding="utf-8").splitlines()
    assert "mojang.com" not in pass_lines
    assert "minecraft.net" in pass_lines

    mc_bundle = next(b for b in load_bundles(Path("configs/bundles.yaml")) if b.id == "minecraft")
    assert mc_bundle.coupling == "storefront"
    pyproject_text = Path("pyproject.toml").read_text(encoding="utf-8")
    assert "cryptography" in pyproject_text


def test_nonweb_tcp_16kb_stall_detection_and_vpn_escalation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import netdoctor.orchestrators as orch_mod
    from datetime import datetime, timezone
    from netdoctor.orchestrators import RealtimeConnectionMonitor

    eng = _make_engine(tmp_path)
    st = Storage(eng.db_path)
    try:
        nk = eng._resolve_network_info(st)[0]
        st.set_bundle_mode(nk, "minecraft", "direct_clean")
    finally:
        st.close()

    old_start = datetime(2020, 1, 1, tzinfo=timezone.utc).isoformat()
    mock_clash = MagicMock()
    mock_clash.get_connections_sync.return_value = {
        "connections": [
            {
                "id": "mc1",
                "metadata": {
                    "destinationIP": "172.65.197.160",
                    "destinationPort": 25565,
                    "network": "tcp",
                    "process": "javaw.exe",
                },
                "download": 19804,
                "upload": 1770,
                "start": old_start,
                "chains": ["direct"],
            },
            {
                "id": "mc2",
                "metadata": {
                    "destinationIP": "172.65.200.155",
                    "destinationPort": 25565,
                    "network": "tcp",
                    "process": "javaw.exe",
                },
                "download": 19804,
                "upload": 1200,
                "start": old_start,
                "chains": ["direct"],
            },
        ]
    }
    monkeypatch.setattr(eng, "_collect_processes_state", lambda: {"winws2": {"running": True}, "sing-box": {"running": True}})
    monkeypatch.setattr(eng.clash_api, "get_connections_sync", mock_clash.get_connections_sync)
    monkeypatch.setattr("psutil.net_connections", lambda kind="inet": [])
    monkeypatch.setattr(orch_mod, "detect_bypass_active", lambda: True)
    monkeypatch.setattr(orch_mod, "_is_admin", lambda: False)

    res_heal = asyncio.run(eng.orchestrator.monitor.auto_heal_connections(eng, max_domains_per_tick=0))
    conns = res_heal["connections"]
    assert conns and all(c["socket_status"] == "16KB_STALL" and c["health"] == "needs_fix" for c in conns)
    mc_alert = next(a for a in eng.orchestrator.monitor.pending_bundle_alerts if a.get("bundle_id") == "minecraft")
    assert mc_alert["stalled_16kb"] is True

    seen_modes: list[str] = []

    def _probe_all_ok(_dom: str, *, proxy_url: str | None = None, timeout: float = 3.0) -> dict[str, object]:
        cur = next(b["mode"] for b in eng.get_bundles_status()["bundles"] if b["id"] == "minecraft")
        seen_modes.append(cur)
        return {"ok": True, "latency_ms": 20.0}

    # With allow_downshift=False and a recorded 16KB TCP stall, minecraft skips direct_dpi and escalates to vpn
    # even when udp_check_fn reports False (minecraft is storefront/TCP-viable).
    esc = eng.find_best_bypass_for_bundle(
        "minecraft",
        probe_fn=_probe_all_ok,
        udp_check_fn=lambda: {"ok": False, "reason": "tcp_only_node"},
        allow_downshift=False,
    )
    assert esc["ok"] is True
    assert esc["mode"] == "vpn"
    assert "direct_dpi" not in seen_modes


def test_multisize_ico_and_win32_loadimage(tmp_path: Path) -> None:
    import struct
    from netdoctor.tray import write_app_icon

    ico_path = tmp_path / "app.ico"
    write_app_icon(ico_path)
    raw = ico_path.read_bytes()
    reserved, img_type, count = struct.unpack_from("<HHH", raw, 0)
    assert (reserved, img_type, count) == (0, 1, 3)
    sizes = [raw[6 + i * 16] for i in range(count)]
    assert sizes == [16, 32, 48]

    if sys.platform == "win32":
        import ctypes

        u32 = ctypes.windll.user32
        u32.LoadImageW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint, ctypes.c_int, ctypes.c_int, ctypes.c_uint]
        u32.LoadImageW.restype = ctypes.c_void_p
        u32.DestroyIcon.argtypes = [ctypes.c_void_p]
        for sz in (16, 32, 48):
            h = u32.LoadImageW(None, str(ico_path.resolve()), 1, sz, sz, 0x0010)
            assert h
            u32.DestroyIcon(h)


def test_cloud_game_udp_dpi_payload_all_and_match_udp_stall_escalation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import netdoctor.orchestrators as orch_mod
    from datetime import datetime, timezone

    # 1. generate_winws2_config includes --payload=all & :payload=all + fake_zero64 for Cloud Game UDP DPI
    lists_dir = tmp_path / "standalone_lists"
    (lists_dir / "zapret2").mkdir(parents=True, exist_ok=True)
    (lists_dir / "zapret2" / "ipset-amazon.txt").write_text("54.115.0.0/16\n", encoding="utf-8")
    (lists_dir / "zapret2" / "ipset-ovh.txt").write_text("51.89.0.0/16\n", encoding="utf-8")
    args, _ = generate_winws2_config(
        decisions=[],
        strategies={s.id: s for s in DEFAULT_STRATEGIES},
        lists_dir=lists_dir,
        enable_game_udp_dpi=True,
    )
    joined = "\n".join(args)
    assert "--filter-udp=1024-65535" in args
    assert "ipset-amazon.txt" in joined
    assert "ipset-ovh.txt" in joined
    assert "--payload=all" in args
    assert "--lua-desync=fake:blob=game_active:repeats=4:payload=all" in args
    assert "--lua-desync=fake:blob=fake_zero64:repeats=6:payload=all" in args
    assert any(tok.startswith("--blob=fake_zero64:") for tok in args)

    # 2. trigger_apply_configs auto-enables Cloud Game UDP DPI on TSPU ISP even when game_filter=0 & bundles=direct_clean
    eng = _make_engine(tmp_path)
    (eng.lists_dir / "zapret2").mkdir(parents=True, exist_ok=True)
    (eng.lists_dir / "zapret2" / "ipset-amazon.txt").write_text("54.115.0.0/16\n", encoding="utf-8")
    (eng.lists_dir / "zapret2" / "ipset-ovh.txt").write_text("51.89.0.0/16\n", encoding="utf-8")
    st = Storage(eng.db_path)
    try:
        nk = eng._resolve_network_info(st)[0]
        st.set_setting("game_filter", "0")
        st.set_bundle_mode(nk, "ubisoft", "direct_clean")
        st.save_decision(
            Decision(
                network_key=nk,
                domain="discord.com",
                protocol=Protocol.TLS,
                layer="dpi",
                strategy_id="tls_alt1_199_fake_fakedsplit",
            )
        )
    finally:
        st.close()

    applied = eng.trigger_apply_configs()
    app_joined = "\n".join(applied["winws2_args"])
    assert "--filter-udp=1024-65535" in applied["winws2_args"]
    assert "ipset-amazon.txt" in app_joined
    assert "--lua-desync=fake:blob=game_active:repeats=4:payload=all" in app_joined
    assert eng._last_game_udp_dpi is True
    pass_lines = (eng.lists_dir / "pass_domains.txt").read_text(encoding="utf-8").splitlines()
    assert "ubisoft.com" in pass_lines

    # 3. Healthy lobby/QoS UDP flow must NOT mask active blackholed match-server UDP flow in Clash
    old_start = datetime(2020, 1, 1, tzinfo=timezone.utc).isoformat()
    mock_clash = MagicMock()
    mock_clash.get_connections_sync.return_value = {
        "connections": [
            {
                "id": "lobby-healthy-udp",
                "metadata": {
                    "destinationIP": "20.174.51.75",
                    "destinationPort": 3075,
                    "network": "udp",
                    "process": "RainbowSix.exe",
                },
                "download": 500,
                "upload": 500,
                "start": old_start,
                "chains": ["direct"],
            },
            {
                "id": "match-blackhole-udp",
                "metadata": {
                    "destinationIP": "54.115.104.208",
                    "destinationPort": 30000,
                    "network": "udp",
                    "process": "RainbowSix.exe",
                },
                "download": 0,
                "upload": 1200,
                "start": old_start,
                "chains": ["direct"],
            },
        ]
    }
    monkeypatch.setattr(eng, "_collect_processes_state", lambda: {"winws2": {"running": True}, "sing-box": {"running": True}})
    monkeypatch.setattr(eng.clash_api, "get_connections_sync", mock_clash.get_connections_sync)
    monkeypatch.setattr("psutil.net_connections", lambda kind="inet": [])
    monkeypatch.setattr(orch_mod, "detect_bypass_active", lambda: True)
    monkeypatch.setattr(orch_mod, "_is_admin", lambda: False)

    asyncio.run(eng.orchestrator.monitor.auto_heal_connections(eng, max_domains_per_tick=0))
    asyncio.run(eng.orchestrator.monitor.auto_heal_connections(eng, max_domains_per_tick=0))
    r6_alert = next(a for a in eng.orchestrator.monitor.pending_bundle_alerts if a.get("bundle_id") == "ubisoft")
    assert r6_alert["stalled_udp"] is True

    # 4. With Cloud UDP DPI already active + stalled_udp, bundle escalation skips direct_dpi -> vpn
    seen_modes: list[str] = []

    def _probe_all_ok(_dom: str, *, proxy_url: str | None = None, timeout: float = 3.0) -> dict[str, object]:
        cur = next(b["mode"] for b in eng.get_bundles_status()["bundles"] if b["id"] == "ubisoft")
        seen_modes.append(cur)
        return {"ok": True, "latency_ms": 20.0}

    esc = eng.find_best_bypass_for_bundle(
        "ubisoft",
        probe_fn=_probe_all_ok,
        udp_check_fn=lambda: {"ok": True, "reason": ""},
        allow_downshift=False,
    )
    assert esc["ok"] is True
    assert esc["mode"] == "vpn"
    assert "direct_dpi" not in seen_modes

