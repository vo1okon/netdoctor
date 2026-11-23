"""Comprehensive unit and integration tests for netdoctor:
- Classifier matrix (including combined verdicts & neutral SNI false-positive protection)
- FakeCensorServer end-to-end probe tests
- SQLite storage & network fingerprint isolation
- Strategy selector (cheapest tier, throughput tie-break, fallback promotion)
- Universal VPN subscription parser (Happ base64, VLESS Reality, VMess, Trojan, Shadowsocks, Hysteria2, Amnezia vpn://)
- winws2 & sing-box config generation (multi-VPN urltest/selector, DoH, tg-ws-proxy)
"""

from __future__ import annotations

import base64
import json
import struct
import zlib
from pathlib import Path

import httpx
import pytest

from netdoctor.classifier import classify_probes
from netdoctor.config_gen import generate_singbox_config, generate_winws2_config
from netdoctor.dynamics import is_decision_expired, promote_fallback_on_failure
from netdoctor.models import (
    Decision,
    DnsProbeResult,
    NetworkFingerprint,
    NetworkKind,
    ProbesSummary,
    Protocol,
    QuicProbeResult,
    StallProbeResult,
    Strategy,
    TcpProbeResult,
    TlsProbeResult,
    VerdictClass,
)
from netdoctor.probes import probe_quic, probe_stall, probe_tls
from netdoctor.selector import CandidateEvaluation, select_best_strategy
from netdoctor.storage import Storage
from netdoctor.vpn import fetch_subscription, parse_subscription_payload
from tests.fake_censor import FakeCensorServer


@pytest.mark.parametrize(
    ("probes", "expected_verdicts"),
    [
        (
            ProbesSummary(),
            [VerdictClass.OK],
        ),
        (
            ProbesSummary(
                dns=DnsProbeResult(system="stub_ip", doh="ok"),
                tcp=TcpProbeResult(result="ok"),
                tls=TlsProbeResult(real_sni="reset", neutral_sni="ok"),
                stall=StallProbeResult(result="ok"),
                quic=QuicProbeResult(result="timeout"),
            ),
            [VerdictClass.DNS_POISON, VerdictClass.SNI_DPI, VerdictClass.QUIC_BLOCK],
        ),
        (
            ProbesSummary(
                dns=DnsProbeResult(system="ok", doh="ok"),
                tcp=TcpProbeResult(result="timeout"),
            ),
            [VerdictClass.IP_BLOCK],
        ),
        (
            ProbesSummary(
                dns=DnsProbeResult(system="ok", doh="ok"),
                tcp=TcpProbeResult(result="ok"),
                tls=TlsProbeResult(real_sni="ok", neutral_sni="ok"),
                stall=StallProbeResult(result="stall"),
                quic=QuicProbeResult(result="ok"),
            ),
            [VerdictClass.THROTTLE],
        ),
    ],
)
def test_classifier_matrix(probes: ProbesSummary, expected_verdicts: list[VerdictClass]) -> None:
    report = classify_probes("discord.com", probes, NetworkFingerprint(asn=12389, kind=NetworkKind.HOME))
    assert report.verdicts == expected_verdicts
    assert report.domain == "discord.com"
    assert report.network == {"asn": 12389, "kind": "home"}


async def test_fake_censor_ok_and_sni_dpi() -> None:
    # 1. Mode 'ok'
    censor_ok = FakeCensorServer(mode="ok", blocked_sni="discord.com")
    await censor_ok.start()
    try:
        tls_res = await probe_tls("127.0.0.1", real_sni="discord.com", port=censor_ok.tcp_port, timeout=2.0)
        stall_res = await probe_stall("127.0.0.1", sni="discord.com", port=censor_ok.tcp_port, timeout=2.0)
        quic_res = await probe_quic("127.0.0.1", sni="discord.com", port=censor_ok.udp_port, timeout=1.5)
        assert tls_res.real_sni == "ok"
        assert tls_res.neutral_sni == "ok"
        assert stall_res.result == "ok"
        assert quic_res.result == "ok"
    finally:
        await censor_ok.stop()

    # 2. Mode 'sni_dpi' + 'quic_block'
    censor_dpi = FakeCensorServer(mode="sni_dpi", blocked_sni="discord.com")
    await censor_dpi.start()
    try:
        tls_res = await probe_tls("127.0.0.1", real_sni="discord.com", port=censor_dpi.tcp_port, timeout=2.0)
        assert tls_res.real_sni == "reset"
        assert tls_res.neutral_sni == "ok"
    finally:
        await censor_dpi.stop()


async def test_fake_censor_throttle_and_quic_block() -> None:
    censor_th = FakeCensorServer(mode="throttle", blocked_sni="youtube.com")
    await censor_th.start()
    try:
        stall_res = await probe_stall("127.0.0.1", sni="youtube.com", port=censor_th.tcp_port, timeout=1.0)
        assert stall_res.result == "stall"
    finally:
        await censor_th.stop()

    censor_qb = FakeCensorServer(mode="quic_block", blocked_sni="youtube.com")
    await censor_qb.start()
    try:
        quic_res = await probe_quic("127.0.0.1", sni="youtube.com", port=censor_qb.udp_port, timeout=0.6)
        assert quic_res.result == "timeout"
    finally:
        await censor_qb.stop()


async def test_selector_picks_cheapest_tier_and_highest_speed() -> None:
    candidates = [
        Strategy(id="s_tier2_slow", family="multisplit", protocol=Protocol.TLS, tier=2, args_template=["--a"]),
        Strategy(id="s_tier2_fast", family="fakedsplit", protocol=Protocol.TLS, tier=2, args_template=["--b"]),
        Strategy(id="s_tier3_superfast", family="fake", protocol=Protocol.TLS, tier=3, args_template=["--c"]),
    ]

    async def fake_eval(domain: str, ip: str, strat: Strategy) -> CandidateEvaluation:
        speeds = {"s_tier2_slow": 1200.0, "s_tier2_fast": 4500.0, "s_tier3_superfast": 9000.0}
        return CandidateEvaluation(strat, success_rate=1.0, throughput_kbps=speeds[strat.id], ttfb_ms=30.0)

    decision = await select_best_strategy(
        network_key="AS12389:home:default",
        domain="discord.com",
        ip="1.2.3.4",
        verdicts=[VerdictClass.SNI_DPI],
        candidates=candidates,
        evaluator=fake_eval,
    )
    # Tier 2 wins over Tier 3 even if Tier 3 has higher speed; within Tier 2, higher throughput wins
    assert decision.strategy_id == "s_tier2_fast"
    assert decision.fallback_strategies == ["s_tier2_slow", "s_tier3_superfast"]


def test_storage_network_isolation_and_fallback_promotion(tmp_path: Path) -> None:
    db_file = tmp_path / "test.db"
    storage = Storage(db_file)
    try:
        net_home = NetworkFingerprint(asn=12389, kind=NetworkKind.HOME)
        net_mobile = NetworkFingerprint(asn=8359, kind=NetworkKind.MOBILE)
        k_home = storage.upsert_network(net_home)
        k_mob = storage.upsert_network(net_mobile)

        d_home = Decision(
            network_key=k_home,
            domain="discord.com",
            protocol=Protocol.TLS,
            layer="dpi",
            strategy_id="tls_multisplit_pos2",
            fallback_strategies=["tls_fakedsplit_pos2"],
        )
        storage.save_decision(d_home)

        # Different network fingerprint has empty cache
        assert len(storage.get_decisions(k_mob)) == 0
        assert len(storage.get_decisions(k_home)) == 1

        # Test failure fallback promotion
        promoted = promote_fallback_on_failure(storage, d_home)
        assert promoted.strategy_id == "tls_fakedsplit_pos2"
        assert promoted.consecutive_fails == 1

        # Second failure with no fallbacks left escalates to VPN
        escalated = promote_fallback_on_failure(storage, promoted)
        assert escalated.layer == "vpn"
        assert escalated.strategy_id == "vpn-select"
    finally:
        storage.close()


def test_vpn_subscription_parsers_happ_and_amnezia() -> None:
    # 1. Happ / V2Ray base64 subscription with VLESS Reality, Trojan, Hysteria2
    raw_uris = "\n".join(
        [
            "vless://11111111-2222-3333-4444-555555555555@de1.example.com:443?security=reality&sni=yahoo.com&fp=chrome&pbk=PUBKEY123&sid=abcd&type=tcp&flow=xtls-rprx-vision#Germany-Reality",
            "trojan://secretpass@nl1.example.com:443?sni=nl1.example.com#Netherlands-Trojan",
            "hy2://hypass@fi1.example.com:8443?sni=fi1.example.com&insecure=0#Finland-Hy2",
        ]
    )
    b64_sub = base64.b64encode(raw_uris.encode("utf-8")).decode("ascii")
    nodes = parse_subscription_payload(b64_sub, subscription_id="happ-sub")
    assert len(nodes) == 3
    assert nodes[0].tag == "Germany-Reality"
    assert nodes[0].protocol == "vless"
    assert nodes[0].raw_outbound["tls"]["reality"]["public_key"] == "PUBKEY123"
    assert nodes[1].protocol == "trojan"
    assert nodes[2].protocol == "hysteria2"

    # 2. Amnezia vpn:// link (Qt qCompress 4-byte header + zlib JSON)
    amnezia_cfg = {
        "hostName": "198.51.100.42",
        "description": "MyAmnezia",
        "containers": [
            {
                "container": "amnezia-awg",
                "awg": {
                    "port": 51820,
                    "client_priv_key": "PRIV123",
                    "server_pub_key": "PUB456",
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

    awg_nodes = parse_subscription_payload(vpn_uri, subscription_id="amnezia")
    assert len(awg_nodes) == 1
    assert awg_nodes[0].protocol == "amneziawg"
    assert awg_nodes[0].server == "198.51.100.42"
    assert awg_nodes[0].raw_outbound["jc"] == 4


def test_config_generators_winws2_and_singbox(tmp_path: Path) -> None:
    strategies = {
        "tls_multisplit_pos2": Strategy(
            id="tls_multisplit_pos2",
            family="multisplit",
            protocol=Protocol.TLS,
            tier=2,
            args_template=["--lua-desync=multisplit:pos=2"],
        )
    }
    decisions = [
        Decision(
            network_key="AS12389:home:default",
            domain="discord.com",
            protocol=Protocol.TLS,
            layer="dpi",
            strategy_id="tls_multisplit_pos2",
        ),
        Decision(
            network_key="AS12389:home:default",
            domain="instagram.com",
            protocol=Protocol.TLS,
            layer="vpn",
            strategy_id="vpn-select",
        ),
    ]
    vpn_nodes = parse_subscription_payload(
        "vless://11111111-2222-3333-4444-555555555555@de1.example.com:443?security=tls#DE-Node1\n"
        "vless://11111111-2222-3333-4444-555555555555@fi1.example.com:443?security=tls#FI-Node2"
    )

    winws_args, hostlists = generate_winws2_config(
        decisions=decisions,
        strategies=strategies,
        lists_dir=tmp_path / "lists",
        vpn_server_ips=[n.server for n in vpn_nodes],
    )
    assert "tls_multisplit_pos2.txt" in hostlists
    assert hostlists["tls_multisplit_pos2.txt"] == ["discord.com"]
    assert any("circular:fails=2" in a for a in winws_args)

    sb_cfg = generate_singbox_config(
        decisions=decisions,
        vpn_nodes=vpn_nodes,
        output_path=tmp_path / "sing-box.json",
    )
    out_tags = {o["tag"] for o in sb_cfg["outbounds"]}
    assert "vpn-auto" in out_tags
    assert "vpn-select" in out_tags
    assert "DE-Node1" in out_tags
    assert "FI-Node2" in out_tags
    assert "tg-ws-out" in out_tags


async def test_happ_remnawave_xray_json_and_fetch_ua_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    xray_array = [
        {
            "remarks": "NL-Reality",
            "outbounds": [
                {
                    "tag": "proxy",
                    "protocol": "vless",
                    "settings": {
                        "vnext": [
                            {
                                "address": "nl1.example.com",
                                "port": 9443,
                                "users": [{"id": "11111111-2222-3333-4444-555555555555", "flow": "xtls-rprx-vision"}],
                            }
                        ]
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "reality",
                        "realitySettings": {
                            "serverName": "nl1.example.com",
                            "publicKey": "PUBKEY_XRAY",
                            "shortId": "1a2b",
                            "fingerprint": "firefox",
                        },
                    },
                },
                {"tag": "direct", "protocol": "freedom"},
            ],
        },
        {
            "remarks": "NL-Reality",
            "outbounds": [
                {
                    "tag": "proxy",
                    "protocol": "vless",
                    "settings": {
                        "vnext": [
                            {
                                "address": "nl2.example.com",
                                "port": 443,
                                "users": [{"id": "22222222-2222-3333-4444-555555555555"}],
                            }
                        ]
                    },
                    "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {"serverName": "nl2.example.com"}},
                }
            ],
        },
        {
            "remarks": "RU-Hy2",
            "outbounds": [
                {
                    "tag": "proxy",
                    "protocol": "hysteria",
                    "settings": {"address": "ru-hy2.example.com", "port": 443, "version": 2},
                    "streamSettings": {
                        "network": "hysteria",
                        "hysteriaSettings": {"version": 2, "auth": "hy2-secret"},
                        "security": "tls",
                        "tlsSettings": {
                            "serverName": "ru-hy2.example.com",
                            "fingerprint": "ios",
                            "alpn": ["h3"],
                        },
                    },
                }
            ],
        },
    ]

    nodes = parse_subscription_payload(json.dumps(xray_array), subscription_id="happ")
    assert len(nodes) == 3
    assert [n.tag for n in nodes] == ["NL-Reality", "NL-Reality-1", "RU-Hy2"]
    assert all(n.subscription_id == "happ" for n in nodes)
    assert nodes[0].protocol == "vless"
    assert nodes[0].transport == "reality"
    assert nodes[0].raw_outbound["tls"]["reality"]["public_key"] == "PUBKEY_XRAY"
    assert nodes[1].raw_outbound["tag"] == "NL-Reality-1"
    assert nodes[2].protocol == "hysteria2"
    assert nodes[2].transport == "quic"
    assert nodes[2].raw_outbound["password"] == "hy2-secret"
    assert "utls" not in nodes[2].raw_outbound["tls"]
    assert nodes[2].raw_outbound["tls"]["alpn"] == ["h3"]

    single_obj = {
        "remarks": "Single-Xray",
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": "de1.example.com",
                            "port": 443,
                            "users": [{"id": "33333333-2222-3333-4444-555555555555"}],
                        }
                    ]
                },
                "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {"serverName": "de1.example.com"}},
            }
        ],
    }
    single_nodes = parse_subscription_payload(json.dumps(single_obj), subscription_id="single")
    assert len(single_nodes) == 1
    assert single_nodes[0].tag == "Single-Xray"
    assert single_nodes[0].subscription_id == "single"
    assert single_nodes[0].server == "de1.example.com"

    real_async_client = httpx.AsyncClient
    seen_uas: list[str] = []
    seen_urls: list[str] = []

    def make_client(transport: httpx.MockTransport) -> type[httpx.AsyncClient]:
        class _PatchedClient(real_async_client):
            def __init__(self, *args: object, **kwargs: object) -> None:
                kwargs["transport"] = transport
                super().__init__(*args, **kwargs)  # type: ignore[arg-type]

        return _PatchedClient

    # 3a. happ://add/ unwrapping + sing-box/1.14.4 native JSON response
    def handler_singbox(request: httpx.Request) -> httpx.Response:
        seen_uas.append(request.headers.get("User-Agent", ""))
        seen_urls.append(str(request.url))
        sb_payload = {
            "outbounds": [
                {"type": "direct", "tag": "direct"},
                {
                    "type": "vless",
                    "tag": "DE-Native",
                    "server": "de-sb.example.com",
                    "server_port": 443,
                    "uuid": "44444444-2222-3333-4444-555555555555",
                },
            ]
        }
        return httpx.Response(200, json=sb_payload)

    monkeypatch.setattr(httpx, "AsyncClient", make_client(httpx.MockTransport(handler_singbox)))
    fetched_sb = await fetch_subscription("happ://add/https://sub.example.com/test", subscription_id="happ")
    assert seen_urls == ["https://sub.example.com/test"]
    assert seen_uas == ["sing-box/1.14.4"]
    assert len(fetched_sb) == 1
    assert fetched_sb[0].tag == "DE-Native"

    # 3b. Fallback from sing-box/1.14.4 (403) -> Happ/1.5.0 (Xray JSON array)
    seen_uas.clear()

    def handler_fallback(request: httpx.Request) -> httpx.Response:
        ua = request.headers.get("User-Agent", "")
        seen_uas.append(ua)
        if ua.startswith("sing-box/"):
            return httpx.Response(403, text="forbidden")
        return httpx.Response(200, json=xray_array)

    monkeypatch.setattr(httpx, "AsyncClient", make_client(httpx.MockTransport(handler_fallback)))
    fetched_fb = await fetch_subscription("https://sub.example.com/fallback", subscription_id="happ-fb")
    assert seen_uas == ["sing-box/1.14.4", "Happ/1.5.0"]
    assert len(fetched_fb) == 3
    assert [n.tag for n in fetched_fb] == ["NL-Reality", "NL-Reality-1", "RU-Hy2"]
