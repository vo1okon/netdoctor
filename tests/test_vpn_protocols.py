"""Tests for universal VPN protocol/key parsing, sing-box 1.14.4 validation, Flowseal 1.10.4 converter, and new Zapret2 strategies."""

from __future__ import annotations

import base64
import json
import subprocess
import tempfile
from pathlib import Path

import pytest

from netdoctor.config_gen import KNOWN_BLOBS, generate_singbox_config, generate_winws2_config
from netdoctor.models import Decision, Protocol
from netdoctor.presets import compile_zapret_preset, parse_bat_to_winws2_text
from netdoctor.selector import DEFAULT_STRATEGIES, load_strategies_from_yaml
from netdoctor.vpn import fetch_subscription, parse_single_uri, parse_subscription_payload


def test_parse_modern_vpn_uris() -> None:
    anytls = parse_single_uri(
        "anytls://secret@fra.example.com:443?sni=cdn.example.com&fp=chrome&alpn=h2,http/1.1"
        "&idle_session_check_interval=30s&idle_session_timeout=30s&min_idle_session=5#DE-AnyTLS"
    )
    assert anytls is not None
    assert anytls.protocol == "anytls"
    assert anytls.transport == "tls"
    assert anytls.region == "eu"
    assert anytls.raw_outbound["idle_session_check_interval"] == "30s"
    assert anytls.raw_outbound["min_idle_session"] == 5

    hy1 = parse_single_uri(
        "hysteria://hy1.example.com:443?auth=tok123&upmbps=40&downmbps=120&peer=cdn.example.com&alpn=h3#HY1"
    )
    assert hy1 is not None
    assert hy1.protocol == "hysteria"
    assert hy1.transport == "quic"
    assert hy1.raw_outbound["auth_str"] == "tok123"
    assert hy1.raw_outbound["up_mbps"] == 40
    assert hy1.raw_outbound["down_mbps"] == 120

    hy2 = parse_single_uri(
        "hy2://pass123@nl.example.com:443?mport=20000-30000&hop_interval=30s&upmbps=50&downmbps=200"
        "&obfs=salamander&obfs-password=obfpwd&sni=nl.example.com#NL-Hy2"
    )
    assert hy2 is not None
    assert hy2.protocol == "hysteria2"
    assert hy2.raw_outbound["server_ports"] == ["20000:30000"]
    assert "server_port" not in hy2.raw_outbound
    assert hy2.raw_outbound["hop_interval"] == "30s"
    assert hy2.raw_outbound["obfs"] == {"type": "salamander", "password": "obfpwd"}

    tuic = parse_single_uri(
        "tuic://00000000-0000-0000-0000-000000000001:tpass@sg.example.com:443"
        "?congestion_control=bbr&udp_relay_mode=native&zero_rtt_handshake=1&heartbeat=10s&alpn=h3#SG-TUIC"
    )
    assert tuic is not None
    assert tuic.protocol == "tuic"
    assert tuic.raw_outbound["udp_relay_mode"] == "native"
    assert tuic.raw_outbound["zero_rtt_handshake"] is True
    assert tuic.raw_outbound["heartbeat"] == "10s"

    vless = parse_single_uri(
        "vless://00000000-0000-0000-0000-000000000002@us.example.com:443"
        "?security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=01ab"
        "&type=ws&path=/ws?ed=2048&host=cdn.us.example.com&packetEncoding=xudp#US-VLESS"
    )
    assert vless is not None
    assert vless.raw_outbound["packet_encoding"] == "xudp"
    assert vless.raw_outbound["transport"]["type"] == "ws"
    assert vless.raw_outbound["transport"]["path"] == "/ws"
    assert vless.raw_outbound["transport"]["max_early_data"] == 2048
    assert "encryption" not in vless.raw_outbound

    vless_http = parse_single_uri(
        "vless://00000000-0000-0000-0000-000000000003@jp.example.com:443?type=http&host=a.example.com&path=/h2#JP-H2"
    )
    assert vless_http is not None
    assert vless_http.raw_outbound["transport"] == {"type": "http", "host": ["a.example.com"], "path": "/h2"}

    trojan_r = parse_single_uri(
        "trojan://trpass@de.example.com:443?security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=aa#DE-Trojan"
    )
    assert trojan_r is not None
    assert trojan_r.transport == "reality"
    assert trojan_r.raw_outbound["tls"]["reality"]["enabled"] is True

    ss_2022 = parse_single_uri(
        "ss://2022-blake3-aes-128-gcm:AAAAAAAAAAAAAAAAAAAAAA==@1.2.3.4:8388"
        "?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dcdn.example.com#SS2022"
    )
    assert ss_2022 is not None
    assert ss_2022.protocol == "shadowsocks"
    assert ss_2022.raw_outbound["method"] == "2022-blake3-aes-128-gcm"
    assert ss_2022.raw_outbound["password"] == "AAAAAAAAAAAAAAAAAAAAAA=="
    assert ss_2022.raw_outbound["plugin"] == "obfs-local"
    assert ss_2022.raw_outbound["plugin_opts"] == "obfs=http;obfs-host=cdn.example.com"

    stls = parse_single_uri("shadowtls://stpass@1.2.3.4:443?sni=gateway.icloud.com&version=3&fp=chrome#STLS")
    assert stls is not None
    assert stls.protocol == "shadowtls"
    assert stls.raw_outbound["version"] == 3

    awg = parse_single_uri(
        "awg://AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=@1.2.3.4:51820"
        "?publickey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=&address=10.8.1.2/32&mtu=1280&jc=4&jmin=40&jmax=70&s1=15&s2=25&h1=1&h2=2&h3=3&h4=4&reserved=1,2,3#AWG"
    )
    assert awg is not None
    assert awg.protocol == "amneziawg"
    assert awg.transport == "awg"
    assert awg.raw_outbound["jc"] == 4
    assert awg.raw_outbound["reserved"] == [1, 2, 3]

    socks = parse_single_uri("socks5://suser:spass@1.2.3.4:1080#SOCKS5")
    assert socks is not None
    assert socks.protocol == "socks"
    assert socks.raw_outbound["version"] == "5"
    assert socks.raw_outbound["username"] == "suser"

    http_proxy = parse_single_uri("http://huser:hpass@1.2.3.4:8080#HTTP")
    assert http_proxy is not None
    assert http_proxy.protocol == "http"
    assert http_proxy.raw_outbound["password"] == "hpass"

    ssh = parse_single_uri("ssh://root:sshpass@1.2.3.4:22#SSH")
    assert ssh is not None
    assert ssh.protocol == "ssh"
    assert ssh.raw_outbound["user"] == "root"

    naive = parse_single_uri("naive+https://nuser:npass@naive.example.com:443?sni=naive.example.com#Naive")
    assert naive is not None
    assert naive.protocol == "naive"
    assert naive.raw_outbound["username"] == "nuser"


def test_parse_wireguard_ini_and_clash_yaml_and_b64_and_singbox_check() -> None:
    wg_conf = """
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.8.1.2/32, fd00::2/128
MTU = 1360
Jc = 5
Jmin = 50
Jmax = 100
S1 = 10
S2 = 20
H1 = 11
H2 = 22
H3 = 33
H4 = 44

[Peer]
PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Endpoint = 198.51.100.10:51820
AllowedIPs = 0.0.0.0/0, ::/0
"""
    wg_nodes = parse_subscription_payload(wg_conf, subscription_id="wg-ini")
    assert len(wg_nodes) == 1
    assert wg_nodes[0].protocol == "amneziawg"
    assert wg_nodes[0].raw_outbound["jc"] == 5
    assert wg_nodes[0].raw_outbound["local_address"] == ["10.8.1.2/32", "fd00::2/128"]

    clash_yaml = """
proxies:
  - name: "DE AnyTLS"
    type: anytls
    server: 198.51.100.20
    port: 443
    password: secret
    sni: cdn.example.com
    client-fingerprint: chrome
  - name: "FI Hy2"
    type: hysteria2
    server: 198.51.100.21
    port: 443
    ports: "20000-30000"
    password: pypwd
    obfs: salamander
    obfs-password: obf
    sni: fi.example.com
  - name: "US Socks"
    type: socks5
    server: 198.51.100.22
    port: 1080
    username: u
    password: p
"""
    clash_nodes = parse_subscription_payload(clash_yaml, subscription_id="clash")
    assert [n.protocol for n in clash_nodes] == ["anytls", "hysteria2", "socks"]
    assert clash_nodes[1].raw_outbound["server_ports"] == ["20000:30000"]

    # Base64-encoded modern schemes subscription
    raw_lines = "\n".join(
        [
            "anytls://secret@198.51.100.1:443?sni=example.com#B64-AnyTLS",
            "socks5://u:p@198.51.100.2:1080#B64-Socks",
            "ssh://root:pw@198.51.100.3:22#B64-SSH",
        ]
    )
    b64_payload = base64.b64encode(raw_lines.encode("utf-8")).decode("ascii")
    b64_nodes = parse_subscription_payload(b64_payload, subscription_id="b64")
    assert [n.protocol for n in b64_nodes] == ["anytls", "socks", "ssh"]

    # Validate generated sing-box config containing all sing-box-native modern protocols via `sing-box check`
    singbox_exe = Path("bin") / "sing-box.exe"
    if singbox_exe.is_file():
        uri_bundle = "\n".join(
            [
                "anytls://secret@198.51.100.1:443?sni=example.com#AnyTLS",
                "hysteria://198.51.100.2:443?auth=tok&upmbps=50&downmbps=100&sni=example.com#Hy1",
                "hy2://pwd@198.51.100.3:443?mport=20000-30000&hop_interval=30s&obfs=salamander&obfs-password=o&sni=example.com#Hy2",
                "tuic://00000000-0000-0000-0000-000000000001:pw@198.51.100.4:443?udp_relay_mode=native&zero_rtt_handshake=1&sni=example.com#TUIC",
                "vless://00000000-0000-0000-0000-000000000002@198.51.100.5:443?security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=01ab&packetEncoding=xudp#VLESS",
                "trojan://trpw@198.51.100.6:443?security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=01ab&sni=example.com#TrojanR",
                "ss://2022-blake3-aes-128-gcm:AAAAAAAAAAAAAAAAAAAAAA==@198.51.100.7:8388#SS22",
                "shadowtls://stpw@198.51.100.8:443?sni=example.com&version=3#STLS",
                "wireguard://AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=@198.51.100.9:51820?publickey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=&address=10.8.1.2/32&reserved=AAAA#WG",
                "socks5://u:p@198.51.100.10:1080#Socks",
                "http://u:p@198.51.100.11:8080#HTTP",
                "ssh://root:pw@198.51.100.12:22#SSH",
            ]
        )
        all_nodes = parse_subscription_payload(uri_bundle, subscription_id="all")
        cfg = generate_singbox_config(
            decisions=[Decision(network_key="net", domain="example.org", layer="vpn", strategy_id="vpn-select")],
            vpn_nodes=all_nodes,
            use_wireguard_endpoints=True,
            extended_core=False,
        )
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as tmp:
            json.dump(cfg, tmp)
            tmp_path = Path(tmp.name)
        try:
            proc = subprocess.run([str(singbox_exe), "check", "-c", str(tmp_path)], capture_output=True, text=True)
            assert proc.returncode == 0, f"sing-box check failed: {proc.stderr}\n{proc.stdout}"
        finally:
            tmp_path.unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_fetch_subscription_deeplinks_and_http_proxy_uri() -> None:
    # Credentialed http:// proxy URI must parse directly without HTTP GET
    nodes = await fetch_subscription("http://user:pass@198.51.100.55:8080#LocalProxy")
    assert len(nodes) == 1
    assert nodes[0].protocol == "http"
    assert nodes[0].raw_outbound["username"] == "user"

    # Deep-link wrapping inline URI
    dl_nodes = await fetch_subscription("v2raytun://import/anytls://pw@198.51.100.66:443?sni=example.com#DL")
    assert len(dl_nodes) == 1
    assert dl_nodes[0].protocol == "anytls"


def test_flowseal_1104_converter_and_new_zapret2_strategies(tmp_path: Path) -> None:
    alt12_bat = Path("presets/zapret-discord-youtube/general (ALT12).bat").read_text(encoding="utf-8")
    converted_alt12 = parse_bat_to_winws2_text(alt12_bat, preset_name="ALT12")
    assert "blob=stun_pat" in converted_alt12
    assert "blob=tls_sferum" in converted_alt12
    assert "seqovl_pattern=tls_sferum" in converted_alt12

    compiled_alt12 = compile_zapret_preset(converted_alt12, bin_dir="bin", lists_dir=tmp_path / "lists")
    assert any(a.startswith("--blob=tls_sferum:") for a in compiled_alt12)
    assert any(a.startswith("--blob=stun_pat:") for a in compiled_alt12)

    alt13_bat = Path("presets/zapret-discord-youtube/general (ALT13).bat").read_text(encoding="utf-8")
    converted_alt13 = parse_bat_to_winws2_text(alt13_bat, preset_name="ALT13")
    assert "blob=tls_sochi" in converted_alt13
    assert "blob=stun2" in converted_alt13
    assert "hostfakesplit:host=mail.ru:altorder=1" in converted_alt13

    # Ensure YAML strategies stay in sync with DEFAULT_STRATEGIES and compile cleanly
    yaml_strats = load_strategies_from_yaml("configs/strategies.yaml")
    assert {s.id for s in yaml_strats} == {s.id for s in DEFAULT_STRATEGIES}
    assert "tls_alt12_1104_sferum_seqovl" in {s.id for s in DEFAULT_STRATEGIES}
    assert "tls_clone_multisplit_sni" in {s.id for s in DEFAULT_STRATEGIES}
    assert "tls_sferum" in KNOWN_BLOBS

    strat_map = {s.id: s for s in DEFAULT_STRATEGIES}
    args, _ = generate_winws2_config(
        decisions=[
            Decision(network_key="k", domain="youtube.com", protocol=Protocol.TLS, layer="dpi", strategy_id="tls_alt12_1104_sferum_seqovl"),
            Decision(network_key="k", domain="youtube.com", protocol=Protocol.QUIC, layer="dpi", strategy_id="quic_fake_rutube_repeats8"),
        ],
        strategies=strat_map,
        lists_dir=tmp_path / "wlists",
    )
    assert "--blob=tls_sferum:@files/tls_clienthello_www_sferum_ru.bin" in args
    assert "--blob=quic_rutube:@files/quic_initial_rutube_ru.bin" in args
