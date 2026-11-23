"""Universal parser for VPN subscriptions: Happ, V2Ray/Xray/Clash URI & YAML lists (vless, vmess, trojan, ss, hy/hy2, tuic, anytls, shadowtls, naive, wireguard/awg, socks, http, ssh), Sing-box JSON, and Amnezia vpn:// links."""

from __future__ import annotations

import base64
import json
import re
import urllib.parse
import zlib
from typing import Any

import httpx
import yaml

from netdoctor.models import VpnNode

_SUBSCRIPTION_USER_AGENTS: tuple[str, ...] = (
    "sing-box/1.14.4",
    "Happ/1.5.0",
    "v2rayNG/1.9.0",
    "ClashMeta/1.19.0",
)

_REGION_FLAGS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("eu", ("🇩🇪", "🇳🇱", "🇫🇮", "🇫🇷", "🇬🇧", "🇸🇪", "🇵🇱", "🇨🇿", "🇨🇭", "🇦🇹", "🇱🇻", "🇪🇪", "🇪🇺")),
    ("us", ("🇺🇸",)),
    ("ru", ("🇷🇺",)),
    ("asia", ("🇸🇬", "🇯🇵", "🇹🇷", "🇭🇰", "🇰🇷", "🇦🇪")),
)

_REGION_WORDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "eu",
        (
            "germany",
            "netherlands",
            "finland",
            "europe",
            "france",
            "united kingdom",
            "sweden",
            "poland",
            "czech",
            "switzerland",
            "austria",
            "latvia",
            "estonia",
            "frankfurt",
            "amsterdam",
            "helsinki",
            "london",
        ),
    ),
    ("us", ("new york", "new-york", "new_york", "dallas", "los angeles", "united states")),
    ("ru", ("russia", "moscow", "saint petersburg")),
    ("asia", ("asia", "singapore", "japan", "tokyo", "hong kong", "hong-kong", "korea", "seoul", "turkey", "istanbul", "dubai")),
)

_REGION_CODE_REGEXES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "eu",
        re.compile(r"(?<![A-Za-z])(?:DE|NL|FI|FR|UK|GB|SE|PL|CZ|CH|AT|LV|EE|EU)(?:\d+)?(?![A-Za-z])", re.IGNORECASE),
    ),
    (
        "us",
        re.compile(r"(?<![A-Za-z])(?:USA|US|LA|CA)(?:\d+)?(?![A-Za-z])", re.IGNORECASE),
    ),
    (
        "ru",
        re.compile(r"(?<![A-Za-z])(?:RU|MSK|SPB)(?:\d+)?(?![A-Za-z])", re.IGNORECASE),
    ),
    (
        "asia",
        re.compile(r"(?<![A-Za-z])(?:SG|JP|HK|KR|TR|AE)(?:\d+)?(?![A-Za-z])", re.IGNORECASE),
    ),
)


def _match_region_text(text: str) -> str | None:
    if not text:
        return None
    for region, flags in _REGION_FLAGS:
        if any(flag in text for flag in flags):
            return region
    low = text.lower()
    for region, words in _REGION_WORDS:
        if any(word in low for word in words):
            return region
    for region, pattern in _REGION_CODE_REGEXES:
        if pattern.search(text):
            return region
    return None


def infer_node_region(tag: str, server: str = "") -> str:
    """Infer region bucket ('eu', 'us', 'ru', 'asia', 'other') from node tag and server."""
    region = _match_region_text(tag)
    if region is not None:
        return region
    region = _match_region_text(server)
    return region if region is not None else "other"


def infer_node_transport(raw_outbound: dict[str, Any], protocol: str) -> str:
    """Infer node transport classification ('reality', 'ws', 'grpc', 'httpupgrade', 'quic', 'awg', 'wg', 'tls', 'tcp')."""
    tls = raw_outbound.get("tls")
    if isinstance(tls, dict):
        reality = tls.get("reality")
        if isinstance(reality, dict) and reality.get("enabled"):
            return "reality"

    transport = raw_outbound.get("transport")
    if isinstance(transport, dict) and transport.get("type"):
        return str(transport["type"]).lower()

    proto = (protocol or str(raw_outbound.get("type") or "")).strip().lower()
    if proto in ("hysteria", "hysteria2", "tuic"):
        return "quic"
    if proto == "amneziawg":
        return "awg"
    if proto == "wireguard":
        return "wg"
    if proto in ("anytls", "shadowtls", "naive"):
        return "tls"
    if isinstance(tls, dict) and tls.get("enabled"):
        return "tls"
    return "tcp"


def _make_vpn_node(
    *,
    tag: str,
    protocol: str,
    server: str,
    server_port: int,
    raw_outbound: dict[str, Any],
    subscription_id: str = "default",
    display_name: str = "",
) -> VpnNode:
    """Construct VpnNode cleanly whether or not extended fields exist in VpnNode yet."""
    shown_name = display_name or tag
    kwargs: dict[str, Any] = {
        "tag": tag,
        "protocol": protocol,
        "server": server,
        "server_port": server_port,
        "raw_outbound": raw_outbound,
        "subscription_id": subscription_id,
        "display_name": shown_name,
        "transport": infer_node_transport(raw_outbound, protocol),
        "region": infer_node_region(shown_name, server),
    }
    model_fields = getattr(VpnNode, "model_fields", None)
    if isinstance(model_fields, dict):
        kwargs = {k: v for k, v in kwargs.items() if k in model_fields}
    return VpnNode(**kwargs)


def _pad_b64(data: str) -> str:
    data = data.strip().replace("-", "+").replace("_", "/")
    missing = len(data) % 4
    if missing:
        data += "=" * (4 - missing)
    return data


def _parse_alpn(raw_alpn: Any) -> list[str]:
    if isinstance(raw_alpn, list):
        return [str(x).strip() for x in raw_alpn if str(x).strip()]
    if isinstance(raw_alpn, str):
        return [x.strip() for x in raw_alpn.split(",") if x.strip()]
    return []


def _is_truthy_flag(val: Any) -> bool:
    return str(val or "").strip().lower() in ("1", "true", "yes")


def _apply_v2ray_transport(outbound: dict[str, Any], net_type: str, host: str, path: str, service_name: str) -> None:
    net = (net_type or "tcp").strip().lower()
    if net == "ws":
        clean_path = path or "/"
        max_early_data: int | None = None
        if "?" in clean_path:
            base_p, query_p = clean_path.split("?", 1)
            q_params = urllib.parse.parse_qs(query_p, keep_blank_values=True)
            if "ed" in q_params:
                try:
                    max_early_data = int(q_params.pop("ed")[0])
                except (ValueError, TypeError):
                    pass
                new_q = urllib.parse.urlencode(q_params, doseq=True)
                clean_path = f"{base_p}?{new_q}" if new_q else (base_p or "/")
        ws_obj: dict[str, Any] = {
            "type": "ws",
            "path": clean_path or "/",
            "headers": {"Host": host},
        }
        if max_early_data is not None and max_early_data > 0:
            ws_obj["max_early_data"] = max_early_data
            ws_obj["early_data_header_name"] = "Sec-WebSocket-Protocol"
        outbound["transport"] = ws_obj
    elif net == "grpc":
        outbound["transport"] = {
            "type": "grpc",
            "service_name": service_name or "",
        }
    elif net in ("http", "h2"):
        http_obj: dict[str, Any] = {
            "type": "http",
            "path": path or "/",
        }
        if host:
            http_obj["host"] = [h.strip() for h in host.split(",") if h.strip()]
        outbound["transport"] = http_obj
    elif net in ("httpupgrade", "xhttp", "splithttp"):
        outbound["transport"] = {
            "type": "httpupgrade",
            "host": host,
            "path": path or "/",
        }


def _extract_xray_last_config_outbounds(
    last_config_raw: Any,
    base_tag: str,
    default_server: str,
) -> list[VpnNode]:
    """Extract valid proxy outbounds from Amnezia's `xray.last_config` JSON."""
    if not last_config_raw:
        return []
    last_cfg: Any = last_config_raw
    if isinstance(last_config_raw, str):
        try:
            last_cfg = json.loads(last_config_raw)
        except Exception:
            return []
    if not isinstance(last_cfg, dict):
        return []

    outbounds = last_cfg.get("outbounds")
    if not isinstance(outbounds, list):
        return []

    nodes: list[VpnNode] = []
    for idx, ob in enumerate(outbounds):
        if not isinstance(ob, dict):
            continue

        # Support sing-box format inside last_config
        sb_type = str(ob.get("type") or "").strip().lower()
        if sb_type in ("vless", "vmess", "trojan", "shadowsocks", "hysteria2", "tuic"):
            server = str(ob.get("server") or default_server).strip()
            if not server:
                continue
            try:
                port = int(ob.get("server_port") or 443)
            except (TypeError, ValueError):
                port = 443
            ob_tag_raw = str(ob.get("tag") or "").strip()
            if ob_tag_raw and ob_tag_raw not in ("proxy", "direct", "block"):
                node_tag = ob_tag_raw
            else:
                node_tag = base_tag if not nodes else f"{base_tag}-{idx}"
            ob_copy = dict(ob)
            ob_copy["tag"] = node_tag
            ob_copy["server"] = server
            ob_copy["server_port"] = port
            nodes.append(
                _make_vpn_node(
                    tag=node_tag,
                    protocol=sb_type,
                    server=server,
                    server_port=port,
                    raw_outbound=ob_copy,
                )
            )
            continue

        # Support Xray-core format inside last_config
        proto = str(ob.get("protocol") or "").strip().lower()
        if proto not in ("vless", "vmess", "trojan", "shadowsocks", "hysteria", "hysteria2"):
            continue

        settings = ob.get("settings")
        if not isinstance(settings, dict):
            continue
        stream = ob.get("streamSettings") if isinstance(ob.get("streamSettings"), dict) else {}

        server = ""
        port = 443
        outbound: dict[str, Any] = {}
        out_proto = "hysteria2" if proto in ("hysteria", "hysteria2") else proto

        if proto in ("vless", "vmess"):
            vnext = settings.get("vnext")
            if not isinstance(vnext, list) or not vnext or not isinstance(vnext[0], dict):
                continue
            ep = vnext[0]
            server = str(ep.get("address") or default_server).strip()
            try:
                port = int(ep.get("port") or 443)
            except (TypeError, ValueError):
                port = 443
            users = ep.get("users")
            user = users[0] if isinstance(users, list) and users and isinstance(users[0], dict) else {}
            uuid = str(user.get("id") or "").strip()
            if not server or not uuid:
                continue
            outbound = {
                "type": proto,
                "server": server,
                "server_port": port,
                "uuid": uuid,
            }
            if proto == "vless":
                flow = str(user.get("flow") or "").strip()
                if flow:
                    outbound["flow"] = flow
            else:
                outbound["security"] = str(user.get("security") or "auto")
                try:
                    outbound["alter_id"] = int(user.get("alterId") or 0)
                except (TypeError, ValueError):
                    outbound["alter_id"] = 0
        elif proto in ("hysteria", "hysteria2"):
            hs = stream.get("hysteriaSettings") if isinstance(stream.get("hysteriaSettings"), dict) else {}
            ts = stream.get("tlsSettings") if isinstance(stream.get("tlsSettings"), dict) else {}
            server = str(settings.get("address") or default_server).strip()
            try:
                port = int(settings.get("port") or 443)
            except (TypeError, ValueError):
                port = 443
            password = str(
                hs.get("auth") or hs.get("password") or settings.get("auth") or settings.get("password") or ""
            )
            if not server:
                continue
            # sing-box rejects `utls` on hysteria2, so emit only SNI / ALPN / insecure
            tls_obj_hy2: dict[str, Any] = {
                "enabled": True,
                "server_name": str(ts.get("serverName") or server),
            }
            alpn_hy2 = _parse_alpn(ts.get("alpn"))
            if alpn_hy2:
                tls_obj_hy2["alpn"] = alpn_hy2
            if _is_truthy_flag(ts.get("allowInsecure")) or _is_truthy_flag(ts.get("insecure")):
                tls_obj_hy2["insecure"] = True
            outbound = {
                "type": "hysteria2",
                "server": server,
                "server_port": port,
                "password": password,
                "tls": tls_obj_hy2,
            }
        else:
            servers = settings.get("servers")
            if not isinstance(servers, list) or not servers or not isinstance(servers[0], dict):
                continue
            srv = servers[0]
            server = str(srv.get("address") or default_server).strip()
            try:
                port = int(srv.get("port") or 443)
            except (TypeError, ValueError):
                port = 443
            password = str(srv.get("password") or "")
            if not server or not password:
                continue
            outbound = {
                "type": proto,
                "server": server,
                "server_port": port,
                "password": password,
            }
            if proto == "shadowsocks":
                outbound["method"] = str(srv.get("method") or "chacha20-ietf-poly1305")

        ob_tag_raw = str(ob.get("tag") or "").strip()
        if ob_tag_raw and ob_tag_raw not in ("proxy", "direct", "block"):
            node_tag = f"{base_tag}-{ob_tag_raw}"
        else:
            node_tag = base_tag if not nodes else f"{base_tag}-{idx}"
        outbound["tag"] = node_tag

        if out_proto != "hysteria2":
            # Convert Xray streamSettings -> sing-box tls + transport
            security = str(stream.get("security") or "").strip().lower()
            if security == "reality":
                rs = stream.get("realitySettings") if isinstance(stream.get("realitySettings"), dict) else {}
                server_names = rs.get("serverNames") if isinstance(rs.get("serverNames"), list) else []
                sni = str(rs.get("serverName") or (server_names[0] if server_names else "") or server)
                tls_obj: dict[str, Any] = {
                    "enabled": True,
                    "server_name": sni,
                    "reality": {
                        "enabled": True,
                        "public_key": str(rs.get("publicKey") or ""),
                        "short_id": str(rs.get("shortId") or ""),
                    },
                }
                fp = str(rs.get("fingerprint") or "").strip()
                if fp:
                    tls_obj["utls"] = {"enabled": True, "fingerprint": fp}
                outbound["tls"] = tls_obj
            elif security == "tls":
                ts = stream.get("tlsSettings") if isinstance(stream.get("tlsSettings"), dict) else {}
                sni = str(ts.get("serverName") or server)
                tls_obj = {"enabled": True, "server_name": sni}
                fp = str(ts.get("fingerprint") or "").strip()
                if fp:
                    tls_obj["utls"] = {"enabled": True, "fingerprint": fp}
                alpn = _parse_alpn(ts.get("alpn"))
                if alpn:
                    tls_obj["alpn"] = alpn
                if _is_truthy_flag(ts.get("allowInsecure")):
                    tls_obj["insecure"] = True
                outbound["tls"] = tls_obj

            net = str(stream.get("network") or "tcp").strip().lower()
            if net == "ws":
                ws = stream.get("wsSettings") if isinstance(stream.get("wsSettings"), dict) else {}
                headers = ws.get("headers") if isinstance(ws.get("headers"), dict) else {}
                ws_host = str(headers.get("Host") or headers.get("host") or server)
                _apply_v2ray_transport(outbound, "ws", ws_host, str(ws.get("path") or "/"), "")
            elif net == "grpc":
                gs = stream.get("grpcSettings") if isinstance(stream.get("grpcSettings"), dict) else {}
                _apply_v2ray_transport(outbound, "grpc", server, "/", str(gs.get("serviceName") or ""))
            elif net in ("httpupgrade", "xhttp", "splithttp"):
                hu = (
                    stream.get("httpupgradeSettings")
                    or stream.get("xhttpSettings")
                    or stream.get("splithttpSettings")
                    or {}
                )
                if not isinstance(hu, dict):
                    hu = {}
                hu_host = str(hu.get("host") or server)
                _apply_v2ray_transport(outbound, "httpupgrade", hu_host, str(hu.get("path") or "/"), "")

        nodes.append(
            _make_vpn_node(
                tag=node_tag,
                protocol=out_proto,
                server=server,
                server_port=port,
                raw_outbound=outbound,
            )
        )

    return nodes


def decode_amnezia_vpn_uri(uri: str) -> list[VpnNode]:
    """Decode an Amnezia `vpn://...` URI (Qt qCompress / zlib-compressed JSON) into sing-box VpnNodes."""
    raw_b64 = uri[len("vpn://") :].strip()
    raw_bytes = base64.b64decode(_pad_b64(raw_b64))
    # Qt qCompress prepends a 4-byte big-endian uncompressed size header before zlib stream
    json_bytes: bytes | None = None
    for offset in (4, 0):
        try:
            json_bytes = zlib.decompress(raw_bytes[offset:])
            break
        except zlib.error:
            continue
    if json_bytes is None:
        # Maybe plain base64 JSON without zlib
        json_bytes = raw_bytes

    cfg = json.loads(json_bytes.decode("utf-8", errors="replace"))
    nodes: list[VpnNode] = []
    containers = cfg.get("containers") or []
    host_name = cfg.get("hostName") or "amnezia-host"
    description = cfg.get("description") or "amnezia"

    for idx, container in enumerate(containers):
        if not isinstance(container, dict):
            continue
        cname = str(container.get("container") or "")
        tag = f"amnezia-{description}-{idx}"
        if "awg" in cname or "wireguard" in cname:
            awg_cfg = container.get("awg") or container.get("wireguard") or {}
            if isinstance(awg_cfg, dict) and isinstance(awg_cfg.get("last_config"), str):
                try:
                    parsed_awg_last = json.loads(awg_cfg["last_config"])
                    if isinstance(parsed_awg_last, dict):
                        merged = dict(parsed_awg_last)
                        merged.update({k: v for k, v in awg_cfg.items() if k != "last_config"})
                        awg_cfg = merged
                except Exception:
                    pass
            if not isinstance(awg_cfg, dict):
                awg_cfg = {}
            port = int(awg_cfg.get("port") or 51820)
            # Extract AmneziaWG obfuscation parameters (Jc, Jmin, Jmax, S1, S2, H1-H4)
            outbound: dict[str, Any] = {
                "type": "wireguard",
                "tag": tag,
                "server": host_name,
                "server_port": port,
                "local_address": ["10.8.1.2/32"],
                "private_key": awg_cfg.get("client_priv_key", ""),
                "peer_public_key": awg_cfg.get("server_pub_key", ""),
                "mtu": int(awg_cfg.get("mtu") or 1280),
            }
            for param in ("Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"):
                if param in awg_cfg:
                    outbound[param.lower()] = int(awg_cfg[param])
            nodes.append(
                _make_vpn_node(
                    tag=tag,
                    protocol="amneziawg" if "awg" in cname else "wireguard",
                    server=host_name,
                    server_port=port,
                    raw_outbound=outbound,
                )
            )
        elif "xray" in cname:
            xray_cfg = container.get("xray") or {}
            if not isinstance(xray_cfg, dict):
                xray_cfg = {}
            last_config_raw = xray_cfg.get("last_config") or container.get("last_config")
            extracted = _extract_xray_last_config_outbounds(
                last_config_raw,
                base_tag=tag,
                default_server=host_name,
            )
            if extracted:
                nodes.extend(extracted)
            else:
                port = int(xray_cfg.get("port") or 443)
                outbound = {
                    "type": "vless",
                    "tag": tag,
                    "server": host_name,
                    "server_port": port,
                    "uuid": xray_cfg.get("client_id", ""),
                    "flow": "xtls-rprx-vision",
                }
                nodes.append(
                    _make_vpn_node(
                        tag=tag,
                        protocol="vless",
                        server=host_name,
                        server_port=port,
                        raw_outbound=outbound,
                    )
                )

    if not nodes and host_name:
        # Generic fallback if container structure is minimal
        port = int(cfg.get("port") or 51820)
        tag = f"amnezia-{description}"
        nodes.append(
            _make_vpn_node(
                tag=tag,
                protocol="amneziawg",
                server=host_name,
                server_port=port,
                raw_outbound={
                    "type": "wireguard",
                    "tag": tag,
                    "server": host_name,
                    "server_port": port,
                },
            )
        )
    return nodes


def _build_tls_obj(
    server: str,
    sni: str = "",
    fp: str = "",
    alpn: list[str] | None = None,
    allow_insecure: bool = False,
    pbk: str = "",
    sid: str = "",
) -> dict[str, Any]:
    tls_obj: dict[str, Any] = {
        "enabled": True,
        "server_name": sni or server,
    }
    if fp:
        tls_obj["utls"] = {"enabled": True, "fingerprint": fp}
    if alpn:
        tls_obj["alpn"] = alpn
    if allow_insecure:
        tls_obj["insecure"] = True
    if pbk:
        tls_obj["reality"] = {
            "enabled": True,
            "public_key": pbk,
            "short_id": sid,
        }
    return tls_obj


def _parse_int_opt(val: Any) -> int | None:
    if val is None or str(val).strip() == "":
        return None
    try:
        return int(str(val).strip())
    except (ValueError, TypeError):
        return None


def _parse_host_port(raw_ep: str, default_port: int = 51820) -> tuple[str, int]:
    ep = raw_ep.strip()
    if ep.startswith("["):
        end_br = ep.find("]")
        if end_br != -1:
            host = ep[1:end_br]
            rest = ep[end_br + 1 :].lstrip(":")
            port = _parse_int_opt(rest) or default_port
            return host, port
    if ":" in ep and ep.count(":") == 1:
        host, port_str = ep.rsplit(":", 1)
        return host.strip(), _parse_int_opt(port_str) or default_port
    return ep, default_port


def _parse_wireguard_conf(text: str, subscription_id: str = "default") -> list[VpnNode]:
    """Parse raw WireGuard / AmneziaWG INI configuration (`[Interface]` + `[Peer]`)."""
    section = ""
    iface: dict[str, str] = {}
    peers: list[dict[str, str]] = []
    cur_peer: dict[str, str] | None = None

    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].split(";", 1)[0].strip()
        if not line:
            continue
        low = line.lower()
        if low == "[interface]":
            section = "interface"
            continue
        if low == "[peer]":
            section = "peer"
            cur_peer = {}
            peers.append(cur_peer)
            continue
        if "=" not in line:
            continue
        key, val = [p.strip() for p in line.split("=", 1)]
        lkey = key.lower()
        if section == "interface":
            iface[lkey] = val
        elif section == "peer" and cur_peer is not None:
            cur_peer[lkey] = val

    priv_key = iface.get("privatekey", "")
    if not priv_key or not peers:
        return []

    first_peer = peers[0]
    server, port = _parse_host_port(first_peer.get("endpoint", ""), 51820)
    if not server:
        return []

    addrs = [a.strip() for a in iface.get("address", "10.0.0.2/32").split(",") if a.strip()]
    is_awg = any(k in iface for k in ("jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4"))
    proto = "amneziawg" if is_awg else "wireguard"
    tag = f"{proto}-{server}"

    outbound: dict[str, Any] = {
        "type": "wireguard",
        "tag": tag,
        "server": server,
        "server_port": port,
        "local_address": addrs or ["10.0.0.2/32"],
        "private_key": priv_key,
        "peer_public_key": first_peer.get("publickey", ""),
    }
    mtu = _parse_int_opt(iface.get("mtu"))
    if mtu:
        outbound["mtu"] = mtu
    if first_peer.get("presharedkey"):
        outbound["pre_shared_key"] = first_peer["presharedkey"]
    if first_peer.get("allowedips"):
        outbound["allowed_ips"] = [x.strip() for x in first_peer["allowedips"].split(",") if x.strip()]
    for awg_k in ("jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4"):
        iv = _parse_int_opt(iface.get(awg_k))
        if iv is not None:
            outbound[awg_k] = iv

    return [
        _make_vpn_node(
            tag=tag,
            protocol=proto,
            server=server,
            server_port=port,
            raw_outbound=outbound,
            subscription_id=subscription_id,
        )
    ]


def _parse_clash_yaml_proxies(data: dict[str, Any], subscription_id: str = "default") -> list[VpnNode]:
    """Parse Clash / Mihomo YAML `proxies:` entries into sing-box outbounds."""
    proxies = data.get("proxies")
    if not isinstance(proxies, list):
        return []

    nodes: list[VpnNode] = []
    seen_tags: set[str] = set()
    for idx, p in enumerate(proxies):
        if not isinstance(p, dict):
            continue
        ptype = str(p.get("type") or "").strip().lower()
        server = str(p.get("server") or "").strip()
        port = _parse_int_opt(p.get("port")) or 443
        tag = str(p.get("name") or f"{ptype}-{idx}").strip()
        if not server or not ptype:
            continue

        outbound: dict[str, Any] | None = None
        out_proto = ptype

        if ptype == "vless":
            uuid = str(p.get("uuid") or "").strip()
            if not uuid:
                continue
            outbound = {"type": "vless", "tag": tag, "server": server, "server_port": port, "uuid": uuid}
            if p.get("flow"):
                outbound["flow"] = str(p["flow"])
            if p.get("packet-encoding"):
                outbound["packet_encoding"] = str(p["packet-encoding"])
            ropts = p.get("reality-opts") if isinstance(p.get("reality-opts"), dict) else {}
            if p.get("tls") or ropts:
                outbound["tls"] = _build_tls_obj(
                    server,
                    sni=str(p.get("servername") or p.get("sni") or server),
                    fp=str(p.get("client-fingerprint") or ("chrome" if ropts else "")),
                    alpn=_parse_alpn(p.get("alpn")),
                    allow_insecure=_is_truthy_flag(p.get("skip-cert-verify")),
                    pbk=str(ropts.get("public-key") or ""),
                    sid=str(ropts.get("short-id") or ""),
                )
            net = str(p.get("network") or "tcp").lower()
            ws_opts = p.get("ws-opts") if isinstance(p.get("ws-opts"), dict) else {}
            grpc_opts = p.get("grpc-opts") if isinstance(p.get("grpc-opts"), dict) else {}
            ws_headers = ws_opts.get("headers") if isinstance(ws_opts.get("headers"), dict) else {}
            _apply_v2ray_transport(
                outbound,
                net_type=net,
                host=str(ws_headers.get("Host") or ws_headers.get("host") or server),
                path=str(ws_opts.get("path") or "/"),
                service_name=str(grpc_opts.get("grpc-service-name") or ""),
            )
        elif ptype == "vmess":
            uuid = str(p.get("uuid") or "").strip()
            if not uuid:
                continue
            outbound = {
                "type": "vmess",
                "tag": tag,
                "server": server,
                "server_port": port,
                "uuid": uuid,
                "security": str(p.get("cipher") or "auto"),
                "alter_id": _parse_int_opt(p.get("alterId")) or 0,
            }
            if p.get("tls"):
                outbound["tls"] = _build_tls_obj(
                    server,
                    sni=str(p.get("servername") or p.get("sni") or server),
                    fp=str(p.get("client-fingerprint") or ""),
                    alpn=_parse_alpn(p.get("alpn")),
                    allow_insecure=_is_truthy_flag(p.get("skip-cert-verify")),
                )
            net = str(p.get("network") or "tcp").lower()
            ws_opts = p.get("ws-opts") if isinstance(p.get("ws-opts"), dict) else {}
            grpc_opts = p.get("grpc-opts") if isinstance(p.get("grpc-opts"), dict) else {}
            ws_headers = ws_opts.get("headers") if isinstance(ws_opts.get("headers"), dict) else {}
            _apply_v2ray_transport(
                outbound,
                net_type=net,
                host=str(ws_headers.get("Host") or ws_headers.get("host") or server),
                path=str(ws_opts.get("path") or "/"),
                service_name=str(grpc_opts.get("grpc-service-name") or ""),
            )
        elif ptype == "trojan":
            ropts = p.get("reality-opts") if isinstance(p.get("reality-opts"), dict) else {}
            outbound = {
                "type": "trojan",
                "tag": tag,
                "server": server,
                "server_port": port,
                "password": str(p.get("password") or ""),
                "tls": _build_tls_obj(
                    server,
                    sni=str(p.get("sni") or server),
                    fp=str(p.get("client-fingerprint") or ""),
                    alpn=_parse_alpn(p.get("alpn")),
                    allow_insecure=_is_truthy_flag(p.get("skip-cert-verify")),
                    pbk=str(ropts.get("public-key") or ""),
                    sid=str(ropts.get("short-id") or ""),
                ),
            }
            net = str(p.get("network") or "tcp").lower()
            ws_opts = p.get("ws-opts") if isinstance(p.get("ws-opts"), dict) else {}
            grpc_opts = p.get("grpc-opts") if isinstance(p.get("grpc-opts"), dict) else {}
            ws_headers = ws_opts.get("headers") if isinstance(ws_opts.get("headers"), dict) else {}
            _apply_v2ray_transport(
                outbound,
                net_type=net,
                host=str(ws_headers.get("Host") or ws_headers.get("host") or server),
                path=str(ws_opts.get("path") or "/"),
                service_name=str(grpc_opts.get("grpc-service-name") or ""),
            )
        elif ptype == "ss":
            out_proto = "shadowsocks"
            outbound = {
                "type": "shadowsocks",
                "tag": tag,
                "server": server,
                "server_port": port,
                "method": str(p.get("cipher") or "chacha20-ietf-poly1305"),
                "password": str(p.get("password") or ""),
            }
            if p.get("plugin"):
                outbound["plugin"] = str(p["plugin"])
                popts = p.get("plugin-opts")
                if isinstance(popts, dict):
                    outbound["plugin_opts"] = ";".join(f"{k}={v}" for k, v in popts.items())
                elif isinstance(popts, str):
                    outbound["plugin_opts"] = popts
        elif ptype == "hysteria2":
            outbound = {
                "type": "hysteria2",
                "tag": tag,
                "server": server,
                "server_port": port,
                "password": str(p.get("password") or ""),
                "tls": _build_tls_obj(
                    server,
                    sni=str(p.get("sni") or server),
                    alpn=_parse_alpn(p.get("alpn")),
                    allow_insecure=_is_truthy_flag(p.get("skip-cert-verify")),
                ),
            }
            if p.get("ports"):
                raw_ports = [x.strip().replace("-", ":") for x in str(p["ports"]).split(",") if x.strip()]
                if raw_ports:
                    outbound.pop("server_port", None)
                    outbound["server_ports"] = raw_ports
            if p.get("obfs"):
                outbound["obfs"] = {
                    "type": str(p["obfs"]),
                    "password": str(p.get("obfs-password") or ""),
                }
        elif ptype == "hysteria":
            outbound = {
                "type": "hysteria",
                "tag": tag,
                "server": server,
                "server_port": port,
                "auth_str": str(p.get("auth-str") or p.get("auth_str") or ""),
                "up_mbps": _parse_int_opt(p.get("up")) or 50,
                "down_mbps": _parse_int_opt(p.get("down")) or 100,
                "tls": _build_tls_obj(
                    server,
                    sni=str(p.get("sni") or server),
                    alpn=_parse_alpn(p.get("alpn")),
                    allow_insecure=_is_truthy_flag(p.get("skip-cert-verify")),
                ),
            }
        elif ptype == "tuic":
            outbound = {
                "type": "tuic",
                "tag": tag,
                "server": server,
                "server_port": port,
                "uuid": str(p.get("uuid") or ""),
                "password": str(p.get("password") or ""),
                "congestion_control": str(p.get("congestion-controller") or "bbr"),
                "tls": _build_tls_obj(
                    server,
                    sni=str(p.get("sni") or server),
                    alpn=_parse_alpn(p.get("alpn")),
                    allow_insecure=_is_truthy_flag(p.get("skip-cert-verify")),
                ),
            }
        elif ptype == "anytls":
            outbound = {
                "type": "anytls",
                "tag": tag,
                "server": server,
                "server_port": port,
                "password": str(p.get("password") or ""),
                "tls": _build_tls_obj(
                    server,
                    sni=str(p.get("sni") or server),
                    fp=str(p.get("client-fingerprint") or ""),
                    alpn=_parse_alpn(p.get("alpn")),
                    allow_insecure=_is_truthy_flag(p.get("skip-cert-verify")),
                ),
            }
        elif ptype == "wireguard":
            awg_opts = p.get("amnezia-wg-option") if isinstance(p.get("amnezia-wg-option"), dict) else {}
            is_awg = bool(awg_opts)
            out_proto = "amneziawg" if is_awg else "wireguard"
            ip_v4 = str(p.get("ip") or "10.0.0.2").strip()
            if "/" not in ip_v4:
                ip_v4 += "/32"
            outbound = {
                "type": "wireguard",
                "tag": tag,
                "server": server,
                "server_port": port,
                "local_address": [ip_v4],
                "private_key": str(p.get("private-key") or ""),
                "peer_public_key": str(p.get("public-key") or ""),
            }
            if p.get("mtu"):
                outbound["mtu"] = int(p["mtu"])
            if p.get("reserved"):
                outbound["reserved"] = p["reserved"]
            for ak, av in awg_opts.items():
                iv = _parse_int_opt(av)
                if iv is not None:
                    outbound[str(ak).lower()] = iv
        elif ptype in ("socks5", "socks"):
            out_proto = "socks"
            outbound = {"type": "socks", "tag": tag, "server": server, "server_port": port, "version": "5"}
            if p.get("username"):
                outbound["username"] = str(p["username"])
            if p.get("password"):
                outbound["password"] = str(p["password"])
        elif ptype == "http":
            outbound = {"type": "http", "tag": tag, "server": server, "server_port": port}
            if p.get("username"):
                outbound["username"] = str(p["username"])
            if p.get("password"):
                outbound["password"] = str(p["password"])
            if p.get("tls"):
                outbound["tls"] = _build_tls_obj(
                    server,
                    sni=str(p.get("sni") or server),
                    allow_insecure=_is_truthy_flag(p.get("skip-cert-verify")),
                )

        if outbound is None:
            continue
        if tag in seen_tags:
            tag = f"{tag}-{idx}"
            outbound["tag"] = tag
        seen_tags.add(tag)
        nodes.append(
            _make_vpn_node(
                tag=tag,
                protocol=out_proto,
                server=server,
                server_port=port,
                raw_outbound=outbound,
                subscription_id=subscription_id,
            )
        )
    return nodes


def parse_single_uri(uri: str, index: int = 0) -> VpnNode | None:
    """Parse a single vless://, vmess://, trojan://, ss://, hy://, hy2://, tuic://, anytls://, shadowtls://, naive+https://, wireguard://, awg://, socks5://, http://, ssh://, or vpn:// link."""
    uri = uri.strip()
    if not uri or uri.startswith("#"):
        return None

    if uri.startswith("vpn://"):
        amnezia_nodes = decode_amnezia_vpn_uri(uri)
        return amnezia_nodes[0] if amnezia_nodes else None

    if uri.startswith("vmess://"):
        raw = base64.b64decode(_pad_b64(uri[len("vmess://") :])).decode("utf-8", errors="replace")
        data = json.loads(raw)
        server = str(data.get("add") or "")
        port = int(data.get("port") or 443)
        tag = str(data.get("ps") or f"vmess-{index}")
        outbound: dict[str, Any] = {
            "type": "vmess",
            "tag": tag,
            "server": server,
            "server_port": port,
            "uuid": str(data.get("id") or ""),
            "security": str(data.get("scy") or "auto"),
            "alter_id": int(data.get("aid") or 0),
        }
        tls_flag = str(data.get("tls") or "").strip().lower()
        if tls_flag in ("tls", "1", "true"):
            outbound["tls"] = _build_tls_obj(
                server,
                sni=str(data.get("sni") or data.get("host") or server),
                fp=str(data.get("fp") or "").strip(),
                alpn=_parse_alpn(data.get("alpn")),
                allow_insecure=_is_truthy_flag(data.get("allowInsecure")) or _is_truthy_flag(data.get("insecure")),
            )
        _apply_v2ray_transport(
            outbound,
            net_type=str(data.get("net") or "tcp"),
            host=str(data.get("host") or data.get("sni") or server),
            path=str(data.get("path") or "/"),
            service_name=str(data.get("serviceName") or data.get("path") or ""),
        )
        return _make_vpn_node(tag=tag, protocol="vmess", server=server, server_port=port, raw_outbound=outbound)

    parsed = urllib.parse.urlsplit(uri)
    scheme = parsed.scheme.lower()
    supported_schemes = (
        "vless",
        "trojan",
        "ss",
        "hy",
        "hysteria",
        "hy2",
        "hysteria2",
        "tuic",
        "anytls",
        "shadowtls",
        "naive+https",
        "naive+quic",
        "wireguard",
        "wg",
        "awg",
        "socks",
        "socks5",
        "socks4",
        "socks4a",
        "http",
        "https",
        "ssh",
    )
    if scheme not in supported_schemes:
        return None

    qs = urllib.parse.parse_qs(parsed.query)
    tag = urllib.parse.unquote(parsed.fragment) if parsed.fragment else f"{scheme}-{index}"
    server = parsed.hostname or ""
    port = parsed.port or 443
    user = urllib.parse.unquote(parsed.username or "")
    password_part = urllib.parse.unquote(parsed.password or "")
    allow_insecure = _is_truthy_flag(qs.get("allowInsecure", ["0"])[0]) or _is_truthy_flag(
        qs.get("insecure", ["0"])[0]
    )
    alpn_list = _parse_alpn(qs.get("alpn", [""])[0])

    if scheme == "vless":
        outbound = {
            "type": "vless",
            "tag": tag,
            "server": server,
            "server_port": port,
            "uuid": user,
        }
        flow = qs.get("flow", [""])[0]
        if flow:
            outbound["flow"] = flow
        pkt_enc = qs.get("packetEncoding", qs.get("packet_encoding", [""]))[0]
        if pkt_enc:
            outbound["packet_encoding"] = pkt_enc
        security = qs.get("security", [""])[0].lower()
        if security in ("tls", "reality"):
            outbound["tls"] = _build_tls_obj(
                server,
                sni=qs.get("sni", [server])[0] or server,
                fp=qs.get("fp", [""])[0] or ("chrome" if security == "reality" else ""),
                alpn=alpn_list,
                allow_insecure=allow_insecure,
                pbk=qs.get("pbk", [""])[0] if security == "reality" else "",
                sid=qs.get("sid", [""])[0] if security == "reality" else "",
            )
        _apply_v2ray_transport(
            outbound,
            net_type=qs.get("type", ["tcp"])[0],
            host=qs.get("host", [server])[0] or server,
            path=qs.get("path", ["/"])[0] or "/",
            service_name=qs.get("serviceName", [""])[0],
        )
        return _make_vpn_node(tag=tag, protocol="vless", server=server, server_port=port, raw_outbound=outbound)

    if scheme == "trojan":
        security = qs.get("security", ["tls"])[0].lower()
        pbk = qs.get("pbk", [""])[0] if security == "reality" else ""
        sid = qs.get("sid", [""])[0] if security == "reality" else ""
        fp = qs.get("fp", [""])[0] or ("chrome" if security == "reality" else "")
        outbound = {
            "type": "trojan",
            "tag": tag,
            "server": server,
            "server_port": port,
            "password": user,
            "tls": _build_tls_obj(
                server,
                sni=qs.get("sni", [server])[0] or server,
                fp=fp,
                alpn=alpn_list,
                allow_insecure=allow_insecure,
                pbk=pbk,
                sid=sid,
            ),
        }
        _apply_v2ray_transport(
            outbound,
            net_type=qs.get("type", ["tcp"])[0],
            host=qs.get("host", [server])[0] or server,
            path=qs.get("path", ["/"])[0] or "/",
            service_name=qs.get("serviceName", [""])[0],
        )
        return _make_vpn_node(tag=tag, protocol="trojan", server=server, server_port=port, raw_outbound=outbound)

    if scheme in ("hy2", "hysteria2"):
        tls_obj = {
            "enabled": True,
            "server_name": qs.get("sni", [server])[0] or server,
            "insecure": allow_insecure,
        }
        if alpn_list:
            tls_obj["alpn"] = alpn_list
        outbound = {
            "type": "hysteria2",
            "tag": tag,
            "server": server,
            "server_port": port,
            "password": user,
            "tls": tls_obj,
        }
        mport = qs.get("mport", [""])[0].strip()
        if mport:
            ports_list = [p.strip().replace("-", ":") for p in mport.split(",") if p.strip()]
            if ports_list:
                outbound.pop("server_port", None)
                outbound["server_ports"] = ports_list
        hop_interval = qs.get("hop_interval", qs.get("hopInterval", [""]))[0].strip()
        if hop_interval:
            outbound["hop_interval"] = hop_interval
        up_mbps = _parse_int_opt(qs.get("upmbps", qs.get("up_mbps", [""]))[0])
        down_mbps = _parse_int_opt(qs.get("downmbps", qs.get("down_mbps", [""]))[0])
        if up_mbps:
            outbound["up_mbps"] = up_mbps
        if down_mbps:
            outbound["down_mbps"] = down_mbps
        obfs_type = qs.get("obfs", [""])[0].strip()
        obfs_pwd = qs.get("obfs-password", qs.get("obfs_password", [""]))[0].strip()
        if obfs_type and obfs_type != "none":
            outbound["obfs"] = {"type": obfs_type, "password": obfs_pwd}
        return _make_vpn_node(tag=tag, protocol="hysteria2", server=server, server_port=port, raw_outbound=outbound)

    if scheme in ("hy", "hysteria"):
        up_mbps = _parse_int_opt(qs.get("upmbps", [""])[0]) or 50
        down_mbps = _parse_int_opt(qs.get("downmbps", [""])[0]) or 100
        auth_str = qs.get("auth", [user])[0]
        sni = qs.get("peer", qs.get("sni", [server]))[0] or server
        outbound = {
            "type": "hysteria",
            "tag": tag,
            "server": server,
            "server_port": port,
            "auth_str": auth_str,
            "up_mbps": up_mbps,
            "down_mbps": down_mbps,
            "tls": _build_tls_obj(server, sni=sni, alpn=alpn_list, allow_insecure=allow_insecure),
        }
        obfs_val = qs.get("obfsParam", qs.get("obfs", [""]))[0]
        if obfs_val and obfs_val != "xplus":
            outbound["obfs"] = obfs_val
        return _make_vpn_node(tag=tag, protocol="hysteria", server=server, server_port=port, raw_outbound=outbound)

    if scheme == "ss":
        method = "chacha20-ietf-poly1305"
        password = user
        if password_part:
            method = user
            password = password_part
        elif not server and parsed.netloc:
            try:
                decoded_netloc = base64.b64decode(_pad_b64(parsed.netloc)).decode("utf-8")
                if "@" in decoded_netloc:
                    userinfo, hostport = decoded_netloc.rsplit("@", 1)
                    if ":" in userinfo:
                        method, password = userinfo.split(":", 1)
                    if ":" in hostport:
                        host_part, port_part = hostport.rsplit(":", 1)
                        server = host_part.strip("[]")
                        port = int(port_part)
            except Exception:
                pass
        elif ":" not in user and user:
            try:
                decoded_user = base64.b64decode(_pad_b64(user)).decode("utf-8")
                if ":" in decoded_user:
                    method, password = decoded_user.split(":", 1)
            except Exception:
                pass
        elif ":" in user:
            method, password = user.split(":", 1)
        outbound = {
            "type": "shadowsocks",
            "tag": tag,
            "server": server,
            "server_port": port,
            "method": method,
            "password": password,
        }
        plugin_raw = urllib.parse.unquote(qs.get("plugin", [""])[0]).strip()
        if plugin_raw:
            if ";" in plugin_raw:
                pname, popts = plugin_raw.split(";", 1)
                outbound["plugin"] = pname.strip()
                outbound["plugin_opts"] = popts.strip()
            else:
                outbound["plugin"] = plugin_raw
        return _make_vpn_node(tag=tag, protocol="shadowsocks", server=server, server_port=port, raw_outbound=outbound)

    if scheme == "tuic":
        outbound = {
            "type": "tuic",
            "tag": tag,
            "server": server,
            "server_port": port,
            "uuid": user,
            "password": password_part,
            "congestion_control": qs.get("congestion_control", ["bbr"])[0],
            "tls": _build_tls_obj(
                server,
                sni=qs.get("sni", [server])[0] or server,
                alpn=alpn_list,
                allow_insecure=allow_insecure,
            ),
        }
        udp_relay = qs.get("udp_relay_mode", qs.get("udp-relay-mode", [""]))[0].strip()
        if udp_relay:
            outbound["udp_relay_mode"] = udp_relay
        if _is_truthy_flag(qs.get("zero_rtt_handshake", qs.get("reduce_rtt", ["0"]))[0]):
            outbound["zero_rtt_handshake"] = True
        heartbeat = qs.get("heartbeat", [""])[0].strip()
        if heartbeat:
            outbound["heartbeat"] = heartbeat
        return _make_vpn_node(tag=tag, protocol="tuic", server=server, server_port=port, raw_outbound=outbound)

    if scheme == "anytls":
        outbound = {
            "type": "anytls",
            "tag": tag,
            "server": server,
            "server_port": port,
            "password": user,
            "tls": _build_tls_obj(
                server,
                sni=qs.get("sni", [server])[0] or server,
                fp=qs.get("fp", [""])[0],
                alpn=alpn_list,
                allow_insecure=allow_insecure,
            ),
        }
        for key in ("idle_session_check_interval", "idle_session_timeout"):
            val = qs.get(key, [""])[0].strip()
            if val:
                outbound[key] = val
        min_idle = _parse_int_opt(qs.get("min_idle_session", [""])[0])
        if min_idle is not None:
            outbound["min_idle_session"] = min_idle
        return _make_vpn_node(tag=tag, protocol="anytls", server=server, server_port=port, raw_outbound=outbound)

    if scheme == "shadowtls":
        password = user
        version = _parse_int_opt(qs.get("version", qs.get("v", ["3"]))[0]) or 3
        sni = qs.get("sni", qs.get("host", [server]))[0] or server
        if not server and parsed.netloc:
            try:
                decoded_b64 = base64.b64decode(_pad_b64(parsed.netloc.split("?", 1)[0])).decode("utf-8")
                st_data = json.loads(decoded_b64)
                server = str(st_data.get("server") or st_data.get("host") or "")
                port = int(st_data.get("port") or 443)
                password = str(st_data.get("password") or password)
                version = int(st_data.get("version") or version)
                sni = str(st_data.get("sni") or server)
            except Exception:
                pass
        if not server:
            return None
        outbound = {
            "type": "shadowtls",
            "tag": tag,
            "server": server,
            "server_port": port,
            "version": version,
            "password": password,
            "tls": _build_tls_obj(
                server,
                sni=sni,
                fp=qs.get("fp", [""])[0],
                alpn=alpn_list,
                allow_insecure=allow_insecure,
            ),
        }
        return _make_vpn_node(tag=tag, protocol="shadowtls", server=server, server_port=port, raw_outbound=outbound)

    if scheme in ("naive+https", "naive+quic"):
        outbound = {
            "type": "naive",
            "tag": tag,
            "server": server,
            "server_port": port,
            "username": user,
            "password": password_part,
            "tls": _build_tls_obj(
                server,
                sni=qs.get("sni", [server])[0] or server,
                allow_insecure=allow_insecure,
            ),
        }
        return _make_vpn_node(tag=tag, protocol="naive", server=server, server_port=port, raw_outbound=outbound)

    if scheme in ("wireguard", "wg", "awg"):
        wg_port = parsed.port or 51820
        priv_key = user
        addrs = [a.strip() for a in qs.get("address", ["10.0.0.2/32"])[0].split(",") if a.strip()]
        pub_key = qs.get("publickey", qs.get("public_key", [""]))[0].strip()
        awg_params: dict[str, int] = {}
        for ak in ("jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4"):
            iv = _parse_int_opt(qs.get(ak, qs.get(ak.capitalize(), [""]))[0])
            if iv is not None:
                awg_params[ak] = iv
        proto = "amneziawg" if (scheme == "awg" or awg_params) else "wireguard"
        outbound = {
            "type": "wireguard",
            "tag": tag,
            "server": server,
            "server_port": wg_port,
            "local_address": addrs or ["10.0.0.2/32"],
            "private_key": priv_key,
            "peer_public_key": pub_key,
        }
        mtu = _parse_int_opt(qs.get("mtu", [""])[0])
        if mtu:
            outbound["mtu"] = mtu
        psk = qs.get("presharedkey", qs.get("pre_shared_key", [""]))[0].strip()
        if psk:
            outbound["pre_shared_key"] = psk
        reserved = qs.get("reserved", [""])[0].strip()
        if reserved:
            if "," in reserved:
                outbound["reserved"] = [int(x.strip()) for x in reserved.split(",") if x.strip().isdigit()]
            else:
                outbound["reserved"] = reserved
        outbound.update(awg_params)
        return _make_vpn_node(tag=tag, protocol=proto, server=server, server_port=wg_port, raw_outbound=outbound)

    if scheme in ("socks", "socks5", "socks4", "socks4a"):
        socks_port = parsed.port or 1080
        socks_user = user
        socks_pass = password_part
        if socks_user and not socks_pass and ":" not in socks_user:
            try:
                dec = base64.b64decode(_pad_b64(socks_user)).decode("utf-8")
                if ":" in dec:
                    socks_user, socks_pass = dec.split(":", 1)
            except Exception:
                pass
        elif not server and parsed.netloc:
            try:
                dec = base64.b64decode(_pad_b64(parsed.netloc)).decode("utf-8")
                if "@" in dec:
                    up, hp = dec.rsplit("@", 1)
                    if ":" in up:
                        socks_user, socks_pass = up.split(":", 1)
                    server, socks_port = _parse_host_port(hp, 1080)
            except Exception:
                pass
        if not server:
            return None
        ver = "4a" if scheme == "socks4a" else ("4" if scheme == "socks4" else "5")
        outbound = {
            "type": "socks",
            "tag": tag,
            "server": server,
            "server_port": socks_port,
            "version": ver,
        }
        if socks_user:
            outbound["username"] = socks_user
        if socks_pass:
            outbound["password"] = socks_pass
        return _make_vpn_node(tag=tag, protocol="socks", server=server, server_port=socks_port, raw_outbound=outbound)

    if scheme in ("http", "https"):
        http_port = parsed.port or (443 if scheme == "https" else 8080)
        outbound = {
            "type": "http",
            "tag": tag,
            "server": server,
            "server_port": http_port,
        }
        if user:
            outbound["username"] = user
        if password_part:
            outbound["password"] = password_part
        if scheme == "https":
            outbound["tls"] = _build_tls_obj(
                server,
                sni=qs.get("sni", [server])[0] or server,
                allow_insecure=allow_insecure,
            )
        return _make_vpn_node(tag=tag, protocol="http", server=server, server_port=http_port, raw_outbound=outbound)

    if scheme == "ssh":
        ssh_port = parsed.port or 22
        outbound = {
            "type": "ssh",
            "tag": tag,
            "server": server,
            "server_port": ssh_port,
        }
        if user:
            outbound["user"] = user
        if password_part:
            outbound["password"] = password_part
        return _make_vpn_node(tag=tag, protocol="ssh", server=server, server_port=ssh_port, raw_outbound=outbound)

    return None


def _append_deduped_xray_nodes(
    extracted: list[VpnNode],
    nodes: list[VpnNode],
    seen_tags: set[str],
    subscription_id: str,
    suffix_hint: int | str,
) -> None:
    """Assign subscription_id and deduplicate tags when appending Xray-extracted nodes."""
    for j, n in enumerate(extracted):
        n.subscription_id = subscription_id
        tag = n.tag
        if tag in seen_tags:
            candidate = f"{tag}-{suffix_hint}"
            if candidate in seen_tags:
                candidate = f"{tag}-{suffix_hint}-{j}"
            tag = candidate
        n.tag = tag
        n.raw_outbound["tag"] = tag
        seen_tags.add(tag)
        nodes.append(n)


def parse_subscription_payload(payload: str, subscription_id: str = "default") -> list[VpnNode]:
    """Parse subscription text (raw URI lines, base64 URI list, WireGuard/AWG .conf, Clash YAML, Amnezia vpn://, Sing-box JSON, or Xray JSON)."""
    text = payload.strip()
    if not text:
        return []

    # 1. Check if it's Sing-box JSON config or Xray/Happ JSON array/object
    if text.startswith(("{", "[")):
        try:
            data = json.loads(text)
            nodes: list[VpnNode] = []
            seen_json_tags: set[str] = set()
            if isinstance(data, list):
                for idx, item in enumerate(data):
                    if not isinstance(item, dict):
                        continue
                    remarks = str(item.get("remarks") or item.get("tag") or f"xray-{idx}").strip()
                    extracted = _extract_xray_last_config_outbounds(
                        item,
                        base_tag=remarks,
                        default_server="",
                    )
                    _append_deduped_xray_nodes(extracted, nodes, seen_json_tags, subscription_id, idx)
                return nodes
            if isinstance(data, dict):
                outbounds = data.get("outbounds") or []
                endpoints = data.get("endpoints") or []
                for idx, ob in enumerate(outbounds):
                    if not isinstance(ob, dict):
                        continue
                    ob_type = str(ob.get("type") or "")
                    if ob_type in ("direct", "block", "dns", "selector", "urltest", ""):
                        continue
                    server = str(ob.get("server") or "")
                    port = int(ob.get("server_port") or 443)
                    tag = str(ob.get("tag") or f"{ob_type}-{idx}")
                    ob_copy = dict(ob)
                    if tag in seen_json_tags:
                        tag = f"{tag}-{idx}"
                    ob_copy["tag"] = tag
                    seen_json_tags.add(tag)
                    nodes.append(
                        _make_vpn_node(
                            tag=tag,
                            protocol=ob_type,
                            server=server,
                            server_port=port,
                            raw_outbound=ob_copy,
                            subscription_id=subscription_id,
                        )
                    )
                for idx, ep in enumerate(endpoints):
                    if not isinstance(ep, dict):
                        continue
                    ep_type = str(ep.get("type") or "")
                    if ep_type not in ("wireguard", "tailscale"):
                        continue
                    if ep_type == "tailscale":
                        tag = str(ep.get("tag") or f"tailscale-ep-{idx}")
                        ep_copy = dict(ep)
                        if tag in seen_json_tags:
                            tag = f"{tag}-{idx}"
                        ep_copy["tag"] = tag
                        seen_json_tags.add(tag)
                        nodes.append(
                            _make_vpn_node(
                                tag=tag,
                                protocol="tailscale",
                                server=str(ep.get("control_url") or "tailscale"),
                                server_port=443,
                                raw_outbound=ep_copy,
                                subscription_id=subscription_id,
                            )
                        )
                        continue
                    peers = ep.get("peers") or []
                    first_peer = peers[0] if isinstance(peers, list) and peers and isinstance(peers[0], dict) else {}
                    server = str(first_peer.get("address") or ep.get("server") or "")
                    port = int(first_peer.get("port") or ep.get("server_port") or 51820)
                    tag = str(ep.get("tag") or f"wireguard-ep-{idx}")
                    ep_copy = dict(ep)
                    if tag in seen_json_tags:
                        tag = f"{tag}-{idx}"
                    ep_copy["tag"] = tag
                    seen_json_tags.add(tag)
                    nodes.append(
                        _make_vpn_node(
                            tag=tag,
                            protocol="wireguard",
                            server=server,
                            server_port=port,
                            raw_outbound=ep_copy,
                            subscription_id=subscription_id,
                        )
                    )
                if not nodes and isinstance(data.get("outbounds"), list):
                    remarks = str(data.get("remarks") or data.get("tag") or "xray").strip()
                    extracted = _extract_xray_last_config_outbounds(
                        data,
                        base_tag=remarks,
                        default_server="",
                    )
                    _append_deduped_xray_nodes(extracted, nodes, seen_json_tags, subscription_id, 0)
                return nodes
        except Exception:
            pass

    # 1b. Raw WireGuard / AmneziaWG INI configuration
    low_text = text.lower()
    if "[interface]" in low_text and "[peer]" in low_text:
        wg_nodes = _parse_wireguard_conf(text, subscription_id=subscription_id)
        if wg_nodes:
            return wg_nodes

    # 1c. Clash / Mihomo YAML subscription
    if "proxies:" in low_text:
        try:
            yaml_data = yaml.safe_load(text)
            if isinstance(yaml_data, dict) and isinstance(yaml_data.get("proxies"), list):
                yaml_nodes = _parse_clash_yaml_proxies(yaml_data, subscription_id=subscription_id)
                if yaml_nodes:
                    return yaml_nodes
        except Exception:
            pass

    # 2. If not starting with a known scheme, try base64 decoding (Happ / V2Ray subscription format)
    known_prefixes = (
        "vless://",
        "vmess://",
        "trojan://",
        "ss://",
        "hy://",
        "hysteria://",
        "hy2://",
        "hysteria2://",
        "tuic://",
        "anytls://",
        "shadowtls://",
        "naive+https://",
        "naive+quic://",
        "wireguard://",
        "wg://",
        "awg://",
        "socks://",
        "socks5://",
        "socks4://",
        "socks4a://",
        "ssh://",
        "vpn://",
    )
    if not any(text.lower().startswith(p) for p in known_prefixes):
        try:
            decoded = base64.b64decode(_pad_b64(text)).decode("utf-8", errors="replace")
            if any(p in decoded.lower() for p in known_prefixes):
                text = decoded
        except Exception:
            pass

    # 3. Parse line by line (preserve node.tag without subscription prefix when unique)
    nodes = []
    seen_tags: set[str] = set()
    for idx, line in enumerate(text.splitlines()):
        line = line.strip()
        if not line:
            continue
        if line.startswith("vpn://"):
            for n in decode_amnezia_vpn_uri(line):
                n.subscription_id = subscription_id
                if n.tag in seen_tags:
                    n.tag = f"{n.tag}-{idx}"
                    n.raw_outbound["tag"] = n.tag
                seen_tags.add(n.tag)
                nodes.append(n)
        else:
            node = parse_single_uri(line, index=idx)
            if node:
                node.subscription_id = subscription_id
                if node.tag in seen_tags:
                    node.tag = f"{node.tag}-{idx}"
                    node.raw_outbound["tag"] = node.tag
                seen_tags.add(node.tag)
                nodes.append(node)
    return nodes


def _unwrap_subscription_deeplink(raw_input: str) -> str:
    val = raw_input.strip()
    low = val.lower()
    for prefix in ("happ://add/", "v2raytun://import/", "hiddify://import/", "streisand://import/"):
        if low.startswith(prefix):
            inner = val[len(prefix) :].strip()
            if inner.lower().startswith(("http%3a", "https%3a")):
                inner = urllib.parse.unquote(inner)
            return inner
    if low.startswith("sing-box://import-remote-profile"):
        parsed = urllib.parse.urlsplit(val)
        qs = urllib.parse.parse_qs(parsed.query)
        target_url = qs.get("url", [""])[0].strip()
        if target_url:
            return target_url
    return val


async def fetch_subscription(url_or_uri: str, subscription_id: str = "default", timeout: float = 10.0) -> list[VpnNode]:
    """Fetch a remote subscription URL (preferring native Sing-box JSON, falling back to Happ/Clash) or parse an inline URI/config."""
    url_or_uri = _unwrap_subscription_deeplink(url_or_uri)

    # HTTP/HTTPS proxy credentials URI (e.g. http://user:pass@host:port) must be parsed locally, not fetched
    is_http_url = url_or_uri.lower().startswith(("http://", "https://"))
    if is_http_url:
        parsed_http = urllib.parse.urlsplit(url_or_uri)
        if "@" in parsed_http.netloc:
            return parse_subscription_payload(url_or_uri, subscription_id=subscription_id)

    if is_http_url:
        last_resp: httpx.Response | None = None
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            for user_agent in _SUBSCRIPTION_USER_AGENTS:
                resp = await client.get(
                    url_or_uri,
                    headers={"User-Agent": user_agent},
                )
                last_resp = resp
                if resp.is_success:
                    nodes = parse_subscription_payload(resp.text, subscription_id=subscription_id)
                    if nodes:
                        return nodes
        if last_resp is not None and not last_resp.is_success:
            last_resp.raise_for_status()
        return []
    return parse_subscription_payload(url_or_uri, subscription_id=subscription_id)


async def refresh_all_subscriptions(storage: Any, timeout: float = 10.0) -> dict[str, int]:
    """Refresh all stored VPN subscriptions from their original URLs/URIs and update storage."""
    results: dict[str, int] = {}
    for sub in storage.get_subscriptions():
        sub_id = sub["id"]
        url_or_uri = sub["url_or_uri"]
        try:
            nodes = await fetch_subscription(url_or_uri, subscription_id=sub_id, timeout=timeout)
        except Exception:
            results[sub_id] = 0
            continue
        if nodes:
            storage.save_subscription(
                sub_id=sub_id,
                url_or_uri=url_or_uri,
                nodes=[n.model_dump(mode="json") for n in nodes],
            )
        results[sub_id] = len(nodes)
    return results
