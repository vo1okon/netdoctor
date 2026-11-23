"""Data models for netdoctor probes, verdicts, decisions, strategies, and VPN subscriptions."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class VerdictClass(StrEnum):
    OK = "ok"
    DNS_POISON = "dns_poison"
    IP_BLOCK = "ip_block"
    SNI_DPI = "sni_dpi"
    THROTTLE = "throttle"
    QUIC_BLOCK = "quic_block"
    PROTOCOL_BLOCK = "protocol_block"
    UNKNOWN = "unknown"


class Protocol(StrEnum):
    TLS = "tls"
    QUIC = "quic"
    HTTP = "http"


class NetworkKind(StrEnum):
    HOME = "home"
    MOBILE = "mobile"
    UNKNOWN = "unknown"


class NetworkFingerprint(BaseModel):
    asn: int = 0
    kind: NetworkKind = NetworkKind.HOME
    isp: str = "unknown"
    gateway_mac: str = ""

    @property
    def key(self) -> str:
        return f"AS{self.asn}:{self.kind.value}:{self.gateway_mac or 'default'}"


class DnsProbeResult(BaseModel):
    system: str = "ok"  # "ok", "stub_ip", "timeout", "nxdomain"
    doh: str = "ok"  # "ok", "timeout", "nxdomain"
    system_ips: list[str] = Field(default_factory=list)
    doh_ips: list[str] = Field(default_factory=list)


class TcpProbeResult(BaseModel):
    result: str = "ok"  # "ok", "timeout", "reset", "refused"
    rtt_ms: float | None = None
    target_ip: str | None = None


class TlsProbeResult(BaseModel):
    real_sni: str = "ok"  # "ok", "reset", "timeout", "cert_mismatch", "alert"
    neutral_sni: str = "ok"  # "ok" (reached server, incl. alert/mismatch), "reset", "timeout"
    ttfb_ms: float | None = None


class StallProbeResult(BaseModel):
    result: str = "ok"  # "ok", "stall", "reset", "timeout", "skipped"
    bytes_read: int = 0
    throughput_kbps: float | None = None


class QuicProbeResult(BaseModel):
    result: str = "ok"  # "ok", "timeout", "reset", "skipped"
    rtt_ms: float | None = None


class ProtocolBlockProbeResult(BaseModel):
    result: str = "skipped"  # "ok", "protocol_block", "unreachable", "skipped"
    detail: str = ""


class ProbesSummary(BaseModel):
    dns: DnsProbeResult = Field(default_factory=DnsProbeResult)
    tcp: TcpProbeResult = Field(default_factory=TcpProbeResult)
    tls: TlsProbeResult = Field(default_factory=TlsProbeResult)
    stall: StallProbeResult = Field(default_factory=StallProbeResult)
    quic: QuicProbeResult = Field(default_factory=QuicProbeResult)
    protocol_tunnel: ProtocolBlockProbeResult = Field(default_factory=ProtocolBlockProbeResult)


class RecommendedAction(BaseModel):
    layer: str  # "direct", "dns", "dpi", "proxy", "vpn"
    action: str  # "none", "doh", "strategy_family", "quic_fallback", "vpn_outbound"
    value: str | None = None


class DiagnosticReport(BaseModel):
    domain: str
    network: dict[str, Any]
    checked_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
    )
    bypass_active: bool = False
    probes: ProbesSummary
    verdicts: list[VerdictClass]
    confidence: float = 0.9
    recommended: list[RecommendedAction] = Field(default_factory=list)
    ttl_sec: int = 21600


class Strategy(BaseModel):
    id: str
    family: str
    protocol: Protocol = Protocol.TLS
    tier: int = 2  # 0=direct, 1=dns, 2=light desync, 3=heavy desync, 4=proxy/vpn
    args_template: list[str] = Field(default_factory=list)
    description: str = ""


class Decision(BaseModel):
    network_key: str
    domain: str
    protocol: Protocol = Protocol.TLS
    layer: str  # "direct", "dns", "dpi", "vpn", "tg_ws"
    strategy_id: str | None = None
    fallback_strategies: list[str] = Field(default_factory=list)
    ttfb_ms: float | None = None
    throughput_kbps: float | None = None
    consecutive_fails: int = 0
    status: str = "active"  # "active", "degraded", "expired"
    pinned: bool = False
    updated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
    )
    ttl_sec: int = 21600


class VpnNode(BaseModel):
    tag: str
    protocol: str  # "vless", "vmess", "trojan", "shadowsocks", "hysteria", "hysteria2", "tuic", "anytls", "shadowtls", "naive", "wireguard", "amneziawg", "tailscale", "socks", "http", "ssh"
    server: str
    server_port: int
    raw_outbound: dict[str, Any]
    subscription_id: str = "default"
    display_name: str = ""
    transport: str = "tcp"
    region: str = "other"
    priority: int = 100
    enabled: bool = True
