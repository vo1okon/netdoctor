"""Deterministic classifier translating probe results into verdict classes and recommended actions."""

from __future__ import annotations

from netdoctor.models import (
    DiagnosticReport,
    NetworkFingerprint,
    ProbesSummary,
    RecommendedAction,
    VerdictClass,
)


def classify_probes(
    domain: str,
    probes: ProbesSummary,
    network: NetworkFingerprint | None = None,
    bypass_active: bool = False,
    ttl_sec: int = 21600,
) -> DiagnosticReport:
    """Classify probe results into one or more VerdictClass values and recommendations."""
    net = network or NetworkFingerprint(asn=0)
    verdicts: list[VerdictClass] = []
    recommended: list[RecommendedAction] = []

    # 1. DNS check
    if probes.dns.system in ("stub_ip", "nxdomain", "timeout") and probes.dns.doh == "ok":
        verdicts.append(VerdictClass.DNS_POISON)
        recommended.append(RecommendedAction(layer="dns", action="doh"))
    elif probes.dns.system != "ok" and probes.dns.doh != "ok":
        # Both DNS resolvers failed
        return DiagnosticReport(
            domain=domain,
            network={"asn": net.asn, "kind": net.kind.value},
            bypass_active=bypass_active,
            probes=probes,
            verdicts=[VerdictClass.UNKNOWN],
            confidence=0.4,
            recommended=[],
            ttl_sec=3600,
        )

    # 2. TCP check (on clean/DoH IP)
    if probes.tcp.result in ("timeout", "reset", "refused"):
        verdicts.append(VerdictClass.IP_BLOCK)
        recommended.append(RecommendedAction(layer="vpn", action="vpn_outbound"))
        confidence = 0.45 if bypass_active else 0.90
        return DiagnosticReport(
            domain=domain,
            network={"asn": net.asn, "kind": net.kind.value},
            bypass_active=bypass_active,
            probes=probes,
            verdicts=verdicts,
            confidence=confidence,
            recommended=recommended,
            ttl_sec=ttl_sec,
        )

    # 3. TLS SNI DPI check
    # Rule: neutral_sni == "ok" (including TLS alert / cert mismatch from real server) means IP is reachable.
    # If real_sni fails ("reset", "timeout") while neutral_sni succeeds -> sni_dpi.
    if probes.tls.real_sni in ("reset", "timeout") and probes.tls.neutral_sni == "ok":
        verdicts.append(VerdictClass.SNI_DPI)
        recommended.append(
            RecommendedAction(layer="dpi", action="strategy_family", value="multisplit")
        )
    elif probes.tls.real_sni in ("reset", "timeout") and probes.tls.neutral_sni in ("reset", "timeout"):
        # Both real and neutral SNI blocked on port 443 -> IP/port level block or strict TLS block
        verdicts.append(VerdictClass.IP_BLOCK)
        recommended.append(RecommendedAction(layer="vpn", action="vpn_outbound"))

    # 4. Post-handshake stall / throttling check
    if probes.stall.result in ("stall", "reset", "timeout"):
        verdicts.append(VerdictClass.THROTTLE)
        if not any(r.layer == "dpi" for r in recommended):
            recommended.append(
                RecommendedAction(layer="dpi", action="strategy_family", value="fakedsplit")
            )

    # 5. QUIC (UDP/443) check
    if probes.quic.result in ("timeout", "reset"):
        verdicts.append(VerdictClass.QUIC_BLOCK)
        if not any(r.layer == "dpi" for r in recommended):
            recommended.append(
                RecommendedAction(layer="dpi", action="strategy_family", value="quic_fake")
            )

    # 5b. Tunnel protocol block check (Stage 2/6)
    if probes.protocol_tunnel.result == "protocol_block":
        verdicts.append(VerdictClass.PROTOCOL_BLOCK)
        recommended.append(
            RecommendedAction(layer="vpn", action="change_obfuscation", value="vless-reality")
        )

    # 5c. Geo-block check (TLS OK, no stall, HTTP 403/451)
    if (
        probes.tls.real_sni == "ok"
        and probes.stall.result == "ok"
        and getattr(probes.stall, "http_status", None) in (403, 451)
        and VerdictClass.IP_BLOCK not in verdicts
        and VerdictClass.SNI_DPI not in verdicts
        and VerdictClass.THROTTLE not in verdicts
    ):
        verdicts.append(VerdictClass.GEO_BLOCK)
        recommended.append(RecommendedAction(layer="dns", action="smartdns", value="ai_bypass"))

    # 6. Everything clean
    if not verdicts:
        verdicts.append(VerdictClass.OK)
        recommended.append(RecommendedAction(layer="direct", action="none"))

    confidence = 0.50 if bypass_active else 0.85
    return DiagnosticReport(
        domain=domain,
        network={"asn": net.asn, "kind": net.kind.value},
        bypass_active=bypass_active,
        probes=probes,
        verdicts=verdicts,
        confidence=confidence,
        recommended=recommended,
        ttl_sec=ttl_sec,
    )
