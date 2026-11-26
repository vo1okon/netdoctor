"""Clean-network startup calibration for selecting live base DNS and ISP TSPU profile."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable

from netdoctor.classifier import classify_probes
from netdoctor.core.bundles import load_bundles
from netdoctor.models import (
    Decision,
    DiagnosticReport,
    NetworkFingerprint,
    Protocol,
    VerdictClass,
)
from netdoctor.orchestrators import AI_GEOBLOCK_DOMAINS, DnsLayerOrchestrator
from netdoctor.probes import (
    detect_bypass_active,
    detect_network_fingerprint,
    run_domain_probes,
)
from netdoctor.selector import (
    _diverse_fallbacks,
    _is_admin,
    _ordered_pool,
    evaluate_domains_live_batch,
)
from netdoctor.storage import Storage

CALIBRATION_BEACONS: tuple[dict[str, str], ...] = (
    {"id": "clean", "domain": "example.com", "kind": "clean"},
    {"id": "sni_dpi", "domain": "discord.com", "kind": "sni_dpi"},
    {"id": "throttle", "domain": "googlevideo.com", "kind": "throttle"},
    {"id": "quic", "domain": "youtube.com", "kind": "quic"},
    {"id": "geoblock", "domain": "chatgpt.com", "kind": "geoblock"},
    {"id": "cloud_cf", "domain": "cloudflare.com", "kind": "cloud"},
)


def _emit_progress(cb: Callable[[str, str], None] | None, step: str, detail: str) -> None:
    if cb is not None:
        try:
            cb(step, detail)
        except Exception:
            pass


async def calibrate_network(
    storage: Storage,
    *,
    dns_orch: DnsLayerOrchestrator | None = None,
    bin_dir: str | Path = "bin",
    timeout: float = 2.5,
    progress_cb: Callable[[str, str], None] | None = None,
    probe_fn: Callable[[str, float], Awaitable[Any]] | None = None,
    base_dns_probe_fn: Callable[[dict[str, Any]], Awaitable[dict[str, Any]]] | None = None,
    strategy_eval_fn: Callable[..., Awaitable[dict[str, Decision]]] | None = None,
) -> dict[str, Any]:
    """Run clean-network calibration: pick live base DNS, probe ISP beacons, and save profile + priors."""
    dns_orchestrator = dns_orch or DnsLayerOrchestrator()
    _emit_progress(progress_cb, "dns", "Подбираем быстрый рабочий DNS…")

    net: NetworkFingerprint = await detect_network_fingerprint(timeout=min(timeout, 2.5))
    net_key = storage.upsert_network(net)

    # Step 1: Select a live non-SmartDNS base resolver (refusing hardcoded 1.1.1.1 fallback when another works)
    base_roll = await dns_orchestrator.roll_base_dns(
        storage,
        probe_fn=base_dns_probe_fn,
        timeout=min(timeout, 2.0),
    )
    selected_dns = dict(base_roll.get("selected") or {})
    base_dns_id = str(selected_dns.get("id") or "").strip()
    if base_dns_id:
        storage.set_setting(f"base_dns_id:{net_key}", base_dns_id)
        cur_active = dns_orchestrator.get_active_dns(storage)
        if str(cur_active.get("category") or "").strip().lower() != "ai_bypass":
            storage.set_setting("active_dns_id", base_dns_id)

    # Step 2: Run beacon probes concurrently on clean network
    _emit_progress(progress_cb, "beacons", "Проверяем профиль блокировок провайдера…")
    doh_url = str(selected_dns.get("doh_url") or "https://dns.quad9.net/dns-query")

    async def _probe_beacon(dom: str) -> Any:
        if probe_fn is not None:
            return await probe_fn(dom, timeout)
        return await run_domain_probes(dom, doh_url=doh_url, timeout=min(timeout, 2.5))

    beacon_domains = [b["domain"] for b in CALIBRATION_BEACONS]
    probe_results = await asyncio.gather(*(_probe_beacon(d) for d in beacon_domains), return_exceptions=True)

    bypass = detect_bypass_active()
    reports: dict[str, DiagnosticReport] = {}
    quic_blocked = False
    sni_dpi_detected = False
    throttle_detected = False
    geo_block_detected = False
    dpi_targets: list[tuple[str, str, list[VerdictClass]]] = []

    for b, pr in zip(CALIBRATION_BEACONS, probe_results):
        dom = b["domain"]
        if isinstance(pr, Exception):
            continue
        rep = classify_probes(domain=dom, probes=pr, network=net, bypass_active=bypass)
        reports[dom] = rep
        storage.save_verdict(net_key, rep, protocol=Protocol.TLS)
        if VerdictClass.QUIC_BLOCK in rep.verdicts:
            quic_blocked = True
        if VerdictClass.SNI_DPI in rep.verdicts:
            sni_dpi_detected = True
        if VerdictClass.THROTTLE in rep.verdicts:
            throttle_detected = True
        if VerdictClass.GEO_BLOCK in rep.verdicts:
            geo_block_detected = True
        if any(v in rep.verdicts for v in (VerdictClass.SNI_DPI, VerdictClass.THROTTLE)):
            ip = pr.tcp.target_ip or (pr.dns.doh_ips[0] if pr.dns.doh_ips else "1.1.1.1")
            dpi_targets.append((dom, ip, rep.verdicts))

    # Step 3: Pick isp_best_tls
    _emit_progress(progress_cb, "strategy", "Подбираем оптимальную стратегию обхода…")
    strategies = storage.get_strategies()
    tls_pool = [s for s in _ordered_pool(strategies, Protocol.TLS) if s.args_template]
    best_tls_id = tls_pool[0].id if tls_pool else "tls_alt1_199_fake_fakedsplit"

    if dpi_targets:
        has_vpn = storage.has_usable_vpn()
        if strategy_eval_fn is not None:
            eval_decs = await strategy_eval_fn(
                dpi_targets,
                net_key,
                candidates=tls_pool,
                bin_dir=bin_dir,
                use_live_eval=True,
                vpn_available=has_vpn,
            )
        else:
            can_live = _is_admin() and not bypass and (Path(bin_dir).resolve() / "winws2.exe").is_file()
            eval_decs = await evaluate_domains_live_batch(
                dpi_targets,
                net_key,
                candidates=tls_pool,
                bin_dir=bin_dir,
                use_live_eval=can_live,
                vpn_available=has_vpn,
            )
        for dom, dec in eval_decs.items():
            if dec.layer == "dpi" and dec.strategy_id:
                best_tls_id = dec.strategy_id
                break

    existing_pinned = {
        (d.domain.lower(), d.protocol)
        for d in storage.get_decisions(net_key, active_only=False)
        if getattr(d, "pinned", False)
    }
    tls_fallbacks = _diverse_fallbacks(tls_pool, best_tls_id, next((s.family for s in tls_pool if s.id == best_tls_id), ""))

    # Seed priors for beacon outcomes and TCP-invisible clusters (YouTube throttle / QUIC / AI geo-block)
    for dom, rep in reports.items():
        if (dom.lower(), Protocol.TLS) not in existing_pinned:
            if any(v in rep.verdicts for v in (VerdictClass.SNI_DPI, VerdictClass.THROTTLE)):
                storage.save_decision(
                    Decision(
                        network_key=net_key,
                        domain=dom,
                        protocol=Protocol.TLS,
                        layer="dpi",
                        strategy_id=best_tls_id,
                        fallback_strategies=tls_fallbacks,
                    )
                )
            elif VerdictClass.DNS_POISON in rep.verdicts:
                storage.save_decision(
                    Decision(
                        network_key=net_key,
                        domain=dom,
                        protocol=Protocol.TLS,
                        layer="dns",
                        strategy_id="doh",
                    )
                )
            elif VerdictClass.GEO_BLOCK in rep.verdicts:
                storage.save_decision(
                    Decision(
                        network_key=net_key,
                        domain=dom,
                        protocol=Protocol.TLS,
                        layer="dns",
                        strategy_id="smartdns",
                    )
                )
        if quic_blocked and VerdictClass.QUIC_BLOCK in rep.verdicts and (dom.lower(), Protocol.QUIC) not in existing_pinned:
            storage.save_decision(
                Decision(
                    network_key=net_key,
                    domain=dom,
                    protocol=Protocol.QUIC,
                    layer="dpi",
                    strategy_id="quic_fallback_tcp",
                )
            )

    if (throttle_detected or sni_dpi_detected) and ("youtube.com", Protocol.TLS) not in existing_pinned:
        for yt_dom in ("youtube.com", "googlevideo.com", "ytimg.com"):
            if (yt_dom, Protocol.TLS) not in existing_pinned:
                storage.save_decision(
                    Decision(
                        network_key=net_key,
                        domain=yt_dom,
                        protocol=Protocol.TLS,
                        layer="dpi",
                        strategy_id=best_tls_id,
                        fallback_strategies=tls_fallbacks,
                    )
                )
            if quic_blocked and (yt_dom, Protocol.QUIC) not in existing_pinned:
                storage.save_decision(
                    Decision(
                        network_key=net_key,
                        domain=yt_dom,
                        protocol=Protocol.QUIC,
                        layer="dpi",
                        strategy_id="quic_fallback_tcp",
                    )
                )

    if geo_block_detected:
        for ai_dom in ("chatgpt.com", "claude.ai", "gemini.google.com"):
            if (ai_dom, Protocol.TLS) not in existing_pinned and ai_dom in AI_GEOBLOCK_DOMAINS:
                existing_ai = [d for d in storage.get_decisions(net_key, active_only=False) if d.domain == ai_dom and d.protocol == Protocol.TLS]
                if not existing_ai:
                    storage.save_decision(
                        Decision(
                            network_key=net_key,
                            domain=ai_dom,
                            protocol=Protocol.TLS,
                            layer="dns",
                            strategy_id="smartdns",
                        )
                    )

    # Set baseline AppBundle routing modes (never overriding pinned manual choices)
    try:
        bundles = load_bundles(storage=storage)
        existing_bundle_modes = storage.get_bundle_modes(net_key)
        cf_rep = reports.get("cloudflare.com")
        cf_dpi = bool(
            cf_rep is not None
            and any(v in cf_rep.verdicts for v in (VerdictClass.SNI_DPI, VerdictClass.THROTTLE))
        )
        for b in bundles:
            rec = existing_bundle_modes.get(b.id) or {}
            if rec.get("pinned"):
                continue
            auth_dpi = any(
                reports.get(d) is not None
                and any(v in reports[d].verdicts for v in (VerdictClass.SNI_DPI, VerdictClass.THROTTLE))
                for d in b.auth_domains
            )
            dpi_env = sni_dpi_detected or cf_dpi or throttle_detected
            if auth_dpi or (dpi_env and (b.default_mode == "direct_dpi" or (b.category == "game" and b.coupling == "tight"))):
                auto_mode = "direct_dpi"
            else:
                auto_mode = b.default_mode if b.default_mode in ("direct_clean", "direct_dpi", "vpn") else "direct_clean"
                if auto_mode == "direct_dpi" and not dpi_env:
                    auto_mode = "direct_clean"
            storage.set_bundle_mode(net_key, b.id, auto_mode, pinned=False)
    except Exception:
        pass

    now_iso = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
    meta = {
        "sni_dpi_detected": sni_dpi_detected,
        "throttle_detected": throttle_detected,
        "geo_block_detected": geo_block_detected,
        "quic_blocked": quic_blocked,
        "base_dns_server": selected_dns.get("ip", ""),
        "base_dns_name": selected_dns.get("name", ""),
        "calibrated_at": now_iso,
    }
    storage.save_network_profile(
        net_key,
        base_dns_id=base_dns_id,
        best_tls_strategy=best_tls_id,
        quic_blocked=quic_blocked,
        calibrated_at=now_iso,
        meta=meta,
    )
    _emit_progress(progress_cb, "done", "Калибровка сети завершена")
    return {
        "ok": True,
        "network_key": net_key,
        "base_dns_id": base_dns_id,
        "base_dns": selected_dns,
        "best_tls_strategy": best_tls_id,
        "quic_blocked": quic_blocked,
        "sni_dpi_detected": sni_dpi_detected,
        "throttle_detected": throttle_detected,
        "geo_block_detected": geo_block_detected,
        "calibrated_at": now_iso,
    }
