"""Dynamic TTL revalidation, failure fallback promotion, and periodic canary checks."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable

import httpx

from netdoctor.models import Decision, NetworkFingerprint, Strategy
from netdoctor.probes import detect_network_fingerprint, probe_dns, probe_tcp, probe_tls
from netdoctor.selector import DEFAULT_STRATEGIES
from netdoctor.storage import Storage


def is_decision_expired(decision: Decision, now: datetime | None = None) -> bool:
    """Check if a decision's TTL has elapsed."""
    now_dt = now or datetime.now(timezone.utc)
    try:
        updated_dt = datetime.fromisoformat(decision.updated_at)
        elapsed = (now_dt - updated_dt).total_seconds()
        return elapsed >= decision.ttl_sec
    except Exception:
        return True


def promote_fallback_on_failure(storage: Storage, decision: Decision) -> Decision:
    """Handle failure policy:
    1. Increment consecutive_fails.
    2. If fallback strategies exist, promote the first fallback to active strategy_id.
    3. If no fallbacks remain, escalate layer to 'vpn' (outbound sing-box urltest/selector).
    """
    decision.consecutive_fails += 1
    decision.updated_at = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")

    if decision.fallback_strategies:
        next_strat = decision.fallback_strategies.pop(0)
        decision.strategy_id = next_strat
        decision.status = "active"
    else:
        decision.layer = "vpn"
        decision.strategy_id = "vpn-select"
        decision.status = "active"

    storage.save_decision(decision)
    return decision


def get_due_decisions(storage: Storage, network: NetworkFingerprint) -> list[Decision]:
    """Return all active decisions for the current network that have expired TTL."""
    decisions = storage.get_decisions(network.key, active_only=True)
    return [d for d in decisions if is_decision_expired(d)]


_CIRCULAR_STRAT_RE = re.compile(
    r"circular[^\r\n]*?(?:rotate\s+strategy\s+to\s+|strategy[=:\s]+)(\d+)",
    re.IGNORECASE,
)
_CIRCULAR_HOST_RE = re.compile(r"\b(?:host|hostname|sni)[=:\s]+'?([a-z0-9.-]+\.[a-z]{2,})'?", re.IGNORECASE)
_CIRCULAR_AUTOSTATE_RE = re.compile(r"autostate\.[a-z0-9_]+\.([a-z0-9.-]+\.[a-z]{2,})", re.IGNORECASE)
_CIRCULAR_HOSTNAME_QUOTED_RE = re.compile(r"hostname='([a-z0-9.-]+\.[a-z]{2,})'", re.IGNORECASE)


def _read_log_tail_text(path: Path, max_bytes: int) -> str:
    if max_bytes <= 0 or not path.is_file():
        return ""
    try:
        size = path.stat().st_size
        if size <= 0:
            return ""
        start = max(0, size - max_bytes)
        with path.open("rb") as f:
            if start > 0:
                f.seek(start)
            raw = f.read(max_bytes)
        if start > 0 and b"\n" in raw:
            raw = raw.split(b"\n", 1)[1]
        return raw.decode("utf-8", errors="replace")
    except OSError:
        return ""


def parse_circular_rotations(log_text_or_path: str | Path, max_bytes: int = 262_144) -> list[dict[str, Any]]:
    """Extract winws2 circular orchestrator rotation events from raw log text or the tail of a log file."""
    if isinstance(log_text_or_path, Path):
        text = _read_log_tail_text(log_text_or_path, max_bytes)
    else:
        maybe_path = Path(log_text_or_path)
        if "\n" not in log_text_or_path and len(log_text_or_path) < 260 and maybe_path.is_file():
            text = _read_log_tail_text(maybe_path, max_bytes)
        else:
            text = log_text_or_path

    lines = text.splitlines()
    events: list[dict[str, Any]] = []
    for idx, raw_line in enumerate(lines):
        low_line = raw_line.lower()
        if "start from strategy" in low_line or "current strategy" in low_line:
            continue
        strat_match = _CIRCULAR_STRAT_RE.search(raw_line)
        if not strat_match:
            continue
        domain: str | None = None
        host_match = _CIRCULAR_HOST_RE.search(raw_line)
        if host_match:
            domain = host_match.group(1)
        else:
            for back in range(1, 4):
                if idx - back < 0:
                    break
                prev_line = lines[idx - back]
                auto_m = _CIRCULAR_AUTOSTATE_RE.search(prev_line)
                if auto_m:
                    domain = auto_m.group(1)
                    break
                hn_m = _CIRCULAR_HOSTNAME_QUOTED_RE.search(prev_line)
                if hn_m:
                    domain = hn_m.group(1)
                    break
        events.append(
            {
                "domain": domain,
                "strategy": int(strat_match.group(1)),
                "line": raw_line.strip(),
            }
        )
    return events


def get_downshift_candidates(
    decision: Decision,
    strategies: list[Strategy] | None = None,
) -> list[Strategy]:
    """Return cheaper-tier strategies for periodic downshift probing if censorship weakened."""
    pool = strategies if strategies is not None else DEFAULT_STRATEGIES
    strat_map = {s.id: s for s in pool}

    if decision.layer == "vpn":
        current_tier = 4
    elif decision.layer == "dns":
        current_tier = 1
    elif decision.layer == "direct":
        current_tier = 0
    elif decision.strategy_id and decision.strategy_id in strat_map:
        current_tier = strat_map[decision.strategy_id].tier
    else:
        current_tier = 3

    candidates = [s for s in pool if s.protocol == decision.protocol and s.tier < current_tier]
    candidates.sort(key=lambda s: (s.tier, s.id))
    return candidates


async def _default_canary_probe(
    domain: str,
    timeout: float = 3.0,
    layer: str = "dpi",
    vpn_proxy_url: str | None = None,
) -> bool:
    if layer == "vpn":
        proxy_url = vpn_proxy_url
        if proxy_url is None:
            local_check = await probe_tcp("127.0.0.1", port=2080, timeout=min(timeout, 0.4))
            if local_check.result == "ok":
                proxy_url = "http://127.0.0.1:2080"
        if proxy_url:
            try:
                async with httpx.AsyncClient(proxy=proxy_url, timeout=timeout, follow_redirects=True) as client:
                    resp = await client.get(f"https://{domain}/")
                    return resp.status_code < 500
            except Exception:
                return False

    dns_res = await probe_dns(domain, timeout=timeout)
    ip = dns_res.doh_ips[0] if dns_res.doh_ips else (dns_res.system_ips[0] if dns_res.system_ips else None)
    if not ip:
        return False
    tcp_res = await probe_tcp(ip, port=443, timeout=timeout)
    if tcp_res.result != "ok":
        return False
    tls_res = await probe_tls(ip, real_sni=domain, port=443, timeout=timeout)
    return tls_res.real_sni == "ok"


async def run_canary_cycle(
    storage: Storage,
    domains: list[str] | None = None,
    network: NetworkFingerprint | None = None,
    probe_fn: Callable[[str], Awaitable[bool]] | None = None,
    winws2_log_path: str | Path = Path("logs") / "winws2.log",
    downshift_probe_fn: Callable[[str, Strategy], Awaitable[bool]] | None = None,
    vpn_proxy_url: str | None = None,
) -> dict[str, Any]:
    """Run one dynamic canary/revalidation cycle:
    1. Detect network fingerprint and upsert into storage.
    2. Identify expired decisions (TTL elapsed) and downshift opportunities.
    3. Inspect winws2.log for circular rotation events.
    4. Probe active decisions; on failure, re-verify once before promoting fallback/VPN.
    """
    net = network or await detect_network_fingerprint()
    net_key = storage.upsert_network(net)
    expired = get_due_decisions(storage, net)
    expired_keys = {(d.domain.lower(), d.protocol) for d in expired}
    active = storage.get_decisions(net_key, active_only=True)
    rotations = parse_circular_rotations(Path(winws2_log_path))

    target_filter = {d.lower() for d in domains} if domains else None

    checked: list[str] = []
    promoted: list[str] = []
    downshifted: list[str] = []
    downshift_candidates: dict[str, list[str]] = {}

    async def _run_probe(dec: Decision) -> bool:
        if probe_fn is not None:
            return await probe_fn(dec.domain)
        return await _default_canary_probe(dec.domain, layer=dec.layer, vpn_proxy_url=vpn_proxy_url)

    for decision in active:
        if target_filter is not None and decision.domain.lower() not in target_filter:
            continue
        checked.append(decision.domain)
        is_expired = (decision.domain.lower(), decision.protocol) in expired_keys
        cands: list[Strategy] = []
        if is_expired:
            cands = get_downshift_candidates(decision)
            if cands:
                downshift_candidates[decision.domain] = [c.id for c in cands[:2]]
        ok = await _run_probe(decision)
        if not ok:
            # Immediate confirmation retry to filter transient single-packet drops
            ok_retry = await _run_probe(decision)
            if not ok_retry:
                promote_fallback_on_failure(storage, decision)
                promoted.append(decision.domain)
                continue

        if is_expired:
            if downshift_probe_fn is not None and cands:
                for cand in cands:
                    if await downshift_probe_fn(decision.domain, cand):
                        old_strat = decision.strategy_id
                        decision.layer = "dpi"
                        decision.strategy_id = cand.id
                        if (
                            old_strat
                            and old_strat != "vpn-select"
                            and old_strat != cand.id
                            and old_strat not in decision.fallback_strategies
                        ):
                            decision.fallback_strategies = [old_strat, *decision.fallback_strategies[:1]]
                        downshifted.append(decision.domain)
                        break
            decision.updated_at = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
            decision.consecutive_fails = 0
            storage.save_decision(decision)

    return {
        "network_key": net_key,
        "checked": checked,
        "promoted": promoted,
        "expired": [d.domain for d in expired],
        "rotations": rotations,
        "downshift_candidates": downshift_candidates,
        "downshifted": downshifted,
    }
