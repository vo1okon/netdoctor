"""Strategy catalog loader and multi-tier strategy selector with success rate, throughput, and TTFB scoring."""

from __future__ import annotations

import asyncio
import os
import re
import subprocess
from pathlib import Path
from typing import Awaitable, Callable

import yaml

from netdoctor.config_gen import detect_physical_egress_iface, extract_blob_args
from netdoctor.models import Decision, Protocol, Strategy, VerdictClass
from netdoctor.probes import (
    detect_bypass_active,
    probe_quic,
    probe_stall,
    silence_proactor_connection_reset,
)
from netdoctor.supervisor import _is_admin


DEFAULT_STRATEGIES: list[Strategy] = [
    Strategy(
        id="tls_multisplit_pos2",
        family="multisplit",
        protocol=Protocol.TLS,
        tier=2,
        args_template=["--lua-desync=multisplit:pos=2"],
        description="Light TLS ClientHello split at byte 2",
    ),
    Strategy(
        id="tls_multisplit_sni",
        family="multisplit",
        protocol=Protocol.TLS,
        tier=2,
        args_template=["--lua-desync=multisplit:pos=midsld"],
        description="Light TLS ClientHello split at middle of SLD",
    ),
    Strategy(
        id="tls_fakedsplit_pos2",
        family="fakedsplit",
        protocol=Protocol.TLS,
        tier=2,
        args_template=["--lua-desync=fakedsplit:pos=2:tcp_ts=-600000:tcp_md5"],
        description="Light TLS fake + split at byte 2",
    ),
    Strategy(
        id="tls_fake_repeats6",
        family="fake",
        protocol=Protocol.TLS,
        tier=3,
        args_template=[
            "--lua-desync=fake:blob=fake_default_tls:repeats=6:tcp_ack=-66000:tcp_ts_up:ip_autottl=-1,3-20:ip6_autottl=-1,3-20"
        ],
        description="Heavy TLS fake ClientHello with 6 repeats",
    ),
    Strategy(
        id="tls_multidisorder_seqovl",
        family="multidisorder",
        protocol=Protocol.TLS,
        tier=3,
        args_template=["--lua-desync=multidisorder:pos=1,midsld:seqovl=5"],
        description="Heavy TLS disorder with sequence overlap",
    ),
    Strategy(
        id="quic_fake_repeats6",
        family="quic_fake",
        protocol=Protocol.QUIC,
        tier=2,
        args_template=["--lua-desync=fake:blob=fake_default_quic:repeats=6"],
        description="QUIC Initial fake packet injection (6 repeats)",
    ),
    Strategy(
        id="quic_fallback_tcp",
        family="quic_fallback",
        protocol=Protocol.QUIC,
        tier=3,
        args_template=[],
        description="Drop UDP/443 in sing-box so browser falls back to TCP/TLS",
    ),
    Strategy(
        id="tls_hostfakesplit_ozon",
        family="hostfakesplit",
        protocol=Protocol.TLS,
        tier=2,
        args_template=["--lua-desync=hostfakesplit:host=ozon.ru:tcp_ts=-600000:tcp_md5:repeats=4"],
        description="ALT9 TLS hostfakesplit impersonating ozon.ru with TCP MD5",
    ),
    Strategy(
        id="tls_hostfakesplit_google",
        family="hostfakesplit",
        protocol=Protocol.TLS,
        tier=2,
        args_template=["--lua-desync=hostfakesplit:host=www.google.com:tcp_ts=-600000:repeats=4:ip_id=zero"],
        description="ALT9 TLS hostfakesplit impersonating www.google.com",
    ),
    Strategy(
        id="tls_fakedsplit_autottl",
        family="fakedsplit",
        protocol=Protocol.TLS,
        tier=2,
        args_template=[
            "--lua-desync=fakedsplit:pos=1:repeats=10:tcp_ack=-66000:tcp_ts_up:ip_autottl=-1,3-20:ip6_autottl=-1,3-20"
        ],
        description="ALT9 Cloudflare fakedsplit with autottl and bad tcp_ack",
    ),
    Strategy(
        id="tls_alt9_youtube_video",
        family="fake_multisplit",
        protocol=Protocol.TLS,
        tier=3,
        args_template=[
            "--lua-desync=fake:blob=tls_google:tcp_ts=-600000:tcp_ts_up:ip_id=zero:repeats=8",
            "--lua-desync=multisplit:pos=1:seqovl=681:seqovl_pattern=tls_google:ip_id=zero",
        ],
        description="ALT9 YouTube video fake + seqovl multisplit with tls_google blob",
    ),
    Strategy(
        id="tls_alt9_discord",
        family="fake_multisplit",
        protocol=Protocol.TLS,
        tier=3,
        args_template=[
            "--lua-desync=fake:blob=fake_default_tls:tls_mod=rnd,dupsid,sni=www.google.com:tcp_ts=-600000:tcp_ts_up:repeats=8",
            "--lua-desync=multisplit:pos=1:seqovl=681:seqovl_pattern=tls_google",
        ],
        description="ALT9 Discord fake TLS SNI mod + seqovl multisplit",
    ),
    Strategy(
        id="quic_fake_google_autottl",
        family="quic_fake",
        protocol=Protocol.QUIC,
        tier=2,
        args_template=[
            "--lua-desync=fake:blob=quic_google:ip_autottl=-2,3-20:ip6_autottl=-2,3-20:repeats=10:payload=all"
        ],
        description="ALT9 QUIC fake using quic_google blob and autottl",
    ),
    # --- Expanded proven Zapret2 strategies (from C:\vso\Dev / Flowseal 1.9.9 & 1.10.3) ---
    Strategy(
        id="tls_alt1_199_fake_fakedsplit",
        family="fake_fakedsplit",
        protocol=Protocol.TLS,
        tier=2,
        args_template=[
            "--lua-desync=fake:blob=tls_google:tcp_ts=-600000:ip_id=zero:repeats=6",
            "--lua-desync=fakedsplit:pattern=0x00:tcp_ts=-600000:ip_id=zero:repeats=6",
        ],
        description="ALT1 1.9.9: fake tls_google + fakedsplit (проверенный пресет для YouTube/Discord)",
    ),
    Strategy(
        id="tls_alt1_1103_fake_fakedsplit",
        family="fake_fakedsplit",
        protocol=Protocol.TLS,
        tier=2,
        args_template=[
            "--lua-desync=fake:blob=tls_google:tcp_ts=-600000:tcp_ts_up:ip_id=zero:repeats=6",
            "--lua-desync=fakedsplit:pos=2:pattern=0x00:tcp_ts=-600000:tcp_ts_up:ip_id=zero:repeats=6",
        ],
        description="ALT1 1.10.3: fake tls_google + fakedsplit pos=2 с tcp_ts_up",
    ),
    Strategy(
        id="tls_general_1103_seqovl681",
        family="multisplit",
        protocol=Protocol.TLS,
        tier=2,
        args_template=[
            "--lua-desync=multisplit:pos=1:seqovl=681:seqovl_pattern=tls_google:ip_id=zero"
        ],
        description="general 1.10.3: multisplit seqovl=681 с паттерном tls_google (YouTube)",
    ),
    Strategy(
        id="tls_general_1103_seqovl568_4pda",
        family="multisplit",
        protocol=Protocol.TLS,
        tier=2,
        args_template=[
            "--lua-desync=multisplit:pos=1:seqovl=568:seqovl_pattern=tls_4pda"
        ],
        description="general 1.10.3: multisplit seqovl=568 с паттерном tls_4pda (Discord/общий)",
    ),
    Strategy(
        id="tls_fake_tls_auto_alt2_1103",
        family="fake_multisplit",
        protocol=Protocol.TLS,
        tier=2,
        args_template=[
            "--lua-desync=fake:blob=fake_default_tls:tls_mod=rnd,dupsid,sni=www.google.com:tcp_seq=10000000:tcp_ack=-66000:tcp_ts_up:ip_id=zero:repeats=8",
            "--lua-desync=multisplit:pos=1:seqovl=681:seqovl_pattern=tls_google:ip_id=zero",
        ],
        description="FAKE TLS AUTO ALT2 1.10.3: fake SNI + tcp_seq + multisplit seqovl 681",
    ),
    Strategy(
        id="tls_fake_tls_auto_11",
        family="fake_multidisorder",
        protocol=Protocol.TLS,
        tier=3,
        args_template=[
            "--lua-desync=fake:blob=0x00000000:repeats=11:tcp_ack=-66000:tcp_ts_up",
            "--lua-desync=fake:blob=fake_default_tls:tls_mod=rnd,dupsid,sni=www.google.com:repeats=11:tcp_ack=-66000:tcp_ts_up",
            "--lua-desync=multidisorder_legacy:pos=1,midsld:repeats=11",
        ],
        description="ALL TCP & UDP fake_tls_auto_11: двойной fake x11 + multidisorder_legacy",
    ),
    Strategy(
        id="tls_simple_fake_alt2_max",
        family="fake",
        protocol=Protocol.TLS,
        tier=2,
        args_template=[
            "--lua-desync=fake:blob=tls_max:tcp_ts=1:repeats=6"
        ],
        description="SIMPLE FAKE ALT2: лёгкий fake tls_max (tcp_ts=1, repeats=6)",
    ),
    Strategy(
        id="tls_simple_fake_badseq",
        family="fake",
        protocol=Protocol.TLS,
        tier=2,
        args_template=[
            "--lua-desync=fake:blob=fake_default_tls:repeats=6:tcp_ack=-66000:tcp_ts_up"
        ],
        description="SIMPLE FAKE: fake ClientHello с badseq (tcp_ack=-66000) и tcp_ts_up",
    ),
    Strategy(
        id="tls_rostelecom_multidisorder",
        family="multidisorder",
        protocol=Protocol.TLS,
        tier=2,
        args_template=[
            "--lua-desync=multidisorder:pos=1,host+2,sld+2,sld+5,sniext+1,sniext+2,endhost-2:seqovl=1"
        ],
        description="Ростелеком: сложная нарезка multidisorder вокруг SNI (7 позиций)",
    ),
    Strategy(
        id="tls_multisplit_complex",
        family="multisplit",
        protocol=Protocol.TLS,
        tier=2,
        args_template=[
            "--lua-desync=multisplit:pos=1,host+2,sld+2,sld+5,sniext+1,sniext+2,endhost-2:seqovl=1"
        ],
        description="Multisplit Complex: нарезка ClientHello по 7 позициям SNI",
    ),
    Strategy(
        id="tls_hostfakesplit_2gis",
        family="hostfakesplit",
        protocol=Protocol.TLS,
        tier=2,
        args_template=[
            "--lua-desync=hostfakesplit:host=2gis.ru:repeats=4:tcp_ts=-600000"
        ],
        description="ALT9 Discord: hostfakesplit с подменой SNI на 2gis.ru",
    ),
    Strategy(
        id="tls_hostfakesplit_ozon_ts1000",
        family="hostfakesplit",
        protocol=Protocol.TLS,
        tier=2,
        args_template=[
            "--lua-desync=hostfakesplit:host=ozon.ru:tcp_ts=-1000:tcp_md5:repeats=4"
        ],
        description="hostfakesplit ozon.ru с tcp_ts=-1000 и tcp_md5 (мессенджеры и веб)",
    ),
    Strategy(
        id="tls_syndata_multidisorder_legacy",
        family="syndata",
        protocol=Protocol.TLS,
        tier=3,
        args_template=[
            "--lua-desync=send:repeats=2",
            "--lua-desync=syndata:blob=tls_google",
            "--lua-desync=multidisorder_legacy:pos=2",
        ],
        description="Syndata + MultiDisorder legacy с паттерном tls_google",
    ),
    Strategy(
        id="tls_syndata_multisplit_seqovl",
        family="syndata",
        protocol=Protocol.TLS,
        tier=3,
        args_template=[
            "--lua-desync=send:repeats=2",
            "--lua-desync=syndata:blob=tls_google",
            "--lua-desync=multisplit:pos=1:seqovl=681:seqovl_pattern=tls_google",
        ],
        description="Syndata + MultiSplit seqovl=681 (tls_google)",
    ),
    Strategy(
        id="tls_censorliber_google_seqovl",
        family="fake",
        protocol=Protocol.TLS,
        tier=3,
        args_template=[
            "--lua-desync=fake:blob=tls_google:ip_autottl=-1,3-20:ip6_autottl=-1,3-20:repeats=6:tcp_ack=-66000:seqovl=680:seqovl_pattern=tls_google"
        ],
        description="Censorliber: fake tls_google + AutoTTL + TCP ACK + seqovl=680",
    ),
    Strategy(
        id="tls_censorliber_max_seqovl",
        family="fake",
        protocol=Protocol.TLS,
        tier=3,
        args_template=[
            "--lua-desync=fake:blob=tls_max:ip_autottl=-1,3-20:ip6_autottl=-1,3-20:repeats=6:tcp_ack=-66000:seqovl=680:seqovl_pattern=tls_max"
        ],
        description="Censorliber: fake tls_max + AutoTTL + TCP ACK + seqovl=680",
    ),
    Strategy(
        id="tls_fake_datanoack",
        family="fake",
        protocol=Protocol.TLS,
        tier=3,
        args_template=[
            "--lua-desync=fake:blob=fake_default_tls:tcp_flags_unset=ack:tls_mod=rnd,rndsni,padencap"
        ],
        description="Fake DataNoAck: сброс ACK-флага + рандомизация SNI и padencap",
    ),
    Strategy(
        id="tls_fakeddisorder_autottl",
        family="fakeddisorder",
        protocol=Protocol.TLS,
        tier=3,
        args_template=[
            "--lua-desync=fakeddisorder:pos=2,midsld-2:tcp_ack=-66000:ip_autottl=0,3-20:ip6_autottl=0,3-20"
        ],
        description="FakedDisorder AutoTTL: расщепление с обратным порядком и badseq",
    ),
    Strategy(
        id="tls_telegram_alt1_combo",
        family="fake_fakedsplit",
        protocol=Protocol.TLS,
        tier=3,
        args_template=[
            "--lua-desync=fake:blob=fake_stun_as_tls:tcp_ts=-600000:repeats=6",
            "--lua-desync=fake:blob=tls_google:tcp_ts=-600000:repeats=6",
            "--lua-desync=fakedsplit:pattern=0x00:tcp_ts=-600000:repeats=6",
            "--lua-desync=fake:blob=tls_max:tcp_ts=-600000:repeats=6",
        ],
        description="ALT1 Telegram / WhatsApp / Social комбо (STUN + Google + fakedsplit + Max)",
    ),
    Strategy(
        id="quic_fake_google_repeats6",
        family="quic_fake",
        protocol=Protocol.QUIC,
        tier=2,
        args_template=[
            "--lua-desync=fake:blob=quic_google:repeats=6:payload=all"
        ],
        description="ALT1 QUIC fake quic_google (6 повторов)",
    ),
    Strategy(
        id="quic_fake_google_repeats11",
        family="quic_fake",
        protocol=Protocol.QUIC,
        tier=2,
        args_template=[
            "--lua-desync=fake:blob=quic_google:repeats=11:payload=all"
        ],
        description="FAKE TLS AUTO ALT2 QUIC fake quic_google (11 повторов)",
    ),
    Strategy(
        id="quic_fake_autottl_repeats12",
        family="quic_fake",
        protocol=Protocol.QUIC,
        tier=2,
        args_template=[
            "--lua-desync=fake:blob=quic_google:repeats=12:ip_autottl=2,3-20:ip6_autottl=2,3-20:payload=all"
        ],
        description="QUIC fake quic_google AutoTTL (12 повторов)",
    ),
    Strategy(
        id="quic_fake_zero64",
        family="quic_fake",
        protocol=Protocol.QUIC,
        tier=3,
        args_template=[
            "--lua-desync=fake:blob=zero64:repeats=12:payload=all"
        ],
        description="QUIC fake zero64 (12 повторов для сложных UDP-блокировок)",
    ),
    Strategy(
        id="quic_fake_ttl0_badsum",
        family="quic_fake",
        protocol=Protocol.QUIC,
        tier=3,
        args_template=[
            "--lua-desync=fake:blob=quic_google:repeats=15:ip_ttl=0:ip6_ttl=0:badsum:payload=all"
        ],
        description="QUIC fake TTL=0 + badsum (15 повторов)",
    ),
    # --- Flowseal 1.10.4 & Zapret2 v1.0.7 modern strategies ---
    Strategy(
        id="tls_alt12_1104_sferum_seqovl",
        family="fake_multisplit",
        protocol=Protocol.TLS,
        tier=2,
        args_template=[
            "--lua-desync=fake:blob=stun_pat:tcp_ts=-600000:repeats=8",
            "--lua-desync=fake:blob=tls_sferum:tcp_ts=-600000:repeats=8",
            "--lua-desync=multisplit:pos=1:seqovl=664:seqovl_pattern=tls_sferum",
        ],
        description="ALT12 1.10.4: двойной fake (STUN + Sferum) + multisplit seqovl=664",
    ),
    Strategy(
        id="tls_alt13_1104_sochi_hostfakesplit",
        family="fake_hostfakesplit",
        protocol=Protocol.TLS,
        tier=2,
        args_template=[
            "--lua-desync=fake:blob=tls_sochi:tcp_ts=-600000:repeats=5",
            "--lua-desync=fake:blob=stun2:tcp_ts=-600000:repeats=5",
            "--lua-desync=hostfakesplit:host=mail.ru:altorder=1:tcp_ts=-600000:repeats=5",
        ],
        description="ALT13 1.10.4: двойной fake (Sochi + STUN2) + hostfakesplit mail.ru altorder=1",
    ),
    Strategy(
        id="tls_exp_1104_hostfakesplit_google",
        family="hostfakesplit",
        protocol=Protocol.TLS,
        tier=2,
        args_template=[
            "--lua-desync=hostfakesplit:host=www.google.com:tcp_ts=-600000:ip_id=zero"
        ],
        description="EXP 1.10.4: hostfakesplit www.google.com с tcp_ts и ip_id=zero",
    ),
    Strategy(
        id="tls_fakedsplit_vk_kyber",
        family="fake_fakedsplit",
        protocol=Protocol.TLS,
        tier=2,
        args_template=[
            "--lua-desync=fake:blob=tls_vk_kyber:tcp_ts=-600000:ip_id=zero:repeats=6",
            "--lua-desync=fakedsplit:pos=2:pattern=0x00:tcp_ts=-600000:ip_id=zero:repeats=6",
        ],
        description="Kyber: fake tls_vk_kyber + fakedsplit pos=2 (для постквантового TLS)",
    ),
    Strategy(
        id="tls_clone_multisplit_sni",
        family="multisplit",
        protocol=Protocol.TLS,
        tier=2,
        args_template=[
            "--lua-desync=tls_client_hello_clone",
            "--lua-desync=multisplit:pos=1,midsld",
        ],
        description="Zapret2 v1.0.7: tls_client_hello_clone + multisplit по midsld",
    ),
    Strategy(
        id="tls_oob_multisplit_pos2",
        family="oob",
        protocol=Protocol.TLS,
        tier=3,
        args_template=[
            "--lua-desync=oob:pos=2",
        ],
        description="Zapret2 v1.0.7: TCP OOB urgent byte на pos=2",
    ),
    Strategy(
        id="tls_tcpseg_sni",
        family="tcpseg",
        protocol=Protocol.TLS,
        tier=2,
        args_template=[
            "--lua-desync=tcpseg:pos=0,midsld",
        ],
        description="Zapret2 v1.0.7: TCP сегментация ClientHello без overlap (tcpseg)",
    ),
    Strategy(
        id="quic_fake_rutube_repeats8",
        family="quic_fake",
        protocol=Protocol.QUIC,
        tier=2,
        args_template=[
            "--lua-desync=fake:blob=quic_rutube:repeats=8:payload=all"
        ],
        description="QUIC fake под Rutube Initial (8 повторов)",
    ),
    Strategy(
        id="quic_fake_5ka_repeats8",
        family="quic_fake",
        protocol=Protocol.QUIC,
        tier=2,
        args_template=[
            "--lua-desync=fake:blob=quic_5ka:repeats=8:payload=all"
        ],
        description="QUIC fake под 5ka Initial (8 повторов)",
    ),
]


def load_strategies_from_yaml(path: str | Path) -> list[Strategy]:
    p = Path(path)
    if not p.exists():
        return list(DEFAULT_STRATEGIES)
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    items = data.get("strategies") or []
    return [Strategy(**item) for item in items]


_REPO_ROOT = Path(__file__).resolve().parents[2]
_TARGETS_YAML_CACHE: dict[str, tuple[tuple[int, int], list[dict[str, str]]]] = {}


def load_targets_from_yaml(path: str | Path = "configs/targets.yaml") -> list[dict[str, str]]:
    """Load target domains and test_url entries from targets.yaml with mtime caching."""
    p = Path(path)
    if not p.exists() and str(path).replace("\\", "/") == "configs/targets.yaml":
        fallback = _REPO_ROOT / "configs" / "targets.yaml"
        if fallback.exists():
            p = fallback
    if not p.exists():
        return []
    key = str(p.resolve())
    try:
        st = p.stat()
        sig = (st.st_mtime_ns, st.st_size)
    except OSError:
        sig = None
    if sig is not None:
        cached = _TARGETS_YAML_CACHE.get(key)
        if cached is not None and cached[0] == sig:
            return [dict(item) for item in cached[1]]
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    items = data.get("targets") or []
    parsed = [
        {"domain": str(item["domain"]), "test_url": str(item.get("test_url") or f"https://{item['domain']}/")}
        for item in items
        if isinstance(item, dict) and item.get("domain")
    ]
    if sig is not None:
        if len(_TARGETS_YAML_CACHE) > 16:
            _TARGETS_YAML_CACHE.clear()
        _TARGETS_YAML_CACHE[key] = (sig, [dict(item) for item in parsed])
    return parsed


class CandidateEvaluation:
    def __init__(
        self,
        strategy: Strategy,
        success_rate: float,
        throughput_kbps: float,
        ttfb_ms: float,
    ) -> None:
        self.strategy = strategy
        self.success_rate = success_rate
        self.throughput_kbps = throughput_kbps
        self.ttfb_ms = ttfb_ms


async def default_strategy_evaluator(
    domain: str,
    ip: str,
    strategy: Strategy,
    port: int = 443,
    repeats: int = 1,
    timeout: float = 1.8,
) -> CandidateEvaluation:
    """Evaluate a candidate strategy by running real data transfer probes and measuring success rate, throughput, and TTFB."""
    successes = 0
    total_kbps = 0.0
    total_ttfb = 0.0

    for _ in range(repeats):
        if strategy.protocol == Protocol.QUIC:
            if strategy.id == "quic_fallback_tcp":
                successes += 1
                total_kbps += 1000.0
                total_ttfb += 50.0
            else:
                qres = await probe_quic(ip, sni=domain, port=port, timeout=min(timeout, 1.5))
                if qres.result == "ok":
                    successes += 1
                    total_kbps += 2000.0
                    total_ttfb += qres.rtt_ms or 50.0
        else:
            sres = await probe_stall(ip, sni=domain, port=port, timeout=timeout)
            if sres.result == "ok":
                successes += 1
                total_kbps += sres.throughput_kbps or 500.0
                total_ttfb += 60.0

    rate = successes / max(repeats, 1)
    avg_kbps = round(total_kbps / max(successes, 1), 2) if successes else 0.0
    avg_ttfb = round(total_ttfb / max(successes, 1), 2) if successes else 9999.0
    return CandidateEvaluation(
        strategy=strategy,
        success_rate=rate,
        throughput_kbps=avg_kbps,
        ttfb_ms=avg_ttfb,
    )


def _expand_winws2_domains(domains: list[str]) -> str:
    expanded: list[str] = []
    seen: set[str] = set()
    for dom in domains:
        candidates = [dom]
        if not dom.startswith("www."):
            candidates.append(f"www.{dom}")
        if "youtube.com" in dom:
            candidates.append("googlevideo.com")
        for c in candidates:
            if c not in seen:
                seen.add(c)
                expanded.append(c)
    return ",".join(expanded)


def _build_winws2_eval_cmd(
    winws2_exe: Path,
    strategy: Strategy,
    domains_arg: str,
    iface: int | None = None,
) -> list[str]:
    cmd: list[str] = [
        str(winws2_exe),
        "--lua-init=@lua/zapret-lib.lua",
        "--lua-init=@lua/zapret-antidpi.lua",
        "--lua-init=@lua/zapret-auto.lua",
        *extract_blob_args(strategy.args_template),
        "--ctrack-disable=0",
        "--wf-tcp-out=80,443",
        "--wf-udp-out=443",
    ]
    if iface is not None:
        cmd.append(f"--wf-iface={iface}")

    uses_syndata = any("syndata" in tok for tok in strategy.args_template)
    has_payload = any(tok.startswith("--payload=") for tok in strategy.args_template)

    if strategy.protocol == Protocol.QUIC:
        cmd.extend(["--filter-udp=443", "--filter-l7=quic", f"--hostlist-domains={domains_arg}"])
    elif strategy.protocol == Protocol.HTTP:
        cmd.extend(["--filter-tcp=80", "--filter-l7=http", f"--hostlist-domains={domains_arg}"])
    else:
        cmd.extend(
            [
                "--filter-tcp=443",
                "--filter-l7=tls",
                f"--hostlist-domains={domains_arg}",
            ]
        )
        if not has_payload:
            cmd.append("--payload=all" if uses_syndata else "--payload=tls_client_hello")
    cmd.extend(strategy.args_template)
    return cmd


async def live_winws2_strategy_evaluator(
    domain: str,
    ip: str,
    strategy: Strategy,
    port: int = 443,
    repeats: int = 1,
    bin_dir: str | Path = "bin",
    iface: int | None = None,
) -> CandidateEvaluation:
    """Evaluate a candidate strategy by spawning an isolated single-domain winws2 process when elevated.

    Falls back to `default_strategy_evaluator` if running non-elevated, missing winws2.exe, or for sing-box fallback.
    """
    bin_path = Path(bin_dir).resolve()
    winws2_exe = bin_path / "winws2.exe"
    if strategy.id == "quic_fallback_tcp" or not _is_admin() or not winws2_exe.is_file():
        return await default_strategy_evaluator(domain, ip, strategy, port=port, repeats=repeats)

    silence_proactor_connection_reset()
    effective_iface = iface if iface is not None else detect_physical_egress_iface()
    cmd = _build_winws2_eval_cmd(winws2_exe, strategy, _expand_winws2_domains([domain]), iface=effective_iface)

    proc = subprocess.Popen(
        cmd,
        cwd=str(bin_path),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    try:
        await asyncio.sleep(0.25)
        if proc.poll() is not None:
            return CandidateEvaluation(strategy, 0.0, 0.0, 9999.0)
        return await default_strategy_evaluator(domain, ip, strategy, port=port, repeats=repeats)
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                proc.kill()


_BLOCKCHECK_TOKEN_RE = re.compile(r"--lua-desync=[^\s\"']+")


def parse_blockcheck2_output(raw_output: str, protocol: Protocol = Protocol.TLS) -> list[Strategy]:
    """Parse blockcheck2 output lines and extract unique candidate Strategy objects."""
    discovered: list[Strategy] = []
    seen_templates: set[tuple[str, ...]] = set()
    idx = 0
    for line in raw_output.splitlines():
        if line.lstrip().startswith("- "):
            continue
        tokens = _BLOCKCHECK_TOKEN_RE.findall(line)
        if not tokens:
            continue
        key = tuple(tokens)
        if key in seen_templates:
            continue
        seen_templates.add(key)
        idx += 1
        first_body = tokens[0][len("--lua-desync=") :]
        family = first_body.split(":", 1)[0] or "desync"
        discovered.append(
            Strategy(
                id=f"bc2_{protocol.value}_{idx}",
                family=family,
                protocol=protocol,
                tier=2,
                args_template=list(tokens),
                description=f"Discovered by blockcheck2 ({family})",
            )
        )
    return discovered


async def run_blockcheck2_for_domain(
    domain: str,
    bin_dir: str | Path = "bin",
    timeout: float = 25.0,
) -> list[Strategy]:
    """Run blockcheck2 non-interactively for a domain when elevated and binaries exist, returning [] otherwise."""
    clean_domain = (domain or "").strip()
    if not clean_domain or not _is_admin():
        return []

    bin_path = Path(bin_dir).resolve()
    bc_dir = bin_path / "blockcheck"
    bc_sh = bc_dir / "zapret2" / "blockcheck2.sh"
    bc_cmd = bc_dir / "blockcheck2.cmd"
    bash_exe = bin_path / "cygwin" / "bin" / "bash.exe"

    if bash_exe.is_file() and bc_sh.is_file():
        cmd = [str(bash_exe), str(bc_sh.name)]
        cwd = bc_sh.parent
    elif bc_cmd.is_file():
        cmd = ["cmd.exe", "/c", str(bc_cmd)]
        cwd = bc_dir
    else:
        return []

    env = os.environ.copy()
    cygwin_bin = bin_path / "cygwin" / "bin"
    if cygwin_bin.is_dir():
        env["PATH"] = f"{cygwin_bin}{os.pathsep}{env.get('PATH', '')}"
    env.update(
        {
            "BATCH": "1",
            "DOMAINS": clean_domain,
            "IPVS": "4",
            "ENABLE_HTTP": "0",
            "ENABLE_HTTPS_TLS12": "1",
            "ENABLE_HTTPS_TLS13": "1",
            "ENABLE_HTTP3": "0",
            "REPEATS": "1",
            "SCANLEVEL": "quick",
            "SKIP_DNSCHECK": "1",
            "SKIP_IPBLOCK": "1",
        }
    )

    def _run_sync() -> str:
        proc = subprocess.Popen(
            cmd,
            cwd=str(cwd),
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        try:
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, err = proc.communicate()
        return f"{out or ''}\n{err or ''}"

    try:
        raw_output = await asyncio.to_thread(_run_sync)
        return parse_blockcheck2_output(raw_output, protocol=Protocol.TLS)
    except Exception:
        return []


_PRIORITY_ORDER: dict[str, int] = {
    "tls_alt1_199_fake_fakedsplit": 0,
    "tls_alt12_1104_sferum_seqovl": 1,
    "tls_alt13_1104_sochi_hostfakesplit": 2,
    "tls_alt1_1103_fake_fakedsplit": 3,
    "tls_exp_1104_hostfakesplit_google": 4,
    "tls_fakedsplit_vk_kyber": 5,
    "tls_fake_tls_auto_alt2_1103": 6,
    "tls_general_1103_seqovl681": 7,
    "tls_clone_multisplit_sni": 8,
    "tls_hostfakesplit_ozon": 9,
    "tls_hostfakesplit_google": 10,
    "tls_fakedsplit_autottl": 11,
    "tls_rostelecom_multidisorder": 12,
    "tls_general_1103_seqovl568_4pda": 13,
    "tls_simple_fake_alt2_max": 14,
    "tls_hostfakesplit_2gis": 15,
    "tls_multisplit_pos2": 16,
    "tls_fakedsplit_pos2": 17,
    "tls_multisplit_sni": 18,
    "tls_tcpseg_sni": 19,
    "tls_simple_fake_badseq": 20,
    "tls_multisplit_complex": 21,
    "tls_hostfakesplit_ozon_ts1000": 22,
    "tls_alt9_youtube_video": 23,
    "tls_alt9_discord": 24,
    "tls_fake_tls_auto_11": 25,
    "tls_telegram_alt1_combo": 26,
    "tls_syndata_multidisorder_legacy": 27,
    "tls_syndata_multisplit_seqovl": 28,
    "tls_censorliber_google_seqovl": 29,
    "tls_censorliber_max_seqovl": 30,
    "tls_oob_multisplit_pos2": 31,
    "quic_fake_google_repeats6": 0,
    "quic_fake_google_autottl": 1,
    "quic_fake_rutube_repeats8": 2,
    "quic_fake_5ka_repeats8": 3,
    "quic_fake_google_repeats11": 4,
    "quic_fake_repeats6": 5,
    "quic_fake_autottl_repeats12": 6,
}


def _ordered_pool(candidates: list[Strategy] | None, protocol: Protocol) -> list[Strategy]:
    pool = [s for s in (candidates or DEFAULT_STRATEGIES) if s.protocol == protocol]
    pool.sort(key=lambda s: (s.tier, _PRIORITY_ORDER.get(s.id, 50), s.id))
    return pool


def _quick_non_dpi_decision(
    network_key: str,
    domain: str,
    verdicts: list[VerdictClass],
    protocol: Protocol,
) -> Decision | None:
    effective = [v for v in verdicts if v != VerdictClass.QUIC_BLOCK] if protocol == Protocol.TLS else list(verdicts)
    if not effective or effective == [VerdictClass.OK]:
        # CRITICAL: If ONLY QUIC failed (most regular HTTPS hosts do not answer UDP/443),
        # do NOT assign a TLS DPI rule to normal HTTPS traffic!
        return Decision(
            network_key=network_key,
            domain=domain,
            protocol=protocol,
            layer="direct",
            strategy_id=None,
        )
    if VerdictClass.UNKNOWN in effective:
        return Decision(
            network_key=network_key,
            domain=domain,
            protocol=protocol,
            layer="direct",
            strategy_id=None,
            status="degraded",
        )
    if VerdictClass.IP_BLOCK in effective or VerdictClass.PROTOCOL_BLOCK in effective:
        return Decision(
            network_key=network_key,
            domain=domain,
            protocol=protocol,
            layer="vpn",
            strategy_id="vpn-select",
        )
    if effective == [VerdictClass.DNS_POISON]:
        return Decision(
            network_key=network_key,
            domain=domain,
            protocol=protocol,
            layer="dns",
            strategy_id="doh",
        )
    return None


async def evaluate_domains_live_batch(
    domains_info: list[tuple[str, str, list[VerdictClass]]],
    network_key: str,
    candidates: list[Strategy] | None = None,
    bin_dir: str | Path = "bin",
    use_live_eval: bool = True,
    iface: int | None = None,
    min_success_rate: float = 0.5,
) -> dict[str, Decision]:
    """Evaluate a batch of TLS domains concurrently, sharing one winws2.exe process per candidate strategy."""
    decisions: dict[str, Decision] = {}
    unresolved: dict[str, tuple[str, list[VerdictClass]]] = {}

    for dom, ip, verdicts in domains_info:
        quick = _quick_non_dpi_decision(network_key, dom, verdicts, Protocol.TLS)
        if quick is not None:
            decisions[dom] = quick
        else:
            unresolved[dom] = (ip, verdicts)

    pool = _ordered_pool(candidates, Protocol.TLS)
    bin_path = Path(bin_dir).resolve()
    winws2_exe = bin_path / "winws2.exe"

    if (
        unresolved
        and pool
        and use_live_eval
        and _is_admin()
        and winws2_exe.is_file()
        and not detect_bypass_active()
    ):
        silence_proactor_connection_reset()
        effective_iface = iface if iface is not None else detect_physical_egress_iface()
        for strat in pool:
            if not unresolved:
                break
            domains_list = list(unresolved.keys())
            cmd = _build_winws2_eval_cmd(
                winws2_exe,
                strat,
                _expand_winws2_domains(domains_list),
                iface=effective_iface,
            )
            proc = subprocess.Popen(
                cmd,
                cwd=str(bin_path),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            try:
                await asyncio.sleep(0.25)
                if proc.poll() is not None:
                    continue
                evals = await asyncio.gather(
                    *(
                        default_strategy_evaluator(dom, unresolved[dom][0], strat, repeats=1, timeout=1.8)
                        for dom in domains_list
                    )
                )
            finally:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=2.0)
                    except subprocess.TimeoutExpired:
                        proc.kill()

            for dom, ev in zip(domains_list, evals):
                if ev.success_rate >= min_success_rate:
                    fallbacks = [s.id for s in pool if s.id != strat.id][:2]
                    decisions[dom] = Decision(
                        network_key=network_key,
                        domain=dom,
                        protocol=Protocol.TLS,
                        layer="dpi",
                        strategy_id=strat.id,
                        fallback_strategies=fallbacks,
                        ttfb_ms=ev.ttfb_ms,
                        throughput_kbps=ev.throughput_kbps,
                    )
                    unresolved.pop(dom, None)

        # Any domain that genuinely failed every tested live strategy escalates to VPN
        for dom in list(unresolved.keys()):
            decisions[dom] = Decision(
                network_key=network_key,
                domain=dom,
                protocol=Protocol.TLS,
                layer="vpn",
                strategy_id="vpn-select",
            )
            unresolved.pop(dom, None)

    for dom in unresolved:
        if pool:
            winner_strat = pool[0]
            fallback_ids = [s.id for s in pool[1:3]]
            decisions[dom] = Decision(
                network_key=network_key,
                domain=dom,
                protocol=Protocol.TLS,
                layer="dpi",
                strategy_id=winner_strat.id,
                fallback_strategies=fallback_ids,
            )
        else:
            decisions[dom] = Decision(
                network_key=network_key,
                domain=dom,
                protocol=Protocol.TLS,
                layer="vpn",
                strategy_id="vpn-select",
            )

    return decisions


async def select_best_strategy(
    network_key: str,
    domain: str,
    ip: str,
    verdicts: list[VerdictClass],
    candidates: list[Strategy] | None = None,
    protocol: Protocol = Protocol.TLS,
    min_success_rate: float = 0.5,
    evaluator: Callable[[str, str, Strategy], Awaitable[CandidateEvaluation]] | None = None,
    early_stop: bool = False,
) -> Decision:
    """Iterate through candidate strategies from cheapest tier to heaviest, picking the lightest tier above threshold,
    tie-breaking by highest throughput_kbps and then lowest ttfb_ms. Saves winner + up to 2 fallback strategies.
    """
    quick = _quick_non_dpi_decision(network_key, domain, verdicts, protocol)
    if quick is not None:
        return quick

    pool = _ordered_pool(candidates, protocol)
    dpi_treatable = (
        VerdictClass.SNI_DPI in verdicts
        or VerdictClass.THROTTLE in verdicts
        or (protocol == Protocol.QUIC and VerdictClass.QUIC_BLOCK in verdicts)
    )
    if evaluator is None and dpi_treatable and pool:
        # Without a live winws2 evaluator, default_strategy_evaluator cannot vary bypass state between strategies.
        winner_strat = pool[0]
        return Decision(
            network_key=network_key,
            domain=domain,
            protocol=protocol,
            layer="dpi",
            strategy_id=winner_strat.id,
            fallback_strategies=[s.id for s in pool[1:3]],
        )

    eval_fn = evaluator or (lambda d, i, s: default_strategy_evaluator(d, i, s))
    passing: list[CandidateEvaluation] = []

    for strat in pool:
        res = await eval_fn(domain, ip, strat)
        if res.success_rate >= min_success_rate:
            passing.append(res)
            if early_stop:
                break

    if not passing:
        if dpi_treatable and pool and evaluator is None and (not _is_admin() or detect_bypass_active()):
            winner_strat = pool[0]
            return Decision(
                network_key=network_key,
                domain=domain,
                protocol=protocol,
                layer="dpi",
                strategy_id=winner_strat.id,
                fallback_strategies=[s.id for s in pool[1:3]],
            )

        # Escalate to Tier 4 (VPN outbound) if live DPI strategies all failed or verdict is non-DPI
        return Decision(
            network_key=network_key,
            domain=domain,
            protocol=protocol,
            layer="vpn",
            strategy_id="vpn-select",
        )

    # Sort by: 1) lowest tier, 2) highest throughput_kbps, 3) lowest ttfb_ms
    passing.sort(
        key=lambda e: (e.strategy.tier, -e.throughput_kbps, e.ttfb_ms)
    )
    winner = passing[0]
    fallbacks = [e.strategy.id for e in passing[1:3]]
    if early_stop and len(fallbacks) < 2:
        for cand in pool:
            if cand.id != winner.strategy.id and cand.id not in fallbacks:
                fallbacks.append(cand.id)
            if len(fallbacks) >= 2:
                break

    return Decision(
        network_key=network_key,
        domain=domain,
        protocol=protocol,
        layer="dpi",
        strategy_id=winner.strategy.id,
        fallback_strategies=fallbacks,
        ttfb_ms=winner.ttfb_ms,
        throughput_kbps=winner.throughput_kbps,
    )
