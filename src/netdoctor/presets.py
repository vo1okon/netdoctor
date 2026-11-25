"""Zapret2 preset library, .txt/.bat importer, and winws2 compatibility compiler."""

from __future__ import annotations

import hashlib
import re
import shlex
import time
from pathlib import Path
from typing import Any

from netdoctor.config_gen import (
    KNOWN_BLOBS,
    TELEGRAM_CIDRS,
    extract_blob_args,
    resolve_vpn_ips,
)
from netdoctor.storage import Storage

_REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ZAPRET2_PRESETS_DIR = (
    (_REPO_ROOT / "presets" / "zapret2")
    if (_REPO_ROOT / "presets" / "zapret2").is_dir()
    else (Path("presets") / "zapret2")
)
DEFAULT_ZDY_PRESETS_DIR = (
    (_REPO_ROOT / "presets" / "zapret-discord-youtube")
    if (_REPO_ROOT / "presets" / "zapret-discord-youtube").is_dir()
    else (Path("presets") / "zapret-discord-youtube")
)
DEFAULT_EXTERNAL_ZAPRET_DIRS: tuple[Path, ...] = (
    Path(r"C:\vso\Dev\presets\winws2"),
    Path(r"C:\vso\Dev\presets\winws2_builtin"),
)

# Recommended priority order for well-known proven presets imported from Zapret2
_FEATURED_PRESET_PRIORITY: dict[str, int] = {
    "general ALT1 1.9.9 (game filter)": 0,
    "general FAKE TLS AUTO ALT2 1.10.3 (game filter)": 1,
    "general ALT9 1.9.9 (game filter)": 2,
    "general ALT1 1.10.3 (game filter)": 3,
    "general 1.10.3 (game filter)": 4,
    "general ALT11 1.10.3 (game filter)": 5,
    "general FAKE TLS AUTO 1.10.3 (game filter)": 6,
    "general SIMPLE FAKE ALT2 1.10.3 (game filter)": 7,
    "ALL TCP & UDP fake_tls_auto_11": 8,
    "ALL TCP & UDP hostfakesplit": 9,
    "Ростелеком": 10,
    "Default (circular)": 11,
    "Universal V5": 12,
}

_PRESET_HEADER_RE = re.compile(r"^#\s*(Preset|Description|BuiltinVersion)\s*:\s*(.+)$", re.IGNORECASE)
_ZDY_BAT_WINWS_RE = re.compile(r'winws2?\.exe"?\s+(.*)$', re.IGNORECASE | re.DOTALL)
_LUA_FUNC_DEF_RE = re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_BUILTIN_PRESETS_CACHE: dict[tuple[Any, ...], list[dict[str, Any]]] = {}


def clear_builtin_presets_cache() -> None:
    """Clear the mtime-keyed cache of built-in Zapret2/.bat presets."""
    _BUILTIN_PRESETS_CACHE.clear()


def slugify_preset_id(name: str, prefix: str = "preset") -> str:
    """Create a deterministic, ASCII/safe identifier from a preset name."""
    raw = re.sub(r"[^a-zA-Z0-9а-яА-ЯёЁ._-]+", "_", (name or "").strip()).strip("_")
    ascii_only = re.sub(r"[^a-zA-Z0-9_-]+", "_", raw).strip("_").lower()
    if ascii_only:
        return f"{prefix}_{ascii_only[:48]}"
    digest = hashlib.sha1((name or "custom").encode("utf-8")).hexdigest()[:10]
    return f"{prefix}_{digest}"


def parse_preset_metadata(content: str, fallback_name: str = "") -> dict[str, str]:
    """Extract `# Preset:` and `# Description:` comments from a Zapret2 preset file."""
    name = fallback_name.strip()
    description = ""
    version = ""
    for line in (content or "").splitlines()[:20]:
        stripped = line.strip()
        if not stripped:
            continue
        if not stripped.startswith("#"):
            break
        m = _PRESET_HEADER_RE.match(stripped)
        if m:
            key = m.group(1).lower()
            val = m.group(2).strip()
            if key == "preset" and val:
                name = val
            elif key == "description" and val:
                description = val
            elif key == "builtinversion" and val:
                version = val
    return {
        "name": name or "Пользовательский пресет",
        "description": description,
        "version": version,
    }


def _map_zdy_blob_name(raw_val: str, *, is_udp: bool = False) -> str:
    val = Path(raw_val.strip().strip('"')).name.lower()
    if raw_val.strip().lower().startswith("0x"):
        return raw_val.strip()
    if "sferum" in val:
        return "tls_sferum"
    if "sochi_park" in val:
        return "tls_sochi"
    if "5ka" in val:
        return "quic_5ka" if is_udp else "tls_5ka"
    if "awswaf" in val:
        return "tls_awswaf"
    if "steam_chat" in val:
        return "tls_steam_chat"
    if "steamstatic" in val:
        return "tls_steam"
    if "teamspeak" in val:
        return "tls_teamspeak"
    if "vk_com_kyber" in val:
        return "tls_vk_kyber"
    if "vk_com" in val:
        return "quic_vk" if is_udp else "tls_vk"
    if "sberbank" in val:
        return "tls_sber_v2" if "v2" in val else "tls_sber"
    if "stun2" in val:
        return "stun2"
    if "stun" in val:
        return "stun_pat"
    if "rutube" in val:
        return "quic_rutube"
    if "lemana" in val:
        return "quic_lemana"
    if "active_discord_udp" in val:
        return "discord_active"
    if "active_game_udp" in val:
        return "game_active"
    if "google" in val:
        return "quic_google" if is_udp else "tls_google"
    if "max" in val:
        return "tls_max"
    if "4pda" in val:
        return "quic_4pda" if is_udp else "tls_4pda"
    return "fake_default_quic" if is_udp else "fake_default_tls"


def _convert_zapret1_profile_to_winws2(tokens: list[str]) -> list[str]:
    """Best-effort converter translating zapret1 `--dpi-desync=...` profile flags to winws2 `--lua-desync=...`."""
    out: list[str] = []
    desync_modes: list[str] = []
    repeats = "6"
    split_pos = "2"
    seqovl = ""
    seqovl_pattern = ""
    fooling: list[str] = []
    autottl = ""
    ttl = ""
    fake_tls_list: list[str] = []
    fake_quic_list: list[str] = []
    fake_tls_mod = ""
    badseq_inc = ""
    hostfakesplit_mods: list[str] = []
    ip_id_zero = False

    for tok in tokens:
        if tok.startswith("--dpi-desync="):
            desync_modes = [p.strip() for p in tok.split("=", 1)[1].split(",") if p.strip()]
        elif tok.startswith("--dpi-desync-repeats="):
            repeats = tok.split("=", 1)[1].strip()
        elif tok.startswith("--dpi-desync-split-pos="):
            split_pos = tok.split("=", 1)[1].strip()
        elif tok.startswith("--dpi-desync-split-seqovl="):
            seqovl = tok.split("=", 1)[1].strip()
        elif tok.startswith("--dpi-desync-split-seqovl-pattern="):
            seqovl_pattern = _map_zdy_blob_name(tok.split("=", 1)[1], is_udp=False)
        elif tok.startswith("--dpi-desync-fooling="):
            fooling = [p.strip() for p in tok.split("=", 1)[1].split(",") if p.strip()]
        elif tok.startswith("--dpi-desync-autottl="):
            autottl = tok.split("=", 1)[1].strip()
        elif tok.startswith("--dpi-desync-ttl="):
            ttl = tok.split("=", 1)[1].strip()
        elif tok.startswith("--dpi-desync-fake-tls="):
            mapped = _map_zdy_blob_name(tok.split("=", 1)[1], is_udp=False)
            if mapped not in fake_tls_list:
                fake_tls_list.append(mapped)
        elif tok.startswith(("--dpi-desync-fake-quic=", "--dpi-desync-fake-discord=", "--dpi-desync-fake-unknown-udp=")):
            mapped = _map_zdy_blob_name(tok.split("=", 1)[1], is_udp=True)
            if mapped not in fake_quic_list:
                fake_quic_list.append(mapped)
        elif tok.startswith("--dpi-desync-fake-tls-mod="):
            fake_tls_mod = tok.split("=", 1)[1].strip()
        elif tok.startswith("--dpi-desync-badseq-increment="):
            badseq_inc = tok.split("=", 1)[1].strip()
        elif tok.startswith("--dpi-desync-hostfakesplit-mod="):
            hostfakesplit_mods = [p.strip() for p in tok.split("=", 1)[1].split(",") if p.strip()]
        elif tok == "--ip-id=zero":
            ip_id_zero = True
        elif tok.startswith("--dpi-desync"):
            continue
        elif tok.startswith(("--filter-", "--hostlist", "--ipset", "--wf-", "--payload=")):
            out.append(tok)

    if not desync_modes:
        return out

    fool_parts: list[str] = []
    if "ts" in fooling:
        fool_parts.append("tcp_ts=-600000")
    if "badseq" in fooling:
        ack_val = f"-{badseq_inc}" if badseq_inc and not badseq_inc.startswith("-") else (badseq_inc or "-66000")
        fool_parts.append(f"tcp_ack={ack_val}")
    if "md5sig" in fooling:
        fool_parts.append("tcp_md5")
    if "badsum" in fooling:
        fool_parts.append("badsum")
    if "datanoack" in fooling:
        fool_parts.append("tcp_flags_unset=ack")
    if autottl:
        fool_parts.append(f"ip_autottl={autottl}")
        fool_parts.append(f"ip6_autottl={autottl}")
    elif ttl:
        fool_parts.append(f"ip_ttl={ttl}")
        fool_parts.append(f"ip6_ttl={ttl}")
    if ip_id_zero:
        fool_parts.append("ip_id=zero")

    is_udp = any(t.startswith("--filter-udp=") or t == "--filter-l7=quic" for t in out)

    for mode in desync_modes:
        if mode == "fake":
            blobs = fake_quic_list if is_udp else fake_tls_list
            if not blobs:
                blobs = ["fake_default_quic" if is_udp else "fake_default_tls"]
            for blob in blobs:
                parts = [f"fake:blob={blob}", f"repeats={repeats}"]
                if fake_tls_mod and not is_udp:
                    parts.append(f"tls_mod={fake_tls_mod}")
                parts.extend(fool_parts)
                out.append("--lua-desync=" + ":".join(parts))
        elif mode in ("multisplit", "split", "split2"):
            parts = [f"multisplit:pos={split_pos}"]
            if seqovl:
                parts.append(f"seqovl={seqovl}")
            if seqovl_pattern:
                parts.append(f"seqovl_pattern={seqovl_pattern}")
            if ip_id_zero:
                parts.append("ip_id=zero")
            out.append("--lua-desync=" + ":".join(parts))
        elif mode in ("multidisorder", "disorder", "disorder2"):
            parts = [f"multidisorder:pos={split_pos}"]
            if seqovl:
                parts.append(f"seqovl={seqovl}")
            if seqovl_pattern:
                parts.append(f"seqovl_pattern={seqovl_pattern}")
            if ip_id_zero:
                parts.append("ip_id=zero")
            out.append("--lua-desync=" + ":".join(parts))
        elif mode == "fakedsplit":
            parts = [f"fakedsplit:pos={split_pos}", f"repeats={repeats}"]
            parts.extend(fool_parts)
            out.append("--lua-desync=" + ":".join(parts))
        elif mode == "hostfakesplit":
            mod_parts = list(hostfakesplit_mods) if any(m.startswith("host=") for m in hostfakesplit_mods) else ["host=www.google.com", *hostfakesplit_mods]
            parts = [f"hostfakesplit:{':'.join(mod_parts)}", f"repeats={repeats}"]
            parts.extend(fool_parts)
            out.append("--lua-desync=" + ":".join(parts))
        elif mode == "syndata":
            out.append("--lua-desync=syndata")

    return out


def parse_bat_to_winws2_text(bat_content: str, preset_name: str = "") -> str:
    """Extract winws/winws2 command arguments from a Windows .bat file and normalize to Zapret2 preset text."""
    # Join cmd.exe line continuations (`^` at end of line)
    cleaned_lines: list[str] = []
    for raw in (bat_content or "").splitlines():
        s = raw.strip()
        if not s or s.lower().startswith(("rem ", "::", "@echo", "chcp", "cd ", "set ", "call ", "if ", "for ")):
            continue
        cleaned_lines.append(s)
    joined = "\n".join(cleaned_lines)
    joined = re.sub(r"\^\s*\r?\n\s*", " ", joined)
    joined = joined.replace("%BIN%", "files/").replace("%LISTS%", "lists/").replace("%GameFilter%", "1024-65535")
    joined = joined.replace("%GameFilterTCP%", "1024-65535").replace("%GameFilterUDP%", "1024-65535")

    m = _ZDY_BAT_WINWS_RE.search(joined)
    arg_str = m.group(1) if m else joined
    arg_str = arg_str.splitlines()[0].strip()

    try:
        tokens = shlex.split(arg_str, posix=False)
    except ValueError:
        tokens = arg_str.split()
    tokens = [t.strip('"').strip("'") for t in tokens if t.strip()]

    # Already winws2 syntax?
    if any(t.startswith("--lua-desync=") for t in tokens):
        header = f"# Preset: {preset_name or 'Imported .bat'}\n"
        return header + "\n".join(tokens) + "\n"

    # Convert zapret1 flags profile by profile
    profiles: list[list[str]] = [[]]
    global_flags: list[str] = []
    seen_filter = False
    for tok in tokens:
        if tok == "--new":
            profiles.append([])
            seen_filter = True
            continue
        if not seen_filter and tok.startswith("--wf-"):
            # Rewrite --wf-tcp= / --wf-udp= into --wf-tcp-out= / --wf-udp-out=
            if tok.startswith("--wf-tcp="):
                global_flags.append("--wf-tcp-out=" + tok.split("=", 1)[1])
            elif tok.startswith("--wf-udp="):
                global_flags.append("--wf-udp-out=" + tok.split("=", 1)[1])
            else:
                global_flags.append(tok)
            continue
        if tok.startswith(("--filter-", "--hostlist", "--ipset")):
            seen_filter = True
        profiles[-1].append(tok)

    lines: list[str] = [
        f"# Preset: {preset_name or 'Converted .bat preset'}",
        "# Description: Автоконвертация из .bat (zapret-discord-youtube) в формат winws2",
        "",
        "--lua-init=@lua/zapret-lib.lua",
        "--lua-init=@lua/zapret-antidpi.lua",
        "--lua-init=@lua/zapret-auto.lua",
        "--ctrack-disable=0",
        "--ipcache-lifetime=8400",
        "--ipcache-hostname=1",
    ]
    if global_flags:
        lines.extend(global_flags)
    else:
        lines.append("--wf-tcp-out=80,443,2053,2083,2087,2096,5222,8443")
        lines.append("--wf-udp-out=443,19294-19344,50000-50100,1024-65535")

    emitted = 0
    for prof in profiles:
        converted = _convert_zapret1_profile_to_winws2(prof)
        if not any(t.startswith("--lua-desync=") for t in converted):
            continue
        if emitted > 0:
            lines.append("--new")
        lines.extend(converted)
        emitted += 1

    return "\n".join(lines) + "\n"


def _tokenize_preset_text(preset_text: str) -> list[str]:
    tokens: list[str] = []
    for raw_line in (preset_text or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        # Zapret2 preset metadata line `--name=...` often contains unquoted spaces & Cyrillic — keep intact!
        if line.lower().startswith("--name="):
            tokens.append(line)
            continue
        # If a line contains a single `--flag=...` with no subsequent ` --` option, preserve the whole line
        # (protects paths with spaces and avoids splitting values incorrectly).
        if line.startswith("--") and " --" not in line and not line.endswith('"') and " #" not in line:
            cleaned = line.strip()
            if len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and cleaned[0] in ('"', "'"):
                cleaned = cleaned[1:-1]
            if cleaned:
                tokens.append(cleaned)
            continue
        try:
            parts = shlex.split(line, posix=False)
        except ValueError:
            parts = line.split()
        for p in parts:
            if p.startswith("#"):
                break
            cleaned = p.strip()
            if len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and cleaned[0] in ('"', "'"):
                cleaned = cleaned[1:-1]
            if cleaned:
                tokens.append(cleaned)
    return tokens


def _resolve_list_file_for_preset(
    raw_ref: str,
    lists_path: Path,
    extra_search_dirs: list[Path],
) -> Path | None:
    """Resolve a preset `--hostlist=` / `--ipset=` path against netdoctor lists, lists/zapret2, and C:\\vso\\Dev."""
    norm = raw_ref.replace("\\", "/").strip()
    if not norm:
        return None
    p = Path(norm)
    if p.is_absolute() and p.is_file():
        return p

    fname = p.name
    candidates: list[Path] = [
        lists_path / norm,
        lists_path / fname,
        lists_path / "zapret2" / fname,
        lists_path.parent / norm,
        Path("lists") / "zapret2" / fname,
        Path("lists") / fname,
        _REPO_ROOT / "lists" / "zapret2" / fname,
        _REPO_ROOT / "lists" / fname,
    ]
    for d in extra_search_dirs:
        candidates.append(d / fname)
        candidates.append(d / "base" / fname)
        candidates.append(d / "user" / fname)

    for cand in candidates:
        if cand.is_file() and cand.stat().st_size > 0:
            return cand
    return None


def _resolve_blob_file_for_preset(raw_ref: str, bin_path: Path) -> str | None:
    """Resolve `@bin/foo.bin` or `@files/foo.bin` against bin_path/files/ and return `@files/<name>` if present."""
    norm = raw_ref.replace("\\", "/").strip()
    if norm.startswith("@"):
        norm = norm[1:]
    fname = Path(norm).name
    if (bin_path / norm).is_file():
        return f"@{norm}"
    if (bin_path / "files" / fname).is_file():
        return f"@files/{fname}"
    # Fallback to project bin/files if running against temporary test bin_dir
    proj_file = Path("bin") / "files" / fname
    if proj_file.is_file():
        return f"@{proj_file.resolve().as_posix()}"
    repo_file = _REPO_ROOT / "bin" / "files" / fname
    if repo_file.is_file():
        return f"@{repo_file.resolve().as_posix()}"
    dev_file = Path(r"C:\vso\Dev\bin") / fname
    if dev_file.is_file():
        return f"@{dev_file.as_posix()}"
    return None


def compile_zapret_preset(
    preset_text: str,
    *,
    bin_dir: str | Path = "bin",
    lists_dir: str | Path = "lists",
    vpn_server_ips: list[str] | None = None,
    exclude_domains: list[str] | None = None,
    iface: int | str | None = None,
    game_filter: bool = True,
) -> list[str]:
    """Compile a built-in or user-supplied Zapret2 preset text into verified winws2 arguments.

    Handles:
    - Full Zapret2 presets (e.g. from C:\\vso\\Dev\\presets\\winws2_builtin)
    - Raw user `--lua-desync=...` snippets (auto-wrapped with TLS/Telegram/Discord profiles)
    - Zapret1 `.bat` content (auto-converted via `parse_bat_to_winws2_text`)
    - Safe path rewriting (`@bin/*.bin` -> `@files/*.bin`, `lists/*.txt` -> `lists/zapret2/*.txt`)
    - Filtering out missing optional lua/blob/hostlist references so winws2.exe never crashes on startup
    - Injecting Unlocker Guard IP/domain exclusions (`exclude_vpn_ips.txt`, `exclude_unlocker_domains.txt`)
    """
    raw = (preset_text or "").strip()
    if not raw:
        raise ValueError("Текст пресета пуст")

    # Auto-convert .bat / zapret1 syntax if detected
    if "--dpi-desync" in raw and "--lua-desync" not in raw:
        raw = parse_bat_to_winws2_text(raw)

    tokens = _tokenize_preset_text(raw)
    if not tokens:
        raise ValueError("Пресет не содержит аргументов winws2")

    bin_path = Path(bin_dir).resolve()
    lists_path = Path(lists_dir).resolve()
    lists_path.mkdir(parents=True, exist_ok=True)

    # Generate Unlocker Guard exclude files
    resolved_vpn_ips = resolve_vpn_ips(vpn_server_ips)
    exclude_ipset_path = lists_path / "exclude_vpn_ips.txt"
    if resolved_vpn_ips:
        exclude_ipset_path.write_text("\n".join(resolved_vpn_ips) + "\n", encoding="utf-8")
    else:
        exclude_ipset_path.write_text("# No VPN server IPs configured\n", encoding="utf-8")

    excluded_doms = sorted({d.strip().lower() for d in (exclude_domains or []) if d and d.strip()})
    exclude_hostlist_path: Path | None = None
    if excluded_doms:
        exclude_hostlist_path = lists_path / "exclude_unlocker_domains.txt"
        exclude_hostlist_path.write_text("\n".join(excluded_doms) + "\n", encoding="utf-8")

    # Case: User pasted ONLY `--lua-desync=...` (snippet mode) -> wrap into full working winws2 config!
    has_filters = any(t.startswith(("--filter-tcp=", "--filter-udp=", "--filter-l7=", "--wf-")) for t in tokens)
    if not has_filters and any(t.startswith("--lua-desync=") for t in tokens):
        desync_lines = [t for t in tokens if t.startswith(("--lua-desync=", "--payload=", "--out-range=", "--in-range="))]
        tg_ipset = lists_path / "ipset-telegram.txt"
        if not tg_ipset.is_file() or tg_ipset.stat().st_size == 0:
            tg_ipset.write_text("\n".join(TELEGRAM_CIDRS) + "\n", encoding="utf-8")
        wrapped: list[str] = [
            "--lua-init=@lua/zapret-lib.lua",
            "--lua-init=@lua/zapret-antidpi.lua",
            "--lua-init=@lua/zapret-auto.lua",
            "--ctrack-disable=0",
            "--ipcache-lifetime=8400",
            "--ipcache-hostname=1",
            "--wf-tcp-out=80,443,2053,2083,2087,2096,5222,8443",
            "--wf-tcp-in=80,443",
            (
                "--wf-udp-out=443,19294-19344,50000-50100,1024-65535"
                if game_filter
                else "--wf-udp-out=443,19294-19344,50000-50100"
            ),
        ]
        if iface is not None:
            wrapped.append(f"--wf-iface={iface}")
        # Profile 1: Global TLS / HTTP using user's working desync args
        wrapped.extend(["--filter-tcp=80,443,2053,2083,2087,2096,8443", "--filter-l7=tls,http"])
        if not any(t.startswith("--payload=") for t in desync_lines):
            wrapped.append("--payload=tls_client_hello,http_req")
        if resolved_vpn_ips:
            wrapped.append(f"--ipset-exclude={exclude_ipset_path.as_posix()}")
        if exclude_hostlist_path is not None:
            wrapped.append(f"--hostlist-exclude={exclude_hostlist_path.as_posix()}")
        wrapped.extend(desync_lines)
        # Profile 2: Telegram MTProto IPSET
        wrapped.extend(["--new", "--filter-tcp=80,443,5222", f"--ipset={tg_ipset.as_posix()}", "--payload=all"])
        if resolved_vpn_ips:
            wrapped.append(f"--ipset-exclude={exclude_ipset_path.as_posix()}")
        wrapped.extend(
            [
                "--lua-desync=fake:blob=fake_stun_as_tls:tcp_ts=-600000:repeats=6",
                "--lua-desync=fake:blob=tls_google:tcp_ts=-600000:repeats=6",
                "--lua-desync=fakedsplit:pattern=0x00:tcp_ts=-600000:repeats=6",
                "--lua-desync=fake:blob=tls_max:tcp_ts=-600000:repeats=6",
            ]
        )
        # Profile 3: Discord / STUN / QUIC UDP
        wrapped.extend(
            [
                "--new",
                "--filter-udp=443,19294-19344,50000-50100" + (",1024-65535" if game_filter else ""),
                "--filter-l7=quic,discord,stun",
                "--payload=all",
            ]
        )
        if resolved_vpn_ips:
            wrapped.append(f"--ipset-exclude={exclude_ipset_path.as_posix()}")
        if exclude_hostlist_path is not None:
            wrapped.append(f"--hostlist-exclude={exclude_hostlist_path.as_posix()}")
        wrapped.append("--lua-desync=fake:blob=quic_google:repeats=6")
        blob_args = extract_blob_args(wrapped)
        if blob_args:
            insert_idx = sum(1 for a in wrapped if a.startswith("--lua-init="))
            wrapped[insert_idx:insert_idx] = blob_args
        return wrapped

    extra_list_dirs: list[Path] = []

    # Split into global header + individual profiles separated by --new
    global_tokens: list[str] = []
    profiles: list[list[str]] = []
    cur_prof: list[str] | None = None

    for tok in tokens:
        if tok == "--new":
            if cur_prof is not None:
                profiles.append(cur_prof)
            cur_prof = []
            continue
        if cur_prof is None and tok.startswith(
            ("--name=", "--skip", "--filter-", "--hostlist", "--ipset", "--out-range=", "--in-range=", "--payload=", "--lua-desync=")
        ):
            cur_prof = [tok]
            continue
        if cur_prof is None:
            global_tokens.append(tok)
        else:
            cur_prof.append(tok)
    if cur_prof is not None:
        profiles.append(cur_prof)

    # Filter & normalize global tokens
    compiled_global: list[str] = []
    seen_lua: set[str] = set()
    loaded_lua_paths: list[Path] = []
    missing_lua: list[str] = []
    defined_blobs: set[str] = set()
    has_ctrack = False
    has_ipcache = False
    has_wf_iface = False

    for tok in global_tokens:
        if tok.startswith("--lua-init="):
            raw_ref = tok[len("--lua-init=") :].lstrip("@").replace("\\", "/")
            fname = Path(raw_ref).name
            if (bin_path / raw_ref).is_file():
                resolved_lua = f"@lua/{fname}" if raw_ref.startswith("lua/") else f"@{raw_ref}"
                lua_disk_path = bin_path / raw_ref
            elif (bin_path / "lua" / fname).is_file():
                resolved_lua = f"@lua/{fname}"
                lua_disk_path = bin_path / "lua" / fname
            else:
                missing_lua.append(fname)
                continue
            if resolved_lua not in seen_lua:
                seen_lua.add(resolved_lua)
                loaded_lua_paths.append(lua_disk_path)
                compiled_global.append(f"--lua-init={resolved_lua}")
        elif tok.startswith("--blob="):
            body = tok[len("--blob=") :]
            if ":" not in body:
                continue
            bname, bval = body.split(":", 1)
            if bval.startswith("@"):
                resolved_b = _resolve_blob_file_for_preset(bval, bin_path)
                if resolved_b is None:
                    continue
                compiled_global.append(f"--blob={bname}:{resolved_b}")
                defined_blobs.add(bname)
            else:
                compiled_global.append(tok)
                defined_blobs.add(bname)
        elif tok.startswith("--wf-raw-part="):
            raw_ref = tok[len("--wf-raw-part=") :].lstrip("@").replace("\\", "/")
            fname = Path(raw_ref).name
            if (bin_path / raw_ref).is_file():
                compiled_global.append(f"--wf-raw-part=@{raw_ref}")
            elif (bin_path / "windivert.filter" / fname).is_file():
                compiled_global.append(f"--wf-raw-part=@windivert.filter/{fname}")
        elif tok.startswith("--ctrack-disable="):
            has_ctrack = True
            compiled_global.append(tok)
        elif tok.startswith("--ipcache-lifetime="):
            has_ipcache = True
            compiled_global.append(tok)
        elif tok.startswith("--wf-iface="):
            has_wf_iface = True
            compiled_global.append(f"--wf-iface={iface}" if iface is not None else tok)
        elif tok.startswith("--wf-"):
            if not game_filter and tok.startswith("--wf-udp-out="):
                raw_ports = [p.strip() for p in tok[len("--wf-udp-out=") :].split(",") if p.strip()]
                filtered_ports = [p for p in raw_ports if p != "1024-65535"]
                if not filtered_ports:
                    continue
                compiled_global.append(f"--wf-udp-out={','.join(filtered_ports)}")
            else:
                compiled_global.append(tok)
        else:
            compiled_global.append(tok)

    # Ensure core Lua scripts are always loaded first
    core_lua = ["@lua/zapret-lib.lua", "@lua/zapret-antidpi.lua", "@lua/zapret-auto.lua"]
    missing_core = [f"--lua-init={x}" for x in core_lua if x not in seen_lua]
    for core_ref in core_lua:
        if core_ref not in seen_lua:
            cp = bin_path / core_ref.lstrip("@")
            if cp.is_file():
                loaded_lua_paths.append(cp)
    if missing_core:
        compiled_global = missing_core + compiled_global

    defined_lua_funcs: set[str] | None = None
    if missing_lua and loaded_lua_paths:
        defined_lua_funcs = set()
        for lp in loaded_lua_paths:
            try:
                defined_lua_funcs.update(_LUA_FUNC_DEF_RE.findall(lp.read_text(encoding="utf-8", errors="replace")))
            except OSError:
                continue

    if not has_ctrack:
        compiled_global.append("--ctrack-disable=0")
    if not has_ipcache:
        compiled_global.extend(["--ipcache-lifetime=8400", "--ipcache-hostname=1"])
    if iface is not None and not has_wf_iface:
        compiled_global.append(f"--wf-iface={iface}")

    # Compile profiles cleanly, resolving list paths & skipping --skip or broken profiles
    compiled_profiles: list[list[str]] = []
    # Pre-insert Unlocker Guard pass profiles (TCP + UDP/443 QUIC) so Antigravity/hosts domains and VPN IPs are NEVER mangled!
    if excluded_doms and exclude_hostlist_path is not None:
        compiled_profiles.append(
            [
                "--filter-tcp=80,443-65535",
                f"--hostlist={exclude_hostlist_path.as_posix()}",
                "--payload=tls_client_hello,http_req",
                "--lua-desync=pass",
            ]
        )
        compiled_profiles.append(
            [
                "--filter-udp=443",
                f"--hostlist={exclude_hostlist_path.as_posix()}",
                "--payload=quic_initial",
                "--lua-desync=pass",
            ]
        )
    if resolved_vpn_ips:
        compiled_profiles.append(
            [
                "--filter-tcp=80,443-65535",
                f"--ipset={exclude_ipset_path.as_posix()}",
                "--payload=all",
                "--lua-desync=pass",
            ]
        )
        compiled_profiles.append(
            [
                "--filter-udp=443,1024-65535",
                f"--ipset={exclude_ipset_path.as_posix()}",
                "--payload=all",
                "--lua-desync=pass",
            ]
        )

    for prof in profiles:
        if any(t == "--skip" for t in prof):
            continue
        out_prof: list[str] = []
        had_positive_list = False
        resolved_positive_list = False
        for tok in prof:
            if tok.startswith("--name="):
                # `--name=` is metadata in ZapretGUI presets; standard winws2 ignores/rejects unknown flags in some builds
                continue
            if tok.startswith("--lua-desync=") and defined_lua_funcs is not None:
                fn_name = tok[len("--lua-desync=") :].split(":", 1)[0].strip()
                if fn_name and fn_name != "pass" and fn_name not in defined_lua_funcs:
                    raise ValueError(
                        f"В пресете используется Lua-функция '{fn_name}', но скрипт отсутствует ({', '.join(missing_lua)})"
                    )
            if tok.startswith(("--hostlist=", "--ipset=")):
                prefix, raw_val = tok.split("=", 1)
                had_positive_list = True
                resolved = _resolve_list_file_for_preset(raw_val, lists_path, extra_list_dirs)
                if resolved is not None:
                    out_prof.append(f"{prefix}={resolved.as_posix()}")
                    resolved_positive_list = True
                continue
            if tok.startswith(("--hostlist-exclude=", "--ipset-exclude=")):
                prefix, raw_val = tok.split("=", 1)
                resolved = _resolve_list_file_for_preset(raw_val, lists_path, extra_list_dirs)
                if resolved is not None:
                    out_prof.append(f"{prefix}={resolved.as_posix()}")
                continue
            out_prof.append(tok)

        # If a profile relied ONLY on a hostlist/ipset that doesn't exist, skip the profile rather than matching ALL traffic!
        if had_positive_list and not resolved_positive_list:
            continue
        if not any(t.startswith("--lua-desync=") for t in out_prof):
            continue
        if not game_filter:
            prof_joined = " ".join(out_prof).lower()
            is_game_port_udp = any(
                t.startswith(("--filter-udp=5000-5500", "--filter-udp=7000-8000")) for t in out_prof
            )
            is_wide_game_ipset_udp = any(
                t.startswith("--filter-udp=") and ("65535" in t or "1024-" in t or "443-" in t) for t in out_prof
            ) and any(
                g in prof_joined
                for g in ("ipset-amazon", "ipset-ovh", "ipset-roblox", "ipset-lol", "ipset-tankix")
            )
            if is_game_port_udp or is_wide_game_ipset_udp:
                continue
        compiled_profiles.append(out_prof)

    if not compiled_profiles:
        raise ValueError("В пресете не найдено рабочих профилей --lua-desync")

    # Assemble final args & auto-inject any KNOWN_BLOBS referenced but not yet defined
    final_args = list(compiled_global)
    for idx, prof in enumerate(compiled_profiles):
        if idx > 0:
            final_args.append("--new")
        final_args.extend(prof)

    needed_blobs = [
        b
        for b in extract_blob_args(final_args)
        if b[len("--blob=") :].split(":", 1)[0] not in defined_blobs
    ]
    if needed_blobs:
        insert_idx = sum(1 for a in final_args if a.startswith("--lua-init="))
        final_args[insert_idx:insert_idx] = needed_blobs

    return final_args


def merge_winws2_base_preset(auto_args: list[str], base_args: list[str]) -> list[str]:
    """Merge Auto-Orchestrator per-domain profiles ahead of a compiled base Zapret2 preset."""
    _profile_starts = ("--filter-", "--hostlist", "--ipset", "--lua-desync", "--new")

    def _split(args: list[str]) -> tuple[list[str], list[str]]:
        for idx, tok in enumerate(args):
            if tok == "--new" or tok.startswith(_profile_starts):
                return list(args[:idx]), list(args[idx:])
        return list(args), []

    auto_glob, auto_prof = _split(auto_args)
    base_glob, base_prof = _split(base_args)

    lua_inits: list[str] = []
    seen_lua: set[str] = set()
    blobs: list[str] = []
    seen_blobs: set[str] = set()
    other_globals: list[str] = []
    seen_keys: set[str] = set()

    for tok in [*auto_glob, *base_glob]:
        if tok.startswith("--lua-init="):
            if tok not in seen_lua:
                seen_lua.add(tok)
                lua_inits.append(tok)
        elif tok.startswith("--blob="):
            bname = tok[len("--blob=") :].split(":", 1)[0]
            if bname not in seen_blobs:
                seen_blobs.add(bname)
                blobs.append(tok)
        else:
            key = tok.split("=", 1)[0]
            if key not in seen_keys:
                seen_keys.add(key)
                other_globals.append(tok)

    def _split_profiles(prof_tokens: list[str]) -> list[list[str]]:
        out: list[list[str]] = []
        cur: list[str] = []
        for tok in prof_tokens:
            if tok == "--new":
                if cur:
                    out.append(cur)
                    cur = []
            else:
                cur.append(tok)
        if cur:
            out.append(cur)
        return out

    def _is_pass_profile(prof: list[str], target_name: str) -> bool:
        has_pass = any(t == "--lua-desync=pass" for t in prof)
        if not has_pass:
            return False
        for tok in prof:
            if tok.startswith(("--hostlist=", "--ipset=")):
                val = tok.split("=", 1)[1].replace("\\", "/")
                if val.rsplit("/", 1)[-1].lower() == target_name:
                    return True
        return False

    vpn_ip_pass: list[list[str]] = []
    auto_specific: list[list[str]] = []
    unlocker_dom_pass: list[list[str]] = []
    auto_generic_udp: list[list[str]] = []

    for prof in _split_profiles(auto_prof):
        if _is_pass_profile(prof, "exclude_vpn_ips.txt"):
            vpn_ip_pass.append(prof)
        elif _is_pass_profile(prof, "exclude_unlocker_domains.txt"):
            unlocker_dom_pass.append(prof)
        elif any(t.startswith("--filter-l7=") for t in prof) or (
            any(t.startswith("--filter-udp=") for t in prof)
            and not any(t.startswith(("--hostlist=", "--ipset=")) for t in prof)
        ):
            auto_generic_udp.append(prof)
        else:
            auto_specific.append(prof)

    had_auto_vpn_pass = bool(vpn_ip_pass)
    had_auto_unlocker_pass = bool(unlocker_dom_pass)
    rest_base: list[list[str]] = []
    for prof in _split_profiles(base_prof):
        if _is_pass_profile(prof, "exclude_vpn_ips.txt"):
            if not had_auto_vpn_pass:
                vpn_ip_pass.append(prof)
            continue
        if _is_pass_profile(prof, "exclude_unlocker_domains.txt"):
            if not had_auto_unlocker_pass:
                unlocker_dom_pass.append(prof)
            continue
        rest_base.append(prof)

    ordered_profiles = [
        *vpn_ip_pass,
        *auto_specific,
        *unlocker_dom_pass,
        *auto_generic_udp,
        *rest_base,
    ]
    merged_profiles: list[str] = []
    for idx, prof in enumerate(ordered_profiles):
        if idx > 0:
            merged_profiles.append("--new")
        merged_profiles.extend(prof)

    return [*lua_inits, *blobs, *other_globals, *merged_profiles]


def discover_builtin_zapret_presets(
    presets_dir: str | Path = DEFAULT_ZAPRET2_PRESETS_DIR,
    zdy_dir: str | Path = DEFAULT_ZDY_PRESETS_DIR,
) -> list[dict[str, Any]]:
    """Return built-in Zapret2 presets from presets/zapret2/*.txt (imported from C:\\vso\\Dev) and presets/zapret-discord-youtube/*.bat."""
    z2_path = Path(presets_dir)
    zdy_path = Path(zdy_dir)

    z2_files: list[Path] = sorted(z2_path.glob("*.txt")) if z2_path.is_dir() else []
    zdy_files: list[Path] = sorted(zdy_path.glob("general*.bat")) if zdy_path.is_dir() else []

    def _stat_sig(paths: list[Path]) -> tuple[tuple[str, int, int], ...]:
        sig: list[tuple[str, int, int]] = []
        for p in paths:
            try:
                st = p.stat()
                sig.append((p.name, st.st_mtime_ns, st.st_size))
            except OSError:
                continue
        return tuple(sig)

    cache_key = (str(z2_path.resolve()), str(zdy_path.resolve()), _stat_sig(z2_files), _stat_sig(zdy_files))
    cached = _BUILTIN_PRESETS_CACHE.get(cache_key)
    if cached is not None:
        return [dict(item) for item in cached]

    items: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    for fpath in z2_files:
        if not fpath.is_file() or fpath.name.startswith("_"):
            continue
        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        meta = parse_preset_metadata(content, fallback_name=fpath.stem)
        pid = slugify_preset_id(fpath.stem, prefix="z2")
        if pid in seen_ids:
            continue
        seen_ids.add(pid)
        name = meta["name"]
        desc = meta["description"] or f"Пресет Zapret2 ({fpath.name})"
        prio = _FEATURED_PRESET_PRIORITY.get(name, _FEATURED_PRESET_PRIORITY.get(fpath.stem, 100))
        items.append(
            {
                "id": pid,
                "name": name,
                "description": desc,
                "content": content,
                "source": "builtin_zapret2",
                "file_path": str(fpath),
                "builtin": True,
                "is_working": prio < 15,
                "featured": prio < 15,
                "priority": prio,
                "success_rate": None,
                "last_tested_at": "",
            }
        )

    for bpath in zdy_files:
        if not bpath.is_file():
            continue
        try:
            raw_bat = bpath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        pid = slugify_preset_id(bpath.stem, prefix="zdy")
        if pid in seen_ids:
            continue
        seen_ids.add(pid)
        converted = parse_bat_to_winws2_text(raw_bat, preset_name=bpath.stem)
        items.append(
            {
                "id": pid,
                "name": f"[ZDY] {bpath.stem}",
                "description": f"Конвертирован из {bpath.name}",
                "content": converted,
                "source": "builtin_zdy",
                "file_path": str(bpath),
                "builtin": True,
                "is_working": False,
                "featured": False,
                "priority": 200,
                "success_rate": None,
                "last_tested_at": "",
            }
        )

    items.sort(key=lambda x: (x["priority"], x["name"].lower()))
    if len(_BUILTIN_PRESETS_CACHE) > 8:
        _BUILTIN_PRESETS_CACHE.clear()
    _BUILTIN_PRESETS_CACHE[cache_key] = [dict(item) for item in items]
    return items


def list_all_zapret_presets(
    storage: Storage,
    presets_dir: str | Path = DEFAULT_ZAPRET2_PRESETS_DIR,
    zdy_dir: str | Path = DEFAULT_ZDY_PRESETS_DIR,
) -> list[dict[str, Any]]:
    """Combine user-saved working presets (first) with built-in Zapret2 presets and merge cached test rates."""
    user_presets = storage.get_zapret_presets()
    builtin_presets = discover_builtin_zapret_presets(presets_dir=presets_dir, zdy_dir=zdy_dir)

    # Load cached test stats for builtin presets stored in settings JSON
    raw_stats = storage.get_setting("builtin_preset_stats", "{}")
    try:
        import json

        b_stats = json.loads(raw_stats) if raw_stats else {}
        if not isinstance(b_stats, dict):
            b_stats = {}
    except Exception:  # noqa: BLE001
        b_stats = {}

    for item in builtin_presets:
        st = b_stats.get(item["id"])
        if isinstance(st, dict):
            if "success_rate" in st:
                item["success_rate"] = st["success_rate"]
            if "last_tested_at" in st:
                item["last_tested_at"] = st["last_tested_at"]
            if "is_working" in st:
                item["is_working"] = bool(st["is_working"])

    return [*user_presets, *builtin_presets]


def save_user_zapret_preset(
    storage: Storage,
    *,
    name: str,
    content: str,
    description: str = "",
    is_working: bool = True,
    source: str = "user",
    preset_id: str | None = None,
) -> dict[str, Any]:
    """Validate and save a user's working Zapret2 preset into SQLite."""
    clean_name = (name or "").strip()
    clean_content = (content or "").strip()
    if not clean_name:
        raise ValueError("Введите название пресета")
    if not clean_content:
        raise ValueError("Вставьте содержимое или аргументы пресета")

    # Auto-convert .bat syntax on save if pasted
    if "--dpi-desync" in clean_content and "--lua-desync" not in clean_content:
        clean_content = parse_bat_to_winws2_text(clean_content, preset_name=clean_name)

    tokens = _tokenize_preset_text(clean_content)
    if not any(t.startswith("--lua-desync=") for t in tokens):
        raise ValueError("Пресет должен содержать хотя бы один параметр --lua-desync= (или --dpi-desync= из .bat)")

    pid = (preset_id or "").strip() or f"{slugify_preset_id(clean_name, prefix='user')}_{int(time.time() * 1000) % 10000}"
    return storage.save_zapret_preset(
        {
            "id": pid,
            "name": clean_name,
            "description": description.strip() or "Пользовательский рабочий пресет",
            "content": clean_content,
            "source": source,
            "is_working": is_working,
        }
    )


def import_preset_from_file(
    storage: Storage,
    file_path: str | Path,
    *,
    name: str | None = None,
    is_working: bool = True,
) -> dict[str, Any]:
    """Import a .txt (winws2) or .bat (zapret1) preset file from disk into user presets."""
    p = Path(file_path)
    if not p.is_file():
        raise FileNotFoundError(f"Файл пресета не найден: {p}")
    raw = p.read_text(encoding="utf-8", errors="replace")
    if p.suffix.lower() in (".bat", ".cmd"):
        content = parse_bat_to_winws2_text(raw, preset_name=name or p.stem)
        preset_name = name or p.stem
        desc = f"Импортирован из {p.name}"
    else:
        meta = parse_preset_metadata(raw, fallback_name=p.stem)
        content = raw
        preset_name = name or meta["name"]
        desc = meta["description"] or f"Импортирован из {p.name}"

    return save_user_zapret_preset(
        storage,
        name=preset_name,
        content=content,
        description=desc,
        is_working=is_working,
        source=f"file:{p.name}",
    )


def import_presets_from_directory(
    storage: Storage,
    dir_path: str | Path,
    *,
    max_files: int = 25,
) -> list[dict[str, Any]]:
    """Bulk-import .txt/.bat presets from a user directory (e.g. C:\\vso\\Dev\\presets\\winws2)."""
    root = Path(dir_path)
    if not root.is_dir():
        raise FileNotFoundError(f"Папка пресетов не найдена: {root}")

    candidates: list[Path] = []
    for ext in ("*.txt", "*.bat"):
        candidates.extend(sorted(root.glob(ext)))
    # Also check winws2 / winws2_builtin subdirs if user pointed at C:\vso\Dev or C:\vso\Dev\presets
    for sub in ("presets/winws2", "winws2", "presets/winws2_builtin", "winws2_builtin"):
        sub_dir = root / sub
        if sub_dir.is_dir():
            candidates.extend(sorted(sub_dir.glob("*.txt")))

    imported: list[dict[str, Any]] = []
    seen_names: set[str] = {p["name"].lower() for p in storage.get_zapret_presets()}
    for fpath in candidates:
        if len(imported) >= max_files:
            break
        if fpath.name.startswith("_") or fpath.name.lower() == "service.bat":
            continue
        meta = parse_preset_metadata(fpath.read_text(encoding="utf-8", errors="replace"), fallback_name=fpath.stem)
        if meta["name"].lower() in seen_names:
            continue
        try:
            saved = import_preset_from_file(storage, fpath, is_working=True)
            seen_names.add(saved["name"].lower())
            imported.append(saved)
        except Exception:  # noqa: BLE001
            continue
    return imported
