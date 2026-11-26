"""Declarative AppBundle registry, child-process inheritance, and indivisible routing compiler."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import psutil
import yaml
from pydantic import BaseModel, Field

BUNDLE_MODES: tuple[str, ...] = ("direct_clean", "direct_dpi", "vpn")
CLOUD_GAMING_BEACONS: tuple[str, ...] = ("aws.amazon.com", "cloudflare.com", "ovh.com")

_REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_BUNDLES_PATH = (
    (_REPO_ROOT / "configs" / "bundles.yaml")
    if (_REPO_ROOT / "configs" / "bundles.yaml").is_file()
    else (Path("configs") / "bundles.yaml")
)


class AppBundle(BaseModel):
    id: str
    name: str
    category: str = "game"  # "game" | "app" | "custom"
    coupling: str = "tight"  # "tight" | "storefront"
    default_mode: str = "direct_clean"
    processes: list[str] = Field(default_factory=list)
    auth_domains: list[str] = Field(default_factory=list)
    download_cdn_domains: list[str] = Field(default_factory=list)
    path_patterns: list[str] = Field(default_factory=list)
    builtin: bool = True


def _clean_proc_list(items: list[str] | tuple[str, ...]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in items:
        name = Path(str(raw or "").strip().replace("\\", "/")).name.strip()
        if name and name.lower() not in seen:
            seen.add(name.lower())
            out.append(name)
    return out


def _clean_domain_list(items: list[str] | tuple[str, ...]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in items:
        dom = str(raw or "").strip().lower().lstrip(".")
        if dom and dom not in seen:
            seen.add(dom)
            out.append(dom)
    return out


def load_bundles(
    bundles_path: str | Path | None = None,
    storage: Any | None = None,
) -> list[AppBundle]:
    """Load built-in bundles from configs/bundles.yaml and merge user custom bundles from Storage."""
    p = Path(bundles_path) if bundles_path is not None else DEFAULT_BUNDLES_PATH
    if not p.is_file():
        alt = _REPO_ROOT / "configs" / "bundles.yaml"
        if alt.is_file():
            p = alt

    bundles: list[AppBundle] = []
    seen_ids: set[str] = set()
    if p.is_file():
        try:
            raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            items = raw.get("bundles") if isinstance(raw, dict) else raw
            if isinstance(items, list):
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    bid = str(item.get("id") or "").strip().lower()
                    if not bid or bid in seen_ids:
                        continue
                    seen_ids.add(bid)
                    def_mode = str(item.get("default_mode") or "direct_clean").strip().lower()
                    if def_mode not in BUNDLE_MODES:
                        def_mode = "direct_clean"
                    bundles.append(
                        AppBundle(
                            id=bid,
                            name=str(item.get("name") or bid).strip(),
                            category=str(item.get("category") or "game").strip() or "game",
                            coupling=str(item.get("coupling") or "tight").strip().lower() or "tight",
                            default_mode=def_mode,
                            processes=_clean_proc_list(item.get("processes") or []),
                            auth_domains=_clean_domain_list(item.get("auth_domains") or []),
                            download_cdn_domains=_clean_domain_list(item.get("download_cdn_domains") or []),
                            path_patterns=[str(x).strip() for x in (item.get("path_patterns") or []) if str(x).strip()],
                            builtin=True,
                        )
                    )
        except Exception:
            pass

    if storage is not None and hasattr(storage, "get_setting"):
        import json

        raw_custom = storage.get_setting("custom_bundles", "[]")
        try:
            custom_items = json.loads(raw_custom) if raw_custom else []
        except (TypeError, ValueError):
            custom_items = []
        if isinstance(custom_items, list):
            for item in custom_items:
                if not isinstance(item, dict):
                    continue
                bid = str(item.get("id") or "").strip().lower()
                if not bid or bid in seen_ids:
                    continue
                seen_ids.add(bid)
                def_mode = str(item.get("default_mode") or "direct_clean").strip().lower()
                if def_mode not in BUNDLE_MODES:
                    def_mode = "direct_clean"
                bundles.append(
                    AppBundle(
                        id=bid,
                        name=str(item.get("name") or bid).strip(),
                        category=str(item.get("category") or "custom").strip() or "custom",
                        coupling=str(item.get("coupling") or "tight").strip().lower() or "tight",
                        default_mode=def_mode,
                        processes=_clean_proc_list(item.get("processes") or []),
                        auth_domains=_clean_domain_list(item.get("auth_domains") or []),
                        download_cdn_domains=_clean_domain_list(item.get("download_cdn_domains") or []),
                        path_patterns=[str(x).strip() for x in (item.get("path_patterns") or []) if str(x).strip()],
                        builtin=False,
                    )
                )

    return bundles


def expand_running_bundle_processes(bundles: list[AppBundle]) -> dict[str, dict[str, Any]]:
    """Inspect active OS processes to detect running bundles and inherit tight child processes."""
    proc_to_bundle: dict[str, AppBundle] = {}
    for b in bundles:
        for p in b.processes:
            proc_to_bundle.setdefault(p.lower(), b)

    pid_info: dict[int, tuple[int, str, str]] = {}
    try:
        for proc in psutil.process_iter(["pid", "ppid", "name", "exe"]):
            info = proc.info
            pid = int(info.get("pid") or 0)
            if pid <= 0:
                continue
            ppid = int(info.get("ppid") or 0)
            name = str(info.get("name") or "").strip()
            exe = str(info.get("exe") or "").strip()
            if name:
                pid_info[pid] = (ppid, name, exe)
    except Exception:
        pid_info = {}

    result: dict[str, dict[str, Any]] = {
        b.id: {"running": False, "processes": set(), "inherited": set(), "path_regexes": set(b.path_patterns)}
        for b in bundles
    }
    matched_pids: dict[int, AppBundle] = {}
    for pid, (_ppid, name, exe) in pid_info.items():
        b = proc_to_bundle.get(name.lower())
        if b is None and exe:
            exe_low = exe.lower()
            for cand in bundles:
                for pat in cand.path_patterns:
                    try:
                        if re.search(pat, exe_low, re.IGNORECASE):
                            b = cand
                            break
                    except re.error:
                        continue
                if b is not None:
                    break
        if b is not None:
            matched_pids[pid] = b
            entry = result[b.id]
            entry["running"] = True
            entry["processes"].add(name)
            if b.coupling == "tight" and exe:
                parent_dir = str(Path(exe).parent)
                if len(parent_dir) > 6 and not parent_dir.lower().endswith("\\system32"):
                    escaped = re.escape(parent_dir)
                    entry["path_regexes"].add(f"(?i)^{escaped}.*")

    # Propagate children of tight bundle processes (multi-hop up to 4 levels)
    for _ in range(4):
        added = False
        for pid, (ppid, name, _exe) in pid_info.items():
            if pid in matched_pids:
                continue
            parent_bundle = matched_pids.get(ppid)
            if parent_bundle is not None and parent_bundle.coupling == "tight":
                matched_pids[pid] = parent_bundle
                entry = result[parent_bundle.id]
                entry["processes"].add(name)
                entry["inherited"].add(name)
                added = True
        if not added:
            break

    return {
        bid: {
            "running": bool(v["running"]),
            "processes": sorted(v["processes"], key=str.lower),
            "inherited": sorted(v["inherited"], key=str.lower),
            "path_regexes": sorted(v["path_regexes"]),
        }
        for bid, v in result.items()
    }


def match_process_to_bundle(
    proc_name: str,
    bundles: list[AppBundle],
    *,
    exe_path: str = "",
    running_map: dict[str, dict[str, Any]] | None = None,
) -> AppBundle | None:
    """Resolve a process name (or inherited running child) to its owning AppBundle."""
    clean = Path(str(proc_name or "").strip().replace("\\", "/")).name.lower()
    if not clean:
        return None
    for b in bundles:
        if any(p.lower() == clean for p in b.processes):
            return b
        if running_map:
            rm = running_map.get(b.id) or {}
            if any(str(p).lower() == clean for p in rm.get("processes") or []):
                return b
        if exe_path and b.path_patterns:
            for pat in b.path_patterns:
                try:
                    if re.search(pat, exe_path, re.IGNORECASE):
                        return b
                except re.error:
                    continue
    return None


def compile_bundle_rules(
    bundles: list[AppBundle],
    mode_map: dict[str, dict[str, Any]] | None = None,
    *,
    running_map: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Compile indivisible sing-box & winws2 routing lists across all configured AppBundles."""
    modes = mode_map or {}
    direct_procs: list[str] = []
    direct_regex: list[str] = []
    direct_domains: list[str] = []
    vpn_procs: list[str] = []
    vpn_regex: list[str] = []
    vpn_domains: list[str] = []
    pass_domains: list[str] = []
    dpi_auth_domains: list[str] = []
    enable_game_udp_dpi = False

    seen_dp: set[str] = set()
    seen_vp: set[str] = set()
    seen_dd: set[str] = set()
    seen_vd: set[str] = set()
    seen_pass: set[str] = set()
    seen_dpi_auth: set[str] = set()

    for b in bundles:
        rec = modes.get(b.id) or {}
        mode = str(rec.get("mode") or b.default_mode or "direct_clean").strip().lower()
        if mode not in BUNDLE_MODES:
            mode = b.default_mode if b.default_mode in BUNDLE_MODES else "direct_clean"
        custom_procs = _clean_proc_list(rec.get("custom_processes") or [])
        inherited = _clean_proc_list((running_map or {}).get(b.id, {}).get("inherited") or [])
        all_procs = _clean_proc_list([*b.processes, *custom_procs, *inherited])
        all_regex = list(dict.fromkeys([*b.path_patterns, *((running_map or {}).get(b.id, {}).get("path_regexes") or [])]))

        # Storefront download CDNs always stay direct so game downloads never saturate VPN
        for cdn in b.download_cdn_domains:
            if cdn not in seen_dd:
                seen_dd.add(cdn)
                direct_domains.append(cdn)

        if mode == "vpn":
            for p in all_procs:
                if p.lower() not in seen_vp:
                    seen_vp.add(p.lower())
                    vpn_procs.append(p)
            for rx in all_regex:
                if rx not in vpn_regex:
                    vpn_regex.append(rx)
            for dom in b.auth_domains:
                if dom not in seen_vd:
                    seen_vd.add(dom)
                    vpn_domains.append(dom)
        else:
            for p in all_procs:
                if p.lower() not in seen_dp:
                    seen_dp.add(p.lower())
                    direct_procs.append(p)
            for rx in all_regex:
                if rx not in direct_regex:
                    direct_regex.append(rx)
            for dom in b.auth_domains:
                if dom not in seen_dd:
                    seen_dd.add(dom)
                    direct_domains.append(dom)
            if mode == "direct_clean":
                for dom in b.auth_domains:
                    if dom not in seen_pass:
                        seen_pass.add(dom)
                        pass_domains.append(dom)
            elif mode == "direct_dpi":
                if b.category == "game":
                    enable_game_udp_dpi = True
                for dom in b.auth_domains:
                    if dom not in seen_dpi_auth:
                        seen_dpi_auth.add(dom)
                        dpi_auth_domains.append(dom)

    return {
        "direct_processes": direct_procs,
        "direct_path_regexes": direct_regex,
        "direct_domains": direct_domains,
        "vpn_processes": vpn_procs,
        "vpn_path_regexes": vpn_regex,
        "vpn_domains": vpn_domains,
        "pass_domains": pass_domains,
        "dpi_auth_domains": dpi_auth_domains,
        "enable_game_udp_dpi": enable_game_udp_dpi,
    }
