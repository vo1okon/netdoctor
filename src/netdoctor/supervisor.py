"""Process supervisor and external binary downloader/verifier for sing-box, winws2, and tg-ws-proxy."""

from __future__ import annotations

import ctypes
import hashlib
import io
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import zipfile
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

import httpx
import psutil


DEFAULT_BIN_DIR = Path("bin")
DEFAULT_LISTS_DIR = Path("lists")
DEFAULT_PRESETS_DIR = Path("presets")
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# Upstream GitHub release metadata for external binaries
UPSTREAM_RELEASES: dict[str, dict[str, str]] = {
    "sing-box": {
        "repo": "SagerNet/sing-box",
        "asset_keyword": "windows-amd64.zip",
        "binary_name": "sing-box.exe",
        "license": "GPL-3.0-or-later (external binary only)",
    },
    "zapret-win-bundle": {
        "repo": "bol-van/zapret-win-bundle",
        "branch_archive": "https://github.com/bol-van/zapret-win-bundle/archive/refs/heads/master.zip",
        "binary_name": "winws2.exe",
        "license": "MIT",
    },
    "tg-ws-proxy": {
        "repo": "Flowseal/tg-ws-proxy",
        "tag": "v1.11.4",
        "exe_url": "https://github.com/Flowseal/tg-ws-proxy/releases/download/v1.11.4/TgWsProxy_windows.exe",
        "source_archive": "https://github.com/Flowseal/tg-ws-proxy/archive/refs/tags/v1.11.4.zip",
        "asset_keyword": "TgWsProxy_windows.exe",
        "binary_name": "TgWsProxy_windows.exe",
        "license": "MIT",
    },
    "zapret-discord-youtube": {
        "repo": "Flowseal/zapret-discord-youtube",
        "tag": "1.10.4",
        "release_archive": "https://github.com/Flowseal/zapret-discord-youtube/releases/download/1.10.4/zapret-discord-youtube-1.10.4.zip",
        "license": "MIT",
    },
    "byedpi": {
        "repo": "hufrea/byedpi",
        "tag": "v0.17.3",
        "release_archive": "https://github.com/hufrea/byedpi/releases/download/v0.17.3/byedpi-17.3-x86_64-w64.zip",
        "asset_keyword": "x86_64-w64.zip",
        "binary_name": "ciadpi.exe",
        "license": "MIT",
    },
    "xray": {
        "repo": "XTLS/Xray-core",
        "asset_keyword": "Xray-windows-64.zip",
        "direct_archive": "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-windows-64.zip",
        "binary_name": "xray.exe",
        "license": "MPL-2.0 (external binary only)",
    },
}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _safe_rel_path(member_name: str, *, strip_root: bool = True) -> PurePosixPath | None:
    """Validate an archive member path against ZipSlip traversal and optionally strip top-level prefix."""
    normalized = member_name.replace("\\", "/").strip()
    if not normalized or normalized.endswith("/"):
        return None
    if normalized.startswith("/") or (len(normalized) >= 2 and normalized[1] == ":"):
        return None
    raw_parts = [p for p in normalized.split("/") if p]
    if not raw_parts:
        return None
    for part in raw_parts:
        if part in (".", "..") or ":" in part or "\x00" in part:
            return None
    parts = raw_parts[1:] if strip_root else raw_parts
    if not parts:
        return None
    return PurePosixPath(*parts)


def _write_bytes_atomic(target: Path, data: bytes) -> Path:
    """Atomically write bytes to target using a temporary file in the same directory."""
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, target)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise
    return target


def _safe_extract_file(dest_root: Path, rel_path: PurePosixPath | Path, data: bytes) -> Path:
    """Write extracted archive bytes ensuring final resolved path stays within dest_root."""
    root_resolved = dest_root.resolve()
    target = (root_resolved / Path(*rel_path.parts)).resolve()
    if not target.is_relative_to(root_resolved):
        raise ValueError(f"Blocked ZipSlip path outside destination: {rel_path}")
    return _write_bytes_atomic(target, data)


def _is_pe_binary(path: Path) -> bool:
    """Return True if path exists, is non-empty, and starts with DOS/PE 'MZ' magic bytes."""
    if not path.is_file():
        return False
    try:
        if path.stat().st_size < 2:
            return False
        with path.open("rb") as f:
            return f.read(2) == b"MZ"
    except OSError:
        return False


def _is_admin() -> bool:
    """Return True if the current Windows process has Administrator privileges."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return False


async def _download_bytes(url: str, *, timeout: float, client: httpx.AsyncClient | None = None) -> bytes:
    if client is not None:
        resp = await client.get(url)
        resp.raise_for_status()
        return resp.content
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as own_client:
        resp = await own_client.get(url)
        resp.raise_for_status()
        return resp.content


async def fetch_singbox_binary(
    bin_dir: Path = DEFAULT_BIN_DIR,
    timeout: float = 60.0,
    *,
    force: bool = False,
    client: httpx.AsyncClient | None = None,
) -> Path:
    """Download latest official SagerNet/sing-box Windows amd64 release binary into bin_dir."""
    bin_dir = Path(bin_dir)
    bin_dir.mkdir(parents=True, exist_ok=True)
    target_exe = bin_dir / "sing-box.exe"
    if target_exe.exists() and not force:
        return target_exe

    async def _fetch_with(active_client: httpx.AsyncClient) -> Path:
        resp = await active_client.get("https://api.github.com/repos/SagerNet/sing-box/releases/latest")
        resp.raise_for_status()
        release = resp.json()
        assets = release.get("assets") or []
        download_url: str | None = None
        for asset in assets:
            name = asset.get("name", "")
            if "windows-amd64.zip" in name and "legacy" not in name:
                download_url = asset.get("browser_download_url")
                break
        if not download_url:
            raise RuntimeError("Could not find windows-amd64.zip asset in SagerNet/sing-box latest release")

        dl_resp = await active_client.get(download_url)
        dl_resp.raise_for_status()

        with zipfile.ZipFile(io.BytesIO(dl_resp.content), "r") as zf:
            for member in zf.namelist():
                rel = _safe_rel_path(member, strip_root=False)
                if rel is not None and rel.name == "sing-box.exe":
                    _write_bytes_atomic(target_exe, zf.read(member))
                    return target_exe
        raise RuntimeError("sing-box.exe not found inside downloaded archive")

    if client is not None:
        return await _fetch_with(client)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as own_client:
        return await _fetch_with(own_client)


async def fetch_xray_binary(
    bin_dir: Path = DEFAULT_BIN_DIR,
    timeout: float = 60.0,
    *,
    force: bool = False,
    client: httpx.AsyncClient | None = None,
) -> Path:
    """Download latest official XTLS/Xray-core Windows amd64 release binary into bin_dir."""
    bin_dir = Path(bin_dir)
    bin_dir.mkdir(parents=True, exist_ok=True)
    target_exe = bin_dir / "xray.exe"
    if target_exe.exists() and not force:
        return target_exe

    async def _fetch_with(active_client: httpx.AsyncClient) -> Path:
        download_url: str | None = None
        try:
            resp = await active_client.get("https://api.github.com/repos/XTLS/Xray-core/releases/latest")
            if resp.is_success:
                release = resp.json()
                assets = release.get("assets") or []
                for asset in assets:
                    name = str(asset.get("name") or "")
                    if name.endswith(".dgst"):
                        continue
                    if "xray-windows-64.zip" in name.lower():
                        download_url = asset.get("browser_download_url")
                        break
        except Exception:  # noqa: BLE001
            download_url = None
        if not download_url:
            download_url = UPSTREAM_RELEASES["xray"]["direct_archive"]

        dl_resp = await active_client.get(download_url)
        dl_resp.raise_for_status()

        with zipfile.ZipFile(io.BytesIO(dl_resp.content), "r") as zf:
            for member in zf.namelist():
                rel = _safe_rel_path(member, strip_root=False)
                if rel is not None and rel.name.lower() == "xray.exe":
                    _write_bytes_atomic(target_exe, zf.read(member))
                    return target_exe
        raise RuntimeError("xray.exe not found inside downloaded archive")

    if client is not None:
        return await _fetch_with(client)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as own_client:
        return await _fetch_with(own_client)


async def fetch_zapret_win_bundle(
    bin_dir: Path = DEFAULT_BIN_DIR,
    *,
    force: bool = False,
    timeout: float = 120.0,
    client: httpx.AsyncClient | None = None,
) -> dict[str, Path]:
    """Download bol-van/zapret-win-bundle master.zip and extract winws2, blockcheck2, tools, and cygwin."""
    bin_dir = Path(bin_dir)
    bin_dir.mkdir(parents=True, exist_ok=True)

    sentinels = {
        "winws2": bin_dir / "winws2.exe",
        "windivert_dll": bin_dir / "WinDivert.dll",
        "windivert_sys": bin_dir / "WinDivert64.sys",
        "cygwin1_dll": bin_dir / "cygwin1.dll",
        "zapret_lib_lua": bin_dir / "lua" / "zapret-lib.lua",
        "windivert_filter_readme": bin_dir / "windivert.filter" / "README.txt",
        "files_quic_google": bin_dir / "files" / "quic_initial_www_google_com.bin",
        "blockcheck2_cmd": bin_dir / "blockcheck" / "blockcheck2.cmd",
        "blockcheck2_sh": bin_dir / "blockcheck" / "zapret2" / "blockcheck2.sh",
        "elevator": bin_dir / "tools" / "elevator.exe",
        "cygwin_bash": bin_dir / "cygwin" / "bin" / "bash.exe",
        "cygwin_cygpath": bin_dir / "cygwin" / "bin" / "cygpath.exe",
    }
    if not force and all(p.exists() and p.stat().st_size > 0 for p in sentinels.values()):
        return sentinels

    url = UPSTREAM_RELEASES["zapret-win-bundle"]["branch_archive"]
    archive_bytes = await _download_bytes(url, timeout=timeout, client=client)

    extracted: dict[str, Path] = {}
    with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            rel = _safe_rel_path(info.filename, strip_root=True)
            if rel is None:
                continue
            parts = rel.parts
            top = parts[0]
            if top == "zapret-winws" and len(parts) > 1:
                sub = PurePosixPath(*parts[1:])
                out = _safe_extract_file(bin_dir, sub, zf.read(info.filename))
                extracted[str(sub)] = out
            elif top in ("blockcheck", "tools", "cygwin") and len(parts) > 1:
                out = _safe_extract_file(bin_dir, rel, zf.read(info.filename))
                extracted[str(rel)] = out

    for key, path in sentinels.items():
        if path.exists():
            extracted.setdefault(key, path)
    return extracted


async def fetch_tg_ws_proxy(
    bin_dir: Path = DEFAULT_BIN_DIR,
    *,
    force: bool = False,
    timeout: float = 120.0,
    client: httpx.AsyncClient | None = None,
) -> dict[str, Path]:
    """Download Flowseal/tg-ws-proxy v1.11.4 Windows exe and headless Python source into bin/tg-ws-proxy/."""
    bin_dir = Path(bin_dir)
    tg_dir = bin_dir / "tg-ws-proxy"
    tg_dir.mkdir(parents=True, exist_ok=True)

    exe_path = tg_dir / "TgWsProxy_windows.exe"
    headless_entry = tg_dir / "proxy" / "tg_ws_proxy.py"
    pyproject_path = tg_dir / "pyproject.toml"
    license_path = tg_dir / "LICENSE"
    utils_init = tg_dir / "utils" / "__init__.py"

    sentinels = [exe_path, headless_entry, pyproject_path, license_path, utils_init]
    if not force and all(p.exists() and p.stat().st_size > 0 for p in sentinels):
        return {
            "exe": exe_path,
            "headless": headless_entry,
            "pyproject": pyproject_path,
            "license": license_path,
        }

    meta = UPSTREAM_RELEASES["tg-ws-proxy"]
    extracted: dict[str, Path] = {}

    exe_bytes = await _download_bytes(meta["exe_url"], timeout=timeout, client=client)
    extracted["exe"] = _write_bytes_atomic(exe_path, exe_bytes)

    src_bytes = await _download_bytes(meta["source_archive"], timeout=timeout, client=client)
    with zipfile.ZipFile(io.BytesIO(src_bytes), "r") as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            rel = _safe_rel_path(info.filename, strip_root=True)
            if rel is None:
                continue
            parts = rel.parts
            if (parts[0] in ("proxy", "utils") and len(parts) > 1) or (
                len(parts) == 1 and parts[0] in ("pyproject.toml", "LICENSE")
            ):
                out = _safe_extract_file(tg_dir, rel, zf.read(info.filename))
                extracted[f"tg-ws-proxy/{rel.as_posix()}"] = out

    extracted["exe"] = exe_path
    extracted["headless"] = headless_entry
    return extracted


async def fetch_zapret_discord_youtube(
    bin_dir: Path = DEFAULT_BIN_DIR,
    lists_dir: Path = DEFAULT_LISTS_DIR,
    presets_dir: Path | None = None,
    *,
    force: bool = False,
    timeout: float = 120.0,
    client: httpx.AsyncClient | None = None,
) -> dict[str, list[Path]]:
    """Download Flowseal/zapret-discord-youtube 1.10.4 zip and extract lists, .bin payloads, and presets."""
    bin_dir = Path(bin_dir).resolve()
    lists_dir = Path(lists_dir).resolve()
    presets_path = Path(presets_dir).resolve() if presets_dir is not None else (bin_dir.parent / "presets")
    zdy_presets_dir = presets_path / "zapret-discord-youtube"
    files_dir = bin_dir / "files"

    lists_dir.mkdir(parents=True, exist_ok=True)
    zdy_presets_dir.mkdir(parents=True, exist_ok=True)
    files_dir.mkdir(parents=True, exist_ok=True)

    sentinel_lists = [
        lists_dir / "list-general.txt",
        lists_dir / "list-google.txt",
        lists_dir / "list-exclude.txt",
        lists_dir / "ipset-exclude.txt",
        lists_dir / "ipset-all.txt",
        lists_dir / "ipset-all.txt.backup",
    ]
    sentinel_presets = [
        zdy_presets_dir / "general.bat",
        zdy_presets_dir / "service.bat",
        zdy_presets_dir / "utils" / "targets.txt",
    ]
    sentinel_bin = files_dir / "tls_clienthello_www_google_com.bin"

    if (
        not force
        and all(p.exists() and p.stat().st_size > 0 for p in sentinel_lists + sentinel_presets)
        and sentinel_bin.exists()
        and sentinel_bin.stat().st_size > 0
    ):
        return {
            "lists": [p for p in sorted(lists_dir.iterdir()) if p.is_file()],
            "blobs": [p for p in sorted(files_dir.glob("*.bin")) if p.is_file()],
            "presets": [p for p in sorted(zdy_presets_dir.rglob("*")) if p.is_file()],
        }

    url = UPSTREAM_RELEASES["zapret-discord-youtube"]["release_archive"]
    archive_bytes = await _download_bytes(url, timeout=timeout, client=client)

    extracted_lists: list[Path] = []
    extracted_blobs: list[Path] = []
    extracted_presets: list[Path] = []

    with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            rel = _safe_rel_path(info.filename, strip_root=True)
            if rel is None:
                continue
            parts = rel.parts
            if parts[0] == "lists" and len(parts) > 1:
                if parts[-1].lower() == "exclude_vpn_ips.txt":
                    continue
                sub = PurePosixPath(*parts[1:])
                out = _safe_extract_file(lists_dir, sub, zf.read(info.filename))
                extracted_lists.append(out)
            elif parts[0] == "bin" and len(parts) == 2 and parts[1].lower().endswith(".bin"):
                # Skip winws.exe, WinDivert.dll, WinDivert64.sys, cygwin1.dll to avoid overwriting zapret-win-bundle
                out = _safe_extract_file(files_dir, PurePosixPath(parts[1]), zf.read(info.filename))
                extracted_blobs.append(out)
            elif len(parts) == 1 and (
                parts[0] == "service.bat" or (parts[0].startswith("general") and parts[0].endswith(".bat"))
            ):
                out = _safe_extract_file(zdy_presets_dir, PurePosixPath(parts[0]), zf.read(info.filename))
                extracted_presets.append(out)
            elif parts == ("utils", "targets.txt"):
                out = _safe_extract_file(zdy_presets_dir, rel, zf.read(info.filename))
                extracted_presets.append(out)

    return {
        "lists": extracted_lists,
        "blobs": extracted_blobs,
        "presets": extracted_presets,
    }


async def fetch_byedpi(
    bin_dir: Path = DEFAULT_BIN_DIR,
    *,
    force: bool = False,
    timeout: float = 60.0,
    client: httpx.AsyncClient | None = None,
) -> Path:
    """Download hufrea/byedpi v0.17.3 Windows x64 zip and extract ciadpi.exe into bin_dir."""
    bin_dir = Path(bin_dir)
    bin_dir.mkdir(parents=True, exist_ok=True)
    target_exe = bin_dir / "ciadpi.exe"
    if target_exe.exists() and not force:
        return target_exe

    url = UPSTREAM_RELEASES["byedpi"]["release_archive"]
    archive_bytes = await _download_bytes(url, timeout=timeout, client=client)

    with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            rel = _safe_rel_path(info.filename, strip_root=False)
            if rel is not None and rel.name.lower() == "ciadpi.exe":
                return _safe_extract_file(bin_dir, PurePosixPath("ciadpi.exe"), zf.read(info.filename))
    raise RuntimeError("ciadpi.exe not found inside hufrea/byedpi archive")


def _file_record(root_kind: str, root_dir: Path, path: Path) -> dict[str, Any]:
    rel = path.resolve().relative_to(root_dir.resolve()).as_posix()
    return {
        "root": root_kind,
        "relpath": rel,
        "size": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def _collect_records(root_kind: str, root_dir: Path, paths: list[Path]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    seen: set[Path] = set()
    for p in paths:
        if p.is_file():
            rp = p.resolve()
            if rp not in seen:
                seen.add(rp)
                records.append(_file_record(root_kind, root_dir, p))
    return sorted(records, key=lambda r: (r["root"], r["relpath"]))


async def fetch_all_bins(
    bin_dir: Path = DEFAULT_BIN_DIR,
    lists_dir: Path = DEFAULT_LISTS_DIR,
    presets_dir: Path | None = None,
    *,
    force: bool = False,
    timeout: float = 120.0,
    client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    """Orchestrate all 5 upstream artifact fetchers, keeping existing sing-box.exe protected, and write manifest.json."""
    bin_dir = Path(bin_dir).resolve()
    lists_dir = Path(lists_dir).resolve()
    presets_path = Path(presets_dir).resolve() if presets_dir is not None else (bin_dir.parent / "presets")
    bin_dir.mkdir(parents=True, exist_ok=True)
    lists_dir.mkdir(parents=True, exist_ok=True)
    presets_path.mkdir(parents=True, exist_ok=True)

    singbox_preexisted = (bin_dir / "sing-box.exe").exists()

    async def _run(active_client: httpx.AsyncClient) -> dict[str, Any]:
        # Protect pre-existing sing-box.exe unless missing (always force=False)
        singbox_exe = await fetch_singbox_binary(bin_dir, timeout=timeout, force=False, client=active_client)
        zapret_files = await fetch_zapret_win_bundle(bin_dir, force=force, timeout=timeout, client=active_client)
        tg_files = await fetch_tg_ws_proxy(bin_dir, force=force, timeout=timeout, client=active_client)
        zdy_files = await fetch_zapret_discord_youtube(
            bin_dir, lists_dir, presets_path, force=force, timeout=timeout, client=active_client
        )
        ciadpi_exe = await fetch_byedpi(bin_dir, force=force, timeout=timeout, client=active_client)

        zapret_tracked = [
            bin_dir / "winws2.exe",
            bin_dir / "WinDivert.dll",
            bin_dir / "WinDivert64.sys",
            bin_dir / "cygwin1.dll",
            *(sorted((bin_dir / "lua").glob("*.lua")) if (bin_dir / "lua").exists() else []),
            *(sorted((bin_dir / "windivert.filter").glob("*")) if (bin_dir / "windivert.filter").exists() else []),
            bin_dir / "blockcheck" / "blockcheck2.cmd",
            bin_dir / "blockcheck" / "blockcheck2-kyber.cmd",
            bin_dir / "blockcheck" / "zapret2" / "blockcheck2.sh",
            bin_dir / "tools" / "elevator.exe",
            bin_dir / "cygwin" / "bin" / "bash.exe",
            bin_dir / "cygwin" / "bin" / "cygpath.exe",
        ]
        tg_tracked = [
            bin_dir / "tg-ws-proxy" / "TgWsProxy_windows.exe",
            *(sorted((bin_dir / "tg-ws-proxy" / "proxy").rglob("*.py")) if (bin_dir / "tg-ws-proxy" / "proxy").exists() else []),
            *(sorted((bin_dir / "tg-ws-proxy" / "utils").rglob("*.py")) if (bin_dir / "tg-ws-proxy" / "utils").exists() else []),
            bin_dir / "tg-ws-proxy" / "pyproject.toml",
            bin_dir / "tg-ws-proxy" / "LICENSE",
        ]
        zdy_bin_tracked = sorted((bin_dir / "files").glob("*.bin")) if (bin_dir / "files").exists() else []
        zdy_list_tracked = [
            lists_dir / name
            for name in (
                "list-general.txt",
                "list-google.txt",
                "list-exclude.txt",
                "ipset-exclude.txt",
                "ipset-all.txt",
                "ipset-all.txt.backup",
            )
            if (lists_dir / name).exists()
        ]
        zdy_preset_tracked = (
            sorted((presets_path / "zapret-discord-youtube").rglob("*"))
            if (presets_path / "zapret-discord-youtube").exists()
            else []
        )

        manifest_data: dict[str, Any] = {
            "schema_version": 1,
            "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "artifacts": {
                "sing-box": {
                    "source": "preinstalled" if singbox_preexisted else UPSTREAM_RELEASES["sing-box"]["repo"],
                    "protected": True,
                    "files": _collect_records("bin", bin_dir, [singbox_exe]),
                },
                "zapret-win-bundle": {
                    "source": UPSTREAM_RELEASES["zapret-win-bundle"]["branch_archive"],
                    "files": _collect_records("bin", bin_dir, zapret_tracked),
                },
                "tg-ws-proxy": {
                    "tag": UPSTREAM_RELEASES["tg-ws-proxy"]["tag"],
                    "source": UPSTREAM_RELEASES["tg-ws-proxy"]["source_archive"],
                    "exe_url": UPSTREAM_RELEASES["tg-ws-proxy"]["exe_url"],
                    "files": _collect_records("bin", bin_dir, tg_tracked),
                },
                "zapret-discord-youtube": {
                    "tag": UPSTREAM_RELEASES["zapret-discord-youtube"]["tag"],
                    "source": UPSTREAM_RELEASES["zapret-discord-youtube"]["release_archive"],
                    "files": [
                        *_collect_records("bin", bin_dir, zdy_bin_tracked),
                        *_collect_records("lists", lists_dir, zdy_list_tracked),
                        *_collect_records("presets", presets_path, zdy_preset_tracked),
                    ],
                },
                "byedpi": {
                    "tag": UPSTREAM_RELEASES["byedpi"]["tag"],
                    "source": UPSTREAM_RELEASES["byedpi"]["release_archive"],
                    "files": _collect_records("bin", bin_dir, [ciadpi_exe]),
                },
            },
        }
        manifest_path = bin_dir / "manifest.json"
        _write_bytes_atomic(manifest_path, (json.dumps(manifest_data, indent=2) + "\n").encode("utf-8"))
        return {
            "manifest_path": manifest_path,
            "sing-box": singbox_exe,
            "zapret-win-bundle": zapret_files,
            "tg-ws-proxy": tg_files,
            "zapret-discord-youtube": zdy_files,
            "byedpi": ciadpi_exe,
        }

    if client is not None:
        return await _run(client)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as own_client:
        return await _run(own_client)


def verify_binaries(
    bin_dir: str | Path = DEFAULT_BIN_DIR,
    lists_dir: str | Path = DEFAULT_LISTS_DIR,
    presets_dir: str | Path | None = None,
    *,
    run_checks: bool = True,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Verify presence, PE headers, companion files, manifest hashes, and non-destructive runnability."""
    bin_path = Path(bin_dir).resolve()
    lists_path = Path(lists_dir).resolve()
    presets_path = Path(presets_dir).resolve() if presets_dir is not None else (bin_path.parent / "presets")
    is_admin = _is_admin()

    tools: dict[str, dict[str, Any]] = {}

    # 1. sing-box
    sb_exe = bin_path / "sing-box.exe"
    sb_pe = _is_pe_binary(sb_exe)
    sb_info: dict[str, Any] = {
        "exists": sb_exe.is_file(),
        "pe_valid": sb_pe,
        "path": str(sb_exe),
        "size": sb_exe.stat().st_size if sb_exe.is_file() else 0,
        "sha256": sha256_file(sb_exe) if sb_exe.is_file() else None,
        "runnable": None,
        "version": None,
        "config_checked": False,
        "config_ok": None,
        "status": "missing",
        "detail": "",
    }
    if sb_pe:
        if run_checks:
            try:
                proc = subprocess.run(
                    [str(sb_exe), "version"],
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=timeout,
                    creationflags=_NO_WINDOW,
                )
                out = (proc.stdout or proc.stderr or "").strip()
                first_line = out.splitlines()[0] if out else ""
                sb_info["version"] = first_line
                sb_info["runnable"] = proc.returncode == 0
                cfg = bin_path.resolve().parent / "configs" / "sing-box.json"
                if cfg.is_file():
                    sb_info["config_checked"] = True
                    chk = subprocess.run(
                        [str(sb_exe), "check", "-c", str(cfg)],
                        stdin=subprocess.DEVNULL,
                        capture_output=True,
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                        timeout=timeout,
                        creationflags=_NO_WINDOW,
                    )
                    sb_info["config_ok"] = chk.returncode == 0
                    if chk.returncode != 0:
                        sb_info["status"] = "error"
                        sb_info["detail"] = (chk.stderr or chk.stdout or "sing-box check failed").strip()
                if sb_info["status"] != "error":
                    if sb_info["runnable"]:
                        sb_info["status"] = "ok"
                        sb_info["detail"] = first_line or "ok"
                    else:
                        sb_info["status"] = "error"
                        sb_info["detail"] = f"version exit {proc.returncode}"
            except Exception as exc:
                sb_info["runnable"] = False
                sb_info["status"] = "error"
                sb_info["detail"] = str(exc)
        else:
            sb_info["status"] = "ok"
            sb_info["detail"] = "PE present (checks skipped)"
    elif sb_exe.is_file():
        sb_info["status"] = "error"
        sb_info["detail"] = "Invalid PE header"
    else:
        sb_info["detail"] = "sing-box.exe not found"
    tools["sing-box"] = sb_info

    # 2. winws2
    winws_exe = bin_path / "winws2.exe"
    winws_pe = _is_pe_binary(winws_exe)
    lua_files = list((bin_path / "lua").glob("*.lua")) if (bin_path / "lua").is_dir() else []
    files_entries = [p for p in (bin_path / "files").iterdir() if p.is_file()] if (bin_path / "files").is_dir() else []
    filter_entries = (
        [p for p in (bin_path / "windivert.filter").iterdir() if p.is_file()]
        if (bin_path / "windivert.filter").is_dir()
        else []
    )
    supporting = {
        "WinDivert.dll": (bin_path / "WinDivert.dll").is_file() and (bin_path / "WinDivert.dll").stat().st_size > 0,
        "WinDivert64.sys": (bin_path / "WinDivert64.sys").is_file() and (bin_path / "WinDivert64.sys").stat().st_size > 0,
        "cygwin1.dll": (bin_path / "cygwin1.dll").is_file() and (bin_path / "cygwin1.dll").stat().st_size > 0,
        "lua": len(lua_files) >= 1,
        "files": len(files_entries) >= 1,
        "windivert.filter": len(filter_entries) >= 1,
    }
    winws_info: dict[str, Any] = {
        "exists": winws_exe.is_file(),
        "pe_valid": winws_pe,
        "path": str(winws_exe),
        "size": winws_exe.stat().st_size if winws_exe.is_file() else 0,
        "sha256": sha256_file(winws_exe) if winws_exe.is_file() else None,
        "supporting_files": supporting,
        "uac_required": False,
        "runnable": None,
        "status": "missing",
        "detail": "",
    }
    if winws_pe and all(supporting.values()):
        if run_checks:
            try:
                proc = subprocess.run(
                    [str(winws_exe.resolve()), "--version"],
                    cwd=str(bin_path.resolve()),
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=timeout,
                    creationflags=_NO_WINDOW,
                )
                combined = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
                if proc.returncode in (0, 1):
                    winws_info["runnable"] = True
                    winws_info["status"] = "ok"
                    winws_info["detail"] = combined.splitlines()[0] if combined else f"exit {proc.returncode}"
                else:
                    winws_info["runnable"] = False
                    winws_info["status"] = "error"
                    winws_info["detail"] = f"exit {proc.returncode}"
            except OSError as exc:
                if getattr(exc, "winerror", None) == 740:
                    winws_info["uac_required"] = True
                    winws_info["runnable"] = None
                    winws_info["status"] = "warn_uac"
                    winws_info["detail"] = "Requires UAC elevation (WinError 740); binary & supporting files present"
                else:
                    winws_info["runnable"] = False
                    winws_info["status"] = "error"
                    winws_info["detail"] = str(exc)
            except Exception as exc:
                winws_info["runnable"] = False
                winws_info["status"] = "error"
                winws_info["detail"] = str(exc)
        else:
            winws_info["status"] = "ok"
            winws_info["detail"] = "PE & companion files present (checks skipped)"
    else:
        missing_parts = [k for k, v in supporting.items() if not v]
        winws_info["status"] = "missing" if not winws_exe.is_file() else "error"
        winws_info["detail"] = (
            "winws2.exe missing or invalid PE"
            if not winws_pe
            else f"Missing supporting files: {', '.join(missing_parts)}"
        )
    tools["winws2"] = winws_info

    # 3. blockcheck2
    bc_cmd = bin_path / "blockcheck" / "blockcheck2.cmd"
    bc_sh = bin_path / "blockcheck" / "zapret2" / "blockcheck2.sh"
    bc_fake_dir = bin_path / "blockcheck" / "zapret" / "files" / "fake"
    bc_bash = bin_path / "cygwin" / "bin" / "bash.exe"
    bc_cygpath = bin_path / "cygwin" / "bin" / "cygpath.exe"
    bc_elevator = bin_path / "tools" / "elevator.exe"
    bc_checks = {
        "blockcheck2.cmd": bc_cmd.is_file() and bc_cmd.stat().st_size > 0,
        "blockcheck2.sh": bc_sh.is_file() and bc_sh.stat().st_size > 0,
        "fake_payloads": bc_fake_dir.is_dir() and any(bc_fake_dir.iterdir()),
        "cygwin_bash": _is_pe_binary(bc_bash),
        "cygwin_cygpath": _is_pe_binary(bc_cygpath),
        "elevator": _is_pe_binary(bc_elevator),
    }
    bc_info: dict[str, Any] = {
        "exists": bc_cmd.is_file(),
        "path": str(bc_cmd),
        "sha256": sha256_file(bc_cmd) if bc_cmd.is_file() else None,
        "components": bc_checks,
        "runnable": None,
        "status": "missing",
        "detail": "",
    }
    if all(bc_checks.values()):
        if run_checks:
            try:
                proc = subprocess.run(
                    [str(bc_cygpath), "--help"],
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=timeout,
                    creationflags=_NO_WINDOW,
                )
                bc_info["runnable"] = proc.returncode == 0
                if proc.returncode == 0:
                    bc_info["status"] = "ok"
                    bc_info["detail"] = "blockcheck2 tree & cygpath verified"
                else:
                    bc_info["status"] = "error"
                    bc_info["detail"] = f"cygpath --help exit {proc.returncode}"
            except Exception as exc:
                bc_info["runnable"] = False
                bc_info["status"] = "error"
                bc_info["detail"] = str(exc)
        else:
            bc_info["status"] = "ok"
            bc_info["detail"] = "blockcheck2 tree present"
    else:
        missing_bc = [k for k, v in bc_checks.items() if not v]
        bc_info["status"] = "missing" if not bc_cmd.is_file() else "error"
        bc_info["detail"] = f"Missing blockcheck2 components: {', '.join(missing_bc)}"
    tools["blockcheck2"] = bc_info

    # 4. ciadpi (byedpi)
    ciadpi_exe = bin_path / "ciadpi.exe"
    ciadpi_pe = _is_pe_binary(ciadpi_exe)
    ciadpi_info: dict[str, Any] = {
        "exists": ciadpi_exe.is_file(),
        "pe_valid": ciadpi_pe,
        "path": str(ciadpi_exe),
        "size": ciadpi_exe.stat().st_size if ciadpi_exe.is_file() else 0,
        "sha256": sha256_file(ciadpi_exe) if ciadpi_exe.is_file() else None,
        "runnable": None,
        "status": "missing",
        "detail": "",
    }
    if ciadpi_pe:
        if run_checks:
            try:
                proc = subprocess.run(
                    [str(ciadpi_exe), "--help"],
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=timeout,
                    creationflags=_NO_WINDOW,
                )
                combined = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
                ciadpi_info["runnable"] = proc.returncode == 0 or ("usage" in combined.lower() or "--port" in combined.lower())
                if ciadpi_info["runnable"]:
                    ciadpi_info["status"] = "ok"
                    ciadpi_info["detail"] = combined.splitlines()[0] if combined else "ok"
                else:
                    ciadpi_info["status"] = "error"
                    ciadpi_info["detail"] = f"ciadpi --help exit {proc.returncode}"
            except Exception as exc:
                ciadpi_info["runnable"] = False
                ciadpi_info["status"] = "error"
                ciadpi_info["detail"] = str(exc)
        else:
            ciadpi_info["status"] = "ok"
            ciadpi_info["detail"] = "PE present"
    elif ciadpi_exe.is_file():
        ciadpi_info["status"] = "error"
        ciadpi_info["detail"] = "Invalid PE header"
    else:
        ciadpi_info["detail"] = "ciadpi.exe not found"
    tools["ciadpi"] = ciadpi_info

    # 5. tg-ws-proxy
    tg_dir = bin_path / "tg-ws-proxy"
    tg_exe = tg_dir / "TgWsProxy_windows.exe"
    tg_script = tg_dir / "proxy" / "tg_ws_proxy.py"
    tg_exe_pe = _is_pe_binary(tg_exe)
    tg_info: dict[str, Any] = {
        "exists": tg_exe.is_file() and tg_script.is_file(),
        "exe_exists": tg_exe.is_file(),
        "exe_pe_valid": tg_exe_pe,
        "headless_exists": tg_script.is_file(),
        "path": str(tg_script),
        "exe_path": str(tg_exe),
        "sha256": sha256_file(tg_exe) if tg_exe.is_file() else None,
        "headless_sha256": sha256_file(tg_script) if tg_script.is_file() else None,
        "runnable": None,
        "status": "missing",
        "detail": "",
    }
    if tg_exe_pe and tg_script.is_file() and tg_script.stat().st_size > 0:
        if run_checks:
            try:
                proc = subprocess.run(
                    [sys.executable, str(tg_script.resolve()), "--help"],
                    cwd=str(tg_dir.resolve()),
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=timeout,
                    creationflags=_NO_WINDOW,
                )
                tg_info["runnable"] = proc.returncode == 0
                if proc.returncode == 0:
                    tg_info["status"] = "ok"
                    tg_info["detail"] = "TgWsProxy_windows.exe PE + headless --help ok"
                else:
                    tg_info["status"] = "error"
                    tg_info["detail"] = (proc.stderr or proc.stdout or f"exit {proc.returncode}").strip()
            except Exception as exc:
                tg_info["runnable"] = False
                tg_info["status"] = "error"
                tg_info["detail"] = str(exc)
        else:
            tg_info["status"] = "ok"
            tg_info["detail"] = "TgWsProxy_windows.exe PE & headless script present"
    else:
        tg_info["status"] = "missing" if not (tg_exe.is_file() or tg_script.is_file()) else "error"
        tg_info["detail"] = "Missing TgWsProxy_windows.exe (valid PE) or proxy/tg_ws_proxy.py"
    tools["tg-ws-proxy"] = tg_info

    # 6. lists
    required_lists = (
        "list-general.txt",
        "list-google.txt",
        "list-exclude.txt",
        "ipset-exclude.txt",
        "ipset-all.txt",
        "ipset-all.txt.backup",
    )
    list_files_info: dict[str, dict[str, Any]] = {}
    missing_lists: list[str] = []
    for fname in required_lists:
        fpath = lists_path / fname
        ok_file = fpath.is_file() and fpath.stat().st_size > 0
        list_files_info[fname] = {
            "exists": fpath.is_file(),
            "size": fpath.stat().st_size if fpath.is_file() else 0,
            "ok": ok_file,
        }
        if not ok_file:
            missing_lists.append(fname)
    bin_blobs = list((bin_path / "files").glob("*.bin")) if (bin_path / "files").is_dir() else []
    lists_ok = not missing_lists and len(bin_blobs) >= 1
    lists_report: dict[str, Any] = {
        "path": str(lists_path),
        "files": list_files_info,
        "bin_blobs_count": len(bin_blobs),
        "status": "ok" if lists_ok else "error",
        "detail": (
            f"{len(required_lists)} lists + {len(bin_blobs)} .bin payloads ok"
            if lists_ok
            else f"Missing lists={missing_lists}, .bin count={len(bin_blobs)}"
        ),
    }

    # 7. presets
    zdy_presets = presets_path / "zapret-discord-youtube"
    bat_files = list(zdy_presets.glob("general*.bat")) if zdy_presets.is_dir() else []
    targets_txt = zdy_presets / "utils" / "targets.txt"
    presets_ok = zdy_presets.is_dir() and len(bat_files) >= 1 and targets_txt.is_file() and targets_txt.stat().st_size > 0
    presets_report: dict[str, Any] = {
        "path": str(zdy_presets),
        "bat_count": len(bat_files),
        "targets_exists": targets_txt.is_file(),
        "status": "ok" if presets_ok else "error",
        "detail": (
            f"{len(bat_files)} general*.bat presets + utils/targets.txt ok"
            if presets_ok
            else "Missing general*.bat presets or utils/targets.txt"
        ),
    }

    # 8. manifest.json integrity
    manifest_file = bin_path / "manifest.json"
    manifest_report: dict[str, Any] = {
        "path": str(manifest_file),
        "exists": manifest_file.is_file(),
        "checked_files": 0,
        "mismatches": [],
        "status": "missing",
        "detail": "",
    }
    if manifest_file.is_file():
        try:
            manifest_obj = json.loads(manifest_file.read_text(encoding="utf-8"))
            artifacts = manifest_obj.get("artifacts", {})
            if not isinstance(artifacts, dict):
                raise ValueError("artifacts must be a JSON object")
            root_map = {
                "bin": bin_path.resolve(),
                "lists": lists_path.resolve(),
                "presets": presets_path.resolve(),
            }
            checked = 0
            mismatches: list[str] = []
            present_entries: set[tuple[str, str, str]] = set()
            for art_name, art_val in artifacts.items():
                if not isinstance(art_val, dict):
                    checked += 1
                    mismatches.append(f"{art_name}:invalid_artifact_entry")
                    continue
                files_list = art_val.get("files", [])
                if not isinstance(files_list, list):
                    checked += 1
                    mismatches.append(f"{art_name}:invalid_files_list")
                    continue
                for rec in files_list:
                    checked += 1
                    if not isinstance(rec, dict):
                        mismatches.append(f"{art_name}:invalid_record")
                        continue
                    root_key = rec.get("root")
                    relpath = rec.get("relpath", "")
                    if not isinstance(root_key, str) or root_key not in root_map:
                        mismatches.append(f"{art_name}:{relpath}:unknown_root:{root_key}")
                        continue
                    if not isinstance(relpath, str) or not relpath.strip():
                        mismatches.append(f"{art_name}:{relpath}:empty_relpath")
                        continue
                    if relpath.startswith(("/", "\\")) or ":" in relpath or "\x00" in relpath:
                        mismatches.append(f"{art_name}:{relpath}:path_traversal")
                        continue
                    norm_rel = relpath.replace("\\", "/")
                    if any(part in ("", ".", "..") for part in norm_rel.split("/")):
                        mismatches.append(f"{art_name}:{relpath}:path_traversal")
                        continue
                    root_resolved = root_map[root_key]
                    target_resolved = (root_resolved / norm_rel).resolve()
                    if target_resolved == root_resolved or not target_resolved.is_relative_to(root_resolved):
                        mismatches.append(f"{art_name}:{relpath}:path_traversal")
                        continue
                    present_entries.add((art_name, root_key, norm_rel))
                    if not target_resolved.is_file():
                        mismatches.append(f"{art_name}:{relpath}:missing")
                    elif target_resolved.stat().st_size != rec.get("size"):
                        mismatches.append(f"{art_name}:{relpath}:size_mismatch")
                    elif sha256_file(target_resolved) != rec.get("sha256"):
                        mismatches.append(f"{art_name}:{relpath}:sha256_mismatch")

            required_manifest_entries: tuple[tuple[str, str, str], ...] = (
                ("sing-box", "bin", "sing-box.exe"),
                ("zapret-win-bundle", "bin", "winws2.exe"),
                ("zapret-win-bundle", "bin", "WinDivert.dll"),
                ("zapret-win-bundle", "bin", "WinDivert64.sys"),
                ("zapret-win-bundle", "bin", "cygwin1.dll"),
                ("zapret-win-bundle", "bin", "blockcheck/blockcheck2.cmd"),
                ("byedpi", "bin", "ciadpi.exe"),
                ("tg-ws-proxy", "bin", "tg-ws-proxy/TgWsProxy_windows.exe"),
                ("tg-ws-proxy", "bin", "tg-ws-proxy/proxy/tg_ws_proxy.py"),
                ("zapret-discord-youtube", "lists", "list-general.txt"),
                ("zapret-discord-youtube", "lists", "list-google.txt"),
                ("zapret-discord-youtube", "lists", "list-exclude.txt"),
                ("zapret-discord-youtube", "lists", "ipset-exclude.txt"),
                ("zapret-discord-youtube", "lists", "ipset-all.txt"),
                ("zapret-discord-youtube", "lists", "ipset-all.txt.backup"),
                ("zapret-discord-youtube", "presets", "zapret-discord-youtube/general.bat"),
                ("zapret-discord-youtube", "presets", "zapret-discord-youtube/utils/targets.txt"),
            )
            for req_art, req_root, req_rel in required_manifest_entries:
                if (req_art, req_root, req_rel) not in present_entries:
                    mismatches.append(f"{req_art}:{req_rel}:missing_from_manifest")

            manifest_report["checked_files"] = checked
            manifest_report["mismatches"] = mismatches
            if checked > 0 and not mismatches:
                manifest_report["status"] = "ok"
                manifest_report["detail"] = f"{checked} files match manifest SHA256"
            else:
                manifest_report["status"] = "error"
                manifest_report["detail"] = (
                    "Empty manifest" if checked == 0 and not mismatches else f"Mismatches: {', '.join(mismatches[:5])}"
                )
        except Exception as exc:
            manifest_report["status"] = "error"
            manifest_report["detail"] = f"Invalid manifest.json: {exc}"
    else:
        manifest_report["detail"] = "manifest.json not found"

    overall_ok = (
        all(t["status"] in ("ok", "warn_uac") for t in tools.values())
        and lists_report["status"] == "ok"
        and presets_report["status"] == "ok"
        and manifest_report["status"] == "ok"
    )
    return {
        "ok": overall_ok,
        "is_admin": is_admin,
        "tools": tools,
        "lists": lists_report,
        "presets": presets_report,
        "manifest": manifest_report,
    }


def _is_pid_running(pid: int | None, expected_create_time: float | None = None) -> bool:
    if not isinstance(pid, int) or pid <= 0:
        return False
    try:
        if not psutil.pid_exists(pid):
            return False
        proc = psutil.Process(pid)
        if not proc.is_running() or proc.status() == psutil.STATUS_ZOMBIE:
            return False
        if (
            isinstance(expected_create_time, (int, float))
            and not isinstance(expected_create_time, bool)
            and expected_create_time > 0
        ):
            try:
                if abs(float(proc.create_time()) - float(expected_create_time)) > 2.0:
                    return False
            except psutil.NoSuchProcess:
                return False
            except (psutil.AccessDenied, ValueError, OSError):
                pass
        return True
    except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError):
        return False


def inspect_supervisor_state(
    state_path: str | Path | None = None,
    logs_dir: str | Path = Path("logs"),
) -> dict[str, dict[str, Any]]:
    """Read supervisor_state.json safely and check live OS status for each recorded PID."""
    resolved_state = Path(state_path) if state_path is not None else (Path(logs_dir) / "supervisor_state.json")
    if not resolved_state.is_file():
        return {}
    try:
        data = json.loads(resolved_state.read_text(encoding="utf-8"))
    except Exception:
        return {}
    procs = data.get("processes") if isinstance(data, dict) else None
    if not isinstance(procs, dict):
        return {}

    result: dict[str, dict[str, Any]] = {}
    for name, info in procs.items():
        pid = info.get("pid") if isinstance(info, dict) else None
        expected_ct = info.get("create_time") if isinstance(info, dict) else None
        alive = _is_pid_running(pid, expected_create_time=expected_ct)
        result[str(name)] = {
            "pid": pid,
            "running": alive,
            "status": "running" if alive else "stopped",
        }
    return result


def stop_persisted_supervisor(
    state_path: str | Path | None = None,
    logs_dir: str | Path = Path("logs"),
    bin_dir: str | Path | None = None,
) -> list[str]:
    """Stop any live processes (and child process trees) recorded in supervisor_state.json in reverse order."""
    resolved_state = Path(state_path) if state_path is not None else (Path(logs_dir) / "supervisor_state.json")
    procs: dict[str, Any] = {}
    if resolved_state.is_file():
        try:
            data = json.loads(resolved_state.read_text(encoding="utf-8"))
            raw_procs = data.get("processes") if isinstance(data, dict) else None
            if isinstance(raw_procs, dict):
                procs = raw_procs
        except Exception:
            procs = {}

    stopped: list[str] = []
    for name in reversed(list(procs.keys())):
        info = procs.get(name)
        pid = info.get("pid") if isinstance(info, dict) else None
        expected_ct = info.get("create_time") if isinstance(info, dict) else None
        if _is_pid_running(pid, expected_create_time=expected_ct):
            try:
                if terminate_process_tree(int(pid)):
                    stopped.append(str(name))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired, OSError, ValueError):
                pass

    if bin_dir is not None:
        for orphan_name in cleanup_orphaned_service_processes(bin_dir):
            if orphan_name not in stopped:
                stopped.append(orphan_name)

    ports_to_wait: list[int] = []
    for name in stopped:
        ports_to_wait.extend(SERVICE_PORTS.get(name, ()))
    if ports_to_wait:
        wait_ports_released(ports_to_wait, timeout=3.0)

    if resolved_state.is_file() or stopped:
        _write_bytes_atomic(resolved_state, b'{"processes": {}}\n')
    return stopped


SERVICE_PORTS: dict[str, tuple[int, ...]] = {
    "sing-box": (2080, 19090),
    "tg-ws-proxy": (10808,),
    "byedpi": (10809,),
    "xray": (18100,),
}


def is_local_port_busy(port: int, host: str = "127.0.0.1") -> bool:
    """Return True if binding ``host:port`` fails (port already occupied)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        sock.bind((host, int(port)))
        return False
    except OSError:
        return True
    finally:
        sock.close()


def wait_ports_released(
    ports: Sequence[int],
    timeout: float = 3.0,
    host: str = "127.0.0.1",
) -> list[int]:
    """Poll until all given local TCP ports become bindable or timeout expires; returns still-busy ports."""
    unique_ports = list(dict.fromkeys(int(p) for p in ports if int(p) > 0))
    if not unique_ports:
        return []
    deadline = time.monotonic() + max(0.0, float(timeout))
    while True:
        busy = [p for p in unique_ports if is_local_port_busy(p, host=host)]
        if not busy or time.monotonic() >= deadline:
            return busy
        time.sleep(0.05)


def terminate_process_tree(
    pid: int,
    *,
    extra_pids: Sequence[int] | None = None,
    graceful_timeout: float = 1.5,
    kill_timeout: float = 2.0,
) -> bool:
    """Terminate and reap a process along with its recursive children and any pre-snapshotted extra PIDs."""
    self_pid = os.getpid()
    seen_pids: set[int] = set()
    targets: list[psutil.Process] = []

    def _add_proc(p: psutil.Process) -> None:
        try:
            p_pid = int(p.pid)
        except (psutil.Error, ValueError, TypeError):
            return
        if p_pid <= 0 or p_pid == self_pid or p_pid in seen_pids:
            return
        seen_pids.add(p_pid)
        targets.append(p)

    # Snapshot children BEFORE terminating parent so Windows venv launcher children are never orphaned
    if isinstance(pid, int) and pid > 0 and pid != self_pid:
        try:
            root = psutil.Process(pid)
            for child in root.children(recursive=True):
                _add_proc(child)
            _add_proc(root)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.Error, OSError):
            pass

    for raw_ep in extra_pids or ():
        try:
            ep = int(raw_ep)
        except (TypeError, ValueError):
            continue
        if ep <= 0 or ep == self_pid or ep in seen_pids:
            continue
        try:
            ep_proc = psutil.Process(ep)
            for child in ep_proc.children(recursive=True):
                _add_proc(child)
            _add_proc(ep_proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.Error, OSError):
            pass

    if not targets:
        return False

    acted = False
    for p in targets:
        try:
            if p.is_running():
                p.terminate()
                acted = True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.Error, OSError):
            pass

    try:
        _gone, alive = psutil.wait_procs(targets, timeout=max(0.1, float(graceful_timeout)))
    except Exception:
        alive = [p for p in targets if p.is_running()]

    if alive:
        for p in alive:
            try:
                if p.is_running():
                    p.kill()
                    acted = True
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.Error, OSError):
                pass
        try:
            psutil.wait_procs(alive, timeout=max(0.1, float(kill_timeout)))
        except Exception:
            pass

    return acted


def cleanup_orphaned_service_processes(
    bin_dir: str | Path,
    names: Sequence[str] | None = None,
) -> list[str]:
    """Terminate leftover netdoctor service processes (or venv child interpreters) scoped strictly to bin_dir."""
    bin_path = Path(bin_dir).resolve()
    target_names = set(names) if names is not None else {"tg-ws-proxy", "sing-box", "winws2", "byedpi", "xray"}

    def _norm(p: str | Path) -> str:
        return os.path.normcase(os.path.normpath(str(p)))

    tg_dir_norm = _norm((bin_path / "tg-ws-proxy").resolve())
    tg_script_norm = _norm((bin_path / "tg-ws-proxy" / "proxy" / "tg_ws_proxy.py").resolve())
    tg_exe_norm = _norm((bin_path / "tg-ws-proxy" / "TgWsProxy_windows.exe").resolve())
    sb_exe_norm = _norm((bin_path / "sing-box.exe").resolve())
    winws_exe_norm = _norm((bin_path / "winws2.exe").resolve())
    ciadpi_exe_norm = _norm((bin_path / "ciadpi.exe").resolve())
    xray_exe_norm = _norm((bin_path / "xray.exe").resolve())

    self_pid = os.getpid()
    matches: list[tuple[str, int]] = []

    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
        try:
            info = proc.info if isinstance(proc.info, dict) else {}
            pid = int(info.get("pid") or 0)
            if pid <= 0 or pid == self_pid:
                continue
            exe_raw = str(info.get("exe") or "").strip()
            exe_norm = _norm(exe_raw) if exe_raw else ""
            cmdline = [str(a) for a in (info.get("cmdline") or []) if a]
            cmd_norms = [_norm(a) for a in cmdline]

            svc_match: str | None = None
            if "sing-box" in target_names and (
                exe_norm == sb_exe_norm or (cmd_norms and cmd_norms[0] == sb_exe_norm)
            ):
                svc_match = "sing-box"
            elif "winws2" in target_names and (
                exe_norm == winws_exe_norm or (cmd_norms and cmd_norms[0] == winws_exe_norm)
            ):
                svc_match = "winws2"
            elif "byedpi" in target_names and (
                exe_norm == ciadpi_exe_norm or (cmd_norms and cmd_norms[0] == ciadpi_exe_norm)
            ):
                svc_match = "byedpi"
            elif "xray" in target_names and (
                exe_norm == xray_exe_norm or (cmd_norms and cmd_norms[0] == xray_exe_norm)
            ):
                svc_match = "xray"
            elif "tg-ws-proxy" in target_names:
                if exe_norm == tg_exe_norm or (cmd_norms and cmd_norms[0] == tg_exe_norm):
                    svc_match = "tg-ws-proxy"
                elif any(
                    cn == tg_script_norm or (cn.endswith("tg_ws_proxy.py") and tg_dir_norm in cn)
                    for cn in cmd_norms
                ):
                    svc_match = "tg-ws-proxy"

            if svc_match is not None:
                matches.append((svc_match, pid))
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError, ValueError):
            continue

    cleaned: list[str] = []
    for svc_name, pid in matches:
        try:
            if terminate_process_tree(pid) and svc_name not in cleaned:
                cleaned.append(svc_name)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired, OSError):
            pass
    return cleaned


def validate_singbox_config(bin_dir: str | Path, config_path: str | Path) -> tuple[bool, str]:
    """Validate a sing-box JSON config via `sing-box.exe check -c <config_path>` if binary is present."""
    exe = Path(bin_dir) / "sing-box.exe"
    if not exe.is_file():
        return True, "skipped"
    try:
        proc = subprocess.run(
            [str(exe), "check", "-c", str(config_path)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=8,
            creationflags=_NO_WINDOW,
        )
        return proc.returncode == 0, (proc.stderr or proc.stdout or "").strip()
    except (subprocess.SubprocessError, OSError) as exc:
        return False, str(exc)


def validate_xray_config(bin_dir: str | Path, config_path: str | Path) -> tuple[bool, str]:
    """Validate an Xray-core JSON config via `xray.exe run -test -c <config_path>` if binary is present."""
    exe = Path(bin_dir) / "xray.exe"
    if not exe.is_file():
        return True, "skipped"
    try:
        proc = subprocess.run(
            [str(exe), "run", "-test", "-c", str(config_path)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=8,
            creationflags=_NO_WINDOW,
        )
        return proc.returncode == 0, (proc.stderr or proc.stdout or "").strip()
    except (subprocess.SubprocessError, OSError) as exc:
        return False, str(exc)


class ProcessSupervisor:
    """Manages external processes (winws2, sing-box, tg-ws-proxy) with log redirection, state persistence, and reverse teardown."""

    def __init__(
        self,
        bin_dir: str | Path = DEFAULT_BIN_DIR,
        logs_dir: str | Path = Path("logs"),
        state_path: str | Path | None = None,
    ) -> None:
        self.bin_dir = Path(bin_dir)
        self.logs_dir = Path(logs_dir)
        self.state_path = Path(state_path) if state_path is not None else (self.logs_dir / "supervisor_state.json")
        self.processes: dict[str, subprocess.Popen[bytes]] = {}
        self._adopted: dict[str, dict[str, Any]] = {}
        self._log_files: dict[str, Any] = {}
        self._cmds: dict[str, list[str]] = {}
        self._started_at: dict[str, str] = {}
        self._create_times: dict[str, float] = {}
        self._stopped_names: set[str] = set()

    def adopt_persisted_state(self) -> dict[str, Any]:
        """Read supervisor_state.json and return still-running processes not currently managed or stopped."""
        if not self.state_path.is_file():
            self._adopted = {}
            return {}
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
        except Exception:
            self._adopted = {}
            return {}
        procs = data.get("processes") if isinstance(data, dict) else None
        if not isinstance(procs, dict):
            self._adopted = {}
            return {}

        adopted: dict[str, Any] = {}
        for name, info in procs.items():
            name_str = str(name)
            if name_str in self.processes or name_str in self._stopped_names:
                continue
            if not isinstance(info, dict):
                continue
            pid = info.get("pid")
            expected_ct = info.get("create_time")
            if _is_pid_running(pid, expected_create_time=expected_ct):
                entry = dict(info)
                entry["pid"] = pid
                entry["running"] = True
                if not isinstance(entry.get("cmd"), list):
                    entry["cmd"] = []
                adopted[name_str] = entry
        self._adopted = dict(adopted)
        return adopted

    def _save_state(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        merged_processes: dict[str, Any] = self.adopt_persisted_state()
        for name, proc in self.processes.items():
            if proc.poll() is None:
                entry: dict[str, Any] = {
                    "pid": proc.pid,
                    "running": True,
                    "cmd": self._cmds.get(name, []),
                    "started_at": self._started_at.get(name, ""),
                }
                if name in self._create_times:
                    entry["create_time"] = self._create_times[name]
                merged_processes[name] = entry
        payload = {
            "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "processes": merged_processes,
        }
        _write_bytes_atomic(self.state_path, (json.dumps(payload, indent=2) + "\n").encode("utf-8"))

    def start_process(self, name: str, cmd: list[str], cwd: Path | None = None) -> subprocess.Popen[bytes]:
        if not cmd:
            raise ValueError(f"Empty command for process '{name}'")
        exe = cmd[0]
        exe_path = Path(exe)
        if exe_path.is_absolute() or "/" in exe or "\\" in exe or exe.lower().endswith(".exe"):
            if not exe_path.is_file() and shutil.which(exe) is None:
                raise FileNotFoundError(f"Executable not found for '{name}': {exe}")

        was_running = (name in self.processes and self.processes[name].poll() is None) or (
            name in self._adopted
            and _is_pid_running(
                self._adopted[name].get("pid"),
                expected_create_time=self._adopted[name].get("create_time"),
            )
        )
        if not was_running:
            persisted = inspect_supervisor_state(state_path=self.state_path)
            was_running = bool((persisted.get(name) or {}).get("running"))
        self.stop_process(name)
        if was_running and name == "winws2":
            # Allow WinDivert64.sys kernel driver to finish releasing the filter handle cleanly
            time.sleep(0.35)
        elif was_running and name == "sing-box":
            # Allow Wintun adapter teardown to settle before re-creating netdoctor-tun
            time.sleep(0.25)

        self.logs_dir.mkdir(parents=True, exist_ok=True)
        log_path = self.logs_dir / f"{name}.log"
        # Preserve previous non-empty log into <name>.prev.log (capped for multi-MB logs) so crash output is kept fast
        try:
            if log_path.is_file():
                prev_size = log_path.stat().st_size
                prev_path = self.logs_dir / f"{name}.prev.log"
                if prev_size > 2 * 1024 * 1024:
                    tail_keep = 512 * 1024
                    with log_path.open("rb") as src:
                        src.seek(max(0, prev_size - tail_keep))
                        _write_bytes_atomic(prev_path, src.read(tail_keep))
                elif prev_size > 0:
                    shutil.copy2(log_path, prev_path)
        except OSError:
            pass
        log_fp = open(log_path, "wb", buffering=0)
        flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | _NO_WINDOW
        try:
            proc = subprocess.Popen(
                cmd,
                cwd=str(cwd or self.bin_dir),
                stdin=subprocess.DEVNULL,
                stdout=log_fp,
                stderr=subprocess.STDOUT,
                creationflags=flags,
            )
        except Exception:
            log_fp.close()
            raise

        self._stopped_names.discard(name)
        self.processes[name] = proc
        self._log_files[name] = log_fp
        self._cmds[name] = list(cmd)
        self._started_at[name] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            self._create_times[name] = round(float(psutil.Process(proc.pid).create_time()), 2)
        except (psutil.Error, OSError):
            self._create_times.pop(name, None)
        self._save_state()
        return proc

    def stop_process(self, name: str) -> None:
        self._stopped_names.add(name)
        proc = self.processes.pop(name, None)
        adopted_info = self._adopted.pop(name, None)
        log_fp = self._log_files.pop(name, None)
        self._cmds.pop(name, None)
        self._started_at.pop(name, None)
        self._create_times.pop(name, None)

        target_pid: int | None = None
        if proc is not None and proc.poll() is None:
            target_pid = proc.pid
        elif adopted_info and _is_pid_running(
            adopted_info.get("pid"),
            expected_create_time=adopted_info.get("create_time"),
        ):
            target_pid = int(adopted_info["pid"])
        elif self.state_path.is_file():
            try:
                data = json.loads(self.state_path.read_text(encoding="utf-8"))
                st_entry = (data.get("processes") or {}).get(name) if isinstance(data, dict) else None
                if isinstance(st_entry, dict) and _is_pid_running(
                    st_entry.get("pid"),
                    expected_create_time=st_entry.get("create_time"),
                ):
                    target_pid = int(st_entry["pid"])
            except Exception:
                pass

        # Snapshot child PIDs (e.g. Windows venv pythonw.exe -> Python312\pythonw.exe) BEFORE signalling parent
        child_pids: list[int] = []
        if target_pid is not None:
            try:
                child_pids = [c.pid for c in psutil.Process(target_pid).children(recursive=True)]
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.Error, OSError):
                child_pids = []

        # Skip CTRL_BREAK_EVENT on Windows: fails with WinError 6 / CPython 3.12 SystemError under pythonw.exe and cannot reach CREATE_NO_WINDOW children
        if os.name != "nt" and proc is not None and proc.poll() is None:
            try:
                proc.send_signal(signal.SIGTERM)
                proc.wait(timeout=0.6)
            except (subprocess.TimeoutExpired, OSError, ValueError):
                pass

        if target_pid is not None:
            terminate_process_tree(target_pid, extra_pids=child_pids)

        if proc is not None:
            try:
                proc.wait(timeout=0.5)
            except (subprocess.TimeoutExpired, OSError):
                pass

        cleanup_orphaned_service_processes(self.bin_dir, names=(name,))

        if log_fp is not None:
            try:
                log_fp.close()
            except OSError:
                pass

        ports = SERVICE_PORTS.get(name, ())
        if ports:
            wait_ports_released(ports, timeout=2.5)

        self._save_state()

    def stop_all(self) -> None:
        names = list(reversed(list(dict.fromkeys([*self._adopted.keys(), *self.processes.keys()]))))
        for name in names:
            self.stop_process(name)
        self._save_state()

    def start_stack(
        self,
        specs: list[tuple[str, list[str]] | tuple[str, list[str], Path | None]],
        startup_wait: float = 0.35,
    ) -> dict[str, subprocess.Popen[bytes]]:
        """Start a stack of services sequentially, rolling back all started processes if any crashes."""
        for spec in specs:
            if len(spec) == 2:
                name, cmd = spec
                cwd = None
            else:
                name, cmd, cwd = spec
            try:
                proc = self.start_process(name, cmd, cwd=cwd)
            except Exception:
                self.stop_all()
                raise
            if startup_wait > 0:
                time.sleep(startup_wait)
            rc = proc.poll()
            if rc is not None:
                log_path = self.logs_dir / f"{name}.log"
                self.stop_all()
                detail = ""
                try:
                    if log_path.is_file():
                        lines = [ln.strip() for ln in log_path.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip()]
                        if lines:
                            detail = f": {lines[-1][:180]}"
                except OSError:
                    pass
                raise RuntimeError(f"Service '{name}' exited prematurely on startup with code {rc}{detail}")
        return dict(self.processes)

    def reload_process(self, name: str, cmd: list[str], cwd: Path | None = None) -> subprocess.Popen[bytes]:
        """Atomically stop an existing process and start the updated one."""
        return self.start_process(name, cmd, cwd=cwd)

    def status(self) -> dict[str, dict[str, Any]]:
        report: dict[str, dict[str, Any]] = {}
        for name, proc in self.processes.items():
            code = proc.poll()
            report[name] = {
                "pid": proc.pid,
                "running": code is None,
                "exit_code": code,
            }
        return report
