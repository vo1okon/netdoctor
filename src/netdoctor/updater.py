"""Application version comparison, GitHub Release update checks, and 1-click self-updater."""

from __future__ import annotations

import io
import json
import re
import shutil
import subprocess
import sys
import tomllib
import zipfile
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, distribution as importlib_distribution, version as importlib_version
from pathlib import Path, PurePosixPath
from typing import Any

import httpx

from netdoctor import __version__
from netdoctor.storage import Storage
from netdoctor.supervisor import _download_bytes, _safe_extract_file, _safe_rel_path

GITHUB_REPO = "vo1okon/netdoctor"
GITHUB_RELEASES_API = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
GITHUB_RELEASES_PAGE = f"https://github.com/{GITHUB_REPO}/releases"
DEFAULT_CHECK_TTL_SEC = 12 * 3600
UPDATE_CACHE_SETTING_KEY = "update_check_cache"
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

_SEMVER_RE = re.compile(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[-.](.+))?$")
_ALLOWED_PORTABLE_ROOT_FILES: frozenset[str] = frozenset(
    {
        "pyproject.toml",
        "install.bat",
        "run.bat",
        "README.md",
        "LICENSES.md",
        ".gitattributes",
        ".gitignore",
    }
)
_ALLOWED_PORTABLE_CONFIG_FILES: frozenset[str] = frozenset(
    {
        "configs/strategies.yaml",
        "configs/targets.yaml",
    }
)


def resolve_repo_root(repo_root: Path | None = None) -> Path:
    """Return explicit repo_root or the netdoctor repository/project root."""
    if repo_root is not None:
        return Path(repo_root).resolve()
    return Path(__file__).resolve().parents[2]


def parse_semver(raw: str) -> tuple[int, int, int, int, str]:
    """Parse a SemVer-like string into a comparable tuple (pre-release sorts below final)."""
    cleaned = str(raw or "").strip()
    if cleaned[:1].lower() == "v":
        cleaned = cleaned[1:].strip()
    match = _SEMVER_RE.match(cleaned)
    if not match:
        return (0, 0, 0, 0, "")
    major = int(match.group(1))
    minor = int(match.group(2) or 0)
    patch = int(match.group(3) or 0)
    pre = (match.group(4) or "").strip()
    return (major, minor, patch, 0 if pre else 1, pre)


def is_newer_version(latest: str, current: str) -> bool:
    """Return True if `latest` parses as a valid version strictly greater than `current`."""
    latest_tuple = parse_semver(latest)
    if latest_tuple == (0, 0, 0, 0, ""):
        return False
    return latest_tuple > parse_semver(current)


def detect_install_mode(repo_root: Path | None = None) -> str:
    """Detect whether netdoctor runs from a git checkout (`git`) or extracted ZIP (`portable`)."""
    root = resolve_repo_root(repo_root)
    if (root / ".git").exists() and shutil.which("git"):
        return "git"
    return "portable"


def _is_trusted_release_url(url: str) -> bool:
    clean = str(url or "").strip()
    return clean.startswith(
        (
            f"https://github.com/{GITHUB_REPO}/",
            f"https://api.github.com/repos/{GITHUB_REPO}/",
        )
    )


def _is_allowed_portable_relpath(rel: PurePosixPath) -> bool:
    posix = rel.as_posix()
    if posix.startswith(("src/", "presets/")):
        return True
    if posix in _ALLOWED_PORTABLE_CONFIG_FILES:
        return True
    return posix in _ALLOWED_PORTABLE_ROOT_FILES


def _pick_release_zip_url(release: dict[str, Any], tag_name: str) -> str:
    assets = release.get("assets") or []
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        name = str(asset.get("name") or "").lower()
        dl = str(asset.get("browser_download_url") or "").strip()
        if name.endswith(".zip") and dl:
            return dl
    if tag_name:
        return f"https://github.com/{GITHUB_REPO}/archive/refs/tags/{tag_name}.zip"
    return ""


async def check_for_updates(
    *,
    current_version: str = __version__,
    storage: Storage | None = None,
    force: bool = False,
    ttl_sec: int = DEFAULT_CHECK_TTL_SEC,
    timeout: float = 8.0,
    client: httpx.AsyncClient | None = None,
    repo_root: Path | None = None,
) -> dict[str, Any]:
    """Check GitHub Releases for a newer version of netdoctor with optional SQLite TTL caching."""
    install_mode = detect_install_mode(repo_root)
    now_dt = datetime.now(timezone.utc)
    now_iso = now_dt.isoformat(timespec="seconds")

    if not force and storage is not None:
        raw_cache = storage.get_setting(UPDATE_CACHE_SETTING_KEY, "")
        if raw_cache:
            try:
                cached = json.loads(raw_cache)
            except (json.JSONDecodeError, TypeError):
                cached = None
            if (
                isinstance(cached, dict)
                and cached.get("ok") is True
                and cached.get("current_version") == current_version
                and cached.get("checked_at")
            ):
                try:
                    checked_dt = datetime.fromisoformat(str(cached["checked_at"]))
                    if checked_dt.tzinfo is None:
                        checked_dt = checked_dt.replace(tzinfo=timezone.utc)
                    if (now_dt - checked_dt).total_seconds() < ttl_sec:
                        return {**cached, "cached": True, "install_mode": install_mode}
                except ValueError:
                    pass

    base_result: dict[str, Any] = {
        "ok": False,
        "update_available": False,
        "current_version": current_version,
        "latest_version": current_version,
        "release_tag": "",
        "release_url": GITHUB_RELEASES_PAGE,
        "download_url": "",
        "published_at": "",
        "release_notes": "",
        "install_mode": install_mode,
        "cached": False,
        "checked_at": now_iso,
        "error": "",
    }

    async def _fetch(active_client: httpx.AsyncClient) -> dict[str, Any]:
        resp = await active_client.get(
            GITHUB_RELEASES_API,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": f"netdoctor/{current_version}",
            },
        )
        if resp.status_code == 404:
            result = {**base_result, "ok": True}
            if storage is not None:
                storage.set_setting(UPDATE_CACHE_SETTING_KEY, json.dumps(result, ensure_ascii=False))
            return result
        if not resp.is_success:
            return {**base_result, "error": f"GitHub API HTTP {resp.status_code}"}

        data = resp.json()
        if not isinstance(data, dict):
            return {**base_result, "error": "Unexpected GitHub Releases API payload"}

        tag_name = str(data.get("tag_name") or "").strip()
        latest_version = tag_name[1:].strip() if tag_name[:1].lower() == "v" else tag_name
        if not latest_version:
            latest_version = current_version

        result = {
            **base_result,
            "ok": True,
            "update_available": is_newer_version(latest_version, current_version),
            "latest_version": latest_version,
            "release_tag": tag_name,
            "release_url": str(data.get("html_url") or GITHUB_RELEASES_PAGE).strip(),
            "download_url": _pick_release_zip_url(data, tag_name),
            "published_at": str(data.get("published_at") or "").strip(),
            "release_notes": str(data.get("body") or "").strip()[:600],
        }
        if storage is not None:
            storage.set_setting(UPDATE_CACHE_SETTING_KEY, json.dumps(result, ensure_ascii=False))
        return result

    try:
        if client is not None:
            return await _fetch(client)
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as own_client:
            return await _fetch(own_client)
    except Exception as exc:  # noqa: BLE001
        return {**base_result, "error": str(exc)}


def _run_cmd(cmd: list[str], *, cwd: Path, timeout: float = 120.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=timeout,
        creationflags=_NO_WINDOW,
    )


def _cmd_err(proc: subprocess.CompletedProcess[str]) -> str:
    return (proc.stderr or proc.stdout or f"exit code {proc.returncode}").strip()


def _has_build_setuptools(min_major: int = 68) -> bool:
    try:
        raw_ver = importlib_version("setuptools")
        return int(raw_ver.split(".", 1)[0]) >= min_major
    except (PackageNotFoundError, ValueError, IndexError):
        return False


def _build_pip_install_cmd(*, no_deps: bool = False) -> list[str]:
    cmd = [sys.executable, "-m", "pip", "install", "-e", "."]
    if no_deps:
        cmd.append("--no-deps")
    if _has_build_setuptools():
        cmd.append("--no-build-isolation")
    return cmd


def _is_locked_exe_pip_error(err_text: str) -> bool:
    low = (err_text or "").lower()
    return "winerror 32" in low and ("netdoctor-gui.exe" in low or "netdoctor.exe" in low)


def _sync_editable_metadata_fallback(
    root: Path,
    *,
    timeout: float = 120.0,
    dist_path_override: Path | None = None,
) -> tuple[bool, str]:
    """Install any missing dependencies directly and sync editable .dist-info version when GUI exe is locked."""
    pyproject_file = root / "pyproject.toml"
    try:
        data = tomllib.loads(pyproject_file.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        return False, f"Failed to read pyproject.toml: {exc}"

    project = data.get("project") if isinstance(data, dict) else {}
    if not isinstance(project, dict):
        project = {}
    new_version = str(project.get("version") or "").strip()
    deps = project.get("dependencies") or []

    missing: list[str] = []
    for dep in deps:
        if not isinstance(dep, str):
            continue
        pkg_name = re.split(r"[<>=!~;\[\s]", dep, 1)[0].strip()
        if not pkg_name:
            continue
        try:
            importlib_version(pkg_name)
        except PackageNotFoundError:
            missing.append(dep)

    if missing:
        dep_proc = _run_cmd([sys.executable, "-m", "pip", "install", *missing], cwd=root, timeout=timeout)
        if dep_proc.returncode != 0:
            return False, _cmd_err(dep_proc)

    dist_dir = dist_path_override
    if dist_dir is None:
        try:
            raw_path = getattr(importlib_distribution("netdoctor"), "_path", None)
            if raw_path is not None:
                dist_dir = Path(raw_path)
        except PackageNotFoundError:
            dist_dir = None

    if dist_dir is not None and dist_dir.is_dir() and new_version:
        meta_file = dist_dir / "METADATA"
        if meta_file.is_file():
            meta_text = meta_file.read_text(encoding="utf-8", errors="replace")
            updated_meta = re.sub(
                r"^Version:\s*.*$",
                f"Version: {new_version}",
                meta_text,
                count=1,
                flags=re.MULTILINE,
            )
            if updated_meta != meta_text:
                meta_file.write_text(updated_meta, encoding="utf-8")
        if dist_dir.name.endswith(".dist-info"):
            target_dir = dist_dir.with_name(f"netdoctor-{new_version}.dist-info")
            if target_dir != dist_dir and not target_dir.exists():
                dist_dir.rename(target_dir)

    return True, f"synced editable metadata to {new_version or 'current'}"


def _run_pip_install(
    cmd: list[str],
    *,
    cwd: Path,
    timeout: float = 120.0,
) -> subprocess.CompletedProcess[str]:
    """Run pip install and recover cleanly when Windows locks running netdoctor-gui.exe (WinError 32)."""
    proc = _run_cmd(cmd, cwd=cwd, timeout=timeout)
    if proc.returncode != 0 and _is_locked_exe_pip_error(_cmd_err(proc)):
        ok, detail = _sync_editable_metadata_fallback(cwd, timeout=timeout)
        if ok:
            return subprocess.CompletedProcess(cmd, 0, stdout=detail, stderr="")
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr=detail)
    return proc


def _sync_bins_subprocess(root: Path, bin_dir: Path | None, lists_dir: Path | None, timeout: float) -> tuple[bool, str]:
    if bin_dir is None:
        return True, ""
    cmd = [sys.executable, "-m", "netdoctor.cli", "fetch-bins", "--bin-dir", str(Path(bin_dir).resolve())]
    if lists_dir is not None:
        cmd.extend(["--lists-dir", str(Path(lists_dir).resolve())])
    try:
        proc = _run_cmd(cmd, cwd=root, timeout=max(timeout, 120.0))
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
    if proc.returncode != 0:
        return False, _cmd_err(proc)
    return True, ""


async def apply_app_update(
    *,
    repo_root: Path | None = None,
    bin_dir: Path | None = None,
    lists_dir: Path | None = None,
    storage: Storage | None = None,
    download_url: str | None = None,
    target_version: str | None = None,
    timeout: float = 120.0,
    client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    """Update netdoctor via `git pull` (git mode) or safe ZIP overlay (portable mode) and sync bins."""
    root = resolve_repo_root(repo_root)
    mode = detect_install_mode(root)

    if mode == "git":
        try:
            status_proc = _run_cmd(["git", "status", "--porcelain", "--untracked-files=no"], cwd=root, timeout=15.0)
            if status_proc.returncode != 0:
                return {"ok": False, "mode": "git", "error": _cmd_err(status_proc)}
            if status_proc.stdout.strip():
                return {
                    "ok": False,
                    "mode": "git",
                    "error": "В репозитории есть незакоммиченные изменения. Сохраните или отмените их перед автообновлением.",
                }

            head_before = _run_cmd(["git", "rev-parse", "--short", "HEAD"], cwd=root, timeout=15.0)
            old_commit = head_before.stdout.strip() if head_before.returncode == 0 else ""

            fetch_proc = _run_cmd(["git", "fetch", "--tags", "origin"], cwd=root, timeout=60.0)
            if fetch_proc.returncode != 0:
                return {"ok": False, "mode": "git", "error": f"git fetch failed: {_cmd_err(fetch_proc)}"}

            pull_proc = _run_cmd(["git", "pull", "--ff-only"], cwd=root, timeout=60.0)
            if pull_proc.returncode != 0:
                return {"ok": False, "mode": "git", "error": f"git pull failed: {_cmd_err(pull_proc)}"}

            head_after = _run_cmd(["git", "rev-parse", "--short", "HEAD"], cwd=root, timeout=15.0)
            new_commit = head_after.stdout.strip() if head_after.returncode == 0 else ""

            pyproject_changed = True
            if old_commit and new_commit and old_commit != new_commit:
                diff_proc = _run_cmd(["git", "diff", "--name-only", old_commit, new_commit], cwd=root, timeout=15.0)
                if diff_proc.returncode == 0:
                    changed_files = {line.strip() for line in diff_proc.stdout.splitlines() if line.strip()}
                    pyproject_changed = "pyproject.toml" in changed_files
            elif old_commit and new_commit and old_commit == new_commit:
                pyproject_changed = False

            pip_cmd = _build_pip_install_cmd(no_deps=not pyproject_changed)
            pip_proc = _run_pip_install(pip_cmd, cwd=root, timeout=max(timeout, 120.0))
            if pip_proc.returncode != 0:
                return {"ok": False, "mode": "git", "error": f"pip install failed: {_cmd_err(pip_proc)}"}
        except (OSError, subprocess.SubprocessError) as exc:
            return {"ok": False, "mode": "git", "error": str(exc)}

        bins_ok, bins_err = _sync_bins_subprocess(root, bin_dir, lists_dir, timeout)
        if not bins_ok:
            return {
                "ok": False,
                "mode": "git",
                "old_commit": old_commit,
                "new_commit": new_commit,
                "error": f"Код обновлён, но не удалось синхронизировать компоненты bin/: {bins_err}",
            }

        if storage is not None:
            storage.set_setting(UPDATE_CACHE_SETTING_KEY, "")
        return {
            "ok": True,
            "mode": "git",
            "old_commit": old_commit,
            "new_commit": new_commit,
            "updated_bins": bool(bin_dir),
            "restart_required": True,
            "detail": (
                f"Обновлено через git ({old_commit} -> {new_commit})"
                if old_commit and new_commit and old_commit != new_commit
                else f"Код синхронизирован ({new_commit or 'HEAD'})"
            ),
        }

    # Portable (ZIP) mode
    url = str(download_url or "").strip()
    if not _is_trusted_release_url(url):
        return {
            "ok": False,
            "mode": "portable",
            "error": "Не указана доверенная ссылка на ZIP-архив релиза.",
        }

    try:
        archive_bytes = await _download_bytes(url, timeout=timeout, client=client)
        updated_files = 0
        with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                rel = _safe_rel_path(info.filename, strip_root=True)
                if rel is None or not _is_allowed_portable_relpath(rel):
                    continue
                _safe_extract_file(root, rel, zf.read(info.filename))
                updated_files += 1
        if updated_files == 0:
            return {
                "ok": False,
                "mode": "portable",
                "error": "В архиве релиза не найдены файлы проекта netdoctor.",
            }
        pip_proc = _run_pip_install(_build_pip_install_cmd(), cwd=root, timeout=max(timeout, 120.0))
        if pip_proc.returncode != 0:
            return {"ok": False, "mode": "portable", "error": f"pip install failed: {_cmd_err(pip_proc)}"}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "mode": "portable", "error": str(exc)}

    bins_ok, bins_err = _sync_bins_subprocess(root, bin_dir, lists_dir, timeout)
    if not bins_ok:
        return {
            "ok": False,
            "mode": "portable",
            "target_version": target_version or "",
            "updated_files": updated_files,
            "error": f"Файлы обновлены, но не удалось синхронизировать компоненты bin/: {bins_err}",
        }

    if storage is not None:
        storage.set_setting(UPDATE_CACHE_SETTING_KEY, "")
    return {
        "ok": True,
        "mode": "portable",
        "target_version": target_version or "",
        "updated_files": updated_files,
        "updated_bins": bool(bin_dir),
        "restart_required": True,
        "detail": f"Обновлено {updated_files} файлов из архива релиза",
    }
