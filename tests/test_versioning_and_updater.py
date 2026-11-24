"""Tests for P0-P4 versioning, SQLite schema migrations, pinned binaries, and self-updater."""

from __future__ import annotations

import copy
import io
import json
import re
import sqlite3
import subprocess
import tkinter as tk
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
import pytest
from typer.testing import CliRunner

import netdoctor
import netdoctor.supervisor as supervisor_mod
from netdoctor.cli import app
from netdoctor.gui import NetdoctorGuiApp
from netdoctor.gui_backend import GuiBackend
from netdoctor.storage import CURRENT_DB_VERSION, Storage
from netdoctor.supervisor import (
    UPSTREAM_RELEASES,
    fetch_all_bins,
    fetch_singbox_binary,
    fetch_xray_binary,
    get_outdated_pinned_artifacts,
    verify_binaries,
)
from netdoctor.updater import (
    GITHUB_RELEASES_API,
    UPDATE_CACHE_SETTING_KEY,
    apply_app_update,
    check_for_updates,
    is_newer_version,
    parse_semver,
)


def _make_zip_bytes(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _fake_pe(tag: bytes = b"TEST") -> bytes:
    return b"MZ" + tag + b"\x00" * 64


# ---------------------------------------------------------------- P0: SQLite PRAGMA user_version


def test_storage_user_version_fresh_migration_and_no_downgrade(tmp_path: Path) -> None:
    # 1. Fresh DB sets PRAGMA user_version == CURRENT_DB_VERSION
    fresh_db = tmp_path / "fresh.db"
    st = Storage(fresh_db)
    try:
        assert st.get_schema_version() == CURRENT_DB_VERSION
        assert st.conn.execute("PRAGMA user_version").fetchone()[0] == CURRENT_DB_VERSION
    finally:
        st.close()

    # 2. Legacy v0 DB lacking decisions.pinned migrates to v2 without losing rows
    legacy_db = tmp_path / "legacy.db"
    raw_conn = sqlite3.connect(legacy_db)
    raw_conn.executescript(
        """
        CREATE TABLE networks (
            network_key TEXT PRIMARY KEY,
            asn INTEGER NOT NULL,
            kind TEXT NOT NULL,
            isp TEXT DEFAULT '',
            gateway_mac TEXT DEFAULT '',
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL
        );
        CREATE TABLE decisions (
            network_key TEXT NOT NULL,
            domain TEXT NOT NULL,
            protocol TEXT NOT NULL,
            layer TEXT NOT NULL,
            strategy_id TEXT,
            fallback_json TEXT NOT NULL DEFAULT '[]',
            ttfb_ms REAL,
            throughput_kbps REAL,
            consecutive_fails INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'active',
            updated_at TEXT NOT NULL,
            ttl_sec INTEGER NOT NULL DEFAULT 21600,
            PRIMARY KEY (network_key, domain, protocol)
        );
        INSERT INTO decisions (network_key, domain, protocol, layer, strategy_id, updated_at)
        VALUES ('AS123:home:aa', 'discord.com', 'tls', 'dpi', 'zapret2:auto', '2026-01-01T00:00:00');
        PRAGMA user_version = 0;
        """
    )
    raw_conn.close()

    migrated = Storage(legacy_db)
    try:
        assert migrated.get_schema_version() == CURRENT_DB_VERSION
        rows = migrated.get_decisions("AS123:home:aa")
        assert len(rows) == 1
        assert rows[0].domain == "discord.com"
        assert rows[0].pinned is False
        assert migrated.set_decision_pinned("AS123:home:aa", "discord.com", "tls", True) is True
    finally:
        migrated.close()

    # 3. Re-opening is idempotent and higher user_version is never downgraded
    reopened = Storage(legacy_db)
    try:
        assert reopened.get_schema_version() == CURRENT_DB_VERSION
        assert reopened.get_decisions("AS123:home:aa")[0].pinned is True
    finally:
        reopened.close()

    future_db = tmp_path / "future.db"
    st_future = Storage(future_db)
    st_future.conn.execute("PRAGMA user_version = 99")
    st_future.conn.commit()
    st_future.close()

    reopened_future = Storage(future_db)
    try:
        assert reopened_future.get_schema_version() == 99
    finally:
        reopened_future.close()


# ---------------------------------------------------------------- P1: Single Source of Truth


def test_app_version_matches_pyproject_and_cli_flag() -> None:
    pyproject_text = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', pyproject_text, re.MULTILINE)
    assert match is not None
    assert netdoctor.__version__ == match.group(1)

    res = CliRunner().invoke(app, ["--version"])
    assert res.exit_code == 0
    assert res.output.strip() == f"netdoctor {netdoctor.__version__}"


# ---------------------------------------------------------------- P3: Pinned binaries & manifest v2


@pytest.mark.asyncio
async def test_fetch_singbox_and_xray_use_pinned_urls_without_latest_api(tmp_path: Path) -> None:
    requested_urls: list[str] = []
    sb_zip = _make_zip_bytes({"sing-box-1.14.4-windows-amd64/sing-box.exe": _fake_pe(b"SB_PINNED")})
    xray_zip = _make_zip_bytes({"xray.exe": _fake_pe(b"XRAY_PINNED")})

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        requested_urls.append(url)
        assert "api.github.com" not in url, f"Floating releases/latest API must not be queried: {url}"
        if url == UPSTREAM_RELEASES["sing-box"]["direct_archive"]:
            return httpx.Response(200, content=sb_zip)
        if url == UPSTREAM_RELEASES["xray"]["direct_archive"]:
            return httpx.Response(200, content=xray_zip)
        return httpx.Response(404)

    bin_dir = tmp_path / "bin"
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        sb = await fetch_singbox_binary(bin_dir, client=client)
        xr = await fetch_xray_binary(bin_dir, client=client)

    assert sb.read_bytes().startswith(b"MZSB_PINNED")
    assert xr.read_bytes().startswith(b"MZXRAY_PINNED")
    assert requested_urls == [
        UPSTREAM_RELEASES["sing-box"]["direct_archive"],
        UPSTREAM_RELEASES["xray"]["direct_archive"],
    ]


@pytest.mark.asyncio
async def test_manifest_v2_and_selective_upgrade_on_pinned_bump(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    patched_releases = copy.deepcopy(UPSTREAM_RELEASES)
    monkeypatch.setattr(supervisor_mod, "UPSTREAM_RELEASES", patched_releases)

    zwb_zip = _make_zip_bytes(
        {
            "zapret-win-bundle-pin/zapret-winws/winws2.exe": _fake_pe(b"WINWS2"),
            "zapret-win-bundle-pin/zapret-winws/WinDivert.dll": b"DLL",
            "zapret-win-bundle-pin/zapret-winws/WinDivert64.sys": b"SYS",
            "zapret-win-bundle-pin/zapret-winws/cygwin1.dll": b"CYG",
            "zapret-win-bundle-pin/zapret-winws/lua/zapret-lib.lua": b"-- lib\n",
            "zapret-win-bundle-pin/zapret-winws/files/quic_initial_www_google_com.bin": b"\x01\x02\x03",
            "zapret-win-bundle-pin/zapret-winws/windivert.filter/README.txt": b"readme\n",
            "zapret-win-bundle-pin/zapret-winws/windivert.filter/windivert_part.stun.txt": b"udp",
            "zapret-win-bundle-pin/blockcheck/blockcheck2.cmd": b"@echo off\r\n",
            "zapret-win-bundle-pin/blockcheck/blockcheck2-kyber.cmd": b"@echo off\r\n",
            "zapret-win-bundle-pin/blockcheck/zapret2/blockcheck2.sh": b"#!/bin/sh\n",
            "zapret-win-bundle-pin/blockcheck/zapret/files/fake/tls.bin": b"\x16\x03\x01",
            "zapret-win-bundle-pin/tools/elevator.exe": _fake_pe(b"ELEV"),
            "zapret-win-bundle-pin/cygwin/bin/bash.exe": _fake_pe(b"BASH"),
            "zapret-win-bundle-pin/cygwin/bin/cygpath.exe": _fake_pe(b"CYGP"),
        }
    )
    tg_exe = _fake_pe(b"TGEXE")
    tg_src = _make_zip_bytes(
        {
            "tg-ws-proxy-1.11.4/proxy/tg_ws_proxy.py": b"print('tg')\n",
            "tg-ws-proxy-1.11.4/utils/__init__.py": b"# utils\n",
            "tg-ws-proxy-1.11.4/pyproject.toml": b"[project]\nname='tg'\n",
            "tg-ws-proxy-1.11.4/LICENSE": b"MIT\n",
        }
    )
    zdy_zip = _make_zip_bytes(
        {
            "zapret-discord-youtube-1.10.4/lists/list-general.txt": b"discord.com\n",
            "zapret-discord-youtube-1.10.4/lists/list-google.txt": b"youtube.com\n",
            "zapret-discord-youtube-1.10.4/lists/list-exclude.txt": b"localhost\n",
            "zapret-discord-youtube-1.10.4/lists/ipset-exclude.txt": b"127.0.0.0/8\n",
            "zapret-discord-youtube-1.10.4/lists/ipset-all.txt": b"203.0.113.113/32\n",
            "zapret-discord-youtube-1.10.4/lists/ipset-all.txt.backup": b"1.1.1.0/24\n",
            "zapret-discord-youtube-1.10.4/bin/tls_clienthello_www_google_com.bin": b"\x16\x03\x01",
            "zapret-discord-youtube-1.10.4/general.bat": b"@echo off\r\n",
            "zapret-discord-youtube-1.10.4/service.bat": b"@echo off\r\n",
            "zapret-discord-youtube-1.10.4/utils/targets.txt": b"Discord = https://discord.com\n",
        }
    )
    sb_v1 = _make_zip_bytes({"sing-box/sing-box.exe": _fake_pe(b"SB_V1")})
    sb_v2 = _make_zip_bytes({"sing-box/sing-box.exe": _fake_pe(b"SB_V2")})
    byedpi_v1 = _make_zip_bytes({"ciadpi.exe": _fake_pe(b"BYEDPI_V1")})
    byedpi_v2 = _make_zip_bytes({"ciadpi.exe": _fake_pe(b"BYEDPI_V2")})
    xray_v1 = _make_zip_bytes({"xray.exe": _fake_pe(b"XRAY_V1")})

    requested: list[str] = []
    sb_v2_url = "https://github.com/SagerNet/sing-box/releases/download/v1.15.0/sing-box-1.15.0-windows-amd64.zip"
    byedpi_v2_url = "https://github.com/hufrea/byedpi/releases/download/v0.18.0/byedpi-18.0-x86_64-w64.zip"

    url_map = {
        patched_releases["sing-box"]["direct_archive"]: sb_v1,
        patched_releases["zapret-win-bundle"]["branch_archive"]: zwb_zip,
        patched_releases["tg-ws-proxy"]["exe_url"]: tg_exe,
        patched_releases["tg-ws-proxy"]["source_archive"]: tg_src,
        patched_releases["zapret-discord-youtube"]["release_archive"]: zdy_zip,
        patched_releases["byedpi"]["release_archive"]: byedpi_v1,
        patched_releases["xray"]["direct_archive"]: xray_v1,
        sb_v2_url: sb_v2,
        byedpi_v2_url: byedpi_v2,
    }

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        requested.append(url)
        payload = url_map.get(url)
        return httpx.Response(200, content=payload) if payload is not None else httpx.Response(404)

    bin_dir = tmp_path / "bin"
    lists_dir = tmp_path / "lists"
    presets_dir = tmp_path / "presets"

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        await fetch_all_bins(bin_dir, lists_dir, presets_dir, force=False, client=client)

    manifest = json.loads((bin_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema_version"] == 2
    assert manifest["netdoctor_version"] == netdoctor.__version__
    for comp in ("sing-box", "zapret-win-bundle", "tg-ws-proxy", "zapret-discord-youtube", "byedpi", "xray"):
        assert manifest["artifacts"][comp]["tag"] == patched_releases[comp]["tag"]
    assert get_outdated_pinned_artifacts(bin_dir) == {}
    initial_report = verify_binaries(bin_dir, lists_dir, presets_dir, run_checks=False)
    assert initial_report["ok"] is True, initial_report

    # Simulate netdoctor upgrade that bumps ONLY sing-box and byedpi pinned versions
    patched_releases["sing-box"]["tag"] = "v1.15.0"
    patched_releases["sing-box"]["direct_archive"] = sb_v2_url
    patched_releases["byedpi"]["tag"] = "v0.18.0"
    patched_releases["byedpi"]["release_archive"] = byedpi_v2_url

    outdated = get_outdated_pinned_artifacts(bin_dir)
    assert set(outdated.keys()) == {"sing-box", "byedpi"}

    bad_report = verify_binaries(bin_dir, lists_dir, presets_dir, run_checks=False)
    assert bad_report["ok"] is False
    assert bad_report["manifest"]["outdated_artifacts"] == outdated
    assert any("version_mismatch" in m for m in bad_report["manifest"]["mismatches"])

    # fetch_all_bins(force=False) selectively downloads ONLY the bumped components
    requested.clear()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        await fetch_all_bins(bin_dir, lists_dir, presets_dir, force=False, client=client)

    assert set(requested) == {sb_v2_url, byedpi_v2_url}
    assert (bin_dir / "sing-box.exe").read_bytes().startswith(b"MZSB_V2")
    assert (bin_dir / "ciadpi.exe").read_bytes().startswith(b"MZBYEDPI_V2")
    assert verify_binaries(bin_dir, lists_dir, presets_dir, run_checks=False)["ok"] is True


# ---------------------------------------------------------------- P2 & P4: SemVer & Updater


def test_semver_comparison_rules() -> None:
    assert parse_semver("v0.2.0") == (0, 2, 0, 1, "")
    assert is_newer_version("0.2.0", "0.1.0") is True
    assert is_newer_version("0.1.10", "0.1.2") is True
    assert is_newer_version("0.1.0", "0.1.0-dev") is True
    assert is_newer_version("v0.1.0", "0.1.0") is False
    assert is_newer_version("0.1.0", "0.2.0") is False
    assert is_newer_version("not-a-version", "0.1.0") is False


@pytest.mark.asyncio
async def test_check_for_updates_releases_cache_404_and_network_error(tmp_path: Path) -> None:
    st = Storage(tmp_path / "upd.db")
    try:
        calls = 0

        def handler_200(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            assert str(request.url) == GITHUB_RELEASES_API
            return httpx.Response(
                200,
                json={
                    "tag_name": "v0.2.0",
                    "html_url": "https://github.com/vo1okon/netdoctor/releases/tag/v0.2.0",
                    "body": "New features",
                    "published_at": "2026-11-24T00:00:00Z",
                    "assets": [
                        {
                            "name": "netdoctor-v0.2.0.zip",
                            "browser_download_url": "https://github.com/vo1okon/netdoctor/releases/download/v0.2.0/netdoctor-v0.2.0.zip",
                        }
                    ],
                },
            )

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler_200)) as client:
            res1 = await check_for_updates(current_version="0.1.0", storage=st, client=client, repo_root=tmp_path)
            res2 = await check_for_updates(current_version="0.1.0", storage=st, client=client, repo_root=tmp_path)
            res_forced = await check_for_updates(
                current_version="0.1.0", storage=st, force=True, client=client, repo_root=tmp_path
            )
            # Changing current_version invalidates cached entry
            res_bumped = await check_for_updates(current_version="0.2.0", storage=st, client=client, repo_root=tmp_path)

        assert res1["ok"] is True and res1["update_available"] is True and res1["cached"] is False
        assert res1["latest_version"] == "0.2.0"
        assert res1["install_mode"] == "portable"
        assert res2["cached"] is True and res2["update_available"] is True
        assert res_forced["cached"] is False
        assert res_bumped["update_available"] is False and res_bumped["cached"] is False
        assert calls == 3

        # Expired cache triggers fresh check and handles 404 (no releases yet) cleanly
        stale = json.loads(st.get_setting(UPDATE_CACHE_SETTING_KEY))
        stale["checked_at"] = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat(timespec="seconds")
        st.set_setting(UPDATE_CACHE_SETTING_KEY, json.dumps(stale))

        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _r: httpx.Response(404))) as client_404:
            res_404 = await check_for_updates(current_version="0.2.0", storage=st, client=client_404, repo_root=tmp_path)
        assert res_404["ok"] is True
        assert res_404["update_available"] is False

        # Network exception is caught and returned as ok=False
        def handler_err(_req: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("offline")

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler_err)) as client_err:
            res_err = await check_for_updates(
                current_version="0.2.0", storage=st, force=True, client=client_err, repo_root=tmp_path
            )
        assert res_err["ok"] is False
        assert res_err["update_available"] is False
        assert "offline" in res_err["error"]
    finally:
        st.close()


@pytest.mark.asyncio
async def test_apply_app_update_git_mode_dirty_and_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import netdoctor.updater as updater_mod

    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    bin_dir = repo / "bin"
    lists_dir = repo / "lists"
    st = Storage(repo / "netdoctor.db")
    st.set_setting(UPDATE_CACHE_SETTING_KEY, '{"cached": true}')

    monkeypatch.setattr(updater_mod.shutil, "which", lambda name: "git.exe" if name == "git" else None)

    # 1. Dirty tracked tree blocks git pull
    cmds_dirty: list[list[str]] = []

    def fake_run_dirty(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        cmds_dirty.append(cmd)
        if cmd[:3] == ["git", "status", "--porcelain"]:
            return subprocess.CompletedProcess(cmd, 0, stdout=" M src/netdoctor/cli.py\n", stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(updater_mod.subprocess, "run", fake_run_dirty)
    res_dirty = await apply_app_update(repo_root=repo, bin_dir=bin_dir, lists_dir=lists_dir, storage=st)
    assert res_dirty["ok"] is False
    assert "незакоммиченные" in res_dirty["error"]
    assert len(cmds_dirty) == 1

    # 2. Clean git tree runs fetch, pull --ff-only, pip install -e ., and fetch-bins subprocess
    cmds_clean: list[list[str]] = []
    rev_calls = 0

    def fake_run_clean(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        nonlocal rev_calls
        cmds_clean.append(cmd)
        if cmd[:3] == ["git", "status", "--porcelain"]:
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        if cmd[:3] == ["git", "rev-parse", "--short"]:
            rev_calls += 1
            return subprocess.CompletedProcess(cmd, 0, stdout="aaa111\n" if rev_calls == 1 else "bbb222\n", stderr="")
        if cmd[:3] == ["git", "diff", "--name-only"]:
            return subprocess.CompletedProcess(cmd, 0, stdout="src/netdoctor/cli.py\n", stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(updater_mod.subprocess, "run", fake_run_clean)
    try:
        res_clean = await apply_app_update(repo_root=repo, bin_dir=bin_dir, lists_dir=lists_dir, storage=st)
    finally:
        st_cache = st.get_setting(UPDATE_CACHE_SETTING_KEY, "nonempty")
        st.close()

    assert res_clean["ok"] is True
    assert res_clean["mode"] == "git"
    assert res_clean["old_commit"] == "aaa111"
    assert res_clean["new_commit"] == "bbb222"
    assert st_cache == ""
    assert any(c[:3] == ["git", "pull", "--ff-only"] for c in cmds_clean)
    assert any("pip" in c and "install" in c for c in cmds_clean)
    assert any("fetch-bins" in c for c in cmds_clean)


@pytest.mark.asyncio
async def test_apply_app_update_portable_mode_preserves_user_data_and_blocks_untrusted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import netdoctor.updater as updater_mod

    root = tmp_path / "portable_app"
    (root / "src" / "netdoctor").mkdir(parents=True)
    (root / "configs").mkdir(parents=True)
    (root / "netdoctor.db").write_bytes(b"USER_DB_DO_NOT_OVERWRITE")
    (root / "configs" / "sing-box.json").write_text('{"user": true}', encoding="utf-8")

    # 1. Untrusted URL is rejected before any network call
    bad_res = await apply_app_update(repo_root=root, download_url="https://evil.example.com/patch.zip")
    assert bad_res["ok"] is False
    assert "доверенная" in bad_res["error"]

    # 2. Trusted GitHub ZIP extracts allowed project files, ignores ZipSlip & user runtime files
    patch_zip = _make_zip_bytes(
        {
            "netdoctor-0.2.0/src/netdoctor/__init__.py": b'__version__ = "0.2.0"\n',
            "netdoctor-0.2.0/presets/zapret2/NewPreset.txt": b"# Preset: New\n",
            "netdoctor-0.2.0/configs/targets.yaml": b"targets: []\n",
            "netdoctor-0.2.0/pyproject.toml": b'[project]\nname = "netdoctor"\nversion = "0.2.0"\n',
            "netdoctor-0.2.0/netdoctor.db": b"CORRUPTED_DB",
            "netdoctor-0.2.0/configs/sing-box.json": b'{"overwritten": true}',
            "netdoctor-0.2.0/../escape.txt": b"pwned",
        }
    )
    dl_url = "https://github.com/vo1okon/netdoctor/archive/refs/tags/v0.2.0.zip"
    transport = httpx.MockTransport(
        lambda req: httpx.Response(200, content=patch_zip) if str(req.url) == dl_url else httpx.Response(404)
    )
    monkeypatch.setattr(
        updater_mod.subprocess,
        "run",
        lambda cmd, **_kw: subprocess.CompletedProcess(cmd, 0, stdout="", stderr=""),
    )

    async with httpx.AsyncClient(transport=transport) as client:
        res = await apply_app_update(
            repo_root=root,
            bin_dir=root / "bin",
            lists_dir=root / "lists",
            download_url=dl_url,
            target_version="0.2.0",
            client=client,
        )

    assert res["ok"] is True
    assert res["mode"] == "portable"
    assert res["updated_files"] == 4
    assert (root / "src" / "netdoctor" / "__init__.py").read_text(encoding="utf-8") == '__version__ = "0.2.0"\n'
    assert (root / "presets" / "zapret2" / "NewPreset.txt").is_file()
    assert (root / "netdoctor.db").read_bytes() == b"USER_DB_DO_NOT_OVERWRITE"
    assert (root / "configs" / "sing-box.json").read_text(encoding="utf-8") == '{"user": true}'
    assert not (tmp_path / "escape.txt").exists()


# ---------------------------------------------------------------- CLI & GUI


def test_cli_update_check_prints_status_and_pinned_bins(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import netdoctor.cli as cli_mod

    async def fake_check(**_kw: Any) -> dict[str, Any]:
        return {
            "ok": True,
            "update_available": True,
            "current_version": netdoctor.__version__,
            "latest_version": "0.2.0",
            "release_url": "https://github.com/vo1okon/netdoctor/releases/tag/v0.2.0",
            "install_mode": "git",
        }

    monkeypatch.setattr(cli_mod, "check_for_updates", fake_check)
    res = CliRunner().invoke(
        app,
        [
            "update",
            "--check",
            "--db",
            str(tmp_path / "cli_upd.db"),
            "--bin-dir",
            str(tmp_path / "bin"),
            "--lists-dir",
            str(tmp_path / "lists"),
        ],
    )
    assert res.exit_code == 0, res.output
    assert "0.2.0" in res.output
    assert "sing-box" in res.output
    assert "winws2" in UPSTREAM_RELEASES["zapret-win-bundle"]["binary_name"]


def test_gui_update_bar_badge_and_service_tab_fit(tmp_path: Path) -> None:
    backend = GuiBackend(
        db_path=tmp_path / "gui_upd.db",
        configs_dir=tmp_path / "configs",
        lists_dir=tmp_path / "lists",
        logs_dir=tmp_path / "logs",
        bin_dir=tmp_path / "bin",
    )
    try:
        gui_app = NetdoctorGuiApp(backend=backend, auto_start=False, enable_tray=False)
    except tk.TclError as exc:
        pytest.skip(f"Tk display unavailable: {exc}")

    try:
        assert netdoctor.__version__ in gui_app.title()
        assert netdoctor.__version__ in gui_app.version_info_label.cget("text")
        assert not gui_app.update_badge_btn.winfo_manager()
        assert not gui_app.apply_update_btn.winfo_manager()

        gui_app._apply_update_check_result(
            {
                "ok": True,
                "update_available": True,
                "current_version": netdoctor.__version__,
                "latest_version": "0.2.0",
                "install_mode": "git",
                "download_url": "https://github.com/vo1okon/netdoctor/archive/refs/tags/v0.2.0.zip",
            },
            silent=True,
        )
        assert gui_app.update_badge_btn.winfo_manager()
        assert "0.2.0" in gui_app.update_badge_btn.cget("text")
        assert gui_app.apply_update_btn.winfo_manager()

        gui_app._select_tab(gui_app.tab_service)
        gui_app.update_idletasks()
        gui_app.update()
        assert gui_app.tab_service.winfo_reqheight() <= gui_app.tab_service.winfo_height() + 5

        gui_app._apply_update_check_result(
            {
                "ok": True,
                "update_available": False,
                "current_version": netdoctor.__version__,
                "latest_version": netdoctor.__version__,
                "install_mode": "git",
            },
            silent=True,
        )
        assert not gui_app.update_badge_btn.winfo_manager()
        assert not gui_app.apply_update_btn.winfo_manager()
    finally:
        gui_app.on_close()


def test_install_bat_reuses_system_packages_and_preserves_crlf(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    install_bat = repo_root / "install.bat"
    raw = install_bat.read_bytes()
    assert b"\r\n" in raw
    assert b"\n" not in raw.replace(b"\r\n", b""), "install.bat must keep strict CRLF line endings"

    text = raw.decode("utf-8")
    assert '"%PY_EXE%" -m venv --system-site-packages .venv' in text
    assert "--no-build-isolation" in text
    assert "if errorlevel 1 \".venv\\Scripts\\python.exe\" -m pip install --upgrade pip" in text

    # Execute the exact batch lines inside a real .bat via cmd.exe
    check_lines = [
        line.strip()
        for line in text.splitlines()
        if line.strip().startswith('".venv\\Scripts\\python.exe" -c ')
        and "importlib.metadata" in line
    ]
    assert len(check_lines) == 3

    def _run_bat_line(name: str, line: str) -> int:
        bat = tmp_path / f"{name}.bat"
        bat.write_bytes(f"@echo off\r\n{line}\r\nexit /b %ERRORLEVEL%\r\n".encode("utf-8"))
        return subprocess.run(["cmd", "/c", str(bat)], cwd=str(repo_root), capture_output=True).returncode

    assert _run_bat_line("deps", check_lines[0]) == 0
    assert _run_bat_line("pip", check_lines[1]) == 0
    assert _run_bat_line("setuptools", check_lines[2]) in (0, 1)


def test_updater_guards_no_build_isolation_by_setuptools(monkeypatch: pytest.MonkeyPatch) -> None:
    from importlib.metadata import PackageNotFoundError
    import netdoctor.updater as updater_mod

    monkeypatch.setattr(updater_mod, "importlib_version", lambda _pkg: "75.0.0")
    assert updater_mod._has_build_setuptools() is True
    assert "--no-build-isolation" in updater_mod._build_pip_install_cmd(no_deps=True)
    assert "--no-deps" in updater_mod._build_pip_install_cmd(no_deps=True)
    assert "--no-build-isolation" in updater_mod._build_pip_install_cmd(no_deps=False)

    monkeypatch.setattr(updater_mod, "importlib_version", lambda _pkg: "67.9.0")
    assert updater_mod._has_build_setuptools() is False
    assert "--no-build-isolation" not in updater_mod._build_pip_install_cmd(no_deps=True)
    assert "--no-deps" in updater_mod._build_pip_install_cmd(no_deps=True)

    def _missing(_pkg: str) -> str:
        raise PackageNotFoundError("setuptools")

    monkeypatch.setattr(updater_mod, "importlib_version", _missing)
    assert updater_mod._has_build_setuptools() is False
    assert "--no-build-isolation" not in updater_mod._build_pip_install_cmd(no_deps=False)
