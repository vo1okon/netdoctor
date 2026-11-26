"""Tests for M1 R1 external dependency fetching, verification, CLI, and local workspace readiness."""

from __future__ import annotations

import asyncio
import importlib.metadata
import io
import json
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Any

import httpx
import pytest
from typer.testing import CliRunner

from netdoctor.cli import app
from netdoctor.config_gen import extract_blob_args
from netdoctor.supervisor import (
    UPSTREAM_RELEASES,
    _sync_blockcheck_fake_bins,
    fetch_all_bins,
    fetch_byedpi,
    fetch_tg_ws_proxy,
    fetch_zapret_discord_youtube,
    fetch_zapret_win_bundle,
    sha256_file,
    verify_binaries,
)


def _make_zip_bytes(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _fake_pe(tag: bytes = b"TEST") -> bytes:
    return b"MZ" + tag + b"\x00" * 64


def _build_mock_transport(
    *,
    zwb_bytes: bytes | None = None,
    tg_exe_bytes: bytes | None = None,
    tg_src_bytes: bytes | None = None,
    zdy_bytes: bytes | None = None,
    byedpi_bytes: bytes | None = None,
) -> httpx.MockTransport:
    zwb_zip = zwb_bytes or _make_zip_bytes(
        {
            "zapret-win-bundle-master/zapret-winws/winws2.exe": _fake_pe(b"WINWS2"),
            "zapret-win-bundle-master/zapret-winws/WinDivert.dll": b"DLL",
            "zapret-win-bundle-master/zapret-winws/WinDivert64.sys": b"SYS",
            "zapret-win-bundle-master/zapret-winws/cygwin1.dll": b"CYG",
            "zapret-win-bundle-master/zapret-winws/lua/zapret-lib.lua": b"-- lib\n",
            "zapret-win-bundle-master/zapret-winws/files/quic_initial_www_google_com.bin": b"\x01\x02\x03",
            "zapret-win-bundle-master/zapret-winws/windivert.filter/README.txt": b"filter readme\n",
            "zapret-win-bundle-master/zapret-winws/windivert.filter/windivert_part.stun.txt": b"udp",
            "zapret-win-bundle-master/blockcheck/blockcheck2.cmd": b"@echo off\r\n",
            "zapret-win-bundle-master/blockcheck/blockcheck2-kyber.cmd": b"@echo off\r\n",
            "zapret-win-bundle-master/blockcheck/zapret2/blockcheck2.sh": b"#!/bin/sh\n",
            "zapret-win-bundle-master/blockcheck/zapret/files/fake/tls.bin": b"\x16\x03\x01",
            "zapret-win-bundle-master/tools/elevator.exe": _fake_pe(b"ELEV"),
            "zapret-win-bundle-master/cygwin/bin/bash.exe": _fake_pe(b"BASH"),
            "zapret-win-bundle-master/cygwin/bin/cygpath.exe": _fake_pe(b"CYGP"),
            "zapret-win-bundle-master/../evil.txt": b"pwned",
            "../outside.txt": b"pwned",
        }
    )
    tg_exe = tg_exe_bytes or _fake_pe(b"TGEXE")
    tg_src = tg_src_bytes or _make_zip_bytes(
        {
            "tg-ws-proxy-1.11.4/proxy/tg_ws_proxy.py": b"print('mtproto')\n",
            "tg-ws-proxy-1.11.4/utils/__init__.py": b"",
            "tg-ws-proxy-1.11.4/utils/logging_setup.py": b"def build_log_handler(): pass\n",
            "tg-ws-proxy-1.11.4/pyproject.toml": b"[project]\nname='tg-ws-proxy'\n",
            "tg-ws-proxy-1.11.4/LICENSE": b"MIT\n",
            "tg-ws-proxy-1.11.4/windows.py": b"# gui skipped\n",
        }
    )
    zdy_zip = zdy_bytes or _make_zip_bytes(
        {
            "zapret-discord-youtube-1.10.4/lists/list-general.txt": b"discord.com\n",
            "zapret-discord-youtube-1.10.4/lists/list-google.txt": b"youtube.com\n",
            "zapret-discord-youtube-1.10.4/lists/list-exclude.txt": b"localhost\n",
            "zapret-discord-youtube-1.10.4/lists/ipset-exclude.txt": b"127.0.0.0/8\n",
            "zapret-discord-youtube-1.10.4/lists/ipset-all.txt": b"203.0.113.113/32\n",
            "zapret-discord-youtube-1.10.4/lists/ipset-all.txt.backup": b"1.1.1.0/24\n",
            "zapret-discord-youtube-1.10.4/bin/tls_clienthello_www_google_com.bin": b"\x16\x03\x01",
            "zapret-discord-youtube-1.10.4/bin/WinDivert.dll": b"OLD_ZAPRET1_DLL_DO_NOT_OVERWRITE",
            "zapret-discord-youtube-1.10.4/bin/winws.exe": b"OLD_WINWS1",
            "zapret-discord-youtube-1.10.4/general.bat": b"@echo off\r\n",
            "zapret-discord-youtube-1.10.4/general (ALT).bat": b"@echo off\r\n",
            "zapret-discord-youtube-1.10.4/service.bat": b"@echo off\r\n",
            "zapret-discord-youtube-1.10.4/utils/targets.txt": b"Discord = https://discord.com\n",
        }
    )
    byedpi_zip = byedpi_bytes or _make_zip_bytes(
        {
            "ciadpi.exe": _fake_pe(b"CIADPI"),
            "byedpi.bat": b"ciadpi.exe\n",
        }
    )

    url_map = {
        UPSTREAM_RELEASES["zapret-win-bundle"]["branch_archive"]: zwb_zip,
        UPSTREAM_RELEASES["tg-ws-proxy"]["exe_url"]: tg_exe,
        UPSTREAM_RELEASES["tg-ws-proxy"]["source_archive"]: tg_src,
        UPSTREAM_RELEASES["zapret-discord-youtube"]["release_archive"]: zdy_zip,
        UPSTREAM_RELEASES["byedpi"]["release_archive"]: byedpi_zip,
    }

    def handler(request: httpx.Request) -> httpx.Response:
        payload = url_map.get(str(request.url))
        if payload is None:
            return httpx.Response(404, text=f"Not mocked: {request.url}")
        return httpx.Response(200, content=payload)

    return httpx.MockTransport(handler)


@pytest.mark.asyncio
async def test_fetch_zapret_win_bundle_extracts_and_blocks_zipslip(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    transport = _build_mock_transport()
    async with httpx.AsyncClient(transport=transport) as client:
        result = await fetch_zapret_win_bundle(bin_dir, client=client)

    assert (bin_dir / "winws2.exe").read_bytes().startswith(b"MZWINWS2")
    assert (bin_dir / "WinDivert.dll").read_bytes() == b"DLL"
    assert (bin_dir / "WinDivert64.sys").read_bytes() == b"SYS"
    assert (bin_dir / "cygwin1.dll").read_bytes() == b"CYG"
    assert (bin_dir / "lua" / "zapret-lib.lua").is_file()
    assert (bin_dir / "blockcheck" / "blockcheck2.cmd").is_file()
    assert (bin_dir / "blockcheck" / "zapret2" / "blockcheck2.sh").is_file()
    assert (bin_dir / "tools" / "elevator.exe").is_file()
    assert (bin_dir / "cygwin" / "bin" / "bash.exe").is_file()
    assert (bin_dir / "cygwin" / "bin" / "cygpath.exe").is_file()
    assert not (tmp_path / "evil.txt").exists()
    assert not (tmp_path / "outside.txt").exists()
    assert "winws2" in result or "winws2.exe" in result


@pytest.mark.asyncio
async def test_fetch_tg_ws_proxy_extracts_exe_and_headless(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    transport = _build_mock_transport()
    async with httpx.AsyncClient(transport=transport) as client:
        result = await fetch_tg_ws_proxy(bin_dir, client=client)

    assert result["exe"] == bin_dir / "tg-ws-proxy" / "TgWsProxy_windows.exe"
    assert result["exe"].read_bytes().startswith(b"MZTGEXE")
    assert (bin_dir / "tg-ws-proxy" / "proxy" / "tg_ws_proxy.py").is_file()
    assert (bin_dir / "tg-ws-proxy" / "utils" / "logging_setup.py").is_file()
    assert (bin_dir / "tg-ws-proxy" / "pyproject.toml").is_file()
    assert (bin_dir / "tg-ws-proxy" / "LICENSE").is_file()
    assert not (bin_dir / "tg-ws-proxy" / "windows.py").exists()


@pytest.mark.asyncio
async def test_fetch_zapret_discord_youtube_preserves_existing_and_no_clobber(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    lists_dir = tmp_path / "lists"
    presets_dir = tmp_path / "presets"
    lists_dir.mkdir(parents=True)
    exclude_vpn = lists_dir / "exclude_vpn_ips.txt"
    exclude_vpn.write_text("de1.example.com\n", encoding="utf-8")

    transport = _build_mock_transport()
    async with httpx.AsyncClient(transport=transport) as client:
        await fetch_zapret_win_bundle(bin_dir, client=client)
        await fetch_zapret_discord_youtube(bin_dir, lists_dir, presets_dir, client=client)

    assert exclude_vpn.read_text(encoding="utf-8") == "de1.example.com\n"
    assert (lists_dir / "list-general.txt").read_text(encoding="utf-8") == "discord.com\n"
    assert (lists_dir / "ipset-all.txt").read_text(encoding="utf-8") == "203.0.113.113/32\n"
    assert (lists_dir / "ipset-all.txt.backup").read_text(encoding="utf-8") == "1.1.1.0/24\n"
    assert (bin_dir / "files" / "tls_clienthello_www_google_com.bin").is_file()
    # zapret1 WinDivert.dll must NOT overwrite zapret-win-bundle's WinDivert.dll
    assert (bin_dir / "WinDivert.dll").read_bytes() == b"DLL"
    assert (presets_dir / "zapret-discord-youtube" / "general.bat").is_file()
    assert (presets_dir / "zapret-discord-youtube" / "utils" / "targets.txt").is_file()


@pytest.mark.asyncio
async def test_fetch_byedpi_extracts_ciadpi(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    transport = _build_mock_transport()
    async with httpx.AsyncClient(transport=transport) as client:
        exe = await fetch_byedpi(bin_dir, client=client)

    assert exe == bin_dir / "ciadpi.exe"
    assert exe.read_bytes().startswith(b"MZCIADPI")


@pytest.mark.asyncio
async def test_fetch_all_bins_protects_existing_singbox_and_verifies_uac_740(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bin_dir = tmp_path / "bin"
    lists_dir = tmp_path / "lists"
    presets_dir = tmp_path / "presets"
    bin_dir.mkdir(parents=True)

    sb_exe = bin_dir / "sing-box.exe"
    sb_bytes = _fake_pe(b"PREINSTALLED_SINGBOX")
    sb_exe.write_bytes(sb_bytes)
    original_sha = sha256_file(sb_exe)

    transport = _build_mock_transport()
    async with httpx.AsyncClient(transport=transport) as client:
        summary = await fetch_all_bins(bin_dir, lists_dir, presets_dir, force=True, client=client)

    assert summary["manifest_path"].is_file()
    assert sha256_file(sb_exe) == original_sha

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        exe_name = Path(cmd[0]).name.lower()
        if exe_name == "winws2.exe":
            err = OSError(1920, "The requested operation requires elevation")
            err.winerror = 740
            raise err
        if exe_name == "sing-box.exe":
            return subprocess.CompletedProcess(cmd, 0, stdout="sing-box version 1.14.4\n", stderr="")
        if exe_name == "ciadpi.exe":
            return subprocess.CompletedProcess(cmd, 0, stdout="-i, --ip <ip>\n", stderr="")
        if exe_name == "cygpath.exe":
            return subprocess.CompletedProcess(cmd, 0, stdout="Usage: cygpath\n", stderr="")
        if "tg_ws_proxy.py" in " ".join(cmd):
            return subprocess.CompletedProcess(cmd, 0, stdout="usage: tg_ws_proxy.py\n", stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    report = verify_binaries(bin_dir, lists_dir, presets_dir, run_checks=True)

    assert report["ok"] is True
    assert report["tools"]["winws2"]["uac_required"] is True
    assert report["tools"]["winws2"]["status"] == "warn_uac"
    assert report["manifest"]["status"] == "ok"

    # Missing file invalidates both manifest and tool status
    (bin_dir / "ciadpi.exe").unlink()
    bad_report = verify_binaries(bin_dir, lists_dir, presets_dir, run_checks=True)
    assert bad_report["ok"] is False
    assert bad_report["tools"]["ciadpi"]["status"] == "missing"
    assert bad_report["manifest"]["status"] == "error"


def test_cli_fetch_bins_verify_only_exit_codes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runner = CliRunner()
    fake_report_ok = {
        "ok": True,
        "is_admin": False,
        "tools": {
            "sing-box": {"status": "ok", "path": "bin/sing-box.exe", "sha256": "a" * 64, "detail": "1.14.4"},
            "winws2": {"status": "warn_uac", "path": "bin/winws2.exe", "sha256": "b" * 64, "detail": "WinError 740"},
        },
        "lists": {"status": "ok", "path": "lists", "detail": "6 lists"},
        "presets": {"status": "ok", "path": "presets", "detail": "22 presets"},
        "manifest": {"status": "ok", "path": "bin/manifest.json", "detail": "ok"},
    }
    monkeypatch.setattr("netdoctor.cli.verify_binaries", lambda *args, **kwargs: fake_report_ok)
    res_ok = runner.invoke(app, ["fetch-bins", "--verify-only", "--bin-dir", str(tmp_path / "bin")])
    assert res_ok.exit_code == 0

    fake_report_bad = json.loads(json.dumps(fake_report_ok))
    fake_report_bad["ok"] = False
    fake_report_bad["tools"]["sing-box"]["status"] = "missing"
    monkeypatch.setattr("netdoctor.cli.verify_binaries", lambda *args, **kwargs: fake_report_bad)
    res_bad = runner.invoke(app, ["fetch-bins", "--verify-only", "--bin-dir", str(tmp_path / "bin")])
    assert res_bad.exit_code == 1


def test_venv_dependencies_installed_and_consistent() -> None:
    required_dists = [
        "httpx",
        "dnspython",
        "PyYAML",
        "pydantic",
        "typer",
        "rich",
        "psutil",
        "pytest",
        "pytest-asyncio",
        "certifi",
        "cryptography",
        "h2",
    ]
    for dist in required_dists:
        ver = importlib.metadata.version(dist)
        assert ver, f"Missing distribution: {dist}"

    proc = subprocess.run([sys.executable, "-m", "pip", "check"], capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0, f"pip check failed: {proc.stdout}\n{proc.stderr}"


def test_local_r1_artifacts_verified() -> None:
    repo_root = Path(__file__).resolve().parent.parent
    bin_dir = repo_root / "bin"
    lists_dir = repo_root / "lists"
    presets_dir = repo_root / "presets"

    report = verify_binaries(bin_dir, lists_dir, presets_dir, run_checks=True)
    assert report["ok"] is True, f"verify_binaries failed: {report}"
    assert report["tools"]["sing-box"]["runnable"] is True
    assert "1.14.4" in (report["tools"]["sing-box"]["version"] or "")
    assert report["tools"]["sing-box"]["config_ok"] is True
    assert report["tools"]["sing-box"]["sha256"] == "8f30682ee198855440d2a7fe070d5d3653793b2d01bb8c85eea88f93bbe7c8b9"

    assert report["tools"]["winws2"]["exists"] is True
    assert all(report["tools"]["winws2"]["supporting_files"].values())
    assert report["tools"]["winws2"]["status"] in ("ok", "warn_uac")

    assert report["tools"]["blockcheck2"]["exists"] is True
    assert report["tools"]["blockcheck2"]["runnable"] is True
    assert report["tools"]["ciadpi"]["runnable"] is True
    assert report["tools"]["tg-ws-proxy"]["exe_exists"] is True
    assert report["tools"]["tg-ws-proxy"]["runnable"] is True

    assert report["lists"]["status"] == "ok"
    assert (lists_dir / "exclude_vpn_ips.txt").is_file()
    assert (lists_dir / "ipset-all.txt.backup").stat().st_size > 1000

    assert report["presets"]["status"] == "ok"
    assert report["presets"]["bat_count"] >= 20
    assert report["manifest"]["status"] == "ok"

    # Empirically confirm tg-ws-proxy headless CLI flags & MTProto-only behavior
    tg_help = subprocess.run(
        [sys.executable, str((bin_dir / "tg-ws-proxy" / "proxy" / "tg_ws_proxy.py").resolve()), "--help"],
        cwd=str((bin_dir / "tg-ws-proxy").resolve()),
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert tg_help.returncode == 0
    assert "--port" in tg_help.stdout
    assert "--host" in tg_help.stdout
    assert "--secret" in tg_help.stdout
    assert "MTProto" in tg_help.stdout


@pytest.mark.asyncio
async def test_verify_binaries_two_args_cwd_independent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ws_dir = tmp_path / "ws"
    bin_dir = ws_dir / "bin"
    lists_dir = ws_dir / "lists"
    presets_dir = ws_dir / "presets"
    other_cwd = tmp_path / "external_cwd"
    bin_dir.mkdir(parents=True)
    other_cwd.mkdir(parents=True)

    (bin_dir / "sing-box.exe").write_bytes(_fake_pe(b"SINGBOX"))
    transport = _build_mock_transport()
    async with httpx.AsyncClient(transport=transport) as client:
        await fetch_all_bins(bin_dir, lists_dir, presets_dir, force=True, client=client)

    monkeypatch.chdir(other_cwd)
    report = verify_binaries(bin_dir, lists_dir, run_checks=False)
    assert report["ok"] is True
    assert report["presets"]["status"] == "ok"
    assert report["manifest"]["status"] == "ok"


@pytest.mark.asyncio
async def test_verify_binaries_rejects_stripped_manifest_with_trojan_binary(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    lists_dir = tmp_path / "lists"
    presets_dir = tmp_path / "presets"
    bin_dir.mkdir(parents=True)
    (bin_dir / "sing-box.exe").write_bytes(_fake_pe(b"REAL_SINGBOX"))

    transport = _build_mock_transport()
    async with httpx.AsyncClient(transport=transport) as client:
        await fetch_all_bins(bin_dir, lists_dir, presets_dir, force=True, client=client)

    # Replace sing-box.exe with a trojan PE and strip manifest.json down to a single list file
    (bin_dir / "sing-box.exe").write_bytes(_fake_pe(b"TROJAN_SINGBOX"))
    list_file = lists_dir / "list-general.txt"
    stripped_manifest = {
        "schema_version": 1,
        "artifacts": {
            "zapret-discord-youtube": {
                "files": [
                    {
                        "root": "lists",
                        "relpath": "list-general.txt",
                        "size": list_file.stat().st_size,
                        "sha256": sha256_file(list_file),
                    }
                ]
            }
        },
    }
    (bin_dir / "manifest.json").write_text(json.dumps(stripped_manifest), encoding="utf-8")

    report = verify_binaries(bin_dir, lists_dir, presets_dir, run_checks=False)
    assert report["ok"] is False
    assert report["manifest"]["status"] == "error"
    assert any("missing_from_manifest" in m for m in report["manifest"]["mismatches"])


@pytest.mark.asyncio
async def test_verify_binaries_rejects_manifest_traversal_and_unknown_root(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    lists_dir = tmp_path / "lists"
    presets_dir = tmp_path / "presets"
    bin_dir.mkdir(parents=True)
    (bin_dir / "sing-box.exe").write_bytes(_fake_pe(b"SINGBOX"))

    transport = _build_mock_transport()
    async with httpx.AsyncClient(transport=transport) as client:
        await fetch_all_bins(bin_dir, lists_dir, presets_dir, force=True, client=client)

    outside_file = tmp_path / "outside.txt"
    outside_file.write_text("secret", encoding="utf-8")
    manifest_path = bin_dir / "manifest.json"
    base_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    # Case 1: path traversal in relpath
    trav_manifest = json.loads(json.dumps(base_manifest))
    trav_manifest["artifacts"]["sing-box"]["files"].append(
        {
            "root": "bin",
            "relpath": "../outside.txt",
            "size": outside_file.stat().st_size,
            "sha256": sha256_file(outside_file),
        }
    )
    manifest_path.write_text(json.dumps(trav_manifest), encoding="utf-8")
    trav_report = verify_binaries(bin_dir, lists_dir, presets_dir, run_checks=False)
    assert trav_report["ok"] is False
    assert trav_report["manifest"]["status"] == "error"
    assert any("path_traversal" in m for m in trav_report["manifest"]["mismatches"])

    # Case 2: unknown root key
    unknown_manifest = json.loads(json.dumps(base_manifest))
    unknown_manifest["artifacts"]["sing-box"]["files"].append(
        {
            "root": "etc",
            "relpath": "passwd",
            "size": 10,
            "sha256": "0" * 64,
        }
    )
    manifest_path.write_text(json.dumps(unknown_manifest), encoding="utf-8")
    unknown_report = verify_binaries(bin_dir, lists_dir, presets_dir, run_checks=False)
    assert unknown_report["ok"] is False
    assert unknown_report["manifest"]["status"] == "error"
    assert any("unknown_root" in m for m in unknown_report["manifest"]["mismatches"])


@pytest.mark.asyncio
async def test_verify_binaries_handles_winws2_timeout_expired_cleanly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bin_dir = tmp_path / "bin"
    lists_dir = tmp_path / "lists"
    presets_dir = tmp_path / "presets"
    bin_dir.mkdir(parents=True)
    (bin_dir / "sing-box.exe").write_bytes(_fake_pe(b"SINGBOX"))

    transport = _build_mock_transport()
    async with httpx.AsyncClient(transport=transport) as client:
        await fetch_all_bins(bin_dir, lists_dir, presets_dir, force=True, client=client)

    def fake_run_timeout(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        assert kwargs.get("stdin") == subprocess.DEVNULL
        exe_name = Path(cmd[0]).name.lower()
        if exe_name == "winws2.exe":
            raise subprocess.TimeoutExpired(cmd=cmd, timeout=5.0)
        if exe_name == "sing-box.exe":
            return subprocess.CompletedProcess(cmd, 0, stdout="sing-box version 1.14.4\n", stderr="")
        if exe_name == "ciadpi.exe":
            return subprocess.CompletedProcess(cmd, 0, stdout="-i, --ip <ip>\n", stderr="")
        if exe_name == "cygpath.exe":
            return subprocess.CompletedProcess(cmd, 0, stdout="Usage: cygpath\n", stderr="")
        if "tg_ws_proxy.py" in " ".join(cmd):
            return subprocess.CompletedProcess(cmd, 0, stdout="usage: tg_ws_proxy.py\n", stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run_timeout)
    report = verify_binaries(bin_dir, lists_dir, presets_dir, run_checks=True)
    assert report["ok"] is False
    assert report["tools"]["winws2"]["runnable"] is False
    assert report["tools"]["winws2"]["status"] == "error"
    assert "timed out" in report["tools"]["winws2"]["detail"].lower()


def test_cli_fetch_bins_verify_only_without_presets_dir_is_cwd_independent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ws_dir = tmp_path / "ws"
    abs_bin = (ws_dir / "bin").resolve()
    abs_lists = (ws_dir / "lists").resolve()
    other_cwd = (tmp_path / "external_cwd").resolve()
    abs_bin.mkdir(parents=True)
    other_cwd.mkdir(parents=True)
    (abs_bin / "sing-box.exe").write_bytes(_fake_pe(b"SINGBOX"))

    async def _setup() -> None:
        transport = _build_mock_transport()
        async with httpx.AsyncClient(transport=transport) as client:
            await fetch_all_bins(abs_bin, abs_lists, force=True, client=client)

    asyncio.run(_setup())

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        exe_name = Path(cmd[0]).name.lower()
        if exe_name == "winws2.exe":
            err = OSError(1920, "The requested operation requires elevation")
            err.winerror = 740
            raise err
        if exe_name == "sing-box.exe":
            return subprocess.CompletedProcess(cmd, 0, stdout="sing-box version 1.14.4\n", stderr="")
        if exe_name == "ciadpi.exe":
            return subprocess.CompletedProcess(cmd, 0, stdout="-i, --ip <ip>\n", stderr="")
        if exe_name == "cygpath.exe":
            return subprocess.CompletedProcess(cmd, 0, stdout="Usage: cygpath\n", stderr="")
        if "tg_ws_proxy.py" in " ".join(cmd):
            return subprocess.CompletedProcess(cmd, 0, stdout="usage: tg_ws_proxy.py\n", stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.chdir(other_cwd)

    res = CliRunner().invoke(
        app,
        ["fetch-bins", "--verify-only", "--bin-dir", str(abs_bin), "--lists-dir", str(abs_lists)],
    )
    assert res.exit_code == 0, res.output
    assert not (other_cwd / "presets").exists()
    assert (abs_bin.parent / "presets" / "zapret-discord-youtube" / "general.bat").is_file()


@pytest.mark.asyncio
async def test_fetch_all_bins_two_args_resolves_presets_relative_to_bin_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ws_dir = tmp_path / "ws"
    abs_bin = (ws_dir / "bin").resolve()
    abs_lists = (ws_dir / "lists").resolve()
    other_cwd = (tmp_path / "external_cwd").resolve()
    abs_bin.mkdir(parents=True)
    other_cwd.mkdir(parents=True)
    (abs_bin / "sing-box.exe").write_bytes(_fake_pe(b"SINGBOX"))

    monkeypatch.chdir(other_cwd)
    transport = _build_mock_transport()
    async with httpx.AsyncClient(transport=transport) as client:
        summary = await fetch_all_bins(abs_bin, abs_lists, client=client)

    expected_presets = abs_bin.parent / "presets"
    assert not (other_cwd / "presets").exists()
    assert (expected_presets / "zapret-discord-youtube" / "general.bat").is_file()
    assert (expected_presets / "zapret-discord-youtube" / "utils" / "targets.txt").is_file()
    assert summary["manifest_path"] == abs_bin / "manifest.json"

    report = verify_binaries(abs_bin, abs_lists, run_checks=False)
    assert report["ok"] is True
    assert report["presets"]["status"] == "ok"
    assert report["manifest"]["status"] == "ok"


def test_gui_backend_ensure_deps_skips_valid_and_downloads_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import netdoctor.gui_backend as backend_mod
    from netdoctor.gui_backend import GuiBackend

    backend = GuiBackend(
        db_path=tmp_path / "deps.db",
        configs_dir=tmp_path / "configs",
        lists_dir=tmp_path / "lists",
        logs_dir=tmp_path / "logs",
        bin_dir=tmp_path / "bin",
    )

    fetch_calls: list[bool] = []

    async def fake_fetch(bin_dir: Path, lists_dir: Path, presets_dir: Path | None = None, *, force: bool = False, **_kw: Any) -> dict[str, Any]:
        fetch_calls.append(force)
        return {"ok": True}

    monkeypatch.setattr(backend_mod, "fetch_all_bins", fake_fetch)

    # 1. Valid binaries -> skips download
    monkeypatch.setattr(backend_mod, "verify_binaries", lambda *_a, **_kw: {"ok": True, "tools": {}})
    res_valid = backend.ensure_deps()
    assert res_valid["ok"] is True
    assert res_valid["downloaded"] is False
    assert fetch_calls == []

    # 2. Missing binaries -> downloads once (force=False), then verifies ok
    states = iter([{"ok": False}, {"ok": True}])
    monkeypatch.setattr(backend_mod, "verify_binaries", lambda *_a, **_kw: next(states))
    res_fetched = backend.ensure_deps()
    assert res_fetched["ok"] is True
    assert res_fetched["downloaded"] is True
    assert fetch_calls == [False]

    # 3. Broken binaries even after first fetch -> retries with force=True
    fetch_calls.clear()
    retry_states = iter([{"ok": False}, {"ok": False}, {"ok": True}])
    monkeypatch.setattr(backend_mod, "verify_binaries", lambda *_a, **_kw: next(retry_states))
    res_retried = backend.ensure_deps()
    assert res_retried["ok"] is True
    assert res_retried["downloaded"] is True
    assert fetch_calls == [False, True]


def test_gui_backend_start_services_auto_fetches_missing_bins_and_surfaces_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import netdoctor.gui_backend as backend_mod
    from netdoctor.gui_backend import GuiBackend

    bin_dir = tmp_path / "bin"
    lists_dir = tmp_path / "lists"
    backend = GuiBackend(
        db_path=tmp_path / "start.db",
        configs_dir=tmp_path / "configs",
        lists_dir=lists_dir,
        logs_dir=tmp_path / "logs",
        bin_dir=bin_dir,
    )

    monkeypatch.setattr(backend_mod, "_is_admin", lambda: True)
    monkeypatch.setattr(backend_mod, "detect_bypass_active", lambda: False)
    monkeypatch.setattr(backend_mod, "validate_singbox_config", lambda *_a, **_kw: (True, "ok"))

    # 1. Auto-fetch fails -> start_services returns clear auto-download error
    async def failing_fetch(*_a: Any, **_kw: Any) -> dict[str, Any]:
        raise RuntimeError("network unreachable")

    monkeypatch.setattr(backend_mod, "fetch_all_bins", failing_fetch)
    monkeypatch.setattr(backend_mod, "verify_binaries", lambda *_a, **_kw: {"ok": False})
    err_res = backend.start_services(force=True)
    assert err_res["ok"] is False
    assert "auto-download failed: network unreachable" in str(err_res["error"])

    # 2. Auto-fetch downloads missing binaries -> start_services proceeds to start_stack
    fetched_paths: list[Path] = []

    async def populating_fetch(b_dir: Path, l_dir: Path, *_a: Any, **_kw: Any) -> dict[str, Any]:
        b_dir.mkdir(parents=True, exist_ok=True)
        (b_dir / "winws2.exe").write_bytes(_fake_pe(b"WINWS2"))
        (b_dir / "sing-box.exe").write_bytes(_fake_pe(b"SINGBOX"))
        fetched_paths.append(b_dir)
        return {"ok": True}

    started_specs: list[Any] = []

    class FakeSupervisor:
        def __init__(self, **_kw: Any) -> None:
            pass

        def start_stack(self, specs: Any, **_kw: Any) -> None:
            started_specs.extend(specs)

        def status(self) -> dict[str, Any]:
            return {"winws2": {"running": True, "pid": 123}, "sing-box": {"running": True, "pid": 456}}

        def stop_all(self) -> list[str]:
            return []

    monkeypatch.setattr(backend_mod, "fetch_all_bins", populating_fetch)
    monkeypatch.setattr(
        backend_mod,
        "verify_binaries",
        lambda *_a, **_kw: {"ok": (bin_dir / "winws2.exe").is_file() and (bin_dir / "sing-box.exe").is_file()},
    )
    monkeypatch.setattr(backend_mod, "ProcessSupervisor", FakeSupervisor)

    ok_res = backend.start_services(force=True)
    assert ok_res["ok"] is True, ok_res
    assert ok_res["started"] is True
    assert fetched_paths == [bin_dir]
    assert [s[0] for s in started_specs] == ["winws2", "sing-box"]


def test_cli_apply_auto_fetches_missing_binaries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import netdoctor.cli as cli_mod

    db_path = tmp_path / "cli_apply.db"
    cfg_dir = tmp_path / "configs"
    lists_dir = tmp_path / "lists"
    bin_dir = tmp_path / "bin"
    logs_dir = tmp_path / "logs"

    monkeypatch.setattr(cli_mod, "_is_admin", lambda: True)
    monkeypatch.setattr(cli_mod, "detect_bypass_active", lambda: False)
    monkeypatch.setattr(cli_mod, "stop_persisted_supervisor", lambda **_kw: [])
    monkeypatch.setattr(cli_mod, "detect_physical_egress_iface", lambda: 1)

    fetch_calls: list[tuple[Path, Path]] = []

    async def fake_cli_fetch(b_dir: Path, l_dir: Path, *_a: Any, **_kw: Any) -> dict[str, Any]:
        b_dir.mkdir(parents=True, exist_ok=True)
        (b_dir / "winws2.exe").write_bytes(_fake_pe(b"WINWS2"))
        (b_dir / "sing-box.exe").write_bytes(_fake_pe(b"SINGBOX"))
        fetch_calls.append((b_dir, l_dir))
        return {"ok": True}

    class FakeSupervisor:
        def __init__(self, **_kw: Any) -> None:
            pass

        def start_stack(self, *_a: Any, **_kw: Any) -> None:
            pass

        def status(self) -> dict[str, Any]:
            return {"winws2": {"running": True}, "sing-box": {"running": True}}

        def stop_all(self) -> list[str]:
            return []

    monkeypatch.setattr(cli_mod, "fetch_all_bins", fake_cli_fetch)
    monkeypatch.setattr(cli_mod, "ProcessSupervisor", FakeSupervisor)

    res = CliRunner().invoke(
        app,
        [
            "apply",
            "--db",
            str(db_path),
            "--configs-dir",
            str(cfg_dir),
            "--lists-dir",
            str(lists_dir),
            "--bin-dir",
            str(bin_dir),
            "--logs-dir",
            str(logs_dir),
            "--iface",
            "1",
            "--duration",
            "0.01",
        ],
    )
    assert res.exit_code == 0, res.output
    assert fetch_calls == [(bin_dir.resolve(), lists_dir.resolve())]
    assert (bin_dir / "winws2.exe").is_file()
    assert (bin_dir / "sing-box.exe").is_file()


def test_sync_blockcheck_fake_bins_copies_without_clobber(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    bc_fake = bin_dir / "blockcheck" / "zapret" / "files" / "fake"
    bc_fake.mkdir(parents=True)
    kyber_src = bc_fake / "tls_clienthello_vk_com_kyber.bin"
    kyber_src.write_bytes(b"KYBER_HELLO")
    existing_src = bc_fake / "tls_clienthello_www_google_com.bin"
    existing_src.write_bytes(b"BLOCKCHECK_GOOGLE")

    files_dir = bin_dir / "files"
    files_dir.mkdir(parents=True)
    existing_dst = files_dir / "tls_clienthello_www_google_com.bin"
    existing_dst.write_bytes(b"EXISTING_GOOGLE")

    copied = _sync_blockcheck_fake_bins(bin_dir)

    assert files_dir / "tls_clienthello_vk_com_kyber.bin" in copied
    assert (files_dir / "tls_clienthello_vk_com_kyber.bin").read_bytes() == b"KYBER_HELLO"
    assert existing_dst.read_bytes() == b"EXISTING_GOOGLE"


def test_extract_blob_args_falls_back_for_missing_files(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    files_dir = bin_dir / "files"
    files_dir.mkdir(parents=True)
    (files_dir / "tls_clienthello_www_google_com.bin").write_bytes(b"TLS_GOOGLE")
    (files_dir / "stun.bin").write_bytes(b"STUN_PKT")

    blob_args = extract_blob_args(
        [
            "--lua-desync=fake:blob=tls_vk_kyber:repeats=6",
            "--lua-desync=fake:blob=discord_active:repeats=6",
            "--lua-desync=fake:blob=quic_rutube:repeats=4",
        ],
        bin_dir=bin_dir,
    )

    assert "--blob=tls_vk_kyber:@files/tls_clienthello_www_google_com.bin" in blob_args
    assert "--blob=discord_active:@files/stun.bin" in blob_args
    assert f"--blob=quic_rutube:0x{'00' * 64}" in blob_args

