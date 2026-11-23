"""Pytest fixtures and elevation gating for netdoctor 4-Tier E2E test suite."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator

import psutil
import pytest

_E2E_DIR = Path(__file__).resolve().parent
if str(_E2E_DIR) not in sys.path:
    sys.path.insert(0, str(_E2E_DIR))

import e2e_support  # noqa: E402
from tests.fake_censor import FakeCensorServer  # noqa: E402


# ---------------------------------------------------------------------------
# Pytest Hooks: @pytest.mark.elevated gating
# ---------------------------------------------------------------------------


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--run-elevated",
        action="store_true",
        default=False,
        help="Run @pytest.mark.elevated live TUN/WinDivert E2E tests (requires Admin & paused Happ/Zapret).",
    )


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "elevated: live Windows Admin test requiring TUN/WinDivert and paused host bypasses (Happ/Zapret).",
    )


def _elevated_enabled(config: pytest.Config) -> bool:
    if config.getoption("--run-elevated"):
        return True
    return os.environ.get("NETDOCTOR_LIVE_E2E", "").strip().lower() in {"1", "true", "yes"}


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if _elevated_enabled(config):
        return
    skip_elevated = pytest.mark.skip(
        reason="Elevated live TUN/WinDivert test skipped; pass --run-elevated or set NETDOCTOR_LIVE_E2E=1"
    )
    for item in items:
        if "elevated" in item.keywords:
            item.add_marker(skip_elevated)


# ---------------------------------------------------------------------------
# Session Path Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session")
def venv_python(repo_root: Path) -> Path:
    py = repo_root / ".venv" / "Scripts" / "python.exe"
    return py if py.is_file() else Path(sys.executable)


@pytest.fixture(scope="session")
def netdoctor_exe(repo_root: Path) -> Path:
    return repo_root / ".venv" / "Scripts" / "netdoctor.exe"


@pytest.fixture(scope="session")
def bin_dir(repo_root: Path) -> Path:
    return repo_root / "bin"


@pytest.fixture(scope="session")
def lists_dir(repo_root: Path) -> Path:
    return repo_root / "lists"


@pytest.fixture(scope="session")
def presets_dir(repo_root: Path) -> Path:
    primary = repo_root / "presets"
    if primary.is_dir():
        return primary
    alt = repo_root / "configs" / "presets"
    return alt if alt.is_dir() else primary


# ---------------------------------------------------------------------------
# Workspace & Ephemeral Port Fixtures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class E2EWorkspace:
    root: Path
    db_path: Path
    configs_dir: Path
    lists_dir: Path
    logs_dir: Path
    bin_dir: Path

    @property
    def state_file(self) -> Path:
        return self.logs_dir / "supervisor_state.json"


@pytest.fixture
def e2e_workspace(tmp_path: Path) -> E2EWorkspace:
    configs = tmp_path / "configs"
    lists = tmp_path / "lists"
    logs = tmp_path / "logs"
    bdir = tmp_path / "bin"
    configs.mkdir(parents=True, exist_ok=True)
    lists.mkdir(parents=True, exist_ok=True)
    logs.mkdir(parents=True, exist_ok=True)
    bdir.mkdir(parents=True, exist_ok=True)
    return E2EWorkspace(
        root=tmp_path,
        db_path=tmp_path / "netdoctor.db",
        configs_dir=configs,
        lists_dir=lists,
        logs_dir=logs,
        bin_dir=bdir,
    )


@pytest.fixture
def free_tcp_port() -> int:
    return e2e_support.allocate_ephemeral_port("tcp")


@pytest.fixture
def free_udp_port() -> int:
    return e2e_support.allocate_ephemeral_port("udp")


# ---------------------------------------------------------------------------
# Subprocess & FakeCensor Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def run_netdoctor(
    netdoctor_exe: Path,
    venv_python: Path,
    repo_root: Path,
) -> Callable[..., subprocess.CompletedProcess[str]]:
    def _run(
        args: list[str],
        cwd: Path | None = None,
        timeout: float = 30.0,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        base_cmd = (
            [str(netdoctor_exe)]
            if netdoctor_exe.is_file()
            else [str(venv_python), "-m", "netdoctor.cli"]
        )
        run_env = os.environ.copy()
        run_env.setdefault("PYTHONIOENCODING", "utf-8")
        if env:
            run_env.update(env)
        return subprocess.run(
            [*base_cmd, *args],
            cwd=str(cwd or repo_root),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env=run_env,
        )

    return _run


@pytest.fixture
def spawn_supervised_process() -> Iterator[Callable[..., subprocess.Popen[bytes]]]:
    spawned: list[subprocess.Popen[bytes]] = []

    def _spawn(
        cmd: list[str],
        cwd: Path | None = None,
        stdout: Any = subprocess.PIPE,
        stderr: Any = subprocess.PIPE,
        env: dict[str, str] | None = None,
    ) -> subprocess.Popen[bytes]:
        run_env = os.environ.copy()
        run_env.setdefault("PYTHONIOENCODING", "utf-8")
        if env:
            run_env.update(env)
        flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        proc = subprocess.Popen(
            cmd,
            cwd=str(cwd) if cwd else None,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            creationflags=flags,
            env=run_env,
        )
        spawned.append(proc)
        return proc

    try:
        yield _spawn
    finally:
        for proc in reversed(spawned):
            if proc.poll() is None:
                try:
                    sig = getattr(signal, "CTRL_BREAK_EVENT", signal.SIGTERM)
                    proc.send_signal(sig)
                    proc.wait(timeout=3.0)
                except Exception:
                    try:
                        proc.terminate()
                        proc.wait(timeout=2.0)
                    except Exception:
                        try:
                            proc.kill()
                            proc.wait(timeout=2.0)
                        except Exception:
                            pass
            for stream in (proc.stdout, proc.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except Exception:
                        pass


@pytest.fixture
async def fake_censor_factory() -> Iterator[Callable[..., FakeCensorServer]]:
    servers: list[FakeCensorServer] = []

    async def _create(mode: str = "ok", blocked_sni: str = "discord.com") -> FakeCensorServer:
        srv = FakeCensorServer(mode=mode, blocked_sni=blocked_sni)
        await srv.start()
        servers.append(srv)
        return srv

    try:
        yield _create
    finally:
        for srv in reversed(servers):
            try:
                await srv.stop()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Elevated Live TUN / WinDivert Preflight & Teardown Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def elevated_clean_host() -> dict[str, Any]:
    """Fail fast if running elevated tests without Admin or with active Happ/Zapret."""
    admin = e2e_support.is_admin()
    bypasses = e2e_support.detect_host_bypasses()
    phys_ifidx = e2e_support.get_physical_uplink_ifindex()

    errors: list[str] = []
    if not admin:
        errors.append("Administrator privileges required (IsUserAnAdmin() == False)")
    if bypasses["active"]:
        errors.append(
            "Conflicting host bypass/VPN active: "
            f"processes={bypasses['processes']}, "
            f"up_tun_adapters={bypasses['up_tun_adapters']}, "
            f"split_routes={bypasses['split_routes']}"
        )
    if phys_ifidx is None:
        errors.append("Could not determine active physical IPv4 uplink adapter ifIndex")

    if errors:
        pytest.fail("elevated_clean_host preflight failed:\n- " + "\n- ".join(errors))

    return {
        "admin": admin,
        "phys_ifidx": phys_ifidx,
        "best_if_1_1_1_1": e2e_support.get_best_interface_index("1.1.1.1"),
    }


def _kill_leftover_stage1_processes() -> None:
    targets = ("sing-box.exe", "winws2.exe", "tg-ws-proxy.exe", "tgwsproxy_windows.exe")
    for target in targets:
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                if (proc.info.get("name") or "").lower() == target:
                    proc.terminate()
                    proc.wait(timeout=2.0)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass


@pytest.fixture
def live_apply_guard(
    elevated_clean_host: dict[str, Any],
    netdoctor_exe: Path,
    venv_python: Path,
    repo_root: Path,
) -> Callable[..., Any]:
    phys_ifidx = int(elevated_clean_host["phys_ifidx"])

    @contextmanager
    def _guard(
        extra_args: list[str] | None = None,
        cwd: Path | None = None,
        wait_for_tun: bool = True,
        startup_timeout: float = 15.0,
    ) -> Iterator[dict[str, Any]]:
        work_cwd = cwd or repo_root
        base_cmd = (
            [str(netdoctor_exe)]
            if netdoctor_exe.is_file()
            else [str(venv_python), "-m", "netdoctor.cli"]
        )
        cmd = [*base_cmd, "apply", *(extra_args or [])]
        flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        proc = subprocess.Popen(
            cmd,
            cwd=str(work_cwd),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=flags,
        )
        tun_info: dict[str, Any] = {}
        try:
            if wait_for_tun:
                tun_info = e2e_support.wait_for_tun_and_split_routes(
                    tun_name="netdoctor-tun", timeout=startup_timeout
                )
            yield {
                "proc": proc,
                "phys_ifidx": phys_ifidx,
                "tun_info": tun_info,
                "cwd": work_cwd,
            }
        finally:
            if proc.poll() is None:
                try:
                    proc.send_signal(getattr(signal, "CTRL_BREAK_EVENT", signal.SIGTERM))
                    proc.wait(timeout=6.0)
                except Exception:
                    pass

            try:
                subprocess.run(
                    [*base_cmd, "stop"],
                    cwd=str(work_cwd),
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    timeout=10.0,
                )
            except Exception:
                pass

            if proc.poll() is None:
                try:
                    proc.terminate()
                    proc.wait(timeout=3.0)
                except Exception:
                    try:
                        proc.kill()
                        proc.wait(timeout=2.0)
                    except Exception:
                        pass

            _kill_leftover_stage1_processes()

            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                byp = e2e_support.detect_host_bypasses()
                if not byp["up_tun_adapters"] and not byp["split_routes"]:
                    break
                time.sleep(0.4)

            # Emergency split-route recovery if orphaned after dead TUN
            byp = e2e_support.detect_host_bypasses()
            if byp["split_routes"]:
                for prefix in ("0.0.0.0", "128.0.0.0"):
                    subprocess.run(
                        ["route", "delete", prefix, "mask", "128.0.0.0"],
                        stdin=subprocess.DEVNULL,
                        capture_output=True,
                        timeout=5.0,
                    )

            for stream in (proc.stdout, proc.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except Exception:
                        pass

            routes_after = e2e_support.get_ipv4_default_and_split_routes()
            split_left = [
                r for r in routes_after if r.get("DestinationPrefix") in {"0.0.0.0/1", "128.0.0.0/1"}
            ]
            assert not split_left, f"Orphaned split routes remain after teardown: {split_left}"
            best_after = e2e_support.get_best_interface_index("1.1.1.1")
            assert best_after == phys_ifidx, (
                f"Default route not restored to physical ifIdx={phys_ifidx}; got {best_after}"
            )

    return _guard


@pytest.fixture
def pktmon_capture(elevated_clean_host: dict[str, Any], tmp_path: Path) -> Callable[..., Any]:
    @contextmanager
    def _capture(port: int = 443, pkt_size: int = 256) -> Iterator[dict[str, Path]]:
        etl_path = tmp_path / "r2_capture.etl"
        pcapng_path = tmp_path / "r2_capture.pcapng"

        subprocess.run(["pktmon", "stop"], stdin=subprocess.DEVNULL, capture_output=True, timeout=5.0)
        subprocess.run(["pktmon", "filter", "remove"], stdin=subprocess.DEVNULL, capture_output=True, timeout=5.0)
        add_res = subprocess.run(
            ["pktmon", "filter", "add", "-p", str(port)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=5.0,
        )
        assert add_res.returncode == 0, f"pktmon filter add failed: {add_res.stdout} {add_res.stderr}"

        start_res = subprocess.run(
            ["pktmon", "start", "--capture", "--pkt-size", str(pkt_size), "-f", str(etl_path)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=10.0,
        )
        assert start_res.returncode == 0, f"pktmon start failed: {start_res.stdout} {start_res.stderr}"
        try:
            yield {"etl": etl_path, "pcapng": pcapng_path}
        finally:
            subprocess.run(["pktmon", "stop"], stdin=subprocess.DEVNULL, capture_output=True, timeout=10.0)
            subprocess.run(["pktmon", "filter", "remove"], stdin=subprocess.DEVNULL, capture_output=True, timeout=5.0)
            if etl_path.is_file():
                subprocess.run(
                    ["pktmon", "etl2pcap", str(etl_path), "--out", str(pcapng_path)],
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    timeout=15.0,
                )

    return _capture
