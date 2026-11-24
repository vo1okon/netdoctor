"""Windows single-instance guard, Task Scheduler autostart, and native Win32 system tray icon."""

from __future__ import annotations

import base64
import ctypes
from ctypes import wintypes
import logging
import os
import struct
import subprocess
import sys
import threading
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import psutil

__all__ = [
    "NetdoctorTrayIcon",
    "acquire_single_instance_mutex",
    "build_autostart_command",
    "create_gui_shortcut",
    "get_autostart_status",
    "release_single_instance_mutex",
    "set_autostart_enabled",
    "terminate_pid_gracefully",
    "write_app_icon",
]

logger = logging.getLogger(__name__)

# Single-instance & schtasks defaults
DEFAULT_MUTEX_NAME = "Local\\NetdoctorGuiMutex"
DEFAULT_AUTOSTART_TASK_NAME = "NetdoctorAutostart"
DEFAULT_TRAY_TOOLTIP = "netdoctor — Обход блокировок"

# Win32 error codes
ERROR_ALREADY_EXISTS = 183
ERROR_ACCESS_DENIED = 5
ERROR_CLASS_ALREADY_EXISTS = 1410

# Win32 window & tray message constants
WM_NULL = 0x0000
WM_DESTROY = 0x0002
WM_CLOSE = 0x0010
WM_QUIT = 0x0012
WM_CANCELMODE = 0x001F
WM_CONTEXTMENU = 0x007B
WM_COMMAND = 0x0111
WM_LBUTTONUP = 0x0202
WM_LBUTTONDBLCLK = 0x0203
WM_RBUTTONUP = 0x0205
WM_APP = 0x8000
WM_TRAYICON = WM_APP + 1

# Shell_NotifyIcon constants
NIM_ADD = 0x00000000
NIM_MODIFY = 0x00000001
NIM_DELETE = 0x00000002

NIF_MESSAGE = 0x00000001
NIF_ICON = 0x00000002
NIF_TIP = 0x00000004
NIF_INFO = 0x00000010

NIIF_NONE = 0x00000000
NIIF_INFO = 0x00000001
NIIF_WARNING = 0x00000002
NIIF_ERROR = 0x00000003

# Menu & cursor constants
MF_STRING = 0x00000000
MF_SEPARATOR = 0x00000800
TPM_LEFTALIGN = 0x0000
TPM_RIGHTALIGN = 0x0008
TPM_BOTTOMALIGN = 0x0020
TPM_NONOTIFY = 0x0080
TPM_RETURNCMD = 0x0100

IDI_APPLICATION = 32512
DIB_RGB_COLORS = 0
BI_RGB = 0

# Tray popup menu command IDs
MENU_ID_SHOW = 1001
MENU_ID_TOGGLE_PROTECTION = 1002
MENU_ID_ROTATE_VPN = 1003
MENU_ID_FLUSH_DNS = 1004
MENU_ID_EXIT = 1005

ICON_STATE_COLORS: dict[str, tuple[int, int, int]] = {
    "green": (63, 185, 80),
    "active": (63, 185, 80),
    "blue": (96, 205, 255),
    "idle": (96, 205, 255),
    "amber": (210, 153, 34),
    "warning": (210, 153, 34),
}

# 64-bit safe LRESULT & WNDPROC definitions
LRESULT = getattr(wintypes, "LRESULT", wintypes.LPARAM)
WNDPROC = ctypes.WINFUNCTYPE(
    LRESULT,
    wintypes.HWND,
    wintypes.UINT,
    wintypes.WPARAM,
    wintypes.LPARAM,
)


class GUID(ctypes.Structure):
    """Win32 GUID structure."""

    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", wintypes.BYTE * 8),
    ]


class NOTIFYICONDATAW(ctypes.Structure):
    """Win32 NOTIFYICONDATAW (Vista+ V4 layout) structure."""

    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("hWnd", wintypes.HWND),
        ("uID", wintypes.UINT),
        ("uFlags", wintypes.UINT),
        ("uCallbackMessage", wintypes.UINT),
        ("hIcon", wintypes.HICON),
        ("szTip", wintypes.WCHAR * 128),
        ("dwState", wintypes.DWORD),
        ("dwStateMask", wintypes.DWORD),
        ("szInfo", wintypes.WCHAR * 256),
        ("uTimeout", wintypes.UINT),
        ("szInfoTitle", wintypes.WCHAR * 64),
        ("dwInfoFlags", wintypes.DWORD),
        ("guidItem", GUID),
        ("hBalloonIcon", wintypes.HICON),
    ]


class WNDCLASSW(ctypes.Structure):
    """Win32 WNDCLASSW structure."""

    _fields_ = [
        ("style", wintypes.UINT),
        ("lpfnWndProc", WNDPROC),
        ("cbClsExtra", ctypes.c_int),
        ("cbWndExtra", ctypes.c_int),
        ("hInstance", wintypes.HINSTANCE),
        ("hIcon", wintypes.HICON),
        ("hCursor", wintypes.HANDLE),
        ("hbrBackground", wintypes.HBRUSH),
        ("lpszMenuName", wintypes.LPCWSTR),
        ("lpszClassName", wintypes.LPCWSTR),
    ]


class BITMAPINFOHEADER(ctypes.Structure):
    """Win32 BITMAPINFOHEADER structure for in-memory DIB creation."""

    _fields_ = [
        ("biSize", wintypes.DWORD),
        ("biWidth", wintypes.LONG),
        ("biHeight", wintypes.LONG),
        ("biPlanes", wintypes.WORD),
        ("biBitCount", wintypes.WORD),
        ("biCompression", wintypes.DWORD),
        ("biSizeImage", wintypes.DWORD),
        ("biXPelsPerMeter", wintypes.LONG),
        ("biYPelsPerMeter", wintypes.LONG),
        ("biClrUsed", wintypes.DWORD),
        ("biClrImportant", wintypes.DWORD),
    ]


class ICONINFO(ctypes.Structure):
    """Win32 ICONINFO structure."""

    _fields_ = [
        ("fIcon", wintypes.BOOL),
        ("xHotspot", wintypes.DWORD),
        ("yHotspot", wintypes.DWORD),
        ("hbmMask", wintypes.HBITMAP),
        ("hbmColor", wintypes.HBITMAP),
    ]


class _Win32Api:
    """Lazy-initialized Win32 DLL bindings with explicit 64-bit-safe prototypes."""

    def __init__(self) -> None:
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.user32 = ctypes.WinDLL("user32", use_last_error=True)
        self.shell32 = ctypes.WinDLL("shell32", use_last_error=True)
        self.gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)
        self._configure_prototypes()

    def _configure_prototypes(self) -> None:
        k32 = self.kernel32
        u32 = self.user32
        s32 = self.shell32
        g32 = self.gdi32

        k32.CreateMutexW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR]
        k32.CreateMutexW.restype = wintypes.HANDLE
        k32.CloseHandle.argtypes = [wintypes.HANDLE]
        k32.CloseHandle.restype = wintypes.BOOL
        k32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
        k32.GetModuleHandleW.restype = wintypes.HMODULE

        u32.RegisterClassW.argtypes = [ctypes.POINTER(WNDCLASSW)]
        u32.RegisterClassW.restype = wintypes.ATOM
        u32.UnregisterClassW.argtypes = [wintypes.LPCWSTR, wintypes.HINSTANCE]
        u32.UnregisterClassW.restype = wintypes.BOOL
        u32.CreateWindowExW.argtypes = [
            wintypes.DWORD,
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            wintypes.DWORD,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            wintypes.HWND,
            wintypes.HMENU,
            wintypes.HINSTANCE,
            wintypes.LPVOID,
        ]
        u32.CreateWindowExW.restype = wintypes.HWND
        u32.DestroyWindow.argtypes = [wintypes.HWND]
        u32.DestroyWindow.restype = wintypes.BOOL
        u32.DefWindowProcW.argtypes = [
            wintypes.HWND,
            wintypes.UINT,
            wintypes.WPARAM,
            wintypes.LPARAM,
        ]
        u32.DefWindowProcW.restype = LRESULT
        u32.PostMessageW.argtypes = [
            wintypes.HWND,
            wintypes.UINT,
            wintypes.WPARAM,
            wintypes.LPARAM,
        ]
        u32.PostMessageW.restype = wintypes.BOOL
        u32.PostQuitMessage.argtypes = [ctypes.c_int]
        u32.PostQuitMessage.restype = None
        u32.GetMessageW.argtypes = [
            ctypes.POINTER(wintypes.MSG),
            wintypes.HWND,
            wintypes.UINT,
            wintypes.UINT,
        ]
        u32.GetMessageW.restype = wintypes.BOOL
        u32.TranslateMessage.argtypes = [ctypes.POINTER(wintypes.MSG)]
        u32.TranslateMessage.restype = wintypes.BOOL
        u32.DispatchMessageW.argtypes = [ctypes.POINTER(wintypes.MSG)]
        u32.DispatchMessageW.restype = LRESULT
        u32.RegisterWindowMessageW.argtypes = [wintypes.LPCWSTR]
        u32.RegisterWindowMessageW.restype = wintypes.UINT
        u32.LoadIconW.argtypes = [wintypes.HINSTANCE, wintypes.LPCWSTR]
        u32.LoadIconW.restype = wintypes.HICON
        u32.DestroyIcon.argtypes = [wintypes.HICON]
        u32.DestroyIcon.restype = wintypes.BOOL
        u32.CreateIconIndirect.argtypes = [ctypes.POINTER(ICONINFO)]
        u32.CreateIconIndirect.restype = wintypes.HICON
        u32.CreatePopupMenu.argtypes = []
        u32.CreatePopupMenu.restype = wintypes.HMENU
        u32.AppendMenuW.argtypes = [
            wintypes.HMENU,
            wintypes.UINT,
            wintypes.WPARAM,
            wintypes.LPCWSTR,
        ]
        u32.AppendMenuW.restype = wintypes.BOOL
        u32.SetMenuDefaultItem.argtypes = [wintypes.HMENU, wintypes.UINT, wintypes.UINT]
        u32.SetMenuDefaultItem.restype = wintypes.BOOL
        u32.DestroyMenu.argtypes = [wintypes.HMENU]
        u32.DestroyMenu.restype = wintypes.BOOL
        u32.GetCursorPos.argtypes = [ctypes.POINTER(wintypes.POINT)]
        u32.GetCursorPos.restype = wintypes.BOOL
        u32.SetForegroundWindow.argtypes = [wintypes.HWND]
        u32.SetForegroundWindow.restype = wintypes.BOOL
        u32.TrackPopupMenu.argtypes = [
            wintypes.HMENU,
            wintypes.UINT,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            wintypes.HWND,
            ctypes.c_void_p,
        ]
        u32.TrackPopupMenu.restype = wintypes.BOOL
        u32.GetDC.argtypes = [wintypes.HWND]
        u32.GetDC.restype = wintypes.HDC
        u32.ReleaseDC.argtypes = [wintypes.HWND, wintypes.HDC]
        u32.ReleaseDC.restype = ctypes.c_int

        s32.Shell_NotifyIconW.argtypes = [wintypes.DWORD, ctypes.POINTER(NOTIFYICONDATAW)]
        s32.Shell_NotifyIconW.restype = wintypes.BOOL

        g32.CreateDIBSection.argtypes = [
            wintypes.HDC,
            ctypes.POINTER(BITMAPINFOHEADER),
            wintypes.UINT,
            ctypes.POINTER(ctypes.c_void_p),
            wintypes.HANDLE,
            wintypes.DWORD,
        ]
        g32.CreateDIBSection.restype = wintypes.HBITMAP
        g32.CreateBitmap.argtypes = [
            ctypes.c_int,
            ctypes.c_int,
            wintypes.UINT,
            wintypes.UINT,
            ctypes.c_void_p,
        ]
        g32.CreateBitmap.restype = wintypes.HBITMAP
        g32.DeleteObject.argtypes = [wintypes.HGDIOBJ]
        g32.DeleteObject.restype = wintypes.BOOL


_WIN32_API: _Win32Api | None = None
_WIN32_LOCK = threading.Lock()


def _get_win32() -> _Win32Api | None:
    """Return the cached Win32 API bindings on Windows, or None elsewhere."""
    if os.name != "nt":
        return None
    global _WIN32_API
    if _WIN32_API is None:
        with _WIN32_LOCK:
            if _WIN32_API is None:
                _WIN32_API = _Win32Api()
    return _WIN32_API


# --------------------------------------------------------------------------------------
# 1. Single-Instance Win32 Mutex & PID Handoff
# --------------------------------------------------------------------------------------


def acquire_single_instance_mutex(name: str = DEFAULT_MUTEX_NAME) -> tuple[bool, Any]:
    """Acquire a named Win32 mutex for single-instance enforcement.

    Returns ``(True, handle)`` when this process is the primary owner (or ``(True, None)``
    on non-Windows platforms), and ``(False, None)`` when another instance already owns it.
    """
    api = _get_win32()
    if api is None:
        return (True, None)

    handle = api.kernel32.CreateMutexW(None, False, name)
    err = ctypes.get_last_error()

    if not handle:
        if err in (ERROR_ALREADY_EXISTS, ERROR_ACCESS_DENIED):
            return (False, None)
        logger.warning("CreateMutexW failed for %r with Win32 error %d", name, err)
        return (False, None)

    if err == ERROR_ALREADY_EXISTS:
        api.kernel32.CloseHandle(handle)
        return (False, None)

    return (True, handle)


def release_single_instance_mutex(handle: Any) -> None:
    """Close a previously acquired Win32 mutex handle cleanly."""
    if handle is None or os.name != "nt":
        return
    api = _get_win32()
    if api is None:
        return
    try:
        api.kernel32.CloseHandle(handle)
    except Exception as exc:
        logger.debug("Failed to close mutex handle cleanly: %s", exc)


def terminate_pid_gracefully(pid: int, timeout: float = 2.5) -> bool:
    """Terminate an external process by PID and wait up to ``timeout`` seconds."""
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return False
    if pid == os.getpid():
        return False

    terminate_sent = False
    try:
        proc = psutil.Process(pid)
        proc.terminate()
        terminate_sent = True
        proc.wait(timeout=max(0.0, float(timeout)))
        return True
    except psutil.NoSuchProcess:
        return terminate_sent
    except (psutil.AccessDenied, psutil.TimeoutExpired, ValueError, OSError) as exc:
        logger.debug("Graceful termination of PID %d did not complete: %s", pid, exc)
        return False


# --------------------------------------------------------------------------------------
# 2. Windows Task Scheduler Autostart (schtasks)
# --------------------------------------------------------------------------------------


def _decode_process_output(raw: bytes) -> str:
    if not raw:
        return ""
    for encoding in ("utf-8", "cp866", "cp1251", "mbcs"):
        try:
            return raw.decode(encoding).strip()
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace").strip()


def _resolve_under(base: Path, target: str | Path) -> Path:
    candidate = Path(target).expanduser()
    if candidate.is_absolute():
        return candidate.resolve()
    return (base / candidate).resolve()


def _quote_win_path(value: str | Path) -> str:
    text = str(value)
    quoted = subprocess.list2cmdline([text])
    if quoted.startswith('"') and quoted.endswith('"'):
        return quoted
    trailing_bs = len(text) - len(text.rstrip("\\"))
    escaped = text.replace('"', '\\"') + ("\\" * trailing_bs)
    return f'"{escaped}"'


def _run_schtasks(args: list[str]) -> tuple[int, str, str]:
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    proc = subprocess.run(
        ["schtasks", *args],
        capture_output=True,
        timeout=15,
        creationflags=creationflags,
        check=False,
    )
    return (
        proc.returncode,
        _decode_process_output(proc.stdout),
        _decode_process_output(proc.stderr),
    )


def _to_compact_win_path(path: Path) -> str:
    resolved = path.resolve()
    raw = str(resolved)
    if os.name == "nt" and resolved.exists():
        try:
            get_short = ctypes.windll.kernel32.GetShortPathNameW  # type: ignore[attr-defined]
            buf = ctypes.create_unicode_buffer(32768)
            n = get_short(raw, buf, len(buf))
            if n and buf.value and len(buf.value) < len(raw):
                return buf.value
        except Exception:  # noqa: BLE001
            pass
    return raw


def build_autostart_command(
    working_dir: str | Path,
    db_path: str | Path = "netdoctor.db",
    configs_dir: str | Path = "configs",
    lists_dir: str | Path = "lists",
    logs_dir: str | Path = "logs",
    bin_dir: str | Path = "bin",
    *,
    auto_start_protection: bool = True,
) -> str:
    """Build a safely quoted Task Scheduler command line launching the minimized GUI (kept <= 261 chars for schtasks /TR)."""
    base_dir = Path(working_dir).expanduser().resolve()
    exe_path = Path(sys.executable)
    pythonw = exe_path.with_name("pythonw.exe")
    python_bin = _to_compact_win_path(pythonw if pythonw.is_file() else exe_path)

    resolved_db = _resolve_under(base_dir, db_path)
    resolved_configs = _resolve_under(base_dir, configs_dir)
    resolved_lists = _resolve_under(base_dir, lists_dir)
    resolved_logs = _resolve_under(base_dir, logs_dir)
    resolved_bin = _resolve_under(base_dir, bin_dir)

    def _build_parts(use_short: bool, omit_defaults: bool) -> list[str]:
        fmt = _to_compact_win_path if use_short else str
        p: list[str] = [
            _quote_win_path(python_bin if use_short else str(pythonw if pythonw.is_file() else exe_path)),
            "-m",
            "netdoctor.cli",
            "gui",
            "--minimized",
        ]
        if auto_start_protection:
            p.append("--auto-start")
        p.extend(["--db", _quote_win_path(fmt(resolved_db))])
        for flag, val, def_name in (
            ("--configs-dir", resolved_configs, "configs"),
            ("--lists-dir", resolved_lists, "lists"),
            ("--logs-dir", resolved_logs, "logs"),
            ("--bin-dir", resolved_bin, "bin"),
        ):
            if omit_defaults and val == (base_dir / def_name).resolve() and resolved_db.parent == base_dir:
                continue
            p.extend([flag, _quote_win_path(fmt(val))])
        return p

    cmd = " ".join(_build_parts(use_short=False, omit_defaults=False))
    if len(cmd) <= 260:
        return cmd
    cmd_short = " ".join(_build_parts(use_short=True, omit_defaults=False))
    if len(cmd_short) <= 260:
        return cmd_short
    return " ".join(_build_parts(use_short=True, omit_defaults=True))


def get_autostart_status(task_name: str = DEFAULT_AUTOSTART_TASK_NAME) -> dict[str, Any]:
    """Query Windows Task Scheduler for the autostart task without raising."""
    if os.name != "nt":
        return {
            "enabled": False,
            "task_name": task_name,
            "detail": "Task Scheduler autostart is only supported on Windows.",
        }

    try:
        rc, out, err = _run_schtasks(["/Query", "/TN", task_name, "/FO", "LIST"])
        if rc == 0:
            return {
                "enabled": True,
                "task_name": task_name,
                "detail": out or "Scheduled task is registered.",
            }
        return {
            "enabled": False,
            "task_name": task_name,
            "detail": err or out or f"schtasks exited with code {rc}.",
        }
    except Exception as exc:
        return {
            "enabled": False,
            "task_name": task_name,
            "detail": str(exc),
        }


def set_autostart_enabled(
    enabled: bool,
    working_dir: str | Path | None = None,
    task_name: str = DEFAULT_AUTOSTART_TASK_NAME,
    **path_kwargs: Any,
) -> dict[str, Any]:
    """Create or delete the Windows Task Scheduler logon autostart entry."""
    if os.name != "nt":
        return {
            "ok": False,
            "enabled": False,
            "task_name": task_name,
            "error": "Task Scheduler autostart is only supported on Windows.",
        }

    if enabled:
        base_dir = Path(working_dir) if working_dir is not None else Path.cwd()
        try:
            cmd = build_autostart_command(base_dir, **path_kwargs)
        except Exception as exc:
            return {
                "ok": False,
                "enabled": get_autostart_status(task_name)["enabled"],
                "task_name": task_name,
                "error": str(exc),
            }

        for run_level in ("HIGHEST", "LIMITED"):
            try:
                rc, out, err = _run_schtasks(
                    [
                        "/Create",
                        "/F",
                        "/TN",
                        task_name,
                        "/SC",
                        "ONLOGON",
                        "/RL",
                        run_level,
                        "/TR",
                        cmd,
                    ]
                )
            except Exception as exc:
                return {
                    "ok": False,
                    "enabled": get_autostart_status(task_name)["enabled"],
                    "task_name": task_name,
                    "error": str(exc),
                }

            if rc == 0:
                return {
                    "ok": True,
                    "enabled": True,
                    "auto_start_protection": bool(path_kwargs.get("auto_start_protection", True)),
                    "task_name": task_name,
                    "run_level": run_level,
                    "command": cmd,
                    "detail": out or f"Scheduled task created ({run_level}).",
                }
            last_error = err or out or f"schtasks exited with code {rc}."

        return {
            "ok": False,
            "enabled": get_autostart_status(task_name)["enabled"],
            "task_name": task_name,
            "error": last_error,
        }

    # Disable autostart
    try:
        rc, out, err = _run_schtasks(["/Delete", "/F", "/TN", task_name])
    except Exception as exc:
        return {
            "ok": False,
            "enabled": get_autostart_status(task_name)["enabled"],
            "task_name": task_name,
            "error": str(exc),
        }

    if rc == 0:
        return {
            "ok": True,
            "enabled": False,
            "task_name": task_name,
            "detail": out or "Scheduled task deleted.",
        }

    current = get_autostart_status(task_name)
    if not current["enabled"]:
        return {
            "ok": True,
            "enabled": False,
            "task_name": task_name,
            "detail": "Scheduled task was not registered.",
        }

    return {
        "ok": False,
        "enabled": True,
        "task_name": task_name,
        "error": err or out or f"schtasks exited with code {rc}.",
    }


# --------------------------------------------------------------------------------------
# 3. Native Win32 System Tray Icon
# --------------------------------------------------------------------------------------


def _make_int_resource(res_id: int) -> wintypes.LPCWSTR:
    return ctypes.cast(ctypes.c_void_p(res_id), wintypes.LPCWSTR)


def _create_badge_hicon(
    api: _Win32Api,
    rgb: tuple[int, int, int] = (63, 185, 80),
) -> tuple[int, bool]:
    """Draw a 16x16 anti-aliased BGRA badge HICON in memory, falling back to IDI_APPLICATION."""
    size = 16
    r_col, g_col, b_col = rgb
    pixels = bytearray(size * size * 4)

    cx = (size - 1) / 2.0
    cy = (size - 1) / 2.0
    outer_r = 7.0
    inner_r = 5.0

    for y in range(size):
        for x in range(size):
            dx = x - cx
            dy = y - cy
            dist = (dx * dx + dy * dy) ** 0.5
            idx = (y * size + x) * 4

            if dist > outer_r + 0.6:
                continue

            # Anti-aliased outer alpha edge
            alpha = 1.0 if dist <= outer_r - 0.5 else max(0.0, (outer_r + 0.6 - dist) / 1.1)
            if dist <= inner_r:
                # Subtle bright core highlight
                pr, pg, pb = r_col, g_col, b_col
            else:
                # Crisp dark slate border ring
                pr, pg, pb = 22, 27, 34

            a_byte = int(max(0, min(255, round(alpha * 255))))
            pixels[idx] = pb
            pixels[idx + 1] = pg
            pixels[idx + 2] = pr
            pixels[idx + 3] = a_byte

    bmi = BITMAPINFOHEADER(
        biSize=ctypes.sizeof(BITMAPINFOHEADER),
        biWidth=size,
        biHeight=-size,
        biPlanes=1,
        biBitCount=32,
        biCompression=BI_RGB,
        biSizeImage=len(pixels),
    )

    bits_ptr = ctypes.c_void_p()
    hdc = api.user32.GetDC(None)
    hbm_color = None
    hbm_mask = None
    try:
        hbm_color = api.gdi32.CreateDIBSection(
            hdc,
            ctypes.byref(bmi),
            DIB_RGB_COLORS,
            ctypes.byref(bits_ptr),
            None,
            0,
        )
        if hbm_color and bits_ptr.value:
            ctypes.memmove(bits_ptr.value, bytes(pixels), len(pixels))
            hbm_mask = api.gdi32.CreateBitmap(size, size, 1, 1, None)
            if hbm_mask:
                info = ICONINFO(
                    fIcon=True,
                    xHotspot=0,
                    yHotspot=0,
                    hbmMask=hbm_mask,
                    hbmColor=hbm_color,
                )
                hicon = api.user32.CreateIconIndirect(ctypes.byref(info))
                if hicon:
                    return (hicon, True)
    except Exception as exc:
        logger.debug("In-memory tray HICON creation failed, using IDI_APPLICATION: %s", exc)
    finally:
        if hdc:
            api.user32.ReleaseDC(None, hdc)
        if hbm_color:
            api.gdi32.DeleteObject(hbm_color)
        if hbm_mask:
            api.gdi32.DeleteObject(hbm_mask)

    fallback = api.user32.LoadIconW(None, _make_int_resource(IDI_APPLICATION))
    return (fallback or 0, False)


class NetdoctorTrayIcon:
    """Native Win32 system tray icon running its own message pump on a daemon thread."""

    def __init__(
        self,
        callbacks: Mapping[str, Callable[[], Any] | None] | None = None,
        *,
        on_show: Callable[[], Any] | None = None,
        on_toggle_protection: Callable[[], Any] | None = None,
        on_rotate_vpn: Callable[[], Any] | None = None,
        on_flush_dns: Callable[[], Any] | None = None,
        on_exit: Callable[[], Any] | None = None,
        tooltip: str = DEFAULT_TRAY_TOOLTIP,
    ) -> None:
        cb_map = dict(callbacks) if callbacks is not None else {}
        self.on_show = on_show if on_show is not None else cb_map.get("on_show") or cb_map.get("show")
        self.on_toggle_protection = (
            on_toggle_protection
            if on_toggle_protection is not None
            else cb_map.get("on_toggle_protection") or cb_map.get("toggle_protection")
        )
        self.on_rotate_vpn = (
            on_rotate_vpn
            if on_rotate_vpn is not None
            else cb_map.get("on_rotate_vpn") or cb_map.get("rotate_vpn")
        )
        self.on_flush_dns = (
            on_flush_dns
            if on_flush_dns is not None
            else cb_map.get("on_flush_dns") or cb_map.get("flush_dns")
        )
        self.on_exit = on_exit if on_exit is not None else cb_map.get("on_exit") or cb_map.get("exit")

        self._tooltip = tooltip or DEFAULT_TRAY_TOOLTIP
        self._icon_color: tuple[int, int, int] = ICON_STATE_COLORS["green"]

        self._lock = threading.RLock()
        self._ready_event = threading.Event()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

        self._hwnd: int = 0
        self._hmenu: int = 0
        self._hicon: int = 0
        self._owns_icon: bool = False
        self._hinstance: int = 0
        self._class_name: str = ""
        self._taskbar_created_msg: int = 0
        self._icon_added: bool = False
        self._delete_pending: bool = False
        self._wndproc_ref: WNDPROC | None = None

    @property
    def tooltip(self) -> str:
        """Return the current tray tooltip text."""
        with self._lock:
            return self._tooltip

    @property
    def is_running(self) -> bool:
        """Return True while the tray message-loop thread is active."""
        with self._lock:
            return self._thread is not None and self._thread.is_alive()

    def _build_nid(self, hwnd: int, flags: int = 0) -> NOTIFYICONDATAW:
        nid = NOTIFYICONDATAW()
        nid.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
        nid.hWnd = hwnd
        nid.uID = 1
        nid.uFlags = flags
        nid.uCallbackMessage = WM_TRAYICON
        nid.hIcon = self._hicon
        nid.szTip = self._tooltip[:127]
        return nid

    def _invoke_callback(self, cb: Callable[[], Any] | None, label: str) -> None:
        if cb is None:
            return
        try:
            cb()
        except Exception:
            logger.exception("Unhandled error in tray callback %r", label)

    def _dispatch_command(self, cmd_id: int) -> None:
        handlers: dict[int, tuple[str, Callable[[], Any] | None]] = {
            MENU_ID_SHOW: ("on_show", self.on_show),
            MENU_ID_TOGGLE_PROTECTION: ("on_toggle_protection", self.on_toggle_protection),
            MENU_ID_ROTATE_VPN: ("on_rotate_vpn", self.on_rotate_vpn),
            MENU_ID_FLUSH_DNS: ("on_flush_dns", self.on_flush_dns),
            MENU_ID_EXIT: ("on_exit", self.on_exit),
        }
        entry = handlers.get(cmd_id)
        if entry is not None:
            label, cb = entry
            self._invoke_callback(cb, label)

    def _show_context_menu(self, api: _Win32Api, hwnd: int) -> None:
        if not self._hmenu:
            return
        pt = wintypes.POINT()
        if not api.user32.GetCursorPos(ctypes.byref(pt)):
            return
        api.user32.SetForegroundWindow(hwnd)
        cmd = int(
            api.user32.TrackPopupMenu(
                self._hmenu,
                TPM_RIGHTALIGN | TPM_BOTTOMALIGN | TPM_RETURNCMD | TPM_NONOTIFY,
                pt.x,
                pt.y,
                0,
                hwnd,
                None,
            )
        )
        api.user32.PostMessageW(hwnd, WM_NULL, 0, 0)
        if cmd:
            self._dispatch_command(cmd)

    def _create_menu(self, api: _Win32Api) -> int:
        hmenu = api.user32.CreatePopupMenu()
        if not hmenu:
            return 0
        api.user32.AppendMenuW(hmenu, MF_STRING, MENU_ID_SHOW, "Открыть окно netdoctor")
        api.user32.AppendMenuW(
            hmenu,
            MF_STRING,
            MENU_ID_TOGGLE_PROTECTION,
            "🚀 Включить / ⏹ Остановить защиту",
        )
        api.user32.AppendMenuW(hmenu, MF_STRING, MENU_ID_ROTATE_VPN, "🔄 Переключить VPN-узел")
        api.user32.AppendMenuW(hmenu, MF_STRING, MENU_ID_FLUSH_DNS, "🧹 Сбросить DNS-кэш")
        api.user32.AppendMenuW(hmenu, MF_SEPARATOR, 0, None)
        api.user32.AppendMenuW(
            hmenu,
            MF_STRING,
            MENU_ID_EXIT,
            "❌ Полный выход (остановить службы)",
        )
        api.user32.SetMenuDefaultItem(hmenu, 0, True)
        return hmenu

    def _add_tray_icon(self, api: _Win32Api, hwnd: int) -> bool:
        nid = self._build_nid(hwnd, flags=NIF_MESSAGE | NIF_ICON | NIF_TIP)
        ok = bool(api.shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(nid)))
        with self._lock:
            self._icon_added = ok
            self._delete_pending = True
        return ok

    def _delete_tray_icon(self, api: _Win32Api, hwnd: int) -> None:
        if not hwnd:
            return
        with self._lock:
            if not self._delete_pending:
                return
            self._delete_pending = False
            self._icon_added = False
        nid = self._build_nid(hwnd, flags=0)
        api.shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(nid))

    def _wnd_proc(self, hwnd: int, msg: int, wparam: int, lparam: int) -> int:
        api = _get_win32()
        if api is None:
            return 0

        if msg == WM_TRAYICON:
            event = int(lparam) & 0xFFFF
            if event in (WM_LBUTTONUP, WM_LBUTTONDBLCLK):
                self._invoke_callback(self.on_show, "on_show")
                return 0
            if event in (WM_RBUTTONUP, WM_CONTEXTMENU):
                self._show_context_menu(api, hwnd)
                return 0
            return 0

        if msg == WM_COMMAND:
            cmd_id = int(wparam) & 0xFFFF
            self._dispatch_command(cmd_id)
            return 0

        if self._taskbar_created_msg and msg == self._taskbar_created_msg:
            self._add_tray_icon(api, hwnd)
            return 0

        if msg == WM_CLOSE:
            api.user32.DestroyWindow(hwnd)
            return 0

        if msg == WM_DESTROY:
            api.user32.PostQuitMessage(0)
            return 0

        return api.user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    def _run_loop(self) -> None:
        api = _get_win32()
        if api is None:
            self._ready_event.set()
            return

        hwnd = 0
        class_registered = False
        try:
            hinstance = int(api.kernel32.GetModuleHandleW(None) or 0)
            class_name = f"NetdoctorTrayWindow_{id(self)}_{threading.get_ident()}"
            wndproc = WNDPROC(self._wnd_proc)
            hicon, owns_icon = _create_badge_hicon(api, self._icon_color)

            with self._lock:
                self._hinstance = hinstance
                self._class_name = class_name
                self._wndproc_ref = wndproc
                self._hicon = hicon
                self._owns_icon = owns_icon
                self._taskbar_created_msg = int(
                    api.user32.RegisterWindowMessageW("TaskbarCreated") or 0
                )

            wc = WNDCLASSW(
                style=0,
                lpfnWndProc=wndproc,
                cbClsExtra=0,
                cbWndExtra=0,
                hInstance=hinstance,
                hIcon=hicon,
                hCursor=0,
                hbrBackground=0,
                lpszMenuName=None,
                lpszClassName=class_name,
            )
            atom = api.user32.RegisterClassW(ctypes.byref(wc))
            if not atom and ctypes.get_last_error() != ERROR_CLASS_ALREADY_EXISTS:
                logger.warning("RegisterClassW failed with Win32 error %d", ctypes.get_last_error())
                return
            class_registered = True

            hwnd = int(
                api.user32.CreateWindowExW(
                    0,
                    class_name,
                    "netdoctor-tray",
                    0,
                    0,
                    0,
                    0,
                    0,
                    None,
                    None,
                    hinstance,
                    None,
                )
                or 0
            )
            if not hwnd:
                logger.warning("CreateWindowExW failed with Win32 error %d", ctypes.get_last_error())
                return

            hmenu = self._create_menu(api)
            with self._lock:
                self._hwnd = hwnd
                self._hmenu = hmenu

            self._add_tray_icon(api, hwnd)
        finally:
            self._ready_event.set()

        if not hwnd:
            self._cleanup_resources(api, hwnd=0, class_registered=class_registered)
            return

        try:
            msg = wintypes.MSG()
            while not self._stop_event.is_set():
                ret = int(api.user32.GetMessageW(ctypes.byref(msg), None, 0, 0))
                if ret <= 0:
                    break
                api.user32.TranslateMessage(ctypes.byref(msg))
                api.user32.DispatchMessageW(ctypes.byref(msg))
        finally:
            self._cleanup_resources(api, hwnd=hwnd, class_registered=class_registered)

    def _cleanup_resources(self, api: _Win32Api, hwnd: int, class_registered: bool) -> None:
        if hwnd:
            self._delete_tray_icon(api, hwnd)
            api.user32.DestroyWindow(hwnd)

        with self._lock:
            hmenu = self._hmenu
            hicon = self._hicon
            owns_icon = self._owns_icon
            class_name = self._class_name
            hinstance = self._hinstance

            self._hwnd = 0
            self._hmenu = 0
            self._hicon = 0
            self._owns_icon = False
            self._wndproc_ref = None

        if hmenu:
            api.user32.DestroyMenu(hmenu)
        if hicon and owns_icon:
            api.user32.DestroyIcon(hicon)
        if class_registered and class_name:
            api.user32.UnregisterClassW(class_name, hinstance)

    def start(self) -> None:
        """Start the Win32 system tray icon message loop on a background daemon thread."""
        if os.name != "nt":
            logger.debug("System tray icon is only supported on Windows; start() is a no-op.")
            return

        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop_event.clear()
            self._ready_event.clear()
            thread = threading.Thread(
                target=self._run_loop,
                name="netdoctor-tray",
                daemon=True,
            )
            self._thread = thread

        thread.start()
        self._ready_event.wait(timeout=5.0)

    def update_tooltip(self, text: str) -> None:
        """Update the tray icon hover tooltip text."""
        with self._lock:
            self._tooltip = text or DEFAULT_TRAY_TOOLTIP
            hwnd = self._hwnd
            if not hwnd or os.name != "nt":
                return
            api = _get_win32()
            if api is None:
                return
            nid = self._build_nid(hwnd, flags=NIF_TIP)
            api.shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(nid))

    def set_icon_state(self, state: str) -> None:
        """Update the tray badge icon color ('green'/'active', 'blue'/'idle', 'amber'/'warning')."""
        rgb = ICON_STATE_COLORS.get(state.lower().strip(), ICON_STATE_COLORS["blue"])
        with self._lock:
            self._icon_color = rgb
            hwnd = self._hwnd
            if not hwnd or os.name != "nt":
                return
            api = _get_win32()
            if api is None:
                return
            new_hicon, new_owns = _create_badge_hicon(api, rgb)
            if not new_hicon:
                return
            old_hicon = self._hicon
            old_owns = self._owns_icon
            self._hicon = new_hicon
            self._owns_icon = new_owns
            nid = self._build_nid(hwnd, flags=NIF_ICON)
            api.shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(nid))
            if old_hicon and old_owns:
                api.user32.DestroyIcon(old_hicon)

    def show_balloon(
        self,
        title: str,
        msg: str,
        timeout_ms: int = 4000,
        info_flags: int = NIIF_INFO,
    ) -> None:
        """Display a Windows tray balloon/toast notification."""
        if os.name != "nt":
            return
        with self._lock:
            hwnd = self._hwnd
            if not hwnd:
                return
            api = _get_win32()
            if api is None:
                return
            nid = self._build_nid(hwnd, flags=NIF_INFO)
            nid.szInfoTitle = (title or "")[:63]
            nid.szInfo = (msg or "")[:255]
            nid.uTimeout = max(1000, int(timeout_ms))
            nid.dwInfoFlags = int(info_flags)
            api.shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(nid))

    def stop(self) -> None:
        """Remove the tray icon, post WM_QUIT, and join the background daemon thread cleanly."""
        with self._lock:
            self._stop_event.set()
            hwnd = self._hwnd
            thread = self._thread

        api = _get_win32()
        if api is not None and hwnd:
            self._delete_tray_icon(api, hwnd)
            api.user32.PostMessageW(hwnd, WM_CANCELMODE, 0, 0)
            api.user32.PostMessageW(hwnd, WM_QUIT, 0, 0)

        if thread is not None and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=3.0)

        with self._lock:
            if self._thread is thread and (thread is None or not thread.is_alive()):
                self._thread = None


# --------------------------------------------------------------------------------------
# 4. Application .ico & Elevated Windows Shortcut (.lnk) Helpers
# --------------------------------------------------------------------------------------

_SHLLINK_HEADER_SIZE = 0x4C
_SLDF_RUNAS_USER = 0x00002000


def _inside_rounded_square(x: int, y: int, size: int = 32, margin: int = 1, radius: float = 6.0) -> bool:
    """Return True when pixel (x, y) falls inside the rounded-square badge silhouette."""
    low = margin
    high = size - 1 - margin
    if x < low or x > high or y < low or y > high:
        return False
    inner_low = low + radius
    inner_high = high - radius
    dx = 0.0
    dy = 0.0
    if x < inner_low:
        dx = inner_low - x
    elif x > inner_high:
        dx = x - inner_high
    if y < inner_low:
        dy = inner_low - y
    elif y > inner_high:
        dy = y - inner_high
    return (dx * dx + dy * dy) <= (radius * radius)


def _shield_pixel_rgba(x: int, y: int) -> tuple[int, int, int, int]:
    """Render one 32x32 Midnight Slate shield-badge RGBA pixel."""
    if not _inside_rounded_square(x, y):
        return (0, 0, 0, 0)

    # Subtle 1px slate border around the rounded badge
    is_border = not _inside_rounded_square(x, y, margin=2, radius=5.0)
    r, g, b = (36, 49, 74) if is_border else (11, 15, 23)

    cx = 15.5
    if 5 <= y <= 26:
        half = 9.0 if y <= 15 else max(0.0, 9.0 * (26.5 - y) / 11.5)
        if abs(x - cx) <= half:
            r, g, b = (2, 132, 199)  # PRIMARY_BG (#0284C7)

    if 8 <= y <= 23:
        inner_half = 5.5 if y <= 15 else max(0.0, 5.5 * (23.5 - y) / 8.5)
        if abs(x - cx) <= inner_half:
            r, g, b = (56, 189, 248)  # ACCENT (#38BDF8)

    dx = x - cx
    dy = y - 14.5
    if (dx * dx + dy * dy) <= (2.6 * 2.6):
        r, g, b = (34, 197, 94)  # OK (#22C55E)

    return (r, g, b, 255)


def write_app_icon(path: str | Path) -> Path:
    """Write a 32x32 32-bit BGRA Windows .ico file using pure stdlib struct."""
    size = 32
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    xor_bytes = bytearray()
    and_bytes = bytearray()
    for y in range(size - 1, -1, -1):
        row_mask = 0
        for x in range(size):
            r, g, b, a = _shield_pixel_rgba(x, y)
            xor_bytes.extend((b, g, r, a))
            if a == 0:
                row_mask |= 1 << (31 - x)
        and_bytes.extend(struct.pack(">I", row_mask))

    dib_header = struct.pack(
        "<IIIHHIIIIII",
        40,
        size,
        size * 2,
        1,
        32,
        BI_RGB,
        len(xor_bytes),
        0,
        0,
        0,
        0,
    )
    image_data = dib_header + bytes(xor_bytes) + bytes(and_bytes)
    icondir = struct.pack("<HHH", 0, 1, 1)
    icondir_entry = struct.pack("<BBBBHHII", size, size, 0, 0, 1, 32, len(image_data), 22)
    out_path.write_bytes(icondir + icondir_entry + image_data)
    return out_path


def _ps_single_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def create_gui_shortcut(
    shortcut_path: str | Path,
    target_path: str | Path,
    *,
    working_dir: str | Path,
    icon_path: str | Path | None = None,
    arguments: str = "",
    description: str = "netdoctor — Панель управления (Admin)",
    run_as_admin: bool = True,
) -> dict[str, Any]:
    """Create a Windows .lnk shortcut with full Unicode path support and optional UAC RunAs flag."""
    if os.name != "nt":
        return {
            "ok": False,
            "path": str(shortcut_path),
            "target": str(target_path),
            "error": "Windows shortcuts are only supported on Windows.",
        }

    lnk = Path(shortcut_path).expanduser().resolve()
    target = Path(target_path).expanduser().resolve()
    workdir = Path(working_dir).expanduser().resolve()
    icon_res = Path(icon_path).expanduser().resolve() if icon_path is not None else None
    lnk.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        "$ErrorActionPreference = 'Stop'",
        "$ws = New-Object -ComObject WScript.Shell",
        f"$sc = $ws.CreateShortcut({_ps_single_quote(str(lnk))})",
        f"$sc.TargetPath = {_ps_single_quote(str(target))}",
        f"$sc.Arguments = {_ps_single_quote(arguments)}",
        f"$sc.WorkingDirectory = {_ps_single_quote(str(workdir))}",
        f"$sc.Description = {_ps_single_quote(description)}",
        "$sc.WindowStyle = 1",
    ]
    if icon_res is not None:
        lines.append(f"$sc.IconLocation = {_ps_single_quote(f'{icon_res},0')}")
    lines.append("$sc.Save()")

    script = "; ".join(lines)
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=15,
            creationflags=creationflags,
            check=False,
        )
    except Exception as exc:
        return {"ok": False, "path": str(lnk), "target": str(target), "error": str(exc)}

    if proc.returncode != 0 or not lnk.is_file():
        err = _decode_process_output(proc.stderr) or _decode_process_output(proc.stdout)
        return {
            "ok": False,
            "path": str(lnk),
            "target": str(target),
            "error": err or f"powershell exited with code {proc.returncode}",
        }

    if run_as_admin:
        data = bytearray(lnk.read_bytes())
        if len(data) < _SHLLINK_HEADER_SIZE or struct.unpack_from("<I", data, 0)[0] != _SHLLINK_HEADER_SIZE:
            return {
                "ok": False,
                "path": str(lnk),
                "target": str(target),
                "error": "Generated .lnk has an invalid ShellLink header.",
            }
        # Set SLDF_RUNAS_USER (0x00002000) in LinkFlags (offset 0x14, little-endian uint32)
        flags = struct.unpack_from("<I", data, 20)[0] | _SLDF_RUNAS_USER
        struct.pack_into("<I", data, 20, flags)
        lnk.write_bytes(bytes(data))

    return {
        "ok": True,
        "path": str(lnk),
        "target": str(target),
        "run_as_admin": bool(run_as_admin),
    }
