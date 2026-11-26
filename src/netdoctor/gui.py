"""Modern, user-friendly ZAPRET // NETDOCTOR desktop GUI built with clear visual hierarchy."""

from __future__ import annotations

import argparse
import ctypes
from datetime import datetime
import gc
import json
import math
import os
import queue
import sys
import threading
import tkinter as tk
import tkinter.font as tkfont
import traceback
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any, Callable

from netdoctor import __version__
from netdoctor.config_gen import parse_process_list
from netdoctor.core.engine import NetdoctorEngine, elevate_gui
from netdoctor.supervisor import _is_admin
from netdoctor.tray import (
    NetdoctorTrayIcon,
    acquire_single_instance_mutex,
    release_single_instance_mutex,
    terminate_pid_gracefully,
    write_app_icon,
)
from netdoctor.updater import find_missing_python_deps
from netdoctor.ui.tab_dns import build_dns_tab
from netdoctor.ui.tab_home import build_home_tab, dismiss_onboarding
from netdoctor.ui.tab_logs import build_logs_tab
from netdoctor.ui.tab_monitor import (
    build_conns_subview,
    build_inspector,
    build_monitor_tab,
    render_bundles_subview,
)
from netdoctor.ui.tab_presets import build_presets_tab
from netdoctor.ui.tab_settings import build_settings_tab
from netdoctor.ui.tab_vpn import build_vpn_tab, sync_telegram_mode_ui
from netdoctor.ui.theme import (
    ACCENT,
    BG,
    BORDER,
    BORDER_LIGHT,
    CARD,
    CARD_ACTIVE,
    CARD_ALT,
    CONN_COLUMNS,
    CYAN_BORDER,
    DARK_PALETTE,
    DIM,
    DOMAIN_COLUMNS,
    ERR,
    ERR_BG,
    ERR_BTN,
    ERR_BTN_HOVER,
    ERR_TEXT,
    FG,
    FG_SOFT,
    FONT_H2,
    FONT_HERO,
    FONT_MICRO,
    FONT_MONO,
    FONT_MONO_S,
    FONT_SMALL,
    FONT_SMALL_B,
    FONT_TITLE,
    FONT_UI,
    FONT_UI_B,
    HEADER_BG,
    INFO_BG,
    INPUT,
    INPUT_HOVER,
    LAVENDER,
    LAVENDER_DARK,
    LAVENDER_HOVER,
    LAYER_FILTER_LABELS,
    LAYER_FILTERS,
    LIGHT_PALETTE,
    LOG_FILES,
    MUTED,
    OK,
    OK_BG,
    OK_BTN,
    OK_BTN_HOVER,
    OK_TEXT,
    OVERRIDE_LAYER_HINTS,
    OVERRIDE_LAYERS,
    PILL_ACTIVE_BG,
    PILL_ACTIVE_BORDER,
    PRESET_COLUMNS,
    PRIMARY_BG,
    PRIMARY_HOVER,
    PROCESS_LEDS,
    PURPLE,
    PURPLE_BG,
    SELECT_BG,
    SERVICE_ACTIONS,
    SIDEBAR_BG,
    VERDICT_EXPLANATIONS,
    VPN_MODE_AUTO_LABEL,
    VPN_MODE_PRIORITY_LABEL,
    WARN,
    WARN_BG,
    WARN_BTN,
    WARN_BTN_HOVER,
    WARN_TEXT,
    _num,
    conn_iid,
    detect_log_alert,
    dumps_pretty,
    format_probe_lines,
    format_updated,
    lerp_hex,
    normalize_domain,
    row_iid,
    row_matches,
    row_tag,
    strip_ansi,
    verdict_human_label,
)
from netdoctor.ui.widgets import (
    ActivityBar,
    AnimatedToggle,
    HoverTooltip,
    LiveSparklineCanvas,
    RoundedButton,
    RoundedCard,
    draw_rounded_rect,
)
from netdoctor.vpn import is_auto_select_node, is_placeholder_node

GuiBackend = NetdoctorEngine


class NetdoctorController:
    """Controller bridging GUI actions and the underlying netdoctor storage/config/supervisor API."""

    def __init__(
        self,
        db_path: str | Path = "netdoctor.db",
        configs_dir: str | Path = "configs",
        lists_dir: str | Path = "lists",
        logs_dir: str | Path = "logs",
        bin_dir: str | Path = "bin",
    ) -> None:
        self.db_path = Path(db_path)
        self.configs_dir = Path(configs_dir)
        self.lists_dir = Path(lists_dir)
        self.logs_dir = Path(logs_dir)
        self.bin_dir = Path(bin_dir)
        self.backend = NetdoctorEngine(
            db_path=self.db_path,
            configs_dir=self.configs_dir,
            lists_dir=self.lists_dir,
            logs_dir=self.logs_dir,
            bin_dir=self.bin_dir,
        )

    def get_status_snapshot(self) -> dict[str, Any]:
        return self.backend.get_status_snapshot()

    def trigger_apply_configs(self) -> dict[str, Any]:
        return self.backend.trigger_apply_configs()

    def force_apply_pending_changes(self, iface: int | None = None) -> dict[str, Any]:
        return self.backend.force_apply_pending_changes(iface=iface)

    def trigger_stop(self) -> list[str]:
        return self.backend.stop_services()

    def trigger_revalidate(self) -> dict[str, Any]:
        return self.backend.trigger_revalidate()


def _ensure_windows_tcl_env() -> None:
    """Resolve non-ASCII Windows TCL_LIBRARY / TK_LIBRARY paths to 8.3 short paths.

    Prevents intermittent ``tk.TclError: couldn't read file ".../init.tcl"`` on
    repeated Tk root creations under Windows user profiles with non-ASCII chars.
    """
    gc.collect()
    if os.name != "nt":
        return
    tcl_root = Path(sys.base_prefix) / "tcl"
    if not tcl_root.is_dir():
        return
    try:
        get_short = ctypes.windll.kernel32.GetShortPathNameW
    except Exception:  # noqa: BLE001
        return

    def _to_short(p: Path) -> str:
        raw = str(p)
        buf = ctypes.create_unicode_buffer(32768)
        res = get_short(raw, buf, len(buf))
        return buf.value if res else raw

    for env_key, subdir in (("TCL_LIBRARY", "tcl8.6"), ("TK_LIBRARY", "tk8.6")):
        candidate = tcl_root / subdir
        if candidate.is_dir():
            os.environ[env_key] = _to_short(candidate)


class NetdoctorGuiApp(tk.Tk):
    """Modern, self-explanatory ZAPRET // NETDOCTOR desktop control panel.

    ``auto_start=False`` skips background refresh timers and initial snapshot loading
    (used in unit tests).
    """

    SNAPSHOT_INTERVAL_MS = 5000
    LOG_INTERVAL_MS = 2000
    REALTIME_INTERVAL_MS = 3000

    def __init__(
        self,
        backend: NetdoctorEngine | None = None,
        *,
        auto_start: bool = True,
        minimized: bool = False,
        auto_start_stack: bool = False,
        enable_tray: bool | None = None,
        db_path: str | Path = "netdoctor.db",
        configs_dir: str | Path = "configs",
        lists_dir: str | Path = "lists",
        logs_dir: str | Path = "logs",
        bin_dir: str | Path = "bin",
    ) -> None:
        _ensure_windows_tcl_env()
        super().__init__()
        self.backend = backend or NetdoctorEngine(
            db_path=db_path,
            configs_dir=configs_dir,
            lists_dir=lists_dir,
            logs_dir=logs_dir,
            bin_dir=bin_dir,
        )
        self.title(f"ZAPRET // NETDOCTOR v{__version__}")
        self.geometry("1280x840")
        self.minsize(1040, 700)
        self.configure(bg=BG)

        self.all_rows: list[dict[str, Any]] = []
        self.rows_by_iid: dict[str, dict[str, Any]] = {}
        self.selected_row: dict[str, Any] | None = None
        self._inspector_sig: tuple[Any, ...] | None = None
        self.live_connections: list[dict[str, Any]] = []
        self.conns_by_iid: dict[str, dict[str, Any]] = {}
        self.selected_conn: dict[str, Any] | None = None
        self._last_conn_events: list[dict[str, Any]] | None = None
        self.conn_health_filter: str = "ALL"
        self.catalog: list[dict[str, Any]] = []
        self.dns_catalog: list[dict[str, Any]] = []
        self.active_dns_id: str = "cloudflare"
        self.dns_category_filter: str = "ALL"
        self._dns_signature = ""
        self._dns_cat_buttons: dict[str, tk.Button] = {}
        self._domain_filter_buttons: dict[str, tk.Button] = {}
        self._conn_filter_buttons: dict[str, tk.Button] = {}
        self._preset_filter_buttons: dict[str, tk.Button] = {}
        self._nav_items: dict[str, tuple[tk.Frame, tk.Frame, tk.Label, tk.Label, tk.Label]] = {}
        self._expert_tabs: tuple[ttk.Frame, ...] = ()
        self._expert_mode: bool = False
        self._onboarding_dismissed: bool = False
        self._notified_bundle_alerts: set[str] = set()
        self.last_snapshot: dict[str, Any] = {}
        self.config_previews: dict[str, str] = {}
        self._vpn_signature = ""
        self._vpn_nodes_by_iid: dict[str, dict[str, Any]] = {}
        self._vpn_policy: dict[str, Any] = {"mode": "auto", "priority_node": "", "priorities": {}}
        self._vpn_mode_syncing: bool = False
        self._preset_cb_syncing: bool = False
        self._stack_mode_syncing: bool = False
        self.zapret_presets: list[dict[str, Any]] = []
        self.presets_by_iid: dict[str, dict[str, Any]] = {}
        self.selected_preset: dict[str, Any] | None = None
        self.active_preset_id: str = "auto"
        self.active_preset_name: str = "Авто-оркестратор (подбор по доменам)"
        self.base_preset_id: str = ""
        self.base_preset_name: str = ""
        self.preset_filter: str = "ALL"
        self._home_preset_label_to_id: dict[str, str] = {}
        self._home_preset_id_to_label: dict[str, str] = {}
        self._domains_subview_mode: str = "domains"
        self._vpn_processes: list[str] = []
        self._base_dns: dict[str, Any] | None = None
        self._busy = 0
        self._closed = False
        self._exiting = False
        self._unlocker_custom_synced = False
        self._refreshing = False
        self._log_refreshing = False
        self._rt_busy = False
        self.radar_enabled = True
        self._sort_state: tuple[str, bool] = ("domain", False)
        self._sock_counts: dict[str, int] = {}
        self._last_preset_err_shown: str = ""
        self._last_update_info: dict[str, Any] = {}
        self._post_queue: queue.Queue[tuple[Callable[..., Any], tuple[Any, ...]]] = queue.Queue()
        self._active_bg_labels: set[str] = set()
        self._tray: NetdoctorTrayIcon | None = None
        self._icon_image: tk.PhotoImage | None = None
        self._win32_hicons: list[int] = []
        self._guide_visible = True
        self._extra_visible = False
        self._tooltips: list[HoverTooltip] = []
        self._anim_jobs: dict[int, str] = {}
        self._pulse_job: str | None = None
        self._fade_job: str | None = None
        self._pulse_phase: float = 0.0
        self._initial_loaded: bool = False
        self._power_transition: str | None = None
        self._spinner_idx: int = 0

        self.minimize_to_tray_var = tk.BooleanVar(value=True)
        self.autostart_var = tk.BooleanVar(value=False)
        self.autostart_protection_var = tk.BooleanVar(value=False)
        self.byedpi_var = tk.BooleanVar(value=False)
        self.debug_log_var = tk.BooleanVar(value=False)
        self.dpi_only_var = tk.BooleanVar(value=False)
        self.game_filter_var = tk.BooleanVar(value=False)
        self.expert_mode_var = tk.BooleanVar(value=False)
        self.tun_stack_var = tk.StringVar(value="mixed")
        self._auto_start_stack = bool(auto_start_stack)
        self._minimized = bool(minimized)
        self._auto_start_enabled = bool(auto_start)

        if auto_start and not minimized:
            try:
                self.attributes("-alpha", 0.0)
            except tk.TclError:
                pass

        self._apply_window_chrome(enable_dark=auto_start and not minimized)
        self._build_style()
        self._build_statusbar()
        self._build_shell()
        self._progress_update()

        use_tray = enable_tray if enable_tray is not None else auto_start
        if use_tray:
            try:
                self._tray = NetdoctorTrayIcon(
                    on_show=lambda: self._post(self.show_from_tray),
                    on_toggle_protection=lambda: self._post(self.on_toggle_autopilot),
                    on_rotate_vpn=lambda: self._post(self.on_rotate_vpn_node),
                    on_flush_dns=lambda: self._post(self.on_flush_dns),
                    on_exit=lambda: self._post(self.on_exit_app),
                )
                self._tray.start()
            except Exception:  # noqa: BLE001
                self._tray = None

        self.protocol("WM_DELETE_WINDOW", self.on_window_delete)
        self.bind("<F5>", lambda _e: self.refresh_async())
        self.bind("<Control-f>", self._on_shortcut_search)
        self.bind("<Control-F>", self._on_shortcut_search)
        self.bind_all("<Control-KeyPress>", self._on_ctrl_keypress_non_ascii, add="+")
        if auto_start or use_tray:
            self.after(40, self._drain_post_queue)
        if auto_start:
            if minimized:
                self.withdraw()
            else:
                self._start_entrance_fade()
            self.refresh_async()
            self.load_catalog_async()
            self.load_zapret_presets_async()
            self.load_dns_catalog_async()
            self.refresh_previews_async()
            self.refresh_realtime_async()
            self._load_autostart_async()
            self._snapshot_job = self.after(self.SNAPSHOT_INTERVAL_MS, self._snapshot_tick)
            self._log_job = self.after(self.LOG_INTERVAL_MS, self._log_tick)
            self._realtime_job = self.after(self.REALTIME_INTERVAL_MS, self._realtime_tick)
            self._pulse_job = self.after(70, self._pulse_tick)
            self._ensure_deps_on_startup()
            self.after(2500, self._check_updates_on_startup)
            delay_ms = 1500 if (minimized and auto_start_stack) else 350
            self.after(delay_ms, self._maybe_auto_start_protection)

    # ---------------------------------------------------------------- window chrome & lifecycle

    def _apply_win32_taskbar_icon(self, ico_path: Path | None = None) -> bool:
        """Apply multi-size .ico via Win32 WM_SETICON so Windows taskbar shows crisp icon instead of blank space."""
        if sys.platform != "win32":
            return False
        target_ico = ico_path or Path(__file__).with_name("netdoctor.ico")
        try:
            if not target_ico.is_file():
                write_app_icon(target_ico)
            self.update_idletasks()
            user32 = ctypes.windll.user32
            user32.GetParent.argtypes = [ctypes.c_void_p]
            user32.GetParent.restype = ctypes.c_void_p
            user32.LoadImageW.argtypes = [
                ctypes.c_void_p,
                ctypes.c_wchar_p,
                ctypes.c_uint,
                ctypes.c_int,
                ctypes.c_int,
                ctypes.c_uint,
            ]
            user32.LoadImageW.restype = ctypes.c_void_p
            user32.SendMessageW.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p]
            user32.SendMessageW.restype = ctypes.c_void_p
            user32.DestroyIcon.argtypes = [ctypes.c_void_p]

            tk_hwnd = self.winfo_id()
            top_hwnd = user32.GetParent(tk_hwnd) or tk_hwnd
            hwnds = list(dict.fromkeys(h for h in (top_hwnd, tk_hwnd) if h))
            h_small = user32.LoadImageW(None, str(target_ico.resolve()), 1, 16, 16, 0x0010)
            h_big = user32.LoadImageW(None, str(target_ico.resolve()), 1, 32, 32, 0x0010)
            new_icons = [h for h in (h_small, h_big) if h]
            if not new_icons or not hwnds:
                for h in new_icons:
                    user32.DestroyIcon(h)
                return False
            for hwnd in hwnds:
                if h_big:
                    user32.SendMessageW(hwnd, 0x0080, 1, h_big)
                if h_small:
                    user32.SendMessageW(hwnd, 0x0080, 0, h_small)
            old_icons = list(self._win32_hicons)
            self._win32_hicons = new_icons
            for old_h in old_icons:
                try:
                    user32.DestroyIcon(old_h)
                except Exception:  # noqa: BLE001
                    pass
            return True
        except Exception:  # noqa: BLE001
            return False

    def _apply_window_chrome(self, *, enable_dark: bool) -> None:
        ico_path = Path(__file__).with_name("netdoctor.ico")
        ico_loaded = False
        if sys.platform == "win32":
            if not ico_path.is_file():
                try:
                    write_app_icon(ico_path)
                except OSError:
                    pass
            if ico_path.is_file():
                try:
                    self.iconbitmap(str(ico_path))
                    self.iconbitmap(default=str(ico_path))
                    ico_loaded = self._apply_win32_taskbar_icon(ico_path)
                except tk.TclError:
                    ico_loaded = self._apply_win32_taskbar_icon(ico_path)

        # Fallback 16x16 shield-dot icon on non-Windows or when .ico cannot be loaded (never overwrite Win32 ICON_BIG)
        if not ico_loaded:
            try:
                img = tk.PhotoImage(width=16, height=16)
                img.put(BG, to=(0, 0, 16, 16))
                for y in range(2, 14):
                    half = 5 if y < 8 else max(1, 13 - y)
                    x0, x1 = 8 - half, 8 + half
                    img.put(PRIMARY_BG, to=(x0, y, x1, y + 1))
                img.put(ACCENT, to=(6, 5, 10, 9))
                img.put(OK, to=(7, 6, 9, 8))
                self._icon_image = img
                self.iconphoto(True, img)
            except tk.TclError:
                pass

        if enable_dark and sys.platform == "win32":
            try:
                self.update_idletasks()
                hwnd = ctypes.windll.user32.GetParent(self.winfo_id())
                if hwnd:
                    val = ctypes.c_int(1)
                    for attr in (20, 19):
                        ctypes.windll.dwmapi.DwmSetWindowAttribute(
                            hwnd, attr, ctypes.byref(val), ctypes.sizeof(val)
                        )
            except Exception:  # noqa: BLE001
                pass

    def _is_window_hidden(self) -> bool:
        try:
            return self.state() == "withdrawn"
        except tk.TclError:
            return False

    def show_from_tray(self) -> None:
        if self._closed:
            return
        try:
            self.deiconify()
            self._apply_win32_taskbar_icon()
            self.lift()
            self.focus_force()
        except tk.TclError:
            pass
        self.refresh_async()

    def on_window_delete(self) -> None:
        if self._tray is not None and self.minimize_to_tray_var.get():
            try:
                self.withdraw()
                self.set_status("netdoctor свёрнут в системный трей — защита продолжает работать", ACCENT)
            except tk.TclError:
                pass
            return
        self.on_exit_app()

    def on_exit_app(self) -> None:
        """Stop all supervised bypass services and exit completely (invoked from tray / Exit button)."""
        if self._exiting or self._closed:
            return
        self._exiting = True
        self._busy += 1
        try:
            self.set_status("Остановка служб и выход…", WARN_TEXT)
        except tk.TclError:
            pass

        def _stop_then_close() -> None:
            try:
                self.backend.stop_services()
            except Exception:  # noqa: BLE001
                pass
            self._post(self.on_close)

        threading.Thread(target=_stop_then_close, name="gui-exit", daemon=True).start()

    def _on_shortcut_search(self, _event: Any = None) -> str:
        try:
            self._select_tab(self.tab_domains)
            if hasattr(self, "search_entry"):
                self.search_entry.focus_set()
                self.search_entry.select_range(0, "end")
        except tk.TclError:
            pass
        return "break"

    @staticmethod
    def _is_widget_readonly_or_disabled(widget: Any) -> bool:
        if isinstance(widget, ttk.Widget):
            try:
                return bool(widget.instate(["disabled"]) or widget.instate(["readonly"]))
            except tk.TclError:
                return False
        try:
            return str(widget.cget("state")) in ("disabled", "readonly")
        except tk.TclError:
            return False

    def _on_ctrl_keypress_non_ascii(self, event: Any) -> str | None:
        """Handle standard Ctrl shortcuts (V/C/X/A/Z/Y/F) when a non-Latin layout (e.g. Russian) is active."""
        if self._closed:
            return None
        state = int(getattr(event, "state", 0) or 0)
        # Skip Alt/AltGr combos
        if state & 0x20000:
            return None
        keysym = str(getattr(event, "keysym", "") or "")
        # Let Tk's native ASCII bindings handle English/Latin layouts to avoid double-triggering
        if len(keysym) == 1 and keysym.isascii():
            return None

        kc = int(getattr(event, "keycode", 0) or 0)
        if kc == 70:  # Ctrl+F
            return self._on_shortcut_search(event)

        widget = getattr(event, "widget", None)
        if not isinstance(widget, (tk.Entry, ttk.Entry, ttk.Combobox, tk.Text)):
            return None

        ro = self._is_widget_readonly_or_disabled(widget)
        is_text = isinstance(widget, tk.Text)

        if kc == 86:  # Ctrl+V (Paste)
            if not ro:
                try:
                    clip = str(widget.clipboard_get() or "")
                except tk.TclError:
                    clip = ""
                if clip:
                    if is_text:
                        try:
                            widget.delete("sel.first", "sel.last")
                        except tk.TclError:
                            pass
                        widget.insert("insert", clip)
                        widget.see("insert")
                    else:
                        clean_clip = clip.replace("\r\n", " ").replace("\r", " ").replace("\n", " ")
                        try:
                            if widget.selection_present():
                                widget.delete("sel.first", "sel.last")
                        except tk.TclError:
                            pass
                        widget.insert("insert", clean_clip)
            return "break"

        if kc == 67:  # Ctrl+C (Copy — works on readonly/disabled widgets too)
            try:
                if is_text:
                    sel_text = widget.get("sel.first", "sel.last")
                elif widget.selection_present():
                    first = int(widget.index("sel.first"))
                    last = int(widget.index("sel.last"))
                    sel_text = str(widget.get())[first:last]
                else:
                    sel_text = ""
                if sel_text:
                    widget.clipboard_clear()
                    widget.clipboard_append(sel_text)
            except tk.TclError:
                pass
            return "break"

        if kc == 88:  # Ctrl+X (Cut)
            if not ro:
                try:
                    if is_text:
                        sel_text = widget.get("sel.first", "sel.last")
                        if sel_text:
                            widget.clipboard_clear()
                            widget.clipboard_append(sel_text)
                            widget.delete("sel.first", "sel.last")
                    elif widget.selection_present():
                        first = int(widget.index("sel.first"))
                        last = int(widget.index("sel.last"))
                        sel_text = str(widget.get())[first:last]
                        if sel_text:
                            widget.clipboard_clear()
                            widget.clipboard_append(sel_text)
                            widget.delete("sel.first", "sel.last")
                except tk.TclError:
                    pass
            return "break"

        if kc == 65:  # Ctrl+A (Select All)
            try:
                if is_text:
                    widget.tag_add("sel", "1.0", "end-1c")
                    widget.mark_set("insert", "end-1c")
                else:
                    widget.select_range(0, "end")
                    widget.icursor("end")
            except tk.TclError:
                pass
            return "break"

        if kc in (89, 90) and is_text:  # Ctrl+Z / Ctrl+Y / Ctrl+Shift+Z (Undo / Redo)
            if not ro:
                try:
                    if kc == 89 or (kc == 90 and bool(state & 0x1)):
                        widget.edit_redo()
                    else:
                        widget.edit_undo()
                except tk.TclError:
                    pass
            return "break"

        return None

    def _start_entrance_fade(self) -> None:
        if self._closed or self._exiting:
            return
        steps = 6

        def _step(idx: int) -> None:
            if self._closed:
                return
            try:
                alpha = min(1.0, idx / steps)
                self.attributes("-alpha", alpha)
                if idx < steps:
                    self._fade_job = self.after(28, lambda: _step(idx + 1))
                else:
                    self._fade_job = None
            except tk.TclError:
                self._fade_job = None

        self._fade_job = self.after(15, lambda: _step(1))

    def on_close(self) -> None:
        self._closed = True
        for attr in ("_fade_job", "_pulse_job", "_snapshot_job", "_log_job", "_realtime_job"):
            job = getattr(self, attr, None)
            if job is not None:
                try:
                    self.after_cancel(job)
                except tk.TclError:
                    pass
                setattr(self, attr, None)
        for job_id in list(self._anim_jobs.values()):
            try:
                self.after_cancel(job_id)
            except tk.TclError:
                pass
        self._anim_jobs.clear()
        for tip in list(self._tooltips):
            tip.hide()
        self._tooltips.clear()
        if HoverTooltip._pending is not None:
            HoverTooltip._pending._cancel_timers()
        if HoverTooltip._active is not None:
            HoverTooltip._active.hide()
        if self._tray is not None:
            try:
                self._tray.stop()
            except Exception:  # noqa: BLE001
                pass
            self._tray = None
        try:
            self.dns_canvas.unbind_all("<MouseWheel>")
            self.unbind_all("<Control-KeyPress>")
        except tk.TclError:
            pass
        self._icon_image = None
        if sys.platform == "win32" and getattr(self, "_win32_hicons", None):
            try:
                user32 = ctypes.windll.user32
                user32.DestroyIcon.argtypes = [ctypes.c_void_p]
                for hicon in self._win32_hicons:
                    user32.DestroyIcon(hicon)
            except Exception:  # noqa: BLE001
                pass
            self._win32_hicons = []
        try:
            self.destroy()
        except tk.TclError:
            pass
        gc.collect()

    def _drain_post_queue(self) -> None:
        if self._closed:
            return
        while True:
            try:
                fn, args = self._post_queue.get_nowait()
            except queue.Empty:
                break
            try:
                fn(*args)
            except Exception:  # noqa: BLE001
                pass
        if not self._closed:
            try:
                self.after(40, self._drain_post_queue)
            except tk.TclError:
                pass

    def _post(self, fn: Callable[..., Any], *args: Any) -> None:
        """Marshal a call onto the Tk main loop from any thread safely via queue."""
        if self._closed:
            return
        if threading.current_thread() is threading.main_thread():
            try:
                fn(*args)
            except tk.TclError:
                pass
            return
        self._post_queue.put((fn, args))

    def run_bg(
        self,
        label: str,
        work: Callable[[], Any],
        on_ok: Callable[[Any], None] | None = None,
        on_err: Callable[[Exception], None] | None = None,
    ) -> threading.Thread:
        """Run ``work`` in a daemon thread; deduplicate identical in-flight tasks."""
        if label in self._active_bg_labels:
            self.set_status(f"Уже выполняется: {label}…", WARN_TEXT)
            t = threading.Thread(target=lambda: None, daemon=True)
            t.start()
            return t

        self._active_bg_labels.add(label)
        self._busy += 1
        self.set_status(f"Выполняется: {label}…", ACCENT)
        self._progress_update()

        def runner() -> None:
            try:
                result = work()
            except Exception as exc:  # noqa: BLE001
                self._post(self._bg_failed, label, exc, on_err)
            else:
                self._post(self._bg_done, label, result, on_ok)

        thread = threading.Thread(target=runner, name=f"gui-{label[:20]}", daemon=True)
        thread.start()
        return thread

    def _bg_done(self, label: str, result: Any, on_ok: Callable[[Any], None] | None) -> None:
        self._active_bg_labels.discard(label)
        self._busy = max(0, self._busy - 1)
        self._progress_update()
        self.set_status(f"Готово: {label}", OK_TEXT)
        if on_ok is not None:
            try:
                on_ok(result)
            except Exception as exc:  # noqa: BLE001
                self.set_status(f"Ошибка обработки ({label}): {exc}", ERR_TEXT)

    def _bg_failed(self, label: str, exc: Exception, on_err: Callable[[Exception], None] | None) -> None:
        self._active_bg_labels.discard(label)
        self._busy = max(0, self._busy - 1)
        self._progress_update()
        self.set_status(f"Ошибка ({label}): {exc}", ERR_TEXT)
        self.log_console(f"[ERROR] {label}: {exc}")
        if on_err is not None:
            try:
                on_err(exc)
            except Exception:  # noqa: BLE001
                pass

    def _progress_update(self) -> None:
        is_busy = self._busy > 0 or not self._initial_loaded or self._power_transition is not None
        if hasattr(self, "activity_bar"):
            self.activity_bar.set_active(is_busy)
        if self._busy > 0:
            if not self.progress.winfo_manager():
                self.progress.pack(side="right", padx=12, pady=5)
            self.progress.start(12)
        else:
            self.progress.stop()
            self.progress.pack_forget()

    def set_status(self, text: str, color: str = FG_SOFT) -> None:
        self.status_var.set(text)
        self.status_label.configure(fg=color)

    def log_console(self, text: str) -> None:
        stamp = datetime.now().strftime("%H:%M:%S")
        self.console.configure(state="normal")
        self.console.insert("end", f"[{stamp}] ", "muted")
        tag = "bad" if "[ERROR]" in text or "ошибка" in text.lower() else ("ok" if "готово" in text.lower() else "")
        self.console.insert("end", f"{text}\n", tag)
        self.console.see("end")
        self.console.configure(state="disabled")

    # ---------------------------------------------------------------- style & reusable primitives

    def _build_style(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(".", background=BG, foreground=FG, fieldbackground=INPUT, bordercolor=BORDER, font=FONT_UI)
        style.configure("TFrame", background=BG)
        style.configure("TLabel", background=BG, foreground=FG)

        # Hidden-tab notebook so left sidebar drives navigation cleanly while preserving ttk.Notebook API
        style.layout("NavHidden.TNotebook", [("Notebook.client", {"sticky": "nswe"})])
        style.layout("NavHidden.TNotebook.Tab", [])
        style.configure(
            "NavHidden.TNotebook",
            background=BG,
            borderwidth=0,
            tabmargins=0,
            lightcolor=BG,
            darkcolor=BG,
            bordercolor=BG,
        )

        style.configure(
            "Treeview",
            background=CARD,
            fieldbackground=CARD,
            foreground=FG,
            rowheight=30,
            bordercolor=BORDER,
            borderwidth=0,
            lightcolor=CARD,
            darkcolor=CARD,
            font=FONT_UI,
        )
        style.configure(
            "Treeview.Heading",
            background=SIDEBAR_BG,
            foreground=FG_SOFT,
            relief="flat",
            font=FONT_SMALL_B,
            padding=(8, 7),
            bordercolor=BORDER,
            lightcolor=SIDEBAR_BG,
            darkcolor=SIDEBAR_BG,
        )
        style.map(
            "Treeview",
            background=[("selected", SELECT_BG)],
            foreground=[("selected", "#FFFFFF")],
        )
        style.map("Treeview.Heading", background=[("active", INPUT)])

        for orient in ("Vertical", "Horizontal"):
            style.configure(
                f"{orient}.TScrollbar",
                background=INPUT,
                troughcolor=BG,
                bordercolor=BG,
                arrowcolor=MUTED,
                lightcolor=INPUT,
                darkcolor=INPUT,
                gripcount=0,
            )
            style.map(f"{orient}.TScrollbar", background=[("active", BORDER_LIGHT)])

        style.configure(
            "TCombobox",
            fieldbackground=INPUT,
            background=INPUT,
            foreground=FG,
            arrowcolor=ACCENT,
            bordercolor=BORDER,
            lightcolor=INPUT,
            darkcolor=INPUT,
            selectbackground=INPUT,
            selectforeground=FG,
            padding=5,
        )
        style.map(
            "TCombobox",
            fieldbackground=[("readonly", INPUT)],
            foreground=[("readonly", FG)],
            selectbackground=[("readonly", INPUT)],
            selectforeground=[("readonly", FG)],
        )
        style.configure("TPanedwindow", background=BG)
        style.configure("Sash", sashthickness=6, background=BG, lightcolor=BORDER, darkcolor=BORDER)
        style.configure(
            "Horizontal.TProgressbar",
            background=ACCENT,
            troughcolor=INPUT,
            bordercolor=BG,
            lightcolor=ACCENT,
            darkcolor=ACCENT,
        )

        self.option_add("*TCombobox*Listbox.background", INPUT)
        self.option_add("*TCombobox*Listbox.foreground", FG)
        self.option_add("*TCombobox*Listbox.selectBackground", SELECT_BG)
        self.option_add("*TCombobox*Listbox.selectForeground", "#FFFFFF")
        self.option_add("*TCombobox*Listbox.font", FONT_UI)

    @staticmethod
    def _button_palette(kind: str) -> tuple[str, str, str, str, str]:
        palettes: dict[str, tuple[str, str, str, str, str]] = {
            "neutral": (INPUT, FG, INPUT_HOVER, BORDER, BORDER_LIGHT),
            "ghost": (CARD, FG_SOFT, CARD_ALT, BORDER, BORDER_LIGHT),
            "primary": (PILL_ACTIVE_BG, "#FFFFFF", PRIMARY_HOVER, PILL_ACTIVE_BORDER, LAVENDER),
            "pill_active": (PILL_ACTIVE_BG, "#FFFFFF", "#3F3475", PILL_ACTIVE_BORDER, LAVENDER),
            "hero": (LAVENDER, LAVENDER_DARK, LAVENDER_HOVER, "#9F82F6", "#DDD0FE"),
            "hero_active": ("#A78BFA", LAVENDER_DARK, "#C4B5FD", CYAN_BORDER, ACCENT),
            "cyan_ghost": ("#10192E", ACCENT, "#162440", "#1E425E", ACCENT),
            "success": (OK_BTN, "#FFFFFF", OK_BTN_HOVER, "#0E7490", ACCENT),
            "danger": (ERR_BTN, ERR_TEXT, ERR_BTN_HOVER, "#7F2642", ERR),
            "warn": (WARN_BTN, "#FFFFFF", WARN_BTN_HOVER, "#B45309", WARN_TEXT),
        }
        return palettes.get(kind, palettes["neutral"])

    def attach_tooltip(self, widget: tk.Misc, text: str, title: str | None = None) -> HoverTooltip:
        tip = HoverTooltip(widget, text, title=title)
        self._tooltips.append(tip)
        return tip

    def _pulse_tick(self) -> None:
        if self._closed or self._exiting:
            return
        self._pulse_phase = (self._pulse_phase + 0.16) % (2.0 * math.pi)
        self._spinner_idx = (self._spinner_idx + 1) % 8
        spin = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧")[self._spinner_idx]
        dots = "." * ((self._spinner_idx // 2) % 4)
        try:
            hidden = self._is_window_hidden()
            if not hidden:
                if hasattr(self, "activity_bar"):
                    self.activity_bar.set_active(
                        self._busy > 0 or self._refreshing or not self._initial_loaded or self._power_transition is not None
                    )
                    self.activity_bar.step()

                if not self._initial_loaded:
                    if hasattr(self, "hero_state_pill"):
                        self.hero_state_pill.configure(text=f"{spin} ЗАГРУЗКА{dots}", fg=ACCENT, bg=INFO_BG)
                    if hasattr(self, "network_label"):
                        self.network_label.configure(text=f"Сеть: определение{dots}")
                elif self._power_transition == "starting" and hasattr(self, "autopilot_btn"):
                    self.autopilot_btn.configure(text=f"{spin} ЗАПУСК ЗАЩИТЫ{dots}")
                elif self._power_transition == "stopping" and hasattr(self, "autopilot_btn"):
                    self.autopilot_btn.configure(text=f"{spin} ОСТАНОВКА{dots}")

                if self.last_snapshot.get("running"):
                    wave = 0.5 + 0.5 * math.sin(self._pulse_phase)
                    glow_col = lerp_hex("#1B8CA3", ACCENT, wave)
                    if glow_col != getattr(self, "_last_glow_col", None):
                        self._last_glow_col = glow_col
                        if hasattr(self, "hero_state_pill"):
                            self.hero_state_pill.configure(fg=glow_col)
                        if hasattr(self, "_home_zapret_card"):
                            self._home_zapret_card.configure(highlightbackground=lerp_hex("#1B5A70", CYAN_BORDER, wave))
                        for key, (canvas, oval, _lbl) in self.leds.items():
                            running = bool(((self.last_snapshot.get("processes") or {}).get(key) or {}).get("running"))
                            if running:
                                canvas.itemconfigure(oval, fill=glow_col)
                if self.radar_enabled and hasattr(self, "sparkline_canvas"):
                    try:
                        on_domains_tab = hasattr(self, "tab_domains") and self.notebook.select() == str(self.tab_domains)
                    except tk.TclError:
                        on_domains_tab = False
                    if on_domains_tab:
                        self.sparkline_canvas.set_pulse(self._pulse_phase)
        except tk.TclError:
            pass
        if self._auto_start_enabled:
            self._pulse_job = self.after(70, self._pulse_tick)

    def make_button(
        self,
        parent: tk.Misc,
        text: str,
        command: Callable[[], Any],
        kind: str = "neutral",
        width: int | None = None,
        font: tuple[Any, ...] = FONT_UI_B,
        padx: int = 12,
        pady: int = 6,
        radius: int | None = None,
        tooltip: str | None = None,
    ) -> RoundedButton:
        pal = self._button_palette(kind)
        if radius is None:
            radius = 12 if kind in ("hero", "hero_active") else (11 if kind in ("pill_active", "primary") else 9)
        btn = RoundedButton(
            parent,
            text=text,
            command=command,
            palette=pal,
            width=width,
            font=font,
            padx=padx,
            pady=pady,
            radius=radius,
        )
        if tooltip:
            self.attach_tooltip(btn, tooltip)
        return btn

    def make_toggle_row(
        self,
        parent: tk.Misc,
        text: str,
        variable: tk.BooleanVar,
        command: Callable[[], Any] | None = None,
        *,
        bg: str = CARD,
        font: tuple[Any, ...] = FONT_SMALL,
        fg: str = FG_SOFT,
        tooltip: str | None = None,
        slider_width: int = 38,
        slider_height: int = 18,
    ) -> tk.Frame:
        """Create a soft slider-switch row replacing legacy square checkboxes."""
        row = tk.Frame(parent, bg=bg, cursor="hand2")
        lbl = tk.Label(row, text=text, bg=bg, fg=fg, font=font, anchor="w", justify="left", cursor="hand2")
        lbl.pack(side="left", fill="x", expand=True, padx=(0, 8))
        tog = AnimatedToggle(row, variable=variable, command=command, bg=bg, width=slider_width, height=slider_height)
        tog.pack(side="right")

        def _toggle_from_label(_e: Any = None) -> None:
            tog._on_click()

        lbl.bind("<Button-1>", _toggle_from_label)
        lbl.bind("<Enter>", lambda _e: lbl.configure(fg=FG), add="+")
        lbl.bind("<Leave>", lambda _e: lbl.configure(fg=fg), add="+")
        if tooltip:
            for w in (row, lbl, tog):
                self.attach_tooltip(w, tooltip)
        return row

    @classmethod
    def _restyle_button(cls, btn: Any, text: str, kind: str) -> None:
        bg, fg, hover, border, border_hover = cls._button_palette(kind)
        btn._netdoc_palette = (bg, fg, hover, border, border_hover)  # type: ignore[attr-defined]
        btn.configure(
            text=text,
            bg=bg,
            fg=fg,
            activebackground=hover,
            activeforeground=fg,
            highlightbackground=border,
        )

    def make_entry(self, parent: tk.Misc, textvariable: tk.StringVar, width: int = 24) -> tk.Entry:
        return tk.Entry(
            parent,
            textvariable=textvariable,
            width=width,
            bg=INPUT,
            fg=FG,
            insertbackground=ACCENT,
            relief="flat",
            highlightthickness=1,
            highlightbackground=BORDER,
            highlightcolor=ACCENT,
            font=FONT_UI,
            disabledbackground=INPUT,
        )

    def make_text(self, parent: tk.Misc, height: int = 10, wrap: str = "none") -> tk.Text:
        return tk.Text(
            parent,
            width=30,
            height=height,
            wrap=wrap,
            bg=SIDEBAR_BG,
            fg=FG_SOFT,
            insertbackground=ACCENT,
            relief="flat",
            highlightthickness=0,
            font=FONT_MONO,
            padx=10,
            pady=8,
            selectbackground=SELECT_BG,
            selectforeground="#FFFFFF",
            state="disabled",
        )

    def make_tree(self, parent: tk.Misc, columns: tuple[str, ...], height: int = 10) -> ttk.Treeview:
        return ttk.Treeview(parent, columns=columns, show="headings", selectmode="browse", height=height)

    def _scrolled(self, parent: tk.Misc, widget: Any, horizontal: bool = False) -> None:
        vsb = ttk.Scrollbar(parent, orient="vertical", command=widget.yview)
        widget.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        if horizontal:
            hsb = ttk.Scrollbar(parent, orient="horizontal", command=widget.xview)
            widget.configure(xscrollcommand=hsb.set)
            hsb.pack(side="bottom", fill="x")
        widget.pack(side="left", fill="both", expand=True)

    @staticmethod
    def _set_text(widget: tk.Text, text: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    def _make_page_header(self, parent: tk.Misc, title: str, subtitle: str) -> tk.Frame:
        hdr = tk.Frame(parent, bg=BG)
        hdr.pack(fill="x", pady=(2, 6))
        tk.Label(hdr, text=title, bg=BG, fg=FG, font=FONT_HERO, anchor="w").pack(anchor="w")
        sub_lbl = tk.Label(hdr, text=subtitle, bg=BG, fg=MUTED, font=FONT_SMALL, anchor="w", justify="left")
        sub_lbl.pack(fill="x", anchor="w", pady=(2, 0))
        self._bind_responsive_wrap(sub_lbl, min_wrap=260, pad=16)
        return hdr

    def _bind_card_hover(
        self,
        card: tk.Frame,
        bg_widgets: list[tk.Misc],
        normal_bg: str,
        hover_bg: str,
        normal_border: str = BORDER,
        hover_border: str = ACCENT,
    ) -> None:
        def _set_state(hovered: bool) -> None:
            try:
                bg = hover_bg if hovered else normal_bg
                brd = hover_border if hovered else normal_border
                card.configure(bg=bg, highlightbackground=brd)
                for w in bg_widgets:
                    if w is not card:
                        w.configure(bg=bg)
            except tk.TclError:
                pass

        def _on_leave(_e: Any) -> None:
            try:
                px, py = self.winfo_pointerxy()
                under = self.winfo_containing(px, py)
                cur = under
                while cur is not None:
                    if cur == card:
                        return
                    cur = cur.master  # type: ignore[assignment]
            except tk.TclError:
                pass
            _set_state(False)

        for w in [card, *bg_widgets]:
            w.bind("<Enter>", lambda _e: _set_state(True), add="+")
            w.bind("<Leave>", _on_leave, add="+")

    @staticmethod
    def _bind_responsive_wrap(label: tk.Label, min_wrap: int = 160, pad: int = 28) -> None:
        def _on_cfg(event: Any) -> None:
            w = getattr(event, "width", 0)
            if w and w > 60:
                try:
                    label.configure(wraplength=max(min_wrap, w - pad))
                except tk.TclError:
                    pass

        label.bind("<Configure>", _on_cfg, add="+")

    # ---------------------------------------------------------------- statusbar & shell layout

    def _build_statusbar(self) -> None:
        bar = tk.Frame(self, bg=SIDEBAR_BG, highlightthickness=1, highlightbackground=BORDER)
        bar.pack(side="bottom", fill="x")
        self.status_var = tk.StringVar(value="Готово к работе")
        self.status_label = tk.Label(bar, textvariable=self.status_var, bg=SIDEBAR_BG, fg=FG_SOFT, font=FONT_SMALL, anchor="w")
        self.status_label.pack(side="left", fill="x", expand=True, padx=14, pady=5)
        self.progress = ttk.Progressbar(bar, mode="indeterminate", length=140)

    def _build_shell(self) -> None:
        shell = tk.Frame(self, bg=BG)
        shell.pack(fill="both", expand=True)

        self._build_sidebar(shell)

        right_col = tk.Frame(shell, bg=BG)
        right_col.pack(side="left", fill="both", expand=True)

        self._build_header(right_col)
        self._build_notebook(right_col)

    def _build_sidebar(self, parent: tk.Misc) -> None:
        sidebar = tk.Frame(parent, bg=SIDEBAR_BG, width=168)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        self._sidebar_frame = sidebar

        # Subtle vertical divider on the right edge of sidebar
        tk.Frame(parent, bg=BORDER, width=1).pack(side="left", fill="y")

        # Top brand emblem + app title
        brand = tk.Frame(sidebar, bg=SIDEBAR_BG)
        brand.pack(fill="x", pady=(12, 8), padx=10)
        emblem = tk.Label(
            brand,
            text="◈  netdoctor",
            bg=SIDEBAR_BG,
            fg=ACCENT,
            font=("Segoe UI", 13, "bold"),
            anchor="w",
        )
        emblem.pack(fill="x")
        self.attach_tooltip(emblem, f"ZAPRET // NETDOCTOR v{__version__}\nАдаптивный обход блокировок")

        tk.Frame(sidebar, bg=BORDER, height=1).pack(fill="x", padx=12, pady=(2, 8))

        self._nav_container = tk.Frame(sidebar, bg=SIDEBAR_BG)
        self._nav_container.pack(fill="x", padx=6)

        # Bottom compact service status LEDs (visible in Expert mode)
        stack_card = tk.Frame(sidebar, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
        self._sidebar_leds_card = stack_card
        stack_card.pack(side="bottom", fill="x", padx=8, pady=10)
        tk.Label(stack_card, text="МОДУЛИ", bg=CARD, fg=DIM, font=("Segoe UI", 7, "bold"), anchor="center").pack(
            fill="x", pady=(5, 2)
        )

        self.leds: dict[str, tuple[tk.Canvas, int, tk.Label]] = {}
        for key, title, tip_text in PROCESS_LEDS:
            row = tk.Frame(stack_card, bg=CARD)
            row.pack(fill="x", padx=8, pady=1)
            canvas = tk.Canvas(row, width=10, height=10, bg=CARD, highlightthickness=0)
            canvas.pack(side="left", padx=(0, 5), pady=2)
            oval = canvas.create_oval(1, 1, 9, 9, fill=ERR, outline="")
            lbl = tk.Label(row, text=title, bg=CARD, fg=MUTED, font=FONT_MICRO, anchor="w")
            lbl.pack(side="left", fill="x", expand=True)
            self.leds[key] = (canvas, oval, lbl)
            for w in (row, canvas, lbl):
                self.attach_tooltip(w, tip_text)
        tk.Frame(stack_card, bg=CARD, height=4).pack()

    def _build_header(self, parent: tk.Misc) -> None:
        banner = tk.Frame(parent, bg=HEADER_BG)
        banner.pack(fill="x")
        self.activity_bar = ActivityBar(parent, bg=BG)
        self.activity_bar.pack(fill="x")

        inner = tk.Frame(banner, bg=HEADER_BG)
        inner.pack(fill="x", padx=16, pady=8)

        # Right: Metadata readouts + conditional badges + single Refresh icon
        ctrl = tk.Frame(inner, bg=HEADER_BG)
        ctrl.pack(side="right", padx=(14, 0))

        refresh_btn = self.make_button(
            ctrl,
            "↻",
            self.refresh_async,
            kind="ghost",
            width=3,
            pady=5,
            tooltip="Обновить состояние сети и всех служб (F5)",
        )
        refresh_btn.pack(side="right", padx=(8, 0))

        meta_box = tk.Frame(ctrl, bg=HEADER_BG)
        meta_box.pack(side="right", padx=(8, 4))

        ver_col = tk.Frame(meta_box, bg=HEADER_BG)
        ver_col.pack(side="left", padx=(0, 12))
        tk.Label(ver_col, text="ВЕРСИЯ", bg=HEADER_BG, fg=DIM, font=("Segoe UI", 7, "bold"), anchor="e").pack(anchor="e")
        tk.Label(ver_col, text=f"v{__version__}", bg=HEADER_BG, fg=LAVENDER, font=FONT_SMALL_B, anchor="e").pack(anchor="e")

        priv_col = tk.Frame(meta_box, bg=HEADER_BG)
        priv_col.pack(side="left")
        tk.Label(priv_col, text="ДОСТУП", bg=HEADER_BG, fg=DIM, font=("Segoe UI", 7, "bold"), anchor="e").pack(anchor="e")
        self.priv_label = tk.Label(
            priv_col,
            text="Проверка…",
            bg=INPUT,
            fg=MUTED,
            font=FONT_MICRO,
            anchor="e",
            padx=6,
            pady=1,
        )
        self.priv_label.pack(anchor="e")
        self.attach_tooltip(
            self.priv_label,
            "Права администратора необходимы для запуска драйвера обхода блокировок и VPN-туннеля.",
        )

        self._priv_btn_slot = tk.Frame(ctrl, bg=HEADER_BG)
        self._priv_btn_slot.pack(side="right")
        self.priv_btn = self.make_button(
            self._priv_btn_slot,
            "Права Admin",
            self.on_elevate,
            "warn",
            font=FONT_SMALL_B,
            padx=10,
            pady=5,
            tooltip="Перезапустить программу с правами администратора (UAC) для полноценной работы защиты.",
        )
        self._pending_btn_slot = tk.Frame(ctrl, bg=HEADER_BG)
        self._pending_btn_slot.pack(side="right")
        self.apply_pending_btn = self.make_button(
            self._pending_btn_slot,
            "Применить изменения",
            self.on_force_apply_pending,
            "primary",
            font=FONT_SMALL_B,
            padx=10,
            pady=5,
            tooltip="Применить отложенные изменения правил прямо сейчас.",
        )
        self._update_btn_slot = tk.Frame(ctrl, bg=HEADER_BG)
        self._update_btn_slot.pack(side="right")
        self.update_badge_btn = self.make_button(
            self._update_btn_slot,
            "↑ Обновление",
            lambda: self._select_tab(self.tab_service),
            "primary",
            font=FONT_SMALL_B,
            padx=10,
            pady=5,
            tooltip="Доступна новая версия NetDoctor — нажмите чтобы перейти к обновлению.",
        )

        # Left: App Title + live status pill + network fingerprint
        left = tk.Frame(inner, bg=HEADER_BG)
        left.pack(side="left", fill="x", expand=True)

        brand_row = tk.Frame(left, bg=HEADER_BG)
        brand_row.pack(fill="x", anchor="w")
        tk.Label(brand_row, text="NETDOCTOR", bg=HEADER_BG, fg=LAVENDER, font=FONT_TITLE).pack(side="left")
        tk.Label(brand_row, text="  adaptive bypass", bg=HEADER_BG, fg=DIM, font=FONT_SMALL).pack(side="left", pady=(2, 0))

        status_row = tk.Frame(left, bg=HEADER_BG)
        status_row.pack(fill="x", anchor="w", pady=(3, 0))
        self.hero_state_pill = tk.Label(
            status_row,
            text="● ОСТАНОВЛЕНО",
            bg=INPUT,
            fg=MUTED,
            font=FONT_MICRO,
            padx=8,
            pady=2,
        )
        self.hero_state_pill.pack(side="left", padx=(0, 10))
        self.attach_tooltip(self.hero_state_pill, "Текущее состояние системы обхода блокировок и активный режим.")

        self.network_label = tk.Label(
            status_row, text="Сеть: определение…", bg=HEADER_BG, fg=MUTED, font=FONT_SMALL, anchor="w", justify="left"
        )
        self.network_label.pack(side="left", fill="x", expand=True)
        self._bind_responsive_wrap(self.network_label, min_wrap=150, pad=8)

        self.bypass_label = tk.Label(
            left,
            text="",
            bg=WARN_BG,
            fg=WARN_TEXT,
            font=FONT_SMALL_B,
            anchor="w",
            justify="left",
            padx=8,
            pady=2,
        )
        self._bind_responsive_wrap(self.bypass_label, min_wrap=220, pad=16)

    def _build_notebook(self, parent: tk.Misc) -> None:
        wrap = tk.Frame(parent, bg=BG)
        wrap.pack(fill="both", expand=True, padx=14, pady=(8, 8))

        self.notebook = ttk.Notebook(wrap, style="NavHidden.TNotebook")
        self.notebook.pack(fill="both", expand=True)

        # Basic tabs (always visible — strictly 3 tabs)
        self.tab_home = ttk.Frame(self.notebook)
        self.tab_vpn = ttk.Frame(self.notebook)
        self.tab_settings = ttk.Frame(self.notebook)
        self.tab_service = self.tab_settings

        # Expert tabs (visible when expert_mode == True — total 7 tabs)
        self.tab_domains = ttk.Frame(self.notebook)
        self.tab_presets = ttk.Frame(self.notebook)
        self.tab_dns = ttk.Frame(self.notebook)
        self.tab_logs = ttk.Frame(self.notebook)
        self.tab_realtime = self.tab_domains
        self._expert_tabs = (self.tab_domains, self.tab_presets, self.tab_dns, self.tab_logs)

        self.notebook.add(self.tab_home, text="Главная")
        self.notebook.add(self.tab_vpn, text="VPN")
        self.notebook.add(self.tab_settings, text="Настройки")
        self.notebook.add(self.tab_domains, text="Монитор и правила")
        self.notebook.add(self.tab_presets, text="Пресеты Zapret")
        self.notebook.add(self.tab_dns, text="Каталог DNS")
        self.notebook.add(self.tab_logs, text="Логи и конфиги")

        nav_defs: tuple[tuple[ttk.Frame, str, str, str, str], ...] = (
            (self.tab_home, "⌂", "Главная", "", "Главная — статус защиты, быстрое включение и лечение сбоев"),
            (self.tab_vpn, "☁", "VPN", "0", "VPN и Telegram — подписки, серверы и режим Telegram"),
            (self.tab_settings, "⚙", "Настройки", "", "Настройки — автозапуск, тема, сброс сети и режим эксперта"),
            (self.tab_domains, "📊", "Монитор", "0/0", "Монитор и правила — сайты, программы/игры и подключения"),
            (self.tab_presets, "⚡", "Пресеты", "0", "Пресеты Zapret — стратегии обхода DPI"),
            (self.tab_dns, "◉", "DNS", "43", "Каталог DNS — защищённый DNS и нейросети"),
            (self.tab_logs, "📜", "Логи", "", "Логи и конфиги служб"),
        )
        for tab, icon, title, badge, tip_text in nav_defs:
            self._add_nav_item(tab, icon, title, badge, tooltip=tip_text)

        self.notebook.bind("<<NotebookTabChanged>>", lambda _e: self._sync_sidebar_selection())

        self._build_home_tab()
        self._build_vpn_tab()
        self._build_service_tab()
        self._build_domains_tab()
        self._build_presets_tab()
        self._build_dns_tab()
        self._build_logs_tab()

        initial_expert = bool(self.backend.get_expert_mode()) if hasattr(self.backend, "get_expert_mode") else False
        self.set_expert_mode(initial_expert, persist=False)
        if hasattr(self.backend, "get_telegram_mode"):
            try:
                sync_telegram_mode_ui(self, self.backend.get_telegram_mode())
            except Exception:
                pass
        self._sync_sidebar_selection()

    def _add_nav_item(
        self,
        tab: ttk.Frame,
        icon: str,
        title: str,
        badge_text: str,
        *,
        tooltip: str = "",
    ) -> None:
        tab_key = str(tab)
        row = tk.Frame(self._nav_container, bg=SIDEBAR_BG, cursor="hand2")
        row.pack(fill="x", pady=3)

        indicator = tk.Frame(row, bg=SIDEBAR_BG, width=3)
        indicator.pack(side="left", fill="y", padx=(0, 3))

        box = tk.Frame(row, bg=SIDEBAR_BG)
        box.pack(side="left", fill="both", expand=True, padx=(0, 4), pady=5)

        icon_lbl = tk.Label(box, text=icon, bg=SIDEBAR_BG, fg=MUTED, font=("Segoe UI", 11, "bold"), anchor="center", width=2)
        icon_lbl.pack(side="left", padx=(4, 5))

        text_lbl = tk.Label(box, text=title, bg=SIDEBAR_BG, fg=FG_SOFT, font=FONT_SMALL, anchor="w")
        text_lbl.pack(side="left", fill="x", expand=True)

        badge_lbl = tk.Label(
            box,
            text=badge_text,
            bg=INPUT if badge_text else SIDEBAR_BG,
            fg=MUTED,
            font=("Segoe UI", 7, "bold"),
            padx=5 if badge_text else 0,
            pady=0,
        )
        if badge_text:
            badge_lbl.pack(side="right", padx=(3, 4))

        self._nav_items[tab_key] = (row, indicator, icon_lbl, text_lbl, badge_lbl)

        for w in (row, indicator, box, icon_lbl, text_lbl, badge_lbl):
            w.bind("<Button-1>", lambda _e, t=tab: self._select_tab(t))
            w.bind("<Enter>", lambda _e, k=tab_key: self._hover_nav_item(k, True))
            w.bind("<Leave>", lambda _e, k=tab_key: self._hover_nav_item(k, False))
            if tooltip:
                self.attach_tooltip(w, tooltip)

    def get_visible_nav_tabs(self) -> list[ttk.Frame]:
        """Return currently visible sidebar navigation tab frames in order."""
        all_tabs = [
            self.tab_home,
            self.tab_vpn,
            self.tab_settings,
            self.tab_domains,
            self.tab_presets,
            self.tab_dns,
            self.tab_logs,
        ]
        visible: list[ttk.Frame] = []
        for t in all_tabs:
            item = self._nav_items.get(str(t))
            if item and item[0].winfo_manager():
                visible.append(t)
        return visible

    def set_expert_mode(self, enabled: bool, *, persist: bool = True) -> None:
        """Toggle Progressive Disclosure between Basic (3 tabs) and Expert (7 tabs) without restart."""
        self._expert_mode = bool(enabled)
        self.expert_mode_var.set(self._expert_mode)
        ordered_tabs = (
            self.tab_home,
            self.tab_vpn,
            self.tab_settings,
            self.tab_domains,
            self.tab_presets,
            self.tab_dns,
            self.tab_logs,
        )
        for tab in self._expert_tabs:
            item = self._nav_items.get(str(tab))
            if self._expert_mode:
                try:
                    self.notebook.add(tab)
                except tk.TclError:
                    pass
                if item and not item[0].winfo_manager():
                    item[0].pack(fill="x", pady=3)
            else:
                if item and item[0].winfo_manager():
                    item[0].pack_forget()
                try:
                    if self.notebook.select() == str(tab):
                        self.notebook.select(self.tab_home)
                except tk.TclError:
                    pass
                try:
                    self.notebook.hide(tab)
                except tk.TclError:
                    pass

        if self._expert_mode:
            for tab in ordered_tabs:
                item = self._nav_items.get(str(tab))
                if item:
                    item[0].pack_forget()
                    item[0].pack(fill="x", pady=3)

        if hasattr(self, "_sidebar_leds_card"):
            if self._expert_mode:
                if not self._sidebar_leds_card.winfo_manager():
                    self._sidebar_leds_card.pack(side="bottom", fill="x", padx=8, pady=10)
            elif self._sidebar_leds_card.winfo_manager():
                self._sidebar_leds_card.pack_forget()

        if hasattr(self, "network_label"):
            if self._expert_mode:
                if not self.network_label.winfo_manager():
                    self.network_label.pack(side="left", fill="x", expand=True)
            elif self.network_label.winfo_manager():
                self.network_label.pack_forget()

        if hasattr(self, "_home_expert_strip"):
            if self._expert_mode:
                if not self._home_expert_strip.winfo_manager():
                    self._home_expert_strip.pack(fill="x", padx=18, pady=(0, 6))
            elif self._home_expert_strip.winfo_manager():
                self._home_expert_strip.pack_forget()

        if hasattr(self, "_expert_settings_frame"):
            if self._expert_mode:
                if not self._expert_settings_frame.winfo_manager():
                    self._expert_settings_frame.pack(fill="x", pady=(0, 10))
            elif self._expert_settings_frame.winfo_manager():
                self._expert_settings_frame.pack_forget()

        if persist and hasattr(self.backend, "set_expert_mode"):
            try:
                self.backend.set_expert_mode(self._expert_mode)
            except Exception:
                pass
        self._sync_sidebar_selection()

    def _select_tab(self, tab: ttk.Frame) -> None:
        self.notebook.select(tab)
        self._sync_sidebar_selection()

    def _hover_nav_item(self, tab_key: str, entering: bool) -> None:
        try:
            active_key = str(self.notebook.select())
        except tk.TclError:
            active_key = ""
        if tab_key == active_key or tab_key not in self._nav_items:
            return
        row, indicator, icon_lbl, text_lbl, badge_lbl = self._nav_items[tab_key]
        if not entering:
            try:
                px, py = self.winfo_pointerxy()
                cur = self.winfo_containing(px, py)
                while cur is not None:
                    if cur == row:
                        return
                    cur = cur.master  # type: ignore[assignment]
            except tk.TclError:
                pass
        bg = CARD if entering else SIDEBAR_BG
        fg = FG if entering else FG_SOFT
        try:
            row.configure(bg=bg)
            indicator.configure(bg=bg)
            icon_lbl.master.configure(bg=bg)
            icon_lbl.configure(bg=bg, fg=ACCENT if entering else MUTED)
            text_lbl.configure(bg=bg, fg=fg)
            if not badge_lbl.cget("text"):
                badge_lbl.configure(bg=bg)
        except tk.TclError:
            pass

    def _sync_sidebar_selection(self) -> None:
        try:
            active_key = str(self.notebook.select())
        except tk.TclError:
            active_key = ""
        for tab_key, (row, indicator, icon_lbl, text_lbl, badge_lbl) in self._nav_items.items():
            active = tab_key == active_key
            bg = PILL_ACTIVE_BG if active else SIDEBAR_BG
            try:
                row.configure(bg=bg)
                indicator.configure(bg=ACCENT if active else bg)
                icon_lbl.master.configure(bg=bg)
                icon_lbl.configure(bg=bg, fg=ACCENT if active else MUTED)
                text_lbl.configure(bg=bg, fg=FG if active else FG_SOFT, font=FONT_UI_B if active else FONT_UI)
                has_badge = bool(badge_lbl.cget("text"))
                badge_lbl.configure(
                    bg=INFO_BG if (active and has_badge) else (INPUT if has_badge else bg),
                    fg=ACCENT if active else MUTED,
                )
            except tk.TclError:
                pass

    def _update_nav_badge(self, tab: ttk.Frame, text: str) -> None:
        item = self._nav_items.get(str(tab))
        if not item:
            return
        _row, _ind, _ic, _tx, badge_lbl = item
        try:
            badge_lbl.configure(text=text, padx=5 if text else 0)
            if text and not badge_lbl.winfo_manager():
                badge_lbl.pack(side="right", padx=(3, 4))
            elif not text and badge_lbl.winfo_manager():
                badge_lbl.pack_forget()
            self._sync_sidebar_selection()
        except tk.TclError:
            pass

    def _build_home_tab(self) -> None:
        build_home_tab(self)

    def _toggle_home_guide(self) -> None:
        if self._guide_visible:
            dismiss_onboarding(self)
            self._guide_visible = False

    def _toggle_home_extra(self) -> None:
        if self._extra_visible:
            if hasattr(self, "_home_extra_frame") and self._home_extra_frame.winfo_manager():
                self._home_extra_frame.pack_forget()
            self._extra_visible = False
            if hasattr(self, "_extra_toggle_lbl"):
                self._extra_toggle_lbl.configure(text="Детали трафика ⌄")
        else:
            if hasattr(self, "_home_extra_frame"):
                self._home_extra_frame.pack(fill="x")
            self._extra_visible = True
            if hasattr(self, "_extra_toggle_lbl"):
                self._extra_toggle_lbl.configure(text="Скрыть детали ⌃")

    # ---------------------------------------------------------------- Tab 2: Монитор трафика и сайты (Unified)

    def _build_domains_tab(self) -> None:
        build_monitor_tab(self)

    def _switch_domains_subview(self, mode: str) -> None:
        clean = mode if mode in ("domains", "bundles", "connections") else "domains"
        self._domains_subview_mode = clean
        for sub_attr in ("_domains_subview", "_bundles_subview", "_conns_subview"):
            frame = getattr(self, sub_attr, None)
            if frame is not None and frame.winfo_manager():
                frame.pack_forget()
        target_frame = {
            "domains": getattr(self, "_domains_subview", None),
            "bundles": getattr(self, "_bundles_subview", None),
            "connections": getattr(self, "_conns_subview", None),
        }.get(clean)
        if target_frame is not None:
            target_frame.pack(fill="both", expand=True)
        for btn_attr, btn_mode in (
            ("_subtab_domains_btn", "domains"),
            ("_subtab_bundles_btn", "bundles"),
            ("_subtab_conns_btn", "connections"),
        ):
            btn = getattr(self, btn_attr, None)
            if btn is not None:
                self._restyle_button(btn, btn.cget("text"), "pill_active" if clean == btn_mode else "neutral")

    def _open_domains_subview(self, mode: str) -> None:
        self._select_tab(self.tab_domains)
        self._switch_domains_subview(mode)

    def _set_domain_layer_filter(self, layer: str) -> None:
        self.layer_filter_var.set(layer)
        self.populate_domain_table()

    def _sync_domain_filter_pills(self) -> None:
        cur = self.layer_filter_var.get() or "ALL"
        for lid, btn in self._domain_filter_buttons.items():
            self._restyle_button(btn, LAYER_FILTER_LABELS.get(lid, lid), "pill_active" if lid == cur else "neutral")

    def _on_domain_context_menu(self, event: Any) -> None:
        iid = self.domain_tree.identify_row(event.y)
        if iid:
            self.domain_tree.selection_set(iid)
            self.on_domain_select()
            try:
                self._domain_menu.tk_popup(event.x_root, event.y_root)
            finally:
                self._domain_menu.grab_release()

    def _quick_pin_selected(self, layer: str, strategy: str | None) -> None:
        if not self.selected_row:
            return
        self.override_layer_var.set(layer)
        self._refresh_strategy_choices(str(self.selected_row.get("protocol", "")))
        self.override_strategy_var.set(strategy or "")
        self.on_pin()

    def _copy_selected_domain(self) -> None:
        if not self.selected_row:
            return
        dom = str(self.selected_row.get("domain") or "")
        if dom:
            self.clipboard_clear()
            self.clipboard_append(dom)
            self.set_status(f"Скопировано в буфер: {dom}", ACCENT)

    def _build_inspector(self, parent: tk.Misc) -> tk.Frame:
        return build_inspector(self, parent)

    def _on_rule_mousewheel(self, event: Any) -> str | None:
        if self._closed or not hasattr(self, "rule_canvas"):
            return None
        is_combo = isinstance(getattr(event, "widget", None), ttk.Combobox)
        try:
            if not self.rule_canvas.winfo_viewable():
                return "break" if is_combo else None
            first, last = self.rule_canvas.yview()
            if float(first) <= 0.001 and float(last) >= 0.999:
                return "break" if is_combo else None
        except tk.TclError:
            return None
        delta = getattr(event, "delta", 0)
        if delta:
            step = -2 if delta > 0 else 2
            if abs(delta) >= 120:
                step = int(-delta / 120) * 2
            if (step < 0 and float(first) <= 0.0) or (step > 0 and float(last) >= 1.0):
                return "break"
            self.rule_canvas.yview_scroll(step, "units")
            return "break"
        return "break" if is_combo else None

    def _bind_rule_mousewheel(self, widget: tk.Misc) -> None:
        """Recursively attach <MouseWheel> handler to rule management panel widgets (also stops Combobox accidental wheel changes)."""
        widget.bind("<MouseWheel>", self._on_rule_mousewheel, add="+")
        for child in widget.winfo_children():
            self._bind_rule_mousewheel(child)

    # ---------------------------------------------------------------- Tab 3: Стратегии обхода (Zapret)

    def _build_presets_tab(self) -> None:
        build_presets_tab(self)

    def _build_dns_tab(self) -> None:
        build_dns_tab(self)

    def _on_dns_mousewheel(self, event: Any) -> str | None:
        if self._closed:
            return None
        try:
            if not self.dns_canvas.winfo_viewable():
                return None
        except tk.TclError:
            return None
        delta = getattr(event, "delta", 0)
        if delta:
            step = -1 if delta > 0 else 1
            if abs(delta) >= 120:
                step = int(-delta / 120)
            self.dns_canvas.yview_scroll(step, "units")
            return "break"
        return None

    def _bind_dns_mousewheel(self, widget: tk.Misc) -> None:
        """Recursively attach <MouseWheel> handler to all card sub-widgets for Windows scrolling."""
        widget.bind("<MouseWheel>", self._on_dns_mousewheel)
        for child in widget.winfo_children():
            self._bind_dns_mousewheel(child)

    def set_dns_category_filter(self, category: str) -> None:
        self.dns_category_filter = category
        for cid, btn in self._dns_cat_buttons.items():
            self._restyle_button(btn, btn.cget("text"), "pill_active" if cid == category else "neutral")
        self._dns_signature = ""
        if self.dns_catalog:
            self.render_dns_grid(self.dns_catalog, self.active_dns_id)

    def load_dns_catalog_async(self) -> None:
        def done(data: dict[str, Any]) -> None:
            self.dns_catalog = list(data.get("servers") or [])
            self.active_dns_id = str(data.get("active_dns_id") or "cloudflare")
            self._base_dns = data.get("base_dns")
            self.render_dns_grid(self.dns_catalog, self.active_dns_id)

        def runner() -> None:
            try:
                data = self.backend.get_dns_catalog()
            except Exception:  # noqa: BLE001
                return
            self._post(done, data)

        threading.Thread(target=runner, name="gui-dns-cat", daemon=True).start()

    def render_dns_grid(self, servers: list[dict[str, Any]], active_dns_id: str) -> None:
        """Render the categorized card grid of DNS servers."""
        self.dns_catalog = list(servers)
        self.active_dns_id = active_dns_id
        self.notebook.tab(self.tab_dns, text=f"DNS и Нейросети ({len(servers)})")
        self._update_nav_badge(self.tab_dns, str(len(servers)))

        active_srv = next((s for s in servers if s.get("id") == active_dns_id), None)
        active_is_smart = bool(active_srv and str(active_srv.get("category") or "").strip().lower() == "ai_bypass")

        raw_base = self._base_dns if isinstance(self._base_dns, dict) and self._base_dns.get("id") else None
        base_dns_id = str(raw_base["id"]) if raw_base else ""
        base_srv = next((s for s in servers if s.get("id") == base_dns_id), None) if base_dns_id else None
        if base_srv is None:
            base_srv = raw_base

        if active_srv:
            srv_name = str(active_srv.get("name", active_dns_id))
            srv_ip = str(active_srv.get("ip", ""))
            if active_is_smart:
                if base_srv:
                    b_name = str(base_srv.get("name") or base_srv.get("id") or "")
                    b_ping = base_srv.get("ping_ms")
                    b_suffix = f" ({b_ping:.0f} мс)" if b_ping is not None else f" ({base_srv.get('ip', '')})"
                    base_txt = f"Обычный / VPN: {b_name}{b_suffix}"
                else:
                    base_txt = "Обычный / VPN: Авто"
                self.active_dns_pill.configure(text=base_txt, bg=INFO_BG, fg=ACCENT)
                if hasattr(self, "smart_dns_pill"):
                    self.smart_dns_pill.configure(text=f"✦ ИИ: {srv_name}", bg=PURPLE_BG, fg=LAVENDER)
                    if not self.smart_dns_pill.winfo_manager():
                        self.smart_dns_pill.pack(side="left", padx=(6, 0))
            else:
                ping_val = active_srv.get("ping_ms")
                ping_part = f" • {ping_val:.0f} мс" if ping_val is not None else f" ({srv_ip})"
                self.active_dns_pill.configure(text=f"Основной DNS: {srv_name}{ping_part}", bg=INFO_BG, fg=ACCENT)
                if hasattr(self, "smart_dns_pill") and self.smart_dns_pill.winfo_manager():
                    self.smart_dns_pill.pack_forget()

        sig = repr(
            (
                self.dns_category_filter,
                active_dns_id,
                base_dns_id if active_is_smart else "",
                [
                    (s.get("id"), s.get("ping_ms"), s.get("alive"), tuple(s.get("assigned_domains") or []))
                    for s in servers
                ],
            )
        )
        if sig == self._dns_signature:
            return
        self._dns_signature = sig

        for child in self.dns_grid_frame.winfo_children():
            child.destroy()

        cat_meta: tuple[tuple[str, str, str], ...] = (
            ("popular", "Популярные", "быстрые мировые и локальные DNS"),
            ("security", "Безопасные", "с защитой от вирусов, рекламы или 18+"),
            ("uncommon", "Малоизвестные", "реже попадают под блокировки"),
            ("ai_bypass", "Для ИИ", "серверы сообщества — ChatGPT, Claude, Grok, Spotify"),
            ("custom", "Мои DNS", "добавленные вами вручную"),
        )
        cat_colors = {
            "popular": ACCENT,
            "security": OK_TEXT,
            "uncommon": PURPLE,
            "ai_bypass": WARN_TEXT,
            "custom": "#FB923C",
        }

        for cat_id, cat_title, cat_hint in cat_meta:
            if self.dns_category_filter != "ALL" and self.dns_category_filter != cat_id:
                continue
            items = [s for s in servers if s.get("category") == cat_id]
            if not items and cat_id != "custom":
                continue

            sec_hdr = tk.Frame(self.dns_grid_frame, bg=BG)
            sec_hdr.pack(fill="x", padx=12, pady=(12, 4))
            tk.Label(sec_hdr, text=cat_title, bg=BG, fg=FG, font=FONT_H2).pack(side="left")
            tk.Label(sec_hdr, text=f" {len(items)} ", bg=INPUT, fg=MUTED, font=FONT_MICRO, padx=5, pady=1).pack(
                side="left", padx=(8, 0)
            )
            if cat_hint:
                tk.Label(sec_hdr, text=cat_hint, bg=BG, fg=MUTED, font=FONT_SMALL).pack(side="left", padx=(10, 0))

            if not items:
                tk.Label(
                    self.dns_grid_frame,
                    text="Добавьте свой DNS-сервер справа вверху — он появится в этом разделе.",
                    bg=BG,
                    fg=MUTED,
                    font=FONT_SMALL,
                    anchor="w",
                ).pack(fill="x", padx=12, pady=(0, 8))
                continue

            grid = tk.Frame(self.dns_grid_frame, bg=BG)
            grid.pack(fill="x", padx=6, pady=(0, 4))
            for c_idx in range(3):
                grid.columnconfigure(c_idx, weight=1, uniform=f"dns_{cat_id}")

            for idx, srv in enumerate(items):
                r_idx, c_idx = divmod(idx, 3)
                sid = str(srv.get("id") or "")
                if active_is_smart:
                    role: str | None = (
                        "smart" if sid == active_dns_id else ("base" if base_dns_id and sid == base_dns_id else None)
                    )
                else:
                    role = "active" if sid == active_dns_id else None
                self._make_dns_card(grid, r_idx, c_idx, srv, cat_colors.get(cat_id, ACCENT), role=role)

        self._bind_dns_mousewheel(self.dns_grid_frame)

    def _make_dns_card(
        self,
        parent: tk.Misc,
        row: int,
        col: int,
        srv: dict[str, Any],
        accent_color: str,
        role: str | None = None,
    ) -> None:
        is_marked = role is not None
        if role == "smart":
            card_bg = PURPLE_BG
            hover_bg = PURPLE_BG
            border_col = PILL_ACTIVE_BORDER
            border_w = 2
            badge_text = "✦ SmartDNS (ИИ)"
            badge_bg, badge_fg = PILL_ACTIVE_BG, LAVENDER
        elif role == "base":
            card_bg = CARD_ACTIVE
            hover_bg = CARD_ACTIVE
            border_col = CYAN_BORDER
            border_w = 2
            badge_text = "✔ Обычный / VPN"
            badge_bg, badge_fg = INFO_BG, ACCENT
        elif role == "active":
            card_bg = CARD_ACTIVE
            hover_bg = CARD_ACTIVE
            border_col = CYAN_BORDER
            border_w = 2
            badge_text = "✔ Активный"
            badge_bg, badge_fg = INFO_BG, ACCENT
        else:
            card_bg = CARD
            hover_bg = CARD_ALT
            border_col = BORDER
            border_w = 1
            badge_text = ""
            badge_bg, badge_fg = INFO_BG, ACCENT

        card = tk.Frame(
            parent,
            bg=card_bg,
            highlightthickness=border_w,
            highlightbackground=border_col,
            cursor="hand2",
        )
        card.grid(row=row, column=col, sticky="nsew", padx=4, pady=4)

        top = tk.Frame(card, bg=card_bg)
        top.pack(fill="x", padx=8, pady=(8, 2))
        clickable: list[tk.Misc] = [card, top]
        hover_widgets: list[tk.Misc] = [top]

        if badge_text:
            chk = tk.Label(top, text=badge_text, bg=badge_bg, fg=badge_fg, font=FONT_MICRO, padx=5, pady=1)
            chk.pack(side="right", padx=(4, 0))
            clickable.append(chk)

        if not srv.get("builtin", True):
            del_btn = tk.Label(top, text="✕", bg=card_bg, fg=ERR_TEXT, font=FONT_SMALL_B, cursor="hand2", padx=4)
            del_btn.pack(side="right", padx=(0, 4))
            del_btn.bind("<Button-1>", lambda _e, sid=srv["id"]: self.on_delete_custom_dns(sid))
            hover_widgets.append(del_btn)

        dot = tk.Label(top, text="●", bg=card_bg, fg=accent_color, font=FONT_SMALL_B)
        dot.pack(side="left", padx=(0, 4))
        name_lbl = tk.Label(top, text=str(srv.get("name", "")), bg=card_bg, fg=FG, font=FONT_SMALL_B, anchor="w")
        name_lbl.pack(side="left", fill="x", expand=True)
        clickable.extend([dot, name_lbl])
        hover_widgets.extend([dot, name_lbl])

        desc_lbl = tk.Label(
            card,
            text=str(srv.get("description") or ""),
            bg=card_bg,
            fg=MUTED,
            font=FONT_SMALL,
            anchor="w",
            justify="left",
            wraplength=175,
        )
        desc_lbl.pack(fill="x", padx=8, pady=(0, 4))
        self._bind_responsive_wrap(desc_lbl, min_wrap=150, pad=18)
        clickable.append(desc_lbl)
        hover_widgets.append(desc_lbl)

        assigned = list(srv.get("assigned_domains") or [])
        if assigned:
            preview_doms = ", ".join(assigned[:3]) + (f" (+{len(assigned) - 3})" if len(assigned) > 3 else "")
            asg_lbl = tk.Label(
                card,
                text=f"Персонально: {preview_doms}",
                bg=OK_BG,
                fg=OK_TEXT,
                font=FONT_MICRO,
                anchor="w",
                justify="left",
                wraplength=175,
                padx=6,
                pady=2,
            )
            asg_lbl.pack(fill="x", padx=8, pady=(0, 4))
            self._bind_responsive_wrap(asg_lbl, min_wrap=150, pad=18)
            clickable.append(asg_lbl)

        meta_row = tk.Frame(card, bg=card_bg)
        meta_row.pack(fill="x", padx=8, pady=(2, 4 if srv.get("badges") else 8))

        ping_val = srv.get("ping_ms")
        alive = srv.get("alive")
        if alive is True and ping_val is not None:
            p_ms = float(ping_val)
            p_color = OK_TEXT if p_ms < 120 else (WARN_TEXT if p_ms < 260 else ERR_TEXT)
            p_text = f"● {p_ms:.0f} мс"
        elif alive is False:
            p_color = MUTED
            p_text = "● нет ответа"
        else:
            p_color = DIM
            p_text = "● не проверен"

        ping_lbl = tk.Label(meta_row, text=p_text, bg=card_bg, fg=p_color, font=FONT_SMALL)
        ping_lbl.pack(side="right", padx=(6, 0))
        ip_lbl = tk.Label(meta_row, text=str(srv.get("ip", "")), bg=card_bg, fg=FG_SOFT, font=FONT_MONO_S, anchor="w")
        ip_lbl.pack(side="left", fill="x", expand=True)
        clickable.extend([meta_row, ip_lbl, ping_lbl])
        hover_widgets.extend([meta_row, ip_lbl, ping_lbl])

        badges_list = list(srv.get("badges") or [])[:3]
        if badges_list:
            badges_row = tk.Frame(card, bg=card_bg)
            badges_row.pack(fill="x", padx=8, pady=(0, 8))
            clickable.append(badges_row)
            hover_widgets.append(badges_row)
            for idx_b, badge in enumerate(badges_list):
                b_str = str(badge)
                if b_str == "блокируется":
                    b_bg, b_fg = ERR_BG, ERR_TEXT
                elif b_str == "под угрозой":
                    b_bg, b_fg = WARN_BG, WARN_TEXT
                elif b_str == "DoH":
                    b_bg, b_fg = INFO_BG, ACCENT
                else:
                    b_bg, b_fg = INPUT, MUTED
                b_lbl = tk.Label(badges_row, text=b_str, bg=b_bg, fg=b_fg, font=FONT_MICRO, padx=5, pady=1)
                b_lbl.pack(side="left", padx=(0 if idx_b == 0 else 3, 0))
                clickable.append(b_lbl)

        if not is_marked:
            self._bind_card_hover(card, hover_widgets, card_bg, hover_bg, border_col, accent_color)

        sid = str(srv["id"])
        for widget in clickable:
            widget.bind("<Button-1>", lambda _e, s_id=sid: self.on_select_dns(s_id))

    # ---------------------------------------------------------------- Live Connections helpers (unified inside tab_domains)

    def _on_conn_context_menu(self, event: Any) -> None:
        iid = self.conn_tree.identify_row(event.y)
        if iid:
            self.conn_tree.selection_set(iid)
            self.on_conn_select()
            proc = str((self.selected_conn or {}).get("process") or "").strip()
            proc_name = Path(proc.replace("\\", "/")).name
            vpn_idx = getattr(self, "_conn_menu_vpn_idx", 4)
            if proc_name and proc_name.lower() not in ("—", "sing-box", "sing-box.exe", "winws2.exe", "winws2", "system"):
                cur_procs = {p.lower() for p in self._vpn_processes}
                in_vpn = proc_name.lower() in cur_procs
                self._conn_menu.entryconfigure(
                    vpn_idx,
                    state="normal",
                    label=f"Убрать {proc_name} из VPN" if in_vpn else f"Направить {proc_name} через VPN",
                )
            else:
                self._conn_menu.entryconfigure(vpn_idx, state="disabled", label="Направить приложение через VPN")
            try:
                self._conn_menu.tk_popup(event.x_root, event.y_root)
            finally:
                self._conn_menu.grab_release()

    def _toggle_selected_conn_process_vpn(self) -> None:
        if not self.selected_conn:
            self.set_status("Выберите соединение в таблице Live-Радара", WARN_TEXT)
            return
        raw_proc = str(self.selected_conn.get("process") or "").strip()
        proc_name = Path(raw_proc.replace("\\", "/")).name
        if not proc_name or proc_name.lower() in ("—", "sing-box", "sing-box.exe", "winws2.exe", "winws2", "system"):
            self.set_status("Этот процесс нельзя направить через VPN", WARN_TEXT)
            return

        def done(res: dict[str, Any]) -> None:
            procs = list(res.get("vpn_processes") or [])
            self._vpn_processes = procs
            verb = "направлен через VPN" if res.get("enabled") else "убран из VPN"
            self.log_console(f"Процесс {proc_name} {verb} (сеть {res.get('network_key', '')}). В VPN: {', '.join(procs) if procs else '(пусто)'}")
            self.set_status(f"Процесс {proc_name} {verb} (sing-box обновлён)", OK_TEXT)
            self._sync_conn_vpn_btn()
            self._after_change()

        self.run_bg(f"VPN для {proc_name}", lambda: self.backend.toggle_vpn_process(proc_name), done)

    def _open_selected_conn_domain(self) -> None:
        if not self.selected_conn:
            return
        dom = normalize_domain(str(self.selected_conn.get("domain") or ""))
        if not dom:
            return
        self.layer_filter_var.set("ALL")
        self.search_var.set(dom)
        self._open_domains_subview("domains")

    def _copy_selected_conn_domain(self) -> None:
        if not self.selected_conn:
            return
        dom = str(self.selected_conn.get("domain") or "").strip()
        if dom and dom != "—":
            self.clipboard_clear()
            self.clipboard_append(dom)
            self.set_status(f"Скопировано в буфер: {dom}", ACCENT)

    def _set_conn_health_filter(self, health: str) -> None:
        self.conn_health_filter = health
        for fid, btn in self._conn_filter_buttons.items():
            self._restyle_button(btn, btn.cget("text"), "pill_active" if fid == health else "neutral")
        self.populate_connections_table(self.live_connections, events=self._last_conn_events)

    # ---------------------------------------------------------------- Tab 5: VPN и журналы

    def _build_vpn_tab(self) -> None:
        build_vpn_tab(self)

    def _build_service_tab(self) -> None:
        build_settings_tab(self)

    def _build_logs_tab(self) -> None:
        build_logs_tab(self)

    # ---------------------------------------------------------------- snapshot / cards / header updates

    def refresh_async(self, *, run_watchdog: bool = False) -> None:
        """Quietly reload the full status snapshot in a background thread (and run winws2 watchdog on ticks)."""
        if self._refreshing or self._closed:
            return
        self._refreshing = True

        def done(payload: tuple[dict[str, Any], dict[str, Any] | None, dict[str, Any] | None]) -> None:
            self._refreshing = False
            snap, wd, vpn_rec = payload
            self.apply_snapshot(snap)
            if isinstance(wd, dict) and wd.get("restarted"):
                cnt = wd.get("restarts_count", 1)
                reason = wd.get("crash_reason") or "внезапное завершение"
                self.log_console(f"[WATCHDOG] winws2.exe автоматически перезапущен (#{cnt}): {reason}")
                self.set_status(f"Watchdog восстановил winws2.exe после сбоя (#{cnt})", WARN_TEXT)
            elif isinstance(wd, dict) and wd.get("fallback_switched_to"):
                fb_id = wd.get("fallback_switched_to")
                self.log_console(f"[WATCHDOG] Автооткат пресета после повторных сбоев -> {fb_id}")
                self.set_status(f"Watchdog откатил пресет на безопасный ({fb_id})", WARN_TEXT)
            elif isinstance(wd, dict) and wd.get("capped"):
                self.log_console(
                    f"[WATCHDOG] winws2.exe падал слишком часто ({wd.get('restarts_count', 0)} раз) — "
                    f"проверьте лог winws2.log: {wd.get('last_crash_reason', '')}"
                )
            if isinstance(vpn_rec, dict):
                act = str(vpn_rec.get("action") or "")
                if act in ("failover", "failover_priority", "failback_priority", "return_to_auto"):
                    self.log_console(
                        f"[VPN] Автопереключение ({act}): {vpn_rec.get('previous') or '—'} -> {vpn_rec.get('selected')}"
                    )
                elif act == "all_unavailable":
                    self.log_console("[VPN] Все настроенные VPN-серверы сейчас недоступны")

        def failed(exc: Exception) -> None:
            self._refreshing = False
            self.set_status(f"Снимок состояния: {exc}", ERR_TEXT)

        def runner() -> None:
            try:
                wd_res: dict[str, Any] | None = None
                vpn_rec: dict[str, Any] | None = None
                if run_watchdog and hasattr(self.backend, "ensure_services_healthy"):
                    try:
                        wd_res = self.backend.ensure_services_healthy()
                    except Exception:  # noqa: BLE001
                        wd_res = None
                if run_watchdog and hasattr(self.backend, "reconcile_vpn_health"):
                    try:
                        vpn_rec = self.backend.reconcile_vpn_health(min_interval_sec=30.0)
                    except Exception:  # noqa: BLE001
                        vpn_rec = None
                snap = self.backend.get_status_snapshot()
            except Exception as exc:  # noqa: BLE001
                self._post(failed, exc)
            else:
                self._post(done, (snap, wd_res, vpn_rec))

        threading.Thread(target=runner, name="gui-snapshot", daemon=True).start()

    def _watchdog_only_async(self) -> None:
        """Lightweight tray-mode watchdog tick skipping full snapshot/UI redraws."""
        if self._refreshing or self._closed or self._exiting or not hasattr(self.backend, "ensure_services_healthy"):
            return
        self._refreshing = True

        def done(wd: dict[str, Any] | None) -> None:
            self._refreshing = False
            if isinstance(wd, dict) and wd.get("restarted"):
                cnt = wd.get("restarts_count", 1)
                self.log_console(f"[WATCHDOG/tray] Перезапуск {', '.join(wd['restarted'])} (#{cnt})")
            elif isinstance(wd, dict) and wd.get("fallback_switched_to"):
                self.log_console(f"[WATCHDOG/tray] Автооткат пресета -> {wd.get('fallback_switched_to')}")

        def runner() -> None:
            try:
                wd = self.backend.ensure_services_healthy()
            except Exception:  # noqa: BLE001
                wd = None
            self._post(done, wd)

        threading.Thread(target=runner, name="gui-watchdog", daemon=True).start()

    def _snapshot_tick(self) -> None:
        if self._closed or self._exiting:
            return
        if self._busy == 0:
            if self._is_window_hidden():
                self._watchdog_only_async()
            else:
                self.refresh_async(run_watchdog=True)
        self._snapshot_job = self.after(self.SNAPSHOT_INTERVAL_MS, self._snapshot_tick)

    def apply_snapshot(self, snap: dict[str, Any]) -> None:
        """Update header, layer cards, preset bar, test pills, domain table, and VPN table from snapshot."""
        self.last_snapshot = snap
        first_load = not self._initial_loaded
        self._initial_loaded = True
        if first_load:
            self._progress_update()
        asn = snap.get("network_asn", 0)
        kind = snap.get("network_kind", "unknown")
        isp = str(snap.get("network_isp") or "")
        net_text = f"Сеть: AS{asn} • {kind}"
        if isp and isp != "unknown":
            isp_short = f"{isp[:14].rstrip()}…" if len(isp) > 16 else isp
            net_text += f" ({isp_short})"
        self.network_label.configure(text=net_text)

        is_admin = bool(snap.get("is_admin"))
        if is_admin:
            self.priv_label.configure(text="ADMIN ✔", bg=OK_BG, fg=OK_TEXT)
            self.priv_btn.pack_forget()
        else:
            self.priv_label.configure(text="Нужны права Admin", bg=WARN_BG, fg=WARN_TEXT)
            if not self.priv_btn.winfo_manager():
                self.priv_btn.pack(side="right", padx=(0, 8))

        ext_bypass = snap["external_bypass_active"] if "external_bypass_active" in snap else snap.get("bypass_active")
        if ext_bypass:
            self.bypass_label.configure(text="⚠ Обнаружен сторонний обход/VPN")
            if not self.bypass_label.winfo_manager():
                self.bypass_label.pack(fill="x", anchor="w", pady=(3, 0))
        else:
            self.bypass_label.configure(text="")
            if self.bypass_label.winfo_manager():
                self.bypass_label.pack_forget()

        dns_alert = snap.get("dns_alert")
        if dns_alert:
            self._home_alert_lbl.configure(text=f"⚠ {dns_alert}")
            if not self._home_alert_frame.winfo_manager():
                self._home_alert_frame.pack(fill="x", padx=16, pady=(0, 5), before=self._home_section1_lbl)
        elif self._home_alert_frame.winfo_manager():
            self._home_alert_frame.pack_forget()

        if "active_preset_id" in snap:
            self.active_preset_id = str(snap.get("active_preset_id") or "auto")
            self.active_preset_name = str(snap.get("active_preset_name") or "Авто-оркестратор (подбор по доменам)")
            self.base_preset_id = str(snap.get("base_preset_id") or "")
            self.base_preset_name = str(snap.get("base_preset_name") or "")
            self._sync_active_preset_indicators()
        if "zapret_presets_count" in snap:
            self._update_nav_badge(self.tab_presets, str(snap.get("zapret_presets_count") or 0))

        processes = snap.get("processes") or {}
        for key, (canvas, oval, lbl) in self.leds.items():
            running = bool((processes.get(key) or {}).get("running"))
            canvas.itemconfigure(oval, fill=OK if running else ERR)
            lbl.configure(fg=FG if running else MUTED)

        stack_running = bool(snap.get("running"))
        pending = snap.get("pending_changes") or {}
        p_cnt = int(pending.get("count") or 0)
        if p_cnt > 0:
            self._restyle_button(self.apply_pending_btn, f"Применить ({p_cnt})", "warn")
            if not self.apply_pending_btn.winfo_manager():
                self.apply_pending_btn.pack(side="right", padx=(0, 8))
        elif self.apply_pending_btn.winfo_manager():
            self.apply_pending_btn.pack_forget()

        preset_locked = self.active_preset_id != "auto"
        wd = snap.get("watchdog") or {}
        wd_cnt = int(wd.get("restarts_count") or 0)
        wd_note = f"  •  Перезапусков модуля: {wd_cnt}" if wd_cnt > 0 else ""

        if stack_running:
            if self._power_transition is None:
                self._restyle_button(self.autopilot_btn, "ОТКЛЮЧИТЬ ЗАЩИТУ  ⏻", "hero_active")
            self.hero_state_pill.configure(text="● ЗАЩИТА АКТИВНА", bg=OK_BG, fg=OK_TEXT)
            self._home_zapret_pill.configure(text="● ПОДКЛЮЧЕНО", bg=OK_BG, fg=OK_TEXT)
            self._home_zapret_card.configure(highlightbackground=CYAN_BORDER)
            if preset_locked:
                self.hint_label.configure(
                    text=f"Активен пресет «{self.active_preset_name}» — защита работает.{wd_note}",
                    fg=OK_TEXT,
                )
            elif self.radar_enabled:
                self.hint_label.configure(
                    text=f"Защита активна + Монитор включён — правила подбираются автоматически.{wd_note}",
                    fg=OK_TEXT,
                )
            else:
                self.hint_label.configure(
                    text=f"Защита активна. Монитор на паузе — можете включить его на вкладке «Монитор».{wd_note}",
                    fg=ACCENT,
                )
        else:
            if self._power_transition is None:
                self._restyle_button(self.autopilot_btn, "ВКЛЮЧИТЬ ЗАЩИТУ  ⏻", "hero")
            self.hero_state_pill.configure(text="● ОСТАНОВЛЕНО", bg=INPUT, fg=MUTED)
            self._home_zapret_pill.configure(text="● ОТКЛЮЧЕНО", bg=INPUT, fg=MUTED)
            self._home_zapret_card.configure(highlightbackground=BORDER)
            if is_admin:
                self.hint_label.configure(
                    text="Выберите стратегию обхода и нажмите «ВКЛЮЧИТЬ ЗАЩИТУ».",
                    fg=MUTED,
                )
            else:
                self.hint_label.configure(
                    text="Нажмите «Права Admin» вверху или «ВКЛЮЧИТЬ ЗАЩИТУ» для запуска.",
                    fg=WARN_TEXT,
                )

        vpn_or_tg_up = bool((processes.get("sing-box") or {}).get("running")) or bool(
            (processes.get("tg-ws-proxy") or {}).get("running")
        )
        if vpn_or_tg_up:
            self._home_vpn_state_pill.configure(text="● ПОДКЛЮЧЕНО", bg=OK_BG, fg=OK_TEXT)
            self._home_vpn_card.configure(highlightbackground=CYAN_BORDER)
        else:
            self._home_vpn_state_pill.configure(text="● РЕЗЕРВ", bg=INPUT, fg=MUTED)
            self._home_vpn_card.configure(highlightbackground=BORDER)

        if "game_filter" in snap:
            self.game_filter_var.set(bool(snap["game_filter"]))
        if "auto_start_protection" in snap:
            self.autostart_protection_var.set(bool(snap["auto_start_protection"]))
        if "auto_heal_enabled" in snap and hasattr(self, "auto_heal_var"):
            self.auto_heal_var.set(bool(snap["auto_heal_enabled"]))
        if "vpn_processes" in snap:
            self._vpn_processes = parse_process_list(str(snap.get("vpn_processes") or ""))
            self._sync_conn_vpn_btn()
        if "base_dns" in snap:
            prev_base_id = (
                str(self._base_dns.get("id") or "")
                if isinstance(self._base_dns, dict)
                else ""
            )
            self._base_dns = snap.get("base_dns")
            new_base_id = (
                str(self._base_dns.get("id") or "")
                if isinstance(self._base_dns, dict)
                else ""
            )
            if new_base_id != prev_base_id and self.dns_catalog:
                self.render_dns_grid(self.dns_catalog, self.active_dns_id)
        if "byedpi_fallback" in snap:
            self.byedpi_var.set(bool(snap["byedpi_fallback"]))
        if "winws2_debug_log" in snap:
            self.debug_log_var.set(bool(snap["winws2_debug_log"]))
        if "stack_mode" in snap:
            dpi_only = str(snap["stack_mode"]) == "dpi_only"
            self.dpi_only_var.set(dpi_only)
            if hasattr(self, "home_stack_mode_var"):
                self._stack_mode_syncing = True
                try:
                    self.home_stack_mode_var.set(self._stack_mode_labels[1 if dpi_only else 0])
                finally:
                    self._stack_mode_syncing = False
        if "tun_stack" in snap and str(snap["tun_stack"]) in ("gvisor", "mixed", "system"):
            self.tun_stack_var.set(str(snap["tun_stack"]))
        if "expert_mode" in snap and bool(snap["expert_mode"]) != self._expert_mode:
            self.set_expert_mode(bool(snap["expert_mode"]), persist=False)
        tg_mode = str(snap.get("telegram_mode") or "mtproto")
        sync_telegram_mode_ui(self, tg_mode)
        if hasattr(self, "_home_tg_val"):
            tg_proxy = snap.get("telegram_proxy") or {}
            if tg_mode == "mtproto":
                tg_up = bool(tg_proxy.get("running"))
                self._home_tg_val.configure(
                    text="MTProto WS-прокси активен" if tg_up else "MTProto WS-прокси (включится со стартом)",
                    fg=OK_TEXT if tg_up else FG,
                )
            else:
                self._home_tg_val.configure(text="Прозрачный режим (через сеть)", fg=ACCENT)

        bundles_data = snap.get("bundles")
        if isinstance(bundles_data, dict):
            render_bundles_subview(self, bundles_data)
            b_items = list(bundles_data.get("bundles") or [])
            vpn_cnt = sum(1 for x in b_items if str(x.get("mode")) == "vpn")
            dpi_cnt = sum(1 for x in b_items if str(x.get("mode")) == "direct_dpi")
            run_cnt = sum(1 for x in b_items if x.get("running"))
            if hasattr(self, "_home_apps_summary"):
                self._home_apps_summary.configure(
                    text=f"Игры и программы: активно {run_cnt}  •  DPI: {dpi_cnt}  •  VPN: {vpn_cnt}"
                )
            if hasattr(self, "home_fix_bundle_cb") and hasattr(self, "_home_fix_bundle_map"):
                sorted_b = sorted(b_items, key=lambda x: (0 if x.get("running") else 1, str(x.get("name") or "").lower()))
                cb_vals: list[str] = []
                cb_map: dict[str, str] = {}
                for b_it in sorted_b:
                    bid = str(b_it.get("id") or "")
                    bname = str(b_it.get("name") or bid)
                    lbl = f"● {bname}" if b_it.get("running") else bname
                    cb_vals.append(lbl)
                    cb_map[lbl] = bid
                    cb_map[bname.lower()] = bid
                    cb_map[bid.lower()] = bid
                self._home_fix_bundle_map = cb_map
                try:
                    self.home_fix_bundle_cb.configure(values=cb_vals)
                    if not self.home_fix_bundle_var.get().strip() and cb_vals:
                        self.home_fix_bundle_var.set(cb_vals[0])
                except tk.TclError:
                    pass
            alerts_list = list(bundles_data.get("alerts") or snap.get("pending_bundle_alerts") or [])
            if hasattr(self, "_home_bundle_alert_frame"):
                for w in self._home_bundle_alert_btns.winfo_children():
                    w.destroy()
                if alerts_list:
                    al0 = alerts_list[0]
                    al_name = str(al0.get("bundle_name") or al0.get("process") or "Приложение")
                    al_id = str(al0.get("bundle_id") or "")
                    al_proc = str(al0.get("process") or "")
                    self._home_bundle_alert_lbl.configure(
                        text=f"У {al_name} проблемы со связью — подобрать другой маршрут?"
                    )
                    if al_id or al_proc:
                        self.make_button(
                            self._home_bundle_alert_btns,
                            "Подобрать маршрут",
                            lambda bid=al_id, pn=al_proc: self.on_escalate_bundle_alert(bid, pn),
                            "warn",
                            font=FONT_MICRO,
                            padx=8,
                            pady=2,
                        ).pack(side="left", padx=(0, 4))
                    self.make_button(
                        self._home_bundle_alert_btns,
                        "Скрыть",
                        lambda key=(al_id or al_proc): self.on_dismiss_bundle_alert(key),
                        "neutral",
                        font=FONT_MICRO,
                        padx=7,
                        pady=2,
                    ).pack(side="left")
                    if not self._home_bundle_alert_frame.winfo_manager():
                        self._home_bundle_alert_frame.pack(
                            fill="x", padx=18, pady=(6, 0), before=self._home_section1_lbl
                        )
                elif self._home_bundle_alert_frame.winfo_manager():
                    self._home_bundle_alert_frame.pack_forget()
            self._update_nav_badge(self.tab_home, f"!{len(alerts_list)}" if alerts_list else "")
            for al in alerts_list:
                al_key = str(al.get("bundle_id") or al.get("process") or "")
                al_name = str(al.get("bundle_name") or al.get("process") or "Приложение")
                if al_key and al_key not in self._notified_bundle_alerts:
                    self._notified_bundle_alerts.add(al_key)
                    if self._tray is not None:
                        self._tray.notify_bundle_issue(
                            al_name,
                            on_click=lambda: self._post(self._open_apps_from_tray),
                        )

        if hasattr(self, "_onboarding_frame"):
            need_onboard = (
                snap.get("network_profile") is None
                and not stack_running
                and not self._onboarding_dismissed
            )
            if need_onboard:
                if not self._onboarding_frame.winfo_manager():
                    self._onboarding_frame.pack(fill="x", padx=18, pady=(10, 0), before=self._home_section1_lbl)
            elif self._onboarding_frame.winfo_manager():
                self._onboarding_frame.pack_forget()
        preset_err = str(snap.get("preset_compile_error") or "")
        if preset_err:
            if preset_err != self._last_preset_err_shown:
                self._last_preset_err_shown = preset_err
                self.log_console(f"[ERROR] {preset_err}")
                self.set_status(preset_err, ERR_TEXT)
        else:
            self._last_preset_err_shown = ""
        if self._tray is not None:
            state_txt = "Защита ВКЛ" if stack_running else "Остановлен"
            self._tray.update_tooltip(f"netdoctor — {state_txt} (AS{asn})")
            self._tray.set_icon_state("active" if stack_running else "idle")

        guard = snap.get("unlocker_guard")
        if isinstance(guard, dict):
            enabled = bool(guard.get("enabled", True))
            self.unlocker_guard_var.set(enabled)
            uc_entry = getattr(self, "unlocker_custom_entry", None)
            try:
                uc_focused = uc_entry is not None and self.focus_get() is uc_entry
            except tk.TclError:
                uc_focused = False
            if not uc_focused:
                self.unlocker_custom_var.set(str(guard.get("custom_exclusions") or ""))
            self._unlocker_custom_synced = True
            if enabled:
                self.unlocker_status_label.configure(
                    text=(
                        f"Защита Antigravity Unlocker и hosts: АКТИВНА "
                        f"(исключено {guard.get('hosts_domains_count', 0)} доменов из hosts и "
                        f"{guard.get('hosts_proxy_ips_count', 0)} прокси-IP)"
                    ),
                    fg=OK_TEXT,
                )
            else:
                self.unlocker_status_label.configure(
                    text="⚠ Защита сторонних анлокеров и hosts отключена пользователем",
                    fg=WARN_TEXT,
                )

        if "active_dns_id" in snap and snap["active_dns_id"] != self.active_dns_id:
            self.active_dns_id = str(snap["active_dns_id"])
            if self.dns_catalog:
                self.render_dns_grid(self.dns_catalog, self.active_dns_id)

        if isinstance(snap.get("test_summary"), dict):
            self._update_test_summary_ui(snap["test_summary"])

        if "orchestrators" in snap and isinstance(snap["orchestrators"], dict):
            self.update_layer_cards(snap["orchestrators"])

        if isinstance(snap.get("vpn_policy"), dict):
            self._vpn_policy = dict(snap["vpn_policy"])
            self._sync_vpn_mode_combo()

        self.populate_domain_table(snap.get("domain_rows") or [])
        self.populate_vpn_table(snap.get("vpn_nodes") or [])

    def _sync_active_preset_indicators(self) -> None:
        is_preset = self.active_preset_id != "auto"
        short_name = (
            self.active_preset_name[:34] + "…" if len(self.active_preset_name) > 36 else self.active_preset_name
        )
        if is_preset:
            self.home_preset_mode_pill.configure(text=f"🔒 Пресет: {short_name}", bg=OK_BG, fg=OK_TEXT)
            self.presets_active_lbl.configure(
                text=f"Активный пресет: {self.active_preset_name}  (оркестратор не перебирает правила)",
                fg=OK_TEXT,
            )
        else:
            self.home_preset_mode_pill.configure(text="● Авто-оркестратор", bg=INFO_BG, fg=ACCENT)
            if self.base_preset_name:
                self.presets_active_lbl.configure(
                    text=f"Активный режим: Автоподбор (база: {self.base_preset_name})",
                    fg=ACCENT,
                )
            else:
                self.presets_active_lbl.configure(
                    text="Активный режим: Авто-оркестратор (подбор по доменам)",
                    fg=ACCENT,
                )
        if self.active_preset_id in self._home_preset_id_to_label:
            self._preset_cb_syncing = True
            try:
                self.home_preset_var.set(self._home_preset_id_to_label[self.active_preset_id])
            finally:
                self._preset_cb_syncing = False
        elif not is_preset:
            self._preset_cb_syncing = True
            try:
                self.home_preset_var.set("Авто-оркестратор (подбор по доменам)")
            finally:
                self._preset_cb_syncing = False

    def _update_test_summary_ui(self, summary: dict[str, Any]) -> None:
        by_srv = summary.get("by_service") or {}
        labels = {"youtube": "YouTube", "discord": "Discord", "telegram": "Telegram"}
        for key, title in labels.items():
            pill = self._home_service_pills.get(key)
            if pill is None:
                continue
            info = by_srv.get(key)
            if not info:
                pill.configure(text=f"● {title}: —", bg=INPUT, fg=MUTED)
            else:
                rate = info.get("success_rate")
                rate_s = f"{rate:.0f}%" if rate is not None else "—"
                if info.get("ok"):
                    pill.configure(text=f"✔ {title}: {rate_s}", bg=OK_BG, fg=OK_TEXT)
                elif info.get("partial"):
                    pill.configure(text=f"◐ {title}: {rate_s}", bg=WARN_BG, fg=WARN_TEXT)
                else:
                    pill.configure(text=f"✖ {title}: {rate_s}", bg=ERR_BG, fg=ERR_TEXT)

        overall = summary.get("overall_success_rate")
        tested = int(summary.get("tested_domains") or 0)
        passing = int(summary.get("passing_domains") or 0)
        if overall is None or tested == 0:
            self.home_test_rate_pill.configure(text="Успех: —", bg=INFO_BG, fg=ACCENT)
            rate_str = "—"
        else:
            rate_str = f"{overall:.0f}% ({passing}/{tested})"
            if overall >= 80.0:
                self.home_test_rate_pill.configure(text=f"Успех: {rate_str}", bg=OK_BG, fg=OK_TEXT)
            elif overall >= 40.0:
                self.home_test_rate_pill.configure(text=f"Успех: {rate_str}", bg=WARN_BG, fg=WARN_TEXT)
            else:
                self.home_test_rate_pill.configure(text=f"Успех: {rate_str}", bg=ERR_BG, fg=ERR_TEXT)

        self._domains_test_summary_lbl.configure(
            text=(
                f"Успех тестов: {rate_str}  •  Подобрано: {len(self.all_rows)}  •  "
                f"Живых сокетов: {len(self.live_connections)}"
            )
        )

    def update_layer_cards(self, orch: dict[str, Any]) -> None:
        dns = orch.get("dns") or {}
        rtt_txt = f" ({dns['best_rtt_ms']} мс)" if dns.get("best_rtt_ms") is not None else ""
        dns_name = dns.get("best_name") or ""
        dns_ip = dns.get("best_server", "1.1.1.1")
        dns_label = f"{dns_name} • {dns_ip}" if dns_name and dns_name != dns_ip else dns_ip
        self.card_dns_val.configure(
            text=f"Общий: {dns_label}{rtt_txt}",
            fg=OK_TEXT if dns.get("status") == "ok" else WARN_TEXT,
        )
        active_dns_snap = self.last_snapshot.get("active_dns") or {}
        if str(active_dns_snap.get("category") or "").strip().lower() == "ai_bypass":
            base = self._base_dns or self.last_snapshot.get("base_dns")
            base_short = str(base.get("name") or base.get("id") or "Авто/Лок.") if isinstance(base, dict) else "Авто/Лок."
            self.card_dns_sub.configure(text=f"Сплит: ИИ → SmartDNS • База → {base_short}")
        else:
            self.card_dns_sub.configure(
                text=f"Сайтов под DNS: {dns.get('doh_protected_count', 0)} • подмен: {dns.get('poisoned_count', 0)}"
            )

        dpi = orch.get("dpi") or {}
        dpi_running = bool(dpi.get("running"))
        self.card_dpi_val.configure(
            text=f"{'АКТИВЕН' if dpi_running else 'ОЖИДАНИЕ'} • {dpi.get('domains_count', 0)} сайтов",
            fg=OK_TEXT if dpi_running else ACCENT,
        )
        if self.active_preset_id != "auto":
            short_p = self.active_preset_name[:26] + "…" if len(self.active_preset_name) > 28 else self.active_preset_name
            self.card_dpi_sub.configure(text=f"Пресет: {short_p}")
        else:
            top_s = dpi.get("top_strategy") or "не выбрана"
            self.card_dpi_sub.configure(text=f"Основная: {top_s}")

        vpn = orch.get("vpn") or {}
        vpn_running = bool(vpn.get("running"))
        alive_txt = (
            f"{vpn.get('alive_count')}/{vpn.get('total_count', 0)} живых"
            if vpn.get("alive_count") is not None
            else f"Узлов: {vpn.get('total_count', 0)}"
        )
        ping_txt = f" ({vpn['best_ping_ms']} мс)" if vpn.get("best_ping_ms") is not None else ""
        self.card_vpn_val.configure(
            text=f"{'АКТИВЕН' if vpn_running else 'ГОТОВ'} • {alive_txt}{ping_txt}",
            fg=OK_TEXT if vpn_running else (WARN_TEXT if vpn.get("total_count", 0) else MUTED),
        )
        tg_ok = "✔" if (vpn.get("tg_proxy_running") or vpn.get("tg_proxy_alive")) else "выкл"
        best_n = str(vpn.get("best_node") or "").strip()
        sel_mode = str(vpn.get("selection_mode") or self._vpn_policy.get("mode") or "auto")
        mode_short = "Приор." if sel_mode == "priority" else "Авто"
        best_short = (best_n[:18] + "…") if len(best_n) > 20 else best_n
        node_part = f" • {mode_short}: {best_short}" if best_short else ""
        proc_part = f" • {len(self._vpn_processes)} прил." if self._vpn_processes else ""
        self.card_vpn_sub.configure(text=f"Через VPN: {vpn.get('vpn_domains_count', 0)} сайтов{proc_part} • TG-WS: {tg_ok}{node_part}")

        rt = orch.get("realtime") or {}
        needs_fix = int(rt.get("needs_fix_count", 0))
        ts = self.last_snapshot.get("test_summary") or {}
        overall = ts.get("overall_success_rate")
        rate_s = f" • Успех {overall:.0f}%" if overall is not None else ""
        self.card_rt_val.configure(
            text=f"{rt.get('active_connections', 0)} сокетов • {rt.get('apps_count', 0)} прилож.",
            fg=WARN_TEXT if needs_fix > 0 else (OK_TEXT if self.radar_enabled else MUTED),
        )
        self.card_rt_sub.configure(
            text=f"Ждут починки: {needs_fix}{rate_s}"
        )

    # ---------------------------------------------------------------- domains table

    def sort_domains(self, column: str) -> None:
        prev_col, prev_rev = self._sort_state
        self._sort_state = (column, (not prev_rev) if prev_col == column else False)
        for cid, title, _width, _anchor in DOMAIN_COLUMNS:
            arrow = (" ▼" if self._sort_state[1] else " ▲") if cid == column else ""
            self.domain_tree.heading(cid, text=f"{title}{arrow}")
        self.populate_domain_table()

    def _sort_key(self, row: dict[str, Any]) -> Any:
        col = self._sort_state[0]
        if col == "ttfb":
            return float(row.get("ttfb_ms") or row.get("last_test_latency_ms") or 0)
        if col == "success":
            sr = row.get("success_rate")
            return float(sr) if sr is not None else -1.0
        if col == "test":
            lo = row.get("last_test_ok")
            return 2 if lo is True else (1 if lo is False else 0)
        if col == "sockets":
            dom = str(row.get("domain") or "").lower()
            return self._sock_counts.get(dom, 0)
        if col == "updated":
            return str(row.get("updated_at") or "")
        if col == "layer":
            return str(row.get("layer") or "")
        if col == "protocol":
            return str(row.get("protocol") or "")
        if col == "strategy":
            return str(row.get("strategy_id") or "")
        if col == "verdicts":
            return ",".join(row.get("verdicts") or [])
        if col == "fallback":
            return ",".join(row.get("fallback_strategies") or [])
        return (str(row.get("domain") or ""), str(row.get("protocol") or ""))

    def populate_domain_table(self, rows: list[dict[str, Any]] | None = None) -> None:
        """Differentially update the domain Treeview without resetting scroll position."""
        if rows is not None:
            self.all_rows = list(rows)

        # Count live sockets per domain once (O(C) instead of O(D*C)) so Domains table sorts & renders fast
        sock_counts: dict[str, int] = {}
        for c in self.live_connections:
            cdom = str(c.get("domain") or "").lower()
            if cdom and cdom != "—":
                sock_counts[cdom] = sock_counts.get(cdom, 0) + 1
        self._sock_counts = sock_counts

        needle = self.search_var.get()
        layer = self.layer_filter_var.get()
        visible = [r for r in self.all_rows if row_matches(r, needle, layer)]
        visible.sort(key=self._sort_key, reverse=self._sort_state[1])

        prev_selected = row_iid(self.selected_row) if self.selected_row else None
        ordered_iids: list[str] = []
        new_rows_by_iid: dict[str, dict[str, Any]] = {}
        values_by_iid: dict[str, tuple[Any, ...]] = {}
        tags_by_iid: dict[str, tuple[str, ...]] = {}
        for row in visible:
            iid = row_iid(row)
            if iid in new_rows_by_iid:
                continue
            new_rows_by_iid[iid] = row
            ordered_iids.append(iid)

            dom = str(row.get("domain", ""))
            dom_display = f"📌 {dom}" if row.get("pinned") else dom

            last_ok = row.get("last_test_ok")
            last_ms = row.get("last_test_latency_ms")
            if last_ok is True:
                test_txt = f"✔ {float(last_ms):.0f}ms" if last_ms is not None else "✔ OK"
            elif last_ok is False:
                test_txt = f"✖ {row.get('last_test_stage') or 'сбой'}"
            else:
                test_txt = "—"

            sr = row.get("success_rate")
            t_tot = int(row.get("test_total") or 0)
            t_pass = int(row.get("test_passed") or 0)
            success_txt = f"{float(sr):.0f}% ({t_pass}/{t_tot})" if (sr is not None and t_tot > 0) else "—"

            scnt = sock_counts.get(dom.lower(), 0)
            sock_txt = f"⚡ {scnt}" if scnt > 0 else "—"

            ping_val = row.get("last_test_latency_ms") if row.get("last_test_latency_ms") is not None else row.get("ttfb_ms")
            values_by_iid[iid] = (
                dom_display,
                str(row.get("protocol", "")).upper(),
                ", ".join(row.get("verdicts") or []) or "—",
                row.get("layer", ""),
                row.get("strategy_id") or "—",
                test_txt,
                success_txt,
                sock_txt,
                ", ".join(row.get("fallback_strategies") or []) or "—",
                _num(ping_val, 0),
                format_updated(row.get("updated_at")),
            )
            tags_by_iid[iid] = (row_tag(row),)

        existing_children = set(self.domain_tree.get_children())
        wanted_set = set(ordered_iids)
        obsolete = [cid for cid in existing_children if cid not in wanted_set]
        if obsolete:
            self.domain_tree.delete(*obsolete)

        for idx, iid in enumerate(ordered_iids):
            if iid in existing_children:
                self.domain_tree.item(iid, values=values_by_iid[iid], tags=tags_by_iid[iid])
                self.domain_tree.move(iid, "", idx)
            else:
                self.domain_tree.insert("", idx, iid=iid, values=values_by_iid[iid], tags=tags_by_iid[iid])

        self.rows_by_iid = new_rows_by_iid
        if prev_selected and prev_selected in self.rows_by_iid:
            if self.domain_tree.selection() != (prev_selected,):
                self.domain_tree.selection_set(prev_selected)
            self.selected_row = self.rows_by_iid[prev_selected]
            self.show_inspector(self.selected_row, sync_controls=False)
        elif prev_selected:
            self.selected_row = None
            self.show_inspector(None)

        badge_txt = f"{len(self.rows_by_iid)}/{len(self.all_rows)}"
        self.notebook.tab(self.tab_domains, text=f"Монитор и правила ({badge_txt})")
        self._update_nav_badge(self.tab_domains, badge_txt)
        self._restyle_button(
            self._subtab_domains_btn,
            f"Сайты ({len(self.rows_by_iid)})",
            "pill_active" if self._domains_subview_mode == "domains" else "neutral",
        )

    def on_domain_select(self, _event: Any = None) -> None:
        sel = self.domain_tree.selection()
        if not sel:
            return
        row = self.rows_by_iid.get(sel[0])
        if row is None:
            return
        same_row = self.selected_row is not None and row_iid(self.selected_row) == sel[0]
        self.selected_row = row
        # Programmatic re-selection on refresh must not overwrite user's in-progress manual layer/strategy choice
        self.show_inspector(row, sync_controls=not same_row)

    def show_inspector(self, row: dict[str, Any] | None, sync_controls: bool = True) -> None:
        w = self.inspector
        if row is None:
            if self._inspector_sig is not None or not w.get("1.0", "end-1c").strip():
                self._inspector_sig = None
                self.inspector_title.configure(text="Выберите сайт в таблице выше, чтобы увидеть результаты проб")
                w.configure(state="normal")
                w.delete("1.0", "end")
                w.insert(
                    "1.0",
                    "Выберите любой сайт в таблице выше — здесь появятся результаты тестов доступности (%), "
                    "проб DNS/TCP/TLS/QUIC, подобранная стратегия и параметры обхода.\n",
                    "muted",
                )
                w.configure(state="disabled")
            return

        sig = (
            row.get("domain"),
            row.get("protocol"),
            row.get("layer"),
            row.get("strategy_id"),
            bool(row.get("pinned")),
            row.get("success_rate"),
            row.get("test_total"),
            row.get("last_tested_at"),
            tuple(row.get("verdicts") or ()),
            row.get("status"),
            row.get("consecutive_fails"),
            row.get("ttfb_ms"),
            row.get("throughput_kbps"),
            tuple(row.get("fallback_strategies") or ()),
            repr(row.get("probes") or {}),
        )
        if not sync_controls and sig == self._inspector_sig:
            return
        self._inspector_sig = sig

        try:
            prev_y = w.yview()[0] if not sync_controls else 0.0
        except tk.TclError:
            prev_y = 0.0

        w.configure(state="normal")
        w.delete("1.0", "end")

        proto = str(row.get("protocol", "")).upper()
        pin_mark = "  📌 ЗАКРЕПЛЕНО" if row.get("pinned") else ""
        self.inspector_title.configure(text=f"Инспектор: {row.get('domain', '')}  [{proto}]{pin_mark}")
        if hasattr(self, "unpin_btn"):
            self._restyle_button(
                self.unpin_btn,
                "Снять фиксацию" if row.get("pinned") else "Зафиксировать",
                "warn" if row.get("pinned") else "neutral",
            )

        raw_verdicts = list(row.get("verdicts") or [])
        verdict_readable = ", ".join(verdict_human_label(v) for v in raw_verdicts) or "—"
        w.insert("end", "Диагноз:     ", "h")
        w.insert(
            "end",
            f"{verdict_readable}\n",
            "ok" if raw_verdicts == ["ok"] else ("muted" if not raw_verdicts else "warn"),
        )
        w.insert("end", "Слой:        ", "h")
        w.insert("end", f"{row.get('layer', '')}   ")
        w.insert("end", "Статус: ", "h")
        status = str(row.get("status", ""))
        w.insert("end", status, "ok" if status == "active" else "bad")
        w.insert("end", f"   ошибок={row.get('consecutive_fails', 0)}   закреплено={'Да' if row.get('pinned') else 'Нет'}\n")

        # Real connectivity test statistics
        t_tot = int(row.get("test_total") or 0)
        t_pass = int(row.get("test_passed") or 0)
        sr = row.get("success_rate")
        w.insert("end", "\nТесты доступности\n", "h")
        if t_tot > 0 and sr is not None:
            tag = "ok" if float(sr) >= 80.0 else ("warn" if float(sr) >= 40.0 else "bad")
            w.insert("end", f"  Успешность: {float(sr):.0f}% ({t_pass}/{t_tot})", tag)
            if row.get("last_test_latency_ms") is not None:
                w.insert("end", f"   •   последний ответ: {float(row['last_test_latency_ms']):.0f} мс")
            if row.get("last_test_error"):
                w.insert("end", f"\n  Последняя ошибка: {row['last_test_error']}", "bad")
            w.insert("end", "\n")
            for rt in (row.get("recent_tests") or [])[:3]:
                mark = "✔" if rt.get("ok") else "✖"
                ms_s = f"{float(rt['latency_ms']):.0f}ms" if rt.get("latency_ms") is not None else rt.get("stage", "")
                w.insert(
                    "end",
                    f"    {mark} {format_updated(rt.get('tested_at'))}  [{rt.get('stage') or 'https'}]  {ms_s}\n",
                    "ok" if rt.get("ok") else "bad",
                )
        else:
            w.insert("end", "  (ещё не тестировался — нажмите «▶ Тест»)\n", "muted")

        w.insert("end", "\nРезультаты сетевых проб\n", "h")
        probe_lines = format_probe_lines(row.get("probes") or {})
        if not probe_lines:
            w.insert("end", "  (нет данных — запустите диагностику)\n", "muted")
        for label, text, status_tag in probe_lines:
            icon = "✔" if status_tag == "ok" else ("✖" if status_tag == "bad" else "—")
            w.insert("end", f"  {icon} {label:<7}", "h")
            w.insert("end", f"{text}\n", status_tag)

        w.insert("end", "\nСтратегия\n", "h")
        w.insert("end", f"  {row.get('strategy_id') or '—'}")
        if row.get("tier") is not None:
            w.insert("end", f"   (уровень {row['tier']})", "muted")
        w.insert("end", "\n")
        if row.get("strategy_description"):
            w.insert("end", f"  {row['strategy_description']}\n", "muted")
        fallback = row.get("fallback_strategies") or []
        if fallback:
            w.insert("end", "  Запасные: ", "h")
            w.insert("end", ", ".join(fallback) + "\n")
        args = row.get("strategy_args") or []
        if args:
            w.insert("end", "\nАргументы winws2\n", "h")
            for arg in args:
                w.insert("end", f"  {arg}\n", "args")
        w.configure(state="disabled")
        if not sync_controls and prev_y > 0.0:
            try:
                w.yview_moveto(prev_y)
            except tk.TclError:
                pass

        if sync_controls:
            layer = str(row.get("layer") or "dpi")
            self.override_layer_var.set(layer)
            self._override_layer_hint_lbl.configure(text=OVERRIDE_LAYER_HINTS.get(layer.lower(), ""))
            self._refresh_strategy_choices(str(row.get("protocol", "")))
            self.override_strategy_var.set(row.get("strategy_id") or "")

    def _on_override_layer_changed(self) -> None:
        layer = (self.override_layer_var.get() or "dpi").lower()
        self._override_layer_hint_lbl.configure(text=OVERRIDE_LAYER_HINTS.get(layer, ""))
        proto = str(self.selected_row.get("protocol", "")) if self.selected_row else ""
        self._refresh_strategy_choices(proto)

    def _refresh_strategy_choices(self, protocol: str = "") -> None:
        layer = (self.override_layer_var.get() or "dpi").lower()
        if layer == "dns":
            dns_ids = [f"dns:{s['id']}" for s in self.dns_catalog if s.get("id")]
            self.override_strategy_cb.configure(values=["", "doh", *dns_ids])
            return
        if layer == "vpn":
            self.override_strategy_cb.configure(values=["vpn-select", "vpn-ai", "byedpi-out", ""])
            return
        if layer == "direct":
            self.override_strategy_cb.configure(values=[""])
            return
        ids = [
            str(s.get("id"))
            for s in self.catalog
            if not protocol or str(s.get("protocol", "")).lower() == protocol.lower()
        ]
        self.override_strategy_cb.configure(values=[""] + ids)

    # ---------------------------------------------------------------- real-time radar tab

    def populate_connections_table(
        self,
        connections: list[dict[str, Any]],
        events: list[dict[str, Any]] | None = None,
    ) -> None:
        """Differentially update Live Connections table without jumping scroll position."""
        self.live_connections = list(connections)
        if events is not None:
            self._last_conn_events = list(events)
        prev_selected = conn_iid(self.selected_conn) if self.selected_conn else None

        total = len(connections)
        protected_cnt = sum(1 for c in connections if str(c.get("health") or "") == "protected")
        needs_fix_cnt = sum(1 for c in connections if str(c.get("health") or "") == "needs_fix")
        direct_cnt = max(0, total - protected_cnt - needs_fix_cnt)
        vpn_proc_note = f"  •  В VPN: {len(self._vpn_processes)} прил." if self._vpn_processes else ""
        self._rt_summary_lbl.configure(
            text=(
                f"Всего: {total}  •  Под защитой: {protected_cnt}  •  "
                f"Требуют обхода: {needs_fix_cnt}  •  Напрямую: {direct_cnt}{vpn_proc_note}"
            ),
            fg=WARN_TEXT if needs_fix_cnt > 0 else FG_SOFT,
        )
        if hasattr(self, "_rt_metric_total"):
            self._rt_metric_total.configure(text=str(total))
            self._rt_metric_prot.configure(text=str(protected_cnt))
            self._rt_metric_fix.configure(text=str(needs_fix_cnt), fg=WARN_TEXT if needs_fix_cnt > 0 else LAVENDER)
        if hasattr(self, "sparkline_canvas"):
            self.sparkline_canvas.push_sample(total, protected_cnt)

        health_labels = {
            "needs_fix": "⚠ Нужна починка",
            "protected": "✔ Под защитой",
            "direct": "● Напрямую",
        }
        ordered_iids: list[str] = []
        new_conns_by_iid: dict[str, dict[str, Any]] = {}
        values_by_iid: dict[str, tuple[Any, ...]] = {}
        tags_by_iid: dict[str, tuple[str, ...]] = {}
        for c in connections:
            health = str(c.get("health") or "direct")
            if self.conn_health_filter != "ALL" and health != self.conn_health_filter:
                continue
            iid = conn_iid(c)
            if iid in new_conns_by_iid:
                continue
            new_conns_by_iid[iid] = c
            ordered_iids.append(iid)
            if str(c.get("layer")) == "unlocker":
                badge_text = "🛡 Анлокер / hosts"
            else:
                badge_text = health_labels.get(health, health)
            values_by_iid[iid] = (
                c.get("process", ""),
                c.get("domain", "—"),
                c.get("remote", ""),
                str(c.get("protocol", "")).upper(),
                c.get("socket_status", ""),
                c.get("layer", "direct"),
                c.get("strategy_id") or "—",
                badge_text,
            )
            tags_by_iid[iid] = (health if health in ("protected", "needs_fix", "direct") else "direct",)

        existing_children = set(self.conn_tree.get_children())
        wanted_set = set(ordered_iids)
        obsolete = [cid for cid in existing_children if cid not in wanted_set]
        if obsolete:
            self.conn_tree.delete(*obsolete)

        for idx, iid in enumerate(ordered_iids):
            if iid in existing_children:
                self.conn_tree.item(iid, values=values_by_iid[iid], tags=tags_by_iid[iid])
                self.conn_tree.move(iid, "", idx)
            else:
                self.conn_tree.insert("", idx, iid=iid, values=values_by_iid[iid], tags=tags_by_iid[iid])

        self.conns_by_iid = new_conns_by_iid
        if prev_selected and prev_selected in self.conns_by_iid:
            self.conn_tree.selection_set(prev_selected)
            self.selected_conn = self.conns_by_iid[prev_selected]

        self._restyle_button(
            self._subtab_conns_btn,
            f"Активные подключения ({len(self.conns_by_iid)})",
            "pill_active" if self._domains_subview_mode == "connections" else "neutral",
        )
        new_sock_counts: dict[str, int] = {}
        for c in connections:
            cdom = str(c.get("domain") or "").lower()
            if cdom and cdom != "—":
                new_sock_counts[cdom] = new_sock_counts.get(cdom, 0) + 1
        if self.all_rows and new_sock_counts != self._sock_counts:
            self.populate_domain_table()
        if isinstance(self.last_snapshot.get("test_summary"), dict):
            self._update_test_summary_ui(self.last_snapshot["test_summary"])

        if events is not None:
            w = self.realtime_feed
            w.configure(state="normal")
            w.delete("1.0", "end")
            if not events:
                w.insert("1.0", "(ожидание событий реального времени…)", "muted")
            else:
                for ev in events:
                    stamp = f"[{ev.get('timestamp', '')}] "
                    body = f"{ev.get('process', '')} • {ev.get('domain', '')}: {ev.get('action', '')}\n"
                    w.insert("end", stamp, "muted")
                    w.insert("end", body, "ok")
            w.configure(state="disabled")

    def _sync_conn_vpn_btn(self) -> None:
        if not hasattr(self, "conn_vpn_btn"):
            return
        proc = str((self.selected_conn or {}).get("process") or "").strip()
        proc_name = Path(proc.replace("\\", "/")).name
        cur_low = {p.lower() for p in self._vpn_processes}
        in_vpn = bool(proc_name and proc_name.lower() in cur_low)
        self._restyle_button(
            self.conn_vpn_btn,
            "Убрать из VPN" if in_vpn else "Через VPN",
            "warn" if in_vpn else "cyan_ghost",
        )

    def on_conn_select(self, _event: Any = None) -> None:
        sel = self.conn_tree.selection()
        if sel:
            self.selected_conn = self.conns_by_iid.get(sel[0])
        self._sync_conn_vpn_btn()

    def refresh_realtime_async(self, auto_heal: bool = False) -> None:
        if self._rt_busy or self._closed:
            return
        self._rt_busy = True

        def done(res: dict[str, Any]) -> None:
            self._rt_busy = False
            conns = res.get("connections") or []
            events = res.get("events") or []
            self.populate_connections_table(conns, events)
            healed = res.get("healed") or []
            deferred = res.get("reload_deferred") or []
            if healed:
                names = ", ".join(f"{h['domain']}→{h.get('strategy_id') or h['layer']}" for h in healed)
                self.log_console(f"Live-Радар автоподбор: {names}")
                self.set_status(f"Live-Радар подобрал: {names}", OK_TEXT)
                if deferred:
                    self.log_console(
                        f"Перезапуск {', '.join(deferred)} отложен — есть активные рабочие соединения"
                    )
                self.refresh_async()

        def failed(_exc: Exception) -> None:
            self._rt_busy = False

        def runner() -> None:
            try:
                if auto_heal:
                    res = self.backend.run_realtime_auto_heal_tick(max_domains_per_tick=3, require_running=True)
                else:
                    res = self.backend.scan_live_connections()
            except Exception as exc:  # noqa: BLE001
                self._post(failed, exc)
            else:
                self._post(done, res)

        threading.Thread(target=runner, name="gui-realtime", daemon=True).start()

    def _realtime_tick(self) -> None:
        if self._closed or self._exiting:
            return
        hidden = self._is_window_hidden()
        stack_running = bool(self.last_snapshot.get("running"))
        can_auto_heal = bool(self.auto_heal_var.get()) and stack_running
        should_scan = (not hidden) or (self.active_preset_id == "auto" and can_auto_heal)
        if self.radar_enabled and self._busy == 0 and should_scan:
            self.refresh_realtime_async(auto_heal=can_auto_heal)
        self._realtime_job = self.after(self.REALTIME_INTERVAL_MS, self._realtime_tick)

    def on_toggle_radar(self) -> None:
        self.radar_enabled = not self.radar_enabled
        if self.radar_enabled:
            self._restyle_button(self.radar_btn, "⏹ Остановить мониторинг", "danger")
            self.refresh_realtime_async(
                auto_heal=bool(self.auto_heal_var.get()) and bool(self.last_snapshot.get("running"))
            )
        else:
            self._restyle_button(self.radar_btn, "▶ Запустить мониторинг", "cyan_ghost")
        if self.last_snapshot:
            self.apply_snapshot(self.last_snapshot)

    def on_toggle_auto_heal(self) -> None:
        enabled = bool(self.auto_heal_var.get())

        def runner() -> None:
            try:
                if hasattr(self.backend, "set_auto_heal_enabled"):
                    self.backend.set_auto_heal_enabled(enabled)
            except Exception:  # noqa: BLE001
                return

        threading.Thread(target=runner, name="gui-autoheal-save", daemon=True).start()

    def on_heal_selected_connection(self) -> None:
        if not self.selected_conn:
            self.set_status("Выберите соединение в таблице Live-Радара", WARN_TEXT)
            return
        domain = str(self.selected_conn.get("domain") or "")
        if not domain or domain == "—":
            self.set_status(
                f"У IP {self.selected_conn.get('remote_ip')} не определено доменное имя — добавьте сайт на вкладке «Сайты»",
                WARN_TEXT,
            )
            return
        self._diag_domains([domain], f"Автоподбор для {domain}")

    # ---------------------------------------------------------------- service / config helpers

    def refresh_previews_async(self) -> None:
        def runner() -> None:
            try:
                previews = self.backend.read_config_preview()
            except Exception as exc:  # noqa: BLE001
                previews = {"error": f"[не удалось прочитать конфиги: {exc}]"}
            self._post(self.set_previews, previews)

        threading.Thread(target=runner, name="gui-preview", daemon=True).start()

    def set_previews(self, previews: dict[str, str]) -> None:
        self.config_previews = previews
        names = list(previews.keys())
        self.file_cb.configure(values=names)
        if names:
            if self.file_var.get() not in previews:
                self.file_var.set(names[0])
            self.show_selected_file()
        else:
            self.file_var.set("")
            self._set_text(self.preview, "(конфиги ещё не сгенерированы — нажмите «Включить защиту»)")

    def show_selected_file(self) -> None:
        self._set_text(self.preview, self.config_previews.get(self.file_var.get(), ""))

    def load_catalog_async(self) -> None:
        def done(catalog: list[dict[str, Any]]) -> None:
            self.catalog = catalog
            proto = str(self.selected_row.get("protocol", "")) if self.selected_row else ""
            self._refresh_strategy_choices(proto)

        def runner() -> None:
            try:
                catalog = self.backend.get_strategies_catalog()
            except Exception:  # noqa: BLE001
                return
            self._post(done, catalog)

        threading.Thread(target=runner, name="gui-catalog", daemon=True).start()

    def _iface(self) -> int | None:
        raw = self.iface_var.get().strip()
        if not raw:
            return None
        try:
            return int(raw)
        except ValueError:
            raise ValueError(f"ifIndex должен быть числом, получено: {raw!r}") from None

    def _after_change(self) -> None:
        self.refresh_async()
        self.refresh_previews_async()

    # ---------------------------------------------------------------- VPN / logs tab

    def _sync_vpn_mode_combo(self) -> None:
        if not hasattr(self, "vpn_mode_var"):
            return
        self._vpn_mode_syncing = True
        try:
            mode = str(self._vpn_policy.get("mode") or "auto")
            self.vpn_mode_var.set(VPN_MODE_PRIORITY_LABEL if mode == "priority" else VPN_MODE_AUTO_LABEL)
        finally:
            self._vpn_mode_syncing = False

    def _active_vpn_node_from_snap(self) -> str:
        vpn_orch = (self.last_snapshot.get("orchestrators") or {}).get("vpn") or {}
        return str(vpn_orch.get("best_node") or "").strip()

    def _selected_vpn_node(self) -> dict[str, Any] | None:
        sel = self.vpn_tree.selection() if hasattr(self, "vpn_tree") else ()
        if not sel:
            return None
        node_row = self._vpn_nodes_by_iid.get(sel[0])
        if isinstance(node_row, dict):
            return node_row
        vals = self.vpn_tree.item(sel[0], "values")
        if vals and len(vals) >= 2:
            raw_name = str(vals[1]).lstrip("▶ ").split(" [⚡", 1)[0].strip()
            for n in self.last_snapshot.get("vpn_nodes") or []:
                if raw_name in (str(n.get("tag") or "").strip(), str(n.get("display_name") or "").strip()):
                    return n
        return None

    def populate_vpn_table(self, nodes: list[dict[str, Any]]) -> None:
        active_vpn_node = self._active_vpn_node_from_snap()
        signature = repr((nodes, self._vpn_policy, active_vpn_node))
        if signature == self._vpn_signature:
            return
        self._vpn_signature = signature
        prev_node = self._selected_vpn_node()
        prev_sel_tag = str(prev_node.get("tag") or "").strip() if isinstance(prev_node, dict) else ""

        self.vpn_tree.delete(*self.vpn_tree.get_children())
        self._vpn_nodes_by_iid = {}

        mode = str(self._vpn_policy.get("mode") or "auto")
        pref_tag = str(self._vpn_policy.get("priority_node") or "").strip()
        alive_cnt = 0
        real_cnt = 0
        ph_cnt = 0
        restore_iid: str | None = None

        for i, node in enumerate(nodes):
            iid = f"n{i}"
            self._vpn_nodes_by_iid[iid] = node
            tag_str = str(node.get("tag") or "").strip()
            if prev_sel_tag and tag_str == prev_sel_tag:
                restore_iid = iid

            is_ph = bool(node["is_placeholder"]) if "is_placeholder" in node else is_placeholder_node(node)
            is_builtin_auto = bool(node["is_builtin_auto"]) if "is_builtin_auto" in node else is_auto_select_node(node)
            enabled = bool(node.get("enabled", True))
            try:
                prio = int(node.get("priority") if node.get("priority") is not None else 100)
            except (TypeError, ValueError):
                prio = 100

            if is_ph:
                ph_cnt += 1
                prio_txt = "—"
            else:
                real_cnt += 1
                if (pref_tag and tag_str == pref_tag) or prio == 1:
                    prio_txt = "★ #1"
                elif prio < 100:
                    prio_txt = f"#{prio}"
                elif mode == "priority":
                    prio_txt = "Резерв"
                else:
                    prio_txt = "Авто"

            is_active = bool(node.get("is_active") or (active_vpn_node and tag_str == active_vpn_node))
            shown = str(node.get("display_name") or tag_str).strip()
            if is_active:
                shown = f"▶ {shown}"
            if is_builtin_auto and not is_ph:
                shown = f"{shown} [⚡ Авто-VPN]"

            endpoint = f"{node.get('server', '')}:{node.get('server_port', '')}"
            if "ping_ms" in node and node.get("ping_ms") is not None:
                suffix = "✔ (туннель)" if node.get("tunnel_verified") else "✔"
                endpoint += f"  •  {node['ping_ms']} ms {suffix}"
            elif node.get("alive") is False and not is_ph:
                endpoint += f"  •  {node.get('probe_result') or 'таймаут'} ✖"

            cb_state = str(node.get("cb_state") or "closed")
            proto_ok = node.get("protocol_ok", True)
            if is_ph:
                health_txt = "ℹ Служебный (не сервер)"
                row_tag = "muted"
            elif not enabled:
                health_txt = "⏸ Отключён"
                row_tag = "muted"
            elif cb_state == "open":
                health_txt = "🔴 Карантин (block)" if not proto_ok else "🔴 Карантин"
                row_tag = "bad"
            elif cb_state == "half_open":
                health_txt = "🟡 Проверка восстановления"
                row_tag = "warn"
            elif node.get("alive") is False:
                health_txt = "🟠 Сбой (недоступен)"
                row_tag = "warn"
            elif node.get("alive"):
                health_txt = "🟢 Активен" if is_active else "🟢 Доступен"
                row_tag = "ok"
                alive_cnt += 1
            else:
                health_txt = "🟢 Активен" if is_active else "● Готов"
                row_tag = "ok"

            self.vpn_tree.insert(
                "",
                "end",
                iid=iid,
                values=(
                    prio_txt,
                    shown,
                    str(node.get("region") or "other").upper(),
                    node.get("protocol", ""),
                    node.get("transport", "tcp"),
                    endpoint,
                    health_txt,
                ),
                tags=(row_tag,),
            )

        if restore_iid:
            self.vpn_tree.selection_set(restore_iid)

        mode_lbl = (
            f"Приоритет ({pref_tag})"
            if (mode == "priority" and pref_tag)
            else ("Приоритетный" if mode == "priority" else "Автовыбор (внутри VPN)")
        )
        active_lbl = f" • Активен: {active_vpn_node}" if active_vpn_node else ""
        alive_lbl = f", доступных: {alive_cnt}" if alive_cnt else ""
        ph_lbl = f", служебных: {ph_cnt}" if ph_cnt else ""
        self._vpn_summary_lbl.configure(
            text=f"Режим: {mode_lbl}{active_lbl} • Серверов: {real_cnt}{alive_lbl}{ph_lbl}"
        )
        self._sync_vpn_mode_combo()
        self._update_nav_badge(self.tab_vpn, str(len(nodes)))

    def refresh_logs_async(self) -> None:
        if self._log_refreshing or self._closed:
            return
        self._log_refreshing = True
        name = self.log_var.get()

        def runner() -> None:
            try:
                logs = self.backend.read_logs_tail(max_lines=200)
            except Exception as exc:  # noqa: BLE001
                logs = {name: f"[не удалось прочитать лог: {exc}]"}
            self._post(self._apply_log, name, logs.get(name, ""))

        threading.Thread(target=runner, name="gui-logs", daemon=True).start()

    def _apply_log(self, name: str, text: str) -> None:
        self._log_refreshing = False
        if name != self.log_var.get():
            return
        clean = strip_ansi(text) if text else ""
        shown = clean or f"(лог {name} пуст или не найден)"

        alert = detect_log_alert(name, shown)
        if alert:
            self._log_alert_lbl.configure(text=alert)
            if not self._log_alert_bar.winfo_manager():
                self._log_alert_bar.pack(fill="x", pady=(0, 6), before=self.log_view.master)
        elif self._log_alert_bar.winfo_manager():
            self._log_alert_bar.pack_forget()

        if self.log_view.get("1.0", "end-1c") != shown:
            at_bottom = self.log_view.yview()[1] >= 0.99
            w = self.log_view
            w.configure(state="normal")
            w.delete("1.0", "end")
            if not clean:
                w.insert("1.0", shown, "muted")
            else:
                for line in shown.splitlines(keepends=True):
                    low = line.lower()
                    if "error" in low or "fatal" in low or "failed" in low:
                        tag = "err"
                    elif "warn" in low:
                        tag = "warn"
                    else:
                        tag = "info"
                    w.insert("end", line, tag)
            w.configure(state="disabled")
            if at_bottom:
                self.log_view.see("end")

    def _log_tick(self) -> None:
        if self._closed or self._exiting:
            return
        try:
            on_logs_tab = self.notebook.select() == str(self.tab_logs)
        except tk.TclError:
            on_logs_tab = False
        if on_logs_tab and not self._is_window_hidden():
            self.refresh_logs_async()
        self._log_job = self.after(self.LOG_INTERVAL_MS, self._log_tick)

    # ---------------------------------------------------------------- actions

    def on_toggle_autopilot(self) -> None:
        if bool(self.last_snapshot.get("running")):
            self.on_stop()
        else:
            self.on_start()

    def on_start(self) -> None:
        try:
            iface = self._iface()
        except ValueError as exc:
            self.set_status(str(exc), ERR_TEXT)
            return

        self._power_transition = "starting"
        if hasattr(self, "autopilot_btn"):
            self._restyle_button(self.autopilot_btn, "⠋ ЗАПУСК ЗАЩИТЫ…", "hero_active")
        self._progress_update()

        def _restore_power_btn(active: bool) -> None:
            self._power_transition = None
            if hasattr(self, "autopilot_btn"):
                if active:
                    self._restyle_button(self.autopilot_btn, "ОТКЛЮЧИТЬ ЗАЩИТУ  ⏻", "hero_active")
                else:
                    self._restyle_button(self.autopilot_btn, "ВКЛЮЧИТЬ ЗАЩИТУ  ⏻", "hero")

        def done(res: dict[str, Any]) -> None:
            _restore_power_btn(bool(res.get("ok")))
            self.log_console(dumps_pretty(res))
            if res.get("live_connections") is not None:
                self.populate_connections_table(res["live_connections"])
            if res.get("orchestrators"):
                self.update_layer_cards(res["orchestrators"])
            if res.get("ok"):
                self.radar_enabled = True
                self._restyle_button(self.radar_btn, "⏹ Остановить мониторинг", "danger")
                self.set_status("Защита запущена: " + ", ".join(res.get("services", [])), OK_TEXT)
            elif res.get("requires_admin"):
                self.set_status("Конфиги готовы! Нужны права Admin (UAC) для запуска служб", WARN_TEXT)
                if not self._is_window_hidden() and messagebox.askyesno(
                    "netdoctor",
                    "Стратегии подобраны и конфиги готовы.\n"
                    "Для запуска winws2 и sing-box TUN нужны права администратора.\n\n"
                    "Перезапустить программу от Admin?",
                ):
                    self.on_elevate()
            else:
                self.set_status(f"Ошибка запуска: {res.get('error', 'неизвестная ошибка')}", ERR_TEXT)
            self._after_change()

        def on_err(_exc: Exception) -> None:
            _restore_power_btn(bool(self.last_snapshot.get("running")))

        self.run_bg("Запуск защиты (Автопилот)", lambda: self.backend.start_autopilot(iface=iface), done, on_err=on_err)

    def on_stop(self) -> None:
        self._power_transition = "stopping"
        if hasattr(self, "autopilot_btn"):
            self._restyle_button(self.autopilot_btn, "⠋ ОСТАНОВКА…", "hero")
        self._progress_update()

        def done(stopped: list[str]) -> None:
            self._power_transition = None
            if hasattr(self, "autopilot_btn"):
                self._restyle_button(self.autopilot_btn, "ВКЛЮЧИТЬ ЗАЩИТУ  ⏻", "hero")
            self.log_console("Остановлено: " + (", ".join(stopped) if stopped else "ничего не запущено"))
            self._after_change()

        def on_err(_exc: Exception) -> None:
            self._power_transition = None
            if hasattr(self, "autopilot_btn"):
                running = bool(self.last_snapshot.get("running"))
                self._restyle_button(
                    self.autopilot_btn,
                    "ОТКЛЮЧИТЬ ЗАЩИТУ  ⏻" if running else "ВКЛЮЧИТЬ ЗАЩИТУ  ⏻",
                    "hero_active" if running else "hero",
                )

        self.run_bg("Остановка защиты", self.backend.stop_services, done, on_err=on_err)

    def on_check_layers(self) -> None:
        def done(orch: dict[str, Any]) -> None:
            self.update_layer_cards(orch)
            self.log_console("Оркестраторы слоёв:\n" + dumps_pretty(orch))
            if orch.get("vpn", {}).get("nodes"):
                self.populate_vpn_table(orch["vpn"]["nodes"])
            self.refresh_async()

        self.run_bg("Замер задержки всех слоёв", lambda: self.backend.get_orchestrators_summary(probe_live=True), done)

    def on_ping_vpn_nodes(self) -> None:
        def done(nodes: list[dict[str, Any]]) -> None:
            self.populate_vpn_table(nodes)
            alive = sum(1 for n in nodes if n.get("alive"))
            self.log_console(f"Пинг VPN узлов: {alive}/{len(nodes)} доступны")
            self.refresh_async()

        self.run_bg("Проверка пинга VPN узлов", self.backend.probe_all_vpn_nodes, done)

    def on_generate(self) -> None:
        try:
            iface = self._iface()
        except ValueError as exc:
            self.set_status(str(exc), ERR_TEXT)
            return

        def done(res: dict[str, Any]) -> None:
            self.log_console(
                f"Конфиги собраны: {res.get('winws2_preset')} | {res.get('singbox_config')} | "
                f"hostlists={res.get('hostlists_count')}"
            )
            self._after_change()

        self.run_bg("Сборка конфигов", lambda: self.backend.trigger_apply_configs(iface=iface), done)

    def on_reload(self) -> None:
        try:
            iface = self._iface()
        except ValueError as exc:
            self.set_status(str(exc), ERR_TEXT)
            return

        def done(res: dict[str, Any]) -> None:
            self.log_console(dumps_pretty(res))
            if res.get("ok"):
                self.set_status("winws2 перезагружен", OK_TEXT)
            elif res.get("requires_admin"):
                self.set_status("Нужны права администратора (UAC)", WARN_TEXT)
            else:
                self.set_status(f"Hot-reload: {res.get('error', 'ошибка')}", ERR_TEXT)
            self._after_change()

        self.run_bg("Hot-reload winws2", lambda: self.backend.reload_winws2(iface=iface), done)

    def on_force_apply_pending(self) -> None:
        try:
            iface = self._iface()
        except ValueError as exc:
            self.set_status(str(exc), ERR_TEXT)
            return

        def done(res: dict[str, Any]) -> None:
            reloaded = res.get("reloaded") or []
            vpn_sw = res.get("vpn_switched")
            parts: list[str] = []
            if reloaded:
                parts.append(f"перезагружено: {', '.join(reloaded)}")
            if vpn_sw:
                parts.append(f"VPN -> {vpn_sw}")
            summary = "; ".join(parts) if parts else "конфиги обновлены"
            self.log_console(f"[APPLY] Новые правила принудительно применены ({summary})")
            self.set_status(f"Правила применены ({summary})", OK_TEXT)
            self._after_change()

        self.run_bg("Применение новых правил", lambda: self.backend.force_apply_pending_changes(iface=iface), done)

    def _format_deps_status(self, res: dict[str, Any]) -> None:
        if res.get("fetch_error"):
            self.set_status(f"Ошибка скачивания компонентов: {res['fetch_error']}", ERR_TEXT)
        elif res.get("ok"):
            if res.get("downloaded"):
                self.set_status("Недостающие компоненты скачаны и проверены", OK_TEXT)
            else:
                self.set_status("Все компоненты проверены и готовы к работе", OK_TEXT)
        else:
            self.set_status("Часть компонентов повреждена или отсутствует", WARN_TEXT)

    def _ensure_deps_on_startup(self) -> None:
        manifest = self.backend.bin_dir / "manifest.json"
        has_outdated = hasattr(self.backend, "has_outdated_pinned_bins") and self.backend.has_outdated_pinned_bins()
        has_missing_py = bool(find_missing_python_deps())
        if self.backend.has_core_binaries() and manifest.is_file() and not has_outdated and not has_missing_py:
            return

        def done(res: dict[str, Any]) -> None:
            self.log_console("Автодокачка компонентов:\n" + dumps_pretty(res))
            self._format_deps_status(res)

        self.run_bg("Автодокачка компонентов", self.backend.ensure_deps, done)

    def _apply_update_check_result(self, info: dict[str, Any], *, silent: bool = False) -> None:
        self._last_update_info = dict(info or {})
        cur = str(info.get("current_version") or __version__)
        latest = str(info.get("latest_version") or cur)
        mode_raw = str(info.get("install_mode") or "portable")
        mode_label = "git" if mode_raw == "git" else "ZIP"

        if info.get("ok") and info.get("update_available"):
            self.version_info_label.configure(
                text=f"Версия: v{cur} ({mode_label}) · Доступно обновление v{latest}",
                fg=ACCENT,
            )
            self._restyle_button(self.update_badge_btn, f"↑ v{latest}", "primary")
            if not self.update_badge_btn.winfo_manager():
                self.update_badge_btn.pack(side="right", padx=(0, 8))
            if not self.apply_update_btn.winfo_manager():
                self.apply_update_btn.pack(side="right", padx=(0, 6))
            if not silent:
                self.set_status(f"Доступно обновление netdoctor v{latest}", ACCENT)
            return

        if self.update_badge_btn.winfo_manager():
            self.update_badge_btn.pack_forget()
        if self.apply_update_btn.winfo_manager():
            self.apply_update_btn.pack_forget()

        if info.get("ok"):
            self.version_info_label.configure(
                text=f"Версия: v{cur} ({mode_label}) · Установлена актуальная версия",
                fg=OK_TEXT,
            )
            if not silent:
                self.set_status(f"Установлена актуальная версия netdoctor v{cur}", OK_TEXT)
        else:
            err = str(info.get("error") or "ошибка сети")
            self.version_info_label.configure(
                text=f"Версия: v{cur} ({mode_label}) · Проверка не удалась",
                fg=WARN_TEXT,
            )
            if not silent:
                self.set_status(f"Не удалось проверить обновления: {err}", WARN_TEXT)

    def _check_updates_on_startup(self) -> None:
        if self._closed or self._exiting or not hasattr(self.backend, "check_updates"):
            return

        def runner() -> None:
            try:
                info = self.backend.check_updates(force=False)
            except Exception as exc:  # noqa: BLE001
                info = {"ok": False, "error": str(exc), "current_version": __version__}
            self._post(lambda res: self._apply_update_check_result(res, silent=True), info)

        threading.Thread(target=runner, name="gui-update-check", daemon=True).start()

    def on_check_updates(self) -> None:
        def done(info: dict[str, Any]) -> None:
            self.log_console("Проверка обновлений:\n" + dumps_pretty(info))
            self._apply_update_check_result(info, silent=False)

        self.run_bg("Проверка обновлений", lambda: self.backend.check_updates(force=True), done)

    def on_apply_update(self) -> None:
        info = self._last_update_info or {}
        latest = str(info.get("latest_version") or "").strip()
        mode_raw = str(info.get("install_mode") or "portable")
        mode_label = "git pull" if mode_raw == "git" else "ZIP-архив"
        prompt = (
            f"Обновить netdoctor до версии v{latest} ({mode_label})?\n\n"
            "На время обновления службы обхода будут остановлены, а затем программа перезапустится."
            if latest
            else f"Выполнить обновление netdoctor ({mode_label})?\n\n"
            "На время обновления службы обхода будут остановлены, а затем программа перезапустится."
        )
        if not messagebox.askyesno("Обновление netdoctor", prompt):
            return

        def done(res: dict[str, Any]) -> None:
            self.log_console("Обновление netdoctor:\n" + dumps_pretty(res))
            if not res.get("ok"):
                err = str(res.get("error") or "Неизвестная ошибка")
                self.set_status(f"Ошибка обновления: {err}", ERR_TEXT)
                messagebox.showerror("Ошибка обновления", err)
                return
            detail = str(res.get("detail") or "Обновление установлено")
            self.set_status(f"{detail} — перезапуск…", OK_TEXT)
            restart = self.backend.restart_gui_process()
            if restart.get("ok"):
                if not self._closed:
                    self.after(150, self.on_close)
            else:
                messagebox.showinfo("Обновление завершено", f"{detail}.\nПерезапустите программу вручную.")

        self.run_bg(
            "Обновление netdoctor",
            lambda: self.backend.apply_update(
                download_url=info.get("download_url") or None,
                target_version=latest or None,
            ),
            done,
        )

    def on_verify(self) -> None:
        def done(res: dict[str, Any]) -> None:
            self.log_console("Verify/Fetch Binaries:\n" + dumps_pretty(res))
            self._format_deps_status(res)

        self.run_bg("Проверка и докачка компонентов", self.backend.ensure_deps, done)

    def on_elevate(self) -> None:
        def done(res: dict[str, Any]) -> None:
            if res.get("ok"):
                self.set_status("Запущено окно с правами администратора — закрытие старого окна...", OK_TEXT)
                self.log_console("Запущено окно с правами администратора")
                if not self._closed:
                    self.after(150, self.on_close)
            elif res.get("cancelled"):
                self.set_status("Запрос прав администратора отменён", WARN_TEXT)
                self.log_console("Запрос прав администратора (UAC) отменён пользователем")
            else:
                self.set_status(f"Не удалось запросить UAC: {res.get('error')}", ERR_TEXT)

        self.run_bg("Запрос прав Admin (UAC)", self.backend.elevate_gui, done)

    def on_diag_all(self) -> None:
        def done(rows: list[dict[str, Any]]) -> None:
            self.log_console(f"Диагностика завершена: {len(rows)} записей")
            self.populate_domain_table(rows)
            self._after_change()

        self.run_bg("Проверка базового списка сайтов", lambda: self.backend.run_diag_sync(None), done)

    def on_revalidate(self) -> None:
        def done(summary: dict[str, Any]) -> None:
            self.log_console(
                f"Канарейка: проверено={len(summary.get('checked', []))}, "
                f"promoted={summary.get('promoted')}, expired={summary.get('expired')}"
            )
            self._after_change()

        self.run_bg("Канарейка (проверка решений)", self.backend.trigger_revalidate, done)

    def _diag_domains(self, domains: list[str], label: str) -> None:
        def done(rows: list[dict[str, Any]]) -> None:
            self.populate_domain_table(rows)
            self.log_console(f"{label}: готово ({', '.join(domains)})")
            self._after_change()

        self.run_bg(label, lambda: self.backend.run_diag_sync(domains), done)

    def on_check_new_domain(self) -> None:
        domain = normalize_domain(self.new_domain_var.get())
        if not domain:
            self.set_status("Введите адрес сайта, например discord.com", WARN_TEXT)
            return
        self.new_domain_var.set("")
        self._diag_domains([domain], f"Подбор для {domain}")

    def on_recheck_selected(self) -> None:
        if not self.selected_row:
            self.set_status("Сначала выберите сайт в таблице", WARN_TEXT)
            return
        domain = str(self.selected_row["domain"])
        self._diag_domains([domain], f"Автоподбор для {domain}")

    def on_find_best_bypass_selected(self) -> None:
        if not self.selected_row:
            self.set_status("Сначала выберите сайт в таблице", WARN_TEXT)
            return
        domain = str(self.selected_row["domain"])

        def done(res: dict[str, Any]) -> None:
            rows = res.get("rows")
            if isinstance(rows, list):
                self.populate_domain_table(rows)
            tried = res.get("tried") or []
            tried_s = ", ".join(
                f"{t.get('layer')}/{t.get('strategy_id') or '—'}:{'OK' if t.get('ok') else 'FAIL'}"
                for t in tried
            )
            win = res.get("winner")
            if win:
                ms_s = f" ({float(win['latency_ms']):.0f}ms)" if win.get("latency_ms") is not None else ""
                msg = f"Лучший обход для {domain}: {win['layer']}/{win.get('strategy_id') or '—'}{ms_s}"
                self.log_console(f"{msg} [{tried_s}]")
                self.set_status(msg, OK_TEXT)
            else:
                msg = f"Не удалось пробить {domain} ни одним слоем"
                self.log_console(f"{msg} [{tried_s}]")
                self.set_status(msg, WARN_TEXT)
            self._after_change()

        self.run_bg(
            f"Поиск лучшего обхода для {domain}",
            lambda: self.backend.find_best_bypass_for_domain(domain),
            done,
        )

    def on_pin(self) -> None:
        if not self.selected_row:
            self.set_status("Сначала выберите сайт в таблице", WARN_TEXT)
            return
        domain = str(self.selected_row["domain"])
        protocol = str(self.selected_row["protocol"])
        layer = self.override_layer_var.get() or "dpi"
        strategy = self.override_strategy_var.get().strip() or None
        if layer == "dpi" and strategy is None:
            self.set_status("Для слоя dpi выберите стратегию", WARN_TEXT)
            return

        def done(decision: dict[str, Any]) -> None:
            self.log_console(
                f"Закреплено: {decision.get('domain')} [{decision.get('protocol')}] → "
                f"{decision.get('layer')} / {decision.get('strategy_id') or '—'}"
            )
            self._after_change()

        self.run_bg(
            f"Закрепление {domain}",
            lambda: self.backend.pin_domain_strategy(domain, protocol, layer, strategy),
            done,
        )

    def on_add_subscription(self) -> None:
        value = self.sub_var.get().strip()
        if not value:
            self.set_status("Введите URL подписки или URI узла", WARN_TEXT)
            return

        def done(count: int) -> None:
            self.log_console(f"Подписка добавлена: {count} узлов")
            if count:
                self.sub_var.set("")
            else:
                self.set_status("Узлы не найдены в подписке", WARN_TEXT)
            self._after_change()

        self.run_bg("Добавление подписки", lambda: self.backend.add_vpn_subscription(value), done)

    def on_refresh_subscriptions(self) -> None:
        def done(results: dict[str, int]) -> None:
            self.log_console("Подписки обновлены: " + json.dumps(results, ensure_ascii=False))
            self._after_change()

        self.run_bg("Обновление подписок", self.backend.refresh_vpn_subscriptions, done)

    # ---------------------------------------------------------------- DNS & Preset actions

    def on_select_dns(self, dns_id: str) -> None:
        def done(selected: dict[str, Any]) -> None:
            self.active_dns_id = str(selected.get("id") or dns_id)
            is_smart = str(selected.get("category") or "").strip().lower() == "ai_bypass"
            if not is_smart:
                self._base_dns = selected
            self._dns_signature = ""
            if self.dns_catalog:
                self.render_dns_grid(self.dns_catalog, self.active_dns_id)
            if is_smart:
                base = self._base_dns if isinstance(self._base_dns, dict) and self._base_dns.get("id") else None
                base_lbl = f"{base['name']} ({base['ip']})" if base else "Авто"
                self.log_console(f"SmartDNS (ИИ): {selected.get('name')} ({selected.get('ip')}) • Обычный/VPN DNS: {base_lbl}")
                self.set_status(f"SmartDNS (ИИ): {selected.get('name')} • Обычный/VPN: {base_lbl}", OK_TEXT)
            else:
                self.log_console(f"Основной DNS: {selected.get('name')} ({selected.get('ip')})")
                self.set_status(f"Основной DNS: {selected.get('name')} ({selected.get('ip')})", OK_TEXT)
            self._after_change()

        self.run_bg(f"Выбор DNS ({dns_id})", lambda: self.backend.select_dns_server(dns_id), done)

    def on_ping_dns_catalog(self) -> None:
        cat = None if self.dns_category_filter == "ALL" else self.dns_category_filter

        def done(servers: list[dict[str, Any]]) -> None:
            self._dns_signature = ""
            self.render_dns_grid(servers, self.active_dns_id)
            alive = sum(1 for s in servers if s.get("alive"))
            self.log_console(f"Пинг DNS завершён: {alive} серверов доступны")
            self._after_change()

        self.run_bg("Измерение пинга DNS-серверов", lambda: self.backend.ping_dns_catalog(category=cat), done)

    def on_auto_select_dns(self, category: str) -> None:
        def done(selected: dict[str, Any]) -> None:
            self.load_dns_catalog_async()
            ping = f" ({selected['ping_ms']} мс)" if selected.get("ping_ms") is not None else ""
            self.log_console(f"Выбран лучший общий DNS ({category}): {selected.get('name')} [{selected.get('ip')}]{ping}")
            self.set_status(f"Лучший общий DNS: {selected.get('name')} {selected.get('ip')}{ping}", OK_TEXT)
            self._after_change()

        self.run_bg(f"Выбор лучшего DNS ({category})", lambda: self.backend.auto_select_best_dns(category), done)

    def on_add_custom_dns(self) -> None:
        name = self.custom_dns_name_var.get().strip()
        ip = self.custom_dns_ip_var.get().strip()
        extra = self.custom_dns_desc_var.get().strip()
        doh_url = extra if extra.startswith("https://") else ""
        desc = "" if doh_url else extra

        def done(saved: dict[str, Any]) -> None:
            self.custom_dns_name_var.set("")
            self.custom_dns_ip_var.set("")
            self.custom_dns_desc_var.set("")
            self.active_dns_id = str(saved["id"])
            self.load_dns_catalog_async()
            self.log_console(f"Добавлен свой DNS: {saved.get('name')} ({saved.get('ip')})")
            self._after_change()

        self.run_bg(
            "Добавление своего DNS",
            lambda: self.backend.add_custom_dns(name=name, ip=ip, description=desc, doh_url=doh_url),
            done,
        )

    def on_delete_custom_dns(self, dns_id: str) -> None:
        def done(_ok: bool) -> None:
            self.load_dns_catalog_async()
            self.log_console(f"Удалён свой DNS: {dns_id}")
            self._after_change()

        self.run_bg("Удаление DNS", lambda: self.backend.remove_custom_dns(dns_id), done)

    def on_toggle_game_filter(self) -> None:
        enabled = bool(self.game_filter_var.get())

        def done(res: dict[str, Any]) -> None:
            state = "включён" if res.get("game_filter") else "выключен"
            self.log_console(f"Игровой фильтр (1024-65535 UDP/TCP): {state}")
            self._after_change()

        self.run_bg("Переключение игрового фильтра", lambda: self.backend.set_game_filter(enabled), done)

    def on_flush_dns(self) -> None:
        def done(res: dict[str, Any]) -> None:
            self.log_console(f"DNS-кэш Windows: {res.get('output')}")
            if res.get("ok"):
                self.set_status("DNS-кэш Windows очищен (flushdns)", OK_TEXT)
            else:
                self.set_status(f"Сброс DNS-кэша: {res.get('output')}", WARN_TEXT)

        self.run_bg("Очистка DNS-кэша Windows", self.backend.flush_windows_dns_cache, done)

    def on_cleanup_stale_db(self) -> None:
        def done(res: dict[str, Any]) -> None:
            removed = int(res.get("removed") or 0)
            self.log_console(f"Очистка БД: удалено {removed} устаревших записей, конфиги пересобраны")
            self.set_status(f"БД очищена: удалено {removed} мусорных правил", OK_TEXT)
            self._after_change()

        self.run_bg("Очистка мусорных правил БД", self.backend.cleanup_stale_db_rules, done)

    def _roll_dns_target(self, domain: str) -> None:
        def done(res: dict[str, Any]) -> None:
            srv = res.get("dns_server") or {}
            dec = res.get("decision") or {}
            name = srv.get("name") or res.get("dns_id")
            ip = srv.get("ip") or ""
            self.log_console(f"Ролл DNS для {domain}: {name} ({ip}) | fallback={dec.get('fallback_strategies')}")
            self.set_status(f"Для {domain} подобран персональный DNS: {name} ({ip})", OK_TEXT)
            self.load_dns_catalog_async()
            self._after_change()

        self.run_bg(f"Ролл DNS для {domain}", lambda: self.backend.roll_dns_for_domain_sync(domain), done)

    def on_roll_dns_domain(self) -> None:
        domain = normalize_domain(self.dns_roll_domain_var.get())
        if not domain:
            self.set_status("Введите адрес сайта, например chatgpt.com", WARN_TEXT)
            return
        self.dns_roll_domain_var.set("")
        self._roll_dns_target(domain)

    def on_roll_dns_selected(self) -> None:
        if not self.selected_row:
            self.set_status("Сначала выберите сайт в таблице", WARN_TEXT)
            return
        self._roll_dns_target(str(self.selected_row["domain"]))

    def on_roll_all_ai_dns(self) -> None:
        def done(decisions: list[dict[str, Any]]) -> None:
            summary = ", ".join(f"{d['domain']}→{d.get('strategy_id')}" for d in decisions)
            self.log_console(f"Персональный ролл DNS для ИИ завершён: {summary}")
            self.set_status(f"Персональный DNS подобран для {len(decisions)} ИИ-сервисов", OK_TEXT)
            self.load_dns_catalog_async()
            self._after_change()

        self.run_bg("Ролл DNS для всех нейросетей (ИИ)", self.backend.roll_ai_dns_batch_sync, done)

    def on_roll_base_dns(self) -> None:
        if self.dns_category_filter == "ai_bypass":
            self.on_auto_select_dns("ai_bypass")
            return
        cat = None if self.dns_category_filter in ("ALL", "ai_bypass") else self.dns_category_filter

        def done(res: dict[str, Any]) -> None:
            sel = res.get("selected")
            if sel:
                self._base_dns = sel
                if res.get("mode") != "smartdns_split":
                    self.active_dns_id = str(sel["id"])
                ms = f"{sel['ping_ms']:.0f} мс" if sel.get("ping_ms") is not None else "—"
                if res.get("mode") == "smartdns_split":
                    smart = res.get("active_dns") or {}
                    smart_name = str(smart.get("name") or self.active_dns_id)
                    self.log_console(f"Обычный/VPN DNS: {sel['name']} ({sel['ip']}) [{ms}] • SmartDNS (ИИ): {smart_name}")
                    self.set_status(f"Обычный/VPN DNS: {sel['name']} ({ms}) • ИИ: {smart_name}", OK_TEXT)
                else:
                    self.log_console(f"Основной DNS: {sel['name']} ({sel['ip']}) [{ms}]")
                    self.set_status(f"Основной DNS: {sel['name']} ({sel['ip']}, {ms})", OK_TEXT)
                self._dns_signature = ""
                self.load_dns_catalog_async()
                self._after_change()
            else:
                msg = str(res.get("error") or "Ни один обычный DNS не ответил")
                self.log_console(f"[WARN] Ролл обычного DNS: {msg}")
                self.set_status(msg, WARN_TEXT)

        self.run_bg(
            "Подбор рабочего обычного DNS",
            (lambda: self.backend.roll_base_dns_sync(category=cat)) if cat else self.backend.roll_base_dns_sync,
            done,
        )

    def on_save_unlocker_guard(self) -> None:
        enabled = bool(self.unlocker_guard_var.get())
        raw = self.unlocker_custom_var.get().strip()

        def done(res: dict[str, Any]) -> None:
            g = res.get("guard") or {}
            self.log_console(
                f"Защита анлокеров: {'вкл' if g.get('enabled') else 'выкл'} | "
                f"hosts доменов={g.get('hosts_domains_count', 0)}, прокси-IP={g.get('hosts_proxy_ips_count', 0)}"
            )
            self.set_status("Исключения для анлокеров/hosts сохранены и конфиги пересобраны", OK_TEXT)
            self._after_change()

        self.run_bg("Сохранение исключений анлокеров", lambda: self.backend.set_unlocker_exclusions(raw, enabled=enabled), done)

    def _load_autostart_async(self) -> None:
        def runner() -> None:
            try:
                st = self.backend.get_autostart_status()
            except Exception:  # noqa: BLE001
                return

            def _apply(res: dict[str, Any] = st) -> None:
                self.autostart_var.set(bool(res.get("enabled")))
                if "auto_start_protection" in res:
                    self.autostart_protection_var.set(bool(res.get("auto_start_protection")))

            self._post(_apply)

        threading.Thread(target=runner, name="gui-autostart-chk", daemon=True).start()

    def _maybe_auto_start_protection(self) -> None:
        if self._closed or self._exiting or not _is_admin():
            return
        should_start = self._auto_start_stack or (
            hasattr(self.backend, "get_auto_start_protection") and self.backend.get_auto_start_protection()
        )
        if not should_start:
            return
        if hasattr(self.backend, "_collect_processes_state"):
            try:
                procs = self.backend._collect_processes_state()
                if bool((procs.get("winws2") or {}).get("running")):
                    return
            except Exception:  # noqa: BLE001
                pass
        self.on_start()

    def on_reload_singbox(self) -> None:
        try:
            iface = self._iface()
        except ValueError as exc:
            self.set_status(str(exc), ERR_TEXT)
            return

        def done(res: dict[str, Any]) -> None:
            self.log_console(dumps_pretty(res))
            if res.get("ok"):
                self.set_status("sing-box перезагружен", OK_TEXT)
            elif res.get("requires_admin"):
                self.set_status("Нужны права администратора (UAC)", WARN_TEXT)
            else:
                self.set_status(f"Перезагрузка sing-box: {res.get('error', 'ошибка')}", ERR_TEXT)
            self._after_change()

        self.run_bg("Перезагрузка sing-box", lambda: self.backend.reload_singbox(iface=iface), done)

    def on_rotate_vpn_node(self) -> None:
        target_tag: str | None = None
        sel_node = self._selected_vpn_node()
        if isinstance(sel_node, dict):
            is_ph = bool(sel_node["is_placeholder"]) if "is_placeholder" in sel_node else is_placeholder_node(sel_node)
            if is_ph:
                self.set_status(
                    "Служебная запись не является VPN-сервером — выберите сервер или снимите выделение для авто-ротации",
                    WARN_TEXT,
                )
                return
            if sel_node.get("tag"):
                target_tag = str(sel_node["tag"]).strip()

        def done(res: dict[str, Any]) -> None:
            if res.get("ok"):
                self.log_console(
                    f"VPN ротация: {res.get('previous') or '—'} -> {res.get('selected')} "
                    f"(live={res.get('switched_live')}, closed_conns={res.get('closed_connections')})"
                )
                self.set_status(f"Активный VPN-узел: {res.get('selected')}", OK_TEXT)
            else:
                self.set_status(f"Ротация VPN: {res.get('error', 'не выполнена')}", WARN_TEXT)
            self._after_change()

        self.run_bg("Ротация VPN-узла", lambda: self.backend.rotate_vpn_node(target_tag=target_tag), done)

    def on_vpn_mode_change(self, _event: Any = None) -> None:
        if self._vpn_mode_syncing:
            return
        target_mode = "priority" if self.vpn_mode_var.get() == VPN_MODE_PRIORITY_LABEL else "auto"

        def done(res: dict[str, Any]) -> None:
            pol = res.get("policy") or {}
            self._vpn_policy = dict(pol) if isinstance(pol, dict) else self._vpn_policy
            rec = res.get("reconcile") or {}
            sel = rec.get("selected") or (self._vpn_policy.get("priority_node") if target_mode == "priority" else "vpn-auto")
            lbl = "Приоритетный" if target_mode == "priority" else "Автовыбор (внутри VPN)"
            self.log_console(f"Режим VPN: {lbl} (узел={sel or 'vpn-auto'})")
            self.set_status(f"Режим VPN: {lbl}", OK_TEXT)
            self._after_change()

        self.run_bg("Переключение режима VPN", lambda: self.backend.set_vpn_selection_mode(target_mode), done)

    def on_set_priority_vpn_node(self) -> None:
        node = self._selected_vpn_node()
        if not node or not node.get("tag"):
            self.set_status("Сначала выберите сервер в таблице VPN", WARN_TEXT)
            return
        is_ph = bool(node["is_placeholder"]) if "is_placeholder" in node else is_placeholder_node(node)
        if is_ph:
            self.set_status("Служебную запись нельзя сделать приоритетным сервером", WARN_TEXT)
            return
        tag = str(node["tag"]).strip()

        def done(res: dict[str, Any]) -> None:
            pol = res.get("policy") or {}
            self._vpn_policy = dict(pol) if isinstance(pol, dict) else self._vpn_policy
            rec = res.get("reconcile") or {}
            live_sel = rec.get("selected") or tag
            self.log_console(f"Приоритетный VPN #1: {tag} (активный={live_sel})")
            self.set_status(f"Приоритетный VPN #1: {tag}", OK_TEXT)
            self._after_change()

        self.run_bg(f"Приоритет VPN ({tag})", lambda: self.backend.set_vpn_priority_node(tag), done)

    def on_move_vpn_priority(self, delta: int) -> None:
        node = self._selected_vpn_node()
        if not node or not node.get("tag"):
            self.set_status("Сначала выберите сервер в таблице VPN", WARN_TEXT)
            return
        is_ph = bool(node["is_placeholder"]) if "is_placeholder" in node else is_placeholder_node(node)
        if is_ph:
            self.set_status("Служебная запись не участвует в приоритетах", WARN_TEXT)
            return
        tag = str(node["tag"]).strip()

        def done(res: dict[str, Any]) -> None:
            pol = res.get("policy") or {}
            self._vpn_policy = dict(pol) if isinstance(pol, dict) else self._vpn_policy
            top = res.get("priority_node") or tag
            self.log_console(f"Обновлён приоритет VPN ({tag}) • #1: {top}")
            self.set_status(f"Приоритет VPN обновлён (#1: {top})", OK_TEXT)
            self._after_change()

        self.run_bg("Изменение приоритета VPN", lambda: self.backend.move_vpn_node_priority(tag, delta), done)

    def on_blockcheck2_selected(self) -> None:
        if not self.selected_row:
            self.set_status("Сначала выберите сайт в таблице", WARN_TEXT)
            return
        domain = str(self.selected_row["domain"])

        def done(res: dict[str, Any]) -> None:
            cnt = int(res.get("discovered_count") or 0)
            self.log_console(f"blockcheck2 ({domain}): найдено стратегий = {cnt}")
            if cnt > 0:
                self.load_catalog_async()
                self.set_status(f"blockcheck2 нашёл {cnt} стратегий для {domain}", OK_TEXT)
            else:
                self.set_status(f"blockcheck2 для {domain}: новых стратегий не найдено (требуется Admin)", WARN_TEXT)

        self.run_bg(f"blockcheck2 ({domain})", lambda: self.backend.run_blockcheck2_sync(domain), done)

    def on_toggle_autostart(self) -> None:
        enabled = bool(self.autostart_var.get())

        def done(res: dict[str, Any]) -> None:
            if "auto_start_protection" in res:
                self.autostart_protection_var.set(bool(res.get("auto_start_protection")))
            if res.get("ok"):
                if res.get("enabled"):
                    suffix = " (с автозапуском защиты)" if res.get("auto_start_protection") else " (только приложение)"
                    self.set_status(f"Автозапуск с Windows включён{suffix}", OK_TEXT)
                else:
                    self.set_status("Автозапуск с Windows отключён", OK_TEXT)
            else:
                self.autostart_var.set(bool(res.get("enabled")))
                self.set_status(f"Автозапуск: {res.get('error', 'ошибка настройки')}", WARN_TEXT)

        self.run_bg("Настройка автозапуска Windows", lambda: self.backend.set_autostart(enabled), done)

    def on_toggle_autostart_protection(self) -> None:
        enabled = bool(self.autostart_protection_var.get())

        def done(res: dict[str, Any]) -> None:
            if res.get("ok"):
                state = "включён" if res.get("auto_start_protection") else "выключен"
                self.set_status(f"Автозапуск защиты при старте {state}", OK_TEXT)
            else:
                self.set_status(f"Автозапуск защиты: {res.get('error', 'ошибка')}", WARN_TEXT)
            self._after_change()

        self.run_bg(
            "Настройка автозапуска защиты",
            lambda: self.backend.set_auto_start_protection(enabled),
            done,
        )

    def on_toggle_byedpi(self) -> None:
        enabled = bool(self.byedpi_var.get())

        def done(res: dict[str, Any]) -> None:
            state = "включён" if res.get("byedpi_fallback") else "выключен"
            self.log_console(f"ByeDPI SOCKS5 (ciadpi): {state}")
            self._after_change()

        self.run_bg("Переключение ByeDPI", lambda: self.backend.set_byedpi_fallback(enabled), done)

    def on_toggle_debug_log(self) -> None:
        enabled = bool(self.debug_log_var.get())

        def done(res: dict[str, Any]) -> None:
            state = "включён" if res.get("winws2_debug_log") else "выключен"
            self.log_console(f"Подробный лог winws2 (--debug=1): {state}")
            self._after_change()

        self.run_bg("Переключение лога winws2", lambda: self.backend.set_winws2_debug_log(enabled), done)

    # ---------------------------------------------------------------- Zapret2 Presets & Live Connectivity Tests

    def load_zapret_presets_async(self) -> None:
        def done(data: dict[str, Any]) -> None:
            self.active_preset_id = str(data.get("active_preset_id") or "auto")
            self.active_preset_name = str(data.get("active_preset_name") or "Авто-оркестратор (подбор по доменам)")
            self.base_preset_id = str(data.get("base_preset_id") or "")
            self.base_preset_name = str(data.get("base_preset_name") or "")
            self.populate_presets_table(list(data.get("presets") or []))
            self._sync_active_preset_indicators()

        def runner() -> None:
            try:
                data = self.backend.get_zapret_presets()
            except Exception:  # noqa: BLE001
                return
            self._post(done, data)

        threading.Thread(target=runner, name="gui-presets", daemon=True).start()

    def _set_preset_filter(self, flt: str) -> None:
        self.preset_filter = flt
        for pid, btn in self._preset_filter_buttons.items():
            self._restyle_button(btn, btn.cget("text"), "pill_active" if pid == flt else "neutral")
        self.populate_presets_table()

    def _sync_home_preset_combo(self) -> None:
        auto_label = "Авто-оркестратор (подбор по доменам)"
        label_to_id: dict[str, str] = {auto_label: "auto"}
        id_to_label: dict[str, str] = {"auto": auto_label}
        values: list[str] = [auto_label]
        for p in self.zapret_presets:
            pid = str(p.get("id") or "")
            name = str(p.get("name") or pid)
            prefix = "★ [Мой] " if not p.get("builtin", True) else ("★ " if p.get("featured") else "")
            sr = p.get("success_rate")
            suffix = f" ({float(sr):.0f}%)" if sr is not None else ""
            label = f"{prefix}{name}{suffix}"
            if label in label_to_id:
                label = f"{label} [{pid[:8]}]"
            label_to_id[label] = pid
            id_to_label[pid] = label
            values.append(label)
        self._home_preset_label_to_id = label_to_id
        self._home_preset_id_to_label = id_to_label
        self.home_preset_cb.configure(values=values)
        self._preset_cb_syncing = True
        try:
            if self.active_preset_id in id_to_label:
                self.home_preset_var.set(id_to_label[self.active_preset_id])
            else:
                self.home_preset_var.set(auto_label)
        finally:
            self._preset_cb_syncing = False

    def populate_presets_table(self, presets: list[dict[str, Any]] | None = None) -> None:
        if presets is not None:
            self.zapret_presets = list(presets)
            self._sync_home_preset_combo()

        needle = self.preset_search_var.get().strip().lower() if hasattr(self, "preset_search_var") else ""
        filtered: list[dict[str, Any]] = []
        for p in self.zapret_presets:
            is_user = not bool(p.get("builtin", True))
            if self.preset_filter == "user" and not is_user:
                continue
            if self.preset_filter == "featured" and not (is_user or p.get("featured") or p.get("is_working")):
                continue
            if needle:
                hay = f"{p.get('name', '')} {p.get('description', '')} {p.get('source', '')}".lower()
                if needle not in hay:
                    continue
            filtered.append(p)

        prev_sel = str(self.selected_preset.get("id") or "") if self.selected_preset else ""
        self.presets_tree.delete(*self.presets_tree.get_children())
        new_map: dict[str, dict[str, Any]] = {}
        for p in filtered:
            pid = str(p.get("id") or "")
            if not pid or pid in new_map:
                continue
            new_map[pid] = p
            is_active = pid == self.active_preset_id
            is_base = (not is_active) and bool(self.base_preset_id) and pid == self.base_preset_id
            is_user = not bool(p.get("builtin", True))
            src = "Мой рабочий" if is_user else ("ZDY .bat" if p.get("source") == "builtin_zdy" else "Zapret2")
            if is_active:
                status_txt = "🔒 АКТИВЕН"
                tag = "active"
            elif is_base:
                status_txt = "⚙ База (Авто)"
                tag = "featured"
            elif is_user:
                status_txt = "★ Рабочий" if p.get("is_working") else "Пользователь"
                tag = "user"
            elif p.get("featured"):
                status_txt = "★ Рекоменд."
                tag = "featured"
            else:
                status_txt = "Готов"
                tag = "builtin"
            sr = p.get("success_rate")
            sr_txt = f"{float(sr):.0f}%" if sr is not None else "—"
            self.presets_tree.insert(
                "",
                "end",
                iid=pid,
                values=(
                    str(p.get("name") or pid),
                    src,
                    status_txt,
                    sr_txt,
                    str(p.get("description") or ""),
                ),
                tags=(tag,),
            )

        self.presets_by_iid = new_map
        if prev_sel and prev_sel in self.presets_by_iid:
            self.presets_tree.selection_set(prev_sel)
            self.selected_preset = self.presets_by_iid[prev_sel]
        self._update_nav_badge(self.tab_presets, str(len(self.zapret_presets)))
        self.notebook.tab(self.tab_presets, text=f"Пресеты Zapret ({len(self.zapret_presets)})")

    def on_preset_select(self, _event: Any = None) -> None:
        sel = self.presets_tree.selection()
        if sel:
            self.selected_preset = self.presets_by_iid.get(sel[0])

    def on_apply_home_preset(self) -> None:
        label = self.home_preset_var.get()
        pid = self._home_preset_label_to_id.get(label, "auto")
        self.on_select_zapret_preset(pid)

    def on_select_zapret_preset(self, preset_id: str) -> None:
        def done(res: dict[str, Any]) -> None:
            self.active_preset_id = str(res.get("active_preset_id") or "auto")
            self.active_preset_name = str(res.get("active_preset_name") or "Авто-оркестратор")
            self._sync_active_preset_indicators()
            self.populate_presets_table()
            if self.active_preset_id == "auto":
                self.log_console("Режим Zapret2: Авто-оркестратор (подбор стратегий по доменам)")
                self.set_status("Включён режим Авто-оркестратор", ACCENT)
            else:
                self.log_console(f"Активирован рабочий пресет Zapret2: {self.active_preset_name}")
                self.set_status(f"Активен пресет: {self.active_preset_name} (оркестратор на паузе)", OK_TEXT)
            self._after_change()

        self.run_bg(f"Применение пресета ({preset_id})", lambda: self.backend.select_zapret_preset(preset_id), done)

    def on_activate_selected_preset(self) -> None:
        if not self.selected_preset:
            self.set_status("Выберите пресет в списке выше", WARN_TEXT)
            return
        self.on_select_zapret_preset(str(self.selected_preset["id"]))

    def on_set_base_selected_preset(self) -> None:
        if not self.selected_preset:
            self.set_status("Выберите пресет в списке выше", WARN_TEXT)
            return
        pid = str(self.selected_preset["id"])

        def done(res: dict[str, Any]) -> None:
            self.active_preset_id = str(res.get("active_preset_id") or "auto")
            self.active_preset_name = str(res.get("active_preset_name") or "Авто-оркестратор (подбор по доменам)")
            self.base_preset_id = str(res.get("base_preset_id") or "")
            self.base_preset_name = str(res.get("base_preset_name") or "")
            self._sync_active_preset_indicators()
            self.populate_presets_table()
            self.log_console(f"Установлен базовый пресет для Авто-оркестратора: {self.base_preset_name}")
            self.set_status(f"Автоподбор + база: {self.base_preset_name}", OK_TEXT)
            self._after_change()

        self.run_bg(f"Базовый пресет ({pid})", lambda: self.backend.set_base_zapret_preset(pid), done)

    def on_load_selected_preset_to_editor(self) -> None:
        if not self.selected_preset:
            self.set_status("Выберите пресет в списке выше", WARN_TEXT)
            return
        name = str(self.selected_preset.get("name") or "")
        self.user_preset_name_var.set(f"{name} (мой)" if self.selected_preset.get("builtin", True) else name)
        self.user_preset_desc_var.set(str(self.selected_preset.get("description") or ""))
        self.user_preset_text.delete("1.0", "end")
        self.user_preset_text.insert("1.0", str(self.selected_preset.get("content") or ""))
        self.set_status(f"Загружено в редактор: {name}", ACCENT)

    def on_add_user_preset(self) -> None:
        name = self.user_preset_name_var.get().strip()
        desc = self.user_preset_desc_var.get().strip()
        content = self.user_preset_text.get("1.0", "end-1c").strip()
        activate = bool(self.user_preset_activate_var.get())
        if not name or not content:
            self.set_status("Укажите название и вставьте текст/аргументы пресета", WARN_TEXT)
            return

        def done(res: dict[str, Any]) -> None:
            saved = res.get("preset") or {}
            self.user_preset_name_var.set("")
            self.user_preset_desc_var.set("")
            self.user_preset_text.delete("1.0", "end")
            self.log_console(f"Сохранён пользовательский пресет: {saved.get('name')} (активирован={res.get('activated')})")
            self.set_status(f"Пресет «{saved.get('name')}» сохранён", OK_TEXT)
            self.load_zapret_presets_async()
            self._after_change()

        self.run_bg(
            f"Сохранение пресета {name}",
            lambda: self.backend.add_user_zapret_preset(
                name=name,
                content=content,
                description=desc,
                is_working=True,
                activate=activate,
            ),
            done,
        )

    def on_import_preset_file(self) -> None:
        fpath = filedialog.askopenfilename(
            title="Выберите файл пресета Zapret (.txt или .bat)",
            filetypes=[("Zapret Presets", "*.txt *.bat *.cmd"), ("All files", "*.*")],
        )
        if not fpath:
            return

        def done(res: dict[str, Any]) -> None:
            saved = res.get("preset") or {}
            self.log_console(f"Импортирован пресет из файла: {saved.get('name')}")
            self.set_status(f"Импортирован и активирован пресет: {saved.get('name')}", OK_TEXT)
            self.load_zapret_presets_async()
            self._after_change()

        self.run_bg(
            "Импорт пресета из файла",
            lambda: self.backend.import_zapret_preset_file(fpath, activate=True),
            done,
        )

    def on_import_presets_dir(self) -> None:
        presets_dir = Path.cwd() / "presets" / "zapret2"
        default_dir = str(presets_dir) if presets_dir.is_dir() else str(Path.cwd())
        dpath = filedialog.askdirectory(title="Выберите папку с пресетами Zapret", initialdir=default_dir)
        if not dpath:
            return

        def done(res: dict[str, Any]) -> None:
            cnt = int(res.get("imported_count") or 0)
            self.log_console(f"Импорт из {res.get('dir_path')}: добавлено {cnt} пресетов")
            self.set_status(f"Импортировано пресетов: {cnt}", OK_TEXT if cnt > 0 else WARN_TEXT)
            self.load_zapret_presets_async()

        self.run_bg(
            "Импорт пресетов из папки",
            lambda: self.backend.import_zapret_presets_from_dir(dpath),
            done,
        )

    def on_delete_selected_preset(self) -> None:
        if not self.selected_preset:
            self.set_status("Выберите свой пресет для удаления", WARN_TEXT)
            return
        if self.selected_preset.get("builtin", True):
            self.set_status("Встроенные пресеты Zapret2 нельзя удалить — можно удалить только свои", WARN_TEXT)
            return
        pid = str(self.selected_preset["id"])
        pname = str(self.selected_preset.get("name") or pid)

        def done(res: dict[str, Any]) -> None:
            self.selected_preset = None
            self.log_console(f"Удалён пользовательский пресет: {pname}")
            self.set_status(f"Удалён пресет «{pname}»", OK_TEXT)
            self.load_zapret_presets_async()
            self._after_change()

        self.run_bg(f"Удаление пресета {pname}", lambda: self.backend.delete_zapret_preset(pid), done)

    def on_test_selected_preset(self) -> None:
        pid = str(self.selected_preset["id"]) if self.selected_preset else None
        activate = bool(pid and pid != self.active_preset_id)

        def done(res: dict[str, Any]) -> None:
            passed = int(res.get("passed") or 0)
            total = int(res.get("total") or 0)
            rate = float(res.get("success_rate") or 0.0)
            if isinstance(res.get("summary"), dict):
                self._update_test_summary_ui(res["summary"])
            self.log_console(
                f"Тест пресета ({res.get('active_preset_name')}): {passed}/{total} ({rate:.0f}%)"
            )
            self.set_status(
                f"Тест пресета: {passed}/{total} ({rate:.0f}%)",
                OK_TEXT if rate >= 80 else (WARN_TEXT if rate >= 40 else ERR_TEXT),
            )
            self.load_zapret_presets_async()
            self._after_change()

        self.run_bg(
            "Тест пресета (YT/DC/TG)",
            lambda: self.backend.test_zapret_preset(preset_id=pid, activate_if_needed=activate),
            done,
        )

    def on_run_connectivity_tests(self, include_picked: bool = False) -> None:
        label = "Тест всех подобранных доменов" if include_picked else "Тест сервисов (YouTube / Discord / Telegram)"

        def done(res: dict[str, Any]) -> None:
            passed = int(res.get("passed") or 0)
            total = int(res.get("total") or 0)
            rate = float(res.get("success_rate") or 0.0)
            if isinstance(res.get("summary"), dict):
                self._update_test_summary_ui(res["summary"])
            lines = [
                f"  {'✔' if r.get('ok') else '✖'} {r.get('domain')} "
                f"({r.get('latency_ms')}ms)" if r.get("ok") else f"  ✖ {r.get('domain')} [{r.get('stage')}] {r.get('error', '')}"
                for r in (res.get("results") or [])
            ]
            self.log_console(f"{label}: {passed}/{total} ({rate:.0f}%)\n" + "\n".join(lines))
            self.set_status(
                f"Проверка завершена: {passed}/{total} ({rate:.0f}%)",
                OK_TEXT if rate >= 80 else (WARN_TEXT if rate >= 40 else ERR_TEXT),
            )
            self.load_zapret_presets_async()
            self.refresh_async()

        self.run_bg(
            label,
            lambda: self.backend.run_connectivity_tests(
                include_key_services=True,
                include_picked_domains=include_picked,
            ),
            done,
        )

    def on_auto_tune_all(self) -> None:
        def done(res: dict[str, Any]) -> None:
            reset = res.get("reset") or {}
            cleaned = int(reset.get("stale_removed") or 0) + int(reset.get("failing_removed") or 0)
            vpn_reset = int(reset.get("vpn_reset") or 0)
            base = res.get("base_dns")
            if isinstance(base, dict) and base.get("id"):
                self._base_dns = base
                self._dns_signature = ""
                self.load_dns_catalog_async()
            dns_txt = (
                f"{base.get('name')} ({base['ping_ms']:.0f} мс)"
                if isinstance(base, dict) and base.get("ping_ms") is not None
                else (str(base.get("name")) if isinstance(base, dict) else "—")
            )
            conn = res.get("connectivity")
            if isinstance(conn, dict) and isinstance(conn.get("summary"), dict):
                self._update_test_summary_ui(conn["summary"])
                conn_txt = f"{conn.get('passed', 0)}/{conn.get('total', 0)} ({conn.get('success_rate', 0):.0f}%)"
            else:
                conn_txt = f"{res.get('diagnosed_count', 0)} правил"
            vpn_txt = f"{res.get('vpn_alive', 0)} узлов" + (f" ({res['vpn_best']})" if res.get("vpn_best") else "")
            self.log_console(
                f"Полный автоподбор завершён: очищено={cleaned}, сброс карантина VPN={vpn_reset}, "
                f"DNS={dns_txt}, VPN={vpn_txt}, проверка={conn_txt}"
            )
            self.set_status(f"Автоподбор готов: DNS {dns_txt} • VPN {vpn_txt} • {conn_txt}", OK_TEXT)
            self.load_zapret_presets_async()
            self._after_change()

        self.run_bg("Полный автоподбор (DNS + VPN + сайты)", self.backend.auto_tune_all_sync, done)

    def on_test_selected_domain(self) -> None:
        if not self.selected_row:
            self.set_status("Сначала выберите сайт в таблице", WARN_TEXT)
            return
        dom = str(self.selected_row["domain"])

        def done(res: dict[str, Any]) -> None:
            r0 = (res.get("results") or [{}])[0]
            ok = bool(r0.get("ok"))
            ms = r0.get("latency_ms")
            msg = f"Тест {dom}: {'✔ ДОСТУПЕН' + (f' ({ms:.0f}ms)' if ms is not None else '') if ok else '✖ НЕДОСТУПЕН (' + str(r0.get('stage') or 'err') + ')'}"
            self.log_console(msg)
            self.set_status(msg, OK_TEXT if ok else ERR_TEXT)
            self.refresh_async()

        self.run_bg(
            f"Тест {dom}",
            lambda: self.backend.run_connectivity_tests(domains=[dom], include_key_services=False),
            done,
        )

    def on_toggle_pin_selected(self) -> None:
        if not self.selected_row:
            self.set_status("Сначала выберите сайт в таблице", WARN_TEXT)
            return
        dom = str(self.selected_row["domain"])
        proto = str(self.selected_row["protocol"])
        new_pin = not bool(self.selected_row.get("pinned"))

        def done(res: dict[str, Any]) -> None:
            state = "закреплено (оркестратор не тронет)" if res.get("pinned") else "откреплено"
            self.log_console(f"Правило {dom} [{proto}]: {state}")
            self.set_status(f"Правило {dom}: {state}", OK_TEXT)
            self.refresh_async()

        self.run_bg(
            f"{'Закрепление' if new_pin else 'Открепление'} {dom}",
            lambda: self.backend.set_domain_pinned(dom, proto, new_pin),
            done,
        )

    def on_connect_telegram_proxy(self) -> None:
        """Open tg://proxy?... link to bind Telegram Desktop to local tg-ws-proxy in 1 click and copy backup."""
        cached_tg = self.last_snapshot.get("telegram_proxy") if isinstance(self.last_snapshot, dict) else None
        info = cached_tg if isinstance(cached_tg, dict) and cached_tg.get("url") else self.backend.get_telegram_proxy_info()
        url = str(info["url"])
        try:
            self.clipboard_clear()
            self.clipboard_append(url)
        except tk.TclError:
            pass
        opened = False
        if sys.platform == "win32" and hasattr(os, "startfile"):
            try:
                os.startfile(url)  # type: ignore[attr-defined]
                opened = True
            except OSError:
                opened = False
        if not opened:
            try:
                opened = bool(webbrowser.open(url))
            except Exception:  # noqa: BLE001
                opened = False
        state = "открыто в Telegram Desktop" if opened else "ссылка скопирована в буфер"
        safe_url = re.sub(r"([?&]secret=)[^&\s]+", r"\1***", url)
        self.log_console(f"Telegram MTProto прокси (127.0.0.1:{info['port']}): {state} ({safe_url})")
        self.set_status(
            f"Telegram прокси {state} (127.0.0.1:{info['port']})",
            OK_TEXT if info.get("running") else WARN_TEXT,
        )

    def on_toggle_dpi_only(self) -> None:
        dpi_only = bool(self.dpi_only_var.get())
        mode = "dpi_only" if dpi_only else "hybrid"
        if hasattr(self, "home_stack_mode_var"):
            self._stack_mode_syncing = True
            try:
                self.home_stack_mode_var.set(self._stack_mode_labels[1 if dpi_only else 0])
            finally:
                self._stack_mode_syncing = False

        def done(res: dict[str, Any]) -> None:
            txt = "Без VPN (только обход DPI + TG)" if res.get("stack_mode") == "dpi_only" else "Гибрид (Обход DPI + точечный VPN)"
            self.log_console(f"Режим маршрутизации: {txt}")
            self.set_status(f"Режим маршрутизации: {txt}", OK_TEXT)
            self._after_change()

        self.run_bg("Переключение режима маршрутизации", lambda: self.backend.set_stack_mode(mode), done)

    def on_change_tun_stack(self) -> None:
        stack = (self.tun_stack_var.get() or "mixed").strip()

        def done(res: dict[str, Any]) -> None:
            self.log_console(f"TUN стек sing-box: {res.get('tun_stack')}")
            self.set_status(f"TUN стек sing-box: {res.get('tun_stack')}", OK_TEXT)
            self._after_change()

        self.run_bg(f"Смена TUN стека ({stack})", lambda: self.backend.set_tun_stack(stack), done)

    def _open_apps_from_tray(self) -> None:
        self.show_from_tray()
        self._select_tab(self.tab_home)
        if hasattr(self, "set_home_fix_kind"):
            self.set_home_fix_kind("bundle", focus=True)

    def set_home_fix_kind(self, kind: str, *, focus: bool = False) -> None:
        """Switch the unified Home «Что-то не открывается?» block between `domain` and `bundle`."""
        clean = "bundle" if kind == "bundle" else "domain"
        if hasattr(self, "_home_fix_kind_var"):
            self._home_fix_kind_var.set(clean)
        if hasattr(self, "_home_fix_site_btn"):
            self._restyle_button(
                self._home_fix_site_btn, "Сайт", "pill_active" if clean == "domain" else "neutral"
            )
        if hasattr(self, "_home_fix_app_btn"):
            self._restyle_button(
                self._home_fix_app_btn, "Игра / программа", "pill_active" if clean == "bundle" else "neutral"
            )
        if hasattr(self, "home_fix_domain_entry") and hasattr(self, "_home_fix_bundle_wrap"):
            if clean == "bundle":
                if self.home_fix_domain_entry.winfo_manager():
                    self.home_fix_domain_entry.pack_forget()
                if not self._home_fix_bundle_wrap.winfo_manager():
                    self._home_fix_bundle_wrap.pack(fill="x", expand=True)
                if focus:
                    self.home_fix_bundle_cb.focus_set()
            else:
                if self._home_fix_bundle_wrap.winfo_manager():
                    self._home_fix_bundle_wrap.pack_forget()
                if not self.home_fix_domain_entry.winfo_manager():
                    self.home_fix_domain_entry.pack(fill="x", expand=True, ipady=3)
                if focus:
                    self.home_fix_domain_entry.focus_set()

    def _browse_home_fix_exe(self) -> None:
        chosen = filedialog.askopenfilename(
            title="Выберите .exe игры или программы",
            filetypes=[("Исполняемые файлы (*.exe)", "*.exe"), ("Все файлы (*.*)", "*.*")],
        )
        if chosen:
            exe_name = Path(chosen).name
            if hasattr(self, "home_fix_bundle_var"):
                self.home_fix_bundle_var.set(exe_name)

    def on_home_fix_target(self) -> None:
        """Unified 1-click Home repair handler for a domain (`Сайт`) or bundle/.exe (`Игра / программа`)."""
        kind = self._home_fix_kind_var.get() if hasattr(self, "_home_fix_kind_var") else "domain"
        if kind == "bundle":
            raw = self.home_fix_bundle_var.get().strip() if hasattr(self, "home_fix_bundle_var") else ""
            if not raw:
                self.set_status("Выберите игру/программу или введите имя .exe", WARN_TEXT)
                return
            cmap = getattr(self, "_home_fix_bundle_map", {})
            target = cmap.get(raw) or cmap.get(raw.lstrip("● ").lower()) or raw.lstrip("● ").strip()
            allow_downshift = True
            try:
                cur_bundles = (self.backend.get_bundles_status() or {}).get("bundles") or []
                t_low = target.lower()
                matched_b = next(
                    (
                        b
                        for b in cur_bundles
                        if str(b.get("id") or "").lower() == t_low
                        or str(b.get("name") or "").lower() == t_low
                        or any(str(p).lower() == t_low for p in (b.get("processes") or ()))
                    ),
                    None,
                )
                if matched_b and str(matched_b.get("mode") or "") in ("direct_clean", "direct_dpi"):
                    # Escalate forward past the currently failing direct/dpi mode instead of re-picking it
                    allow_downshift = False
            except Exception:  # noqa: BLE001
                allow_downshift = True
            self.on_find_best_bypass_bundle(target, allow_downshift=allow_downshift)
            return

        raw_dom = self.home_fix_domain_var.get().strip() if hasattr(self, "home_fix_domain_var") else ""
        dom = normalize_domain(raw_dom)
        if not dom or "." not in dom:
            self.set_status("Введите корректный адрес сайта (например youtube.com)", WARN_TEXT)
            return
        if hasattr(self, "home_fix_result_lbl"):
            self.home_fix_result_lbl.configure(text=f"Подбор для {dom}…", fg=ACCENT)

        def done(res: dict[str, Any]) -> None:
            win = res.get("winner")
            if win:
                layer_map = {"direct": "Напрямую", "dpi": "DPI", "dns": "SmartDNS", "vpn": "VPN"}
                layer_txt = layer_map.get(str(win.get("layer") or ""), str(win.get("layer") or ""))
                msg = f"{dom}: {layer_txt}"
                if hasattr(self, "home_fix_result_lbl"):
                    self.home_fix_result_lbl.configure(text=msg, fg=OK_TEXT)
                self.set_status(msg, OK_TEXT)
                self.log_console(f"Подбор для {dom}: {win.get('layer')}/{win.get('strategy_id') or '—'}")
            else:
                msg = f"{dom}: не удалось подобрать обход"
                if hasattr(self, "home_fix_result_lbl"):
                    self.home_fix_result_lbl.configure(text=msg, fg=WARN_TEXT)
                self.set_status(msg, WARN_TEXT)
            self._after_change()

        self.run_bg(f"Подбор для сайта {dom}", lambda: self.backend.find_best_bypass_for_domain(dom), done)

    def on_find_best_bypass_bundle(self, bundle_id_or_exe: str, *, allow_downshift: bool = True) -> None:
        if hasattr(self, "home_fix_result_lbl"):
            self.home_fix_result_lbl.configure(text="Подбираем рабочий маршрут…", fg=ACCENT)

        def done(res: dict[str, Any]) -> None:
            bname = str(res.get("bundle_name") or res.get("bundle_id") or bundle_id_or_exe)
            mode = str(res.get("mode") or "")
            mode_lbl = {"direct_clean": "Напрямую", "direct_dpi": "DPI", "vpn": "VPN"}.get(mode, mode)
            hint = str(res.get("restart_hint") or "")
            if res.get("ok"):
                msg = f"{bname}: {mode_lbl}" + (f" • {hint}" if hint else "")
                if hasattr(self, "home_fix_result_lbl"):
                    self.home_fix_result_lbl.configure(text=msg, fg=OK_TEXT)
                self.set_status(msg, OK_TEXT)
                self.log_console(f"Автоподбор {bname} -> {mode}" + (f" ({hint})" if hint else ""))
            else:
                msg = f"{bname}: не удалось пробить маршрут"
                if hasattr(self, "home_fix_result_lbl"):
                    self.home_fix_result_lbl.configure(text=msg, fg=WARN_TEXT)
                self.set_status(msg, WARN_TEXT)
            self._after_change()

        self.run_bg(
            f"Подбор маршрута ({bundle_id_or_exe})",
            lambda: self.backend.find_best_bypass_for_bundle(bundle_id_or_exe, allow_downshift=allow_downshift),
            done,
        )

    def on_escalate_bundle_alert(self, bundle_id: str, proc_name: str = "") -> None:
        target = bundle_id or proc_name
        if not target:
            return
        self.on_find_best_bypass_bundle(target, allow_downshift=False)

    def on_toggle_bundle_pin(self, bundle_id: str, pinned: bool) -> None:
        def done(ok: bool) -> None:
            if ok:
                self.set_status(
                    f"Профиль {bundle_id}: " + ("режим закреплён 📌" if pinned else "возвращён автоподбор"),
                    OK_TEXT,
                )
            self._after_change()

        self.run_bg(f"Фиксация профиля {bundle_id}", lambda: self.backend.set_bundle_pinned(bundle_id, pinned), done)

    def on_toggle_expert_mode(self) -> None:
        self.set_expert_mode(bool(self.expert_mode_var.get()), persist=True)
        self.set_status(
            "Режим эксперта включён" if self._expert_mode else "Включён базовый режим",
            ACCENT if self._expert_mode else FG_SOFT,
        )

    def on_toggle_theme(self) -> None:
        want_light = hasattr(self, "theme_mode_var") and self.theme_mode_var.get() == "Светлая"
        pal = LIGHT_PALETTE if want_light else DARK_PALETTE
        bg_map = {BG: pal["BG"], CARD: pal["CARD"], PANEL: pal["PANEL"], ELEVATED: pal["ELEVATED"]}
        fg_map = {FG: pal["FG"], FG_SOFT: pal["FG_SOFT"], MUTED: pal["MUTED"]}

        def _repaint(widget: tk.Misc) -> None:
            try:
                cur_bg = str(widget.cget("bg"))
                if cur_bg in bg_map:
                    widget.configure(bg=bg_map[cur_bg])
                elif isinstance(widget, (tk.Frame, tk.Canvas)):
                    widget.configure(bg=pal["CARD"])
            except tk.TclError:
                pass
            try:
                cur_fg = str(widget.cget("fg"))
                if cur_fg in fg_map:
                    widget.configure(fg=fg_map[cur_fg])
            except tk.TclError:
                pass
            for ch in widget.winfo_children():
                _repaint(ch)

        try:
            self.configure(bg=pal["BG"])
            _repaint(self)
        except tk.TclError:
            pass
        self.set_status(f"Тема переключена: {'Светлая' if want_light else 'Тёмная'}", OK_TEXT)

    def on_run_first_calibration(self) -> None:
        def _progress(step: str, detail: str) -> None:
            def _ui() -> None:
                if hasattr(self, "_onboarding_step_lbl"):
                    self._onboarding_step_lbl.configure(text=detail)
                self.set_status(detail, ACCENT)

            self._post(_ui)

        def work() -> dict[str, Any]:
            cal = self.backend.run_calibration_sync(progress_cb=_progress)
            if _is_admin():
                self.backend.start_services(iface=self._iface(), force=True)
            return cal

        def done(cal: dict[str, Any]) -> None:
            dismiss_onboarding(self)
            dns_name = str((cal.get("base_dns") or {}).get("name") or "Авто")
            best_tls = str(cal.get("best_tls_strategy") or "")
            self.log_console(f"Калибровка завершена: DNS={dns_name}, DPI={best_tls}")
            self.set_status(f"Настройка завершена: DNS {dns_name}", OK_TEXT)
            self._after_change()

        self.run_bg("Первичная настройка интернета", work, done)

    def on_set_bundle_mode(self, bundle_id: str, mode: str, *, pinned: bool | None = None) -> None:
        def done(res: dict[str, Any]) -> None:
            warn = str(res.get("udp_warning") or "")
            if warn:
                self.set_status(f"{bundle_id}: {warn}", WARN_TEXT)
                self.log_console(f"[WARN] {bundle_id} -> {mode}: {warn}")
            else:
                self.set_status(f"Профиль {bundle_id} переключён: {mode}", OK_TEXT)
                self.log_console(f"Приложение {bundle_id} -> {mode}")
            self._after_change()

        self.run_bg(
            f"Маршрут приложения ({bundle_id} -> {mode})",
            lambda: self.backend.set_bundle_mode(bundle_id, mode, pinned=pinned),
            done,
        )

    def on_add_custom_bundle(self, name: str, processes: str, mode: str = "vpn") -> None:
        def done(entry: dict[str, Any]) -> None:
            self.set_status(f"Добавлен профиль: {entry.get('name')}", OK_TEXT)
            self._after_change()

        self.run_bg(f"Добавление профиля ({name})", lambda: self.backend.add_custom_bundle(name, processes, mode), done)

    def on_remove_custom_bundle(self, bundle_id: str) -> None:
        def done(ok: bool) -> None:
            if ok:
                self.set_status(f"Профиль {bundle_id} удалён", MUTED)
                self._after_change()

        self.run_bg("Удаление профиля", lambda: self.backend.remove_custom_bundle(bundle_id), done)

    def on_dismiss_bundle_alert(self, key: str) -> None:
        self.backend.dismiss_bundle_alert(key)
        self.refresh_async()

    def on_set_telegram_mode(self, mode: str) -> None:
        sync_telegram_mode_ui(self, mode)

        def done(res: dict[str, Any]) -> None:
            m = res.get("telegram_mode")
            txt = "MTProto WS-прокси" if m == "mtproto" else "Прозрачно через сеть"
            self.set_status(f"Режим Telegram: {txt}", OK_TEXT)
            self.log_console(f"Режим Telegram переключён: {txt}")
            self._after_change()

        self.run_bg(f"Режим Telegram ({mode})", lambda: self.backend.set_telegram_mode(mode), done)

    def on_settings_telegram_mode_selected(self) -> None:
        if not hasattr(self, "settings_tg_mode_var") or not hasattr(self, "_settings_tg_labels"):
            return
        want_mt = self.settings_tg_mode_var.get() == self._settings_tg_labels[0]
        target_mode = "mtproto" if want_mt else "transparent"
        if hasattr(self, "telegram_mode_var") and self.telegram_mode_var.get() == target_mode:
            return
        self.on_set_telegram_mode(target_mode)


# --------------------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------------------


def _ensure_gui_stdio() -> None:
    """Ensure sys.stdout/sys.stderr are writable streams when running under pythonw.exe."""
    for stream_name in ("stdout", "stderr"):
        if getattr(sys, stream_name) is None:
            setattr(sys, stream_name, open(os.devnull, "w", encoding="utf-8", errors="replace"))


def _has_console_window() -> bool:
    """Return True when the current process has an attached Windows console window."""
    if sys.platform != "win32":
        return True
    try:
        return bool(ctypes.windll.kernel32.GetConsoleWindow())
    except Exception:  # noqa: BLE001
        return False


def _resolve_workspace_root(db_path: str | Path = "netdoctor.db") -> Path:
    """Locate the netdoctor project root even when launched from System32 or Explorer."""
    cwd = Path.cwd().resolve()
    if (cwd / "pyproject.toml").is_file() or ((cwd / "bin").is_dir() and (cwd / "configs").is_dir()):
        return cwd
    db_candidate = Path(db_path)
    if db_candidate.is_absolute():
        parent = db_candidate.resolve().parent
        if (parent / "bin").is_dir() or (parent / "presets").is_dir():
            return parent
    parents = Path(__file__).resolve().parents
    if len(parents) > 2:
        repo_root = parents[2]
        if (repo_root / "pyproject.toml").is_file() or (repo_root / "bin").is_dir() or (repo_root / "presets").is_dir():
            return repo_root
    return cwd


def _show_startup_error(message: str, logs_dir: Path) -> None:
    """Record GUI startup errors to logs/gui_startup.log and show MessageBoxW when no console exists."""
    try:
        logs_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with (logs_dir / "gui_startup.log").open("a", encoding="utf-8", errors="replace") as f:
            f.write(f"[{stamp}] {message.rstrip()}\n")
    except OSError:
        pass
    if sys.platform == "win32" and not _has_console_window():
        try:
            ctypes.windll.user32.MessageBoxW(0, message[:1500], "netdoctor", 0x10)
        except Exception:  # noqa: BLE001
            pass
    else:
        try:
            sys.stderr.write(message.rstrip() + "\n")
        except Exception:  # noqa: BLE001
            pass


def _enable_dpi_awareness() -> None:
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        pass
    if sys.platform == "win32":
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("netdoctor.gui")
        except Exception:  # noqa: BLE001
            pass


def launch_gui(
    db_path: str = "netdoctor.db",
    logs_dir: str = "logs",
    configs_dir: str = "configs",
    lists_dir: str = "lists",
    bin_dir: str = "bin",
    headless_check: bool = False,
    minimized: bool = False,
    auto_start_stack: bool = False,
) -> dict[str, Any]:
    """Launch the desktop control panel, or return the status snapshot immediately when headless_check=True."""
    if headless_check:
        return NetdoctorController(
            db_path=db_path,
            configs_dir=configs_dir,
            lists_dir=lists_dir,
            logs_dir=logs_dir,
            bin_dir=bin_dir,
        ).get_status_snapshot()

    _ensure_gui_stdio()
    workspace_root = _resolve_workspace_root(db_path)
    if workspace_root != Path.cwd().resolve():
        os.chdir(workspace_root)

    ctrl = NetdoctorController(
        db_path=db_path,
        configs_dir=configs_dir,
        lists_dir=lists_dir,
        logs_dir=logs_dir,
        bin_dir=bin_dir,
    )

    acquired, mutex_handle = acquire_single_instance_mutex()
    if not acquired:
        return ctrl.get_status_snapshot()

    app: NetdoctorGuiApp | None = None
    _enable_dpi_awareness()
    try:
        app = NetdoctorGuiApp(
            backend=ctrl.backend,
            minimized=minimized,
            auto_start_stack=auto_start_stack,
        )
        app.mainloop()
    finally:
        if app is None or not getattr(app, "_exiting", False):
            try:
                ctrl.backend.stop_services()
            except Exception:
                pass
        release_single_instance_mutex(mutex_handle)
    return ctrl.get_status_snapshot()


def _resolve_arg_path(raw: str, base: Path) -> Path:
    candidate = Path(raw).expanduser()
    return candidate.resolve() if candidate.is_absolute() else (base / candidate).resolve()


def main(argv: list[str] | None = None) -> int:
    """Non-console Windows GUI entry point (`netdoctor-gui.exe`) with automatic UAC elevation."""
    _ensure_gui_stdio()
    parser = argparse.ArgumentParser(prog="netdoctor-gui", description="netdoctor desktop control panel")
    parser.add_argument("--db", default="netdoctor.db", help="Path to SQLite database")
    parser.add_argument("--logs-dir", default="logs", help="Directory for process logs and supervisor state")
    parser.add_argument("--configs-dir", default="configs", help="Directory for generated configs")
    parser.add_argument("--lists-dir", default="lists", help="Directory for winws2 hostlists")
    parser.add_argument("--bin-dir", default="bin", help="Directory containing external binaries")
    parser.add_argument("--headless-check", action="store_true", help="Print GUI controller snapshot JSON and exit")
    parser.add_argument("--minimized", action="store_true", help="Start minimized to system tray")
    parser.add_argument("--auto-start", action="store_true", help="Trigger protection autopilot right after GUI startup")
    parser.add_argument("--replace-pid", type=int, default=None, help="Gracefully stop an older GUI PID")
    parser.add_argument("--no-elevate", action="store_true", help="Skip automatic Administrator UAC prompt")
    args = parser.parse_args(argv)

    if args.headless_check:
        snap = launch_gui(
            db_path=args.db,
            logs_dir=args.logs_dir,
            configs_dir=args.configs_dir,
            lists_dir=args.lists_dir,
            bin_dir=args.bin_dir,
            headless_check=True,
            minimized=args.minimized,
            auto_start_stack=args.auto_start,
        )
        sys.stdout.write(json.dumps(snap, indent=2, ensure_ascii=False) + "\n")
        sys.stdout.flush()
        return 0

    workspace_root = _resolve_workspace_root(args.db)
    if workspace_root != Path.cwd().resolve():
        os.chdir(workspace_root)

    db_resolved = _resolve_arg_path(args.db, workspace_root)
    configs_resolved = _resolve_arg_path(args.configs_dir, workspace_root)
    lists_resolved = _resolve_arg_path(args.lists_dir, workspace_root)
    logs_resolved = _resolve_arg_path(args.logs_dir, workspace_root)
    bin_resolved = _resolve_arg_path(args.bin_dir, workspace_root)

    if sys.platform == "win32" and not args.no_elevate and not _is_admin():
        res = elevate_gui(
            db_path=db_resolved,
            configs_dir=configs_resolved,
            lists_dir=lists_resolved,
            logs_dir=logs_resolved,
            working_dir=workspace_root,
            bin_dir=bin_resolved,
            replace_pid=args.replace_pid,
            auto_start=args.auto_start,
            minimized=args.minimized,
        )
        if res.get("ok") or res.get("cancelled"):
            return 0
        _show_startup_error(
            f"Не удалось запустить netdoctor с правами администратора:\n{res.get('error', 'Unknown error')}",
            logs_resolved,
        )
        return 1

    if args.replace_pid is not None:
        terminate_pid_gracefully(args.replace_pid)

    try:
        launch_gui(
            db_path=str(db_resolved),
            logs_dir=str(logs_resolved),
            configs_dir=str(configs_resolved),
            lists_dir=str(lists_resolved),
            bin_dir=str(bin_resolved),
            headless_check=False,
            minimized=args.minimized,
            auto_start_stack=args.auto_start,
        )
        return 0
    except Exception as exc:  # noqa: BLE001
        _show_startup_error(
            f"Ошибка запуска GUI netdoctor: {exc}\n{traceback.format_exc()}",
            logs_resolved,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
