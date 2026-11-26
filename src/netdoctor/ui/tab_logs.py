"""Expert Logs & Config Previews tab (`Логи`) for netdoctor v2."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any

from netdoctor.ui.theme import (
    ACCENT,
    BG,
    BORDER,
    ERR_TEXT,
    FG_SOFT,
    FONT_MICRO,
    FONT_MONO_S,
    FONT_SMALL,
    FONT_SMALL_B,
    LOG_FILES,
    MUTED,
    OK_BG,
    OK_TEXT,
    SIDEBAR_BG,
    WARN,
    WARN_BG,
    WARN_TEXT,
)


def build_logs_tab(app: Any) -> None:
    """Build Expert Logs & Config Previews tab (separated out of VPN/Settings tabs)."""
    tab = app.tab_logs
    app._make_page_header(
        tab,
        "Логи служб и конфиги",
        "Журналы работы winws2, sing-box, tg-ws-proxy и просмотр сгенерированных конфигов.",
    )

    paned = ttk.PanedWindow(tab, orient="vertical")
    paned.pack(fill="both", expand=True)

    # Top: Service logs
    log_panel = tk.Frame(paned, bg=BG)
    head = tk.Frame(log_panel, bg=BG)
    head.pack(fill="x", pady=(0, 4))
    tk.Label(head, text="Журнал фоновой службы:", bg=BG, fg=FG_SOFT, font=FONT_SMALL_B).pack(side="left", padx=(0, 8))
    app.log_var = tk.StringVar(value=LOG_FILES[0])
    log_cb = ttk.Combobox(head, textvariable=app.log_var, values=LOG_FILES, state="readonly", width=20)
    log_cb.pack(side="left")
    log_cb.bind("<<ComboboxSelected>>", lambda _e: app.refresh_logs_async())
    app.attach_tooltip(log_cb, "winws2.log — обход DPI; sing-box.log — VPN и DNS; tg-ws-proxy.log — прокси Telegram.")
    tk.Label(head, text="● автообновление 2с", bg=OK_BG, fg=OK_TEXT, font=FONT_MICRO, padx=7, pady=2).pack(
        side="left", padx=10
    )

    app._log_alert_bar = tk.Frame(log_panel, bg=WARN_BG, highlightthickness=1, highlightbackground=WARN)
    app.make_button(
        app._log_alert_bar,
        "Перейти в DNS →",
        lambda: app._select_tab(app.tab_dns),
        "warn",
        font=FONT_MICRO,
        padx=8,
        pady=2,
    ).pack(side="right", padx=8, pady=4)
    app._log_alert_lbl = tk.Label(
        app._log_alert_bar, text="", bg=WARN_BG, fg=WARN_TEXT, font=FONT_SMALL, anchor="w", justify="left"
    )
    app._log_alert_lbl.pack(side="left", fill="x", expand=True, padx=10, pady=5)
    app._bind_responsive_wrap(app._log_alert_lbl, min_wrap=220, pad=20)

    wrap = tk.Frame(log_panel, bg=SIDEBAR_BG, highlightthickness=1, highlightbackground=BORDER)
    wrap.pack(fill="both", expand=True)
    app.log_view = app.make_text(wrap, height=11, wrap="none")
    app.log_view.configure(font=FONT_MONO_S)
    app.log_view.tag_configure("err", foreground=ERR_TEXT)
    app.log_view.tag_configure("warn", foreground=WARN_TEXT)
    app.log_view.tag_configure("info", foreground=FG_SOFT)
    app.log_view.tag_configure("muted", foreground=MUTED)
    app._scrolled(wrap, app.log_view, horizontal=True)
    paned.add(log_panel, weight=3)

    # Bottom: Config preview + operations console
    bot_split = ttk.PanedWindow(paned, orient="horizontal")
    paned.add(bot_split, weight=2)

    preview_panel = tk.Frame(bot_split, bg=BG)
    p_head = tk.Frame(preview_panel, bg=BG)
    p_head.pack(fill="x", pady=(6, 4))
    app.make_button(
        p_head,
        "↻ Обновить",
        app.refresh_previews_async,
        "neutral",
        font=FONT_SMALL_B,
        pady=3,
        tooltip="Перечитать содержимое выбранного файла конфигурации с диска.",
    ).pack(side="right", padx=(6, 0))
    tk.Label(p_head, text="Просмотр конфига:", bg=BG, fg=FG_SOFT, font=FONT_SMALL_B).pack(side="left", padx=(0, 8))
    app.file_var = tk.StringVar()
    app.file_cb = ttk.Combobox(p_head, textvariable=app.file_var, state="readonly", width=24)
    app.file_cb.pack(side="left", fill="x", expand=True)
    app.file_cb.bind("<<ComboboxSelected>>", lambda _e: app.show_selected_file())
    p_wrap = tk.Frame(preview_panel, bg=SIDEBAR_BG, highlightthickness=1, highlightbackground=BORDER)
    p_wrap.pack(fill="both", expand=True)
    app.preview = app.make_text(p_wrap, height=8, wrap="none")
    app._scrolled(p_wrap, app.preview, horizontal=True)
    bot_split.add(preview_panel, weight=3)

    con_panel = tk.Frame(bot_split, bg=BG)
    tk.Label(con_panel, text="Журнал операций", bg=BG, fg=ACCENT, font=FONT_SMALL_B, anchor="w").pack(
        fill="x", pady=(6, 4)
    )
    con_wrap = tk.Frame(con_panel, bg=SIDEBAR_BG, highlightthickness=1, highlightbackground=BORDER)
    con_wrap.pack(fill="both", expand=True)
    app.console = app.make_text(con_wrap, height=8, wrap="word")
    app.console.configure(font=FONT_MONO_S)
    app.console.tag_configure("muted", foreground=MUTED)
    app.console.tag_configure("ok", foreground=OK_TEXT)
    app.console.tag_configure("bad", foreground=ERR_TEXT)
    app._scrolled(con_wrap, app.console)
    bot_split.add(con_panel, weight=2)
