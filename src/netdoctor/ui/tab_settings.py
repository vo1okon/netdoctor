"""Settings tab (`Настройки`) with Progressive Disclosure (Basic + Expert block) for netdoctor v2."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any, Callable

from netdoctor import __version__
from netdoctor.ui.theme import (
    ACCENT,
    BG,
    BORDER,
    CARD,
    CARD_ALT,
    FG,
    FG_SOFT,
    FONT_H2,
    FONT_SMALL,
    FONT_SMALL_B,
    FONT_UI_B,
    LAVENDER,
    MUTED,
    OK_TEXT,
    PILL_ACTIVE_BORDER,
    SERVICE_ACTIONS,
)
from netdoctor.ui.widgets import RoundedCard


def build_settings_tab(app: Any) -> None:
    """Build clean `Настройки` tab with 6 basic controls and collapsible Expert section."""
    tab = app.tab_settings
    app._make_page_header(
        tab,
        "Настройки",
        "Основные параметры запуска, темы оформления и быстрый сброс сети.",
    )

    # Scrollable vertical container so basic + expanded expert settings fit any window height cleanly
    outer = tk.Frame(tab, bg=BG)
    outer.pack(fill="both", expand=True)
    canvas = tk.Canvas(outer, bg=BG, highlightthickness=0, bd=0)
    vsb = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
    canvas.configure(yscrollcommand=vsb.set)
    vsb.pack(side="right", fill="y")
    canvas.pack(side="left", fill="both", expand=True)

    inner = tk.Frame(canvas, bg=BG)
    win_id = canvas.create_window((0, 0), window=inner, anchor="nw")
    inner.bind("<Configure>", lambda _e: canvas.configure(scrollregion=canvas.bbox("all")))
    canvas.bind("<Configure>", lambda e: canvas.itemconfigure(win_id, width=max(360, int(e.width))))

    # ---------------- Basic Settings Card (6 clean controls) ----------------
    basic_wrap = RoundedCard(inner, bg=CARD, outer_bg=BG, border=BORDER, radius=14, pad=2)
    basic_wrap.pack(fill="x", padx=4, pady=(0, 10))
    basic = basic_wrap.body
    tk.Label(basic, text="Основные настройки", bg=CARD, fg=ACCENT, font=FONT_H2, anchor="w").pack(
        fill="x", padx=14, pady=(10, 6)
    )

    for var, label, cmd, tip in (
        (
            app.autostart_var,
            "1. Запускать вместе с Windows",
            app.on_toggle_autostart,
            "Автоматически запускать netdoctor в свёрнутом виде при входе в Windows.",
        ),
        (
            app.autostart_protection_var,
            "2. Включать защиту автоматически при старте",
            app.on_toggle_autostart_protection,
            "Сразу запускать обход блокировок при открытии программы.",
        ),
        (
            app.minimize_to_tray_var,
            "3. Сворачивать в трей при закрытии окна",
            None,
            "Крестик скрывает окно в область уведомлений (трей), не останавливая защиту.",
        ),
    ):
        row = app.make_toggle_row(
            basic,
            label,
            var,
            command=cmd,
            bg=CARD,
            font=FONT_SMALL_B,
            fg=FG_SOFT,
            tooltip=tip,
            slider_width=38,
            slider_height=18,
        )
        row.pack(fill="x", padx=14, pady=3)

    # 4. Telegram mode choice row (Basic Settings — Section 5.2)
    tg_row = tk.Frame(basic, bg=CARD)
    tg_row.pack(fill="x", padx=14, pady=4)
    tk.Label(tg_row, text="4. Режим Telegram:", bg=CARD, fg=FG_SOFT, font=FONT_SMALL_B).pack(side="left")
    app.settings_tg_open_btn = app.make_button(
        tg_row,
        "Подключить в 1 клик",
        app.on_connect_telegram_proxy,
        "cyan_ghost",
        font=FONT_SMALL,
        padx=8,
        pady=2,
        tooltip="Открыть локальный MTProto-прокси (127.0.0.1:10808) в Telegram Desktop.",
    )
    app.settings_tg_open_btn.pack(side="right", padx=(6, 0))
    app._settings_tg_labels = (
        "MTProto-прокси (рекомендуется)",
        "Прозрачный обход (Zapret / VPN)",
    )
    app.settings_tg_mode_var = tk.StringVar(value=app._settings_tg_labels[0])
    app.settings_tg_mode_cb = ttk.Combobox(
        tg_row,
        textvariable=app.settings_tg_mode_var,
        values=app._settings_tg_labels,
        state="readonly",
        width=30,
    )
    app.settings_tg_mode_cb.pack(side="right")
    app.settings_tg_mode_cb.bind("<<ComboboxSelected>>", lambda _e: app.on_settings_telegram_mode_selected())

    # 5. Theme toggle row
    theme_row = tk.Frame(basic, bg=CARD)
    theme_row.pack(fill="x", padx=14, pady=4)
    tk.Label(theme_row, text="5. Тема интерфейса:", bg=CARD, fg=FG_SOFT, font=FONT_SMALL_B).pack(side="left")
    app.theme_mode_var = tk.StringVar(value="Тёмная")
    app.theme_cb = ttk.Combobox(
        theme_row,
        textvariable=app.theme_mode_var,
        values=("Тёмная", "Светлая"),
        state="readonly",
        width=12,
    )
    app.theme_cb.pack(side="right")
    app.theme_cb.bind("<<ComboboxSelected>>", lambda _e: app.on_toggle_theme())

    # 6. Repair / Flush DNS + Check Updates row
    tools_row = tk.Frame(basic, bg=CARD)
    tools_row.pack(fill="x", padx=14, pady=6)
    mode_raw = app.backend.get_install_mode() if hasattr(app.backend, "get_install_mode") else "portable"
    mode_label = "git" if mode_raw == "git" else "ZIP"
    app.version_info_label = tk.Label(
        tools_row,
        text=f"6. Версия: v{__version__} ({mode_label}) · Сеть и обновления",
        bg=CARD,
        fg=FG_SOFT,
        font=FONT_SMALL,
        anchor="w",
    )
    app.version_info_label.pack(side="left", fill="x", expand=True)

    app.apply_update_btn = app.make_button(
        tools_row,
        "Обновить",
        app.on_apply_update,
        "success",
        font=FONT_SMALL_B,
        padx=10,
        pady=3,
    )
    app.check_update_btn = app.make_button(
        tools_row,
        "Проверить обновления",
        app.on_check_updates,
        "neutral",
        font=FONT_SMALL_B,
        padx=10,
        pady=3,
    )
    app.check_update_btn.pack(side="right", padx=(6, 0))
    app.make_button(
        tools_row,
        "Починить сеть (DNS)",
        app.on_flush_dns,
        "cyan_ghost",
        font=FONT_SMALL_B,
        padx=10,
        pady=3,
        tooltip="Сбрасывает кэш DNS Windows (ipconfig /flushdns) при зависании сайтов.",
    ).pack(side="right", padx=(6, 0))

    # 7. Expert mode toggle (Progressive Disclosure)
    tk.Frame(basic, bg=BORDER, height=1).pack(fill="x", padx=14, pady=(4, 4))
    exp_row = app.make_toggle_row(
        basic,
        "7. Режим эксперта (Монитор, Пресеты, DNS, Логи и тонкая настройка)",
        app.expert_mode_var,
        command=app.on_toggle_expert_mode,
        bg=CARD,
        font=FONT_UI_B,
        fg=LAVENDER,
        tooltip="Включает профессиональные вкладки (Монитор, Пресеты, DNS, Логи) и низкоуровневые настройки драйвера.",
        slider_width=40,
        slider_height=19,
    )
    exp_row.pack(fill="x", padx=14, pady=(4, 10))

    # Full Exit action
    exit_row = tk.Frame(inner, bg=BG)
    exit_row.pack(fill="x", padx=4, pady=(0, 10))
    app.make_button(
        exit_row,
        "Выход и остановка всех служб",
        app.on_exit_app,
        "danger",
        font=FONT_SMALL_B,
        padx=14,
        pady=5,
        tooltip="Полностью останавливает winws2, sing-box, tg-ws-proxy и закрывает программу.",
    ).pack(side="right")

    # ---------------- Expert Section (hidden unless expert_mode == True) ----------------
    app._expert_settings_frame = tk.Frame(inner, bg=BG)

    exp_cols = tk.Frame(app._expert_settings_frame, bg=BG)
    exp_cols.pack(fill="x", padx=4)
    exp_cols.columnconfigure(0, weight=1, uniform="exp_s")
    exp_cols.columnconfigure(1, weight=1, uniform="exp_s")

    # Left expert card: Service maintenance actions
    act_wrap = RoundedCard(exp_cols, bg=CARD, outer_bg=BG, border=PILL_ACTIVE_BORDER, radius=13, pad=2)
    act_wrap.grid(row=0, column=0, sticky="nsew", padx=(0, 6), pady=(0, 8))
    act_card = act_wrap.body
    tk.Label(act_card, text="Обслуживание модулей (Эксперт)", bg=CARD, fg=ACCENT, font=FONT_UI_B, anchor="w").pack(
        fill="x", padx=12, pady=(8, 4)
    )
    handlers: dict[str, Callable[[], None]] = {
        "layers": app.on_check_layers,
        "reload": app.on_reload,
        "reload_sb": app.on_reload_singbox,
        "reval": app.on_revalidate,
        "gen": app.on_generate,
        "flush_dns": app.on_flush_dns,
        "cleanup_db": app.on_cleanup_stale_db,
        "verify": app.on_verify,
    }
    kinds = {"layers": "primary"}
    for key, title, tip_text in SERVICE_ACTIONS:
        btn = app.make_button(
            act_card,
            title,
            handlers[key],
            kinds.get(key, "neutral"),
            font=FONT_SMALL_B,
            padx=9,
            pady=3,
            radius=8,
            tooltip=tip_text,
        )
        btn.configure(anchor="w")
        btn.pack(fill="x", padx=12, pady=2)
    app.make_button(
        act_card,
        "Калибровка провайдера заново",
        app.on_run_first_calibration,
        "cyan_ghost",
        font=FONT_SMALL_B,
        padx=9,
        pady=3,
        radius=8,
    ).pack(fill="x", padx=12, pady=(4, 8))

    # Right expert card: TUN stack, Debug log, Game filter, Unlocker guard
    adv_wrap = RoundedCard(exp_cols, bg=CARD, outer_bg=BG, border=PILL_ACTIVE_BORDER, radius=13, pad=2)
    adv_wrap.grid(row=0, column=1, sticky="nsew", padx=(6, 0), pady=(0, 8))
    adv_card = adv_wrap.body
    tk.Label(adv_card, text="Параметры стека и исключения", bg=CARD, fg=LAVENDER, font=FONT_UI_B, anchor="w").pack(
        fill="x", padx=12, pady=(8, 4)
    )

    net_row = tk.Frame(adv_card, bg=CARD)
    net_row.pack(fill="x", padx=12, pady=(2, 6))
    tk.Label(net_row, text="TUN стек:", bg=CARD, fg=MUTED, font=FONT_SMALL).pack(side="left", padx=(0, 4))
    app.tun_stack_cb = ttk.Combobox(
        net_row,
        textvariable=app.tun_stack_var,
        values=("mixed", "gvisor", "system"),
        state="readonly",
        width=9,
    )
    app.tun_stack_cb.pack(side="left", padx=(0, 10))
    app.tun_stack_cb.bind("<<ComboboxSelected>>", lambda _e: app.on_change_tun_stack())

    tk.Label(net_row, text="ifIndex:", bg=CARD, fg=MUTED, font=FONT_SMALL).pack(side="left", padx=(0, 4))
    app.iface_var = tk.StringVar()
    app.make_entry(net_row, app.iface_var, 7).pack(side="left", fill="x", expand=True, ipady=2)

    app.make_toggle_row(
        adv_card,
        "Подробный журнал отладки winws2 (--debug=1)",
        app.debug_log_var,
        command=app.on_toggle_debug_log,
        bg=CARD,
        font=FONT_SMALL,
        fg=FG_SOFT,
        slider_width=34,
        slider_height=16,
    ).pack(fill="x", padx=12, pady=2)

    app.make_toggle_row(
        adv_card,
        "Расширенный Game UDP DPI-профиль",
        app.game_filter_var,
        command=app.on_toggle_game_filter,
        bg=CARD,
        font=FONT_SMALL,
        fg=FG_SOFT,
        slider_width=34,
        slider_height=16,
    ).pack(fill="x", padx=12, pady=2)

    tk.Frame(adv_card, bg=BORDER, height=1).pack(fill="x", padx=12, pady=6)
    tk.Label(
        adv_card,
        text="Защита сторонних программ и hosts",
        bg=CARD,
        fg=OK_TEXT,
        font=FONT_SMALL_B,
        anchor="w",
    ).pack(fill="x", padx=12, pady=(0, 2))
    app.unlocker_guard_var = tk.BooleanVar(value=True)
    app.make_toggle_row(
        adv_card,
        "Не вмешиваться в Antigravity.exe, Cursor, ag_dns.exe, xray/happ и hosts",
        app.unlocker_guard_var,
        command=app.on_save_unlocker_guard,
        bg=CARD,
        font=FONT_SMALL,
        fg=FG_SOFT,
        slider_width=34,
        slider_height=16,
    ).pack(fill="x", padx=12, pady=(0, 4))

    g_row = tk.Frame(adv_card, bg=CARD)
    g_row.pack(fill="x", padx=12, pady=(0, 10))
    app.make_button(
        g_row,
        "Сохранить",
        app.on_save_unlocker_guard,
        "primary",
        font=FONT_SMALL_B,
        pady=3,
    ).pack(side="right", padx=(6, 0))
    tk.Label(g_row, text="Исключения:", bg=CARD, fg=MUTED, font=FONT_SMALL).pack(side="left", padx=(0, 6))
    app.unlocker_custom_var = tk.StringVar()
    app.unlocker_custom_entry = app.make_entry(g_row, app.unlocker_custom_var, 12)
    app.unlocker_custom_entry.pack(side="left", fill="x", expand=True, ipady=2)
