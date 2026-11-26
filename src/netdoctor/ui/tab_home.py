"""Clean Home tab (`Главная`) with plain-language status and First-Run calibration overlay."""

from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, ttk
from typing import Any

from netdoctor.ui.theme import (
    ACCENT,
    BG,
    BORDER,
    CARD,
    CARD_ALT,
    DIM,
    FG,
    FG_SOFT,
    FONT_H2,
    FONT_HERO,
    FONT_MICRO,
    FONT_SMALL,
    FONT_SMALL_B,
    FONT_UI_B,
    INFO_BG,
    INPUT,
    LAVENDER,
    MUTED,
    OK_BG,
    OK_TEXT,
    PILL_ACTIVE_BORDER,
    SIDEBAR_BG,
    WARN,
    WARN_BG,
    WARN_TEXT,
)
from netdoctor.ui.widgets import AnimatedToggle, RoundedCard


def build_home_tab(app: Any) -> None:
    """Build the clean v2 `Главная` tab (Simple status + unified Fix block + 1-click protection + First-Run overlay)."""
    tab = app.tab_home
    outer = tk.Frame(tab, bg=SIDEBAR_BG, highlightthickness=1, highlightbackground=BORDER)
    outer.pack(fill="both", expand=True)

    canvas = tk.Canvas(outer, bg=SIDEBAR_BG, highlightthickness=0, bd=0)
    vsb = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
    canvas.configure(yscrollcommand=vsb.set)
    vsb.pack(side="right", fill="y")
    canvas.pack(side="left", fill="both", expand=True)

    surface = tk.Frame(canvas, bg=SIDEBAR_BG)
    win_id = canvas.create_window((0, 0), window=surface, anchor="nw")
    app._home_canvas = canvas
    surface.bind("<Configure>", lambda _e=None: canvas.configure(scrollregion=canvas.bbox("all")))
    canvas.bind("<Configure>", lambda e: canvas.itemconfigure(win_id, width=max(320, int(e.width))))

    # First-Run Onboarding Banner / Card (shown when network_profile is None)
    app._onboarding_frame = RoundedCard(
        surface, bg=INFO_BG, outer_bg=SIDEBAR_BG, border=ACCENT, radius=14, pad=2
    )
    ob_body = app._onboarding_frame.body
    ob_btns = tk.Frame(ob_body, bg=INFO_BG)
    ob_btns.pack(side="right", padx=12, pady=6)
    app.make_button(
        ob_btns,
        "Настроить и включить защиту",
        app.on_run_first_calibration,
        "hero",
        font=FONT_SMALL_B,
        padx=12,
        pady=4,
    ).pack(side="left", padx=(0, 6))
    app.make_button(
        ob_btns,
        "Позже",
        lambda: dismiss_onboarding(app),
        "neutral",
        font=FONT_SMALL,
        padx=8,
        pady=4,
    ).pack(side="left")

    ob_text = tk.Frame(ob_body, bg=INFO_BG)
    ob_text.pack(side="left", fill="x", expand=True, padx=(14, 8), pady=6)
    tk.Label(
        ob_text,
        text="Первый запуск: быстрая настройка под вашего провайдера",
        bg=INFO_BG,
        fg=ACCENT,
        font=FONT_H2,
        anchor="w",
    ).pack(fill="x")
    app._onboarding_step_lbl = tk.Label(
        ob_text,
        text="Нажмите «Настроить и включить защиту» — мы выберем быстрый рабочий DNS и проверим блокировки.",
        bg=INFO_BG,
        fg=FG_SOFT,
        font=FONT_SMALL,
        anchor="w",
        justify="left",
    )
    app._onboarding_step_lbl.pack(fill="x", pady=(2, 0))
    app._bind_responsive_wrap(app._onboarding_step_lbl, min_wrap=240, pad=24)

    # Conditional DoH / DNS alert banner
    app._home_alert_frame = RoundedCard(
        surface, bg=WARN_BG, outer_bg=SIDEBAR_BG, border=WARN, radius=11, pad=2
    )
    alert_body = app._home_alert_frame.body
    alert_btns = tk.Frame(alert_body, bg=WARN_BG)
    alert_btns.pack(side="right", padx=8, pady=4)
    app.make_button(
        alert_btns,
        "Включить рабочий DNS",
        lambda: app.on_select_dns("comss_dns"),
        "warn",
        font=FONT_MICRO,
        padx=8,
        pady=2,
    ).pack(side="right")
    app._home_alert_lbl = tk.Label(
        alert_body,
        text="",
        bg=WARN_BG,
        fg=WARN_TEXT,
        font=FONT_SMALL,
        anchor="w",
        justify="left",
    )
    app._home_alert_lbl.pack(side="left", fill="x", expand=True, padx=(10, 4), pady=4)
    app._bind_responsive_wrap(app._home_alert_lbl, min_wrap=220, pad=24)

    # Conditional pending bundle connectivity alert banner
    app._home_bundle_alert_frame = RoundedCard(
        surface, bg=WARN_BG, outer_bg=SIDEBAR_BG, border="#F59E0B", radius=11, pad=2
    )
    ba_body = app._home_bundle_alert_frame.body
    app._home_bundle_alert_btns = tk.Frame(ba_body, bg=WARN_BG)
    app._home_bundle_alert_btns.pack(side="right", padx=8, pady=4)
    app._home_bundle_alert_lbl = tk.Label(
        ba_body,
        text="",
        bg=WARN_BG,
        fg=WARN_TEXT,
        font=FONT_SMALL_B,
        anchor="w",
        justify="left",
    )
    app._home_bundle_alert_lbl.pack(side="left", fill="x", expand=True, padx=(10, 4), pady=4)
    app._bind_responsive_wrap(app._home_bundle_alert_lbl, min_wrap=220, pad=24)

    # ---------------- Primary Hero Card ----------------
    hero_card_wrap = RoundedCard(surface, bg=CARD, outer_bg=SIDEBAR_BG, border=BORDER, radius=16, pad=3)
    app._home_section1_lbl = hero_card_wrap
    app._home_zapret_card = hero_card_wrap
    hero_card_wrap.pack(fill="x", padx=18, pady=(8, 6))
    hero_card = hero_card_wrap.body

    hc_top = tk.Frame(hero_card, bg=CARD)
    hc_top.pack(fill="x", padx=18, pady=(8, 4))
    app._home_zapret_pill = tk.Label(
        hc_top,
        text="● ОТКЛЮЧЕНО",
        bg=INPUT,
        fg=MUTED,
        font=FONT_SMALL_B,
        padx=10,
        pady=3,
    )
    app._home_zapret_pill.pack(side="left")

    app.home_preset_mode_pill = tk.Label(
        hc_top,
        text="● Автоподбор",
        bg=INFO_BG,
        fg=ACCENT,
        font=FONT_MICRO,
        padx=8,
        pady=2,
    )
    app.home_preset_mode_pill.pack(side="right")

    app._home_hero_title = tk.Label(
        hero_card,
        text="Защита интернета и обход блокировок",
        bg=CARD,
        fg=FG,
        font=FONT_HERO,
        anchor="w",
    )
    app._home_hero_title.pack(fill="x", padx=18, pady=(0, 2))
    app.hint_label = tk.Label(
        hero_card,
        text="YouTube, Discord и заблокированные сайты работают на полной скорости; игры и лаунчеры управляются отдельно.",
        bg=CARD,
        fg=MUTED,
        font=FONT_SMALL,
        anchor="w",
        justify="left",
    )
    app.hint_label.pack(fill="x", padx=18, pady=(0, 6))
    app._bind_responsive_wrap(app.hint_label, min_wrap=280, pad=36)

    btn_row = tk.Frame(hero_card, bg=CARD)
    btn_row.pack(fill="x", padx=18, pady=(0, 8))
    btn_row.columnconfigure(0, weight=3)
    btn_row.columnconfigure(1, weight=1)
    btn_row.columnconfigure(2, weight=1)

    app.autopilot_btn = app.make_button(
        btn_row,
        "ВКЛЮЧИТЬ ЗАЩИТУ  ⏻",
        app.on_toggle_autopilot,
        "hero",
        font=("Segoe UI", 12, "bold"),
        padx=18,
        pady=7,
        radius=13,
        tooltip="Запускает или останавливает обход блокировок, точечный VPN и защищённый DNS.",
    )
    app.autopilot_btn.grid(row=0, column=0, sticky="nsew", padx=(0, 8))

    app.auto_tune_all_btn = app.make_button(
        btn_row,
        "⚡ Починить",
        app.on_auto_tune_all,
        "primary",
        font=FONT_SMALL_B,
        padx=10,
        pady=7,
        radius=12,
        tooltip="Сбрасывает сбойные правила, проверяет рабочий DNS и перенастраивает обход.",
    )
    app.auto_tune_all_btn.grid(row=0, column=1, sticky="nsew", padx=(0, 6))

    app.make_button(
        btn_row,
        "Проверить ↗",
        lambda: app.on_run_connectivity_tests(include_picked=False),
        "cyan_ghost",
        font=FONT_SMALL_B,
        padx=10,
        pady=7,
        radius=12,
        tooltip="Быстрая проверка открытия YouTube, Discord и Telegram прямо сейчас.",
    ).grid(row=0, column=2, sticky="nsew")

    # Quick service check pills
    pills_wrap = tk.Frame(hero_card, bg=CARD)
    pills_wrap.pack(fill="x", padx=18, pady=(0, 8))
    app._home_service_pills: dict[str, tk.Label] = {}
    for sg_key, sg_title in (("youtube", "YouTube"), ("discord", "Discord"), ("telegram", "Telegram")):
        lbl = tk.Label(
            pills_wrap,
            text=f"● {sg_title}: —",
            bg=INPUT,
            fg=MUTED,
            font=FONT_MICRO,
            padx=7,
            pady=2,
        )
        lbl.pack(side="left", padx=(0, 5))
        app._home_service_pills[sg_key] = lbl
    app.home_test_rate_pill = tk.Label(
        pills_wrap,
        text="Проверка: —",
        bg=INFO_BG,
        fg=ACCENT,
        font=FONT_MICRO,
        padx=7,
        pady=2,
    )
    app.home_test_rate_pill.pack(side="right")

    # ---------------- 4 Clean Plain-Language Status Rows ----------------
    status_grid = tk.Frame(surface, bg=SIDEBAR_BG)
    status_grid.pack(fill="x", padx=18, pady=(0, 6))
    status_grid.columnconfigure(0, weight=1, uniform="home_st")
    status_grid.columnconfigure(1, weight=1, uniform="home_st")

    # 1. DNS Card
    dns_wrap = RoundedCard(status_grid, bg=CARD, outer_bg=SIDEBAR_BG, border=BORDER, radius=13, pad=2)
    dns_wrap.grid(row=0, column=0, sticky="nsew", padx=(0, 6), pady=(0, 5))
    dns_body = dns_wrap.body
    tk.Label(dns_body, text="◉ ИНТЕРНЕТ И DNS", bg=CARD, fg=LAVENDER, font=FONT_MICRO, anchor="w").pack(
        fill="x", padx=12, pady=(5, 1)
    )
    app.card_dns_val = tk.Label(dns_body, text="—", bg=CARD, fg=FG, font=FONT_UI_B, anchor="w")
    app.card_dns_val.pack(fill="x", padx=12)
    app._bind_responsive_wrap(app.card_dns_val, min_wrap=160, pad=24)
    app.card_dns_sub = tk.Label(dns_body, text="—", bg=CARD, fg=MUTED, font=FONT_SMALL, anchor="w")
    app.card_dns_sub.pack(fill="x", padx=12, pady=(0, 5))
    app._bind_responsive_wrap(app.card_dns_sub, min_wrap=160, pad=24)

    # 2. DPI / Sites Card
    dpi_wrap = RoundedCard(status_grid, bg=CARD, outer_bg=SIDEBAR_BG, border=BORDER, radius=13, pad=2)
    dpi_wrap.grid(row=0, column=1, sticky="nsew", padx=(6, 0), pady=(0, 5))
    dpi_body = dpi_wrap.body
    tk.Label(dpi_body, text="⚡ САЙТЫ И ОБХОД БЛОКИРОВОК", bg=CARD, fg=ACCENT, font=FONT_MICRO, anchor="w").pack(
        fill="x", padx=12, pady=(5, 1)
    )
    app.card_dpi_val = tk.Label(dpi_body, text="—", bg=CARD, fg=FG, font=FONT_UI_B, anchor="w")
    app.card_dpi_val.pack(fill="x", padx=12)
    app._bind_responsive_wrap(app.card_dpi_val, min_wrap=160, pad=24)
    app.card_dpi_sub = tk.Label(dpi_body, text="—", bg=CARD, fg=MUTED, font=FONT_SMALL, anchor="w")
    app.card_dpi_sub.pack(fill="x", padx=12, pady=(0, 5))
    app._bind_responsive_wrap(app.card_dpi_sub, min_wrap=160, pad=24)

    # 3. VPN Card
    vpn_wrap = RoundedCard(status_grid, bg=CARD, outer_bg=SIDEBAR_BG, border=BORDER, radius=13, pad=2)
    app._home_vpn_card = vpn_wrap
    vpn_wrap.grid(row=1, column=0, sticky="nsew", padx=(0, 6))
    vpn_body = vpn_wrap.body
    vp_head = tk.Frame(vpn_body, bg=CARD)
    vp_head.pack(fill="x", padx=12, pady=(5, 1))
    tk.Label(vp_head, text="☁ ТОЧЕЧНЫЙ VPN", bg=CARD, fg="#FB923C", font=FONT_MICRO, anchor="w").pack(side="left")
    app._home_vpn_state_pill = tk.Label(
        vp_head, text="● РЕЗЕРВ", bg=INPUT, fg=MUTED, font=FONT_MICRO, padx=6, pady=1
    )
    app._home_vpn_state_pill.pack(side="right")
    app.card_vpn_val = tk.Label(vpn_body, text="—", bg=CARD, fg=FG, font=FONT_UI_B, anchor="w")
    app.card_vpn_val.pack(fill="x", padx=12)
    app._bind_responsive_wrap(app.card_vpn_val, min_wrap=160, pad=24)
    app.card_vpn_sub = tk.Label(vpn_body, text="—", bg=CARD, fg=MUTED, font=FONT_SMALL, anchor="w")
    app.card_vpn_sub.pack(fill="x", padx=12, pady=(0, 5))
    app._bind_responsive_wrap(app.card_vpn_sub, min_wrap=160, pad=24)

    # 4. Telegram & Active Bundles Card
    tg_wrap = RoundedCard(status_grid, bg=CARD, outer_bg=SIDEBAR_BG, border=BORDER, radius=13, pad=2)
    tg_wrap.grid(row=1, column=1, sticky="nsew", padx=(6, 0))
    tg_body = tg_wrap.body
    tg_head = tk.Frame(tg_body, bg=CARD)
    tg_head.pack(fill="x", padx=12, pady=(5, 1))
    tk.Label(tg_head, text="✈ TELEGRAM И ИГРЫ", bg=CARD, fg=ACCENT, font=FONT_MICRO, anchor="w").pack(side="left")
    app.tg_proxy_btn = app.make_button(
        tg_head,
        "Открыть в Telegram",
        app.on_connect_telegram_proxy,
        "ghost",
        font=FONT_MICRO,
        padx=7,
        pady=1,
    )
    app.tg_proxy_btn.pack(side="right")
    app._home_tg_val = tk.Label(tg_body, text="MTProto прокси готов", bg=CARD, fg=FG, font=FONT_UI_B, anchor="w")
    app._home_tg_val.pack(fill="x", padx=12)
    app._home_apps_summary = tk.Label(
        tg_body,
        text="Игры и программы подбираются автоматически — проверьте в «Что-то не открывается?» ниже",
        bg=CARD,
        fg=MUTED,
        font=FONT_SMALL,
        anchor="w",
        cursor="hand2",
    )
    app._home_apps_summary.pack(fill="x", padx=12, pady=(0, 5))
    app._home_apps_summary.bind(
        "<Button-1>",
        lambda _e: (
            app._open_domains_subview("bundles")
            if getattr(app, "_expert_mode", False)
            else app.set_home_fix_kind("bundle", focus=True)
        ),
    )

    # ---------------- Unified «Что-то не открывается?» Fix Block ----------------
    app._home_fix_frame = RoundedCard(surface, bg=CARD, outer_bg=SIDEBAR_BG, border=BORDER, radius=13, pad=2)
    app._home_fix_frame.pack(fill="x", padx=18, pady=(0, 6))
    fx_b = app._home_fix_frame.body

    fx_top = tk.Frame(fx_b, bg=CARD)
    fx_top.pack(fill="x", padx=12, pady=(6, 4))
    tk.Label(fx_top, text="Что-то не открывается?", bg=CARD, fg=FG, font=FONT_SMALL_B, anchor="w").pack(side="left")

    app._home_fix_kind_var = tk.StringVar(value="domain")
    fx_pills = tk.Frame(fx_top, bg=CARD)
    fx_pills.pack(side="left", padx=(10, 0))
    app._home_fix_site_btn = app.make_button(
        fx_pills,
        "Сайт",
        lambda: app.set_home_fix_kind("domain"),
        "pill_active",
        font=FONT_MICRO,
        padx=8,
        pady=2,
    )
    app._home_fix_site_btn.pack(side="left", padx=(0, 4))
    app._home_fix_app_btn = app.make_button(
        fx_pills,
        "Игра / программа",
        lambda: app.set_home_fix_kind("bundle"),
        "neutral",
        font=FONT_MICRO,
        padx=8,
        pady=2,
    )
    app._home_fix_app_btn.pack(side="left")

    app.home_fix_result_lbl = tk.Label(fx_top, text="", bg=CARD, fg=MUTED, font=FONT_MICRO, anchor="e")
    app.home_fix_result_lbl.pack(side="right", fill="x", expand=True, padx=(8, 0))

    fx_row = tk.Frame(fx_b, bg=CARD)
    fx_row.pack(fill="x", padx=12, pady=(0, 7))
    app.home_fix_btn = app.make_button(
        fx_row,
        "Починить",
        app.on_home_fix_target,
        "primary",
        font=FONT_SMALL_B,
        padx=12,
        pady=4,
        tooltip="Автоматически подбирает рабочий слой (Напрямую → DPI → VPN) для выбранного сайта или игры/программы.",
    )
    app.home_fix_btn.pack(side="right", padx=(8, 0))

    app._home_fix_input_host = tk.Frame(fx_row, bg=CARD)
    app._home_fix_input_host.pack(side="left", fill="x", expand=True)

    app.home_fix_domain_var = tk.StringVar()
    app.home_fix_domain_entry = app.make_entry(app._home_fix_input_host, app.home_fix_domain_var, 28)
    app.home_fix_domain_entry.pack(fill="x", expand=True, ipady=3)
    app.home_fix_domain_entry.bind("<Return>", lambda _e: app.on_home_fix_target())

    app._home_fix_bundle_wrap = tk.Frame(app._home_fix_input_host, bg=CARD)
    app.home_fix_bundle_var = tk.StringVar()
    app.home_fix_bundle_cb = ttk.Combobox(
        app._home_fix_bundle_wrap,
        textvariable=app.home_fix_bundle_var,
        state="normal",
        values=[],
    )
    app.home_fix_bundle_cb.pack(side="left", fill="x", expand=True)
    app.home_fix_bundle_cb.bind("<Return>", lambda _e: app.on_home_fix_target())
    app.make_button(
        app._home_fix_bundle_wrap,
        "Обзор .exe…",
        app._browse_home_fix_exe,
        "neutral",
        font=FONT_MICRO,
        padx=7,
        pady=3,
    ).pack(side="left", padx=(6, 0))
    app._home_fix_bundle_map: dict[str, str] = {}

    # ---------------- Compact Expert Quick Strip (hidden unless expert_mode == True) ----------------
    app._home_expert_strip = RoundedCard(surface, bg=CARD, outer_bg=SIDEBAR_BG, border=PILL_ACTIVE_BORDER, radius=13, pad=2)
    exp_b = app._home_expert_strip.body

    exp_top = tk.Frame(exp_b, bg=CARD)
    exp_top.pack(fill="x", padx=12, pady=(6, 4))
    tk.Label(exp_top, text="Пресет Zapret2:", bg=CARD, fg=MUTED, font=FONT_MICRO).pack(side="left", padx=(0, 6))
    app.home_preset_var = tk.StringVar(value="Авто-оркестратор (подбор по доменам)")
    app.home_preset_cb = ttk.Combobox(
        exp_top,
        textvariable=app.home_preset_var,
        state="readonly",
        values=["Авто-оркестратор (подбор по доменам)"],
        width=30,
    )
    app.home_preset_cb.pack(side="left", padx=(0, 12))
    app.home_preset_cb.bind("<<ComboboxSelected>>", lambda _e: _on_home_preset_selected(app))

    app._stack_mode_labels = (
        "Гибридный (Обход DPI + точечный VPN)",
        "Только обход DPI (без VPN-туннеля)",
    )
    app.home_stack_mode_var = tk.StringVar(value=app._stack_mode_labels[0])
    app.home_stack_mode_cb = ttk.Combobox(
        exp_top,
        textvariable=app.home_stack_mode_var,
        state="readonly",
        values=app._stack_mode_labels,
        width=28,
    )
    app.home_stack_mode_cb.pack(side="left")
    app.home_stack_mode_cb.bind("<<ComboboxSelected>>", lambda _e: _on_home_stack_mode_selected(app))

    AnimatedToggle(exp_top, variable=app.byedpi_var, command=app.on_toggle_byedpi, bg=CARD, width=34, height=16).pack(
        side="right"
    )
    tk.Label(exp_top, text="ByeDPI", bg=CARD, fg=MUTED, font=FONT_MICRO).pack(side="right", padx=(0, 6))

    # Preserved unlocker_status_label & realtime summary widgets inside expert strip
    guard_strip = tk.Frame(exp_b, bg=CARD_ALT)
    guard_strip.pack(fill="x", padx=12, pady=(0, 6))
    app.unlocker_status_label = tk.Label(
        guard_strip,
        text="Защита Antigravity Unlocker и файла hosts: активна",
        bg=CARD_ALT,
        fg=OK_TEXT,
        font=FONT_MICRO,
        anchor="w",
    )
    app.unlocker_status_label.pack(side="left", fill="x", expand=True, padx=8, pady=4)
    app.card_rt_val = tk.Label(guard_strip, text="—", bg=CARD_ALT, fg=FG_SOFT, font=FONT_MICRO, anchor="e")
    app.card_rt_val.pack(side="right", padx=(6, 8))
    app.card_rt_sub = tk.Label(guard_strip, text="—", bg=CARD_ALT, fg=MUTED, font=FONT_MICRO, anchor="e")


def dismiss_onboarding(app: Any) -> None:
    app._onboarding_dismissed = True
    if hasattr(app, "_onboarding_frame") and app._onboarding_frame.winfo_manager():
        app._onboarding_frame.pack_forget()


def _on_home_preset_selected(app: Any) -> None:
    if app._preset_cb_syncing:
        return
    app.on_apply_home_preset()


def _on_home_stack_mode_selected(app: Any) -> None:
    if app._stack_mode_syncing:
        return
    want_dpi_only = app.home_stack_mode_var.get() == app._stack_mode_labels[1]
    if bool(app.dpi_only_var.get()) != want_dpi_only:
        app.dpi_only_var.set(want_dpi_only)
        app.on_toggle_dpi_only()
