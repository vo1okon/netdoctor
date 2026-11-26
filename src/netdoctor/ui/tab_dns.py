"""Expert DNS & SmartDNS catalog tab (`DNS`) for netdoctor v2."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any

from netdoctor.ui.theme import (
    ACCENT,
    BG,
    BORDER,
    CARD,
    FG,
    FONT_HERO,
    FONT_SMALL,
    FONT_SMALL_B,
    FONT_UI_B,
    INFO_BG,
    LAVENDER,
    MUTED,
    OK_TEXT,
    PURPLE_BG,
)


def build_dns_tab(app: Any) -> None:
    """Build Expert DNS & SmartDNS tab."""
    tab = app.tab_dns
    hdr = tk.Frame(tab, bg=BG)
    hdr.pack(fill="x", pady=(2, 8))

    app._dns_hdr_right = tk.Frame(hdr, bg=BG)
    app._dns_hdr_right.pack(side="right", anchor="n", padx=(10, 0), pady=(2, 0))
    app.active_dns_pill = tk.Label(
        app._dns_hdr_right,
        text="Основной DNS: Авто",
        bg=INFO_BG,
        fg=ACCENT,
        font=FONT_SMALL_B,
        padx=9,
        pady=4,
        cursor="hand2",
    )
    app.active_dns_pill.pack(side="left")
    app.active_dns_pill.bind("<Button-1>", lambda _e: app.set_dns_category_filter("ALL"))

    app.smart_dns_pill = tk.Label(
        app._dns_hdr_right,
        text="",
        bg=PURPLE_BG,
        fg=LAVENDER,
        font=FONT_SMALL_B,
        padx=9,
        pady=4,
        cursor="hand2",
    )
    app.smart_dns_pill.bind("<Button-1>", lambda _e: app.set_dns_category_filter("ai_bypass"))

    hdr_left = tk.Frame(hdr, bg=BG)
    hdr_left.pack(side="left", fill="x", expand=True)
    tk.Label(hdr_left, text="DNS и нейросети", bg=BG, fg=FG, font=FONT_HERO, anchor="w").pack(anchor="w")
    sub_lbl = tk.Label(
        hdr_left,
        text=(
            "Выберите основной DNS для сети и VPN. "
            "Серверы из «Для ИИ» работают как SmartDNS только для нейросетей и геоблоков."
        ),
        bg=BG,
        fg=MUTED,
        font=FONT_SMALL,
        anchor="w",
        justify="left",
    )
    sub_lbl.pack(fill="x", anchor="w", pady=(2, 0))
    app._bind_responsive_wrap(sub_lbl, min_wrap=220, pad=16)

    bar = tk.Frame(tab, bg=BG)
    bar.pack(fill="x", pady=(0, 8))
    app.roll_base_dns_btn = app.make_button(
        bar, "Подобрать лучший DNS", app.on_roll_base_dns, "cyan_ghost", font=FONT_SMALL_B, padx=9, pady=3
    )
    app.roll_base_dns_btn.pack(side="right", padx=(6, 0))
    app.make_button(
        bar, "Измерить пинг всех", app.on_ping_dns_catalog, "success", font=FONT_SMALL_B, padx=9, pady=3
    ).pack(side="right", padx=(6, 0))

    cat_btns: tuple[tuple[str, str], ...] = (
        ("ALL", "Все"),
        ("popular", "Популярные"),
        ("security", "Безопасные"),
        ("uncommon", "Малоизвестные"),
        ("ai_bypass", "Для ИИ"),
        ("custom", "Мои DNS"),
    )
    for cat_id, label in cat_btns:
        btn = app.make_button(
            bar,
            label,
            lambda c=cat_id: app.set_dns_category_filter(c),
            "pill_active" if cat_id == "ALL" else "neutral",
            font=FONT_SMALL,
            padx=7,
            pady=3,
        )
        btn.pack(side="left", padx=(0, 3))
        app._dns_cat_buttons[cat_id] = btn

    tools_row = tk.Frame(tab, bg=BG)
    tools_row.pack(fill="x", pady=(0, 8))
    tools_row.columnconfigure(0, weight=1, uniform="dnstools")
    tools_row.columnconfigure(1, weight=1, uniform="dnstools")

    roll_box = tk.Frame(tools_row, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
    roll_box.grid(row=0, column=0, sticky="nsew", padx=(0, 5))
    tk.Label(roll_box, text="Персональный DNS для сайта / нейросети", bg=CARD, fg=OK_TEXT, font=FONT_UI_B, anchor="w").pack(
        fill="x", padx=12, pady=(8, 2)
    )
    roll_sub = tk.Label(
        roll_box,
        text="Находит отдельный рабочий DNS для указанного домена или сразу для всех ИИ.",
        bg=CARD,
        fg=MUTED,
        font=FONT_SMALL,
        anchor="w",
        wraplength=280,
        justify="left",
    )
    roll_sub.pack(fill="x", padx=12, pady=(0, 6))
    app._bind_responsive_wrap(roll_sub, min_wrap=200, pad=24)
    r_inner = tk.Frame(roll_box, bg=CARD)
    r_inner.pack(fill="x", padx=12, pady=(0, 10))
    app.make_button(
        r_inner, "Настроить для всех ИИ", app.on_roll_all_ai_dns, "primary", font=FONT_SMALL_B, padx=8, pady=4
    ).pack(side="right", padx=(4, 0))
    app.make_button(
        r_inner, "Подобрать", app.on_roll_dns_domain, "success", font=FONT_SMALL_B, padx=8, pady=4
    ).pack(side="right", padx=(6, 0))
    app.dns_roll_domain_var = tk.StringVar()
    roll_entry = app.make_entry(r_inner, app.dns_roll_domain_var, 10)
    roll_entry.pack(side="left", fill="x", expand=True, ipady=3)
    roll_entry.bind("<Return>", lambda _e: app.on_roll_dns_domain())

    custom_box = tk.Frame(tools_row, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
    custom_box.grid(row=0, column=1, sticky="nsew", padx=(5, 0))
    tk.Label(custom_box, text="Добавить свой DNS-сервер", bg=CARD, fg=ACCENT, font=FONT_UI_B, anchor="w").pack(
        fill="x", padx=12, pady=(8, 4)
    )
    c_row1 = tk.Frame(custom_box, bg=CARD)
    c_row1.pack(fill="x", padx=12, pady=(0, 4))
    tk.Label(c_row1, text="Имя:", bg=CARD, fg=MUTED, font=FONT_SMALL).pack(side="left", padx=(0, 4))
    app.custom_dns_name_var = tk.StringVar()
    app.make_entry(c_row1, app.custom_dns_name_var, 10).pack(side="left", fill="x", expand=True, padx=(0, 8), ipady=2)
    tk.Label(c_row1, text="IP:", bg=CARD, fg=MUTED, font=FONT_SMALL).pack(side="left", padx=(0, 4))
    app.custom_dns_ip_var = tk.StringVar()
    app.make_entry(c_row1, app.custom_dns_ip_var, 11).pack(side="left", fill="x", expand=True, ipady=2)

    c_row2 = tk.Frame(custom_box, bg=CARD)
    c_row2.pack(fill="x", padx=12, pady=(0, 10))
    app.make_button(
        c_row2, "+ Добавить DNS", app.on_add_custom_dns, "primary", font=FONT_SMALL_B, padx=8, pady=4
    ).pack(side="right", padx=(6, 0))
    tk.Label(c_row2, text="DoH URL / заметка:", bg=CARD, fg=MUTED, font=FONT_SMALL).pack(side="left", padx=(0, 4))
    app.custom_dns_desc_var = tk.StringVar()
    app.make_entry(c_row2, app.custom_dns_desc_var, 10).pack(side="left", fill="x", expand=True, ipady=2)

    wrap = tk.Frame(tab, bg=BG, highlightthickness=1, highlightbackground=BORDER)
    wrap.pack(fill="both", expand=True)

    app.dns_canvas = tk.Canvas(wrap, bg=BG, highlightthickness=0)
    dns_vsb = ttk.Scrollbar(wrap, orient="vertical", command=app.dns_canvas.yview)
    app.dns_canvas.configure(yscrollcommand=dns_vsb.set)
    dns_vsb.pack(side="right", fill="y")
    app.dns_canvas.pack(side="left", fill="both", expand=True)

    app.dns_grid_frame = tk.Frame(app.dns_canvas, bg=BG)
    app._dns_window_id = app.dns_canvas.create_window((0, 0), window=app.dns_grid_frame, anchor="nw")

    app.dns_grid_frame.bind(
        "<Configure>",
        lambda _e: app.dns_canvas.configure(scrollregion=app.dns_canvas.bbox("all")),
    )
    app.dns_canvas.bind(
        "<Configure>",
        lambda e: app.dns_canvas.itemconfigure(app._dns_window_id, width=e.width),
    )
    app.dns_canvas.bind("<MouseWheel>", app._on_dns_mousewheel)
    app.dns_grid_frame.bind("<MouseWheel>", app._on_dns_mousewheel)
    app.dns_canvas.bind("<Enter>", lambda _e: app.dns_canvas.bind_all("<MouseWheel>", app._on_dns_mousewheel))
    app.dns_canvas.bind("<Leave>", lambda _e: app.dns_canvas.unbind_all("<MouseWheel>"))
