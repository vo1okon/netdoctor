"""Expert Zapret2 Presets tab (`Пресеты`) for netdoctor v2."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any

from netdoctor.ui.theme import (
    ACCENT,
    BG,
    BORDER,
    BORDER_LIGHT,
    CARD,
    FG,
    FG_SOFT,
    FONT_MONO_S,
    FONT_SMALL,
    FONT_SMALL_B,
    FONT_UI_B,
    MUTED,
    OK_TEXT,
    PRESET_COLUMNS,
    SELECT_BG,
    SIDEBAR_BG,
    WARN_TEXT,
)


def build_presets_tab(app: Any) -> None:
    """Build Expert Zapret2 Presets tab."""
    tab = app.tab_presets
    app._make_page_header(
        tab,
        "Стратегии и пресеты Zapret",
        "Выберите готовый пресет обхода или добавьте свой рабочий (.txt / .bat). Пока выбран пресет, автоподбор на паузе.",
    )

    top_card = tk.Frame(tab, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
    top_card.pack(fill="x", pady=(0, 6))

    r1 = tk.Frame(top_card, bg=CARD)
    r1.pack(fill="x", padx=12, pady=(7, 5))
    app.make_button(r1, "Импорт из папки…", app.on_import_presets_dir, "neutral", font=FONT_SMALL_B, padx=9, pady=4).pack(
        side="right", padx=(4, 0)
    )
    app.make_button(r1, "Загрузить файл…", app.on_import_preset_file, "neutral", font=FONT_SMALL_B, padx=9, pady=4).pack(
        side="right", padx=(4, 0)
    )
    app.make_button(
        r1,
        "Режим автоподбора",
        lambda: app.on_select_zapret_preset("auto"),
        "cyan_ghost",
        font=FONT_SMALL_B,
        padx=9,
        pady=4,
    ).pack(side="right", padx=(6, 0))

    app.presets_active_lbl = tk.Label(
        r1,
        text="Активный режим: Автоподбор (для каждого сайта отдельно)",
        bg=CARD,
        fg=ACCENT,
        font=FONT_UI_B,
        anchor="w",
    )
    app.presets_active_lbl.pack(side="left", fill="x", expand=True)

    tk.Frame(top_card, bg=BORDER_LIGHT, height=1).pack(fill="x", padx=12)

    r2 = tk.Frame(top_card, bg=CARD)
    r2.pack(fill="x", padx=12, pady=(5, 7))

    pill_wrap = tk.Frame(r2, bg=CARD)
    pill_wrap.pack(side="right", padx=(8, 0))
    app._preset_filter_buttons.clear()
    for pf_id, pf_lbl in (("ALL", "Все"), ("user", "Мои рабочие"), ("featured", "Рекомендуемые")):
        btn = app.make_button(
            pill_wrap,
            pf_lbl,
            lambda f=pf_id: app._set_preset_filter(f),
            "pill_active" if pf_id == "ALL" else "neutral",
            font=FONT_SMALL,
            padx=8,
            pady=3,
        )
        btn.pack(side="left", padx=2)
        app._preset_filter_buttons[pf_id] = btn

    tk.Label(r2, text="Поиск пресета:", bg=CARD, fg=MUTED, font=FONT_SMALL_B).pack(side="left", padx=(0, 6))
    app.preset_search_var = tk.StringVar()
    app.preset_search_var.trace_add("write", lambda *_: app.populate_presets_table())
    app.make_entry(r2, app.preset_search_var, 20).pack(side="left", fill="x", expand=True, ipady=2)

    paned = ttk.PanedWindow(tab, orient="vertical")
    paned.pack(fill="both", expand=True)

    top_pane = tk.Frame(paned, bg=BG)
    act_bar = tk.Frame(top_pane, bg=BG)
    act_bar.pack(fill="x", pady=(0, 4))
    app.make_button(
        act_bar, "✔ Включить выбранный", app.on_activate_selected_preset, "hero", font=FONT_SMALL_B, padx=10, pady=4
    ).pack(side="left", padx=(0, 6))
    app.make_button(
        act_bar, "База для Авто", app.on_set_base_selected_preset, "cyan_ghost", font=FONT_SMALL_B, padx=10, pady=4
    ).pack(side="left", padx=(0, 6))
    app.make_button(
        act_bar, "▶ Проверить пресет", app.on_test_selected_preset, "primary", font=FONT_SMALL_B, padx=10, pady=4
    ).pack(side="left", padx=(0, 6))
    app.make_button(
        act_bar, "Изменить в редакторе ↓", app.on_load_selected_preset_to_editor, "neutral", font=FONT_SMALL, padx=8, pady=4
    ).pack(side="left", padx=(0, 6))
    app.make_button(
        act_bar, "Удалить свой", app.on_delete_selected_preset, "danger", font=FONT_SMALL, padx=8, pady=4
    ).pack(side="right")

    tree_wrap = tk.Frame(top_pane, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
    tree_wrap.pack(fill="both", expand=True)
    pcols = tuple(c[0] for c in PRESET_COLUMNS)
    app.presets_tree = app.make_tree(tree_wrap, pcols, height=9)
    for cid, title, width, anchor in PRESET_COLUMNS:
        app.presets_tree.heading(cid, text=title)
        app.presets_tree.column(cid, width=width, anchor=anchor, stretch=cid in ("name", "description"))  # type: ignore[arg-type]
    app.presets_tree.tag_configure("active", foreground=OK_TEXT)
    app.presets_tree.tag_configure("user", foreground=ACCENT)
    app.presets_tree.tag_configure("featured", foreground=WARN_TEXT)
    app.presets_tree.tag_configure("builtin", foreground=FG_SOFT)
    app.presets_tree.bind("<<TreeviewSelect>>", app.on_preset_select)
    app.presets_tree.bind("<Double-1>", lambda _e: app.on_activate_selected_preset())
    app._scrolled(tree_wrap, app.presets_tree, horizontal=True)
    paned.add(top_pane, weight=3)

    ed_card = tk.Frame(paned, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
    ed_hdr = tk.Frame(ed_card, bg=CARD)
    ed_hdr.pack(fill="x", padx=12, pady=(7, 4))
    app.user_preset_activate_var = tk.BooleanVar(value=True)
    app.make_button(
        ed_hdr, "+ Сохранить свой пресет", app.on_add_user_preset, "primary", font=FONT_SMALL_B, padx=10, pady=4
    ).pack(side="right")
    app.make_toggle_row(
        ed_hdr,
        "Включить сразу",
        app.user_preset_activate_var,
        bg=CARD,
        font=FONT_SMALL,
        fg=FG_SOFT,
        slider_width=34,
        slider_height=16,
    ).pack(side="right", padx=(4, 10))
    tk.Label(
        ed_hdr,
        text="Добавить свой рабочий пресет (аргументы winws2 или .bat)",
        bg=CARD,
        fg=OK_TEXT,
        font=FONT_UI_B,
        anchor="w",
    ).pack(side="left", fill="x", expand=True)

    meta_r = tk.Frame(ed_card, bg=CARD)
    meta_r.pack(fill="x", padx=12, pady=(0, 5))
    tk.Label(meta_r, text="Название:", bg=CARD, fg=MUTED, font=FONT_SMALL).pack(side="left", padx=(0, 5))
    app.user_preset_name_var = tk.StringVar()
    app.user_preset_name_entry = app.make_entry(meta_r, app.user_preset_name_var, 22)
    app.user_preset_name_entry.pack(side="left", fill="x", expand=True, padx=(0, 10), ipady=2)
    tk.Label(meta_r, text="Заметка:", bg=CARD, fg=MUTED, font=FONT_SMALL).pack(side="left", padx=(0, 5))
    app.user_preset_desc_var = tk.StringVar()
    app.make_entry(meta_r, app.user_preset_desc_var, 24).pack(side="left", fill="x", expand=True, ipady=2)

    txt_wrap = tk.Frame(ed_card, bg=SIDEBAR_BG, highlightthickness=1, highlightbackground=BORDER)
    txt_wrap.pack(fill="both", expand=True, padx=12, pady=(0, 8))
    app.user_preset_text = tk.Text(
        txt_wrap,
        height=5,
        wrap="none",
        undo=True,
        bg=SIDEBAR_BG,
        fg=FG,
        insertbackground=ACCENT,
        relief="flat",
        highlightthickness=0,
        font=FONT_MONO_S,
        padx=8,
        pady=6,
        selectbackground=SELECT_BG,
        selectforeground="#FFFFFF",
    )
    app._scrolled(txt_wrap, app.user_preset_text, horizontal=True)
    paned.add(ed_card, weight=2)
