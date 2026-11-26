"""Expert Monitor & Domains tab (`Монитор`) for netdoctor v2."""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk
from typing import Any

from netdoctor.ui.theme import (
    ACCENT,
    BG,
    BORDER,
    BORDER_LIGHT,
    CARD,
    CARD_ALT,
    CONN_COLUMNS,
    DIM,
    DOMAIN_COLUMNS,
    ERR_TEXT,
    FG,
    FG_SOFT,
    FONT_H2,
    FONT_HERO,
    FONT_MICRO,
    FONT_SMALL,
    FONT_SMALL_B,
    FONT_UI_B,
    INPUT,
    LAVENDER,
    LAYER_FILTERS,
    LAYER_FILTER_LABELS,
    MUTED,
    OK_BG,
    OK_TEXT,
    OVERRIDE_LAYERS,
    OVERRIDE_LAYER_HINTS,
    PILL_ACTIVE_BG,
    PILL_ACTIVE_BORDER,
    PURPLE,
    SELECT_BG,
    SIDEBAR_BG,
    WARN_BG,
    WARN_TEXT,
)
from netdoctor.ui.widgets import LiveSparklineCanvas, RoundedCard


def build_monitor_tab(app: Any) -> None:
    """Build unified Expert Monitor (Domains + Live Connections + Rule Inspector)."""
    tab = app.tab_domains
    hdr = tk.Frame(tab, bg=BG)
    hdr.pack(fill="x", pady=(2, 6))

    app.radar_btn = app.make_button(
        hdr,
        "⏹ Остановить мониторинг",
        app.on_toggle_radar,
        "danger",
        font=FONT_SMALL_B,
        padx=10,
        pady=4,
        tooltip="Включает или приостанавливает сканирование активных подключений ПК в реальном времени.",
    )
    app.radar_btn.pack(side="right", padx=(8, 0))

    title_col = tk.Frame(hdr, bg=BG)
    title_col.pack(side="left", fill="x", expand=True)
    t_row = tk.Frame(title_col, bg=BG)
    t_row.pack(fill="x")
    tk.Label(t_row, text="МОНИТОР И ПРАВИЛА", bg=BG, fg=FG, font=FONT_HERO, anchor="w").pack(side="left")
    tk.Label(
        t_row,
        text="  LIVE  ",
        bg=PILL_ACTIVE_BG,
        fg=LAVENDER,
        font=FONT_MICRO,
        padx=6,
        pady=2,
    ).pack(side="left", padx=(8, 0))
    sub_lbl = tk.Label(
        title_col,
        text="Живая активность подключений, правила для сайтов и авто-маршруты программ и игр.",
        bg=BG,
        fg=MUTED,
        font=FONT_SMALL,
        anchor="w",
        justify="left",
    )
    sub_lbl.pack(fill="x", anchor="w", pady=(2, 0))
    app._bind_responsive_wrap(sub_lbl, min_wrap=260, pad=16)

    switch_bar = tk.Frame(tab, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
    switch_bar.pack(fill="x", pady=(0, 6))

    sw_row = tk.Frame(switch_bar, bg=CARD)
    sw_row.pack(fill="x", padx=12, pady=6)

    app.make_button(
        sw_row,
        "▶ Проверить все сайты",
        lambda: app.on_run_connectivity_tests(include_picked=True),
        "cyan_ghost",
        font=FONT_SMALL_B,
        padx=10,
        pady=4,
        tooltip="Проверяет доступность всех сайтов из таблицы ниже.",
    ).pack(side="right", padx=(6, 0))

    app._subtab_domains_btn = app.make_button(
        sw_row,
        "Сайты (0)",
        lambda: app._switch_domains_subview("domains"),
        "pill_active",
        font=FONT_SMALL_B,
        padx=10,
        pady=4,
    )
    app._subtab_domains_btn.pack(side="left", padx=(0, 4))

    app._subtab_bundles_btn = app.make_button(
        sw_row,
        "Программы и игры (0)",
        lambda: app._switch_domains_subview("bundles"),
        "neutral",
        font=FONT_SMALL_B,
        padx=10,
        pady=4,
    )
    app._subtab_bundles_btn.pack(side="left", padx=(0, 4))

    app._subtab_conns_btn = app.make_button(
        sw_row,
        "Активные подключения (0)",
        lambda: app._switch_domains_subview("connections"),
        "neutral",
        font=FONT_SMALL_B,
        padx=10,
        pady=4,
    )
    app._subtab_conns_btn.pack(side="left", padx=(0, 10))

    app._domains_test_summary_lbl = tk.Label(
        sw_row,
        text="Успех проверок: —  •  Сайтов: 0  •  Подключений: 0",
        bg=CARD,
        fg=FG_SOFT,
        font=FONT_SMALL_B,
        anchor="w",
    )
    app._domains_test_summary_lbl.pack(side="left", fill="x", expand=True)

    app._domains_view_container = tk.Frame(tab, bg=BG)
    app._domains_view_container.pack(fill="both", expand=True)

    # ---- Sub-view 1: Domains & Inspector ----
    app._domains_subview = tk.Frame(app._domains_view_container, bg=BG)
    app._domains_subview.pack(fill="both", expand=True)

    toolbar = tk.Frame(app._domains_subview, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
    toolbar.pack(fill="x", pady=(0, 6))

    filt_top = tk.Frame(toolbar, bg=CARD)
    filt_top.pack(fill="x", padx=12, pady=(7, 4))

    app.layer_filter_var = tk.StringVar(value="ALL")
    app.layer_filter_var.trace_add("write", lambda *_: app._sync_domain_filter_pills())
    pill_box = tk.Frame(filt_top, bg=CARD)
    pill_box.pack(side="right", padx=(8, 0))
    app._domain_filter_buttons.clear()
    for lid in LAYER_FILTERS:
        btn = app.make_button(
            pill_box,
            LAYER_FILTER_LABELS.get(lid, lid),
            lambda c=lid: app._set_domain_layer_filter(c),
            "pill_active" if lid == "ALL" else "neutral",
            font=FONT_SMALL,
            padx=8,
            pady=3,
        )
        btn.pack(side="left", padx=2)
        app._domain_filter_buttons[lid] = btn

    tk.Label(filt_top, text="Поиск:", bg=CARD, fg=MUTED, font=FONT_SMALL_B).pack(side="left", padx=(0, 6))
    app.search_var = tk.StringVar()
    app.search_var.trace_add("write", lambda *_: app.populate_domain_table())
    app.search_entry = app.make_entry(filt_top, app.search_var, 18)
    app.search_entry.pack(side="left", fill="x", expand=True, ipady=3)
    app.make_button(
        filt_top,
        "✕",
        lambda: app.search_var.set(""),
        "ghost",
        font=FONT_SMALL,
        padx=6,
        pady=2,
    ).pack(side="left", padx=(4, 0))

    tk.Frame(toolbar, bg=BORDER_LIGHT, height=1).pack(fill="x", padx=12)

    filt_bot = tk.Frame(toolbar, bg=CARD)
    filt_bot.pack(fill="x", padx=12, pady=(5, 7))
    app.make_button(
        filt_bot,
        "Проверить популярные сайты",
        app.on_diag_all,
        "neutral",
        font=FONT_SMALL_B,
        padx=10,
        pady=3,
    ).pack(side="right", padx=(8, 0))
    tk.Label(filt_bot, text="Добавить сайт:", bg=CARD, fg=ACCENT, font=FONT_SMALL_B).pack(side="left", padx=(0, 6))
    app.new_domain_var = tk.StringVar()
    entry = app.make_entry(filt_bot, app.new_domain_var, 22)
    entry.pack(side="left", fill="x", expand=True, ipady=3)
    entry.bind("<Return>", lambda _e: app.on_check_new_domain())
    app.make_button(
        filt_bot,
        "Подобрать обход",
        app.on_check_new_domain,
        "primary",
        font=FONT_SMALL_B,
        padx=10,
        pady=3,
    ).pack(side="left", padx=(8, 0))

    paned = ttk.PanedWindow(app._domains_subview, orient="vertical")
    paned.pack(fill="both", expand=True)

    tree_wrap = tk.Frame(paned, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
    cols = tuple(c[0] for c in DOMAIN_COLUMNS)
    app.domain_tree = app.make_tree(tree_wrap, cols, height=8)
    for cid, title, width, anchor in DOMAIN_COLUMNS:
        heading_txt = f"{title} ▲" if cid == "domain" else title
        app.domain_tree.heading(cid, text=heading_txt, command=lambda c=cid: app.sort_domains(c))
        app.domain_tree.column(cid, width=width, anchor=anchor, stretch=cid in ("domain", "strategy"))  # type: ignore[arg-type]
    app.domain_tree.tag_configure("dpi", foreground=ACCENT)
    app.domain_tree.tag_configure("vpn", foreground=WARN_TEXT)
    app.domain_tree.tag_configure("dns", foreground=PURPLE)
    app.domain_tree.tag_configure("direct", foreground=OK_TEXT)
    app.domain_tree.tag_configure("other", foreground=FG)
    app.domain_tree.tag_configure("degraded", foreground=ERR_TEXT)
    app.domain_tree.tag_configure("expired", foreground=MUTED)
    app.domain_tree.bind("<<TreeviewSelect>>", app.on_domain_select)
    app.domain_tree.bind("<Button-3>", app._on_domain_context_menu)
    app._scrolled(tree_wrap, app.domain_tree, horizontal=True)
    paned.add(tree_wrap, weight=5)

    paned.add(app._build_inspector(paned), weight=4)

    app._domain_menu = tk.Menu(app, tearoff=0, bg=CARD_ALT, fg=FG, activebackground=SELECT_BG, activeforeground="#FFFFFF")
    app._domain_menu.add_command(label="▶ Проверить доступность сейчас", command=app.on_test_selected_domain)
    app._domain_menu.add_command(label="⚡ Подобрать лучший обход (все слои)", command=app.on_find_best_bypass_selected)
    app._domain_menu.add_command(label="📌 Зафиксировать / Снять фиксацию", command=app.on_toggle_pin_selected)
    app._domain_menu.add_separator()
    app._domain_menu.add_command(label="Подобрать обход DPI", command=app.on_recheck_selected)
    app._domain_menu.add_command(label="Подобрать персональный DNS", command=app.on_roll_dns_selected)
    app._domain_menu.add_command(label="Глубокий поиск стратегии (blockcheck2)", command=app.on_blockcheck2_selected)
    app._domain_menu.add_separator()
    app._domain_menu.add_command(label="Направить через VPN", command=lambda: app._quick_pin_selected("vpn", "vpn-select"))
    app._domain_menu.add_command(label="Открывать напрямую (без обхода)", command=lambda: app._quick_pin_selected("direct", None))
    app._domain_menu.add_command(label="Копировать адрес сайта", command=app._copy_selected_domain)

    # ---- Sub-view 2: Live Connections ----
    app._conns_subview = tk.Frame(app._domains_view_container, bg=BG)
    build_conns_subview(app, app._conns_subview)

    # ---- Sub-view 3: Programs & Games (AppBundles) ----
    app._bundles_subview = tk.Frame(app._domains_view_container, bg=BG)
    build_bundles_subview(app, app._bundles_subview)


def build_conns_subview(app: Any, parent: tk.Frame) -> None:
    metrics = tk.Frame(parent, bg=BG)
    metrics.pack(fill="x", pady=(0, 6))
    for col in range(3):
        metrics.columnconfigure(col, weight=1, uniform="rt_metrics")

    def _metric_card(col: int, title: str, fg_col: str, note: str) -> tk.Label:
        wrap = RoundedCard(metrics, bg=CARD, outer_bg=BG, border=BORDER, radius=13, pad=2)
        wrap.grid(row=0, column=col, sticky="nsew", padx=(0 if col == 0 else 4, 0 if col == 2 else 4))
        c = wrap.body
        tk.Label(c, text=title, bg=CARD, fg=MUTED, font=FONT_MICRO, anchor="w").pack(fill="x", padx=12, pady=(5, 1))
        val = tk.Label(c, text="0", bg=CARD, fg=fg_col, font=("Segoe UI", 16, "bold"), anchor="w")
        val.pack(fill="x", padx=12)
        tk.Label(c, text=note, bg=CARD, fg=DIM, font=FONT_MICRO, anchor="w").pack(fill="x", padx=12, pady=(0, 5))
        return val

    app._rt_metric_total = _metric_card(0, "ПОДКЛЮЧЕНИЯ", FG, "Всего активных соединений")
    app._rt_metric_prot = _metric_card(1, "ПОД ЗАЩИТОЙ", ACCENT, "Обрабатываются обходом")
    app._rt_metric_fix = _metric_card(2, "ТРЕБУЮТ ВНИМАНИЯ", LAVENDER, "Зависшие или без правила")

    chart_wrap = RoundedCard(parent, bg=CARD, outer_bg=BG, border=BORDER, radius=13, pad=2)
    chart_wrap.pack(fill="x", pady=(0, 6))
    chart_card = chart_wrap.body
    ch_hdr = tk.Frame(chart_card, bg=CARD)
    ch_hdr.pack(fill="x", padx=12, pady=(5, 0))
    tk.Label(ch_hdr, text="АКТИВНОСТЬ В РЕАЛЬНОМ ВРЕМЕНИ", bg=CARD, fg=MUTED, font=FONT_MICRO).pack(side="left")
    tk.Label(ch_hdr, text="● ВСЕГО", bg=CARD, fg=LAVENDER, font=FONT_MICRO).pack(side="right", padx=(8, 0))
    tk.Label(ch_hdr, text="● ПОД ЗАЩИТОЙ", bg=CARD, fg=ACCENT, font=FONT_MICRO).pack(side="right")
    app.sparkline_canvas = LiveSparklineCanvas(chart_card, height=74, bg=CARD)
    app.sparkline_canvas.pack(fill="x", padx=6, pady=(2, 4))

    bar_wrap = RoundedCard(parent, bg=CARD, outer_bg=BG, border=BORDER, radius=13, pad=2)
    bar_wrap.pack(fill="x", pady=(0, 6))
    bar = bar_wrap.body

    top_r = tk.Frame(bar, bg=CARD)
    top_r.pack(fill="x", padx=12, pady=(5, 4))

    app.make_button(top_r, "Обновить список", app.refresh_realtime_async, "neutral", font=FONT_SMALL_B, pady=3).pack(
        side="right", padx=(6, 0)
    )
    app.conn_vpn_btn = app.make_button(
        top_r, "Через VPN", app._toggle_selected_conn_process_vpn, "cyan_ghost", font=FONT_SMALL_B, pady=3
    )
    app.conn_vpn_btn.pack(side="right", padx=(6, 0))
    app.make_button(
        top_r, "Подобрать обход", app.on_heal_selected_connection, "primary", font=FONT_SMALL_B, pady=3
    ).pack(side="right", padx=(8, 0))
    app._rt_summary_lbl = tk.Label(
        top_r,
        text="Всего: 0  •  Под защитой: 0  •  Нужна починка: 0  •  Напрямую: 0",
        bg=CARD,
        fg=FG_SOFT,
        font=FONT_SMALL_B,
        anchor="w",
    )
    app._rt_summary_lbl.pack(side="left", fill="x", expand=True)

    tk.Frame(bar, bg=BORDER_LIGHT, height=1).pack(fill="x", padx=12)

    bot_r = tk.Frame(bar, bg=CARD)
    bot_r.pack(fill="x", padx=12, pady=(4, 5))

    pill_wrap = tk.Frame(bot_r, bg=CARD)
    pill_wrap.pack(side="right", padx=(8, 0))
    app._conn_filter_buttons.clear()
    for fid, flabel in (("ALL", "Все"), ("needs_fix", "Требуют обхода"), ("protected", "Под защитой")):
        btn = app.make_button(
            pill_wrap,
            flabel,
            lambda f=fid: app._set_conn_health_filter(f),
            "pill_active" if fid == "ALL" else "neutral",
            font=FONT_SMALL,
            padx=8,
            pady=3,
        )
        btn.pack(side="left", padx=2)
        app._conn_filter_buttons[fid] = btn

    app.auto_heal_var = tk.BooleanVar(value=True)
    ah_row = app.make_toggle_row(
        bot_r,
        "Автоподбор обхода для зависших веб-подключений (80/443)",
        app.auto_heal_var,
        command=app.on_toggle_auto_heal,
        bg=CARD,
        font=FONT_SMALL_B,
        fg=FG,
        slider_width=36,
        slider_height=18,
    )
    ah_row.pack(side="left", fill="x", expand=True, padx=(0, 8))

    paned = ttk.PanedWindow(parent, orient="vertical")
    paned.pack(fill="both", expand=True)

    conn_wrap = tk.Frame(paned, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
    cols = tuple(c[0] for c in CONN_COLUMNS)
    app.conn_tree = app.make_tree(conn_wrap, cols, height=8)
    for cid, title, width, anchor in CONN_COLUMNS:
        app.conn_tree.heading(cid, text=title)
        app.conn_tree.column(cid, width=width, anchor=anchor, stretch=cid in ("domain", "strategy"))  # type: ignore[arg-type]
    app.conn_tree.tag_configure("protected", foreground=ACCENT)
    app.conn_tree.tag_configure("needs_fix", foreground=ERR_TEXT)
    app.conn_tree.tag_configure("direct", foreground=MUTED)
    app.conn_tree.bind("<<TreeviewSelect>>", app.on_conn_select)
    app.conn_tree.bind("<Double-1>", lambda _e: app.on_heal_selected_connection())
    app.conn_tree.bind("<Button-3>", app._on_conn_context_menu)
    app._scrolled(conn_wrap, app.conn_tree, horizontal=True)
    paned.add(conn_wrap, weight=3)

    app._conn_menu = tk.Menu(app, tearoff=0, bg=CARD_ALT, fg=FG, activebackground=SELECT_BG, activeforeground="#FFFFFF")
    app._conn_menu.add_command(label="Подобрать обход для этого сайта", command=app.on_heal_selected_connection)
    app._conn_menu.add_command(label="Показать в таблице сайтов", command=app._open_selected_conn_domain)
    app._conn_menu.add_command(label="Копировать адрес сайта", command=app._copy_selected_conn_domain)
    app._conn_menu.add_separator()
    app._conn_menu_vpn_idx = 4
    app._conn_menu.add_command(label="Направить приложение через VPN", command=app._toggle_selected_conn_process_vpn)

    feed_panel = tk.Frame(paned, bg=BG)
    tk.Label(
        feed_panel,
        text="Журнал подключений и автоподбора",
        bg=BG,
        fg=ACCENT,
        font=FONT_SMALL_B,
        anchor="w",
    ).pack(fill="x", pady=(4, 3))
    feed_box = tk.Frame(feed_panel, bg=SIDEBAR_BG, highlightthickness=1, highlightbackground=BORDER)
    feed_box.pack(fill="both", expand=True)
    app.realtime_feed = app.make_text(feed_box, height=4, wrap="word")
    app.realtime_feed.tag_configure("ok", foreground=OK_TEXT)
    app.realtime_feed.tag_configure("muted", foreground=MUTED)
    app._scrolled(feed_box, app.realtime_feed)
    paned.add(feed_panel, weight=1)


def build_inspector(app: Any, parent: tk.Misc) -> tk.Frame:
    panel = tk.Frame(parent, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
    panel.rowconfigure(0, weight=1, minsize=185)
    panel.columnconfigure(0, weight=7, minsize=340)
    panel.columnconfigure(1, weight=4, minsize=320)

    left = tk.Frame(panel, bg=CARD)
    left.grid(row=0, column=0, sticky="nsew", padx=(12, 6), pady=8)
    app.inspector_title = tk.Label(
        left, text="Выберите сайт в таблице выше, чтобы увидеть результаты проверок", bg=CARD, fg=ACCENT, font=FONT_UI_B, anchor="w"
    )
    app.inspector_title.pack(fill="x")
    box = tk.Frame(left, bg=SIDEBAR_BG, highlightthickness=1, highlightbackground=BORDER)
    box.pack(fill="both", expand=True, pady=(6, 0))
    app.inspector = app.make_text(box, height=7, wrap="word")
    app.inspector.tag_configure("h", foreground=ACCENT, font=("Consolas", 10, "bold"))
    app.inspector.tag_configure("ok", foreground=OK_TEXT)
    app.inspector.tag_configure("bad", foreground=ERR_TEXT)
    app.inspector.tag_configure("muted", foreground=MUTED)
    app.inspector.tag_configure("warn", foreground=WARN_TEXT)
    app.inspector.tag_configure("args", foreground="#93C5FD")
    app.inspector.configure(state="normal")
    app.inspector.insert(
        "1.0",
        "Выберите любой сайт в таблице выше — здесь появятся причины блокировки, "
        "подобранная стратегия и история проверок.\n",
        "muted",
    )
    app.inspector.configure(state="disabled")
    app._scrolled(box, app.inspector)

    right_outer = tk.Frame(panel, bg=CARD_ALT, highlightthickness=1, highlightbackground=BORDER)
    right_outer.grid(row=0, column=1, sticky="nsew", padx=(6, 10), pady=8)

    app.rule_canvas = tk.Canvas(
        right_outer, bg=CARD_ALT, highlightthickness=0, bd=0, height=195, yscrollincrement=18
    )
    rule_vsb = ttk.Scrollbar(right_outer, orient="vertical")
    app._rule_vsb = rule_vsb

    right = tk.Frame(app.rule_canvas, bg=CARD_ALT)
    app._rule_form_frame = right

    def _sync_rule_scrollbar(first: str, last: str) -> None:
        rule_vsb.set(first, last)
        try:
            canv_h = app.rule_canvas.winfo_height()
            req_h = right.winfo_reqheight()
            need_scroll = (req_h > canv_h + 4) if canv_h > 10 else (float(first) > 0.001 or float(last) < 0.999)
            if need_scroll:
                if not rule_vsb.winfo_ismapped():
                    rule_vsb.pack(side="right", fill="y")
            elif rule_vsb.winfo_ismapped() and (canv_h <= 10 or req_h <= canv_h - 4):
                rule_vsb.pack_forget()
                app.rule_canvas.yview_moveto(0.0)
        except (ValueError, tk.TclError):
            pass

    rule_vsb.configure(command=app.rule_canvas.yview)
    app.rule_canvas.configure(yscrollcommand=_sync_rule_scrollbar)
    app.rule_canvas.pack(side="left", fill="both", expand=True)

    app._rule_window_id = app.rule_canvas.create_window((0, 0), window=right, anchor="nw")

    def _on_rule_frame_cfg(_e: Any = None) -> None:
        try:
            bbox = app.rule_canvas.bbox("all")
            if bbox:
                app.rule_canvas.configure(scrollregion=bbox)
        except tk.TclError:
            pass

    def _on_rule_canvas_cfg(e: Any) -> None:
        try:
            w = max(240, int(getattr(e, "width", 0)))
            app.rule_canvas.itemconfigure(app._rule_window_id, width=w)
            bbox = app.rule_canvas.bbox("all")
            if bbox:
                app.rule_canvas.configure(scrollregion=bbox)
        except tk.TclError:
            pass

    right.bind("<Configure>", _on_rule_frame_cfg)
    app.rule_canvas.bind("<Configure>", _on_rule_canvas_cfg)

    tk.Label(right, text="Настройка правила", bg=CARD_ALT, fg=FG, font=FONT_UI_B, anchor="w").pack(
        fill="x", padx=10, pady=(5, 0)
    )
    sub_rule_lbl = tk.Label(
        right,
        text="Запустите автоподбор или задайте способ обхода вручную:",
        bg=CARD_ALT,
        fg=MUTED,
        font=FONT_SMALL,
        anchor="w",
        justify="left",
    )
    sub_rule_lbl.pack(fill="x", padx=10, pady=(0, 3))
    app._bind_responsive_wrap(sub_rule_lbl, min_wrap=200, pad=20)

    app.best_bypass_btn = app.make_button(
        right,
        "⚡ Подобрать лучший (все слои)",
        app.on_find_best_bypass_selected,
        "primary",
        font=FONT_SMALL_B,
        padx=6,
        pady=3,
    )
    app.best_bypass_btn.pack(fill="x", padx=10, pady=(0, 3))

    auto_row = tk.Frame(right, bg=CARD_ALT)
    auto_row.pack(fill="x", padx=10, pady=(0, 4))
    app.make_button(auto_row, "▶ Проверить", app.on_test_selected_domain, "success", font=FONT_SMALL_B, padx=5, pady=2).pack(
        side="left", fill="x", expand=True, padx=(0, 3)
    )
    app.make_button(auto_row, "Подбор DPI", app.on_recheck_selected, "primary", font=FONT_SMALL_B, padx=5, pady=2).pack(
        side="left", fill="x", expand=True, padx=(0, 3)
    )
    app.make_button(auto_row, "Подбор DNS", app.on_roll_dns_selected, "neutral", font=FONT_SMALL_B, padx=5, pady=2).pack(
        side="left", fill="x", expand=True
    )

    tk.Frame(right, bg=BORDER_LIGHT, height=1).pack(fill="x", padx=10, pady=(0, 3))

    tk.Label(right, text="Способ обхода и правило вручную:", bg=CARD_ALT, fg=FG_SOFT, font=FONT_SMALL_B, anchor="w").pack(
        fill="x", padx=10
    )
    app.override_layer_var = tk.StringVar(value="dpi")
    app.override_layer_cb = ttk.Combobox(
        right, textvariable=app.override_layer_var, values=OVERRIDE_LAYERS, state="readonly"
    )
    app.override_layer_cb.pack(fill="x", padx=10, pady=(2, 1))
    app.override_layer_cb.bind("<<ComboboxSelected>>", lambda _e: app._on_override_layer_changed())

    app._override_layer_hint_lbl = tk.Label(
        right,
        text=OVERRIDE_LAYER_HINTS["dpi"],
        bg=CARD_ALT,
        fg=MUTED,
        font=FONT_SMALL,
        anchor="w",
        wraplength=280,
        justify="left",
    )
    app._override_layer_hint_lbl.pack(fill="x", padx=10, pady=(0, 3))
    app._bind_responsive_wrap(app._override_layer_hint_lbl, min_wrap=200, pad=20)

    app.override_strategy_var = tk.StringVar()
    app.override_strategy_cb = ttk.Combobox(right, textvariable=app.override_strategy_var, state="readonly")
    app.override_strategy_cb.pack(fill="x", padx=10, pady=(0, 4))

    pin_row = tk.Frame(right, bg=CARD_ALT)
    pin_row.pack(fill="x", padx=10, pady=(0, 6))
    app.pin_btn = app.make_button(pin_row, "Сохранить правило", app.on_pin, "hero", font=FONT_SMALL_B, padx=8, pady=3)
    app.pin_btn.pack(side="left", fill="x", expand=True, padx=(0, 4))
    app.unpin_btn = app.make_button(
        pin_row, "Снять фиксацию", app.on_toggle_pin_selected, "neutral", font=FONT_SMALL, padx=8, pady=3
    )
    app.unpin_btn.pack(side="left")

    app._bind_rule_mousewheel(right_outer)
    return panel


def build_bundles_subview(app: Any, parent: tk.Frame) -> None:
    """Build the Expert `Программы и игры` subview inside `Монитор и правила`."""
    ctrl_wrap = RoundedCard(parent, bg=CARD, outer_bg=BG, border=BORDER, radius=13, pad=2)
    ctrl_wrap.pack(fill="x", pady=(0, 6))
    ctrl = ctrl_wrap.body
    top_row = tk.Frame(ctrl, bg=CARD)
    top_row.pack(fill="x", padx=12, pady=7)

    tk.Label(top_row, text="Поиск:", bg=CARD, fg=MUTED, font=FONT_SMALL_B).pack(side="left", padx=(0, 6))
    app.apps_search_var = tk.StringVar()
    app.apps_search_var.trace_add("write", lambda *_: render_bundles_subview(app))
    app.make_entry(top_row, app.apps_search_var, 26).pack(side="left", fill="x", expand=True, ipady=3)

    app.make_button(
        top_row,
        "+ Добавить свою программу",
        lambda: open_add_bundle_dialog(app),
        "primary",
        font=FONT_SMALL_B,
        padx=10,
        pady=3,
        tooltip="Создать свой профиль (.exe процессы) и подобрать маршрут.",
    ).pack(side="right", padx=(10, 0))

    app._apps_alert_card = RoundedCard(parent, bg=WARN_BG, outer_bg=BG, border="#F59E0B", radius=12, pad=2)
    alert_body = app._apps_alert_card.body
    app._apps_alert_btns = tk.Frame(alert_body, bg=WARN_BG)
    app._apps_alert_btns.pack(side="right", padx=10, pady=5)
    app._apps_alert_lbl = tk.Label(
        alert_body,
        text="",
        bg=WARN_BG,
        fg=WARN_TEXT,
        font=FONT_SMALL_B,
        anchor="w",
        justify="left",
    )
    app._apps_alert_lbl.pack(side="left", fill="x", expand=True, padx=(12, 8), pady=5)
    app._bind_responsive_wrap(app._apps_alert_lbl, min_wrap=220, pad=24)

    outer_wrap = tk.Frame(parent, bg=BG, highlightthickness=1, highlightbackground=BORDER)
    outer_wrap.pack(fill="both", expand=True)

    canvas = tk.Canvas(outer_wrap, bg=BG, highlightthickness=0, bd=0)
    vsb = ttk.Scrollbar(outer_wrap, orient="vertical", command=canvas.yview)
    canvas.configure(yscrollcommand=vsb.set)
    vsb.pack(side="right", fill="y")
    canvas.pack(side="left", fill="both", expand=True)

    app.apps_list_frame = tk.Frame(canvas, bg=BG)
    win_id = canvas.create_window((0, 0), window=app.apps_list_frame, anchor="nw")
    app._apps_canvas = canvas
    app._apps_win_id = win_id
    app.apps_list_frame.bind("<Configure>", lambda _e=None: canvas.configure(scrollregion=canvas.bbox("all")))
    canvas.bind("<Configure>", lambda e: canvas.itemconfigure(win_id, width=max(320, int(e.width))))
    app._bundle_items_cache: list[dict[str, Any]] = []
    app._bundle_alerts_cache: list[dict[str, Any]] = []


def render_bundles_subview(app: Any, status_payload: dict[str, Any] | None = None) -> None:
    """Render AppBundle cards inside Monitor -> `Программы и игры` with auto-ladder & pin overrides."""
    if not hasattr(app, "apps_list_frame"):
        return
    if status_payload is not None:
        app._bundle_items_cache = list(status_payload.get("bundles") or [])
        app._bundle_alerts_cache = list(status_payload.get("alerts") or [])

    if hasattr(app, "_subtab_bundles_btn"):
        run_cnt = sum(1 for i in app._bundle_items_cache if i.get("running"))
        tot_cnt = len(app._bundle_items_cache)
        lbl_txt = f"Программы и игры ({run_cnt}/{tot_cnt})" if run_cnt else f"Программы и игры ({tot_cnt})"
        app._restyle_button(
            app._subtab_bundles_btn,
            lbl_txt,
            "pill_active" if getattr(app, "_domains_subview_mode", "domains") == "bundles" else "neutral",
        )

    alerts = app._bundle_alerts_cache
    for w in app._apps_alert_btns.winfo_children():
        w.destroy()
    if alerts:
        top_alert = alerts[0]
        b_name = str(top_alert.get("bundle_name") or top_alert.get("process") or "Приложение")
        b_id = str(top_alert.get("bundle_id") or "")
        proc_name = str(top_alert.get("process") or "")
        msg = f"У {b_name} проблемы со связью — подобрать другой маршрут?"
        app._apps_alert_lbl.configure(text=msg)
        if b_id or proc_name:
            app.make_button(
                app._apps_alert_btns,
                "Подобрать маршрут",
                lambda bid=b_id, pn=proc_name: app.on_escalate_bundle_alert(bid, pn),
                "warn",
                font=FONT_SMALL_B,
                padx=10,
                pady=3,
            ).pack(side="left", padx=(0, 6))
        app.make_button(
            app._apps_alert_btns,
            "Скрыть",
            lambda key=(b_id or proc_name): app.on_dismiss_bundle_alert(key),
            "neutral",
            font=FONT_SMALL_B,
            padx=8,
            pady=3,
        ).pack(side="left")
        if not app._apps_alert_card.winfo_manager():
            app._apps_alert_card.pack(fill="x", pady=(0, 6), before=app._apps_canvas.master)
    else:
        if app._apps_alert_card.winfo_manager():
            app._apps_alert_card.pack_forget()

    needle = app.apps_search_var.get().strip().lower() if hasattr(app, "apps_search_var") else ""
    items = [
        it
        for it in app._bundle_items_cache
        if not needle
        or needle in str(it.get("name") or "").lower()
        or any(needle in str(p).lower() for p in (it.get("processes") or []))
    ]
    items.sort(key=lambda x: (0 if x.get("running") else 1, str(x.get("name") or "").lower()))

    sig = tuple(
        (
            str(i.get("id")),
            str(i.get("mode")),
            bool(i.get("pinned")),
            bool(i.get("running")),
            tuple(i.get("running_processes") or ()),
        )
        for i in items
    )
    if getattr(app, "_last_apps_render_sig", None) == sig and len(app.apps_list_frame.winfo_children()) == len(items):
        return
    app._last_apps_render_sig = sig

    for w in app.apps_list_frame.winfo_children():
        w.destroy()

    if not items:
        tk.Label(app.apps_list_frame, text="Совпадений не найдено.", bg=BG, fg=MUTED, font=FONT_SMALL, pady=18).pack(
            fill="x"
        )
        return

    mode_defs: tuple[tuple[str, str], ...] = (
        ("direct_clean", "Напрямую"),
        ("direct_dpi", "DPI"),
        ("vpn", "VPN"),
    )
    cat_labels = {"game": "Игра", "app": "Программа", "custom": "Своё"}

    for item in items:
        bid = str(item.get("id") or "")
        name = str(item.get("name") or bid)
        icon = str(item.get("icon") or "🎮")
        mode = str(item.get("mode") or "direct_clean")
        pinned = bool(item.get("pinned"))
        cat = str(item.get("category") or "game")
        running = bool(item.get("running"))
        run_procs = list(item.get("running_processes") or [])
        procs = list(item.get("processes") or [])
        is_game = cat == "game" or bool(item.get("vpn_required"))

        card_wrap = RoundedCard(
            app.apps_list_frame,
            bg=CARD,
            outer_bg=BG,
            border=PILL_ACTIVE_BORDER if running else BORDER,
            radius=12,
            pad=2,
        )
        card_wrap.pack(fill="x", padx=6, pady=3)
        body = card_wrap.body

        row = tk.Frame(body, bg=CARD)
        row.pack(fill="x", padx=12, pady=7)

        info_col = tk.Frame(row, bg=CARD)
        info_col.pack(side="left", fill="x", expand=True)

        title_line = tk.Frame(info_col, bg=CARD)
        title_line.pack(fill="x")
        tk.Label(title_line, text=f"{icon}  {name}", bg=CARD, fg=FG, font=FONT_UI_B, anchor="w").pack(side="left")
        tk.Label(
            title_line,
            text=cat_labels.get(cat, cat),
            bg=INPUT,
            fg=LAVENDER,
            font=FONT_MICRO,
            padx=6,
            pady=1,
        ).pack(side="left", padx=(6, 0))
        if pinned:
            tk.Label(
                title_line,
                text="📌 Закреплено",
                bg=WARN_BG,
                fg=WARN_TEXT,
                font=FONT_MICRO,
                padx=6,
                pady=1,
            ).pack(side="left", padx=(6, 0))
        else:
            tk.Label(
                title_line,
                text="Авто",
                bg=CARD_ALT,
                fg=MUTED,
                font=FONT_MICRO,
                padx=6,
                pady=1,
            ).pack(side="left", padx=(6, 0))
        if running:
            tk.Label(
                title_line,
                text=f"● запущено ({', '.join(run_procs[:2])})",
                bg=OK_BG,
                fg=OK_TEXT,
                font=FONT_MICRO,
                padx=6,
                pady=1,
            ).pack(side="left", padx=(6, 0))

        sub_parts = [", ".join(procs[:4]) + ("…" if len(procs) > 4 else "")]
        if item.get("auth_domains"):
            sub_parts.append("Авторизация: " + ", ".join(list(item["auth_domains"])[:3]))
        tk.Label(
            info_col,
            text="  •  ".join(p for p in sub_parts if p),
            bg=CARD,
            fg=MUTED,
            font=FONT_MICRO,
            anchor="w",
        ).pack(fill="x", pady=(2, 0))

        btn_col = tk.Frame(row, bg=CARD)
        btn_col.pack(side="right", padx=(10, 0))
        app.make_button(
            btn_col,
            "⚡ Авто",
            lambda b_id=bid: app.on_find_best_bypass_bundle(b_id),
            "cyan_ghost",
            font=FONT_MICRO,
            padx=7,
            pady=3,
            tooltip="Подобрать лучший рабочий слой автоматически (Напрямую → DPI → VPN).",
        ).pack(side="left", padx=(0, 4))
        for m_key, m_lbl in mode_defs:
            active = m_key == mode
            app.make_button(
                btn_col,
                m_lbl,
                lambda b_id=bid, b_name=name, mk=m_key, ig=is_game: _on_select_bundle_mode(app, b_id, b_name, mk, ig),
                "pill_active" if active else "neutral",
                font=FONT_MICRO,
                padx=8,
                pady=3,
            ).pack(side="left", padx=2)
        app.make_button(
            btn_col,
            "📌" if not pinned else "✕ 📌",
            lambda b_id=bid, target=(not pinned): app.on_toggle_bundle_pin(b_id, target),
            "warn" if pinned else "ghost",
            font=FONT_MICRO,
            padx=6,
            pady=3,
            tooltip="Закрепить/снять фиксацию выбранного режима бандла.",
        ).pack(side="left", padx=(4, 0))
        if item.get("custom"):
            app.make_button(
                btn_col,
                "✕",
                lambda b_id=bid: app.on_remove_custom_bundle(b_id),
                "ghost",
                font=FONT_MICRO,
                padx=6,
                pady=3,
                tooltip="Удалить свой профиль",
            ).pack(side="left", padx=(2, 0))


def _on_select_bundle_mode(app: Any, bundle_id: str, bundle_name: str, mode: str, is_game: bool) -> None:
    if mode == "vpn" and is_game and hasattr(app, "backend") and hasattr(app.backend, "check_vpn_udp_reachability"):
        try:
            chk = app.backend.check_vpn_udp_reachability()
        except Exception:
            chk = {"ok": True}
        if not chk.get("ok"):
            reason = str(chk.get("reason") or "Нет активного UDP-маршрута VPN")
            proceed = messagebox.askyesno(
                "Предупреждение VPN для игры",
                f"{reason}\n\nВсё равно перевести и закрепить «{bundle_name}» через VPN?",
            )
            if not proceed:
                return
    app.on_set_bundle_mode(bundle_id, mode, pinned=True)


def open_add_bundle_dialog(app: Any) -> None:
    """Open modal dialog to add a custom application/game bundle."""
    dlg = tk.Toplevel(app)
    dlg.title("Добавить программу или игру")
    dlg.configure(bg=BG)
    dlg.geometry("460x260")
    dlg.transient(app)
    dlg.grab_set()

    tk.Label(dlg, text="Название программы или игры:", bg=BG, fg=FG_SOFT, font=FONT_SMALL_B, anchor="w").pack(
        fill="x", padx=16, pady=(14, 3)
    )
    name_var = tk.StringVar()
    app.make_entry(dlg, name_var, 40).pack(fill="x", padx=16, ipady=3)

    tk.Label(dlg, text=".exe процессы (через запятую, например game.exe, launcher.exe):", bg=BG, fg=FG_SOFT, font=FONT_SMALL_B, anchor="w").pack(
        fill="x", padx=16, pady=(10, 3)
    )
    procs_var = tk.StringVar()
    app.make_entry(dlg, procs_var, 40).pack(fill="x", padx=16, ipady=3)

    tk.Label(dlg, text="Начальный режим (по умолчанию подберётся автоматически):", bg=BG, fg=FG_SOFT, font=FONT_SMALL_B, anchor="w").pack(
        fill="x", padx=16, pady=(10, 3)
    )
    mode_var = tk.StringVar(value="direct_clean")
    ttk.Combobox(dlg, textvariable=mode_var, values=("direct_clean", "direct_dpi", "vpn"), state="readonly").pack(
        fill="x", padx=16
    )

    btn_row = tk.Frame(dlg, bg=BG)
    btn_row.pack(fill="x", padx=16, pady=16)

    def _save() -> None:
        nm = name_var.get().strip()
        pr = procs_var.get().strip()
        if not nm or not pr:
            messagebox.showwarning("Недостаточно данных", "Укажите название и хотя бы один .exe процесс.", parent=dlg)
            return
        dlg.destroy()
        app.on_add_custom_bundle(nm, pr, mode_var.get())

    app.make_button(btn_row, "Добавить", _save, "hero", font=FONT_SMALL_B, padx=14, pady=5).pack(side="right", padx=(6, 0))
    app.make_button(btn_row, "Отмена", dlg.destroy, "neutral", font=FONT_SMALL, padx=10, pady=5).pack(side="right")
