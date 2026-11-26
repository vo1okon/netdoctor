"""Clean VPN & Telegram tab (`VPN`) without logs for netdoctor v2."""

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
    ERR_TEXT,
    FG,
    FG_SOFT,
    FONT_H2,
    FONT_MICRO,
    FONT_SMALL,
    FONT_SMALL_B,
    INPUT,
    MUTED,
    OK_TEXT,
    PILL_ACTIVE_BG,
    PILL_ACTIVE_BORDER,
    VPN_MODE_AUTO_LABEL,
    VPN_MODE_PRIORITY_LABEL,
    WARN_TEXT,
)
from netdoctor.ui.widgets import RoundedCard


def build_vpn_tab(app: Any) -> None:
    """Build clean VPN management + honest 2-layer Telegram card (no log panels)."""
    tab = app.tab_vpn
    app._make_page_header(
        tab,
        "VPN и Telegram",
        "Обычный трафик идёт напрямую или через Zapret; VPN используется точечно для IP-блокировок и выбранных игр/программ.",
    )

    # Telegram 2-layer choice card
    tg_wrap = RoundedCard(tab, bg=CARD, outer_bg=BG, border=BORDER, radius=13, pad=2)
    tg_wrap.pack(fill="x", pady=(0, 8))
    tg_body = tg_wrap.body
    tg_row = tk.Frame(tg_body, bg=CARD)
    tg_row.pack(fill="x", padx=12, pady=8)

    tg_info = tk.Frame(tg_row, bg=CARD)
    tg_info.pack(side="left", fill="x", expand=True)
    tk.Label(tg_info, text="✈ Telegram", bg=CARD, fg=ACCENT, font=FONT_H2, anchor="w").pack(fill="x")
    app.tg_mode_hint_lbl = tk.Label(
        tg_info,
        text="Встроенный MTProto WS-прокси для Telegram Desktop (127.0.0.1:10808).",
        bg=CARD,
        fg=MUTED,
        font=FONT_SMALL,
        anchor="w",
    )
    app.tg_mode_hint_lbl.pack(fill="x")

    tg_ctrl = tk.Frame(tg_row, bg=CARD)
    tg_ctrl.pack(side="right", padx=(10, 0))
    app.telegram_mode_var = tk.StringVar(value="mtproto")
    app._tg_mode_mtproto_btn = tk.Button(
        tg_ctrl,
        text="MTProto прокси",
        command=lambda: app.on_set_telegram_mode("mtproto"),
        bg=PILL_ACTIVE_BG,
        fg=ACCENT,
        font=FONT_SMALL_B,
        relief="flat",
        padx=10,
        pady=4,
        cursor="hand2",
        highlightthickness=1,
        highlightbackground=PILL_ACTIVE_BORDER,
    )
    app._tg_mode_mtproto_btn.pack(side="left", padx=2)
    app._tg_mode_trans_btn = tk.Button(
        tg_ctrl,
        text="Прозрачно (через сеть)",
        command=lambda: app.on_set_telegram_mode("transparent"),
        bg=INPUT,
        fg=FG_SOFT,
        font=FONT_SMALL,
        relief="flat",
        padx=10,
        pady=4,
        cursor="hand2",
        highlightthickness=1,
        highlightbackground=BORDER,
    )
    app._tg_mode_trans_btn.pack(side="left", padx=2)

    app.tg_vpn_open_btn = app.make_button(
        tg_ctrl,
        "Открыть в Telegram",
        app.on_connect_telegram_proxy,
        "cyan_ghost",
        font=FONT_SMALL_B,
        padx=10,
        pady=3,
        tooltip="Открывает deep-link tg://proxy и копирует ссылку MTProto-прокси.",
    )
    app.tg_vpn_open_btn.pack(side="left", padx=(8, 0))

    # Subscription / VPN management card
    vpn_card = tk.Frame(tab, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
    vpn_card.pack(fill="x", pady=(0, 8))

    row1 = tk.Frame(vpn_card, bg=CARD)
    row1.pack(fill="x", padx=12, pady=(8, 5))
    app.make_button(
        row1,
        "Обновить список",
        app.on_refresh_subscriptions,
        "neutral",
        font=FONT_SMALL_B,
        padx=9,
        pady=4,
        tooltip="Скачать актуальный список серверов из всех добавленных подписок.",
    ).pack(side="right", padx=(4, 0))
    app.make_button(
        row1,
        "+ Добавить подписку",
        app.on_add_subscription,
        "primary",
        font=FONT_SMALL_B,
        padx=10,
        pady=4,
        tooltip="Добавить ссылку на подписку (URL) или ключ vless://, vmess://, trojan://, ss://.",
    ).pack(side="right", padx=(8, 0))
    tk.Label(row1, text="Ссылка / ключ:", bg=CARD, fg=MUTED, font=FONT_SMALL_B).pack(side="left", padx=(0, 8))
    app.sub_var = tk.StringVar()
    sub_entry = app.make_entry(row1, app.sub_var, 20)
    sub_entry.pack(side="left", ipady=3, fill="x", expand=True)
    sub_entry.bind("<Return>", lambda _e: app.on_add_subscription())

    tk.Frame(vpn_card, bg=BORDER_LIGHT, height=1).pack(fill="x", padx=12)

    row2 = tk.Frame(vpn_card, bg=CARD)
    row2.pack(fill="x", padx=12, pady=(5, 5))
    app.make_button(
        row2,
        "Сменить сервер",
        app.on_rotate_vpn_node,
        "warn",
        font=FONT_SMALL_B,
        padx=9,
        pady=4,
        tooltip="Переключить активный VPN на выбранный сервер или на следующий рабочий без перезапуска защиты.",
    ).pack(side="right", padx=(6, 0))
    app.make_button(
        row2,
        "Проверить пинг серверов",
        app.on_ping_vpn_nodes,
        "cyan_ghost",
        font=FONT_SMALL_B,
        padx=9,
        pady=4,
        tooltip="Измерить реальную задержку (пинг) и доступность каждого VPN-сервера.",
    ).pack(side="right", padx=(8, 0))
    app._vpn_summary_lbl = tk.Label(
        row2,
        text="Список серверов VPN и текущая задержка внутри туннеля",
        bg=CARD,
        fg=FG_SOFT,
        font=FONT_SMALL,
        anchor="w",
        justify="left",
    )
    app._vpn_summary_lbl.pack(side="left", fill="x", expand=True)
    app._bind_responsive_wrap(app._vpn_summary_lbl, min_wrap=200, pad=16)

    tk.Frame(vpn_card, bg=BORDER_LIGHT, height=1).pack(fill="x", padx=12)

    row3 = tk.Frame(vpn_card, bg=CARD)
    row3.pack(fill="x", padx=12, pady=(5, 8))
    tk.Label(row3, text="Режим выбора:", bg=CARD, fg=MUTED, font=FONT_SMALL_B).pack(side="left", padx=(0, 6))
    app.vpn_mode_var = tk.StringVar(value=VPN_MODE_AUTO_LABEL)
    app.vpn_mode_cb = ttk.Combobox(
        row3,
        textvariable=app.vpn_mode_var,
        values=[VPN_MODE_AUTO_LABEL, VPN_MODE_PRIORITY_LABEL],
        state="readonly",
        width=26,
    )
    app.vpn_mode_cb.pack(side="left", padx=(0, 8))
    app.vpn_mode_cb.bind("<<ComboboxSelected>>", app.on_vpn_mode_change)
    app.make_button(
        row3,
        "↓ Ниже",
        lambda: app.on_move_vpn_priority(1),
        "neutral",
        font=FONT_SMALL_B,
        padx=8,
        pady=3,
    ).pack(side="right", padx=(4, 0))
    app.make_button(
        row3,
        "↑ Выше",
        lambda: app.on_move_vpn_priority(-1),
        "neutral",
        font=FONT_SMALL_B,
        padx=8,
        pady=3,
    ).pack(side="right", padx=(4, 0))
    app.make_button(
        row3,
        "★ Сделать основным",
        app.on_set_priority_vpn_node,
        "primary",
        font=FONT_SMALL_B,
        padx=9,
        pady=3,
    ).pack(side="right", padx=(8, 0))

    # Full-height VPN servers table (no log panels!)
    vpn_wrap = tk.Frame(tab, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
    vpn_wrap.pack(fill="both", expand=True)
    app.vpn_tree = app.make_tree(
        vpn_wrap, ("priority", "tag", "region", "protocol", "transport", "server", "health"), height=12
    )
    for cid, title, width in (
        ("priority", "Приоритет", 82),
        ("tag", "Сервер", 180),
        ("region", "Регион", 66),
        ("protocol", "Протокол", 82),
        ("transport", "Транспорт", 82),
        ("server", "Адрес : Порт / Пинг", 210),
        ("health", "Состояние сервера", 175),
    ):
        app.vpn_tree.heading(cid, text=title)
        app.vpn_tree.column(cid, width=width, anchor="w", stretch=cid in ("tag", "health"))  # type: ignore[arg-type]
    app.vpn_tree.tag_configure("ok", foreground=OK_TEXT)
    app.vpn_tree.tag_configure("warn", foreground=WARN_TEXT)
    app.vpn_tree.tag_configure("bad", foreground=ERR_TEXT)
    app.vpn_tree.tag_configure("muted", foreground=MUTED)
    app._scrolled(vpn_wrap, app.vpn_tree, horizontal=True)


def sync_telegram_mode_ui(app: Any, mode: str) -> None:
    """Update visual toggle state of the 2-layer Telegram card."""
    clean = (mode or "mtproto").strip().lower()
    if hasattr(app, "telegram_mode_var"):
        app.telegram_mode_var.set(clean)
    is_mt = clean == "mtproto"
    if hasattr(app, "settings_tg_mode_var") and hasattr(app, "_settings_tg_labels"):
        target_lbl = app._settings_tg_labels[0] if is_mt else app._settings_tg_labels[1]
        if app.settings_tg_mode_var.get() != target_lbl:
            app.settings_tg_mode_var.set(target_lbl)
    if hasattr(app, "settings_tg_open_btn"):
        try:
            if is_mt and not app.settings_tg_open_btn.winfo_manager():
                app.settings_tg_open_btn.pack(side="right", padx=(6, 0))
            elif not is_mt and app.settings_tg_open_btn.winfo_manager():
                app.settings_tg_open_btn.pack_forget()
        except tk.TclError:
            pass
    if not hasattr(app, "_tg_mode_mtproto_btn"):
        return
    app._tg_mode_mtproto_btn.configure(
        bg=PILL_ACTIVE_BG if is_mt else INPUT,
        fg=ACCENT if is_mt else FG_SOFT,
        font=FONT_SMALL_B if is_mt else FONT_SMALL,
        highlightbackground=PILL_ACTIVE_BORDER if is_mt else BORDER,
    )
    app._tg_mode_trans_btn.configure(
        bg=PILL_ACTIVE_BG if not is_mt else INPUT,
        fg=ACCENT if not is_mt else FG_SOFT,
        font=FONT_SMALL_B if not is_mt else FONT_SMALL,
        highlightbackground=PILL_ACTIVE_BORDER if not is_mt else BORDER,
    )
    if hasattr(app, "tg_mode_hint_lbl"):
        app.tg_mode_hint_lbl.configure(
            text=(
                "Встроенный MTProto WS-прокси для Telegram Desktop (127.0.0.1:10808)."
                if is_mt
                else "Прозрачный режим: Telegram проходит через общую сеть (Zapret / TUN / VPN) без локального прокси."
            )
        )
