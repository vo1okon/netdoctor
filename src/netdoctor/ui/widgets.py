"""Reusable custom Tkinter canvas widgets for netdoctor UI."""

from __future__ import annotations

from collections import deque
import math
import sys
import tkinter as tk
import tkinter.font as tkfont
from typing import Any, Callable

from netdoctor.ui.theme import (
    ACCENT,
    BG,
    BORDER,
    BORDER_LIGHT,
    CARD,
    CARD_ALT,
    FG_SOFT,
    FONT_SMALL,
    FONT_SMALL_B,
    FONT_UI_B,
    LAVENDER,
    LAVENDER_HOVER,
    PILL_ACTIVE_BORDER,
    lerp_hex,
)


def draw_rounded_rect(
    canvas: tk.Canvas,
    x1: float,
    y1: float,
    x2: float,
    y2: float,
    r: float,
    **kwargs: Any,
) -> int:
    """Draw a smooth rounded rectangle on a Tk ``Canvas``."""
    r = max(0.0, min(float(r), (x2 - x1) / 2.0, (y2 - y1) / 2.0))
    pts = (
        x1 + r, y1,
        x1 + r, y1,
        x2 - r, y1,
        x2 - r, y1,
        x2, y1,
        x2, y1 + r,
        x2, y1 + r,
        x2, y2 - r,
        x2, y2 - r,
        x2, y2,
        x2 - r, y2,
        x2 - r, y2,
        x1 + r, y2,
        x1 + r, y2,
        x1, y2,
        x1, y2 - r,
        x1, y2 - r,
        x1, y1 + r,
        x1, y1 + r,
        x1, y1,
    )
    return canvas.create_polygon(pts, smooth=True, splinesteps=16, **kwargs)


class HoverTooltip:
    """Singleton floating rounded dark-indigo tooltip with delayed reveal and soft fade-in."""

    _active: HoverTooltip | None = None
    _pending: HoverTooltip | None = None

    def __init__(self, widget: tk.Misc, text: str, title: str | None = None, delay_ms: int = 180) -> None:
        self.widget = widget
        self.text = text
        self.title = title
        self.delay_ms = delay_ms
        self._after_id: str | None = None
        self._fade_id: str | None = None
        self._win: tk.Toplevel | None = None

        widget.bind("<Enter>", self._on_enter, add="+")
        widget.bind("<Leave>", self._on_leave, add="+")
        widget.bind("<ButtonPress>", self._on_leave, add="+")
        widget.bind("<Destroy>", self._on_destroy, add="+")

    def _cancel_timers(self) -> None:
        if self._after_id is not None:
            try:
                self.widget.after_cancel(self._after_id)
            except tk.TclError:
                pass
            self._after_id = None
        if self._fade_id is not None:
            try:
                self.widget.after_cancel(self._fade_id)
            except tk.TclError:
                pass
            self._fade_id = None
        if HoverTooltip._pending is self:
            HoverTooltip._pending = None

    def _on_enter(self, _event: Any = None) -> None:
        if HoverTooltip._pending is not None and HoverTooltip._pending is not self:
            HoverTooltip._pending._cancel_timers()
        active = HoverTooltip._active
        if active is not None and active._win is not None:
            if active is self or (active.text == self.text and active.title == self.title):
                return
            active.hide()
        self._cancel_timers()
        try:
            if not self.widget.winfo_viewable():
                return
            HoverTooltip._pending = self
            self._after_id = self.widget.after(self.delay_ms, self.show)
        except tk.TclError:
            pass

    def _on_leave(self, _event: Any = None) -> None:
        self._cancel_timers()
        self.hide()

    def _on_destroy(self, _event: Any = None) -> None:
        self._cancel_timers()
        self.hide()

    def show(self) -> None:
        if HoverTooltip._pending is self:
            HoverTooltip._pending = None
        if HoverTooltip._active is not None and HoverTooltip._active is not self:
            HoverTooltip._active.hide()
        if self._win is not None or not self.text:
            return
        try:
            if not self.widget.winfo_exists() or not self.widget.winfo_viewable():
                return
            win = tk.Toplevel(self.widget)
            win.wm_overrideredirect(True)
            win.attributes("-topmost", True)
            trans_col = "#010102"
            use_trans = sys.platform == "win32"
            if use_trans:
                try:
                    win.configure(bg=trans_col)
                    win.attributes("-transparentcolor", trans_col)
                except tk.TclError:
                    use_trans = False
                    win.configure(bg=CARD_ALT)
            else:
                win.configure(bg=CARD_ALT)
            try:
                win.attributes("-alpha", 0.0)
            except tk.TclError:
                pass

            canvas = tk.Canvas(
                win,
                bg=trans_col if use_trans else CARD_ALT,
                highlightthickness=0,
                bd=0,
            )
            canvas.pack()

            inner = tk.Frame(canvas, bg=CARD_ALT, padx=11, pady=7)
            if self.title:
                tk.Label(
                    inner, text=self.title, bg=CARD_ALT, fg=ACCENT, font=FONT_SMALL_B, anchor="w", justify="left"
                ).pack(fill="x", pady=(0, 2))
            tk.Label(
                inner,
                text=self.text,
                bg=CARD_ALT,
                fg=FG_SOFT,
                font=FONT_SMALL,
                anchor="w",
                justify="left",
                wraplength=290,
            ).pack(fill="x")
            inner.update_idletasks()
            iw = max(80, inner.winfo_reqwidth() + 4)
            ih = max(28, inner.winfo_reqheight() + 4)
            canvas.configure(width=iw, height=ih)
            draw_rounded_rect(canvas, 1, 1, iw - 1, ih - 1, 10, fill=CARD_ALT, outline=PILL_ACTIVE_BORDER, width=1)
            canvas.create_window(iw // 2, ih // 2, window=inner, anchor="center")
            win.update_idletasks()

            rx = self.widget.winfo_rootx() + min(18, max(4, self.widget.winfo_width() // 4))
            ry = self.widget.winfo_rooty() + self.widget.winfo_height() + 6
            sw = win.winfo_screenwidth()
            sh = win.winfo_screenheight()
            tw = win.winfo_reqwidth()
            th = win.winfo_reqheight()
            if rx + tw > sw - 12:
                rx = max(8, sw - tw - 12)
            if ry + th > sh - 12:
                ry = max(8, self.widget.winfo_rooty() - th - 6)
            win.wm_geometry(f"+{rx}+{ry}")
            self._win = win
            HoverTooltip._active = self
            self._fade_step(0)
        except tk.TclError:
            self.hide()

    def _fade_step(self, step: int) -> None:
        if self._win is None:
            return
        try:
            alpha = min(0.97, 0.25 + step * 0.24)
            self._win.attributes("-alpha", alpha)
            if alpha < 0.96:
                self._fade_id = self.widget.after(22, lambda: self._fade_step(step + 1))
        except tk.TclError:
            self.hide()

    def hide(self) -> None:
        self._cancel_timers()
        if HoverTooltip._active is self:
            HoverTooltip._active = None
        if HoverTooltip._pending is self:
            HoverTooltip._pending = None
        if self._win is not None:
            try:
                self._win.destroy()
            except tk.TclError:
                pass
            self._win = None


class AnimatedToggle(tk.Canvas):
    """Smooth animated capsule toggle switch synced with a ``tk.BooleanVar``."""

    def __init__(
        self,
        parent: tk.Misc,
        variable: tk.BooleanVar,
        command: Callable[[], Any] | None = None,
        bg: str = CARD,
        width: int = 42,
        height: int = 20,
    ) -> None:
        self._tog_w = int(width)
        self._tog_h = int(height)
        super().__init__(
            parent,
            width=self._tog_w,
            height=self._tog_h,
            bg=bg,
            highlightthickness=0,
            bd=0,
            cursor="hand2",
        )
        self.variable = variable
        self.command = command
        self._progress = 1.0 if bool(variable.get()) else 0.0
        self._anim_id: str | None = None
        self._trace_id: str | None = None

        self._draw(self._progress)
        self.bind("<Button-1>", self._on_click)
        self.bind("<Destroy>", self._on_destroy)
        self._trace_id = self.variable.trace_add("write", self._on_var_changed)

    def _draw(self, t: float) -> None:
        self.delete("all")
        t = max(0.0, min(1.0, t))
        track_col = lerp_hex("#232846", "#3E3275", t)
        border_col = lerp_hex(BORDER_LIGHT, LAVENDER, t)
        thumb_col = lerp_hex("#8590B3", LAVENDER, t)

        pad = 2
        r = (self._tog_h - pad * 2) / 2.0
        x0, y0, x1, y1 = pad, pad, self._tog_w - pad, self._tog_h - pad
        draw_rounded_rect(self, x0, y0, x1, y1, r, fill=track_col, outline=border_col, width=1)

        cx = (x0 + r) + ((x1 - r) - (x0 + r)) * t
        cy = self._tog_h / 2.0
        tr = max(3.5, r - 2.3)
        self.create_oval(cx - tr, cy - tr, cx + tr, cy + tr, fill=thumb_col, outline="")

    def _on_click(self, _event: Any = None) -> None:
        self.variable.set(not bool(self.variable.get()))
        if self.command is not None:
            self.command()

    def _on_var_changed(self, *_args: Any) -> None:
        target = 1.0 if bool(self.variable.get()) else 0.0
        self._animate_to(target)

    def _animate_to(self, target: float) -> None:
        if self._anim_id is not None:
            try:
                self.after_cancel(self._anim_id)
            except tk.TclError:
                pass
            self._anim_id = None
        try:
            viewable = bool(self.winfo_viewable())
        except tk.TclError:
            return
        if not viewable:
            self._progress = target
            self._draw(target)
            return
        start = self._progress
        steps = 6

        def _step(idx: int) -> None:
            try:
                if not self.winfo_exists():
                    return
                frac = idx / steps
                eased = 1.0 - (1.0 - frac) ** 2
                self._progress = start + (target - start) * eased
                self._draw(self._progress)
                if idx < steps:
                    self._anim_id = self.after(18, lambda: _step(idx + 1))
                else:
                    self._anim_id = None
            except tk.TclError:
                self._anim_id = None

        _step(1)

    def _on_destroy(self, _event: Any = None) -> None:
        if self._anim_id is not None:
            try:
                self.after_cancel(self._anim_id)
            except tk.TclError:
                pass
            self._anim_id = None
        if self._trace_id is not None:
            try:
                self.variable.trace_remove("write", self._trace_id)
            except tk.TclError:
                pass
            self._trace_id = None


class RoundedButton(tk.Canvas):
    """Soft-corner animated button rendered on Tk ``Canvas`` with ``tk.Button``-compatible API."""

    def __init__(
        self,
        parent: tk.Misc,
        text: str,
        command: Callable[[], Any],
        palette: tuple[str, str, str, str, str],
        *,
        width: int | None = None,
        font: tuple[Any, ...] = FONT_UI_B,
        padx: int = 12,
        pady: int = 6,
        radius: int = 10,
        anchor: str = "center",
    ) -> None:
        try:
            parent_bg = str(parent.cget("bg"))
        except tk.TclError:
            parent_bg = BG
        self._parent_bg = parent_bg
        self._text = text
        self._command = command
        self._font = font
        self._padx = padx
        self._pady = pady
        self._radius = radius
        self._anchor = anchor
        self._width_chars = width
        self._netdoc_palette = palette
        self._cur_bg, self._cur_fg, _hov, self._cur_brd, _bhov = palette
        self._pressed = False
        self._hovered = False
        self._tween_id: str | None = None

        self._measure()
        super().__init__(
            parent,
            width=self._req_w,
            height=self._req_h,
            bg=self._parent_bg,
            highlightthickness=0,
            bd=0,
            cursor="hand2",
        )
        self._redraw()
        self.bind("<Configure>", lambda _e: self._redraw())
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<ButtonPress-1>", self._on_press)
        self.bind("<ButtonRelease-1>", self._on_release)
        self.bind("<Destroy>", self._on_destroy)

    def _measure(self) -> None:
        try:
            fnt = tkfont.Font(font=self._font)
            tw = fnt.measure(self._text or " ")
            lh = fnt.metrics("linespace")
            ch = max(7, fnt.measure("0"))
        except tk.TclError:
            tw = max(24, len(self._text) * 8)
            lh = 16
            ch = 8
        if self._width_chars:
            self._req_w = max(tw + self._padx * 2 + 4, self._width_chars * ch + self._padx * 2)
        else:
            self._req_w = tw + self._padx * 2 + 6
        self._req_h = max(24 if self._pady >= 2 else 22, lh + self._pady * 2 + 2)

    def _redraw(self) -> None:
        try:
            w = self.winfo_width()
            h = self.winfo_height()
        except tk.TclError:
            return
        if w <= 1:
            w = self._req_w
        if h <= 1:
            h = self._req_h
        self.delete("all")
        fill = lerp_hex(self._cur_bg, "#FFFFFF", 0.08) if self._pressed else self._cur_bg
        draw_rounded_rect(self, 1, 1, w - 1, h - 1, min(self._radius, (h - 2) / 2.0), fill=fill, outline=self._cur_brd, width=1)
        if self._anchor == "w":
            tx = self._padx + 3
            anc = "w"
        else:
            tx = w / 2.0
            anc = "center"
        ty = h / 2.0 + (1 if self._pressed else 0)
        self.create_text(tx, ty, text=self._text, fill=self._cur_fg, font=self._font, anchor=anc)

    def _tween_to(self, target_bg: str, target_brd: str) -> None:
        if self._tween_id is not None:
            try:
                self.after_cancel(self._tween_id)
            except tk.TclError:
                pass
            self._tween_id = None
        try:
            viewable = bool(self.winfo_viewable())
        except tk.TclError:
            return
        if not viewable:
            self._cur_bg = target_bg
            self._cur_brd = target_brd
            self._redraw()
            return
        s_bg, s_brd = self._cur_bg, self._cur_brd
        steps = 4

        def _step(idx: int) -> None:
            try:
                if not self.winfo_exists():
                    return
                frac = idx / steps
                self._cur_bg = lerp_hex(s_bg, target_bg, frac)
                self._cur_brd = lerp_hex(s_brd, target_brd, frac)
                self._redraw()
                if idx < steps:
                    self._tween_id = self.after(16, lambda: _step(idx + 1))
                else:
                    self._tween_id = None
            except tk.TclError:
                self._tween_id = None

        _step(1)

    def _on_enter(self, _e: Any = None) -> None:
        self._hovered = True
        self._tween_to(self._netdoc_palette[2], self._netdoc_palette[4])

    def _on_leave(self, _e: Any = None) -> None:
        self._hovered = False
        self._pressed = False
        self._tween_to(self._netdoc_palette[0], self._netdoc_palette[3])

    def _on_press(self, _e: Any = None) -> None:
        self._pressed = True
        self._redraw()

    def _on_release(self, event: Any = None) -> None:
        was_pressed = self._pressed
        self._pressed = False
        self._redraw()
        if not was_pressed:
            return
        if event is not None:
            try:
                if not (0 <= event.x <= self.winfo_width() and 0 <= event.y <= self.winfo_height()):
                    return
            except tk.TclError:
                pass
        if self._command is not None:
            self._command()

    def invoke(self) -> Any:
        if self._command is not None:
            return self._command()
        return None

    def cget(self, key: str) -> Any:
        if key == "text":
            return self._text
        if key in ("bg", "background"):
            return self._cur_bg
        if key in ("fg", "foreground"):
            return self._cur_fg
        if key == "anchor":
            return self._anchor
        return super().cget(key)

    def configure(self, cnf: dict[str, Any] | None = None, **kw: Any) -> Any:  # type: ignore[override]
        opts = dict(cnf or {})
        opts.update(kw)
        recalc = False
        if "text" in opts:
            self._text = str(opts.pop("text"))
            recalc = True
        if "font" in opts:
            self._font = opts.pop("font")
            recalc = True
        if "anchor" in opts:
            self._anchor = str(opts.pop("anchor"))
        if "bg" in opts:
            self._cur_bg = str(opts.pop("bg"))
        if "fg" in opts:
            self._cur_fg = str(opts.pop("fg"))
        if "highlightbackground" in opts:
            self._cur_brd = str(opts.pop("highlightbackground"))
        opts.pop("activebackground", None)
        opts.pop("activeforeground", None)
        if recalc:
            self._measure()
            opts.setdefault("width", self._req_w)
            opts.setdefault("height", self._req_h)
        res = super().configure(**opts) if opts else None
        self._redraw()
        return res

    config = configure

    def _on_destroy(self, _e: Any = None) -> None:
        if self._tween_id is not None:
            try:
                self.after_cancel(self._tween_id)
            except tk.TclError:
                pass
            self._tween_id = None


class RoundedCard(tk.Canvas):
    """Soft rounded surface card hosting a ``self.body`` frame with dynamic border glow."""

    def __init__(
        self,
        parent: tk.Misc,
        *,
        bg: str = CARD,
        outer_bg: str | None = None,
        border: str = BORDER,
        radius: int = 14,
        pad: int = 2,
        border_width: int = 1,
    ) -> None:
        if outer_bg is None:
            try:
                outer_bg = str(parent.cget("bg"))
            except tk.TclError:
                outer_bg = BG
        self._card_bg = bg
        self._border = border
        self._radius = radius
        self._pad = pad
        self._bw = border_width
        self._last_req = (0, 0)
        super().__init__(parent, bg=outer_bg, highlightthickness=0, bd=0)
        self.body = tk.Frame(self, bg=bg)
        self._win_id = self.create_window(pad, pad, window=self.body, anchor="nw")
        self.body.bind("<Configure>", self._on_body_cfg)
        self.bind("<Configure>", self._on_canvas_cfg)

    def _on_body_cfg(self, _e: Any = None) -> None:
        try:
            rh = max(20, self.body.winfo_reqheight() + self._pad * 2)
            rw = max(40, self.body.winfo_reqwidth() + self._pad * 2)
            if (rw, rh) != self._last_req:
                self._last_req = (rw, rh)
                super().configure(width=rw, height=rh)
            self._redraw()
        except tk.TclError:
            pass

    def _on_canvas_cfg(self, e: Any) -> None:
        try:
            w = max(24, int(getattr(e, "width", 0)) - self._pad * 2)
            self.itemconfigure(self._win_id, width=w)
            self._redraw()
        except tk.TclError:
            pass

    def _redraw(self) -> None:
        try:
            w = max(self._last_req[0], self.winfo_width())
            h = max(self._last_req[1], self.winfo_height())
            if w <= 4 or h <= 4:
                return
            self.delete("card_bg")
            tid = draw_rounded_rect(
                self,
                1,
                1,
                w - 1,
                h - 1,
                self._radius,
                fill=self._card_bg,
                outline=self._border,
                width=self._bw,
                tags=("card_bg",),
            )
            self.tag_lower(tid)
        except tk.TclError:
            pass

    def cget(self, key: str) -> Any:
        if key == "highlightbackground":
            return self._border
        if key in ("bg", "background"):
            return self._card_bg
        return super().cget(key)

    def configure(self, cnf: dict[str, Any] | None = None, **kw: Any) -> Any:  # type: ignore[override]
        opts = dict(cnf or {})
        opts.update(kw)
        need_redraw = False
        if "highlightbackground" in opts:
            self._border = str(opts.pop("highlightbackground"))
            need_redraw = True
        if "bg" in opts or "background" in opts:
            bg_val = str(opts.pop("bg", opts.pop("background", self._card_bg)))
            self._card_bg = bg_val
            try:
                self.body.configure(bg=bg_val)
            except tk.TclError:
                pass
            need_redraw = True
        if "outer_bg" in opts:
            opts["bg"] = str(opts.pop("outer_bg"))
        res = super().configure(**opts) if opts else None
        if need_redraw:
            self._redraw()
        return res

    config = configure


class ActivityBar(tk.Canvas):
    """Thin sweeping cyan-lavender progress beam under header showing live background activity."""

    def __init__(self, parent: tk.Misc, bg: str = BG) -> None:
        super().__init__(parent, height=3, bg=bg, highlightthickness=0, bd=0)
        self._active = False
        self._pos = 0.0
        self.bind("<Configure>", lambda _e: self.redraw())

    def set_active(self, active: bool) -> None:
        if self._active != active:
            self._active = active
            self.redraw()

    def step(self) -> None:
        if self._active:
            self._pos = (self._pos + 0.045) % 1.35
            self.redraw()

    def redraw(self) -> None:
        try:
            w = max(120, int(self.winfo_width()))
        except tk.TclError:
            return
        self.delete("all")
        if not self._active:
            self.create_line(0, 1, w, 1, fill=BORDER, width=1)
            return
        self.create_line(0, 1, w, 1, fill="#151932", width=1)
        beam_w = max(80, int(w * 0.24))
        x0 = (self._pos - 0.24) * w
        x1 = x0 + beam_w
        mid = (x0 + x1) / 2.0
        self.create_rectangle(x0, 0, mid, 3, fill=LAVENDER, outline="")
        self.create_rectangle(mid, 0, x1, 3, fill=ACCENT, outline="")


class LiveSparklineCanvas(tk.Canvas):
    """Real-time dual-line connection activity chart."""

    def __init__(self, parent: tk.Misc, height: int = 92, bg: str = CARD) -> None:
        super().__init__(parent, height=height, bg=bg, highlightthickness=0, bd=0)
        self._bg = bg
        self._total_hist: deque[int] = deque([0] * 32, maxlen=36)
        self._prot_hist: deque[int] = deque([0] * 32, maxlen=36)
        self._pulse = 0.5
        self.bind("<Configure>", lambda _e: self.redraw())

    def push_sample(self, total: int, protected: int) -> None:
        self._total_hist.append(max(0, int(total)))
        self._prot_hist.append(max(0, int(protected)))
        self.redraw()

    def set_pulse(self, phase: float) -> None:
        self._pulse = 0.5 + 0.5 * math.sin(phase)
        self.redraw()

    def redraw(self) -> None:
        try:
            w = max(240, int(self.winfo_width()))
            h = max(64, int(self.winfo_height()))
        except tk.TclError:
            return
        self.delete("all")
        pad_x, pad_top, pad_bot = 12, 10, 12
        plot_w = max(40, w - pad_x * 2 - 22)
        plot_h = max(24, h - pad_top - pad_bot)

        for i in range(4):
            y = pad_top + plot_h * (i / 3.0)
            self.create_line(pad_x, y, pad_x + plot_w, y, fill="#1B203B", width=1)

        max_val = max(4, max(self._total_hist, default=0), max(self._prot_hist, default=0))
        n = len(self._total_hist)
        if n < 2:
            return

        def _pts(series: deque[int]) -> list[float]:
            coords: list[float] = []
            for idx, val in enumerate(series):
                x = pad_x + plot_w * (idx / max(1, n - 1))
                y = pad_top + plot_h * (1.0 - min(1.0, val / max_val))
                coords.extend((x, y))
            return coords

        tot_pts = _pts(self._total_hist)
        prot_pts = _pts(self._prot_hist)

        self.create_line(*tot_pts, fill=LAVENDER, width=2, smooth=True)
        self.create_line(*prot_pts, fill=ACCENT, width=2, smooth=True)

        bx = pad_x + plot_w + 10
        tot_y = tot_pts[-1]
        prot_y = prot_pts[-1]
        tot_glow = lerp_hex("#8B74E8", LAVENDER_HOVER, self._pulse)
        prot_glow = lerp_hex("#22B8CF", ACCENT, self._pulse)
        self.create_rectangle(bx, tot_y, bx + 5, pad_top + plot_h, fill=tot_glow, outline="")
        self.create_rectangle(bx + 7, prot_y, bx + 12, pad_top + plot_h, fill=prot_glow, outline="")
        self.create_oval(tot_pts[-2] - 3, tot_y - 3, tot_pts[-2] + 3, tot_y + 3, fill=tot_glow, outline="")
        self.create_oval(prot_pts[-2] - 3, prot_y - 3, prot_pts[-2] + 3, prot_y + 3, fill=prot_glow, outline="")
