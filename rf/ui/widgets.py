#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UI 基础件：滚动容器 / 自动隐藏滚动条 / 流式布局 / 滚轮路由。

为什么单独一个文件：
    tkinter 默认行为有三个坑，散落在十几个页面里各修一遍必然漏。

    1) Text 默认请求 24 行高（约 400px）。一个页面叠两个就超过窗口高度，
       而 pack 在空间不足时会把「最后排的那个」压成 0 高度 —— 表现就是
       「按钮/输入框莫名不见」，其实它还在，只是高度为 0。
    2) ttk.Scrollbar 永远占位，内容不满也画一条，看着像多余的东西。
    3) 滚轮事件只在指针正对可滚控件时才生效；指针停在它外面的容器上就
       「滑不动」。Tk 不会往父级冒泡。
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk


# ----------------------------------------------------------------------
# 滚轮路由
# ----------------------------------------------------------------------
def install_wheel_routing(root: tk.Misc) -> None:
    """
    全局滚轮路由：从指针下的控件开始往上找，找到第一个能纵向滚的就滚它。

    Tk 自带的 <MouseWheel> 绑定只认控件本身，指针在容器/留白上时事件没人
    处理，用户感受就是「滑不动」。这里统一接管，代价只有一次 bind_all。
    """

    def _wheel(event):
        w = event.widget
        try:
            delta = int(-event.delta / 120)
        except Exception:                                # noqa: BLE001
            return None
        if delta == 0:
            delta = -1 if event.delta > 0 else 1

        # 指针正压在 Text/Treeview 上时交给 Tk 自己的绑定：
        # 我们也滚一遍会变成两倍速（class 绑定先执行，我们的 bind_all 后执行）。
        if _scrollable(w):
            return None

        # 指针在容器/留白上 → 逐级向上，第一个"有内容可滚"的接管
        cur = w
        while cur is not None:
            if _scrollable(cur):
                try:
                    first, last = _view(cur)
                except Exception:                        # noqa: BLE001
                    first, last = 0.0, 1.0
                if not (first <= 0.0 and last >= 1.0):
                    try:
                        cur.yview_scroll(delta, "units")
                    except Exception:                    # noqa: BLE001
                        pass
                    return "break"
            cur = getattr(cur, "master", None)
        return None

    root.bind_all("<MouseWheel>", _wheel, add="+")
    # Linux/X11 用 Button-4/5：Button-4 是「向上滚」，对应 Windows 的 delta=+120
    root.bind_all("<Button-4>", lambda e: _wheel(_FakeWheel(e, 1)), add="+")
    root.bind_all("<Button-5>", lambda e: _wheel(_FakeWheel(e, -1)), add="+")


class _FakeWheel:
    """把 X11 的 Button-4/5 包成 delta 形式，复用同一套逻辑。"""

    def __init__(self, event, step: int):
        self.widget = event.widget
        self.delta = 120 * step


def _scrollable(w) -> bool:
    if not hasattr(w, "yview_scroll"):
        return False
    # 只认真实可滚的几类，避免误伤 Entry 之类
    kinds = ("Text", "Listbox", "Canvas", "Treeview", "Spinbox")
    try:
        cls = w.winfo_class()
    except Exception:                                    # noqa: BLE001
        return False
    return any(k in cls for k in kinds)


def _view(w) -> tuple[float, float]:
    first, last = w.yview()
    return float(first), float(last)


# ----------------------------------------------------------------------
# 自动隐藏滚动条
# ----------------------------------------------------------------------
class AutoScrollbar(ttk.Scrollbar):
    """
    内容装得下时自动消失的滚动条（纵/横都支持，pack 与 grid 都支持）。

    坑：光靠目标的 scrollcommand 回调判断是不够的 —— 内容一开始就装得下时，
    这条回调可能一次都不触发，滚动条就永远挂着一条拖不动的灰条（用户口径：
    「多余的滑不动」）。所以额外在 after_idle 和目标 <Configure> 时主动核一次。
    """

    def __init__(self, master, target, axis: str = "y", **kw):
        self._target = target
        self._axis = axis
        self._how: tuple[str, dict] | None = None
        vertical = axis == "y"
        super().__init__(
            master,
            orient="vertical" if vertical else "horizontal",
            command=target.yview if vertical else target.xview,
            **kw,
        )
        if vertical:
            target.configure(yscrollcommand=self._on_view)
        else:
            target.configure(xscrollcommand=self._on_view)
        target.bind("<Configure>", lambda _e: self.refresh(), add="+")
        self.after_idle(self.refresh)

    # -- 摆放 ---------------------------------------------------------
    def show(self, manager: str = "pack", **kw) -> None:
        """按指定方式摆放一次，并记住参数；之后隐藏/恢复都还原这里。"""
        self._how = (manager, kw)
        getattr(self, manager)(**kw)
        self.refresh()

    # 兼容老写法：sb.pack(side="right", fill="y")
    def pack(self, **kw):                                # noqa: A003
        self._how = ("pack", kw)
        super().pack(**kw)
        self.refresh()

    def grid(self, **kw):
        self._how = ("grid", kw)
        super().grid(**kw)
        self.refresh()

    # -- 显示/隐藏 ----------------------------------------------------
    def refresh(self) -> None:
        try:
            first, last = self._target.yview() if self._axis == "y" else self._target.xview()
        except Exception:                                # noqa: BLE001
            return
        self._on_view(first, last)

    def _on_view(self, first, last) -> None:
        ttk.Scrollbar.set(self, first, last)
        try:
            full = float(first) <= 0.0 and float(last) >= 1.0
        except (TypeError, ValueError):
            full = False
        if self._how is None:
            return
        manager, kw = self._how
        mapped = bool(self.winfo_manager())
        if full and mapped:
            if manager == "grid":
                self.grid_remove()
            else:
                self.pack_forget()
        elif not full and not mapped:
            if manager == "grid":
                super().grid(**kw)
            else:
                super().pack(**kw)


def mount_scroll(widget, parent=None, side: str = "right"):
    """建一条自动隐藏的竖滚动条并 pack 好，返回滚动条对象。"""
    sb = AutoScrollbar(parent or widget.master, widget, axis="y")
    sb.show("pack", side=side, fill="y")
    return sb


# ----------------------------------------------------------------------
# 可滚动容器（整页/整栏）
# ----------------------------------------------------------------------
class ScrollFrame(tk.Frame):
    """
    竖向可滚动容器：把内容放进 .body 就会自动获得滚动能力。

    - 内容比可视区短：滚动条自动隐藏，且内容顶部对齐（不会拉伸出空白）。
    - 内容比可视区长：出现滚动条，滚轮在内容任意位置都生效（配合全局路由）。
    - 宽度始终跟随容器，避免出现横向滚动条。
    """

    def __init__(self, master, bg: str = "#000000", **kw):
        super().__init__(master, bg=bg, **kw)
        # 用 grid 而不是 pack：Canvas 自身请求宽度 378px，pack 时它先把槽位吃满，
        # 后 pack 的滚动条只能分到 1x1（表现为「滚动条不出现」）。grid 由权重决定，
        # 不受请求宽度影响。
        self.canvas = tk.Canvas(self, bg=bg, highlightthickness=0, bd=0, width=1)
        self.canvas.grid(row=0, column=0, sticky="nsew")
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        self.body = tk.Frame(self.canvas, bg=bg)
        self._win = self.canvas.create_window((0, 0), window=self.body, anchor="nw")
        # 这里用普通滚动条 + 单一来源判断（winfo_ismapped）。
        # 之前用 AutoScrollbar 自己的 _packed 标志，和容器这边的 _sb_packed
        # 会不同步：滚动条被自己隐藏后容器仍以为它在显示 → 再也不出现。
        self._sb = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self._sb.set)

        self.body.bind("<Configure>", self._on_body)
        self.canvas.bind("<Configure>", self._on_canvas)

    def _on_body(self, _evt=None) -> None:
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        self._sync_sb()

    def _on_canvas(self, evt) -> None:
        # 内层宽度跟着画布走，避免内容按自身宽度撑出横向滚动
        self.canvas.itemconfigure(self._win, width=evt.width)
        self._sync_sb()

    def scroll_to(self, widget: tk.Widget) -> None:
        """
        把某个子控件滚进可视区。

        用「最小移动量」而不是「顶到最上面」：顶到最上面会把上面的脚本列表
        整块推出视野，用户会以为选错了东西；只要保证目标完整可见就够了。
        """
        try:
            self.update_idletasks()
            y = widget.winfo_rooty() - self.body.winfo_rooty()
            h = widget.winfo_height()
            view = self.canvas.winfo_height()
            total = max(1, self.body.winfo_height())
            top = int(self.canvas.canvasy(0))
            if top <= y and y + h <= top + view:
                return                       # 已经完整可见，不动
            new_top = y if y + h - view <= 0 else min(y, y + h - view)
            self.canvas.yview_moveto(max(0.0, min(1.0, new_top / total)))
        except Exception:                                # noqa: BLE001
            pass

    def _sync_sb(self) -> None:
        need = self.body.winfo_reqheight() > self.canvas.winfo_height() + 1
        shown = bool(self._sb.winfo_manager())
        if need and not shown:
            self._sb.grid(row=0, column=1, sticky="ns")
        elif not need and shown:
            self._sb.grid_remove()
            try:
                self.canvas.yview_moveto(0)
            except Exception:                            # noqa: BLE001
                pass


# ----------------------------------------------------------------------
# 流式布局：按钮多了/窗口窄了自动换行
# ----------------------------------------------------------------------
class FlowFrame(tk.Frame):
    """
    按可用宽度自动换行的容器。tkinter 没有流式布局，窄窗口下按钮会被挤出
    可视区（用户看到的就是「有个东西显示不出来」），这里按行重排。
    """

    def __init__(self, master, bg: str, gap: int = 6, **kw):
        super().__init__(master, bg=bg, **kw)
        self._gap = gap
        self._items: list[tk.Widget] = []
        self.bind("<Configure>", self._reflow)

    def add(self, w: tk.Widget) -> None:
        self._items.append(w)
        self._reflow()

    def _reflow(self, _evt=None) -> None:
        width = self.winfo_width()
        if width <= 1:
            return
        x = y = 0
        row_h = 0
        for w in self._items:
            try:
                ww = w.winfo_reqwidth()
                wh = w.winfo_reqheight()
            except Exception:                            # noqa: BLE001
                continue
            if x and x + ww > width:
                x = 0
                y += row_h + self._gap
                row_h = 0
            try:
                w.place(x=x, y=y)
            except Exception:                            # noqa: BLE001
                pass
            x += ww + self._gap
            row_h = max(row_h, wh)
        need = y + row_h
        if int(self.cget("height") or 0) != need:
            self.configure(height=need)


# ----------------------------------------------------------------------
# 代码框：横竖双滚动条（代码不能自动折行，长行必须能横向看到）
# ----------------------------------------------------------------------
class CodeBox(tk.Frame):
    """
    代码编辑/查看框。

    wrap="none" 保证缩进和长行不被折断，代价是必须给横向滚动条 ——
    否则超宽的那半行永远看不到（用户口径：「显示不了」）。
    """

    def __init__(self, master, factory=None, bg: str = "#000000", **kw):
        super().__init__(master, bg=bg, **kw)
        if factory is None:
            self.text = tk.Text(self, wrap="none", bd=0, highlightthickness=0,
                                bg=bg, fg="#e6edf3", insertbackground="#e6edf3")
        else:
            self.text = factory(self)
        self.vsb = AutoScrollbar(self, self.text, axis="y")
        self.hsb = AutoScrollbar(self, self.text, axis="x")
        self.text.grid(row=0, column=0, sticky="nsew")
        self.vsb.show("grid", row=0, column=1, sticky="ns")
        self.hsb.show("grid", row=1, column=0, sticky="ew")
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
