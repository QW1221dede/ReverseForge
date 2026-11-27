#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 rf.ui.theme · 视觉层
============================================================================

    深色工具风配色 + 统一字体 + ttk 样式。
    刻意不用第三方主题库 —— 打包后任何额外依赖都会变成事故源。

    配色逻辑：
        背景近黑（长时间盯代码不刺眼）
        强调色只用一种（橙），全部"可点击/进行中"都用它
        状态色三档：绿=可用 黄=注意 红=错误
============================================================================
"""

from __future__ import annotations

import sys
import tkinter as tk
from tkinter import ttk

# ---------------- 调色板 ----------------
BG        = "#0e1014"     # 窗口底
PANEL     = "#151821"     # 面板
PANEL2    = "#1b1f2a"     # 次级面板 / 输入框
BORDER    = "#262c39"     # 分隔线
TEXT      = "#d6dbe6"     # 主文字
MUTED     = "#79839a"     # 次要文字
ACCENT    = "#ff8a3d"     # 强调（橙）
ACCENT_D  = "#cc6a26"     # 强调按下
OK        = "#3ddc84"     # 可用
WARN      = "#f2c14e"     # 注意
ERR       = "#ff5f5f"     # 错误
SEL       = "#232a38"     # 选中行
TERM_BG   = "#0b0d11"     # 终端背景
TERM_FG   = "#c8d0de"
TERM_OK   = "#4ade80"
TERM_WARN = "#fbbf24"
TERM_ERR  = "#f87171"
TERM_CMD  = "#7dd3fc"

# ---------------- 字体 ----------------
def _pick(cands: list[str], fallback: str) -> str:
    """在当前系统已安装字体里挑第一个可用的。"""
    try:
        from tkinter import font as tkfont
        avail = {f.lower() for f in tkfont.families()}
        for c in cands:
            if c.lower() in avail:
                return c
    except Exception:
        pass
    return fallback


_UI_CANDS = ["Microsoft YaHei UI", "Microsoft YaHei", "PingFang SC", "Segoe UI", "Arial"]
_MONO_CANDS = ["Cascadia Mono", "Consolas", "JetBrains Mono", "Courier New", "Courier"]

UI_FONT = ""       # 由 apply() 填充
UI_FONT_S = ""
UI_FONT_B = ""
MONO_FONT = ""


def apply(root: tk.Misc, scale: float = 1.0) -> ttk.Style:
    """给整个应用套样式。返回 Style 以便局部微调。"""
    global UI_FONT, UI_FONT_S, UI_FONT_B, MONO_FONT

    ui = _pick(_UI_CANDS, "TkDefaultFont")
    mono = _pick(_MONO_CANDS, "Courier New")
    UI_FONT = (ui, max(9, int(10 * scale)))
    UI_FONT_S = (ui, max(8, int(9 * scale)))
    UI_FONT_B = (ui, max(10, int(11 * scale)), "bold")
    MONO_FONT = (mono, max(9, int(10 * scale)))

    st = ttk.Style(root)
    try:
        st.theme_use("clam")     # clam 是唯一能被完整配色的内置主题
    except tk.TclError:
        pass

    root.configure(bg=BG)

    st.configure(".", background=PANEL, foreground=TEXT, font=UI_FONT,
                 bordercolor=BORDER, darkcolor=PANEL, lightcolor=PANEL,
                 troughcolor=PANEL2, focuscolor=ACCENT)
    st.configure("TFrame", background=PANEL)
    st.configure("Bg.TFrame", background=BG)
    st.configure("Panel.TFrame", background=PANEL)
    st.configure("Card.TFrame", background=PANEL2)
    st.configure("TLabel", background=PANEL, foreground=TEXT, font=UI_FONT)
    st.configure("Muted.TLabel", background=PANEL, foreground=MUTED, font=UI_FONT_S)
    st.configure("Head.TLabel", background=BG, foreground=TEXT, font=UI_FONT_B)
    st.configure("H1.TLabel", background=BG, foreground=TEXT,
                 font=(UI_FONT[0], int(15 * scale), "bold"))
    st.configure("Accent.TLabel", background=PANEL, foreground=ACCENT, font=UI_FONT_S)
    st.configure("TCheckbutton", background=PANEL, foreground=TEXT, font=UI_FONT)
    st.map("TCheckbutton", background=[("active", PANEL)],
           foreground=[("disabled", MUTED)])

    # 按钮：默认扁平，强调按钮橙底
    st.configure("TButton", background=PANEL2, foreground=TEXT, font=UI_FONT,
                 borderwidth=0, padding=(10, 6), relief="flat")
    st.map("TButton",
           background=[("active", SEL), ("pressed", BORDER), ("disabled", PANEL)],
           foreground=[("disabled", MUTED)])
    st.configure("Accent.TButton", background=ACCENT, foreground="#141414",
                 font=(UI_FONT[0], UI_FONT[1], "bold"), borderwidth=0,
                 padding=(14, 7))
    st.map("Accent.TButton",
           background=[("active", "#ffa15f"), ("pressed", ACCENT_D),
                       ("disabled", "#5a4029")],
           foreground=[("disabled", "#9a8775")])
    st.configure("Ghost.TButton", background=PANEL, foreground=MUTED,
                 borderwidth=0, padding=(8, 4))
    st.map("Ghost.TButton", background=[("active", PANEL2)],
           foreground=[("active", TEXT)])

    # 输入框
    st.configure("TEntry", fieldbackground=PANEL2, background=PANEL2,
                 foreground=TEXT, insertcolor=ACCENT, borderwidth=0,
                 padding=(8, 6))
    st.map("TEntry", fieldbackground=[("disabled", PANEL)],
           foreground=[("disabled", MUTED)])
    st.configure("TCombobox", fieldbackground=PANEL2, background=PANEL2,
                 foreground=TEXT, arrowcolor=MUTED, borderwidth=0, padding=(6, 4))
    st.map("TCombobox", fieldbackground=[("readonly", PANEL2)],
           foreground=[("readonly", TEXT)])

    # 进度条：cl​am 下 thickness 太薄会看不见，6px + 亮一档的底槽才够
    st.configure("TProgressbar", background=ACCENT, troughcolor="#2b3243",
                 borderwidth=0, thickness=6, lightcolor=ACCENT, darkcolor=ACCENT)
    st.configure("Thin.Horizontal.TProgressbar", background=ACCENT,
                 troughcolor="#2b3243", borderwidth=0, thickness=6,
                 lightcolor=ACCENT, darkcolor=ACCENT)

    # Notebook
    st.configure("TNotebook", background=BG, borderwidth=0, tabmargins=(0, 0, 0, 0))
    st.configure("TNotebook.Tab", background=BG, foreground=MUTED,
                 padding=(16, 8), borderwidth=0, font=UI_FONT)
    st.map("TNotebook.Tab",
           background=[("selected", PANEL), ("active", PANEL2)],
           foreground=[("selected", ACCENT), ("active", TEXT)])

    # 分隔条
    st.configure("TPanedwindow", background=BG)
    st.configure("Sash", sashthickness=6, gripcount=0, background=BG)

    # 滚动条
    st.configure("TScrollbar", background=PANEL2, troughcolor=BG,
                 borderwidth=0, arrowcolor=MUTED, arrowsize=12)
    st.map("TScrollbar", background=[("active", BORDER)])

    # 树
    st.configure("Treeview", background=PANEL, fieldbackground=PANEL,
                 foreground=TEXT, borderwidth=0, rowheight=max(22, int(24 * scale)),
                 font=UI_FONT_S)
    st.configure("Treeview.Heading", background=PANEL2, foreground=MUTED,
                 font=UI_FONT_S, borderwidth=0, padding=(6, 4))
    st.map("Treeview", background=[("selected", SEL)],
           foreground=[("selected", TEXT)])

    # 标签页内的容器
    st.configure("Tab.TFrame", background=PANEL)

    return st


def make_text(parent, mono: bool = True, bg: str | None = None,
              fg: str | None = None, size: int | None = None, **kw) -> tk.Text:
    """统一风格的 Text 控件（带基本配色与边距）。"""
    font = (MONO_FONT[0], size or MONO_FONT[1]) if mono else (UI_FONT[0], size or UI_FONT[1])
    t = tk.Text(
        parent,
        bg=bg or TERM_BG, fg=fg or TERM_FG,
        insertbackground=ACCENT if mono else TEXT,
        selectbackground=SEL, selectforeground=TEXT,
        font=font, borderwidth=0, highlightthickness=0,
        padx=10, pady=8, wrap=kw.pop("wrap", "none"),
        undo=kw.pop("undo", False), **kw,
    )
    t.configure(state="disabled")
    return t
