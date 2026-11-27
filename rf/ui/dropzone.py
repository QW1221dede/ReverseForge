#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 rf.ui.dropzone · 左栏文件投放区（拖拽 / 选择）
============================================================================

【要解决的问题】
    以前用这个工具，得先选脚本、再在参数区点"浏览"、一个文件一个文件挑。
    实际用起来是"手里有一堆东西想一起看"——拖进来最省事。

【行为】
    · 把文件（或整个文件夹）拖到方块里 → 自动识别类型、大小，进队列
    · 拖拽不可用时（没装 tkinterdnd2）→ 方块照样可点，弹文件选择框
    · 队列支持多选、移除、清空、按类型过滤显示
    · 类型识别只在加入时做一次（缓存），几千个文件也不会卡

【为什么不自己写拖拽】
    Windows 拖拽要挂 WM_DROPFILES 并子类化窗口过程（ctypes + WNDPROC），
    一旦写错，整个窗口的消息循环都会出问题。
    tkinterdnd2 已经把这个做稳了，能装就用它；不能装就降级成"点击选择"，
    并且**在界面上明确写出来**，不做"看起来能拖但没反应"的假象。

【拖拽回来的路径格式】
    tkdnd 给的是 Tcl 列表字符串：
        {C:/path with space/a.txt} C:/b.txt
    所以不能简单 split()，要用 Tcl 的 splitlist 规则解析。
============================================================================
"""

from __future__ import annotations

import heapq
import os
import time
import tkinter as tk
from dataclasses import dataclass, field
from pathlib import Path
from tkinter import filedialog, ttk

from . import theme as T

# 拖拽支持（可选）
try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    HAS_DND = True
except Exception:                                    # pragma: no cover
    DND_FILES = None
    TkinterDnD = None
    HAS_DND = False


def _parser_drop(data: str) -> list[str]:
    """
    解析 tkdnd 拖回来的路径串。
    `{C:/a b/x.txt} C:/y.txt` 这种带空格的花括号形式，必须用 Tcl 规则切。
    """
    s = (data or "").strip()
    if not s:
        return []
    out: list[str] = []
    buf: list[str] = []
    depth = 0
    for ch in s:
        if ch == "{":
            depth += 1
            if depth == 1:
                continue
        elif ch == "}":
            depth -= 1
            if depth == 0:
                out.append("".join(buf))
                buf = []
                continue
        elif ch in " \t" and depth == 0:
            if buf:
                out.append("".join(buf))
                buf = []
            continue
        buf.append(ch)
    if buf:
        out.append("".join(buf))
    return [x for x in out if x]


def _human(n: int) -> str:
    if n < 1024:
        return f"{n}B"
    if n < 1024 * 1024:
        return f"{n / 1024:.0f}KB"
    if n < 1024 ** 3:
        return f"{n / 1024 / 1024:.1f}MB"
    return f"{n / 1024 ** 3:.2f}GB"


# ---------------------------------------------------------------------------
# 队列条目
# ---------------------------------------------------------------------------

@dataclass
class InputFile:
    path: Path
    size: int = 0
    label: str = ""          # 类型中文名
    real: str = ""           # 机器标签
    category: str = ""
    confidence: int = 0
    entropy: float = 0.0
    note: str = ""
    added: float = field(default_factory=time.time)

    @property
    def name(self) -> str:
        return self.path.name or str(self.path)

    def row(self) -> tuple[str, str, str]:
        return (self.name, self.label or "…", _human(self.size))


# ---------------------------------------------------------------------------
# 投放区控件
# ---------------------------------------------------------------------------

class FileDropZone(tk.Frame):
    """
    长方形投放区 + 文件队列。
    on_change(files)  列表变化时回调
    on_analyze()      点「分析」时回调
    """

    MAX_FILES = 400

    def __init__(self, master, on_change=None, on_analyze=None,
                 height: int = 9, **kw):
        super().__init__(master, bg=T.PANEL, **kw)
        self.on_change = on_change
        self.on_analyze = on_analyze
        self.files: list[InputFile] = []
        self._seen: set[str] = set()

        # ---- 标题 ----
        head = tk.Frame(self, bg=T.PANEL)
        head.pack(fill="x", pady=(0, 4))
        tk.Label(head, text="投放文件", bg=T.PANEL, fg=T.TEXT,
                 font=T.UI_FONT_B).pack(side="left")
        self.lbl_count = tk.Label(head, text="0 个", bg=T.PANEL, fg=T.MUTED,
                                  font=T.UI_FONT_S)
        self.lbl_count.pack(side="right")

        # ---- 投放方块 ----
        self.box = tk.Frame(self, bg=T.PANEL2, height=54,
                            highlightthickness=1, highlightbackground=T.BORDER,
                            highlightcolor=T.ACCENT, cursor="hand2")
        self.box.pack(fill="x")
        self.box.pack_propagate(False)

        self.lbl_hint = tk.Label(
            self.box,
            text=("拖文件 / 文件夹到这里\n（也可以点一下选择）" if HAS_DND
                  else "点一下选择文件\n（拖拽需要 tkinterdnd2）"),
            bg=T.PANEL2, fg=T.MUTED, font=T.UI_FONT_S, justify="center",
            cursor="hand2")
        self.lbl_hint.pack(expand=True, fill="both")
        for w in (self.box, self.lbl_hint):
            w.bind("<Button-1>", lambda e: self.pick_files())

        # ---- 文件列表 ----
        wrap = tk.Frame(self, bg=T.PANEL)
        wrap.pack(fill="both", expand=True, pady=(6, 0))
        cols = ("name", "type", "size")
        self.tree = ttk.Treeview(wrap, columns=cols, show="headings",
                                 height=height, selectmode="extended")
        self.tree.heading("name", text="文件")
        self.tree.heading("type", text="类型")
        self.tree.heading("size", text="大小")
        self.tree.column("name", width=150, anchor="w")
        self.tree.column("type", width=96, anchor="w")
        self.tree.column("size", width=56, anchor="e")
        self.tree.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(wrap, orient="vertical", command=self.tree.yview)
        sb.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.bind("<Double-1>", lambda e: self._open_selected())
        self.tree.bind("<Delete>", lambda e: self.remove_selected())

        # ---- 按钮 ----
        bar = tk.Frame(self, bg=T.PANEL)
        bar.pack(fill="x", pady=(4, 0))
        ttk.Button(bar, text="＋文件", style="Ghost.TButton",
                   command=self.pick_files).pack(side="left")
        ttk.Button(bar, text="＋文件夹", style="Ghost.TButton",
                   command=self.pick_folder).pack(side="left", padx=4)
        ttk.Button(bar, text="移除", style="Ghost.TButton",
                   command=self.remove_selected).pack(side="left")
        ttk.Button(bar, text="清空", style="Ghost.TButton",
                   command=self.clear).pack(side="left", padx=4)
        self.btn_analyze = ttk.Button(bar, text="分析", style="Accent.TButton",
                                      command=self._analyze)
        self.btn_analyze.pack(side="right")

        self._setup_dnd()

    # ---- 拖拽 ----
    def _setup_dnd(self) -> None:
        if not HAS_DND:
            return
        try:
            for w in (self.box, self.lbl_hint, self.tree):
                w.drop_target_register(DND_FILES)
                w.dnd_bind("<<Drop>>", self._on_drop)
                w.dnd_bind("<<DropEnter>>", lambda e: self._hl(True))
                w.dnd_bind("<<DropLeave>>", lambda e: self._hl(False))
        except Exception as e:                       # noqa: BLE001
            self.lbl_hint.configure(text=f"拖拽初始化失败：{e}\n点这里选择文件")

    def _hl(self, on: bool) -> None:
        try:
            self.box.configure(highlightbackground=T.ACCENT if on else T.BORDER,
                               bg=T.SEL if on else T.PANEL2)
            self.lbl_hint.configure(bg=T.SEL if on else T.PANEL2,
                                    fg=T.ACCENT if on else T.MUTED)
        except tk.TclError:
            pass

    def _on_drop(self, event) -> None:
        self._hl(False)
        paths = _parser_drop(getattr(event, "data", "") or "")
        self.add_paths(paths)

    # ---- 添加 ----
    def pick_files(self) -> None:
        ps = filedialog.askopenfilenames(title="选择要分析的文件")
        if ps:
            self.add_paths(list(ps))

    def pick_folder(self) -> None:
        p = filedialog.askdirectory(title="选择文件夹（会递归加入其中的文件）")
        if p:
            self.add_paths([p])

    def add_paths(self, paths: list[str]) -> int:
        """加入一批路径；目录会递归展开（受 MAX_FILES 限制）。返回新增数量。"""
        from ..analysis import filetype

        added = 0
        for raw in paths:
            p = Path(raw)
            if p.is_dir():
                try:
                    # 只留最大的 MAX_FILES 个：先物化再排序，几万文件的目录
                    # 会在主线程上冻住整个窗口
                    subs = heapq.nlargest(
                        self.MAX_FILES,
                        (x for x in p.rglob("*") if x.is_file()),
                        key=_safe_size)
                except OSError:
                    subs = []
                for sub in subs:
                    if added + len(self.files) >= self.MAX_FILES:
                        break
                    added += self._add_one(sub, filetype)
            elif p.is_file():
                if added + len(self.files) >= self.MAX_FILES:
                    break
                added += self._add_one(p, filetype)

        if added:
            self._refresh()
            self._changed()
        return added

    def _add_one(self, p: Path, filetype) -> int:
        key = str(p.resolve()).lower()
        if key in self._seen:
            return 0
        try:
            size = p.stat().st_size
        except OSError:
            return 0
        item = InputFile(path=p, size=size)
        try:
            k = filetype.sniff(p)
            item.label, item.real, item.category = k.label, k.real, k.category
            item.confidence, item.entropy = k.confidence, k.entropy
            item.note = "；".join(k.notes[:2])
        except Exception as e:                       # noqa: BLE001
            item.label = "识别失败"
            item.note = str(e)
        self.files.append(item)
        self._seen.add(key)
        return 1

    # ---- 移除 ----
    def remove_selected(self) -> None:
        sel = list(self.tree.selection())
        if not sel:
            return
        idxs = sorted((self.tree.index(i) for i in sel), reverse=True)
        for i in idxs:
            if 0 <= i < len(self.files):
                f = self.files.pop(i)
                self._seen.discard(str(f.path.resolve()).lower())
        self._refresh()
        self._changed()

    def clear(self) -> None:
        self.files.clear()
        self._seen.clear()
        self._refresh()
        self._changed()

    def selected_files(self) -> list[InputFile]:
        sel = self.tree.selection()
        if not sel:
            return list(self.files)
        return [self.files[self.tree.index(i)] for i in sel
                if 0 <= self.tree.index(i) < len(self.files)]

    def _open_selected(self) -> None:
        from .app import open_path
        sel = self.selected_files()
        if sel:
            open_path(sel[0].path.parent)

    # ---- 刷新 ----
    def _refresh(self) -> None:
        for i in self.tree.get_children():
            self.tree.delete(i)
        for f in self.files:
            self.tree.insert("", "end", values=f.row())
        n = len(self.files)
        self.lbl_count.configure(text=f"{n} 个" if n else "0 个",
                                 fg=T.OK if n else T.MUTED)
        self.btn_analyze.configure(state="normal" if n else "disabled")

    def _changed(self) -> None:
        if self.on_change:
            try:
                self.on_change(self.files)
            except Exception:                        # noqa: BLE001
                pass

    def _analyze(self) -> None:
        if self.on_analyze and self.files:
            self.on_analyze(list(self.files))

    # ---- 摘要（给编排器/日志用） ----
    def summary(self) -> dict:
        by_cat: dict[str, int] = {}
        for f in self.files:
            by_cat[f.category or "unknown"] = by_cat.get(f.category or "unknown", 0) + 1
        return {
            "count": len(self.files),
            "total_size": sum(f.size for f in self.files),
            "by_category": by_cat,
            "paths": [str(f.path) for f in self.files],
        }


def _safe_size(p: Path) -> int:
    try:
        return p.stat().st_size
    except OSError:
        return 0
