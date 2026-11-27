#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 rf.ui.app · 主窗口
============================================================================

【界面结构】

    ┌──────────────────────────────────────────────────────────────┐
    │ ReverseForge 逆锻台            工具 17/17  [工具链] [工作区] │
    ├───────────────┬──────────────────────────────────────────────┤
    │ 脚本库        │  终端 │ 产物 │ 报告                            │
    │  拆解 APK     │  ┌────────────────────────────────────────┐  │
    │  分析 so      │  │ ▶ 运行脚本 ...                          │  │
    │  ...          │  │ ── [ 12%] 资源解包 · apktool d          │  │
    │ ─────────     │  │ ✓ 资源解包完成：smali 152 个            │  │
    │ 参数          │  └────────────────────────────────────────┘  │
    │  目标 [....]  │  [=========进度=========] 42%                │
    │  □ 加注释     │                                              │
    │  [ 开 始 ]    │                                              │
    ├───────────────┴──────────────────────────────────────────────┤
    │ 就绪 · 17 个工具可用                        v0.1.0           │
    └──────────────────────────────────────────────────────────────┘

【线程模型】
    GUI 主线程只做界面；脚本在 ScriptRun 的线程里跑；
    子进程输出 → 事件队列 → after(60ms) 轮询消费 → 终端。
    任何一条链路都不允许在 UI 线程里阻塞 —— 这是 tkinter 唯一的铁律。
============================================================================
"""

from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading
import time
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .. import config
from ..tools import runner
from ..tools.registry import registry
from ..engine.script_runtime import ScriptMeta, ScriptRun, discover_scripts, parse_meta
from . import theme as T

APP_TITLE = "ReverseForge · 逆锻台"


def open_path(p: str | Path) -> None:
    """在系统文件管理器里打开路径。"""
    p = str(p)
    try:
        if sys.platform == "win32":
            os.startfile(p)      # noqa: S606
        elif sys.platform == "darwin":
            subprocess.Popen(["open", p])
        else:
            subprocess.Popen(["xdg-open", p])
    except Exception:
        pass


# 有 tkinterdnd2 就用它做根窗口（拖拽才生效），没有就退回普通 Tk
try:
    from tkinterdnd2 import TkinterDnD as _DND

    _ROOT_BASE = _DND.Tk
    HAS_DND = True
except Exception:                                    # pragma: no cover
    _ROOT_BASE = tk.Tk
    HAS_DND = False


class App(_ROOT_BASE):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        # 按屏幕自适应：小屏（1366×768）也不会超出可视区
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        w = min(1340, int(sw * 0.88))
        h = min(860, int(sh * 0.84))
        x = max(0, (sw - w) // 2)
        y = max(0, (sh - h) // 2 - 24)
        self.geometry(f"{w}x{h}+{x}+{y}")
        self.minsize(1000, 640)
        self.configure(bg=T.BG)
        T.apply(self)

        config.ensure_dirs()

        # 状态
        self.scripts: list[ScriptMeta] = []
        self.current: ScriptMeta | None = None
        self.param_vars: dict[str, tuple[str, tk.Variable]] = {}
        self.run: ScriptRun | None = None
        self._tools_ready = False
        self._pct = 0
        self._last_dir: Path | None = None
        self._closing = False        # 关闭窗口时置位，三个 pump 见到就停
        self._ui_q: "queue.Queue" = queue.Queue()   # 后台线程 → 主线程的 UI 投递

        self._build_menu()
        self._build_header()
        self._build_body()
        self._build_status()

        # 冒烟测试/演示用：RF_START_TAB=3 直接打开「积木」页
        tab = os.environ.get("RF_START_TAB", "")
        if tab.isdigit():
            try:
                self.after(300, lambda: self.nb.select(int(tab)))
            except Exception:
                pass
        # 演示/冒烟：RF_PATCH_DIR 指定目录后自动扫描
        pdir = os.environ.get("RF_PATCH_DIR", "")
        if pdir:
            def _auto_patch() -> None:
                self.nb.select(4)
                self.patch_target.set(pdir)
                self._patch_scan()
            self.after(500, _auto_patch)

        self.protocol("WM_DELETE_WINDOW", self._on_close)

        # 先出界面，再后台探测工具（探测要 1-5 秒，不能卡住窗口）
        self.after(50, self._load_scripts)
        self.after(120, self._load_tools_async)
        self.after(60, self._pump)
        self.after(900, self._first_run_hint)

        self._term("ReverseForge 已就绪。", "ok")
        self._term("选一个脚本，填好参数，点「开始」。", "muted")

    # ==================================================================
    # 菜单
    # ==================================================================
    def _build_menu(self) -> None:
        m = tk.Menu(self, tearoff=0, bg=T.PANEL2, fg=T.TEXT,
                    activebackground=T.SEL, activeforeground=T.TEXT,
                    borderwidth=0, font=T.UI_FONT)

        fm = tk.Menu(m, tearoff=0, bg=T.PANEL2, fg=T.TEXT,
                     activebackground=T.SEL, activeforeground=T.TEXT, borderwidth=0,
                     font=T.UI_FONT)
        fm.add_command(label="打开脚本目录", command=lambda: open_path(config.BUILTIN_SCRIPT_ROOT))
        fm.add_command(label="打开用户脚本目录", command=lambda: open_path(config.SCRIPT_ROOT))
        fm.add_command(label="打开工作区", command=lambda: open_path(config.WORKSPACE_ROOT))
        fm.add_separator()
        fm.add_command(label="退出", command=self._on_close)
        m.add_cascade(label="文件", menu=fm)

        tm = tk.Menu(m, tearoff=0, bg=T.PANEL2, fg=T.TEXT,
                     activebackground=T.SEL, activeforeground=T.TEXT, borderwidth=0,
                     font=T.UI_FONT)
        tm.add_command(label="工具链状态", command=self._show_tools)
        tm.add_command(label="重新探测全部工具", command=lambda: self._load_tools_async(force=True))
        tm.add_separator()
        tm.add_command(label="创建桌面快捷方式", command=self._make_shortcut)
        tm.add_command(label="终止所有子进程", command=self._stop)
        m.add_cascade(label="工具", menu=tm)

        hm = tk.Menu(m, tearoff=0, bg=T.PANEL2, fg=T.TEXT,
                     activebackground=T.SEL, activeforeground=T.TEXT, borderwidth=0,
                     font=T.UI_FONT)
        hm.add_command(label="脚本写法说明", command=self._show_help)
        hm.add_separator()
        hm.add_command(label="使用前须知（杀软 / 免责）", command=self._show_notice)
        hm.add_command(label="打开免责声明 DISCLAIMER.md", command=self._open_disclaimer)
        hm.add_command(label="打开杀软说明 SECURITY.md", command=self._open_security)
        hm.add_separator()
        hm.add_command(label="环境安装（缺工具时）", command=self._open_install)
        m.add_cascade(label="帮助", menu=hm)
        self.config(menu=m)

    # ==================================================================
    # 顶部
    # ==================================================================
    def _build_header(self) -> None:
        h = tk.Frame(self, bg=T.BG, height=74)
        h.pack(fill="x", side="top")
        h.pack_propagate(False)

        # 标识
        mark = tk.Canvas(h, width=32, height=32, bg=T.BG, highlightthickness=0)
        mark.create_rectangle(3, 3, 29, 29, outline=T.ACCENT, width=2)
        mark.create_line(10, 23, 16, 9, 22, 23, fill=T.ACCENT, width=2)
        mark.pack(side="left", padx=(18, 11), pady=21)

        box = tk.Frame(h, bg=T.BG)
        box.pack(side="left", pady=14)
        tk.Label(box, text="ReverseForge", bg=T.BG, fg=T.TEXT,
                 font=(T.UI_FONT[0], 15, "bold")).pack(anchor="w")
        tk.Label(box, text="逆锻台 · 逆向工作台", bg=T.BG, fg=T.MUTED,
                 font=T.UI_FONT_S).pack(anchor="w", pady=(2, 0))

        # 右侧状态
        right = tk.Frame(h, bg=T.BG)
        right.pack(side="right", padx=18)

        self.lbl_tools = tk.Label(right, text="工具 探测中…", bg=T.BG, fg=T.MUTED,
                                  font=T.UI_FONT_S)
        self.lbl_tools.pack(side="left", padx=(0, 12))

        ttk.Button(right, text="工作区", style="Ghost.TButton",
                   command=lambda: open_path(config.WORKSPACE_ROOT)).pack(side="left", padx=4)
        ttk.Button(right, text="工具链", style="Ghost.TButton",
                   command=self._show_tools).pack(side="left", padx=4)

        tk.Frame(self, bg=T.BORDER, height=1).pack(fill="x")

    # ==================================================================
    # 主体
    # ==================================================================
    def _build_body(self) -> None:
        body = tk.Frame(self, bg=T.BG)
        body.pack(fill="both", expand=True)

        pw = tk.PanedWindow(body, orient="horizontal", bg=T.BG,
                            sashwidth=5, sashrelief="flat", bd=0,
                            handlesize=0, showhandle=False)
        pw.pack(fill="both", expand=True, padx=10, pady=10)

        left = tk.Frame(pw, bg=T.PANEL, width=336)
        right = tk.Frame(pw, bg=T.PANEL)
        pw.add(left, minsize=300, width=336)
        pw.add(right, minsize=560)

        self._build_left(left)
        self._build_right(right)

    # ---------------- 左：脚本 + 参数 ----------------
    def _build_left(self, root: tk.Frame) -> None:
        # ---- 文件投放区（拖拽 / 选择）----
        from .dropzone import FileDropZone

        self.drop = FileDropZone(root, on_change=self._on_files_changed,
                                 on_analyze=self._on_files_analyze, height=5)
        self.drop.pack(fill="x", padx=10, pady=(12, 6))
        tk.Frame(root, bg=T.BORDER, height=1).pack(fill="x", padx=14, pady=(0, 6))

        # 标题行
        top = tk.Frame(root, bg=T.PANEL)
        top.pack(fill="x", padx=14, pady=(2, 6))
        tk.Label(top, text="脚本库", bg=T.PANEL, fg=T.TEXT,
                 font=T.UI_FONT_B).pack(side="left")
        ttk.Button(top, text="刷新", style="Ghost.TButton",
                   command=self._load_scripts).pack(side="right")

        # 脚本列表
        wrap = tk.Frame(root, bg=T.PANEL)
        wrap.pack(fill="both", expand=False, padx=10, pady=(0, 8))

        self.lb = tk.Listbox(
            wrap, bg=T.PANEL2, fg=T.TEXT, selectbackground=T.SEL,
            selectforeground=T.ACCENT, borderwidth=0, highlightthickness=0,
            font=T.UI_FONT, activestyle="none", height=7,
            exportselection=False,
        )
        self.lb.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(wrap, orient="vertical", command=self.lb.yview)
        sb.pack(side="right", fill="y")
        self.lb.configure(yscrollcommand=sb.set)
        self.lb.bind("<<ListboxSelect>>", self._on_pick_script)

        # 脚本说明
        self.lbl_desc = tk.Label(root, text="", bg=T.PANEL, fg=T.MUTED,
                                 font=T.UI_FONT_S, justify="left", anchor="w",
                                 wraplength=300)
        self.lbl_desc.pack(fill="x", padx=16, pady=(0, 10))

        tk.Frame(root, bg=T.BORDER, height=1).pack(fill="x", padx=14)

        # 参数区
        hd = tk.Frame(root, bg=T.PANEL)
        hd.pack(fill="x", padx=14, pady=(10, 4))
        tk.Label(hd, text="参数", bg=T.PANEL, fg=T.TEXT,
                 font=T.UI_FONT_B).pack(side="left")

        self.param_box = tk.Frame(root, bg=T.PANEL)
        self.param_box.pack(fill="both", expand=True, padx=14, pady=(0, 8))

        # 底部操作
        tk.Frame(root, bg=T.BORDER, height=1).pack(fill="x", padx=14)
        act = tk.Frame(root, bg=T.PANEL)
        act.pack(fill="x", padx=14, pady=12)

        self.btn_run = ttk.Button(act, text="开 始", style="Accent.TButton",
                                  command=self._run)
        self.btn_run.pack(side="left", fill="x", expand=True)
        self.btn_stop = ttk.Button(act, text="停止", style="TButton",
                                   command=self._stop, state="disabled", width=6)
        self.btn_stop.pack(side="left", padx=(8, 0))

    # ---------------- 投放区回调 ----------------
    def _on_files_changed(self, files) -> None:
        n = len(files)
        # 投放区一变，参数区里所有路径项同步更新（它们没有独立输入框）
        self._drop_sync()
        if n:
            by: dict[str, int] = {}
            for f in files:
                by[f.label] = by.get(f.label, 0) + 1
            top = "、".join(f"{k}×{v}" for k, v in
                            sorted(by.items(), key=lambda kv: -kv[1])[:3])
            self.lbl_status.configure(text=f"投放区 {n} 个文件：{top}")
        else:
            self.lbl_status.configure(text="就绪")

    def _on_files_analyze(self, files) -> None:
        """投放区点「分析」：先在终端给一份即时画像，再交给编排器。"""
        if not files:
            return
        self.nb.select(0)
        self._term(f"\n■ 投放区：{len(files)} 个文件，开始分析\n", "cmd")

        # 有对话页就走编排器；没有就先跑内置快扫
        if hasattr(self, "_chat_dispatch"):
            # 不能用"解密"开头：意图识别会把整件事判成只解密，
            # 直接跳过卡密/授权扫描（用户丢外挂就是这么漏的）。
            self._chat_dispatch(
                "全面分析这些文件：识别类型、找卡密/密码/授权校验，"
                "再查明文头与密文，最后尝试还原明文",
                [str(f.path) for f in files])
            return

        threading.Thread(target=self._quick_analyze,
                         args=([str(f.path) for f in files],), daemon=True).start()

    def _quick_analyze(self, paths: list[str]) -> None:
        """不依赖编排器的兜底快扫（后台线程，输出回主线程）。"""
        from ..api import make_api

        api = make_api()
        lines: list[str] = []
        api.log = lambda m: lines.append(str(m))
        try:
            for i, p in enumerate(paths[:40]):
                self._post(self.lbl_status.configure,
                           text=f"分析 {i + 1}/{min(len(paths), 40)}：{Path(p).name}")
                try:
                    kind = api.file_type(p)
                    if kind.category == "encrypted":
                        sm = api.segments(p)
                        if sm.split.found and sm.split.head_keys:
                            api.log("  头部密钥：" + "、".join(sm.split.head_keys))
                    elif kind.category == "script":
                        api.auth_scan(Path(p).parent if Path(p).is_dir() else p)
                except Exception as e:               # noqa: BLE001
                    api.log(f"  ! {Path(p).name}: {e}")
        finally:
            text = "\n".join(lines) + "\n"
            self._post(self._term, text, "ok")
            self._post(self.lbl_status.configure, text="投放区分析完成")

    # ---------------- 右：终端 / 产物 / 报告 ----------------
    def _build_right(self, root: tk.Frame) -> None:
        nb = ttk.Notebook(root)
        nb.pack(fill="both", expand=True, padx=(0, 0), pady=0)
        self.nb = nb

        # --- 终端 ---
        tframe = tk.Frame(nb, bg=T.PANEL)
        nb.add(tframe, text="  终端  ")

        bar = tk.Frame(tframe, bg=T.PANEL)
        bar.pack(fill="x", padx=12, pady=(10, 4))

        self.bar = ttk.Progressbar(bar, style="Thin.Horizontal.TProgressbar",
                                   mode="determinate", maximum=100)
        self.bar.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.lbl_pct = tk.Label(bar, text="0%", bg=T.PANEL, fg=T.MUTED,
                                font=T.UI_FONT_S, width=5, anchor="e")
        self.lbl_pct.pack(side="left")

        ttk.Button(bar, text="清空", style="Ghost.TButton",
                   command=self._clear_term).pack(side="left", padx=(10, 0))
        ttk.Button(bar, text="导出", style="Ghost.TButton",
                   command=self._export_log).pack(side="left", padx=(4, 0))

        tw = tk.Frame(tframe, bg=T.PANEL)
        tw.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self.term = T.make_text(tw, mono=True)
        self.term.pack(side="left", fill="both", expand=True)
        tsb = ttk.Scrollbar(tw, orient="vertical", command=self.term.yview)
        tsb.pack(side="right", fill="y")
        self.term.configure(yscrollcommand=tsb.set)
        self._init_term_tags()

        # --- 产物 ---
        aframe = tk.Frame(nb, bg=T.PANEL)
        nb.add(aframe, text="  产物  ")

        abar = tk.Frame(aframe, bg=T.PANEL)
        abar.pack(fill="x", padx=12, pady=(10, 6))
        self.lbl_out = tk.Label(abar, text="（尚未产生产物）", bg=T.PANEL, fg=T.MUTED,
                                font=T.UI_FONT_S, anchor="w")
        self.lbl_out.pack(side="left", fill="x", expand=True)
        ttk.Button(abar, text="刷新", style="Ghost.TButton",
                   command=self._refresh_artifacts).pack(side="left", padx=4)
        ttk.Button(abar, text="打开目录", style="Ghost.TButton",
                   command=self._open_out).pack(side="left", padx=4)

        tw2 = tk.Frame(aframe, bg=T.PANEL)
        tw2.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        cols = ("size",)
        self.tree = ttk.Treeview(tw2, columns=cols, show="tree headings",
                                 selectmode="browse")
        self.tree.heading("#0", text="文件", anchor="w")
        self.tree.heading("size", text="大小", anchor="e")
        self.tree.column("#0", width=520, anchor="w")
        self.tree.column("size", width=100, anchor="e", stretch=False)
        self.tree.pack(side="left", fill="both", expand=True)
        tsb2 = ttk.Scrollbar(tw2, orient="vertical", command=self.tree.yview)
        tsb2.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=tsb2.set)
        self.tree.bind("<Double-1>", self._open_tree_item)

        # --- 报告 ---
        rframe = tk.Frame(nb, bg=T.PANEL)
        nb.add(rframe, text="  报告  ")

        rbar = tk.Frame(rframe, bg=T.PANEL)
        rbar.pack(fill="x", padx=12, pady=(10, 6))
        self.lbl_rep = tk.Label(rbar, text="（尚未生成报告）", bg=T.PANEL, fg=T.MUTED,
                                font=T.UI_FONT_S, anchor="w")
        self.lbl_rep.pack(side="left", fill="x", expand=True)
        ttk.Button(rbar, text="刷新", style="Ghost.TButton",
                   command=self._load_report).pack(side="left", padx=4)

        rw = tk.Frame(rframe, bg=T.PANEL)
        rw.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self.report = T.make_text(rw, mono=False, bg=T.PANEL, fg=T.TEXT)
        self.report.pack(side="left", fill="both", expand=True)
        rsb = ttk.Scrollbar(rw, orient="vertical", command=self.report.yview)
        rsb.pack(side="right", fill="y")
        self.report.configure(yscrollcommand=rsb.set)
        self.report.tag_configure("h1", foreground=T.ACCENT,
                                  font=(T.UI_FONT[0], 14, "bold"), spacing1=8, spacing3=6)
        self.report.tag_configure("h2", foreground="#9ecbff",
                                  font=(T.UI_FONT[0], 11, "bold"), spacing1=10, spacing3=4)
        self.report.tag_configure("code", foreground=T.MUTED, font=T.MONO_FONT)

        self._build_snippets_tab(nb)
        self._build_patch_tab(nb)
        self._build_repl_tab(nb)
        self._build_chat_tab(nb)
        self._build_fullauto_tab(nb)

    # ---------------- 状态栏 ----------------
    def _build_status(self) -> None:
        tk.Frame(self, bg=T.BORDER, height=1).pack(fill="x", side="bottom")
        s = tk.Frame(self, bg=T.BG, height=26)
        s.pack(fill="x", side="bottom")
        s.pack_propagate(False)

        self.lbl_status = tk.Label(s, text="就绪", bg=T.BG, fg=T.MUTED,
                                   font=T.UI_FONT_S)
        self.lbl_status.pack(side="left", padx=16)
        tk.Label(s, text=f"v{config.APP_VERSION}", bg=T.BG, fg=T.MUTED,
                 font=T.UI_FONT_S).pack(side="right", padx=16)

    # ==================================================================
    # 终端
    # ==================================================================
    def _init_term_tags(self) -> None:
        self.term.tag_configure("cmd", foreground=T.TERM_CMD)
        self.term.tag_configure("ok", foreground=T.TERM_OK)
        self.term.tag_configure("warn", foreground=T.TERM_WARN)
        self.term.tag_configure("err", foreground=T.TERM_ERR)
        self.term.tag_configure("head", foreground=T.ACCENT,
                                font=(T.MONO_FONT[0], T.MONO_FONT[1], "bold"))
        self.term.tag_configure("muted", foreground=T.MUTED)
        self.term.tag_configure("text", foreground=T.TERM_FG)

    def _term(self, line: str, tag: str = "text") -> None:
        self.term.configure(state="normal")
        self.term.insert("end", line + "\n", tag)
        self.term.see("end")
        self.term.configure(state="disabled")

    def _classify(self, line: str) -> str:
        s = line.lstrip()
        if s.startswith("$ "):
            return "cmd"
        if s.startswith("═") or s.startswith("── [") or s.startswith("▶"):
            return "head"
        if s.startswith("✓"):
            return "ok"
        if s.startswith("✗") or s.startswith("ERROR") or "Traceback" in line:
            return "err"
        if s.startswith("⚠") or s.startswith("!"):
            return "warn"
        if s.startswith("  ·") or s.startswith("  "):
            return "muted"
        return "text"

    def _clear_term(self) -> None:
        self.term.configure(state="normal")
        self.term.delete("1.0", "end")
        self.term.configure(state="disabled")

    def _export_log(self) -> None:
        p = filedialog.asksaveasfilename(
            title="导出终端日志", defaultextension=".log",
            initialfile=time.strftime("rf_log_%Y%m%d_%H%M%S.log"),
            filetypes=[("日志", "*.log"), ("全部", "*.*")])
        if not p:
            return
        try:
            Path(p).write_text(self.term.get("1.0", "end"), encoding="utf-8")
            self._term(f"✓ 已导出到 {p}", "ok")
        except OSError as e:
            self._term(f"✗ 导出失败：{e}", "err")

    # ==================================================================
    # 脚本库
    # ==================================================================
    def _load_scripts(self) -> None:
        try:
            self.scripts = discover_scripts()
        except Exception as e:
            self._term(f"✗ 脚本扫描失败：{e}", "err")
            return
        self.lb.delete(0, "end")
        for s in self.scripts:
            self.lb.insert("end", "  " + (s.name or Path(s.file).stem))
        # 列表高度跟着脚本数量走，避免底下挂一串空行
        try:
            self.lb.configure(height=max(4, min(9, len(self.scripts) or 4)))
        except Exception:
            pass
        if self.scripts:
            self.lb.selection_set(0)
            self._on_pick_script()
        else:
            self.lbl_desc.configure(text="没有找到脚本。把 .py 放到 scripts/ 目录下，"
                                        "或用「文件 → 打开脚本目录」查看位置。")

    def _on_pick_script(self, _evt=None) -> None:
        sel = self.lb.curselection()
        if not sel:
            return
        idx = sel[0]
        if idx >= len(self.scripts):
            return
        self.current = self.scripts[idx]
        self.lbl_desc.configure(text=self.current.desc or "（无说明）")
        self._render_params(self.current)

    def _render_params(self, meta: ScriptMeta) -> None:
        for w in self.param_box.winfo_children():
            w.destroy()
        self.param_vars = {}
        self._drop_labels = []

        if not meta.params:
            tk.Label(self.param_box, text="此脚本无需参数，直接点「开始」。",
                     bg=T.PANEL, fg=T.MUTED, font=T.UI_FONT_S,
                     justify="left", wraplength=290).pack(anchor="w", pady=6)
            return

        for p in meta.params:
            # 开关类参数：勾选框自己带文字，不需要左侧那列标签
            if p.ptype == "bool":
                rowb = tk.Frame(self.param_box, bg=T.PANEL)
                rowb.pack(fill="x", pady=3)
                var = tk.BooleanVar(value=bool(p.default))
                tk.Checkbutton(
                    rowb, text=p.label, variable=var,
                    bg=T.PANEL, fg=T.TEXT, activebackground=T.PANEL,
                    activeforeground=T.TEXT, selectcolor=T.PANEL2,
                    borderwidth=0, highlightthickness=0,
                    font=T.UI_FONT_S, anchor="w",
                ).pack(side="left")
                self.param_vars[p.name] = ("bool", var)
                continue

            row = tk.Frame(self.param_box, bg=T.PANEL)
            row.pack(fill="x", pady=4)

            tk.Label(row, text=p.label, bg=T.PANEL, fg=T.MUTED,
                     font=T.UI_FONT_S, anchor="w", width=11).pack(side="left")

            if p.ptype == "choice":
                # 默认值必须在候选里：脚本写错或者改了候选，StringVar 里留一个
                # 不存在的值（如 "pack:all"）会原样传给脚本，执行范围直接错。
                d0 = str(p.default or "")
                if d0 not in p.choices:
                    d0 = p.choices[0] if p.choices else ""
                var = tk.StringVar(value=d0)
                cbx = ttk.Combobox(row, textvariable=var, values=p.choices,
                                   state="readonly", width=14)
                cbx.pack(side="left", fill="x", expand=True)
                self.param_vars[p.name] = ("str", var)

            elif p.ptype in ("file", "dir"):
                # 不给人填路径了 —— 所有路径参数统一从左上投放区取。
                # 以前这里有 apk/path/target/smali_dir 好几个框，名字乱、还经常空着，
                # 脚本直接跑不起来。现在只显示"投放区 → xxx"，一个入口。
                row.configure(bg=T.PANEL2)
                tk.Label(row, text="目标", bg=T.PANEL2, fg=T.MUTED,
                         font=T.UI_FONT_S, anchor="w", width=11).pack(side="left")
                var = tk.StringVar(value="")
                shown = tk.Label(row, text="（拖文件到左上投放区）",
                                 bg=T.PANEL2, fg=T.MUTED, font=T.UI_FONT_S,
                                 anchor="w", wraplength=190, justify="left")
                shown.pack(side="left", fill="x", expand=True)
                self.param_vars[p.name] = (f"drop:{p.ptype}", var)
                self._drop_labels.append((var, shown, p.ptype))

            else:  # str / int
                var = tk.StringVar(value=str(p.default if p.default != "" else ""))
                ent = ttk.Entry(row, textvariable=var)
                ent.pack(side="left", fill="x", expand=True)
                self.param_vars[p.name] = ("int" if p.ptype == "int" else "str", var)

        # 参数少时用提示把底部填满，避免大片空白
        tk.Frame(self.param_box, bg=T.PANEL).pack(fill="both", expand=True)
        tk.Label(
            self.param_box,
            text="目标统一从左上「投放文件」区取。\n"
                 "拖进来 → 选脚本 → 开始。不用再填 APK 路径。",
            bg=T.PANEL, fg="#6b7689", font=T.UI_FONT_S,
            justify="left", anchor="w", wraplength=290,
        ).pack(anchor="w", pady=(10, 2))
        self._drop_sync()

    # ---- 所有路径参数的唯一来源：投放区 ----
    def _drop_target(self, kind: str = "file") -> str:
        files = getattr(self, "drop", None) and self.drop.files
        if not files:
            return ""
        if kind == "dir":
            parents = {str(f.path.parent) for f in files}
            if len(parents) == 1:
                return parents.pop()
            return str(files[0].path.parent)
        return str(files[0].path)

    def _drop_sync(self) -> None:
        """投放区一变，所有路径参数的显示同步刷新。"""
        for var, shown, kind in getattr(self, "_drop_labels", []):
            v = self._drop_target(kind)
            var.set(v)
            if v:
                p = Path(v)
                shown.configure(text="投放区 → " + (p.name or str(p)), fg=T.OK)
            else:
                shown.configure(text="（拖文件到左上投放区）", fg=T.MUTED)

    def _pick_path(self, var: tk.StringVar, kind: str) -> None:
        """保留兼容旧调用；界面已不再给用户单独填路径的入口。"""
        self._drop_sync()

    def _collect_params(self) -> dict:
        out: dict = {}
        for name, (kind, var) in self.param_vars.items():
            if kind.startswith("drop:"):
                # 不管参数原来叫 apk / target / path / src，值都来自投放区
                out[name] = self._drop_target(kind.split(":", 1)[1])
                continue
            try:
                v = var.get()
            except Exception:
                v = ""
            if kind == "int":
                try:
                    v = int(str(v).strip() or 0)
                except ValueError:
                    v = 0
            elif kind == "bool":
                v = bool(v)
            out[name] = v
        # 顺手把所有投放文件给脚本，脚本可用 args.get("files") 拿全量
        if getattr(self, "drop", None) and self.drop.files:
            out["files"] = [str(f.path) for f in self.drop.files]
        return out

    # ==================================================================
    # 运行
    # ==================================================================
    def _run(self) -> None:
        if self.run and self.run.alive:
            return
        # 两个入口互斥：左侧「开始」和全自动页会抢同一个临时目录、同一个桌面文件名
        auto = getattr(self, "_auto_run", None)
        if auto and auto.alive:
            messagebox.showinfo("正在运行", "全自动化页还有任务在跑，等它结束再开始。")
            return
        if not self.current:
            messagebox.showinfo("提示", "先在左侧选一个脚本。")
            return

        meta = self.current
        # 重新读一次元信息，确保脚本改动后参数是最新的
        try:
            fresh = parse_meta(meta.file)
            if fresh.params:
                # 参数集合变了（新增/改名）→ 旧控件收集不到新参数，
                # 必须先重建表单，否则新参数静默取默认值、file 参数还会报"没放文件"
                if set(p.name for p in fresh.params) != set(self.param_vars):
                    self.current = fresh
                    self._render_params(fresh)
                meta = fresh
        except Exception:
            pass

        params = self._collect_params()

        # 校验 file/dir 参数 —— 值只能来自投放区
        self._drop_sync()
        for p in meta.params:
            if p.ptype in ("file", "dir"):
                v = str(params.get(p.name, "")).strip()
                if not v:
                    messagebox.showwarning(
                        "还没放文件",
                        "先把文件或文件夹拖到左上角的「投放文件」区。\n"
                        "所有路径参数都从那里取，不用单独填了。")
                    return
                if not Path(v).exists():
                    messagebox.showwarning("路径不存在", f"投放区里的路径失效了：\n{v}")
                    return

        # 工作目录
        safe = "".join(c for c in (meta.name or "task") if c.isalnum() or c in "-_")[:20]
        workdir = config.WORKSPACE_ROOT / f"{time.strftime('%m%d_%H%M%S')}_{safe}"
        self._last_dir = workdir

        self._clear_term()
        self._set_pct(0)
        self._term("═" * 62, "head")
        self._term(f"  {meta.name}", "head")
        self._term(f"  参数：{params}", "muted")
        self._term(f"  产物：{workdir}", "muted")
        self._term("═" * 62, "head")

        self.run = ScriptRun(meta.file, params, workdir)
        self.run.start()

        self.btn_run.configure(state="disabled", text="运行中…")
        self.btn_stop.configure(state="normal")
        self.lbl_status.configure(text=f"正在运行：{meta.name}")
        self.nb.select(0)

    def _post(self, fn, *a, **kw) -> None:
        """
        后台线程 → 主线程的 UI 投递。

        tkinter 不是线程安全的：工作线程直接 after()/configure()，在
        主线程忙或窗口已销毁时会抛 "main thread is not in main loop"
        甚至崩进程。统一进队列，由常驻的 _pump 在主线程执行。
        """
        try:
            self._ui_q.put((fn, a, kw))
        except Exception:                            # noqa: BLE001
            pass

    def _pump(self) -> None:
        """每 60ms 收一次事件 —— GUI 唯一的输入源，绝不阻塞。"""
        try:
            while True:
                fn, a, kw = self._ui_q.get_nowait()
                try:
                    fn(*a, **kw)
                except Exception:                    # noqa: BLE001
                    pass
        except queue.Empty:
            pass
        try:
            if self.run:
                done_seen = False
                for ev in self.run.poll():
                    if ev.kind == "log":
                        self._term(ev.text, self._classify(ev.text))
                    elif ev.kind == "step":
                        self._set_pct(ev.pct)
                    elif ev.kind == "error":
                        self._term("✗ " + ev.text.splitlines()[0], "err")
                        tb = ev.text if len(ev.text) < 4000 else ev.text[:4000] + "…"
                        for line in tb.splitlines()[1:]:
                            self._term("   " + line, "muted")
                    elif ev.kind == "done":
                        done_seen = True
                        self._finish(ev.ok, ev.dur)
                # 兜底：线程已经结束却没送来 done（进程被强杀、线程里抛
                # SystemExit/BaseException、回调吞异常）→ 必须在这里收尾，
                # 否则界面永久停在"运行中"，按钮再也点不了。
                if not done_seen and self.run is not None and not self.run.alive:
                    self._finish(False, 0.0)
        except Exception:
            pass
        if self._closing:
            return
        self.after(60, self._pump)

    def _finish(self, ok: bool, dur: float) -> None:
        self.btn_run.configure(state="normal", text="开 始")
        self.btn_stop.configure(state="disabled")
        if ok:
            self._set_pct(100)
            self.lbl_status.configure(text=f"完成 · {dur:.1f}s")
            self._term(f"✓ 完成，用时 {dur:.1f}s", "ok")
        else:
            self.lbl_status.configure(text=f"失败 · {dur:.1f}s")
            self._term("✗ 本轮没有正常收尾（失败/被终止），产物以磁盘为准", "err")
        # 成功失败都刷新：失败时也要清掉上一轮的树和报告，
        # 否则界面显示的是上一个任务的产物，看着像这次跑出来了。
        self._refresh_artifacts()
        self._load_report()
        self.run = None

    def _set_pct(self, pct: int) -> None:
        self._pct = max(0, min(100, int(pct)))
        try:
            self.bar.configure(value=self._pct)
            self.lbl_pct.configure(text=f"{self._pct}%")
        except Exception:
            pass

    def _stop(self) -> None:
        n = runner.kill_all()
        if n:
            self._term(f"⏹ 已终止 {n} 个正在执行的工具进程（含子进程树）", "warn")
        else:
            self._term("⏹ 当前没有可终止的子进程（脚本可能在纯 Python 步骤里）", "warn")
        # 子进程杀掉了，但脚本线程本身杀不掉（纯 Python 循环）。
        # 界面必须立刻恢复可用，否则"运行中"永远挂着；脚本的后续输出
        # 会进队列但没人再读，无害。
        if self.run is not None:
            self._term("⏹ 本轮按终止处理，界面已恢复（线程可能在后台跑完）", "warn")
            self._finish(False, 0.0)

    # ==================================================================
    # 产物 / 报告
    # ==================================================================
    def _out_dir(self) -> Path | None:
        if self._last_dir and Path(self._last_dir).exists():
            return Path(self._last_dir)
        return None

    def _open_out(self) -> None:
        d = self._out_dir()
        if d:
            open_path(d)
        else:
            messagebox.showinfo("提示", "还没有产物目录，先跑一个脚本。")

    def _refresh_artifacts(self) -> None:
        d = self._out_dir()
        for i in self.tree.get_children():
            self.tree.delete(i)
        if not d:
            self.lbl_out.configure(text="（尚未产生产物）")
            return
        self.lbl_out.configure(text=str(d))
        # 全局节点预算：只限深度是不够的（3 层 × 400 可以到 16 万节点，
        # 建树在主线程，会把窗口冻住几十秒）。
        self._tree_budget = 1200
        self._fill_tree("", d, depth=0)
        if getattr(self, "_tree_budget", 1) <= 0:
            try:
                self.tree.insert("", "end", text="   … 产物太多，其余未显示（用「打开目录」看全）",
                                 values=("", ""))
            except Exception:
                pass

    def _fill_tree(self, parent: str, path: Path, depth: int) -> None:
        """只展开两层 + 全局节点上限，避免产物里有几万个文件时把界面卡死。"""
        if depth > 2 or getattr(self, "_tree_budget", 0) <= 0:
            return
        try:
            items = sorted(path.iterdir(), key=lambda p: (p.is_file(), p.name.lower()))
        except OSError:
            return
        for it in items[:400]:
            try:
                size = f"{it.stat().st_size / 1024:.0f} KB" if it.is_file() else ""
            except OSError:
                size = ""
            icon = "📁 " if it.is_dir() else "   "
            try:
                # 绝对路径存进 values：显示文本被 strip / 带图标，反推路径会错
                node = self.tree.insert(parent, "end", text=icon + it.name,
                                        values=(size, str(it)), open=(depth < 1))
            except Exception:
                continue
            self._tree_budget = getattr(self, "_tree_budget", 1) - 1
            if it.is_dir():
                self._fill_tree(node, it, depth + 1)
        if len(items) > 400:
            try:
                self.tree.insert(parent, "end",
                                 text=f"   … 另有 {len(items) - 400} 项未显示",
                                 values=("", ""))
            except Exception:
                pass

    def _open_tree_item(self, _evt=None) -> None:
        sel = self.tree.selection()
        if not sel or not self._last_dir:
            return
        # 优先用建树时存下的绝对路径（文件名首尾空格 + 图标前缀会让文本反推失效）
        vals = self.tree.item(sel[0], "values")
        if len(vals) >= 2 and str(vals[1]).strip():
            target = Path(str(vals[1]))
            if target.exists():
                open_path(target)
            return
        # 旧节点兜底：由节点文本逐级拼路径
        parts = []
        cur = sel[0]
        while cur:
            txt = self.tree.item(cur, "text").strip()
            txt = txt.replace("📁", "").strip()
            parts.append(txt)
            cur = self.tree.parent(cur)
        target = Path(self._last_dir).joinpath(*reversed(parts))
        if target.exists():
            open_path(target)

    def _load_report(self) -> None:
        d = self._out_dir()
        self.report.configure(state="normal")
        self.report.delete("1.0", "end")
        if not d:
            self.report.configure(state="disabled")
            self.lbl_rep.configure(text="（尚未生成报告）")
            return
        # 16 号脚本的正式报告固定叫「全自动化报告.md」；其次 report.md；
        # 再退到顶层任意 .md。不能直接 rglob("*.md") —— 解包目录里
        # 常有 APK 自带的 README/CHANGELOG，取第一个就是错的。
        f: Path | None = None
        for rel in ("全自动化报告.md", "report.md"):
            cand = d / rel
            if cand.is_file():
                f = cand
                break
        if f is None:
            top = sorted((p for p in d.glob("*.md") if p.is_file()),
                         key=lambda p: p.name)
            if top:
                f = top[0]
        if f is None:
            deep = sorted(p for p in d.rglob("*报告*.md") if p.is_file())
            if deep:
                f = deep[0]
        if f is None:
            self.report.configure(state="disabled")
            self.lbl_rep.configure(text="（未找到 .md 报告）")
            return
        self.lbl_rep.configure(text=str(f))
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            text = f"读取失败：{e}"
        for line in text.splitlines():
            if line.startswith("# "):
                self.report.insert("end", line[2:] + "\n", "h1")
            elif line.startswith("## "):
                self.report.insert("end", line[3:] + "\n", "h2")
            elif line.startswith(("```", "|")):
                self.report.insert("end", line + "\n", "code")
            else:
                self.report.insert("end", line + "\n")
        self.report.configure(state="disabled")

    # ==================================================================
    # 工具链
    # ==================================================================
    def _load_tools_async(self, force: bool = False) -> None:
        self.lbl_tools.configure(text="工具 探测中…", fg=T.MUTED)
        self.lbl_status.configure(text="正在探测本机工具链…")

        def work() -> None:
            try:
                reg = registry()
                reg.build(force=force)
                data = reg.status()
                self._post(lambda: self._tools_done(data, force))
            except Exception as e:
                # 必须把 e 绑成默认参数：except 块一结束 Python 就删掉这个名字，
                # lambda 延后执行时 str(e) 会 NameError，工具探测失败反而静默。
                self._post(lambda msg=str(e): self._tools_fail(msg))

        import threading
        threading.Thread(target=work, daemon=True).start()

    def _tools_done(self, data: list[dict], force: bool) -> None:
        ok = sum(1 for d in data if d["available"])
        total = len(data)
        color = T.OK if ok == total else (T.WARN if ok else T.ERR)
        self.lbl_tools.configure(text=f"工具 {ok}/{total}", fg=color)
        self._tools_ready = True
        miss = [d for d in data if not d["available"]]
        if miss:
            self._term(f"⚠ {len(miss)} 个工具不可用：" +
                       "、".join(d["name"] for d in miss), "warn")
        else:
            self._term(f"✓ 工具链就绪：{ok}/{total} 全部可用", "ok")
        self.lbl_status.configure(text=f"工具链 {ok}/{total} 可用")

    def _tools_fail(self, err: str) -> None:
        self.lbl_tools.configure(text="工具 探测失败", fg=T.ERR)
        self._term(f"✗ 工具探测失败：{err}", "err")

    def _show_tools(self) -> None:
        win = tk.Toplevel(self)
        win.title("工具链")
        win.geometry("980x560")
        win.configure(bg=T.BG)
        win.transient(self)

        head = tk.Frame(win, bg=T.BG)
        head.pack(fill="x", padx=14, pady=(14, 8))
        tk.Label(head, text="工具链状态", bg=T.BG, fg=T.TEXT,
                 font=T.UI_FONT_B).pack(side="left")
        tk.Label(head, text="双击某行可手动指定可执行文件路径", bg=T.BG,
                 fg=T.MUTED, font=T.UI_FONT_S).pack(side="left", padx=12)

        wrap = tk.Frame(win, bg=T.BG)
        wrap.pack(fill="both", expand=True, padx=14, pady=(0, 8))

        cols = ("state", "id", "cat", "ver", "path")
        tv = ttk.Treeview(wrap, columns=cols, show="headings")
        for c, txt, w in (("state", "状态", 60), ("id", "ID", 90),
                          ("cat", "分类", 80), ("ver", "版本", 260),
                          ("path", "路径", 460)):
            tv.heading(c, text=txt)
            tv.column(c, width=w, anchor="w" if c != "state" else "center")
        tv.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(wrap, orient="vertical", command=tv.yview)
        sb.pack(side="right", fill="y")
        tv.configure(yscrollcommand=sb.set)

        tv.tag_configure("ok", foreground=T.OK)
        tv.tag_configure("miss", foreground=T.ERR)
        tv.tag_configure("warn", foreground=T.WARN)

        for d in registry().status():
            state = "可用" if d["available"] else "缺失"
            tag = "ok" if d["available"] else "miss"
            if d["available"] and ("未" in d["version"] or "缺" in d["version"]):
                state, tag = "警告", "warn"
            tv.insert("", "end", values=(state, d["id"], d["category"],
                                         d["version"], d["path"]), tags=(tag,))

        def on_double(_e=None):
            sel = tv.selection()
            if not sel:
                return
            vals = tv.item(sel[0], "values")
            tid = vals[1]
            p = filedialog.askopenfilename(
                title=f"为 {tid} 指定可执行文件",
                filetypes=[("可执行", "*.exe *.bat *.jar"), ("全部", "*.*")])
            if not p:
                return
            s = config.load_settings()
            s.set("tool_overrides." + tid, p)
            s.save()
            registry().build(force=True)
            win.destroy()
            self._load_tools_async(force=True)

        tv.bind("<Double-1>", on_double)

        btns = tk.Frame(win, bg=T.BG)
        btns.pack(fill="x", padx=14, pady=(0, 14))
        ttk.Button(btns, text="刷新缓存并重新探测", style="Accent.TButton",
                   command=lambda: (win.destroy(), self._load_tools_async(force=True))
                   ).pack(side="left")
        ttk.Button(btns, text="关闭", style="TButton",
                   command=win.destroy).pack(side="right")

    # ==================================================================
    # 积木库
    # ==================================================================
    def _build_snippets_tab(self, nb) -> None:
        f = tk.Frame(nb, bg=T.PANEL)
        nb.add(f, text="  积木  ")

        top = tk.Frame(f, bg=T.PANEL)
        top.pack(fill="x", padx=12, pady=(10, 6))
        tk.Label(top, text="代码积木", bg=T.PANEL, fg=T.TEXT,
                 font=T.UI_FONT_B).pack(side="left")
        tk.Label(top, text="每块都可单独运行；选中多块可拼装", bg=T.PANEL,
                 fg=T.MUTED, font=T.UI_FONT_S).pack(side="left", padx=10)

        self.snip_kw = tk.StringVar()
        ent = ttk.Entry(top, textvariable=self.snip_kw, width=24)
        ent.pack(side="right", padx=(6, 0))
        ent.bind("<Return>", lambda e: self._snip_fill(self.snip_kw.get()))
        ttk.Button(top, text="搜索", style="Ghost.TButton",
                   command=lambda: self._snip_fill(self.snip_kw.get())
                   ).pack(side="right", padx=4)
        ttk.Button(top, text="重置", style="Ghost.TButton",
                   command=self._snip_reset).pack(side="right")

        self.lbl_snip_stat = tk.Label(f, text="", bg=T.PANEL, fg=T.MUTED,
                                      font=T.UI_FONT_S, anchor="w")
        self.lbl_snip_stat.pack(fill="x", padx=14, pady=(0, 4))

        pw = tk.PanedWindow(f, orient="horizontal", bg=T.PANEL, sashwidth=5,
                            sashrelief="flat", bd=0, showhandle=False)
        pw.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        left = tk.Frame(pw, bg=T.PANEL2)
        right = tk.Frame(pw, bg=T.PANEL)
        pw.add(left, minsize=250, width=300)
        pw.add(right, minsize=420)

        self.snip_tree = ttk.Treeview(left, show="tree", selectmode="extended")
        self.snip_tree.pack(side="left", fill="both", expand=True)
        ssb = ttk.Scrollbar(left, orient="vertical", command=self.snip_tree.yview)
        ssb.pack(side="right", fill="y")
        self.snip_tree.configure(yscrollcommand=ssb.set)
        self.snip_tree.bind("<<TreeviewSelect>>", self._snip_on_select)

        # --- 右侧详情 ---
        self.lbl_snip_title = tk.Label(right, text="选一块积木", bg=T.PANEL,
                                       fg=T.TEXT, font=(T.UI_FONT[0], 12, "bold"),
                                       anchor="w")
        self.lbl_snip_title.pack(fill="x", padx=14, pady=(12, 2))

        self.lbl_snip_meta = tk.Label(right, text="", bg=T.PANEL, fg=T.MUTED,
                                      font=T.UI_FONT_S, anchor="w",
                                      justify="left", wraplength=620)
        self.lbl_snip_meta.pack(fill="x", padx=14, pady=(0, 6))

        self.lbl_snip_purpose = tk.Label(right, text="", bg=T.PANEL, fg=T.TEXT,
                                         font=T.UI_FONT_S, anchor="w",
                                         justify="left", wraplength=620)
        self.lbl_snip_purpose.pack(fill="x", padx=14, pady=(0, 6))

        code_wrap = tk.Frame(right, bg=T.PANEL)
        code_wrap.pack(fill="both", expand=True, padx=12, pady=(0, 6))
        self.snip_code = T.make_text(code_wrap, mono=True, undo=True)
        self.snip_code.pack(side="left", fill="both", expand=True)
        csb = ttk.Scrollbar(code_wrap, orient="vertical", command=self.snip_code.yview)
        csb.pack(side="right", fill="y")
        self.snip_code.configure(yscrollcommand=csb.set, wrap="none")
        self.snip_code.tag_configure("ok", foreground=T.TERM_OK)
        self.snip_code.tag_configure("err", foreground=T.TERM_ERR)

        bar = tk.Frame(right, bg=T.PANEL)
        bar.pack(fill="x", padx=12, pady=(0, 10))
        ttk.Button(bar, text="校验语法", style="Accent.TButton",
                   command=self._snip_validate).pack(side="left")
        ttk.Button(bar, text="＋新代码块", style="TButton",
                   command=lambda: self._snip_editor()).pack(side="left", padx=6)
        ttk.Button(bar, text="编辑", style="Ghost.TButton",
                   command=self._snip_edit).pack(side="left")
        ttk.Button(bar, text="复制", style="TButton",
                   command=self._snip_copy).pack(side="left", padx=6)
        ttk.Button(bar, text="送终端", style="TButton",
                   command=self._snip_to_repl).pack(side="left")
        ttk.Button(bar, text="保存为脚本", style="TButton",
                   command=self._snip_save).pack(side="left", padx=6)
        ttk.Button(bar, text="拼装选中", style="TButton",
                   command=self._snip_compose).pack(side="left", padx=6)
        ttk.Button(bar, text="目录总览", style="TButton",
                   command=self._snip_catalog_window).pack(side="left")
        ttk.Button(bar, text="导出目录", style="Ghost.TButton",
                   command=self._snip_catalog).pack(side="right")

        self.lbl_snip_msg = tk.Label(right, text="", bg=T.PANEL, fg=T.OK,
                                     font=T.UI_FONT_S, anchor="w")
        self.lbl_snip_msg.pack(fill="x", padx=14, pady=(0, 10))

        self._snip_map: dict[str, str] = {}
        self._snip_current: str = ""
        self.after(180, self._snip_reload)

    def _snip_reload(self, filter_kw: str = "") -> None:
        from ..snippets import get_library
        try:
            self._snip_lib = get_library()
        except Exception as e:
            self.lbl_snip_msg.configure(text=f"积木库加载失败：{e}", fg=T.ERR)
            return
        self._snip_fill(filter_kw)
        st = self._snip_lib.stats()
        self.lbl_snip_stat.configure(
            text=f"{st['total']} 块 · 入门 {st['by_level'].get('入门', 0)} / "
                 f"进阶 {st['by_level'].get('进阶', 0)} / "
                 f"高阶 {st['by_level'].get('高阶', 0)} · 语法异常 {st['invalid']}")

    def _snip_fill(self, kw: str = "") -> None:
        lib = getattr(self, "_snip_lib", None)
        if lib is None:
            return
        self.snip_tree.delete(*self.snip_tree.get_children())
        self._snip_map = {}
        kw = (kw or "").strip()
        total = 0
        for c in lib.categories():
            items = [s for s in lib.all(c["name"])
                     if not kw or kw.lower() in
                     (s.sid + s.title + s.purpose + " ".join(s.tags)).lower()]
            if not items:
                continue
            node = self.snip_tree.insert("", "end", text=f"{c['name']}（{len(items)}）",
                                        open=True)
            for s in items:
                iid = self.snip_tree.insert(
                    node, "end",
                    text=f"{s.title}  ·  {s.level_name}")
                self._snip_map[iid] = s.sid
                total += 1
        self.lbl_snip_stat.configure(
            text=f"当前 {total} 块" + (f"（筛选：{kw}）" if kw else ""))
        # 顶栏常驻一份"全库概览"，别让人猜有多少块、分几类
        try:
            st = lib.stats()
            cats = "、".join(f"{k} {v}" for k, v in
                            sorted(st["by_category"].items(), key=lambda kv: -kv[1]))
            self.lbl_snip_stat.configure(
                text=(f"{len(st['by_category'])} 类 · {st['total']} 块"
                      f"　入门 {st['by_level'].get('入门', 0)} / "
                      f"进阶 {st['by_level'].get('进阶', 0)} / "
                      f"高阶 {st['by_level'].get('高阶', 0)}"
                      f"　｜ {cats}"
                      + (f"　（筛选：{kw}）" if kw else "")))
        except Exception:                            # noqa: BLE001
            pass
        # 默认选中第一块，右侧立刻有内容 —— 小白不用先猜"点哪里"
        tops = self.snip_tree.get_children()
        if tops:
            kids = self.snip_tree.get_children(tops[0])
            if kids:
                self.snip_tree.selection_set(kids[0])
                self.snip_tree.focus(kids[0])
                self._snip_on_select()

    def _snip_reset(self) -> None:
        self.snip_kw.set("")
        self._snip_fill("")

    def _snip_on_select(self, _e=None) -> None:
        sel = self.snip_tree.selection()
        sid = ""
        for iid in sel:
            if iid in self._snip_map:
                sid = self._snip_map[iid]
                break
        if not sid:
            return
        self._snip_current = sid
        try:
            sn = self._snip_lib.get(sid)
        except KeyError as e:
            self.lbl_snip_msg.configure(text=str(e), fg=T.ERR)
            return
        self.lbl_snip_title.configure(text=f"{sn.title}   [{sn.sid}]")
        meta = [f"{sn.category} · {sn.level_name} · 风险：{sn.risk}",
                f"需要：{'、'.join(sn.needs) or '无'}    "
                f"产出：{'、'.join(sn.gives) or '无'}"]
        if sn.depends:
            meta.append("依赖：" + "、".join(sn.depends))
        if sn.when:
            meta.append("适用：" + sn.when)
        self.lbl_snip_meta.configure(text="\n".join(meta))
        self.lbl_snip_purpose.configure(text=sn.purpose)
        self.snip_code.configure(state="normal")
        self.snip_code.delete("1.0", "end")
        self.snip_code.insert("1.0", sn.code)
        self.lbl_snip_msg.configure(
            text="（语法已在加载时校验通过）" if sn.valid else
            "⚠ " + "；".join(sn.errors), fg=T.OK if sn.valid else T.ERR)

    def _snip_validate(self) -> None:
        from ..analysis import validator
        code = self.snip_code.get("1.0", "end")
        r = validator.validate(code, "python", self._snip_current or "<积木>")
        if r.ok:
            self.lbl_snip_msg.configure(
                text=f"✓ 语法通过（{r.stats.get('lines', 0)} 行）", fg=T.OK)
        else:
            self.lbl_snip_msg.configure(
                text="✗ " + r.errors[0].text(), fg=T.ERR)
            ln = r.errors[0].line
            if ln:
                self.snip_code.tag_add("err", f"{ln}.0", f"{ln}.end")

    def _snip_copy(self) -> None:
        code = self.snip_code.get("1.0", "end").rstrip()
        try:
            self.clipboard_clear()
            self.clipboard_append(code)
            self.lbl_snip_msg.configure(text="✓ 已复制到剪贴板", fg=T.OK)
        except Exception as e:
            self.lbl_snip_msg.configure(text=f"复制失败：{e}", fg=T.ERR)

    def _snip_save(self) -> None:
        sid = self._snip_current
        if not sid:
            return
        sn = self._snip_lib.get(sid)
        name = sid.replace(".", "_") + ".py"
        path = config.SCRIPT_ROOT / name
        body = (f"# @name {sn.title}\n"
                f"# @desc {sn.purpose}\n"
                f"# 来源：积木 {sid}（{sn.category}/{sn.level_name}）\n\n"
                + self.snip_code.get("1.0", "end").rstrip() + "\n")
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body, encoding="utf-8")
            self._load_scripts()
            self.lbl_snip_msg.configure(text=f"✓ 已保存到脚本库：{name}", fg=T.OK)
        except OSError as e:
            self.lbl_snip_msg.configure(text=f"保存失败：{e}", fg=T.ERR)

    # ---------------- 自定义代码块：新建 / 编辑 ----------------
    def _snip_editor(self, sid: str = "") -> None:
        """新建或编辑一块**真正的代码积木**（内容完全由你写，不限于内置模板）。"""
        from ..analysis import validator

        lib = getattr(self, "_snip_lib", None)
        if lib is None:
            return
        old = lib.get(sid) if sid else None
        if old and old.source != "用户":
            if not messagebox.askokcancel(
                    "内置积木只读",
                    f"「{old.title}」是内置积木，不能直接改。\n"
                    "要基于它改一块自己的吗？会以新 ID 保存一份副本。"):
                return

        win = tk.Toplevel(self)
        win.title("新代码块" if not old else "编辑代码块")
        win.geometry("820x660")
        win.configure(bg=T.BG)
        win.transient(self)

        tk.Label(win, text=("新代码块 —— 粘贴任意 Python 代码，存进去就是一块积木"
                            if not old else f"编辑：{old.sid}"),
                 bg=T.BG, fg=T.TEXT, font=T.UI_FONT_B).pack(fill="x", padx=14, pady=10)

        form = tk.Frame(win, bg=T.BG)
        form.pack(fill="x", padx=14, pady=(0, 8))
        fields: dict[str, tk.StringVar] = {}
        defaults = {
            "id": (old.sid if old else f"user.block_{time.strftime('%H%M%S')}"),
            "title": (old.title if old else "我的代码块"),
            "category": (old.category if old else "工程"),
            "level": (str(old.level) if old else "2"),
            "purpose": (old.purpose if old else "这段代码的用途"),
        }
        for col, (key, label, width) in enumerate((
                ("id", "编号", 20), ("title", "名称", 18),
                ("category", "分类", 10), ("level", "难度 1-3", 10),
                ("purpose", "作用", 34))):
            tk.Label(form, text=label, bg=T.BG, fg=T.MUTED,
                     font=T.UI_FONT_S).grid(row=0, column=col * 2, sticky="w")
            v = tk.StringVar(value=defaults[key])
            tk.Entry(form, textvariable=v, width=width).grid(
                row=0, column=col * 2 + 1, sticky="w", padx=(2, 10))
            fields[key] = v

        tk.Label(win, text="代码（原样保存；拼装时会按你排的顺序拼成一整段）",
                 bg=T.BG, fg=T.MUTED, font=T.UI_FONT_S).pack(fill="x", padx=14)
        cw = tk.Frame(win, bg=T.BG)
        cw.pack(fill="both", expand=True, padx=14, pady=(4, 8))
        code_t = T.make_text(cw, mono=True, undo=True)
        code_t.configure(state="normal")
        code_t.pack(side="left", fill="both", expand=True)
        csb = ttk.Scrollbar(cw, orient="vertical", command=code_t.yview)
        csb.pack(side="right", fill="y")
        code_t.configure(yscrollcommand=csb.set)
        if old:
            code_t.insert("1.0", old.code)
        else:
            code_t.insert("1.0", "# 写你的代码\nrf.log(\"hello from my block\")\n")

        msg = tk.Label(win, text="", bg=T.BG, fg=T.MUTED,
                       font=T.UI_FONT_S, anchor="w")
        msg.pack(fill="x", padx=14)

        bar = tk.Frame(win, bg=T.BG)
        bar.pack(fill="x", padx=14, pady=(0, 12))
        side = tk.StringVar(value="我自己的积木")

        def save() -> None:
            from ..analysis import validator
            src = code_t.get("1.0", "end").strip()
            if not src:
                msg.configure(text="代码是空的", fg=T.ERR)
                return
            vr = validator.validate(src, "python", "<block>")
            if not vr.ok:
                msg.configure(text="语法不通过：" + vr.errors[0].text(), fg=T.ERR)
                return
            sid = fields["id"].get().strip() or f"user.block_{time.strftime('%H%M%S')}"
            try:
                p = lib.save_user(
                    sid, fields["title"].get().strip() or sid, src,
                    category=fields["category"].get().strip() or "工程",
                    level=int(fields["level"].get() or 2),
                    purpose=fields["purpose"].get().strip() or "自定义代码块",
                    tags=["自定义"], risk="无")
            except Exception as e:                   # noqa: BLE001
                msg.configure(text=f"保存失败：{e}", fg=T.ERR)
                return
            self._snip_reload()
            msg.configure(text=f"✓ 已保存 → {p.name}", fg=T.OK)
            win.after(700, win.destroy)

        ttk.Button(bar, text="校验语法", style="Ghost.TButton",
                   command=lambda: msg.configure(
                       text=("语法 OK" if validator.validate(
                           code_t.get("1.0", "end"), "python", "<b>").ok
                             else "语法有问题"),
                       fg=T.OK if validator.validate(
                           code_t.get("1.0", "end"), "python", "<b>").ok else T.ERR)
                   ).pack(side="left")
        ttk.Button(bar, text="保存到积木库", style="Accent.TButton",
                   command=save).pack(side="left", padx=8)
        ttk.Button(bar, text="取消", style="Ghost.TButton",
                   command=win.destroy).pack(side="right")

    def _snip_edit(self) -> None:
        sid = getattr(self, "_snip_current", "")
        if not sid:
            messagebox.showinfo("提示", "先选中一块积木。")
            return
        self._snip_editor(sid)

    # ---------------- 拼装工作台 ----------------
    @staticmethod
    def _parse_args(text: str) -> dict:
        """`key=value, key2=123` → dict；值会先试字面量再退回字符串。"""
        import ast
        out: dict = {}
        for part in (text or "").split(","):
            if "=" not in part:
                continue
            k, v = part.split("=", 1)
            k, v = k.strip(), v.strip()
            if not k:
                continue
            try:
                out[k] = ast.literal_eval(v)
            except (ValueError, SyntaxError):
                out[k] = v
        return out

    def _snip_compose(self) -> None:
        """拼装工作台：任意代码块 → 手动排序 → 一串真代码 → 直接运行。"""
        lib = getattr(self, "_snip_lib", None)
        if lib is None:
            return
        ids = [self._snip_map[i] for i in self.snip_tree.selection()
               if i in self._snip_map]
        if not ids and getattr(self, "_snip_current", ""):
            ids = [self._snip_current]
        if not ids:
            messagebox.showinfo("提示", "先在左边选一块或多块积木，"
                                        "或者点「新代码块」自己写一块。")
            return

        win = tk.Toplevel(self)
        win.title("拼装工作台")
        win.geometry("1080x720")
        win.configure(bg=T.BG)
        win.transient(self)

        head = tk.Label(win, text="拼装工作台　选中的块按下面顺序拼成一整段代码，"
                                  "可以用 ↑↓ 调整，拼完直接送终端运行",
                        bg=T.BG, fg=T.TEXT, font=T.UI_FONT_B, anchor="w")
        head.pack(fill="x", padx=14, pady=(10, 6))

        pw = tk.PanedWindow(win, orient="horizontal", bg=T.BG,
                            sashwidth=5, sashrelief="flat")
        pw.pack(fill="both", expand=True, padx=14, pady=(0, 6))

        # 左：已选块 + 顺序
        left = tk.Frame(pw, bg=T.PANEL)
        pw.add(left, minsize=300, width=340)
        tk.Label(left, text="拼装顺序", bg=T.PANEL, fg=T.TEXT,
                 font=T.UI_FONT_S).pack(fill="x", padx=10, pady=(8, 4))
        lwrap = tk.Frame(left, bg=T.PANEL)
        lwrap.pack(fill="both", expand=True, padx=10)
        order_tv = ttk.Treeview(lwrap, columns=("id", "title"),
                                show="headings", selectmode="extended")
        order_tv.heading("id", text="编号")
        order_tv.heading("title", text="名称")
        order_tv.column("id", width=160)
        order_tv.column("title", width=180)
        order_tv.pack(side="left", fill="both", expand=True)
        lsb = ttk.Scrollbar(lwrap, orient="vertical", command=order_tv.yview)
        lsb.pack(side="right", fill="y")
        order_tv.configure(yscrollcommand=lsb.set)
        for sid in ids:
            sn = lib.get(sid)
            order_tv.insert("", "end", values=(sid, sn.title if sn else sid))

        obar = tk.Frame(left, bg=T.PANEL)
        obar.pack(fill="x", padx=10, pady=6)

        def cur_ids() -> list[str]:
            return [order_tv.item(i, "values")[0]
                    for i in order_tv.get_children()]

        def move(delta: int) -> None:
            sel = order_tv.selection()
            if not sel:
                return
            items = list(order_tv.get_children())
            i = items.index(sel[0])
            j = i + delta
            if 0 <= j < len(items):
                order_tv.move(sel[0], "", j)
                preview()

        ttk.Button(obar, text="↑ 上移", style="Ghost.TButton",
                   command=lambda: move(-1)).pack(side="left")
        ttk.Button(obar, text="↓ 下移", style="Ghost.TButton",
                   command=lambda: move(1)).pack(side="left", padx=4)
        ttk.Button(obar, text="移除", style="Ghost.TButton",
                   command=lambda: (order_tv.delete(*order_tv.selection()),
                                    preview())).pack(side="left")

        tk.Label(left, text="加入其它块", bg=T.PANEL, fg=T.MUTED,
                 font=T.UI_FONT_S).pack(fill="x", padx=10, pady=(8, 2))
        allv = tk.StringVar()
        choices = [f"{s.sid}  ·  {s.title}" for s in lib.all()]
        cbox = ttk.Combobox(left, textvariable=allv, values=choices,
                            width=38, state="readonly")
        cbox.pack(fill="x", padx=10)

        def add_block() -> None:
            v = allv.get().strip()
            if not v:
                return
            sid = v.split("  ·  ")[0]
            if sid in cur_ids():
                return
            sn = lib.get(sid)
            order_tv.insert("", "end", values=(sid, sn.title if sn else sid))
            preview()

        ttk.Button(left, text="＋ 加入", style="Ghost.TButton",
                   command=add_block).pack(fill="x", padx=10, pady=4)

        # 右：代码预览
        right = tk.Frame(pw, bg=T.PANEL)
        pw.add(right, minsize=440)
        tk.Label(right, text="拼装结果（完整可运行代码）", bg=T.PANEL,
                 fg=T.TEXT, font=T.UI_FONT_S).pack(fill="x", padx=10, pady=(8, 4))
        rwrap = tk.Frame(right, bg=T.PANEL)
        rwrap.pack(fill="both", expand=True, padx=10)
        code_t = T.make_text(rwrap, mono=True)
        code_t.configure(state="normal")
        code_t.pack(side="left", fill="both", expand=True)
        rsb = ttk.Scrollbar(rwrap, orient="vertical", command=code_t.yview)
        rsb.pack(side="right", fill="y")
        code_t.configure(yscrollcommand=rsb.set)

        argw = tk.Frame(right, bg=T.PANEL)
        argw.pack(fill="x", padx=10, pady=6)
        tk.Label(argw, text="运行参数  k=v, k2=123", bg=T.PANEL,
                 fg=T.MUTED, font=T.UI_FONT_S).pack(side="left")
        argv = tk.StringVar(value="")
        tk.Entry(argw, textvariable=argv, width=42).pack(side="left", padx=6)
        msg = tk.Label(right, text="", bg=T.PANEL, fg=T.MUTED,
                       font=T.UI_FONT_S, anchor="w")
        msg.pack(fill="x", padx=10, pady=(0, 6))

        bar = tk.Frame(win, bg=T.BG)
        bar.pack(fill="x", padx=14, pady=(0, 12))

        state: dict = {"code": ""}

        def preview() -> None:
            seq = cur_ids()
            if not seq:
                state["code"] = ""
                code_t.delete("1.0", "end")
                msg.configure(text="没有块", fg=T.WARN)
                return
            try:
                code = lib.compose(seq, order=seq,
                                   args=self._parse_args(argv.get()))
            except Exception as e:                   # noqa: BLE001
                msg.configure(text=f"拼装失败：{e}", fg=T.ERR)
                return
            state["code"] = code
            code_t.delete("1.0", "end")
            code_t.insert("1.0", code)
            msg.configure(text=f"✓ {len(seq)} 块 → {len(code.splitlines())} 行，"
                               "语法校验通过，可直接运行", fg=T.OK)

        def save_script() -> None:
            if not state["code"]:
                preview()
            if not state["code"]:
                return
            p = filedialog.asksaveasfilename(
                title="拼装脚本保存到", initialdir=str(config.SCRIPT_ROOT),
                defaultextension=".py", initialfile="composed.py",
                filetypes=[("Python", "*.py")])
            if p:
                Path(p).write_text(state["code"], encoding="utf-8")
                self._load_scripts()
                msg.configure(text=f"✓ 已保存 {Path(p).name}", fg=T.OK)

        def run_it() -> None:
            if not state["code"]:
                preview()
            if not state["code"]:
                return
            code = state["code"]
            win.destroy()
            self.repl_send(code, "拼装脚本")
            self._repl_run()

        ttk.Button(bar, text="刷新预览", style="TButton",
                   command=preview).pack(side="left")
        ttk.Button(bar, text="保存为脚本", style="TButton",
                   command=save_script).pack(side="left", padx=6)
        ttk.Button(bar, text="复制到剪贴板", style="Ghost.TButton",
                   command=lambda: (self.clipboard_clear(),
                                    self.clipboard_append(state["code"]))
                   ).pack(side="left")
        ttk.Button(bar, text="送终端并运行", style="Accent.TButton",
                   command=run_it).pack(side="right")
        ttk.Button(bar, text="关闭", style="Ghost.TButton",
                   command=win.destroy).pack(side="right", padx=6)

        preview()

    def _snip_catalog(self) -> None:
        try:
            p = self._snip_lib.markdown()
            out = config.WORKSPACE_ROOT / "积木目录.md"
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(p, encoding="utf-8")
            self.lbl_snip_msg.configure(text=f"✓ 目录：{out}", fg=T.OK)
            open_path(out)
        except OSError as e:
            self.lbl_snip_msg.configure(text=f"生成失败：{e}", fg=T.ERR)

    # ==================================================================
    # 补丁
    # ==================================================================
    def _build_patch_tab(self, nb) -> None:
        f = tk.Frame(nb, bg=T.PANEL)
        nb.add(f, text="  补丁  ")

        tk.Label(f, text="① 选目录  ② 扫描  ③ 预演  ④ 应用  ⑤ 重建",
                 bg=T.PANEL, fg=T.MUTED, font=T.UI_FONT_S,
                 anchor="w").pack(fill="x", padx=12, pady=(10, 4))

        bar = tk.Frame(f, bg=T.PANEL)
        bar.pack(fill="x", padx=12, pady=(0, 6))
        tk.Label(bar, text="解包目录", bg=T.PANEL, fg=T.MUTED,
                 font=T.UI_FONT_S).pack(side="left")
        self.patch_target = tk.StringVar(value="")
        ttk.Entry(bar, textvariable=self.patch_target).pack(
            side="left", fill="x", expand=True, padx=6)
        ttk.Button(bar, text="…", width=3, style="TButton",
                   command=self._patch_pick).pack(side="left")
        self.btn_patch_scan = ttk.Button(bar, text="扫描", style="Accent.TButton",
                                         command=self._patch_scan)
        self.btn_patch_scan.pack(side="left", padx=6)

        opt = tk.Frame(f, bg=T.PANEL)
        opt.pack(fill="x", padx=12, pady=(0, 6))
        self.patch_only_pre = tk.BooleanVar(value=True)
        tk.Checkbutton(opt, text="只看启动路径", variable=self.patch_only_pre,
                       bg=T.PANEL, fg=T.TEXT, selectcolor=T.PANEL2,
                       activebackground=T.PANEL, activeforeground=T.TEXT,
                       borderwidth=0, highlightthickness=0,
                       font=T.UI_FONT_S).pack(side="left")
        tk.Label(opt, text="最低置信度", bg=T.PANEL, fg=T.MUTED,
                 font=T.UI_FONT_S).pack(side="left", padx=(14, 4))
        self.patch_min = tk.StringVar(value="25")
        ttk.Spinbox(opt, from_=10, to=95, increment=5, width=6,
                    textvariable=self.patch_min).pack(side="left", padx=(0, 8))
        self.lbl_patch_status = tk.Label(opt, text="尚未扫描", bg=T.PANEL,
                                         fg=T.MUTED, font=T.UI_FONT_S)
        self.lbl_patch_status.pack(side="right")

        cols = ("id", "pre", "conf", "cat", "method", "sug")
        wrap = tk.Frame(f, bg=T.PANEL)
        wrap.pack(fill="both", expand=True, padx=12, pady=(0, 6))
        self.patch_tv = ttk.Treeview(wrap, columns=cols, show="headings",
                                     selectmode="extended", height=8)
        for c, txt, w, anchor in (("id", "ID", 52, "center"),
                                  ("pre", "启动", 52, "center"),
                                  ("conf", "置信", 52, "center"),
                                  ("cat", "类别", 88, "w"),
                                  ("method", "类.方法", 240, "w"),
                                  ("sug", "建议", 300, "w")):
            self.patch_tv.heading(c, text=txt)
            self.patch_tv.column(c, width=w, anchor=anchor)
        self.patch_tv.pack(side="left", fill="both", expand=True)
        psb = ttk.Scrollbar(wrap, orient="vertical", command=self.patch_tv.yview)
        psb.pack(side="right", fill="y")
        self.patch_tv.configure(yscrollcommand=psb.set)
        self.patch_tv.bind("<<TreeviewSelect>>", self._patch_on_select)
        self.patch_tv.tag_configure("pre", foreground=T.ACCENT)
        self.patch_tv.tag_configure("run", foreground=T.MUTED)

        det = tk.Frame(f, bg=T.PANEL)
        det.pack(fill="both", expand=False, padx=12, pady=(0, 4))
        self.patch_detail = T.make_text(det, mono=True, height=9, wrap="word")
        self.patch_detail.pack(side="left", fill="both", expand=True)
        dsb = ttk.Scrollbar(det, orient="vertical", command=self.patch_detail.yview)
        dsb.pack(side="right", fill="y")
        self.patch_detail.configure(yscrollcommand=dsb.set)
        self.patch_detail.tag_configure("head", foreground=T.ACCENT,
                                        font=(T.MONO_FONT[0], T.MONO_FONT[1], "bold"))
        self.patch_detail.tag_configure("ok", foreground=T.TERM_OK)
        self.patch_detail.tag_configure("err", foreground=T.TERM_ERR)
        self.patch_detail.tag_configure("muted", foreground=T.MUTED)

        act = tk.Frame(f, bg=T.PANEL)
        act.pack(fill="x", padx=12, pady=(4, 10))
        ttk.Button(act, text="预演（不写盘）", style="TButton",
                   command=lambda: self._patch_run("dry")).pack(side="left")
        ttk.Button(act, text="应用补丁", style="Accent.TButton",
                   command=lambda: self._patch_run("apply")).pack(side="left", padx=6)
        ttk.Button(act, text="重建 APK", style="TButton",
                   command=lambda: self._patch_run("rebuild")).pack(side="left")
        ttk.Button(act, text="回滚", style="Ghost.TButton",
                   command=self._patch_rollback).pack(side="left", padx=6)
        ttk.Button(act, text="改法送终端", style="Ghost.TButton",
                   command=self._patch_to_repl).pack(side="left")
        ttk.Button(act, text="打开产物", style="Ghost.TButton",
                   command=self._open_out).pack(side="right")

        self._patch_root: Path | None = None
        self._patch_rep = None
        self._patch_ops: list = []
        self._patch_backup: str = ""
        self._patch_last_apk: str = ""
        self._patch_busy = False

    def _patch_pick(self) -> None:
        p = filedialog.askdirectory(title="选择 apktool 解包目录")
        if p:
            self.patch_target.set(p)

    def _bg(self, fn, done) -> None:
        """后台跑重活，结果回主线程；避免扫描/重建把界面卡死。"""
        import threading

        def work() -> None:
            try:
                r = fn()
                self._post(lambda: done(r, None))
            except Exception as e:      # noqa: BLE001
                err = e
                self._post(lambda err=err: done(None, err))

        threading.Thread(target=work, daemon=True).start()

    def _patch_scan(self) -> None:
        if self._patch_busy:
            return
        target = self.patch_target.get().strip()
        if not target:
            messagebox.showinfo("提示", "先选 apktool 解包目录；或用脚本 08 直接传 APK。")
            return
        p = Path(target)
        if not p.exists():
            messagebox.showwarning("路径不存在", target)
            return
        try:
            minc = int(self.patch_min.get())
        except ValueError:
            minc = 25

        self._patch_busy = True
        self.btn_patch_scan.configure(state="disabled")
        self.lbl_patch_status.configure(text="扫描中…")

        def work():
            from ..patch import checkpoints as cp
            root = p
            if p.is_file() and p.suffix.lower() == ".apk":
                from ..analysis import apk as apkmod
                out = p.parent / (p.stem + "_unpack")
                pipe = apkmod.ApkPipeline(p, out)
                r = pipe.run(do_apktool=True, do_jadx=False)
                if not r.apktool_dir:
                    raise RuntimeError("解包失败：" + "；".join(r.errors[:2]))
                root = Path(r.apktool_dir)
            elif p.is_file():
                root = p.parent
            rep = cp.analyze(root, min_confidence=minc)
            return root, rep

        self._bg(work, self._patch_scan_done)

    def _patch_scan_done(self, res, err) -> None:
        self._patch_busy = False
        self.btn_patch_scan.configure(state="normal")
        if err or not res:
            self.lbl_patch_status.configure(text="扫描失败")
            messagebox.showerror("扫描失败", str(err))
            return
        root, rep = res
        self._patch_root = root
        self._patch_rep = rep
        self.patch_target.set(str(root))
        self._patch_fill()
        n_pre = len(rep.pre_run)
        self.lbl_patch_status.configure(
            text=f"{rep.files} 文件 / {rep.methods} 方法 · 命中 {len(rep.points)}"
                 f"（启动 {n_pre}）· {rep.elapsed:.1f}s")
        self._detail_reset(
            f"扫描完成：{rep.summary()}\n"
            f"启动入口：{'、'.join(rep.entries[:6]) or '（未识别）'}\n"
            f"提示：双击某行看证据；选多行可只对这些点操作。")

    def _patch_fill(self) -> None:
        tv = self.patch_tv
        tv.delete(*tv.get_children())
        rep = self._patch_rep
        if not rep:
            return
        pts = rep.pre_run if self.patch_only_pre.get() else rep.points
        for p in pts:
            sug = p.best.label if p.best else "仅识别"
            tv.insert("", "end", iid=p.cid,
                      values=(p.cid, "✓" if p.pre_run else "",
                              p.confidence, p.category,
                              f"{p.cls_simple}.{p.method}", sug),
                      tags=("pre" if p.pre_run else "run",))
        first = [p.cid for p in pts if p.pre_run] or [p.cid for p in pts[:1]]
        if first:
            tv.selection_set(first[0])
            tv.focus(first[0])
            self._patch_on_select()

    def _patch_on_select(self, _e=None) -> None:
        rep = self._patch_rep
        if not rep:
            return
        sel = self.patch_tv.selection()
        if not sel:
            return
        p = rep.get(sel[0])
        if not p:
            return
        L = [f"{p.cid} · {p.cls_simple}.{p.method}{p.signature}",
             f"类别：{p.category}    置信度：{p.confidence}    "
             f"{'启动路径' if p.pre_run else '运行期触发'}",
             f"位置：{Path(p.file).name}:{p.line}"]
        if p.chain:
            L.append(f"链路：{p.chain}")
        if p.evidence:
            L += ["", "证据："] + [f"  · {e}" for e in p.evidence]
        if p.note:
            L += ["", f"注意：{p.note}"]
        if p.best:
            L += ["", f"首选建议：{p.best.label}（风险 {p.best.risk}）",
                  f"理由：{p.best.why}", "", "── 改前 ──",
                  p.best.op.original.strip()[:800], "── 改后 ──",
                  p.best.op.replacement.strip()[:800]]
        else:
            L += ["", "（没有可自动应用的改法，需要手工分析）"]
        self._detail_set("\n".join(L))

    def _detail_reset(self, text: str = "") -> None:
        self.patch_detail.configure(state="normal")
        self.patch_detail.delete("1.0", "end")
        if text:
            self.patch_detail.insert("1.0", text)
        self.patch_detail.configure(state="disabled")

    def _detail_set(self, text: str) -> None:
        self._detail_reset(text)

    def _patch_ids(self) -> list[str]:
        ids = [i for i in self.patch_tv.selection() if i.startswith("P")]
        if ids:
            return ids
        rep = self._patch_rep
        if not rep:
            return []
        rows = rep.pre_run if self.patch_only_pre.get() else rep.points
        return [p.cid for p in rows if p.best]

    def _patch_ops_for(self) -> list:
        from ..patch import checkpoints as cp
        if not self._patch_rep or not self._patch_root:
            raise RuntimeError("先扫描")
        ids = self._patch_ids()
        ops = cp.to_plan(self._patch_rep, ids=ids, only_pre=self.patch_only_pre.get())
        if not ops:
            raise RuntimeError("选中的校验点没有可自动应用的补丁建议")
        return ops

    def _patch_run(self, mode: str) -> None:
        if self._patch_busy:
            return
        if not self._patch_root:
            messagebox.showinfo("提示", "先扫描一个解包目录。")
            return
        try:
            ops = self._patch_ops_for()
        except Exception as e:      # noqa: BLE001
            messagebox.showwarning("无法生成补丁", str(e))
            return
        self._patch_ops = ops

        if mode == "rebuild":
            out = filedialog.asksaveasfilename(
                title="重建 APK 保存到", initialdir=str(config.WORKSPACE_ROOT),
                defaultextension=".apk", initialfile="patched.apk",
                filetypes=[("APK", "*.apk")])
            if not out:
                return
            self._patch_busy = True
            self.lbl_patch_status.configure(text="重建中…（apktool 编译需要时间）")
            from ..patch import engine as pe
            self._bg(lambda: pe.rebuild(self._patch_root, out, ops=ops),
                     lambda r, e: self._patch_rebuild_done(r, e))
            return

        dry = mode == "dry"
        if not dry:
            if not messagebox.askokcancel(
                    "确认应用",
                    f"将修改 {len(ops)} 处 smali（先自动备份，失败整批回滚）。\n"
                    f"目录：{self._patch_root}\n\n继续？"):
                return
        self._patch_busy = True
        self.lbl_patch_status.configure(text="预演中…" if dry else "应用补丁中…")
        from ..patch import engine as pe

        def work():
            return pe.apply(self._patch_root, ops, dry_run=dry)

        self._bg(work, lambda r, e: self._patch_apply_done(r, e, dry))

    def _patch_apply_done(self, res, err, dry: bool) -> None:
        self._patch_busy = False
        if err or not res:
            self.lbl_patch_status.configure(text="失败")
            messagebox.showerror("补丁失败", str(err))
            return
        self._patch_backup = res.backup_dir or self._patch_backup
        self.lbl_patch_status.configure(
            text=("✓ 预演通过" if dry and res.ok else
                  "✗ 预演未通过" if dry else
                  "✓ 补丁已应用" if res.ok else "✗ 已回滚"))
        self._detail_set(res.text() + "\n\n备份目录：" + (res.backup_dir or "（无）"))
        if not dry and res.ok:
            self._patch_scan()
        if not res.ok:
            messagebox.showwarning("未通过", "详见下方输出；文件已回滚。" if not dry
                                   else "预演未通过，未改任何文件。")

    def _patch_rebuild_done(self, rb, err) -> None:
        self._patch_busy = False
        if err or not rb:
            self.lbl_patch_status.configure(text="重建失败")
            messagebox.showerror("重建失败", str(err))
            return
        self.lbl_patch_status.configure(
            text="✓ 重建完成" if rb.ok else "✗ 重建未通过")
        self._detail_set(rb.text())
        if rb.ok:
            self._patch_last_apk = rb.apk
            open_path(str(Path(rb.apk).parent))

    def _patch_rollback(self) -> None:
        if not self._patch_root or not self._patch_backup:
            messagebox.showinfo("提示", "还没有可用的备份。先「应用补丁」，"
                                        "或把之前的备份目录手动填进脚本。")
            return
        if not messagebox.askokcancel("确认回滚",
                                      f"将用备份覆盖回滚：\n{self._patch_backup}"):
            return
        from ..patch import engine as pe
        try:
            files = pe.rollback(self._patch_root, self._patch_backup)
            self._detail_set(f"✓ 已还原 {len(files)} 个文件\n" + "\n".join(files[:30]))
            self.lbl_patch_status.configure(text=f"已回滚 {len(files)} 个文件")
            self._patch_scan()
        except Exception as e:      # noqa: BLE001
            messagebox.showerror("回滚失败", str(e))

    # ==================================================================
    # 帮助
    # ==================================================================
    def _show_help(self) -> None:
        win = tk.Toplevel(self)
        win.title("脚本写法")
        win.geometry("760x600")
        win.configure(bg=T.BG)
        win.transient(self)

        txt = T.make_text(win, mono=True, bg=T.TERM_BG)
        txt.pack(fill="both", expand=True, padx=12, pady=12)
        txt.configure(state="normal")
        txt.insert("end", HELP_TEXT)
        txt.configure(state="disabled")

    # ---------------- 桌面快捷方式 ----------------
    def _make_shortcut(self) -> None:
        from ..tools.shortcut import create_desktop_shortcut
        try:
            p = create_desktop_shortcut()
            messagebox.showinfo("桌面快捷方式", f"已创建：\n{p}")
        except Exception as e:                       # noqa: BLE001
            messagebox.showerror("创建失败", str(e))

    # ---------------- 免责 / 杀软 / 安装 ----------------
    NOTICE_TEXT = """使用前须知

一、这不是病毒，但会被杀软拦
   本工具用 PyInstaller 打包，内含 hook、跨进程读取、修改文件等
   逆向分析必备能力 —— 这些特征与注入类木马重合，所以会被误报。
   杀软看不懂"你是否有授权"，只看行为。

   第一次使用前，请先加白名单：
     设置 → 隐私和安全性 → Windows 安全中心 → 病毒和威胁防护
     → 管理设置 → 排除项 → 添加排除项 → 文件夹
     添加：%LOCALAPPDATA%\\ReverseForge
     添加：本程序所在目录

   用 360 / 火绒 / 卡巴的：到"信任区"把这些路径加进去。

二、仅限自有或已授权目标
   分析你自己的软件、你获得书面授权的目标 —— 可以。
   破解商业软件、盗版、未授权获取他人账号数据、做外挂木马 —— 禁止。
   因使用产生的法律责任由使用者自行承担。完整条款见 DISCLAIMER.md。

三、缺工具怎么办
   双击安装包里的 install.bat（管理员），它会把
   JDK / apktool / aapt2 / apksigner / zipalign / adb / 7zr 装到
   %LOCALAPPDATA%\\ReverseForge\\vendor，装完就能用。

四、数据不出本机
   本工具全程本地运行，不上传任何被分析的文件、密钥或结果。
"""

    def _show_notice(self) -> None:
        messagebox.showinfo("使用前须知", self.NOTICE_TEXT)

    def _open_doc(self, name: str) -> None:
        for base in (config.APP_ROOT, Path(__file__).resolve().parent.parent.parent):
            p = Path(base) / name
            if p.exists():
                open_path(p)
                return
        messagebox.showinfo(name, "文档未随包提供，可在开源仓库根目录查看。")

    def _open_disclaimer(self) -> None:
        self._open_doc("DISCLAIMER.md")

    def _open_security(self) -> None:
        self._open_doc("SECURITY.md")

    def _open_install(self) -> None:
        for base in (config.APP_ROOT, Path(__file__).resolve().parent.parent.parent):
            p = Path(base) / "install.bat"
            if p.exists():
                open_path(p.parent)
                messagebox.showinfo(
                    "环境安装",
                    "已打开程序目录。\n\n请右键 install.bat → 以管理员身份运行。\n"
                    "装完重开本程序，右上角「工具」会显示可用项数。")
                return
        messagebox.showinfo("环境安装", "没找到 install.bat。可从开源仓库下载安装包。")

    def _first_run_hint(self) -> None:
        """
        第一次启动只写终端提示，**不再弹模态框**。

        原因（用户实测抓到）：拖了 19 个文件进投放区，700ms 后弹窗把主窗口
        全灰掉，一边让你干活一边锁住界面 —— 典型的左右脑互搏。
        真要看须知，帮助菜单里有，随时可点；RF_NOTICE=1 可强制弹（排障用）。
        """
        marker = config.USER_ROOT / ".notice_ok"
        if marker.exists():
            return
        try:
            marker.parent.mkdir(parents=True, exist_ok=True)
            marker.write_text(time.strftime("%Y-%m-%d %H:%M:%S"), encoding="utf-8")
        except OSError:
            pass
        self.lbl_status.configure(text="提示：帮助 → 使用前须知（杀软白名单 / 免责）")
        self._term("提示：第一次使用请看「帮助 → 使用前须知」"
                   "（杀软白名单、免责声明）。这里不会弹窗挡住你干活。", "warn")
        if os.environ.get("RF_NOTICE"):
            self._show_notice()

    def _first_run_notice(self) -> None:
        """兼容旧调用：仍然只给非模态提示。"""
        self._first_run_hint()

    # ==================================================================
    def _on_close(self) -> None:
        auto = getattr(self, "_auto_run", None)
        busy = bool((self.run and self.run.alive) or (auto and auto.alive))
        if busy:
            if not messagebox.askokcancel(
                    "确认退出", "还有任务在跑，退出会终止所有子进程。继续？"):
                return
        self._closing = True                     # 让三个 pump 不再排下一次
        try:
            runner.kill_all()                    # 按进程树杀，apktool/java 不留孤儿
        except Exception:                        # noqa: BLE001
            pass
        try:
            if getattr(self, "_repl", None):
                self._repl.stop()                # 常驻解释器（python.exe）一起收掉
        except Exception:                        # noqa: BLE001
            pass
        self.destroy()


    # ===================================================================
    # 代码终端（常驻 Python，跨次保留变量）
    # ===================================================================

    def _build_repl_tab(self, nb) -> None:
        f = tk.Frame(nb, bg=T.PANEL)
        nb.add(f, text="  代码终端  ")

        top = tk.Frame(f, bg=T.PANEL)
        top.pack(fill="x", padx=12, pady=(10, 6))
        tk.Label(top, text="代码终端", bg=T.PANEL, fg=T.TEXT,
                 font=T.UI_FONT_B).pack(side="left")
        tk.Label(top, text="常驻进程，变量跨次保留；和写脚本完全一致",
                 bg=T.PANEL, fg=T.MUTED, font=T.UI_FONT_S).pack(side="left", padx=10)
        self.lbl_repl_stat = tk.Label(top, text="未启动", bg=T.PANEL, fg=T.MUTED,
                                      font=T.UI_FONT_S)
        self.lbl_repl_stat.pack(side="right")
        ttk.Button(top, text="重启终端", style="Ghost.TButton",
                   command=self._repl_restart).pack(side="right", padx=6)
        ttk.Button(top, text="清空", style="Ghost.TButton",
                   command=self._repl_clear_code).pack(side="right")

        # 先占住底部按钮条，再让 PanedWindow 吃剩余空间
        # （反过来写的话，窗口一矮按钮条就被挤到可视区外）
        bar = tk.Frame(f, bg=T.PANEL)
        bar.pack(side="bottom", fill="x", padx=12, pady=(0, 10))
        ttk.Button(bar, text="运行  F5", style="Accent.TButton",
                   command=self._repl_run).pack(side="left")
        ttk.Button(bar, text="运行选中", style="TButton",
                   command=lambda: self._repl_run(True)).pack(side="left", padx=6)
        ttk.Button(bar, text="清空输出", style="Ghost.TButton",
                   command=self._repl_clear_out).pack(side="left")
        ttk.Button(bar, text="存回积木", style="TButton",
                   command=self._repl_save_snippet).pack(side="left", padx=6)
        ttk.Button(bar, text="变量表", style="Ghost.TButton",
                   command=self._repl_vars).pack(side="left")
        self.lbl_repl_msg = tk.Label(bar, text="", bg=T.PANEL, fg=T.MUTED,
                                     font=T.UI_FONT_S)
        self.lbl_repl_msg.pack(side="right")

        pw = tk.PanedWindow(f, orient="vertical", bg=T.PANEL, sashwidth=5,
                            sashrelief="flat", bd=0, showhandle=False)
        pw.pack(fill="both", expand=True, padx=10, pady=(0, 6))
        top_f = tk.Frame(pw, bg=T.PANEL)
        bot_f = tk.Frame(pw, bg=T.PANEL)
        pw.add(top_f, minsize=110, height=260)
        pw.add(bot_f, minsize=90)

        # --- 上：编辑器 ---
        ew = tk.Frame(top_f, bg=T.PANEL)
        ew.pack(fill="both", expand=True)
        self.repl_edit = T.make_text(ew, mono=True, undo=True)
        self.repl_edit.configure(state="normal")     # make_text 默认只读，这里要可编辑
        self.repl_edit.pack(side="left", fill="both", expand=True)
        esb = ttk.Scrollbar(ew, orient="vertical", command=self.repl_edit.yview)
        esb.pack(side="right", fill="y")
        self.repl_edit.configure(yscrollcommand=esb.set)
        self.repl_edit.bind("<F5>", lambda e: (self._repl_run(), "break")[1])
        self.repl_edit.bind("<Control-Return>", lambda e: (self._repl_run(), "break")[1])
        self.repl_edit.insert("1.0", _REPL_WELCOME)

        # --- 下：输出 ---
        ow = tk.Frame(bot_f, bg=T.PANEL)
        ow.pack(fill="both", expand=True)
        self.repl_out = T.make_text(ow, mono=True)
        self.repl_out.pack(side="left", fill="both", expand=True)
        osb = ttk.Scrollbar(ow, orient="vertical", command=self.repl_out.yview)
        osb.pack(side="right", fill="y")
        self.repl_out.configure(yscrollcommand=osb.set, state="disabled")
        self.repl_out.tag_configure("meta", foreground=T.MUTED)
        self.repl_out.tag_configure("err", foreground=T.TERM_ERR)
        self.repl_out.tag_configure("ok", foreground=T.TERM_OK)

        self._repl = None
        self._repl_busy = False
        self._repl_sid = ""
        self._repl_title = ""

    # ---- 输出 ----
    def _repl_append(self, text: str, tag: str = "") -> None:
        self.repl_out.configure(state="normal")
        self.repl_out.insert("end", text, tag or ())
        self.repl_out.see("end")
        self.repl_out.configure(state="disabled")

    def _repl_clear_out(self) -> None:
        self.repl_out.configure(state="normal")
        self.repl_out.delete("1.0", "end")
        self.repl_out.configure(state="disabled")

    def _repl_clear_code(self) -> None:
        self.repl_edit.delete("1.0", "end")

    def _repl_status(self, msg: str, color: str = "") -> None:
        self.lbl_repl_stat.configure(text=msg, fg=color or T.MUTED)

    # ---- 送入代码 ----
    def repl_send(self, code: str, title: str = "", sid: str = "") -> None:
        """把一段代码送进终端编辑区（积木页/补丁页都调这里）。"""
        cur = self.repl_edit.get("1.0", "end").strip()
        if cur and cur != _REPL_WELCOME.strip():
            self.repl_edit.insert("end", "\n\n# ---- 分隔 ----\n")
        self.repl_edit.insert("end", code.rstrip() + "\n")
        self.repl_edit.see("end")
        self._repl_sid = sid or ""
        self._repl_title = title or ""
        # 切到终端页
        try:
            for i in range(self.nb.index("end")):
                if self.nb.tab(i, "text").strip() == "代码终端":
                    self.nb.select(i)
                    break
        except tk.TclError:
            pass
        self._repl_status(f"已送入：{title or '代码'}"
                          + (f"（{sid}）" if sid else ""), T.OK)

    # ---- 执行 ----
    def _repl_run(self, selected: bool = False) -> None:
        src = ""
        if selected:
            try:
                src = self.repl_edit.get("sel.first", "sel.last")
            except tk.TclError:
                src = ""
        if not src.strip():
            src = self.repl_edit.get("1.0", "end").strip()
        if not src:
            self._repl_status("没有代码可运行", T.WARN)
            return
        if self._repl_busy:
            self._repl_status("上一段还在跑…", T.WARN)
            return
        self._repl_busy = True
        self._repl_status("运行中…", T.MUTED)
        self._repl_append("\n▶ " + time.strftime("%H:%M:%S") + "\n", "meta")
        threading.Thread(target=self._repl_worker, args=(src,), daemon=True).start()

    def _repl_worker(self, src: str) -> None:
        res = None
        err = ""
        try:
            if self._repl is None:
                from ..engine.repl import Repl
                self._repl = Repl()
                self._repl.start()
            self._repl.runs = getattr(self._repl, "runs", 0)
            res = self._repl.run(src)
        except Exception as e:                       # noqa: BLE001
            err = f"{type(e).__name__}: {e}"
        self._post(self._repl_done, res, err)

    def _repl_done(self, res, err: str = "") -> None:
        self._repl_busy = False
        if res is None:
            self._repl_append(err + "\n", "err")
            self._repl_status("启动失败", T.ERR)
            return
        if res.out:
            self._repl_append(res.out + ("" if res.out.endswith("\n") else "\n"))
        if not res.ok:
            extra = res.err or ""
            if extra and extra.strip() != (res.out or "").strip():
                self._repl_append(extra + ("" if extra.endswith("\n") else "\n"), "err")
            self._repl_status(f"出错 · {res.elapsed * 1000:.0f}ms", T.ERR)
        else:
            note = f"完成 · 第 {getattr(self._repl, 'runs', 0)} 次 · {res.elapsed * 1000:.0f}ms"
            if res.restarted:
                note += " · 子进程已重启（变量丢失）"
            self._repl_status(note, T.OK)
        if res.restarted:
            self._repl_append("[终端进程重启过，之前的变量没有了]\n", "meta")

    def _repl_restart(self) -> None:
        try:
            if self._repl:
                self._repl.restart()
            self._repl_append("[已重启终端]\n", "meta")
            self._repl_status("已重启", T.OK)
        except Exception as e:                       # noqa: BLE001
            self._repl_status(f"重启失败：{e}", T.ERR)

    def _repl_vars(self) -> None:
        if not self._repl or not self._repl.alive:
            self._repl_status("终端没在跑", T.WARN)
            return
        vs = self._repl.variables()
        self._repl_append("\n变量：\n", "meta")
        if not vs:
            self._repl_append("  （空）\n", "meta")
        for k, v in vs:
            self._repl_append(f"  {k} = {v}\n")

    def _repl_save_snippet(self) -> None:
        src = self.repl_edit.get("1.0", "end").strip()
        if not src:
            self._repl_status("没有代码可存", T.WARN)
            return
        from ..snippets import get_library
        sid = self._repl_sid or f"user.term_{time.strftime('%H%M%S')}"
        title = self._repl_title or f"终端积木 {time.strftime('%H:%M')}"
        try:
            p = get_library().save_user(
                sid, title, src, category="工程", level=2,
                purpose="终端里调通的代码，直接复用",
                tags=["终端", "自定义"])
        except Exception as e:                       # noqa: BLE001
            self._repl_status(f"保存失败：{e}", T.ERR)
            return
        self._snip_reload()
        self._repl_status(f"已存为积木 {sid}（{p.name}）", T.OK)
        self._repl_append(f"[已存为积木 {sid} → {p}]\n", "meta")

    # ---- 目录总览：一眼看全 42 块 ----
    def _snip_catalog_window(self) -> None:
        lib = getattr(self, "_snip_lib", None)
        if lib is None:
            return
        win = tk.Toplevel(self)
        win.title("积木目录总览")
        win.geometry("900x620")
        win.configure(bg=T.BG)
        win.transient(self)

        st = lib.stats()
        head = tk.Label(
            win,
            text=(f"{len(st['by_category'])} 个分类 · 共 {st['total']} 块　"
                  f"入门 {st['by_level'].get('入门', 0)} / "
                  f"进阶 {st['by_level'].get('进阶', 0)} / "
                  f"高阶 {st['by_level'].get('高阶', 0)}　"
                  f"语法异常 {st['invalid']}"),
            bg=T.BG, fg=T.TEXT, font=T.UI_FONT_B, anchor="w")
        head.pack(fill="x", padx=14, pady=(12, 6))

        bar = tk.Frame(win, bg=T.BG)
        bar.pack(fill="x", padx=14, pady=(0, 6))
        kw = tk.StringVar()
        ttk.Entry(bar, textvariable=kw, width=30).pack(side="left")
        ttk.Button(bar, text="筛选", style="Ghost.TButton",
                   command=lambda: fill(kw.get())).pack(side="left", padx=6)
        ttk.Button(bar, text="复制全部", style="Ghost.TButton",
                   command=lambda: (self.clipboard_clear(),
                                    self.clipboard_append(lib.markdown()),
                                    self.lbl_snip_msg.configure(
                                        text="全库目录已复制到剪贴板", fg=T.OK))
                   ).pack(side="right")

        wrap = tk.Frame(win, bg=T.BG)
        wrap.pack(fill="both", expand=True, padx=14, pady=(0, 12))
        cols = ("id", "title", "cat", "lv", "purpose")
        tv = ttk.Treeview(wrap, columns=cols, show="headings")
        for c, t, w in (("id", "编号", 150), ("title", "名称", 180),
                        ("cat", "分类", 70), ("lv", "难度", 60),
                        ("purpose", "作用", 420)):
            tv.heading(c, text=t)
            tv.column(c, width=w, anchor="w")
        tv.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(wrap, orient="vertical", command=tv.yview)
        sb.pack(side="right", fill="y")
        tv.configure(yscrollcommand=sb.set)

        def fill(k: str = "") -> None:
            tv.delete(*tv.get_children())
            k = (k or "").strip().lower()
            for s in lib.all():
                blob = (s.sid + s.title + s.category + s.purpose +
                        " ".join(s.tags)).lower()
                if k and k not in blob:
                    continue
                tv.insert("", "end", values=(s.sid, s.title, s.category,
                                             s.level_name, s.purpose))
        fill()

        def on_double(_e=None) -> None:
            sel = tv.selection()
            if not sel:
                return
            sid = tv.item(sel[0], "values")[0]
            win.destroy()
            # 回到积木页并选中它
            for i in range(self.nb.index("end")):
                if self.nb.tab(i, "text").strip() == "积木":
                    self.nb.select(i)
                    break
            for iid, s in self._snip_map.items():
                if s == sid:
                    self.snip_tree.selection_set(iid)
                    self.snip_tree.see(iid)
                    self._snip_on_select()
                    break

        tv.bind("<Double-1>", on_double)

    def _snip_to_repl(self) -> None:
        sid = getattr(self, "_snip_current", "")
        if not sid:
            self.lbl_snip_msg.configure(text="先选一块积木", fg=T.WARN)
            return
        code = self.snip_code.get("1.0", "end").strip()
        snip = self._snip_lib.get(sid) if hasattr(self, "_snip_lib") else None
        self.repl_send(code, snip.title if snip else sid, sid)

    # ---- 从补丁页送过来 ----
    def _patch_to_repl(self) -> None:
        ids = self._patch_ids() if hasattr(self, "_patch_ids") else []
        if not ids:
            self.lbl_patch_status.configure(text="先勾选补丁点，再送终端", fg=T.WARN)
            return
        target = self.patch_target.get().strip() or "<解包目录>"
        code = (
            f"# 来自补丁页：{', '.join(ids)}\n"
            f"# 先在预演里确认改法，再落盘\n"
            f"SMALI = r\"{target}\"\n"
            f"rep = globals().get('rep') or rf.patch_scan(SMALI)\n"
            f"ops = rf.patch_plan(rep, ids={ids!r})\n"
            f"print(rf.patch_apply(SMALI, ops, dry_run=True).text())\n"
        )
        self.repl_send(code, f"补丁 {','.join(ids)}")


    # ===================================================================
    # 对话（自然语言 → 计划 → 调工具）
    # ===================================================================
    def _build_chat_tab(self, nb) -> None:
        f = tk.Frame(nb, bg=T.PANEL)
        nb.add(f, text="  对话  ")

        top = tk.Frame(f, bg=T.PANEL)
        top.pack(fill="x", padx=12, pady=(10, 4))
        tk.Label(top, text="对话分析", bg=T.PANEL, fg=T.TEXT,
                 font=T.UI_FONT_B).pack(side="left")
        self.lbl_chat_engine = tk.Label(top, text="引擎：规则（离线）",
                                        bg=T.PANEL, fg=T.MUTED, font=T.UI_FONT_S)
        self.lbl_chat_engine.pack(side="left", padx=10)
        self.lbl_chat_api = tk.Label(top, text="API：未启动", bg=T.PANEL,
                                     fg=T.MUTED, font=T.UI_FONT_S)
        self.lbl_chat_api.pack(side="right")
        ttk.Button(top, text="本地 API", style="Ghost.TButton",
                   command=self._api_toggle).pack(side="right", padx=6)

        tk.Label(f, text="目标取自左侧「投放文件」区；直接说人话就行，"
                         "例如：这几个文件是什么、能解密吗、把脚本里的卡密找出来",
                 bg=T.PANEL, fg=T.MUTED, font=T.UI_FONT_S, anchor="w").pack(
            fill="x", padx=14, pady=(0, 6))

        wrap = tk.Frame(f, bg=T.PANEL)
        wrap.pack(fill="both", expand=True, padx=12, pady=(0, 6))
        self.chat_log = T.make_text(wrap, mono=True)
        self.chat_log.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(wrap, orient="vertical", command=self.chat_log.yview)
        sb.pack(side="right", fill="y")
        self.chat_log.configure(yscrollcommand=sb.set)
        for tag, color in (("me", T.ACCENT), ("plan", T.TERM_CMD),
                           ("ok", T.TERM_OK), ("err", T.TERM_ERR),
                           ("hint", T.MUTED)):
            self.chat_log.tag_configure(tag, foreground=color)

        inw = tk.Frame(f, bg=T.PANEL)
        inw.pack(fill="x", padx=12, pady=(0, 10))
        self.chat_input = T.make_text(inw, mono=False, height=3)
        self.chat_input.configure(state="normal")
        self.chat_input.pack(side="left", fill="both", expand=True)
        self.chat_input.bind("<Control-Return>",
                             lambda e: (self._chat_send(), "break")[1])
        btns = tk.Frame(inw, bg=T.PANEL)
        btns.pack(side="right", fill="y", padx=(8, 0))
        self.btn_chat = ttk.Button(btns, text="发 送", style="Accent.TButton",
                                   command=self._chat_send)
        self.btn_chat.pack(fill="x")
        ttk.Button(btns, text="清空", style="Ghost.TButton",
                   command=self._chat_clear).pack(fill="x", pady=(6, 0))

        self._api_srv = None
        self._chat_busy = False
        # 后台线程不直接碰 Tk（会抛 "main thread is not in main loop"），
        # 一律往队列里塞，主线程定期抽。
        import queue as _q
        self._chat_q: "_q.Queue" = _q.Queue()
        self.after(150, self._chat_pump)
        self.after(400, self._chat_refresh_engine)
        self._chat_append("在左边拖入文件，然后在这里说要干什么。\n"
                          "Ctrl+Enter 发送。\n", "hint")

    def _chat_pump(self) -> None:
        """主线程里抽队列，把后台产生的内容画出来。"""
        try:
            while True:
                item = self._chat_q.get_nowait()
                kind = item[0]
                if kind == "line":
                    self._chat_append(item[1], item[2] if len(item) > 2 else "")
                elif kind == "done":
                    self._chat_done(item[1], item[2])
                elif kind == "plan":
                    self._chat_append(item[1], "plan")
        except Exception:                            # noqa: BLE001  (空队列)
            pass
        if self._closing:
            return
        self.after(120, self._chat_pump)

    def _chat_refresh_engine(self) -> None:
        try:
            from ..agent import orchestrator as ag
            if ag.llm_ready():
                self.lbl_chat_engine.configure(
                    text="引擎：LLM（已配置端点）", fg=T.OK)
            else:
                self.lbl_chat_engine.configure(
                    text="引擎：规则（离线可用；配 LLM 端点可升级）", fg=T.MUTED)
        except Exception:                            # noqa: BLE001
            self.lbl_chat_engine.configure(text="引擎：不可用", fg=T.ERR)

    def _chat_append(self, text: str, tag: str = "") -> None:
        self.chat_log.configure(state="normal")
        self.chat_log.insert("end", text, tag or ())
        self.chat_log.see("end")
        self.chat_log.configure(state="disabled")

    def _chat_clear(self) -> None:
        self.chat_log.configure(state="normal")
        self.chat_log.delete("1.0", "end")
        self.chat_log.configure(state="disabled")

    def _chat_targets(self) -> list[str]:
        if hasattr(self, "drop") and self.drop.files:
            return [str(f.path) for f in
                    (self.drop.selected_files() or self.drop.files)]
        return []

    def _chat_send(self) -> None:
        task = self.chat_input.get("1.0", "end").strip()
        if not task:
            return
        if self._chat_busy:
            self._chat_append("上一件事还在跑，稍等…\n", "hint")
            return
        files = self._chat_targets()
        self.chat_input.delete("1.0", "end")
        self._chat_append(f"\n你：{task}\n", "me")
        if not files:
            self._chat_append("（投放区是空的，只能做规划，不能真跑）\n", "hint")
        self._chat_busy = True
        self.btn_chat.configure(state="disabled")
        threading.Thread(target=self._chat_worker, args=(task, files),
                         daemon=True).start()

    def _chat_worker(self, task: str, files: list[str]) -> None:
        try:
            from ..agent import orchestrator as ag
            p = ag.make_plan(task, files)
            self._chat_q.put(("plan", p.describe() + "\n"))
            if not files:
                self._chat_q.put(("done", None, ""))
                return
            out = ag.run(p, files,
                         on_event=lambda s: self._chat_q.put(("line", s + "\n")))
            self._chat_q.put(("done", out, ""))
        except Exception as e:                       # noqa: BLE001
            self._chat_q.put(("done", None, f"{type(e).__name__}: {e}"))

    def _chat_done(self, out, err: str = "") -> None:
        self._chat_busy = False
        self.btn_chat.configure(state="normal")
        if err:
            self._chat_append(f"出错了：{err}\n", "err")
        elif out is not None:
            if out.ok:
                self._chat_append(f"\n完成，用时 {out.elapsed:.1f}s。\n", "ok")
            else:
                self._chat_append(f"\n完成，但有 {len(out.errors)} 处失败。\n", "err")

    # ---- 供投放区调用 ----
    def _chat_dispatch(self, task: str, paths: list[str]) -> None:
        try:
            for i in range(self.nb.index("end")):
                if self.nb.tab(i, "text").strip() == "对话":
                    self.nb.select(i)
                    break
        except tk.TclError:
            pass
        self.chat_input.delete("1.0", "end")
        self.chat_input.insert("1.0", task)
        self._chat_send()

    # ---- 本地 API ----
    def _api_toggle(self) -> None:
        try:
            if self._api_srv and self._api_srv.running:
                self._api_srv.stop()
                self._api_srv = None
                self.lbl_chat_api.configure(text="API：未启动", fg=T.MUTED)
                self._chat_append("[本地 API 已停止]\n", "hint")
                return
            from ..server import ApiServer
            srv = ApiServer(port=8765, allow_write=False).start()
            self._api_srv = srv
            self.lbl_chat_api.configure(
                text=f"API：127.0.0.1:{srv.port}", fg=T.OK)
            self.clipboard_clear()
            self.clipboard_append(srv.token)
            self._chat_append(
                f"[本地 API 已启动] {srv.url}\n"
                f"token 已复制到剪贴板：{srv.token}\n"
                f"工具清单：GET /tools　调用：POST /call　"
                f"一句话分析：POST /analyze\n"
                f"写操作默认禁用（打补丁/重建需要显式允许）。\n", "ok")
        except Exception as e:                       # noqa: BLE001
            self.lbl_chat_api.configure(text="API：启动失败", fg=T.ERR)
            self._chat_append(f"[API 启动失败] {e}\n", "err")


    # ------------------------------------------------------------------
    # 全自动化：一键拆包 / 解密 / 删前置验证 / 打包 / 丢桌面
    # ------------------------------------------------------------------
    _FULLAUTO_STAGES = [
        ("⚡ 全流程一键到底", "all"),
        ("① 一键拆包", "unpack"),
        ("② 一键解密", "decrypt"),
        ("③ 一键删除前置验证", "patch"),
        ("④ 一键打包(仅APP)", "pack"),
    ]

    def _build_fullauto_tab(self, nb) -> None:
        f = tk.Frame(nb, bg=T.PANEL)
        nb.add(f, text="  全自动化  ")

        top = tk.Frame(f, bg=T.PANEL)
        top.pack(fill="x", padx=12, pady=(10, 4))
        tk.Label(top, text="全自动化 · 拆包 → 解密 → 删验证 → 打包 → 桌面",
                 bg=T.PANEL, fg=T.TEXT, font=T.UI_FONT_B).pack(side="left")
        self.lbl_auto = tk.Label(top, text="目标：投放区为空", bg=T.PANEL,
                                 fg=T.MUTED, font=T.UI_FONT_S)
        self.lbl_auto.pack(side="left", padx=10)

        tk.Label(f, text="唯一的处理入口（原「卡密绕过」已并入这一页，不再单独一个页签）。"
                         "文件丢左上投放区，点一个按钮就完事。防拦截分三层，任一层生效程序就能跑：\n"
                         "　① 改判定 —— 把校验方法改成恒返回「通过」；\n"
                         "　② 摘处置 —— 把「检测到就不让跑」的 exit / killProcess / finish 换成空操作，"
                         "不管检测藏多深、套几层包装都退不出去；\n"
                         "　③ 联网覆盖 —— 服务器说不行也没关系：状态码强制 200、成功标志强制 true，"
                         "并附一份 Frida 脚本把返回体一起洗白（加固包也能用）。\n"
                         "重打包必然踩的「签名自校验 / dex 完整性 / 反调试 / 反 root / 反模拟器 / 反注入」"
                         "会被逐条中和；壳与代码抽取这类改不动的会如实报出来。"
                         "原文件不动，全程可备份回滚。",
                 bg=T.PANEL, fg=T.MUTED, font=T.UI_FONT_S,
                 anchor="w", wraplength=1000).pack(fill="x", padx=14, pady=(0, 8))

        bar = tk.Frame(f, bg=T.PANEL)
        bar.pack(fill="x", padx=12, pady=(0, 8))
        for i, (label, stage) in enumerate(self._FULLAUTO_STAGES):
            b = ttk.Button(bar, text=label,
                           style="Accent.TButton" if stage == "all" else "Ghost.TButton",
                           command=lambda s=stage: self._fullauto_start(s))
            b.pack(side="left", padx=(0 if i == 0 else 6, 0))
        self._fullauto_btns = list(bar.winfo_children())
        self.auto_desktop = tk.BooleanVar(value=True)   # 默认开：小白不用学打包
        tk.Checkbutton(bar, text="成品自动放桌面", variable=self.auto_desktop,
                       bg=T.PANEL, fg=T.TERM_OK, activebackground=T.PANEL,
                       selectcolor=T.PANEL2, borderwidth=0,
                       font=T.UI_FONT_S).pack(side="left", padx=12)
        self.auto_verify = tk.BooleanVar(value=False)
        tk.Checkbutton(bar, text="装到设备并启动验证（需 adb）", variable=self.auto_verify,
                       bg=T.PANEL, fg=T.TEXT, activebackground=T.PANEL,
                       selectcolor=T.PANEL2, borderwidth=0,
                       font=T.UI_FONT_S).pack(side="left")
        ttk.Button(bar, text="打开产物", style="Ghost.TButton",
                   command=self._fullauto_open).pack(side="right")

        wrap = tk.Frame(f, bg=T.PANEL)
        wrap.pack(fill="both", expand=True, padx=12, pady=(0, 10))
        self.auto_log = T.make_text(wrap, mono=True)
        self.auto_log.configure(state="normal")
        self.auto_log.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(wrap, orient="vertical", command=self.auto_log.yview)
        sb.pack(side="right", fill="y")
        self.auto_log.configure(yscrollcommand=sb.set)
        self.auto_log.tag_configure("ok", foreground=T.TERM_OK)
        self.auto_log.tag_configure("err", foreground=T.TERM_ERR)
        self.auto_log.tag_configure("meta", foreground=T.MUTED)
        self.auto_log.delete("1.0", "end")
        self.auto_log.insert("1.0",
                             "流程：① 拆包 → ② 解密(assets/规则包) → "
                             "③ 删前置验证(卡密/密码/服务器复核) → "
                             "④ 打包签名 → ⑤ 丢桌面。\n"
                             "每个按钮可单独跑，也可以全流程一键到底。\n", "meta")

        import queue as _q
        self._auto_q: "_q.Queue" = _q.Queue()
        self._auto_run = None
        self._auto_stage = "all"
        self.after(150, self._fullauto_pump)
        self.after(400, self._fullauto_sync_target)

    def _fullauto_sync_target(self) -> None:
        files = getattr(self, "drop", None) and self.drop.files
        if files:
            self.lbl_auto.configure(
                text=f"目标：{files[0].name}"
                     + (f" 等 {len(files)} 个" if len(files) > 1 else ""),
                fg=T.OK)
        else:
            self.lbl_auto.configure(text="目标：投放区为空", fg=T.MUTED)
        self.after(600, self._fullauto_sync_target)

    def _fullauto_append(self, text: str, tag: str = "") -> None:
        self.auto_log.configure(state="normal")
        self.auto_log.insert("end", text + "\n", tag or ())
        self.auto_log.see("end")
        self.auto_log.configure(state="disabled")

    def _fullauto_start(self, stage: str) -> None:
        from ..engine.script_runtime import ScriptRun

        if self._auto_run and self._auto_run.alive:
            self._fullauto_append("上一轮还在跑…", "meta")
            return
        if self.run and self.run.alive:
            messagebox.showinfo("正在运行", "左侧还有脚本在跑，等它结束再开全自动化。")
            return
        files = getattr(self, "drop", None) and self.drop.files
        if not files:
            messagebox.showinfo("提示", "先把 APK 或文件拖到左上角投放区。")
            return
        script = next((s.file for s in self.scripts
                       if "16_full_auto" in str(s.file)), None)
        if script is None:
            messagebox.showerror("找不到脚本",
                                 "scripts/16_full_auto.py 不在脚本库里，点一下刷新。")
            return

        self._auto_stage = stage
        params = {
            "target": str(files[0].path),
            "stage": stage,
            "to_desktop": bool(self.auto_desktop.get()),
            "run_verify": bool(self.auto_verify.get()),
        }
        if len(files) > 1:
            self._fullauto_append(
                f"投放区有 {len(files)} 个目标，全自动化一次只跑一个："
                f"本次取 {files[0].name}（批量请用左侧「批量」页）", "meta")

        # 先清日志、先立 running 标志：脚本可能 100ms 内就失败（目标被删、
        # apktool 缺失），那时 pump 还没看到 alive，标志为 False 就会让
        # 5 个按钮永久禁用、整页没有任何恢复入口。
        self.auto_log.configure(state="normal")
        self.auto_log.delete("1.0", "end")
        self.auto_log.configure(state="disabled")
        self._auto_was_running = True
        for w in self._fullauto_btns:
            try:
                w.configure(state="disabled")
            except Exception:                        # noqa: BLE001
                pass
        self._fullauto_append(f"\n▶ 开始（{stage}）：" + str(files[0].path), "meta")

        workdir = config.WORKSPACE_ROOT / f"{time.strftime('%m%d_%H%M%S')}_fullauto"
        # 产物页/报告页跟着这次跑，否则跑完整页还是空的（或指着上一个任务）
        self._last_dir = workdir
        try:
            self._auto_run = ScriptRun(
                script, params, workdir=workdir,
                on_event=lambda ev: self._auto_q.put(ev))
            self._auto_run.start()
        except Exception as e:                       # noqa: BLE001
            self._auto_was_running = False
            self._fullauto_append(f"启动失败：{e}", "err")
            for w in self._fullauto_btns:
                try:
                    w.configure(state="normal")
                except Exception:                    # noqa: BLE001
                    pass

    def _fullauto_pump(self) -> None:
        try:
            while True:
                ev = self._auto_q.get_nowait()
                if ev.kind == "step":
                    self._fullauto_append(f"── [{ev.pct:>3}%] {ev.text}", "meta")
                elif ev.kind == "error":
                    self._fullauto_append(str(ev.text), "err")
                else:
                    self._fullauto_append(str(ev.text))
        except Exception:                            # noqa: BLE001
            pass
        run = self._auto_run
        if run and not run.alive and getattr(self, "_auto_was_running", False):
            self._auto_was_running = False
            for w in self._fullauto_btns:
                try:
                    w.configure(state="normal")
                except Exception:                    # noqa: BLE001
                    pass
            self._fullauto_append("■ 结束。报告与成品在「打开产物」里。", "meta")
            # 收尾同步：产物树 + 报告页指向这一次的 workdir
            try:
                if run.ctx.workdir:
                    self._last_dir = Path(run.ctx.workdir)
                self._refresh_artifacts()
                self._load_report()
            except Exception:                        # noqa: BLE001
                pass
        if run and run.alive:
            self._auto_was_running = True
        if getattr(self, "_closing", False):
            return                                   # 窗口在关，别再排 after
        self.after(150, self._fullauto_pump)

    def _fullauto_open(self) -> None:
        run = self._auto_run
        if run and run.ctx.workdir:
            open_path(run.ctx.workdir)
        else:
            open_path(config.WORKSPACE_ROOT)


# 终端页的初始提示（第一次打开就有东西可点）
_REPL_WELCOME = """# 这里就是终端：改完按 F5 跑，变量会留到下一次。
# rf 已经注入好了，和写脚本一模一样。

rf.which("python")

# 试试：
# rep = rf.scan_any(".")          # 任意文件识别
# rf.decrypt_auto("secret.bin")   # 自动试解
# rf.auth_scan("tool.py")         # 找密码/卡密校验
"""

HELP_TEXT = """ReverseForge 脚本写法
════════════════════════════════════════════════════════════

一、脚本是什么
    scripts/ 目录下的普通 .py 文件。运行时会被注入：

        rf     工具门面（下面所有能力都在这里）
        args   参数字典；每个 @param 声明的参数也会变成同名全局变量

二、头部元信息（写了界面会自动生成表单）
    # @name  启动校验扫描
    # @desc  找启动前的卡密/授权判定
    # @param apk   目标 APK      [file]
    # @param out   输出目录       [dir]
    # @param note  生成中文注释    [bool:true]
    # @param jobs  并发数         [int:4]
    # @param mode  模式           [choice:fast,full:full]

三、侦察
    rf.apk_info(path)              包名/版本/权限/加固
    rf.apk_unpack(path, annotate=) 解包 + 反编译 + 中文注释
    rf.dex / rf.elf / rf.pe        结构解析
    rf.strings(path)               字符串提取与分类
    rf.keys(path)                  硬编码密钥/口令
    rf.deps(src)                   跨文件依赖图（入度/校验点/调用链）

四、校验点（启动前到底查了什么）
    rep = rf.patch_scan(unpack_dir)
        → 沿 Application/Activity 启动调用链 BFS，四路证据交叉：
          命名（license/card/verify/isVip…）、结构（布尔闸门/阻断分支）、
          常量（URL/key/卡密提示）、接口（摘要/签名/网络/存储）
        每个点给出：证据、置信度、是否启动路径、调用链、补丁建议

    rf.patch_plan(rep, ids=None, only_pre=True)   → 可执行补丁列表
    rf.frida(rep)                                  → 运行时覆盖脚本

五、补丁（改完必须还能跑）
    rf.patch_apply(dir, ops, dry_run=True)   预演：核对原指令 + 语法，不写盘
    rf.patch_apply(dir, ops)                 应用：备份→原子写→校验→失败整批回滚
    rf.patch_rebuild(dir, out, ops=ops)      重建→对齐→签名→验签→回读补丁
    rf.patch_rollback(dir, backup)           回到动手之前

    支持四类改法：
        方法体短路（布尔闸门恒 true/false，方向按 isExpired/isRooted 识别）
        分支取反（if-eqz ↔ if-nez）
        强制跳转（goto）
        单点常量（const/4 0x0 ↔ 0x1）

六、代码积木（30+ 块，可拆可拼）
    rf.snippets("补丁")          按关键词/分类/难度取
    rf.snippet("patch.apply")    取一块看作用/风险/代码
    rf.compose([...], out=path)  按依赖排序拼成脚本并整体校验
    界面上「积木」页：分类树 + 说明 + 代码 + 校验 + 保存为脚本 + 拼装选中

七、语法校验
    rf.validate("a.py")                 按扩展名自动判断
    rf.validate("def f(:", "python")     直接校验一段代码
    rf.validate_tree(dir)               批量校验 smali
    支持 python / smali / java / json / xml；错误带行号与中文提示。

八、本机强加密
    rf.crypto.encrypt(data, "口令")      AES-256-GCM（默认）
    rf.crypto.decrypt(env, "口令")       认证失败会明确报错
    rf.crypto.hmac_sign / hmac_verify    HMAC-SHA256，常数时间比较
    rf.crypto.seal_json / open_json      加密落盘（补丁配方/密钥清单）
    rf.crypto_test()                     真跑一遍往返并给出本机耗时

九、注释是怎么判"核心"的
    语义：类名/方法名/字段/字面量/API 命中授权、签名、完整性、
          环境检测、鉴权、有效期、服务端校验
    结构：被多少类依赖（入度）
    两条证据都写进注释，能看出"为什么标它"，不是黑盒结论。

十、两个新标签页
    「积木」 左树分类 → 右侧作用/需要/风险/代码 → 校验/保存/拼装
    「补丁」 ①选目录 ②扫描 ③预演 ④应用 ⑤重建；可回滚、可打开产物
             双击/多选校验点，只对选中的点操作

十一、错误处理
    脚本抛异常 → 界面显示中文原因 + 完整堆栈。
    raise RuntimeError("原因") 即可让用户看到业务错误。

十二、注意
    脚本在后台线程执行，产物默认落在「工作区/时间戳_脚本名/」下。
    重建包用本地调试证书签名；覆盖安装原版需先卸载（签名不同）。
"""

def main() -> None:
    app = App()
    try:
        app.mainloop()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
