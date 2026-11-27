#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 tests/gui_blocks_test.py · 代码块工作台自测
============================================================================

    [1] 首次启动不弹模态框（投放区能继续用）
    [2] 任意代码块保存 → 出现在积木树
    [3] 显式顺序拼装 → 代码顺序真的变了
    [4] args 兜底 → 拼完的代码不依赖运行环境，直接 exec 能跑
    [5] GUI 拼装工作台能打开、预览出完整代码、语法通过
============================================================================
"""

from __future__ import annotations

import sys
import time
import tkinter as tk
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rf.snippets import get_library
from rf.ui.app import App

FAILED: list[str] = []


def check(name: str, cond: bool, extra: str = "") -> None:
    print(("  ✓ " if cond else "  ✗ ") + name + (f"  [{extra}]" if extra else ""))
    if not cond:
        FAILED.append(name)


# ---------------------------------------------------------------------------
# 1-4：库层
# ---------------------------------------------------------------------------
print("[1] 首次启动不弹窗")
app = App()
app.update()
for _ in range(30):
    app.update()
    time.sleep(0.03)
modals = [w for w in app.winfo_children()
          if str(w).startswith(".!toplevel")]
check("没有模态子窗口", not modals, str(modals[:2]))
app.drop.add_paths(["_test_out/decrypt/mixed.bin"])
app.update()
check("投放区仍可用", app.drop.lbl_count.cget("text") == "1 个")

print("[2] 任意代码块可保存")
lib = get_library(True)
p1 = lib.save_user("selftest.block.one", "自测块一", "a = 1\nprint('ONE', a)",
                   category="工程", purpose="自测一")
p2 = lib.save_user("selftest.block.two", "自测块二", "b = 2\nprint('TWO', b)",
                   category="工程", purpose="自测二")
check("两块都落盘", p1.exists() and p2.exists())

print("[3] 显式顺序")
code_ab = lib.compose(["selftest.block.one", "selftest.block.two"],
                      order=["selftest.block.one", "selftest.block.two"],
                      args={})
code_ba = lib.compose(["selftest.block.one", "selftest.block.two"],
                      order=["selftest.block.two", "selftest.block.one"],
                      args={})
check("ONE 在 TWO 前", code_ab.index("ONE") < code_ab.index("TWO"))
check("顺序可对调", code_ba.index("TWO") < code_ba.index("ONE"))

print("[4] args 兜底 + 直接执行")
code = lib.compose(["selftest.block.one", "selftest.block.two"],
                   args={"path": "D:/x.bin"})
check("生成 args 兜底", "except NameError:" in code and "args = " in code)
ns: dict = {}
try:
    exec(compile(code, "<composed>", "exec"), ns)
    ran = ns.get("a") == 1 and ns.get("b") == 2
except Exception as e:                               # noqa: BLE001
    ran = False
    print("    执行失败:", e)
check("不依赖运行环境也能跑", ran)

# ---------------------------------------------------------------------------
# 5：GUI 工作台
# ---------------------------------------------------------------------------
print("[5] GUI 拼装工作台")
app._snip_reload()
app.update()
app.nb.select(3)
# 在树上真正选中这两块，工作台才拿得到它们
sel = []
for iid, sid in app._snip_map.items():
    if sid in ("selftest.block.one", "selftest.block.two"):
        sel.append(iid)
check("树上找到自测块", len(sel) == 2, str(len(sel)))
app.snip_tree.selection_set(sel)
app._snip_compose()
app.update()
wins = [w for w in app.winfo_children() if str(w).startswith(".!toplevel")]
check("工作台窗口打开", bool(wins), str(len(wins)))
if wins:
    w = wins[-1]
    # 找代码预览 Text：工作台里唯一带完整代码的 Text
    texts = [c for c in w.winfo_children() if isinstance(c, tk.Frame)]
    found = ""
    for fr in texts:
        for c in fr.winfo_children():
            if isinstance(c, tk.Text):
                s = c.get("1.0", "end")
                if "selftest.block.one" in s:
                    found = s
    # PanedWindow 里的 Text 是孙级，再挖一层
    if not found:
        def dig(widget, depth=0):
            global found
            if depth > 4 or found:
                return
            if isinstance(widget, tk.Text):
                s = widget.get("1.0", "end")
                if "selftest.block.one" in s and "拼装脚本" in s:
                    found = s
                    return
            for c in widget.winfo_children():
                dig(c, depth + 1)
        dig(w)
    check("预览里有完整代码", bool(found), f"{len(found.splitlines())} 行")
    check("预览含两块", "selftest.block.two" in found)
    w.destroy()

# ---------------------------------------------------------------------------
# 清理
# ---------------------------------------------------------------------------
for p in (p1, p2):
    if p.exists():
        p.unlink()
try:
    app._repl and app._repl.stop()
except Exception:                                    # noqa: BLE001
    pass
app.destroy()

if FAILED:
    print(f"\n失败 {len(FAILED)} 项：")
    for f in FAILED:
        print("  ✗", f)
    sys.exit(1)
print("\n全部通过")
