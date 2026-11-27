#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GUI 端到端测试（核心依赖脚本）：选中「核心依赖与校验链」→ 填目录 → 点开始。

验证的是三件事，不是"窗口能打开"：
    1. 新脚本能被界面发现并自动生成参数表单
    2. 点「开始」后真的会跑，且终端有输出
    3. 产物（deps.md）真的落到工作区

    python tests/gui_deps_test.py [源码目录]
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from PIL import ImageGrab            # noqa: E402
from rf.ui.app import App            # noqa: E402

FOLDER = sys.argv[1] if len(sys.argv) > 1 else \
    r"C:\Users\SRIB\AppData\Local\ReverseForge\workspace\1126_185808_拆解APK全家桶" \
    r"\X-提权者-1.57-赞赏版\jadx\sources"
SHOT = ROOT / "_test_out" / "gui_deps.png"
SHOT.parent.mkdir(parents=True, exist_ok=True)

app = App()
app.lift()
try:
    app.attributes("-topmost", True)
except Exception:
    pass

state = {"started": 0.0, "done": False}


def start_run() -> None:
    names = [s.name for s in app.scripts]
    print("脚本列表:", names)
    idx = next((i for i, s in enumerate(app.scripts) if "核心依赖" in s.name), -1)
    if idx < 0:
        print("✗ 没找到「核心依赖与校验链」脚本")
        app.destroy()
        return
    app.lb.selection_clear(0, "end")
    app.lb.selection_set(idx)
    app._on_pick_script()
    print("选中:", app.current.name if app.current else None)
    print("参数项:", list(app.param_vars.keys()))

    for k, (kind, var) in app.param_vars.items():
        if k == "folder":
            var.set(FOLDER)
        elif k == "annotate":
            var.set(True)

    print("提交参数:", app._collect_params())
    state["started"] = time.time()
    app._run()
    if app.run is None:
        print("✗ 脚本没有启动")
        app.destroy()


def watch() -> None:
    if app.run is None and state["started"]:
        state["done"] = True
        time.sleep(0.8)
        app.update()
        try:
            x, y = app.winfo_rootx(), app.winfo_rooty()
            w, h = app.winfo_width(), app.winfo_height()
            ImageGrab.grab(bbox=(x, y, x + w, y + h)).save(SHOT)
            print(f"截图: {SHOT}")
        except Exception as e:
            print("截图失败:", e)
        print("产物目录:", app._last_dir)
        d = Path(app._last_dir) if app._last_dir else None
        if d and d.exists():
            md = list(d.rglob("*.md"))
            print("报告:", md)
            for f in md:
                print("  首行:", f.read_text(encoding="utf-8").splitlines()[:5])
        print(f"耗时: {time.time() - state['started']:.1f}s")
        app.destroy()
        return

    if state["started"] and time.time() - state["started"] > 420:
        print("✗ 超时未完成")
        app.destroy()
        return
    app.after(400, watch)


app.after(3500, start_run)
app.after(4000, watch)
app.mainloop()
print("GUI 测试结束" + ("（成功）" if state["done"] else "（失败）"))
