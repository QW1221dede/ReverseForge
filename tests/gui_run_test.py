#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GUI 端到端测试：真的点一次「开始」，看它能不能跑完整个 APK 拆解流程。

不是模拟 —— 直接驱动 App 实例：选中脚本、填参数、调用 _run、
轮询事件循环，最后截图 + 检查产物。

    python tests/gui_run_test.py [apk路径]
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from rf.ui.app import App            # noqa: E402
from PIL import ImageGrab            # noqa: E402

APK = sys.argv[1] if len(sys.argv) > 1 else \
    r"D:\android_tools\tmp\dfroot\X-提权者-1.57-赞赏版.apk"
SHOT = ROOT / "_test_out" / "gui_run.png"
SHOT.parent.mkdir(parents=True, exist_ok=True)

app = App()
app.lift()
try:
    app.attributes("-topmost", True)
except Exception:
    pass

state = {"started": 0.0, "done": False}


def start_run() -> None:
    # 选第一个脚本（拆解 APK 全家桶）
    names = [s.name for s in app.scripts]
    print("脚本列表:", names)
    idx = next((i for i, s in enumerate(app.scripts) if "APK" in s.name), 0)
    app.lb.selection_clear(0, "end")
    app.lb.selection_set(idx)
    app._on_pick_script()
    print("选中:", app.current.name if app.current else None)

    # 填参数
    for k, (kind, var) in app.param_vars.items():
        if k == "apk":
            var.set(APK)
    print("参数:", app._collect_params())

    state["started"] = time.time()
    app._run()
    if app.run is None:
        print("✗ 脚本没有启动")
        app.destroy()


def watch() -> None:
    if app.run is None and state["started"]:
        # 跑完了
        state["done"] = True
        time.sleep(0.6)
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
            n = sum(1 for _ in d.rglob("*") if _.is_file())
            print(f"产物文件数: {n}")
            print("报告:", list(d.rglob('*.md')))
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
