#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GUI 补丁页联动测试：扫描 → 全选 → 预演，确认按钮链路真的通。

    E:/Tools/Python312/python.exe tests/gui_patch_test.py
"""

from __future__ import annotations

import shutil
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from rf.ui.app import App      # noqa: E402

SRC = ROOT / "_test_out" / "sample_unpack"
WORK = ROOT / "_test_out" / "gui_patch_work"
if WORK.exists():
    shutil.rmtree(WORK)
shutil.copytree(SRC, WORK)

app = App()
app.lift()
result = {"ok": False, "msg": ""}


def fail(msg: str) -> None:
    result["msg"] = msg
    print("FAIL:", msg)
    app.destroy()


def step_scan() -> None:
    app.nb.select(4)
    app.patch_target.set(str(WORK))
    app._patch_scan()
    app.after(800, step_wait)


def step_wait(tries: int = 0) -> None:
    if app._patch_busy and tries < 40:
        app.after(200, lambda: step_wait(tries + 1))
        return
    if not app._patch_rep:
        fail("扫描没有返回结果")
        return
    rows = app.patch_tv.get_children()
    print("扫描到行数:", len(rows))
    if len(rows) < 2:
        fail("表格行数不足")
        return
    app.patch_tv.selection_set(rows)
    app._patch_run("dry")
    app.after(600, lambda: step_wait_dry(0))


def step_wait_dry(tries: int) -> None:
    if app._patch_busy and tries < 40:
        app.after(200, lambda: step_wait_dry(tries + 1))
        return
    text = app.patch_detail.get("1.0", "end")
    print("详情片段:", text.strip().splitlines()[:2])
    if "预演通过" in text or "应用 2 条" in text:
        result["ok"] = True
        print("PASS: GUI 预演链路正常")
    else:
        result["msg"] = "详情里没有预演结果"
        print("FAIL:", result["msg"])
    app.destroy()


app.after(2000, step_scan)
app.mainloop()
raise SystemExit(0 if result["ok"] else 1)
