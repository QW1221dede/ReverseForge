#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
新标签页冒烟测试：
    积木页 → 选一块 → 截图
    补丁页 → 扫样本 → 截图
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from PIL import ImageGrab                 # noqa: E402

from rf.ui.app import App                 # noqa: E402

OUT = ROOT / "_test_out"
OUT.mkdir(exist_ok=True)
app = App()
app.lift()
try:
    app.attributes("-topmost", True)
except Exception:
    pass


def grab(name: str) -> None:
    app.update_idletasks()
    app.update()
    x, y = app.winfo_rootx(), app.winfo_rooty()
    w, h = app.winfo_width(), app.winfo_height()
    img = ImageGrab.grab(bbox=(x, y, x + w, y + h))
    p = OUT / name
    img.save(p)
    print("saved", p, img.size)


def step1() -> None:
    app.nb.select(3)
    # 选中第一块积木，展示右侧详情
    for iid in app.snip_tree.get_children():
        kids = app.snip_tree.get_children(iid)
        if kids:
            app.snip_tree.selection_set(kids[0])
            app.snip_tree.see(kids[0])
            break
    app.after(600, lambda: (grab("tab_snippets.png"), step2()))


def step2() -> None:
    app.nb.select(4)
    app.patch_target.set(str(ROOT / "_test_out" / "sample_unpack"))
    app._patch_scan()
    app.after(2500, lambda: (grab("tab_patch.png"), done()))


def done() -> None:
    app.destroy()


app.after(2200, step1)
app.mainloop()
print("OK")
