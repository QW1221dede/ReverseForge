#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
新标签页（代码终端）冒烟截图：
    积木页「送终端」→ 代码进编辑区 → F5 运行 → 看输出 → 截图
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


SAMPLE = '''# 这段就是"送到终端"进来的样子
from rf.analysis import segments

kind = rf.file_type(r"_test_out/decrypt/mixed.bin")
print(kind.brief())

sm = rf.segments(r"_test_out/decrypt/mixed.bin")
print(sm.table(6))
if sm.split.head_keys:
    print("头部密钥:", sm.split.head_keys)
'''


def step1() -> None:
    app.repl_send(SAMPLE, "分段演示", "demo.split")
    app.after(400, step2)


def step2() -> None:
    app._repl_run()
    app.after(4000, step3)


def step3() -> None:
    grab("tab_terminal.png")
    app.quit()


app.after(500, step1)
app.after(60_000, app.quit)
app.mainloop()
try:
    app._repl and app._repl.stop()
except Exception:                        # noqa: BLE001
    pass
