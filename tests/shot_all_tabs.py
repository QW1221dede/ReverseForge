#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
逐页截图：核对每个页签在「窗口不大」时是否被裁切、滚动条是否多余。

用法：python tests/shot_all_tabs.py [宽x高]
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

size = sys.argv[1] if len(sys.argv) > 1 else "1160x700"
w, h = (int(x) for x in size.lower().split("x"))

app = App()
app.geometry(f"{w}x{h}+60+30")
app.lift()
try:
    app.attributes("-topmost", True)
except Exception:
    pass

n = app.nb.index("end")
print("页签数:", n)


def grab(i: int) -> None:
    app.update_idletasks()
    app.update()
    x, y = app.winfo_rootx(), app.winfo_rooty()
    img = ImageGrab.grab(bbox=(x, y, x + app.winfo_width(), y + app.winfo_height()))
    tab = app.nb.tab(i, "text").strip()
    p = OUT / f"tabs_{i}_{tab}.png"
    img.save(p)
    print(f"{i} {tab:6s} {img.size} -> {p.name}")


def run(i: int = 0) -> None:
    if i >= n:
        app.destroy()
        return
    app.nb.select(i)
    app.after(700, lambda: (grab(i), run(i + 1)))


app.after(1800, run)
app.mainloop()
print("OK")
