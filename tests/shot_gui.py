#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GUI 冒烟测试：启动窗口 → 等工具探测完 → 截图 → 退出。

    python tests/shot_gui.py [输出png]
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from rf.ui.app import App            # noqa: E402
from PIL import ImageGrab            # noqa: E402

out = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "_test_out" / "gui_shot.png"
out.parent.mkdir(parents=True, exist_ok=True)

app = App()
app.lift()
try:
    app.attributes("-topmost", True)
except Exception:
    pass


def shot() -> None:
    try:
        app.update_idletasks()
        app.update()
        x, y = app.winfo_rootx(), app.winfo_rooty()
        w, h = app.winfo_width(), app.winfo_height()
        img = ImageGrab.grab(bbox=(x, y, x + w, y + h))
        img.save(out)
        print(f"saved {out}  {img.size}")
    except Exception as e:
        print("截图失败:", e)
    finally:
        app.destroy()


app.after(5000, shot)
app.mainloop()
print("GUI 启动/退出正常")
