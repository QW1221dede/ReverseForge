#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UI 裁切探测：找出所有「超出所在页面可见范围」的控件。

判据（对比页面实际可见矩形，而不是请求尺寸）：
    控件 bottom > 页面 bottom + 1  → 底部被切
    控件 right  > 页面 right  + 1  → 右边被切
    控件高度 <= 1 且本应有高度     → 被压成 0

用法：python tests/check_clip.py [宽x高]
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from rf.ui.app import App  # noqa: E402

SKIP_CLASSES = {"Menu", "Toplevel"}


def walk(w, out):
    out.append(w)
    for c in w.winfo_children():
        walk(c, out)


def main() -> None:
    size = sys.argv[1] if len(sys.argv) > 1 else "1160x700"
    wpx, hpx = (int(x) for x in size.lower().split("x"))
    app = App()
    app.geometry(f"{wpx}x{hpx}+40+20")
    app.update_idletasks()
    app.update()

    nb = app.nb
    total = 0
    for i in range(nb.index("end")):
        app.nb.select(i)
        for _ in range(4):
            app.update_idletasks()
            app.update()
        page = app.nametowidget(nb.tabs()[i])
        name = nb.tab(i, "text").strip()
        px, py = page.winfo_rootx(), page.winfo_rooty()
        pr, pb = px + page.winfo_width(), py + page.winfo_height()

        widgets = []
        walk(page, widgets)
        bad = []
        for w in widgets:
            if w is page or w.winfo_class() in SKIP_CLASSES:
                continue
            if not w.winfo_ismapped():
                continue
            cls = w.winfo_class()
            if cls in ("TScrollbar", "Scrollbar"):
                # 滚动条被压成 1px 同样是缺陷：看得见但拖不动
                if w.winfo_ismapped() and (w.winfo_width() <= 2 and w.winfo_height() <= 2):
                    bad.append(f"  滚动条被压扁 {txt}")
                continue
            x, y = w.winfo_rootx(), w.winfo_rooty()
            r, b = x + w.winfo_width(), y + w.winfo_height()
            txt = ""
            try:
                txt = str(w.cget("text"))[:14]
            except Exception:                            # noqa: BLE001
                txt = ""
            if b > pb + 1:
                bad.append(f"  底部被切 {cls:10s} {txt:16s} bottom={b - pb:+d}px")
            elif r > pr + 1:
                bad.append(f"  右边被切 {cls:10s} {txt:16s} right={r - pr:+d}px")
        if bad:
            total += len(bad)
            print(f"[{i}] {name}  页面 {page.winfo_width()}x{page.winfo_height()}")
            print("\n".join(bad))
        else:
            print(f"[{i}] {name}  OK")
    print("\n合计被裁控件:", total)
    app.destroy()


if __name__ == "__main__":
    main()
