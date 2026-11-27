#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""打包版冒烟：分别打开「积木」「补丁」页并截图。"""

from __future__ import annotations

import ctypes
import os
import subprocess
import time
from pathlib import Path

from PIL import ImageGrab

ROOT = Path(__file__).resolve().parent.parent
EXE = ROOT / "dist" / "ReverseForge" / "ReverseForge.exe"
OUT = ROOT / "_test_out"
OUT.mkdir(exist_ok=True)
SAMPLE = ROOT / "_test_out" / "sample_unpack"


def grab(name: str) -> None:
    user32 = ctypes.windll.user32
    hwnd = user32.FindWindowW(None, "ReverseForge · 逆锻台")
    if not hwnd:
        print("没找到窗口")
        ImageGrab.grab().save(OUT / name)
        return
    user32.ShowWindow(hwnd, 9)
    user32.SetForegroundWindow(hwnd)
    time.sleep(1.2)
    from ctypes import wintypes
    r = wintypes.RECT()
    user32.GetWindowRect(hwnd, ctypes.byref(r))
    img = ImageGrab.grab(bbox=(r.left, r.top, r.right, r.bottom))
    img.save(OUT / name)
    print("saved", OUT / name, img.size)


def run(env: dict, name: str, wait: float = 9.0) -> None:
    e = dict(os.environ)
    e.update(env)
    p = subprocess.Popen([str(EXE)], env=e)
    time.sleep(wait)
    grab(name)
    p.terminate()
    try:
        p.wait(timeout=5)
    except Exception:
        p.kill()
    time.sleep(0.6)


if not EXE.exists():
    raise SystemExit("先 build.py")

run({"RF_START_TAB": "3"}, "exe_tab_snippets.png")
run({"RF_START_TAB": "4", "RF_PATCH_DIR": str(SAMPLE)}, "exe_tab_patch.png", 11)
print("done")
