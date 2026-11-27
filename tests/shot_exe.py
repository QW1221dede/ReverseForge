#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
exe 冒烟测试：启动打包后的 exe → 等窗口出现 → 前置 → 截图 → 关闭。
"""

from __future__ import annotations

import ctypes
import subprocess
import sys
import time
from pathlib import Path

from PIL import ImageGrab

EXE = Path(__file__).resolve().parent.parent / "dist" / "ReverseForge" / "ReverseForge.exe"
OUT = Path(__file__).resolve().parent.parent / "_test_out" / "exe_shot.png"
OUT.parent.mkdir(parents=True, exist_ok=True)

if not EXE.exists():
    print("找不到 exe:", EXE)
    raise SystemExit(1)

print("启动:", EXE)
proc = subprocess.Popen([str(EXE)])
time.sleep(10)

user32 = ctypes.windll.user32
hwnd = user32.FindWindowW(None, "ReverseForge · 逆锻台")
print("窗口句柄:", hwnd)

try:
    if hwnd:
        user32.ShowWindow(hwnd, 9)          # SW_RESTORE
        user32.SetForegroundWindow(hwnd)
        time.sleep(1.5)
        rect = ctypes.wintypes.RECT() if hasattr(ctypes, "wintypes") else None
        from ctypes import wintypes
        r = wintypes.RECT()
        user32.GetWindowRect(hwnd, ctypes.byref(r))
        box = (r.left, r.top, r.right, r.bottom)
        print("窗口区域:", box)
        img = ImageGrab.grab(bbox=box)
    else:
        img = ImageGrab.grab()
    img.save(OUT)
    print("saved", OUT, img.size)
except Exception as e:
    print("截图失败:", e)

time.sleep(0.5)
proc.terminate()
try:
    proc.wait(timeout=5)
except Exception:
    proc.kill()
print("已关闭")
