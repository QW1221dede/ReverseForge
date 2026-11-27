#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 rf.tools.shortcut · 桌面快捷方式
============================================================================

    用 Windows 自带的 WScript.Shell COM 建 .lnk，不加任何依赖。

    踩过的坑：中文名字通过 subprocess 命令行参数传给 PowerShell 会被
    控制台编码搞成乱码（"逆锻台" → ???）。所以参数**不命令行传**，
    而是直接写进 UTF-8-with-BOM 的 .ps1 里（PS 5.1 靠 BOM 认 UTF-8）。
============================================================================
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

PS_TEMPLATE = r'''
$ErrorActionPreference = "Stop"
$Exe     = '__EXE__'
$Name    = '__NAME__'
$WorkDir = '__WORKDIR__'
$desktop = [Environment]::GetFolderPath("Desktop")
$link = Join-Path $desktop ($Name + ".lnk")
$ws = New-Object -ComObject WScript.Shell
$sc = $ws.CreateShortcut($link)
$sc.TargetPath = $Exe
$sc.WorkingDirectory = $WorkDir
$sc.Description = "ReverseForge 逆锻台"
$sc.IconLocation = "$Exe,0"
$sc.Save()
[System.IO.File]::WriteAllText('__OUTFILE__', $link, (New-Object System.Text.UTF8Encoding $false))
'''


def _ps_str(s: str) -> str:
    """塞进 PowerShell 单引号字符串：内部单引号要写两遍。"""
    return str(s).replace("'", "''")


def find_exe() -> Path:
    if getattr(sys, "frozen", False):
        p = Path(sys.executable)
        if p.name.lower() != "python.exe":
            return p
    base = Path(__file__).resolve().parent.parent.parent
    for p in (base / "ReverseForge.exe",
              base / "dist" / "ReverseForge" / "ReverseForge.exe"):
        if p.exists():
            return p
    raise RuntimeError("找不到 ReverseForge.exe（程序目录和 dist 下都没有）")


def create_desktop_shortcut(name: str = "ReverseForge 逆锻台") -> Path:
    exe = find_exe()
    workdir = str(exe.parent)

    fd, ps_path = tempfile.mkstemp(prefix="rf_shortcut_", suffix=".ps1")
    os.close(fd)
    fd, out_path = tempfile.mkstemp(prefix="rf_shortcut_out_", suffix=".txt")
    os.close(fd)

    script = (PS_TEMPLATE
              .replace("__EXE__", _ps_str(exe))
              .replace("__NAME__", _ps_str(name))
              .replace("__WORKDIR__", _ps_str(workdir))
              .replace("__OUTFILE__", _ps_str(out_path)))
    p = Path(ps_path)
    p.write_text(script, encoding="utf-8-sig")
    try:
        flags = 0x08000000 if os.name == "nt" else 0
        r = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
             "-File", str(p)],
            capture_output=True, timeout=30, creationflags=flags)
        err = r.stderr.decode("utf-8", "replace").strip()
        if r.returncode != 0:
            raise RuntimeError(f"创建失败：{err or '未知错误'}")
        link = Path(Path(out_path).read_text(encoding="utf-8").strip())
        if not link.exists():
            raise RuntimeError(f"快捷方式未生成：{link}")
        return link
    finally:
        for f in (p, Path(out_path)):
            try:
                f.unlink()
            except OSError:
                pass


if __name__ == "__main__":
    print(create_desktop_shortcut())
