#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 rf.tools.desktop · 把成品丢到桌面
============================================================================

    一键脚本改完 APK 后调用：自动复制到桌面、起一个能看懂的名字，
    并避免覆盖用户已有文件（同名就加 _2 / _3）。

    Windows 桌面路径用 [Environment]::GetFolderPath("Desktop")，
    不走 ~/Desktop —— OneDrive 重定向、企业策略改过桌面位置时才不会跑偏。
============================================================================
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

PS_DESKTOP = r'''
$ErrorActionPreference = "Stop"
$desktop = [Environment]::GetFolderPath("Desktop")
[System.IO.File]::WriteAllText('__OUT__', $desktop, (New-Object System.Text.UTF8Encoding $false))
'''


def desktop_dir() -> Path:
    """取真实桌面路径（含 OneDrive 重定向）。"""
    try:
        fd, outp = tempfile.mkstemp(prefix="rf_desk_", suffix=".txt")
        os.close(fd)
        p = Path(outp)
        script = PS_DESKTOP.replace("__OUT__", str(p).replace("'", "''"))
        fd2, spath = tempfile.mkstemp(prefix="rf_desk_", suffix=".ps1")
        os.close(fd2)
        sp = Path(spath)
        sp.write_text(script, encoding="utf-8-sig")
        try:
            flags = 0x08000000 if os.name == "nt" else 0
            subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy",
                            "Bypass", "-File", str(sp)],
                           capture_output=True, timeout=20, creationflags=flags)
            d = Path(p.read_text(encoding="utf-8").strip())
            if d.is_dir():
                return d
        finally:
            for f in (p, sp):
                try:
                    f.unlink()
                except OSError:
                    pass
    except Exception:                                # noqa: BLE001
        pass
    return Path.home() / "Desktop"


def safe_name(name: str) -> str:
    """Windows 文件名不能带的字符全替换掉。"""
    return re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name).strip(" .")[:80] or "output"


def unique_path(directory: Path, name: str) -> Path:
    """同名不覆盖，自动加 _2 / _3。"""
    base = Path(name).stem
    ext = Path(name).suffix or ".apk"
    p = directory / name
    i = 2
    while p.exists():
        p = directory / f"{base}_{i}{ext}"
        i += 1
    return p


def drop_to_desktop(src: str | Path, name: str = "",
                    *, tag: str = "已绕过") -> tuple[Path, str]:
    """
    复制成品到桌面。返回 (桌面路径, 说明)。
    用 copy 而不是 move —— 产物目录里那份要留着做报告/回滚。
    """
    s = Path(src)
    if not s.exists():
        raise RuntimeError(f"成品不存在：{s}")
    desk = desktop_dir()
    stem = safe_name(Path(name).stem if name else s.stem)
    out = unique_path(desk, f"{stem}_{tag}.apk")
    shutil.copy2(s, out)
    return out, f"✓ 已复制到桌面：{out.name}"
