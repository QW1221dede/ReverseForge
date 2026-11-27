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


def split_ext(name: str) -> tuple[str, str]:
    """把文件名拆成 (主体, 完整后缀)。.tar.gz / .7z.001 这类多段后缀整体算后缀。

    不用 Path(name).stem / .suffix —— 那只会认最后一段，
    重名编号时会把 foo.tar.gz 变成 foo.tar_2.gz。
    """
    n = Path(name).name
    for i, ch in enumerate(n):
        if ch == "." and i > 0:
            return n[:i], n[i:]
    return n, ""


def unique_path(directory: Path, name: str) -> Path:
    """同名不覆盖，自动加 _2 / _3。后缀必须跟传进来的完全一致，绝不替换。"""
    base, ext = split_ext(name)
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

    后缀跟成品本身走：成品是 .zip 就落 .zip，是 .elf 就落 .elf，
    绝不再一律改成 .apk（之前那版把非 APK 样本全变成假 APK，装不上也打不开）。
    name 只给「主体名」，不带后缀。
    """
    s = Path(src)
    if not s.exists():
        raise RuntimeError(f"成品不存在：{s}")
    desk = desktop_dir()
    stem = safe_name(Path(name).stem if name else split_ext(s.name)[0])
    _, ext = split_ext(s.name)          # 真实后缀，可能为空（无后缀文件）
    out = unique_path(desk, f"{stem}_{tag}{ext}")
    shutil.copy2(s, out)
    return out, f"✓ 已复制到桌面：{out.name}"
