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
            txt = p.read_text(encoding="utf-8", errors="ignore").strip()
            # 空字符串会让 Path("") 变成 "."，is_dir() 为真 → 成品落到当前目录
            if txt and Path(txt).is_absolute():
                d = Path(txt)
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


_MULTI_SUFFIX = (".tar.gz", ".tar.bz2", ".tar.xz", ".tar.zst", ".tar.lz4",
                 ".tar.lzma")


def split_ext(name: str) -> tuple[str, str]:
    """把文件名拆成 (主体, 完整后缀)。

    规则：默认只认**最后一段**后缀（`ACE拦截2.0.apk` 的主体是 `ACE拦截2.0`，
    不能按第一个点切，否则会变成 `ACE拦截2`）；`.tar.gz` 这类复合后缀整体算后缀。
    """
    n = Path(name).name
    low = n.lower()
    for suf in _MULTI_SUFFIX:
        if low.endswith(suf) and len(n) > len(suf):
            return n[:-len(suf)], n[-len(suf):]
    i = n.rfind(".")
    if i <= 0:                       # 没有后缀，或 .bashrc 这种点开头的
        return n, ""
    return n[:i], n[i:]


_REPEAT_TAG = re.compile(
    r"[_\-\s]*(?:已绕过|已处理|已解密|已重打包|已修复|已破解)(?:[_\-\s]*\d+)?$"
)


def strip_tags(stem: str) -> str:
    """去掉本工具上次留下的后缀，避免 `XX_已绕过_已绕过` 这种叠罗汉。"""
    prev = ""
    while prev != stem:
        prev = stem
        stem = _REPEAT_TAG.sub("", stem).rstrip("_- ")
    return stem or prev


def base_stem(name: str) -> str:
    """成品命名用的主体名：`ACE拦截2.0.apk.1` → `ACE拦截2.0`。

    下载器常在 .apk 后面加 `.1`；不处理的话产物会叫
    `ACE拦截2.0.apk_已绕过.apk`，看着像坏文件。
    已经被处理过的名字（`_已绕过` / `_已处理` / `_已绕过_6`）先剥掉再拼，
    否则连跑两次就变成 `ACE拦截2.0_已绕过_6_已绕过.apk`。
    """
    n = Path(name).name
    m = re.match(r"(?i)^(.*)\.(apk|aab|apks|xapk)(\.\d+)?$", n)
    if m and m.group(1):
        return strip_tags(m.group(1))
    return strip_tags(split_ext(n)[0])


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
    # name 传进来时**已经是主体名**（可能自带点，如 ACE拦截2.0），
    # 不能再走 Path(name).stem —— 那会把 .0 当后缀吃掉。
    stem = safe_name(name) if name else safe_name(split_ext(s.name)[0])
    stem = strip_tags(stem) or stem
    _, ext = split_ext(s.name)          # 真实后缀，可能为空（无后缀文件）
    out = unique_path(desk, f"{stem}_{tag}{ext}")
    shutil.copy2(s, out)
    return out, f"✓ 已复制到桌面：{out.name}"
