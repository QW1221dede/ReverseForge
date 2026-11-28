#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rf.analysis.readable · 二进制产物的"人能读"旁路报告（2026-11-28）

【解决什么】
    解密/拆包落盘的是 .bin / .so / .elf —— 用户用记事本打开全是乱码，
    以为"解密失败了"。其实数据是对的，只是 Presentation 层缺失。

    本模块在产物落盘时**自动生成一份同名 .txt**，把二进制翻译成人话：
      · 文件真实类型（ELF/PE/ZIP/DEX/文本...）
      · ELF/PE 结构（位数/架构/节表/导入/风险导入）
      · 分类字符串（URL / 域名 / 文件路径 / 命令 / 中文业务提示 / 疑似密钥）
      · 明确告诉用户"这个能不能用记事本看、该用什么工具看"

【设计原则】
    * 只读产物，不改原文件；生成失败不影响主流程（不影响解密成功率）
    * 大文件只扫前 64MB（与 strings.scan_file 一致）
    * 每类字符串限量，避免报告爆炸
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

from . import strings as strmod
from . import native as natmod
from . import filetype as ftmod

# 每类最多列多少条
CAP = {"URL": 40, "域名": 40, "文件路径": 30, "命令": 20,
       "敏感关键字": 40, "Base64": 10, "AES/DES 密钥": 10, "中文": 60, "其他": 30}
KIND_ORDER = ["URL", "域名", "文件路径", "命令", "敏感关键字",
              "Base64", "AES/DES 密钥", "中文", "其他"]


def identify(data: bytes) -> str:
    """魔数识别真实类型（比文件名后缀可靠）。"""
    if data[:4] == b"\x7fELF":
        cls = {1: "32位", 2: "64位"}.get(data[4], "?")
        end = {1: "小端", 2: "大端"}.get(data[5], "?")
        # ELF e_type：2=DYN(共享库/PIE)，3=EXEC(可执行文件)，4=CORE
        et = {0: "REL", 1: "EXEC", 2: "DYN/PIE", 3: "EXEC", 4: "CORE"}.get(
            int.from_bytes(data[16:18], "little"), "?")
        mach = {183: "AArch64/ARM64", 62: "x86-64", 3: "x86", 40: "ARM"}.get(
            int.from_bytes(data[18:20], "little"), "?")
        return "ELF %s %s %s %s" % (cls, end, et, mach)
    if data[:2] == b"MZ":
        return "PE/COFF (Windows 可执行)"
    if data[:4] == b"dex\n":
        return "DEX (Android 字节码)"
    if data[:2] == b"PK":
        return "ZIP/JAR/APK"
    if data[:4] == b"\x1f\x8b\x08":
        return "gzip"
    if data[:6] == b"\xfd7zXZ\x00":
        return "xz"
    if data[:4] == b"UPX!":
        return "UPX 加壳"
    # 文本判定
    try:
        head = data[:4096].decode("utf-8")
        printable = sum(c.isprintable() or c in "\r\n\t" for c in head)
        if printable / max(1, len(head)) > 0.92:
            return "UTF-8 文本（记事本可直接看）"
    except UnicodeDecodeError:
        pass
    try:
        head = data[:4096].decode("gbk")
        printable = sum(c.isprintable() or c in "\r\n\t" for c in head)
        if printable / max(1, len(head)) > 0.92:
            return "GBK 文本（记事本可直接看）"
    except UnicodeDecodeError:
        pass
    return "二进制（记事本会乱码，需专用工具）"


def how_to_view(kind: str, path: Path) -> str:
    """告诉用户该用什么工具看——这是小白最缺的一环。"""
    if "文本" in kind:
        return "直接双击用记事本打开即可。"
    if kind.startswith("ELF"):
        return ("这是 Android/Linux 的原生库或程序，记事本看不懂。"
                "用 Ghidra / rizin 反编译，或在工具箱里跑「ELF 分析」。"
                "下面已把能读的字符串和符号整理出来。")
    if "PE" in kind:
        return "这是 Windows 程序，用 Ghidra / IDA 打开。下面已整理字符串与导入表。"
    if "DEX" in kind:
        return "这是 Android 字节码，用 jadx 反编译成 Java。工具箱里有「APK 反编译」。"
    if "ZIP" in kind or "APK" in kind:
        return "这是压缩包，改后缀为 .zip 用 7-Zip 打开，或工具箱里跑「APK 拆包」。"
    if "UPX" in kind:
        return "这是 UPX 加壳文件，先工具箱里跑「UPX 脱壳」再分析。"
    return "这是二进制数据，记事本会乱码。下面已尽力提取可读片段；进一步分析请按文件真实类型选工具。"


def render(path: Path) -> Path:
    """为单个产物生成 .可读报告.txt；返回报告路径。失败返回原路径。"""
    try:
        data = path.read_bytes()
        if not data:
            return path
        if len(data) > 64 << 20:
            data = data[:64 << 20]
        kind = identify(data)
        r = strmod.scan_file(path, min_len=5, with_cjk=True)

        L = [
            "=" * 74,
            "可读报告 · " + path.name,
            "=" * 74,
            "工具箱自动生成 —— 这个文件用记事本打开是乱码，看这份就行。",
            "",
            "【文件】",
            "  路径：" + str(path),
            "  大小：%d 字节" % path.stat().st_size,
            "  SHA256：" + hashlib.sha256(data).hexdigest(),
            "  真实类型：" + kind,
            "",
            "【怎么看】",
            "  " + how_to_view(kind, path),
            "",
        ]

        # ELF / PE 结构
        try:
            if kind.startswith("ELF") or kind.startswith("PE"):
                info = natmod.parse(path)
                if info:
                    L += ["【结构】", "  " + info.brief()]
                    risky = natmod.risky_imports(info)
                    if risky:
                        L.append("【风险导入】")
                        for imp, why in risky[:15]:
                            L.append("  ⚠ %-18s %s" % (imp, why))
                    L.append("")
        except Exception as e:
            L += ["【结构解析失败】%r" % (e,), ""]

        # 分类字符串
        L.append("【可读内容】共 %d 条：%s" % (r.total, r.summary()))
        L.append("")
        for kind_name in KIND_ORDER:
            items = r.by_kind.get(kind_name) or []
            if not items:
                continue
            cap = CAP.get(kind_name, 30)
            L.append("── [%s] %d 条 ──" % (kind_name, len(items)))
            for s in items[:cap]:
                L.append("  " + s[:200])
            if len(items) > cap:
                L.append("  … 另有 %d 条，见工具箱内完整扫描" % (len(items) - cap))
            L.append("")

        out = path.with_name(path.stem + ".可读报告.txt")
        out.write_text("\n".join(L), encoding="utf-8")
        return out
    except Exception:
        return path


def render_tree(root: Path, exts=(".bin", ".so", ".elf", ".dat", ".o", ".a"),
                limit: int = 200) -> list[Path]:
    """给目录树里所有二进制产物批量生成可读报告。"""
    root = Path(root)
    outs = []
    if not root.is_dir():
        return outs
    n = 0
    for p in root.rglob("*"):
        if n >= limit:
            break
        if not p.is_file() or p.suffix.lower() not in exts:
            continue
        if ".可读报告" in p.name:
            continue
        r = render(p)
        if r != p:
            outs.append(r)
            n += 1
    return outs
