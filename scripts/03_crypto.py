#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
# @name 加密文件识别与解密
# @desc 魔数识别 → 熵判定 → ZIP 弱口令 → 单字节 XOR 爆破 → 硬编码密钥扫描
# @param target 目标文件 [file]
# @param unzip 尝试 ZIP 弱口令 [bool:true]
# @param xor 尝试单字节 XOR [bool:true]
# @out 产物目录：解密结果与报告
"""

# 处理"打不开的文件"的标准流程：
#   第一步不是解密，是判类型 —— 很多时候它根本不是加密，只是扩展名骗人。
#   真的加密也要分清"容器加密（可试口令）"和"整文件加密（基本无解）"。

import os
import time
from pathlib import Path

p = Path(target)
if not p.is_file():
    raise RuntimeError(f"文件不存在：{p}")

rf.note("阶段 1/4 · 文件类型识别", f"{p.name}  {p.stat().st_size:,} 字节")
info = rf.identify(p)

rf.log(f"  判定：{info.label}")
rf.log(f"  熵值：{info.entropy}  （>7.5 通常意味着加密或已压缩）")
if info.zip_entries:
    rf.log(f"  ZIP 条目：{info.zip_entries} 个，其中加密 {info.zip_encrypted_entries} 个")
for n in info.notes:
    rf.log("  " + n)

if info.entropy >= 7.9 and info.kind in ("encrypted", "compressed"):
    rf.log("")
    rf.log("  ⚠ 熵接近 8.0：这是整文件加密的典型特征。")
    rf.log("    无密钥时无法解密，正确路径是从代码里找密钥/解密函数，或动态 hook。")

# ── ZIP 弱口令 ────────────────────────────────────────────────
if unzip and info.zip_entries:
    rf.note("阶段 2/4 · ZIP 弱口令尝试")
    if not info.zip_encrypted_entries:
        rf.log("  该 ZIP 未加密，直接解包即可")
    else:
        def on_try(pw, i, n):
            if i % 10 == 0:
                rf.step(f"试口令 {i}/{n}", 30 + int(i / n * 40))

        r = rf.zip_password(p)
        if r.ok:
            rf.log(f"  ✓ 命中口令：「{r.password}」")
            rf.log(f"  已解到：{r.out_path}")
        else:
            rf.log("  ✗ 常见口令未命中。下一步：用字典（rockyou）或已知明文攻击")

# ── 单字节 XOR ────────────────────────────────────────────────
if xor:
    rf.note("阶段 3/4 · 单字节 XOR 爆破")
    r = rf.xor(p)
    if r.ok:
        rf.log(f"  ✓ {r.method}")
        rf.log(f"  输出：{r.out_path}")
    else:
        rf.log(f"  ✗ {r.note}")

# ── 硬编码密钥 ────────────────────────────────────────────────
rf.note("阶段 4/4 · 顺带找密钥线索")
hits = rf.keys(p, limit=20) if p.suffix.lower() not in (".so", ".dex") else []
if hits:
    for label, frag in hits[:10]:
        rf.log(f"  · {label}: {frag[:70]}")
else:
    rf.log("  未在文件内发现明显的密钥/口令字符串")

rf.report(f"加密分析 · {p.name}", {
    "文件": {
        "路径": str(p),
        "大小": f"{p.stat().st_size:,} 字节",
        "判定类型": info.label,
        "熵": info.entropy,
        "是否加密": "是" if info.encrypted else "否/未知",
    },
    "说明": info.notes or ["无"],
    "后续建议": [
        "若是 APK/JAR/ZIP：用「拆解 APK」脚本继续",
        "若是整文件加密：在代码里搜 Cipher/AES/decrypt，或动态 hook 解密函数拿明文",
        "若是高熵 but 无容器头：考虑是压缩流，试试 7z / binwalk 切分",
    ],
}, "crypto_report.md")
