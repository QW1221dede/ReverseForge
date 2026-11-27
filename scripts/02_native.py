#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
# @name 分析原生库（so / dll）
# @desc 结构解析 → 加壳判定 → 危险导入 → 字符串分类 → 函数清单
# @param folder 原生库所在目录（lib/arm64-v8a 之类）[dir]
# @param strings 提取字符串 [bool:true]
# @param funcs 列出函数符号 [bool:false]
# @out 产物目录：native/report.md 与逐文件明细
"""

# so 是加固与核心逻辑最常藏身的地方。这个脚本把一批 so 过一遍，
# 先看"有没有壳"、"调了哪些危险系统调用"，再决定值不值得上 Ghidra。

import os
from pathlib import Path

from rf.analysis import native as nativemod

root = Path(folder)
if not root.is_dir():
    raise RuntimeError(f"目录不存在：{root}")

libs = sorted(list(root.rglob("*.so")) + list(root.rglob("*.dll")))
if not libs:
    raise RuntimeError(f"该目录下没有 .so / .dll：{root}")

rf.note("阶段 1/3 · 结构解析与加壳判定", f"共 {len(libs)} 个原生库")

rows = []
risk_all = []
for i, lib in enumerate(libs, 1):
    rf.step(f"解析 {lib.name}", int(i / len(libs) * 55))
    try:
        info = rf.native(lib)
    except Exception as e:
        rf.log(f"  ! 跳过 {lib.name}：{e}")
        continue

    is_elf = type(info).__name__ == "ElfInfo"
    size_kb = lib.stat().st_size // 1024

    row = {
        "文件": lib.name,
        "架构": info.machine,
        "大小": f"{size_kb} KB",
        "节数": len(info.sections),
        "导入": len(info.imports),
        "加壳": "疑似" if info.packed else "否",
    }
    if info.packed:
        detail = []
        if info.shell_hits:
            detail.append("壳节名 " + ",".join(info.shell_hits[:3]))
        if info.high_entropy_sections:
            detail.append("高熵节 " + ",".join(info.high_entropy_sections[:3]))
        rf.log(f"  ⚠ {lib.name} 疑似加壳：{'；'.join(detail)}")

    risky = [f"{imp}（{why}）" for imp, why in nativemod.risky_imports(info)]
    if risky:
        row["危险导入"] = len(risky)
        risk_all.append(f"{lib.name}：" + "、".join(risky[:6]))
        for r in risky[:5]:
            rf.log(f"     ⚠ {r}")

    rows.append(row)

# 字符串
if strings:
    rf.note("阶段 2/3 · 字符串提取")
    for i, lib in enumerate(libs, 1):
        rf.step(f"字符串 {lib.name}", 55 + int(i / len(libs) * 25))
        try:
            s = rf.strings(lib)
            urls = s.by_kind.get("URL", [])
            cmds = s.by_kind.get("命令", [])
            if urls:
                rf.log(f"  {lib.name} 接口地址 {len(urls)} 个，示例：{urls[0][:80]}")
            if cmds:
                rf.log(f"  ⚠ {lib.name} 出现命令类字符串：{cmds[0][:60]}")
        except Exception as e:
            rf.log(f"  ! {lib.name} 字符串提取失败：{e}")

# 函数符号
func_table = {}
if funcs:
    rf.note("阶段 3/3 · 函数符号")
    for lib in libs[:8]:
        try:
            fs = rf.functions(lib, limit=80)
            func_table[lib.name] = fs[:40]
            rf.log(f"  {lib.name}: {len(fs)} 个函数")
        except Exception as e:
            rf.log(f"  ! {lib.name} 函数列表失败：{e}")

# 报告
rf.note("生成报告")
sections = {
    "总览": {
        "扫描目录": str(root),
        "原生库数量": len(libs),
        "疑似加壳": sum(1 for r in rows if r.get("加壳") == "疑似"),
    },
    "逐文件": rows,
}
if risk_all:
    sections["危险系统调用"] = risk_all
if func_table:
    sections["函数符号（前 40）"] = [f"{k}: " + ", ".join(v) for k, v in func_table.items()]

rf.report(f"原生库分析 · {root.name}", sections, "native_report.md")
rf.log("")
rf.log("提示：加壳的 so 需要先脱壳（dump 内存 + 修复 ELF 头），否则反汇编出来的逻辑是壳的。")
