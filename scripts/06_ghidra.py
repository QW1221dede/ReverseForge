#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
# @name Ghidra 反编译原生库（出 C 伪代码）
# @desc 调用 Ghidra headless 完整分析 → 每个函数导出一个 .c，再汇总索引
# @param lib 目标 .so / .dll 文件 [file]
# @param names 只导出名字含关键字的函数（留空=全部）[str]
# @out 产物目录：ghidra_out/*.c
"""

# 这是最重的一步：Ghidra 要做完整静态分析（函数识别、类型推导、反编译），
# 1MB 的 so 可能要几分钟，10MB 的可能半小时以上。先跑小而关键的库。
# 需要 JDK21（Ghidra 12 强制），工具链里已配好会自动切换。

import os
import shutil
from pathlib import Path

p = Path(lib)
if not p.is_file():
    raise RuntimeError(f"文件不存在：{p}")

size_mb = p.stat().st_size / 1048576
rf.note("Ghidra 反编译", f"{p.name}  {size_mb:.1f} MB")

if size_mb > 30:
    rf.log("  ⚠ 文件超过 30MB，Ghidra 分析可能非常久。建议先用「分析原生库」脚本判断值得不值得。")

# 先看一眼结构，确认不是加壳的（加壳的跑 Ghidra 通常是白跑）
info = None
try:
    info = rf.native(p)
    if info.packed:
        rf.log("  ⚠ 该库疑似加壳，Ghidra 只会看到壳的代码。建议先脱壳。")
        rf.log("     仍然继续，但结果参考价值有限。")
except Exception as e:
    rf.log(f"  ! 结构解析失败：{e}")

rf.step("启动 Ghidra 分析", 20)
out = rf.ghidra_decompile(p)

# 汇总
cfiles = sorted(out.glob("*.c")) if out else []
rf.step("整理索引", 90)

if not cfiles:
    rf.log("  ✗ 没有导出任何函数（可能架构不支持或分析失败）")
else:
    rf.log(f"  ✓ 导出 {len(cfiles)} 个函数")

    # 按大小排序，最大的通常是核心逻辑
    sized = sorted(cfiles, key=lambda f: f.stat().st_size, reverse=True)
    rf.log("  最大的 10 个函数（一般是核心逻辑）：")
    for f in sized[:10]:
        rf.log(f"    {f.name:<48} {f.stat().st_size:>7,} 字节")

    # 关键字过滤：把匹配的复制到一个子目录，方便集中看
    if names:
        keys = [k.strip().lower() for k in names.split(",") if k.strip()]
        picked = [f for f in cfiles if any(k in f.name.lower() for k in keys)]
        dst = rf.sub("picked")
        for f in picked:
            shutil.copy2(f, dst / f.name)
        rf.log(f"  按关键字 {keys} 命中 {len(picked)} 个，已复制到 {dst}")

    # 生成索引
    idx = ["# " + f.name + "  (%d 字节)" % f.stat().st_size for f in sized]
    (out / "index.txt").write_text("\n".join(idx), encoding="utf-8")

rf.report(f"Ghidra 反编译 · {p.name}", {
    "目标": {
        "文件": str(p),
        "大小": f"{size_mb:.2f} MB",
        "架构": getattr(info, "machine", "—") if info else "—",
    },
    "结果": {
        "导出函数": len(cfiles),
        "输出目录": str(out),
    },
}, "ghidra_report.md")

rf.log("")
rf.log("伪代码是「近似还原」：类型、结构体名、变量名都是 Ghidra 推断的，")
rf.log("逻辑顺序可信，具体类型可能不准。关键函数建议人工对照反汇编看。")
