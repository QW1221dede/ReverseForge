#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
# @name 核心依赖与校验链
# @desc 建跨文件调用图 → 算入度 → 找校验点（授权/签名/环境/鉴权）→ 回溯入口链路
# @param folder 源码目录（jadx 反编译产物） [dir]
# @param annotate 顺带产出带注释的源码 [bool:false]
# @out 产物目录：deps.md 核心依赖报告 + sources_cn 注释源码（可选）
"""

# 逆向时最先要回答的问题不是"这段代码写了什么"，
# 而是"改哪里才有效果"。这个脚本就是回答它的：
#   1) 谁被依赖最多 —— 改它波及面最大，也最可能是主流程
#   2) 哪里有校验 —— 授权/签名/环境检测，功能开关都卡在这些人身上
#   3) 校验从哪进来 —— 顺着调用链回溯到 Activity/Service，才知道触发条件

import time
from pathlib import Path

root = Path(folder)
if not root.is_dir():
    raise RuntimeError(f"目录不存在：{root}")

t0 = time.time()
rf.step("建依赖图", 10)
g = rf.deps(root)
rf.step("依赖图完成", 55)

if not g.nodes:
    rf.log("没扫到 Java 类。确认目录里是 jadx 反编译出来的 .java 源码。")
else:
    # —— 核心依赖：语义命中 + 入度枢纽 ——
    core = g.core_nodes()
    rf.log(f"核心依赖 {len(core)} 个：")
    for n in core[:10]:
        rf.log(f"  ⚑ {n.name:<24} 入度 {n.fan_in:<3} 出度 {n.fan_out:<3} "
               f"{n.verify_cat or '结构枢纽'}")

    # —— 校验点：真正决定"功能能不能用"的地方 ——
    vers = g.verify_nodes()
    rf.log("")
    rf.log(f"校验点 {len(vers)} 个：")
    for n in vers[:10]:
        rf.log(f"  ⚑ {n.name} —— {n.verify_cat}（{n.verify_score} 分，入度 {n.fan_in}）")
        for h in n.verify_hits[:3]:
            rf.log(f"      · {h}")
        for ch in n.chains[:2]:
            rf.log("      链：" + " → ".join(ch))
        if not n.chains:
            if n.is_entry:
                rf.log("      链：本类即入口，系统直接启动它")
            else:
                rf.log("      链：未还原（可能经反射/接口回调，或入口不在本次范围内）")

    # —— 依赖枢纽：不是校验点，但改动风险最高 ——
    rf.log("")
    rf.log("依赖枢纽 Top8（改动风险最高）：")
    hubs = [n for n in g.hubs(8) if n.fan_in > 0]
    for n in hubs:
        rf.log(f"  {n.name:<24} 被 {n.fan_in} 个类依赖")

    # —— 孤立类：可能是死代码，也可能是加固壳的残渣 ——
    iso = [n.name for n in g.nodes.values() if n.fan_in == 0 and n.fan_out == 0]
    if iso:
        rf.log("")
        rf.log(f"孤立类 {len(iso)} 个（无人调用也未被调用，常为混淆残片）："
               + "、".join(iso[:8]))

rf.step("写报告", 70)
md = g.report_md()
rf.write_text(Path(out_dir) / "deps.md", "# 核心依赖与校验链\n\n" + md + "\n")
rf.log(f"报告：{Path(out_dir) / 'deps.md'}")

if annotate:
    rf.step("中文注释", 78)
    rf.log("开始全量注释（方法体内的条件/循环也会翻译成中文）…")
    src_cn = Path(out_dir) / "sources_cn"
    r = rf.annotate(root, src_cn, density="full")
    rf.log(f"注释产物：{r.out_root}")

rf.step("完成", 100)
rf.log(f"耗时 {time.time() - t0:.1f} 秒")
