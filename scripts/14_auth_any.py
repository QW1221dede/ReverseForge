#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @name 任意校验点扫描
# @desc 脚本/EXE/DLL/class/smali 里的密码、卡密、授权校验，精确到行并给改法
# @param target 文件或目录 [file]
# @param min_conf 最低置信度 [int:45]
# @param fix 直接改掉脚本里的校验（会先备份） [bool:false]
# @param dry 只预演不落盘 [bool:true]

"""
用法：
    选一个脚本、一个 EXE/DLL，或者一整个程序目录。

    能认的：
      · Python / JS / Lua / Shell / BAT / PowerShell / PHP / AutoHotkey
      · PE（exe/dll）、ELF（so）—— 按字符串 + 比较函数导入定位到文件偏移
      · JAR / class 常量池
      · APK 的 smali（内部走 checkpoints，含调用图与布尔闸门判定）

    每条命中都带：文件 + 行号/偏移、代码上下文、置信度、以及**可直接替换的改法**。
    fix=true 时才真的写盘，写前先备份，改完自动校验语法。

    产出：校验点.md / 校验点.json
"""

import json
from pathlib import Path

from rf.analysis import authscan

target = Path(target)
if not target.exists():
    raise RuntimeError(f"路径不存在：{target}")

rf.step("扫描", 20)
rep = rf.auth_scan(target, min_confidence=int(min_conf))
rf.log(f"  {rep.summary()}")

out = rf.sub("report")
out.mkdir(parents=True, exist_ok=True)

md = out / "校验点.md"
md.write_text(authscan.report_md(rep), encoding="utf-8")
rf.log(f"✓ 报告：{md}")

js = out / "校验点.json"
js.write_text(json.dumps([p.to_dict() for p in rep.points],
                         ensure_ascii=False, indent=2), encoding="utf-8")
rf.log(f"✓ 数据：{js}")

# ---- 启动路径上的重点 ----
pre = rep.pre_run
if pre:
    rf.log(f"\n启动路径上有 {len(pre)} 个校验点：")
    for p in pre[:10]:
        rf.log(f"  {p.aid} {p.loc} · {p.kind_cn} · {p.confidence}%")
        if p.fix_old and p.fix_new:
            rf.log(f"      改：{p.fix_old.strip()[:60]}")
            rf.log(f"      → {p.fix_new.strip()[:60]}")

# ---- 可选：改掉 ----
if fix:
    fixable = rep.fixable
    if not fixable:
        rf.log("\n没有可自动修改的点（二进制类只能手工打补丁）")
    else:
        rf.step("改写脚本校验", 70)
        res = rf.auth_apply(rep, ids=[p.aid for p in fixable],
                            dry_run=bool(dry), backup_dir=rf.out_dir / "备份")
        rf.log(f"{'（预演，未写盘）' if dry else '已改写 %d 个文件' % len(res.changed)}")
        if not dry:
            rf.log(f"  备份在：{res.backup}")
            rf.log("  建议立刻跑一遍改后的脚本，确认能进主流程")

rf.step("完成", 100)
rf.log("完成")
