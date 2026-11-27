#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @name 积木拼装
# @desc 从 30+ 块代码积木里挑一组，拼成可直接运行的脚本
# @param preset 预设组合 [choice:扫描全家桶,补丁全家桶,只做侦察,解密与校验,自定义]
# @param ids 自定义积木ID，逗号分隔（preset=自定义时生效） [str:]
# @param name 输出文件名 [str:my_script.py]

"""
积木的意义：
    不用从空白文件开始写。每块都已经过语法校验，
    拼装时按依赖排序，拼完再整体校验一次。

常用 ID 示例：
    intro.log / intro.guard / intro.safe
    recon.apk / recon.unpack / recon.strings / recon.keys
    verify.deps / verify.scan / verify.report
    patch.plan / patch.apply / patch.rebuild / patch.rollback
    crypto.aes / crypto.verify
    runtime.frida / runtime.install
"""

PRESETS = {
    "扫描全家桶": ["intro.log", "intro.guard", "recon.apk", "recon.unpack",
                   "recon.strings", "verify.scan", "verify.report", "report.md"],
    "补丁全家桶": ["intro.log", "intro.guard", "recon.apk", "verify.scan",
                   "patch.plan", "patch.apply", "patch.rebuild", "report.md"],
    "只做侦察": ["intro.log", "recon.apk", "recon.strings", "recon.keys",
                 "recon.elf", "report.md"],
    "解密与校验": ["intro.log", "crypto.identify", "crypto.aes",
                   "crypto.verify", "eng.selftest"],
    "自定义": [],
}

choice = str(preset or "扫描全家桶")
ids = PRESETS.get(choice, [])
if choice == "自定义":
    ids = [x.strip() for x in str(ids or "").replace("，", ",").split(",") if x.strip()]
    if not ids:
        raise RuntimeError("preset=自定义 时请在 ids 里填积木 ID，逗号分隔")

rf.step("检查积木", 15)
for sid in ids:
    sn = rf.snippet(sid)
    if not sn.valid:
        raise RuntimeError(f"积木 {sid} 语法未通过：" + "；".join(sn.errors[:2]))
    rf.log(f"✓ {sid} · {sn.title}")

rf.step("拼装", 55)
out = rf.out_dir / (str(name or "my_script.py"))
code = rf.compose(ids, out=out)

rf.step("整体语法校验", 80)
v = rf.validate(out)
if not v.ok:
    raise RuntimeError("拼装脚本语法未通过：" + v.errors[0].text())

rf.log(f"✓ {len(ids)} 块 → {out}（{len(code.splitlines())} 行）")
rf.step("完成", 100)
rf.note("下一步", f"把 {out.name} 复制到 scripts/ 目录，刷新脚本库即可运行")
