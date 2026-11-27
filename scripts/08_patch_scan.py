#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @name 启动校验扫描
# @desc 找启动前的卡密/授权/签名判定，输出证据、置信度与补丁建议
# @param target 解包目录或 APK 文件 [file]
# @param min_conf 最低置信度 [int:25]
# @param frida 生成 Frida 覆盖脚本 [bool:true]

"""
用法：
    选一个 apktool 解包目录，或直接选 APK（会自动解包，不反编译）。
    产出：校验点.md / patch_recipe.json / hook.js
"""

import json
from pathlib import Path

from rf.patch import checkpoints as cp

target = Path(target)

if target.suffix.lower() == ".apk":
    rf.step("解包 APK", 5)
    res = rf.apk_unpack(target, out=rf.sub("unpack"), apktool=True, jadx=False)
    if not res.apktool_dir:
        raise RuntimeError("解包失败：" + "；".join(res.errors[:3]))
    root = Path(res.apktool_dir)
else:
    root = target

rf.step("扫描校验点", 30)
rep = rf.patch_scan(root, min_confidence=int(min_conf))

out = rf.sub("report")
md = out / "校验点.md"
md.write_text(cp.report_md(rep), encoding="utf-8")
rf.log(f"✓ 报告：{md}")

recipe = rf.out_dir / "patch_recipe.json"
recipe.write_text(json.dumps([p.to_dict() for p in rep.points],
                             ensure_ascii=False, indent=2), encoding="utf-8")
rf.log(f"✓ 配方：{recipe}（{len(rep.points)} 条）")

if frida and rep.pre_run:
    js = rf.frida(rep, out=rf.out_dir / "hook.js")
    rf.log(f"✓ 运行期验证脚本：{js}")

rf.step("完成", 100)
rf.note("结论", "\n".join([
    rep.summary(),
    f"启动路径上的校验 {len(rep.pre_run)} 个",
    "下一步：09_patch_apply.py（先预演，再落盘，再重建）",
]))
