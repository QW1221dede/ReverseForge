#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @name 一键打补丁并重建
# @desc 预演 → 应用 → 重建 → 签名 → 验签 → 回读，全程可回滚
# @param target 解包目录或 APK 文件 [file]
# @param ids 指定校验点ID，逗号分隔（空=全部启动路径） [str:]
# @param only_pre 只处理启动路径 [bool:true]
# @param rebuild 补丁后重建 APK [bool:true]
# @param out_apk 输出 APK 路径（空=产物目录/patched.apk） [str:]
# @param install 装到已连接设备 [bool:false]

"""
流程：
    1. 扫描（或复用已有解包目录）
    2. 生成方案 → dry_run 预演（不写盘）
    3. 预演通过才真正落盘；任何一条失败整批回滚
    4. 重建 → zipalign → 签名 → 验签 → 回读确认补丁进包
    5. 写中文报告

注意：
    * 改的是解包目录里的 smali，不动原 APK
    * 重建包用本地调试证书签名；覆盖安装原版需先卸载
"""

from pathlib import Path

from rf.patch import checkpoints as cp

target = Path(target)
if not target.exists():
    raise RuntimeError(f"目标不存在：{target}")

if target.suffix.lower() == ".apk":
    rf.step("解包 APK", 5)
    un = rf.apk_unpack(target, out=rf.sub("unpack"), apktool=True, jadx=False)
    if not un.apktool_dir:
        raise RuntimeError("解包失败：" + "；".join(un.errors[:3]))
    root = Path(un.apktool_dir)
    rf.log(f"解包目录：{root}")
else:
    root = target

rf.step("扫描校验点", 15)
rep = rf.patch_scan(root)

ids = [x.strip() for x in str(ids or "").replace("，", ",").split(",") if x.strip()]
ops = rf.patch_plan(rep, ids=ids or None, only_pre=bool(only_pre))
if not ops:
    raise RuntimeError("没有可自动应用的补丁建议。先用 08_patch_scan.py 看报告，"
                       "或在脚本里手写 PatchOp。")

rf.step("预演补丁", 30)
dry = rf.patch_apply(root, ops, dry_run=True)
if not dry.ok:
    raise RuntimeError("预演未通过，未改任何文件：\n" + dry.text())

rf.step("应用补丁", 45)
res = rf.patch_apply(root, ops)
if not res.ok:
    raise RuntimeError("应用失败，已回滚：\n" + res.text())
rf.log(f"备份：{res.backup_dir}")

rb = None
if rebuild:
    rf.step("重建 APK", 65)
    out = Path(out_apk) if str(out_apk or "").strip() else (rf.out_dir / "patched.apk")
    rb = rf.patch_rebuild(root, out, ops=ops, install=bool(install))
    if not rb.ok:
        raise RuntimeError("重建失败：" + "；".join(rb.errors[:3]))

sections = {
    "输入": {
        "目标": str(target),
        "解包目录": str(root),
        "启动校验": len(rep.pre_run),
        "补丁数": len(ops),
    },
    "应用的补丁": [f"{op.reason} @ {Path(op.file).name}:{op.line}" for op in ops],
    "备份": {"目录": res.backup_dir},
}
if rb:
    sections["重建"] = {
        "APK": rb.apk,
        "体积KB": round(rb.size / 1024, 1),
        "签名": "通过" if rb.verified else "未通过",
        "回读补丁": "确认" if rb.roundtrip else "未确认",
        "用时秒": round(rb.dur, 1),
    }
rf.report("补丁执行报告", sections, name="补丁报告.md")

rf.step("完成", 100)
rf.note("完成", "先装到测试机验证；起不来就用 patch_rollback 回滚。")
