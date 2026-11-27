#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @name 内嵌对象雕刻
# @desc 任意文件里挖出 zip/dex/so/图片：vdex·oat 挖 dex、固件扒段、加壳找资源
# @param target 文件或目录 [file]
# @param to_desktop 成品复制到桌面 [bool:false]

"""
用法：
    丢进来一个文件（或一个目录批量），扫描字节流里的已知格式特征，
    把内嵌对象整块抠出来：

    vdex / oat / odex  → 内嵌原始 dex（可丢进 APK 页反编译）
    固件 / 镜像 / 加壳 PE → 残留的 zip、so、png、jpg、pdf、sqlite
    加固 APK 的 lib/*.so → 藏着的原始 dex

    产出：<名字>_carved/ 目录，对象按 类型_序号_偏移 命名。
"""

from pathlib import Path

target = Path(target)
if not target.exists():
    raise RuntimeError(f"路径不存在：{target}")

files = ([p for p in sorted(target.rglob("*"))
          if p.is_file() and not p.name.startswith(".") and p.stat().st_size > 512]
         if target.is_dir() else [target])

rf.step("内嵌对象雕刻", 10)
put = rf.log
put(f"共 {len(files)} 个待雕刻目标")

ok = 0
report: list[str] = ["# 内嵌对象雕刻报告", ""]
for i, f in enumerate(files, 1):
    rf.step(f"雕刻 {f.name}", int(10 + 80 * i / max(1, len(files))))
    try:
        r = rf.carve(f)
        if r["found"]:
            ok += 1
            put(f"✓ [{i}/{len(files)}] {f.name}："
                + "、".join(f"{o['kind']}@0x{o['offset']:x}" for o in r["objects"][:8]))
            report += [f"## {f.name}"]
            report += [f"- [{o['kind']}] @0x{o['offset']:x} {o['size']} 字节"
                       + (f" —— {o['note']}" if o.get("note") else "")
                       for o in r["objects"]]
            report += [f"- 产物：{r['output']}", ""]
        else:
            put(f"- [{i}/{len(files)}] {f.name}：没有可雕刻对象")
    except Exception as e:                                       # noqa: BLE001
        put(f"✗ [{i}/{len(files)}] {f.name}：{e}")

rf.step("汇总", 95)
rep = rf.sub("report") / "内嵌雕刻报告.md"
rep.parent.mkdir(parents=True, exist_ok=True)
rep.write_text("\n".join(report) if len(report) > 2 else "# 没有发现内嵌对象",
               encoding="utf-8")
put(f"雕刻完成：{ok} / {len(files)} 个文件有收获；报告 → {rep}")

if to_desktop:
    from rf.tools.desktop import drop_to_desktop
    p = drop_to_desktop(rep)
    put(f"报告已复制到桌面：{p.name}")
