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

# 产物收成「小白版」：根目录只留 使用说明.txt + 详细资料/，
# 抠出来的对象和报告全进 详细资料/（跟 16 号全自动化一致）。
out = rf.sub("内嵌雕刻")
detail = out / "详细资料"
detail.mkdir(parents=True, exist_ok=True)

ok = 0
report: list[str] = ["# 内嵌对象雕刻报告", ""]
found_dirs: list[str] = []
for i, f in enumerate(files, 1):
    rf.step(f"雕刻 {f.name}", int(10 + 80 * i / max(1, len(files))))
    try:
        r = rf.carve(f, out=detail / f"{f.stem}_carved")
        if r["found"]:
            ok += 1
            put(f"✓ [{i}/{len(files)}] {f.name}："
                + "、".join(f"{o['kind']}@0x{o['offset']:x}" for o in r["objects"][:8]))
            report += [f"## {f.name}"]
            report += [f"- [{o['kind']}] @0x{o['offset']:x} {o['size']} 字节"
                       + (f" —— {o['note']}" if o.get("note") else "")
                       for o in r["objects"]]
            report += [f"- 产物：{r['output']}", ""]
            found_dirs.append(f"{f.stem}_carved/")
        else:
            put(f"- [{i}/{len(files)}] {f.name}：没有可雕刻对象")
    except Exception as e:                                   # noqa: BLE001
        put(f"✗ [{i}/{len(files)}] {f.name}：{e}")

rf.step("汇总", 95)
rep = detail / "内嵌雕刻报告.md"
rep.write_text("\n".join(report) if len(report) > 2 else "# 没有发现内嵌对象",
               encoding="utf-8")

note = out / "使用说明.txt"
note.write_text(
    "这个文件夹是什么\n\n"
    "　　已经从你给的文件里把藏着的 zip / dex / so / 图片等对象抠出来了。\n\n"
    "要用的文件\n\n"
    + ("".join(f"　　详细资料/{d}　抠出来的对象按 类型_序号_偏移 命名\n"
               for d in found_dirs[:20]) or "　　本次没有发现可雕刻的对象。\n")
    + "　　详细资料/内嵌雕刻报告.md　每个对象是什么、在文件什么位置。\n\n"
    "别的都不用管\n\n"
    "　　根目录只有这份说明和 详细资料/，平时打开 详细资料/ 找文件就行。\n\n"
    "　　（本工具只做本地分析，原始文件从未被修改。）\n",
    encoding="utf-8")
put(f"雕刻完成：{ok} / {len(files)} 个文件有收获；报告 → {rep}")
put(f"  产物：{out}")

if to_desktop:
    from rf.tools.desktop import drop_to_desktop
    p = drop_to_desktop(note)
    put(f"说明已复制到桌面：{p.name}")
