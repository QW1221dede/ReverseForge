#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @name 通用拆解（任何文件）
# @desc 不止 APK：压缩包/磁盘镜像/OLE文档/CHM/PE资源 全部自动选拆法
# @param target 文件或目录 [file]
# @param to_desktop 成品复制到桌面 [bool:false]

"""
用法：
    丢进来一个文件（或一个目录批量），自动按类型选拆法：

    APK / AAB / APKS / XAPK  → apktool + jadx 全流程
    ZIP 家族（jar/docx/xlsx/pptx/ipa/appx/epub/crx/xpi…）→ 原生解压
    tar / tar.gz / tar.bz2 / tar.xz / 裸 gzip·bz2·xz → 原生 tarfile
    RAR / 7z / ISO / DMG / MSI / CAB / WIM / VHD / RPM…  → 7-Zip
    旧版 Office / Outlook 邮件 msg / Access mdb / CHM   → 7-Zip 抽流
    EXE / DLL（PE）→ 7-Zip 抽资源节 + 字符串清单
    其它（ELF/脚本/密文…）→ 分段 + 熵 + 画像报告

    产出：unpack_<名字>/ 目录 + 拆解报告要点打在日志里。
"""

import shutil
from pathlib import Path

target = Path(target)
if not target.exists():
    raise RuntimeError(f"路径不存在：{target}")

files = ([p for p in sorted(target.rglob("*"))
          if p.is_file() and not p.name.startswith(".")]
         if target.is_dir() else [target])

rf.step("通用拆解", 10)
put = rf.log
put(f"共 {len(files)} 个待拆目标")

# 产物收成「小白版」：根目录只留 使用说明.txt + 详细资料/，
# 各文件的拆解目录和报告全进 详细资料/（跟 16 号全自动化一致）。
out = rf.sub("通用拆解")
detail = out / "详细资料"
detail.mkdir(parents=True, exist_ok=True)

ok = fail = 0
report: list[str] = ["# 通用拆解报告", ""]
for i, f in enumerate(files, 1):
    rf.step(f"拆解 {f.name}", int(10 + 80 * i / max(1, len(files))))
    try:
        r = rf.unpack_any(f, out=detail / f"unpack_{f.stem}")
        ok += 1
        put(f"✓ [{i}/{len(files)}] {f.name} → {r['method']}（{r['files']} 个文件）")
        for n in r["notes"][:3]:
            put(f"    · {n}")
        report += [f"## {f.name}", f"- 方法：{r['method']}",
                   f"- 产物：{r['output']}（{r['files']} 文件）",
                   *[f"- {n}" for n in r["notes"]], ""]
    except Exception as e:                                   # noqa: BLE001
        fail += 1
        put(f"✗ [{i}/{len(files)}] {f.name}：{e}")
        report += [f"## {f.name}", f"- 失败：{e}", ""]

rf.step("汇总", 95)
rep = detail / "通用拆解报告.md"
rep.write_text("\n".join(report), encoding="utf-8")

note = out / "使用说明.txt"
note.write_text(
    "这个文件夹是什么\n\n"
    f"　　{len(files)} 个文件已经按各自的类型拆开了。\n\n"
    "要用的文件\n\n"
    f"　　详细资料/unpack_<文件名>/　每个输入文件拆出来的东西都在这里；\n"
    "　　详细资料/通用拆解报告.md　哪个文件用了什么拆法、出了多少文件。\n\n"
    "别的都不用管\n\n"
    "　　根目录只有这份说明和 详细资料/，平时打开 详细资料/ 找文件就行。\n\n"
    "　　（本工具只做本地分析，原始文件从未被修改。）\n",
    encoding="utf-8")
put(f"拆解完成：成功 {ok} / 失败 {fail}；报告 → {rep}")
put(f"  产物：{out}")

if to_desktop:
    from rf.tools.desktop import drop_to_desktop
    p = drop_to_desktop(note)
    put(f"说明已复制到桌面：{p.name}")
