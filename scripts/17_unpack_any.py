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

ok = fail = 0
report: list[str] = ["# 通用拆解报告", ""]
for i, f in enumerate(files, 1):
    rf.step(f"拆解 {f.name}", int(10 + 80 * i / max(1, len(files))))
    try:
        r = rf.unpack_any(f)
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
rep = rf.sub("report") / "通用拆解报告.md"
rep.parent.mkdir(parents=True, exist_ok=True)
rep.write_text("\n".join(report), encoding="utf-8")
put(f"拆解完成：成功 {ok} / 失败 {fail}；报告 → {rep}")

if to_desktop:
    from rf.tools.desktop import drop_to_desktop
    p = drop_to_desktop(rep)
    put(f"报告已复制到桌面：{p.name}")
