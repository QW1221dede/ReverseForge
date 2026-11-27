#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @name 任意文件画像
# @desc 不限 APK：识别类型、分段找「明文头+密文」、判乱码、出清单
# @param target 文件或目录 [file]
# @param deep 大文件也做全量分段 [bool:false]

"""
用法：
    选任意一个文件（exe/dll/脚本/数据文件…）或一个目录。

    干的事：
      1. 判类型（魔数 + 容器结构 + 扩展名 + 熵兜底），给建议分析器
      2. 分段：找明文头 / 密文体的分界，顺便把头部里的密钥捞出来
      3. 判"看不懂"是哪种：菱形问号 / 方块（字体加密）/ 乱码（可修）
    产出：类型清单.md / 分段.md / 乱码诊断.md
"""

from pathlib import Path

from rf.analysis import authscan, filetype, garble, segments

target = Path(target)
if not target.exists():
    raise RuntimeError(f"路径不存在：{target}")

out = rf.sub("report")
out.mkdir(parents=True, exist_ok=True)

# ---- 1) 类型 ----
rf.step("识别类型", 10)
if target.is_dir():
    scan = rf.scan_any(target, quiet=True)
    (out / "类型清单.md").write_text(filetype.report_md(scan), encoding="utf-8")
    rf.log(f"✓ {scan.summary()}")
    files = [Path(k.path) for k in scan.kinds
             if k.category in (filetype.CAT_ENCRYPTED, filetype.CAT_SCRIPT)][:20]
else:
    kind = rf.file_type(target)
    rf.log(f"  {kind.label} · 熵 {kind.entropy:.2f} · 建议 {kind.route}")
    files = [target]

# ---- 2) 分段 ----
rf.step("分段", 40)
seg_lines = ["# 文件分段", ""]
for f in files[:12]:
    try:
        sm = rf.segments(f)
    except Exception as e:                       # noqa: BLE001
        seg_lines.append(f"- `{f.name}`：跳过（{e}）")
        continue
    seg_lines.append(f"## {f.name}")
    seg_lines.append("")
    seg_lines.append(f"- 概况：{sm.brief()}")
    if sm.split.found:
        seg_lines.append(f"- 明暗分界：明文 {sm.split.head_len}B + 密文 "
                         f"{sm.split.tail_len}B（可信 {sm.split.confidence}%）")
        if sm.split.head_keys:
            seg_lines.append(f"- 头部疑似密钥：{'、'.join(sm.split.head_keys)}")
    if sm.embedded:
        seg_lines.append(f"- 嵌套容器：{sm.embedded}")
    seg_lines += ["", sm.table(12), ""]
(out / "分段.md").write_text("\n".join(seg_lines), encoding="utf-8")
rf.log(f"✓ 分段报告：{out / '分段.md'}")

# ---- 3) 乱码诊断 ----
rf.step("乱码诊断", 70)
g_lines = ["# 乱码诊断", ""]
for f in files[:12]:
    try:
        rep = rf.garble(f)
    except Exception as e:                       # noqa: BLE001
        g_lines.append(f"- `{f.name}`：跳过（{e}）")
        continue
    g_lines.append(garble.report_md(rep, title=f.name))
    g_lines.append("")
(out / "乱码诊断.md").write_text("\n".join(g_lines), encoding="utf-8")
rf.log(f"✓ 乱码诊断：{out / '乱码诊断.md'}")

# ---- 4) 校验点（脚本/二进制都扫） ----
rf.step("校验点", 85)
arep = authscan.scan(target, min_confidence=45)
(out / "校验点.md").write_text(authscan.report_md(arep), encoding="utf-8")
rf.log(f"✓ {arep.summary()}")
if arep.fixable:
    rf.log(f"  可自动改的 {len(arep.fixable)} 个；用 14_auth_any.py 或"
           f" auth_apply(..., dry_run=False) 落盘")

rf.log("完成。下一步建议：13_decrypt_auto.py 解加密文件")
