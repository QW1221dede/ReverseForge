#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
# @name 拆解 APK（全家桶）
# @desc 画像 → 解包 → 反编译 → 中文注释 → 密钥扫描 → 报告，一条龙
# @param apk 目标 APK 路径 [file]
# @param annotate 生成中文注释 [bool:true]
# @param keyscan 扫描硬编码密钥 [bool:true]
# @out 产物目录：apktool/ jadx/ sources_cn/ report/
"""

# 这个脚本是 ReverseForge 的「主菜」：一个 APK 从进来到出报告，全在这里。
# 脚本里可以直接用：rf（门面）、args（参数字典）、out_dir（产物目录）。
# 参数名 apk / annotate / keyscan 由头部 @param 声明，运行时自动注入为全局变量。

import os

target = apk
if not target or not os.path.exists(target):
    raise RuntimeError(f"APK 不存在：{target}")

# 非 APK 文件自动分流：本页五阶段全是 APK 专属（smali/重签/验签），
# 硬跑必然全崩 —— 转投通用拆解，产出一样落进产物目录
_kind = rf.file_type(target)
if _kind.real != "apk":
    rf.log(f"- 识别为 {_kind.label}，不是 APK → 自动转「通用拆解」")
    _r = rf.unpack_any(target)
    rf.log(f"- ✓ {_r['method']}（{_r['files']} 个文件）")
    for _n in _r["notes"][:3]:
        rf.log(f"    · {_n}")
    rf.log("- 拆包产物见上方目录；dex 可拖回本页继续反编译，密文接「一键解密」")
    raise SystemExit(0)

# ── 1. 静态画像（不调外部工具，秒出）─────────────────────────────
rf.note("阶段 1/5 · 静态画像")
info = rf.apk_info(target)
rf.log(f"  包名：{info.package or '未知'}")
rf.log(f"  版本：{info.version_name or '?'} ({info.version_code or '?'})")
rf.log(f"  应用名：{info.label or '—'}")
rf.log(f"  SDK：min {info.min_sdk or '—'} / target {info.target_sdk or '—'}")
rf.log(f"  权限 {len(info.permissions)} 个，dex {len(info.dex_files)} 个，"
       f"so {len(info.native_libs)} 个")
if info.packers:
    rf.log(f"  ⚠ 加固：{'、'.join(info.packers)}")
    rf.log("  提示：加固包的 dex 是被壳保护的，直接反编译只能看到壳入口，需要先脱壳")

# ── 2. 解包 + 反编译 ───────────────────────────────────────────
rf.note("阶段 2/5 · 解包与反编译")
res = rf.apk_unpack(target)
if not res.ok_apktool and not res.ok_jadx:
    raise RuntimeError("解包与反编译都失败了，见上方日志")

# ── 3. 中文注释 ────────────────────────────────────────────────
cn_dir = None
if annotate and res.sources_dir:
    rf.note("阶段 3/5 · 中文注释")
    a = rf.annotate(res.sources_dir)
    cn_dir = a.out_root
    rf.log(f"  注释后源码：{cn_dir}")
else:
    rf.log("（跳过注释）")

# ── 4. 硬编码密钥 / 口令扫描 ───────────────────────────────────
key_hits = []
if keyscan:
    rf.note("阶段 4/5 · 硬编码密钥扫描")
    scan_root = res.apktool_dir or res.sources_dir
    if scan_root:
        key_hits = rf.keys(scan_root)
        if not key_hits:
            rf.log("  未发现明显的硬编码密钥")

# ── 5. 汇总报告 ────────────────────────────────────────────────
rf.note("阶段 5/5 · 生成报告")
st = info.dex_stats or {}
sections = {
    "基本信息": {
        "文件": os.path.basename(target),
        "包名": info.package or "—",
        "版本": f"{info.version_name or '?'} ({info.version_code or '?'})",
        "应用名": info.label or "—",
        "大小": f"{info.size / 1048576:.2f} MB",
        "SDK": f"min {info.min_sdk or '—'} / target {info.target_sdk or '—'}",
    },
    "规模": {
        "dex 数量": st.get("dex_count", 0),
        "类": st.get("classes", 0),
        "方法": st.get("methods", 0),
        "字段": st.get("fields", 0),
        "native 库": st.get("so_count", 0),
        "Java 文件": st.get("java_files", 0),
    },
    "加固判定": "、".join(info.packers) if info.packers else "未检出加固特征",
    "权限": info.permissions or ["（无）"],
    "产物": {
        "资源/Manifest/smali": res.apktool_dir or "—",
        "Java 源码": res.sources_dir or "—",
        "中文注释版": cn_dir or "（未生成）",
    },
}

if key_hits:
    sections["疑似硬编码密钥"] = [f"{label} → {frag}" for label, frag in key_hits[:30]]
if res.errors:
    sections["过程中出现的错误"] = res.errors

rf.report(f"{info.label or os.path.basename(target)} · 拆解报告", sections)
rf.log("")
rf.log("全部完成。产物目录：" + str(rf.out_dir))
