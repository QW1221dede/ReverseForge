#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
# @name 批量扫描 APK（仅画像）
# @desc 一次过一批 APK：包名/版本/加固/权限/组件数量，出汇总表，不解包
# @param folder APK 所在目录 [dir]
# @param recursive 含子目录 [bool:true]
# @out 产物目录：apk_inventory.md
"""

# 适合先做"摸底"：几百个包里哪些加了壳、哪些权限离谱、哪些值得深挖。
# 只读 APK 头与 dex 头部，不调 apktool / jadx，所以几百个包也就几十秒。

from pathlib import Path

root = Path(folder)
if not root.is_dir():
    raise RuntimeError(f"目录不存在：{root}")

pattern = "**/*.apk" if recursive else "*.apk"
apks = sorted(root.glob(pattern))
if not apks:
    raise RuntimeError(f"没找到 .apk 文件：{root}")

rf.note("批量画像", f"{len(apks)} 个 APK")

rows = []
packers_count: dict[str, int] = {}
failed = []

for i, apk in enumerate(apks, 1):
    rf.step(f"{i}/{len(apks)} {apk.name}", int(i / len(apks) * 90))
    try:
        info = rf.apk_info(apk, quiet=True)
    except Exception as e:
        failed.append(f"{apk.name}: {e}")
        rf.log(f"  ✗ {apk.name}：{e}")
        continue

    if info.packers:
        for pk in info.packers:
            packers_count[pk] = packers_count.get(pk, 0) + 1

    st = info.dex_stats or {}
    rows.append({
        "文件": apk.name,
        "包名": info.package or "—",
        "版本": info.version_name or "—",
        "大小MB": round(info.size / 1048576, 1),
        "dex": len(info.dex_files),
        "so": len(info.native_libs),
        "权限": len(info.permissions),
        "加固": "、".join(info.packers) if info.packers else "—",
    })

# 汇总
rf.note("汇总")
total_mb = sum(r["大小MB"] for r in rows)
rf.log(f"  成功 {len(rows)} 个，失败 {len(failed)} 个，合计 {total_mb:.1f} MB")
if packers_count:
    rf.log("  加固分布：" + "、".join(f"{k}×{v}" for k, v in
                                     sorted(packers_count.items(), key=lambda x: -x[1])))
else:
    rf.log("  未检出加固特征")

# 权限最多的前 5 个，通常是"最值得看"的
top = sorted(rows, key=lambda r: r["权限"], reverse=True)[:5]
if top:
    rf.log("  权限最多的包：")
    for r in top:
        rf.log(f"    {r['包名']:<32} {r['权限']:>3} 个权限  {r['加固']}")

sections = {
    "总览": {
        "扫描目录": str(root),
        "APK 数量": len(rows),
        "失败": len(failed),
        "总体积": f"{total_mb:.1f} MB",
        "加固分布": "、".join(f"{k}×{v}" for k, v in packers_count.items()) or "未检出",
    },
    "清单": rows,
}
if failed:
    sections["处理失败"] = failed

rf.report(f"APK 批量画像 · {root.name}", sections, "apk_inventory.md")
rf.log("")
rf.log("下一步：挑出要深挖的包，用「拆解 APK（全家桶）」单独跑。")
