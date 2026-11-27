#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
# @name AndroidManifest 安全审计
# @desc 解包后的 Manifest 逐项检查：可调试/允许备份/明文流量/导出组件/危险权限
# @param manifest AndroidManifest.xml 路径或 apktool 解包目录 [dir]
# @out 产物目录：manifest_audit.md
"""

# 这里查的是"配置层面的洞"，和代码逻辑无关 —— 但往往是最容易得手的一类：
#   debuggable=true           → 可以直接 adb 附加调试、dump 内存
#   allowBackup=true          → adb backup 能导出应用私有数据
#   exported=true 无权限保护  → 任意应用可调用该组件
#   usesCleartextTraffic      → 明文 HTTP 可被中间人改包

import re
import xml.etree.ElementTree as ET
from pathlib import Path

src = Path(manifest)
if src.is_dir():
    cands = list(src.rglob("AndroidManifest.xml"))
    if not cands:
        raise RuntimeError(f"目录下没有 AndroidManifest.xml：{src}")
    mf = cands[0]
elif src.is_file():
    mf = src
else:
    raise RuntimeError(f"路径不存在：{src}")

rf.note("解析 Manifest", str(mf))
raw = mf.read_bytes()
if raw[:2] == b"\x03\x00":
    raise RuntimeError("这是二进制 AXML（未解码），请先用 apktool 解包再审计")

try:
    tree = ET.parse(str(mf))
    root_el = tree.getroot()
except ET.ParseError as e:
    raise RuntimeError(f"XML 解析失败：{e}")

ANDROID = "{http://schemas.android.com/apk/res/android}"
pkg = root_el.get("package", "—")

findings: list[tuple[str, str, str]] = []   # (级别, 项, 说明)


def attr(el, name: str, default: str = "") -> str:
    return el.get(ANDROID + name, el.get(name, default) or default)


def add(level: str, item: str, note: str) -> None:
    findings.append((level, item, note))


# ---- 应用级 ----
app_el = root_el.find("application")
if app_el is not None:
    if attr(app_el, "debuggable").lower() == "true":
        add("严重", "application debuggable=true",
            "可直接 adb 附加调试、内存 dump、任意改代码运行")
    if attr(app_el, "allowBackup").lower() != "false":
        add("高危", "allowBackup 未关闭",
            "adb backup 可导出应用私有数据（/data/data/<包名>）")
    if attr(app_el, "usesCleartextTraffic").lower() == "true":
        add("高危", "usesCleartextTraffic=true",
            "允许明文 HTTP，可被中间人抓包/改包")
    if attr(app_el, "networkSecurityConfig"):
        add("提示", "自定义 networkSecurityConfig",
            "检查是否 trust-all 或固定了可被替换的 CA")
    if attr(app_el, "testOnly").lower() == "true":
        add("注意", "testOnly=true", "测试包标记，部分系统限制安装")
    if attr(app_el, "name"):
        add("提示", "Application 类", attr(app_el, "name") +
            "（加固壳的入口通常在这里）")

# ---- 组件 ----
comp_stats = {}
for tag in ("activity", "activity-alias", "service", "receiver", "provider"):
    items = root_el.findall(f".//{tag}")
    comp_stats[tag] = len(items)
    for el in items:
        name = attr(el, "name", "?")
        if attr(el, "exported").lower() != "true":
            continue
        has_perm = bool(attr(el, "permission"))
        level = "高危" if not has_perm else "提示"
        note = ("可从任意应用调用" if not has_perm else
                f"导出但受权限保护：{attr(el, 'permission')}")
        if tag == "provider":
            if not has_perm:
                note += "；ContentProvider 无保护 = 任意读写其数据"
            if attr(el, "grantUriPermissions").lower() == "true":
                note += "；授予 URI 权限"
        add(level, f"{tag} 导出：{name}", note)

# ---- 权限 ----
perms = [attr(p, "name", "") for p in root_el.findall(".//uses-permission")]
DANGER = {
    "READ_SMS": "读短信", "SEND_SMS": "发短信", "RECEIVE_SMS": "收短信",
    "READ_CONTACTS": "读联系人", "READ_CALL_LOG": "读通话记录",
    "CALL_PHONE": "打电话", "RECORD_AUDIO": "录音", "CAMERA": "相机",
    "ACCESS_FINE_LOCATION": "精确定位", "READ_EXTERNAL_STORAGE": "读外部存储",
    "WRITE_EXTERNAL_STORAGE": "写外部存储", "SYSTEM_ALERT_WINDOW": "悬浮窗",
    "REQUEST_INSTALL_PACKAGES": "安装应用", "QUERY_ALL_PACKAGES": "枚举全部应用",
    "READ_PHONE_STATE": "读设备标识", "BIND_ACCESSIBILITY_SERVICE": "无障碍服务",
    "WRITE_SECURE_SETTINGS": "改系统设置", "MANAGE_EXTERNAL_STORAGE": "全盘文件访问",
}
hit_danger = []
for p in perms:
    short = p.split(".")[-1]
    if short in DANGER:
        hit_danger.append(f"{short}（{DANGER[short]}）")

if hit_danger:
    add("注意", f"敏感权限 {len(hit_danger)} 项", "、".join(hit_danger))

# ---- 输出 ----
rf.log(f"  包名：{pkg}")
rf.log(f"  组件：活动 {comp_stats['activity']} / 服务 {comp_stats['service']} / "
       f"广播 {comp_stats['receiver']} / 提供者 {comp_stats['provider']}")
rf.log(f"  权限：{len(perms)} 个，其中敏感 {len(hit_danger)} 个")
rf.log("")

order = {"严重": 0, "高危": 1, "注意": 2, "提示": 3}
findings.sort(key=lambda x: order.get(x[0], 9))

if findings:
    rf.log(f"  发现 {len(findings)} 条：")
    for level, item, note in findings[:25]:
        mark = {"严重": "‼", "高危": "⚠", "注意": "·", "提示": " "}.get(level, " ")
        rf.log(f"   {mark} [{level}] {item}")
        rf.log(f"        {note}")
else:
    rf.log("  未发现明显的配置层问题")

rf.report(f"Manifest 审计 · {pkg}", {
    "基本信息": {
        "Manifest": str(mf),
        "包名": pkg,
        "组件统计": f"活动 {comp_stats['activity']} / 服务 {comp_stats['service']} / "
                    f"广播 {comp_stats['receiver']} / 提供者 {comp_stats['provider']}",
        "权限数": len(perms),
    },
    "发现": [f"[{lvl}] {item} —— {note}" for lvl, item, note in findings] or ["无"],
    "权限清单": perms or ["（无）"],
}, "manifest_audit.md")
