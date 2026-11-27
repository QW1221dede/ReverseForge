#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @name 真签名回填（抓包→发包）
# @desc 从手机抓包/日志里收割服务器认的真签名，回填假包直接发包
# @param target 样本文件或解包目录 [file]
# @param capture 抓包文本/har/xlog 文件路径，或直接粘贴的 cURL [str:]
# @param to_desktop 报告复制到桌面 [bool:false]

"""
用法：
    1. 手机上正常跑一次程序，抓下它发出的验证请求/响应
       （VPN 抓包 / Charles / mitmproxy / 直接复制 cURL 都行）。
    2. 把抓包内容存成文件，或整段粘到「capture」参数里。
    3. 本脚本从抓包里收割 token/signature/timestampsign/session 等真签名，
       回填到假请求包，产出「已签名请求包.json」——可直接拿去发包。

    为什么不能直接造签名：T3 用设备私钥 + plaintext_sha256 做签名，
    私钥在手机上现算，样本里没有。抓真包是拿到服务器认的签名的唯一实路。
"""

from pathlib import Path

target = Path(target)
if not target.exists():
    raise RuntimeError(f"路径不存在：{target}")

rf.step("假包 + 抓包收割", 10)
result = rf.fakepacket_capture(str(capture or ""), target)

rf.step("落盘", 90)
out = rf.sub("真签名发包")
files = rf.fakepacket_save(result, out)

sigs = result.get("captured", [])
rf.step("完成", 100)
if sigs:
    rf.log(f"✓ 从抓包收割 {len(sigs)} 个真签名字段：")
    for h in sigs[:12]:
        rf.log(f"    · {h.row()}")
    rf.log("✓ 已回填到请求体")
else:
    rf.log("! 抓包里没找到签名字段 —— 检查抓的是不是验证请求那段")
rf.log(f"✓ 产物：{out}")
rf.log("  已签名请求包.json 可直接发包；发包脚本默认 DRY=1。")

if to_desktop:
    from rf.tools.desktop import drop_to_desktop
    d = drop_to_desktop(out / "假包方案报告.md")
    rf.log(f"报告已复制到桌面：{d[0].name}")
