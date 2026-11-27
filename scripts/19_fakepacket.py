#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @name 假包方案（骗服务器验证）
# @desc 解密出来的片段自动串成线索 → 判定协议 → 生成假请求/假响应/发包时序
# @param target 文件或解包目录 [file]
# @param to_desktop 报告复制到桌面 [bool:false]

"""
用法：
    先跑「12 任意文件画像」和「13 自动解密」把明文挖出来，
    再把文件或解包目录丢进来。脚本自动做三件事：

      ① 提线索：URL / 卡密字段 / 状态码 / 签名方式 / 设备证书 / 心跳 / 成功文案
      ② 判协议：T3 卡密验证 / 通用 HTTP 鉴权 / 本地缓存判定，带置信度
      ③ 造假包：假请求包 + 假响应包 + 发包时序 + 发包脚本（DRY=1 默认只打印）

    和解密是同一套流程：不靠猜，每条线索带证据；不确定的如实写占位符。

    产出：假包方案/**（报告 / 假包 / 发包脚本）
"""

from pathlib import Path

target = Path(target)
if not target.exists():
    raise RuntimeError(f"路径不存在：{target}")

rf.step("假包管线", 8)
result = rf.fakepacket_build(target)

protos = result["protocols"]
packs = result["packets"]

rf.step("落盘", 88)
out = rf.sub("假包方案")
files = rf.fakepacket_save(result, out)

rf.step("完成", 100)
if protos:
    p = protos[0]
    rf.log(f"✓ 判定：{p.name}（置信 {p.confidence}%）")
    rf.log(f"  发到：{p.endpoint}")
    rf.log(f"  什么时候发：{p.timing}")
    rf.log(f"  怎么算成功：{p.success_rule}")
    if len(protos) > 1:
        rf.log(f"  备选方案：{len(protos) - 1} 个（见报告）")
rf.log(f"✓ 假包 {len(packs)} 个：")
for pk in packs:
    rf.log(f"    · {pk.name}　{pk.note}")
rf.log(f"✓ 报告：{out / '假包方案报告.md'}")
rf.log("  报告第五节是「明文线索图」：二进制里藏的中文/URL/字段全列出来了，"
       "不用自己拿十六进制工具翻。")
rf.log("  发包脚本默认 DRY=1（只打印不发送），确认字段后再去掉。")

if to_desktop:
    from rf.tools.desktop import drop_to_desktop
    d = drop_to_desktop(out / "假包方案报告.md")
    rf.log(f"报告已复制到桌面：{d[0].name}")
