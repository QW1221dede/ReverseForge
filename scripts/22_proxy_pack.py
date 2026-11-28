#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @name 网络层劫持·透明代理（壳里打不动时用）
# @desc 请求照真发到服务器、响应改写后回给程序，真签名真数据全程录像
# @param target 目标文件（ELF / makeself .sh） [file]
# @param mode proxy=转发真服务器并改写响应，mock=不外连直接回成功 [choice:proxy,mock:proxy]
# @param port 本地监听端口 [int:18888]
# @param out 输出目录（留空则放「proxy」目录下） [str:]

"""
网络层劫持页的引擎。

什么时候用这个：
    卡密闸门在 UPX / VMProtect 壳里，静态补丁改不到（改了会崩）。

它干什么：
    ① 生成 rf_hook.so（AArch64，NDK 交叉编译）
    ② hook connect/getaddrinfo/gethostbyname，把外连导到本地
    ③ proxy 模式：请求原样发给真服务器 → 响应把失败标志原地改成通过 → 回给程序
       同时把服务器原始响应录进 rf_capture.log（真签名、真数据都在里面）
    ④ mock 模式：不外连，任何请求都回成功 JSON

给的程序物：
    假包包/
      rf_hook.so      注入用
      rf_hook.conf    模式/端口/抓包路径/回落 JSON
      run.sh          启动器（导出 LD_PRELOAD 再跑原样本）
      使用说明.txt
      <原样本>         原封不动

拿到抓包之后：
    python -m rf.fakepacket.capture rf_capture.log        看真签名
    python -m rf.fakepacket.replay_http rf_capture.log code=xxx   让服务器改口
"""

from pathlib import Path

from rf.fakepacket import hijack

target = Path(target)
if not target.exists():
    raise RuntimeError("目标不存在。先把文件拖到左上投放区。")

mode = str(mode or "proxy").strip().lower()
if mode not in ("proxy", "mock"):
    mode = "proxy"

out = Path(out) if out else rf.sub("proxy")
out.mkdir(parents=True, exist_ok=True)

# ---- ① 先判断该走哪条路 -------------------------------------------------
rf.step("① 判断策略", 15)
d = hijack.decide(target)
info = d.get("detail", {}).get("analyze", {})
rf.log(f"  加壳类型：{info.get('shell', '?')}")
rf.log(f"  网络客户端：{'有（自实现 HTTP）' if info.get('net_client') else '没发现'}")
if info.get("domains"):
    rf.log(f"  疑似域名：{', '.join(info['domains'][:4])}")
rf.log(f"  策略：{d.get('strategy')}")
for r in d.get("reasons", []):
    rf.log("    · " + r)

if d.get("strategy") == "static_patch":
    rf.log("")
    rf.log("  这个样本明文可补，静态补丁更干净（无运行时开销）。")
    rf.log("  建议直接用「全自动化」页，那里会先试静态补丁。")
    rf.log("  仍要生成网络层包也可以——继续往下走。")

# ---- ② 生成运行包 -------------------------------------------------------
rf.step("② 生成运行包（编译 .so）", 45)
dst = out / "假包包"
b = hijack.build_bundle(target, dst, mode=mode, port=int(port or 18888))
for line in b.text().splitlines():
    rf.log(line)
if not b.ok:
    raise RuntimeError("生成失败：" + b.error)

# ---- ③ 后续怎么用 -------------------------------------------------------
rf.step("③ 交付", 90)
rf.log("")
rf.log("  拷到手机后：")
rf.log("    chmod +x run.sh")
rf.log("    sh run.sh")
rf.log("")
if mode == "proxy":
    rf.log("  跑完把抓包取回来（/data/local/tmp/rf_capture.log），然后：")
    rf.log("    python -m rf.fakepacket.capture rf_capture.log")
    rf.log("    → 真实服务器地址、请求/响应原文、真签名、卡密字段")
    rf.log("")
    rf.log("  服务器没认这次请求的话，改字段让它改口：")
    rf.log("    python -m rf.fakepacket.replay_http rf_capture.log code=<值> --dry-run")
    rf.log("    python -m rf.fakepacket.replay_http rf_capture.log code=<值>")
else:
    rf.log("  mock 模式：不外连，任何请求都回成功，程序能启动就走完。")

rf.log("")
rf.log(f"  产物目录：{dst}")
rf.log("✓ 网络层假包已生成")
