#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @name 真机内卡密收割
# @desc 用破解版内卡密让程序真跑一次，把设备现算的真签名自动收回来
# @param target 文件或解包目录（用来挖卡密/包名） [file]
# @param serial 设备序列号（空 = 唯一设备） [str:]
# @param package 应用包名（空 = 从样本里猜） [str:]
# @param card 内卡密（空 = 自动从样本里挖） [str:]
# @param seconds 让程序跑多久（秒） [int:25]
# @param capture 已有抓包/日志文件（给了就直接离线解析，不需要设备） [str:]
# @param to_desktop 报告复制到桌面 [bool:false]

"""
为什么需要这一页
-----------------
T3 这类平台的签名 = 设备私钥对明文 SHA256 的签名，私钥在手机 keystore 里，
样本里没有。静态造包只能造出「结构对、签名假」的包 → 服务器回「错误的调用」。

唯一实路（用户提的路线）：
    用破解版自带的有效卡密 → 让程序跑起来 → 它自己会发一次带真签名的包
    → 我们在旁边把 (明文, 签名) 收下来 → 回填到假包 → 之后就能以合法身份发。

三条通道：
    ① frida（推荐）：拦 OkHttp/HttpURLConnection 的请求与响应，同时拦
       Signature.initSign / sign 与 Mac.doFinal，设备替我们签任意明文。
    ② logcat：零依赖兜底，只捞程序自己打印的 url/token/sign。
    ③ 离线：手机抓包（mitmproxy/Charles/VPN）存成文件，用 capture 参数喂进来。

没有设备 / 没装 frida，报告里会如实写「未执行」，不会冒充成功。

产物：假包方案/**（报告 / 已签名请求包.json / 已签名请求头.json / 真机收割.py）
"""

from pathlib import Path

target = Path(target)
if not target.exists():
    raise RuntimeError(f"路径不存在：{target}")

rf.step("真机收割", 10)
out = rf.sub("真机收割")
result = rf.fakepacket_live(str(target), serial=str(serial or ""),
                            package=str(package or ""), card=str(card or ""),
                            seconds=int(seconds or 25),
                            capture_log=(str(capture) if capture else None),
                            out_dir=out)

rep = result.get("live")
sigs = result.get("captured", [])

rf.step("完成", 100)
if rep is not None:
    rf.log(f"模式：{rep.mode or '未执行'}")
    for name, ok, detail in rep.steps:
        rf.log(f"  {'✓' if ok else '×'} {name}" + (f" —— {detail}" if detail else ""))
    if rep.note:
        rf.log(f"结论：{rep.note}")

if sigs:
    rf.log(f"✓ 收割 {len(sigs)} 个签名字段：")
    for h in sigs[:10]:
        rf.log(f"    · {h.row()}")
    rf.log(f"✓ 已回填：{out / '已签名请求包.json'}")
else:
    rf.log("! 没收到签名 —— 先确认程序确实跑到了验证那一步")
    rf.log("  没装 frida 时只能靠 logcat，签名基本抓不到；建议 pip install frida-tools")
rf.log(f"✓ 独立脚本：{out / '真机收割.py'}（改完参数可直接在别的机器跑）")
rf.log("  也可用 capture 参数喂手机抓包，不需要设备就能离线收割。")

if to_desktop:
    from rf.tools.desktop import drop_to_desktop
    d = drop_to_desktop(out / "真机收割报告.md")
    rf.log(f"报告已复制到桌面：{d[0].name}")
