#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @name 本机强加密实测
# @desc 真跑 AES-256-GCM / ChaCha20 / HMAC / PBKDF2 / scrypt 往返并计时
# @param payload_kb 测试数据量 KB [int:256]
# @param seal 额外做一次加密落盘+回读 [bool:true]

"""
这不是 mock：
    每个算法都真的加密一段随机数据、真的解密、逐字节比对；
    还会故意篡改一个字节，确认认证标签能拒绝。

产出：
    crypto_selftest.json   本机实测结果
    sealed_demo.bin        加密信封（口令随机生成，仅本次有效）
"""

import json
import os
import secrets
from pathlib import Path

from rf.secure import crypto as C

rf.step("能力探测", 5)
prof = C.profile()
for k, v in prof.items():
    rf.log(f"{k}: {v}")

if not prof["aes_gcm"]:
    rf.log("⚠ 没有 pycryptodome，AES 不可用；HMAC/PBKDF2 仍可测")

rf.step("真实往返测试", 30)
rep = C.selftest(payload_kb=int(payload_kb))

rf.log("")
rf.log(f"{'算法':<28}{'耗时':>12}  结果")
for case in rep["cases"]:
    algo = case.get("算法", "?")
    cost = (case.get("含派生加密ms") or case.get("耗时ms") or "-")
    rf.log(f"{algo:<28}{str(cost):>12}  {case.get('结果', '')}")
    if "吞吐MB/s" in case:
        rf.log(f"{'':<28}{case['吞吐MB/s']:>10} MB/s")

out = rf.out_dir / "crypto_selftest.json"
out.write_text(json.dumps(rep, ensure_ascii=False, indent=2), encoding="utf-8")
rf.log(f"✓ 结果：{out}")

if seal:
    rf.step("加密落盘 + 回读", 75)
    pw = secrets.token_urlsafe(24)
    payload = {
        "note": "ReverseForge 加密信封演示",
        "size": len(os.urandom(1024)),
        "items": ["LicenseManager.verify", "isExpired"],
    }
    p = C.seal_json(payload, pw, rf.out_dir / "sealed_demo.bin")
    back = C.open_json(p, pw)
    ok = back == payload
    rf.log(f"{'✓' if ok else '✗'} 回读{'一致' if ok else '不一致'}：{p} "
           f"（{rf.size(p)} 字节）")
    rf.log("口令只存在于本次运行内存中，没有写盘")
    if not ok:
        raise RuntimeError("加密信封回读不一致")

rf.step("完成", 100)
rf.note("结论", "全部通过" if rep["ok"] else "有算法未通过，见上方明细")
