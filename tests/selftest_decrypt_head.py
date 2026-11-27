#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 tests/selftest_decrypt_head.py · 大段明文头 + 加密体自测
============================================================================

    模拟真实外挂形态：前面一大段中文注释/Python 代码（含 KEY = '...'），
    后面跟加密配置体。覆盖弱加密 12 种 + 中等加密 5 种。

    验收线：弱加密 100%，中等加密 >= 80%，总破解率 >= 90%。

    这是回归测试 —— 任何改动导致破解率下降，这里会红。
============================================================================
"""
from __future__ import annotations

import base64
import codecs
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from rf.decrypt import auto, ciphers as C, keys as K
from rf.analysis import segments

FAILED: list[str] = []
PLAIN = (b'{"user":"admin","card":"123456","vip":true,"expire":"2099-12-31",'
         b'"note":"this is the license payload for testing"}')
KEY_WEAK = "pass1234"
KEY_MID = "0123456789abcdef"
HEAD = (
    "# -*- coding: utf-8 -*-\n"
    "# 外挂配置加载器 v3.2 - 内部版本，请勿外传\n"
    "# 说明：本文件负责校验用户卡密并加载核心模块。\n"
    "# 联系方式：m358685@163.com\n\n"
    "import os, sys, json, base64, hashlib\n"
    "from datetime import datetime\n\n"
    "APP_NAME = 'X-提权者'\n"
    f"KEY = '{KEY_WEAK}'\n"
    f"AES_KEY = '{KEY_MID}'\n"
    "IV = '0000000000000000'\n\n"
    "def log(msg):\n"
    "    print('[%s] %s' % (datetime.now(), msg))\n\n"
    "def check_env():\n"
    "    log('checking environment')\n"
    "    return sys.version_info >= (3, 8)\n\n"
    "# 下面是加密配置段\n"
) * 2

_DELTA = 0x9E3779B9


def tea_enc(data: bytes, key: bytes) -> bytes:
    """标准 TEA 加密（与 ciphers.tea_decrypt 对称）。"""
    out, fmt = bytearray(), "<2I"
    k = struct.unpack("<4I", key.ljust(16, b"\x00")[:16])
    for i in range(0, len(data) - len(data) % 8, 8):
        v0, v1 = struct.unpack(fmt, data[i:i + 8])
        s = 0
        for _ in range(32):
            s = (s + _DELTA) & 0xFFFFFFFF
            v0 = (v0 + ((((v1 << 4) + k[0]) & 0xFFFFFFFF) ^ ((v1 + s) & 0xFFFFFFFF)
                        ^ (((v1 >> 5) + k[1]) & 0xFFFFFFFF))) & 0xFFFFFFFF
            v1 = (v1 + ((((v0 << 4) + k[2]) & 0xFFFFFFFF) ^ ((v0 + s) & 0xFFFFFFFF)
                        ^ (((v0 >> 5) + k[3]) & 0xFFFFFFFF))) & 0xFFFFFFFF
        out += struct.pack(fmt, v0, v1)
    return bytes(out)


def check(name: str, cond: bool, extra: str = "") -> None:
    mark = "✓" if cond else "✗"
    print(f"  {mark} {name}" + (f"  [{extra}]" if extra else ""))
    if not cond:
        FAILED.append(name)


def wrap(kind: str, body: bytes) -> bytes:
    if kind == "raw":
        return body
    if kind == "b64":
        return base64.b64encode(body)
    if kind == "hex":
        return body.hex().encode()
    return body


def run_case(label: str, blob: bytes, kind: str, key: str | None,
             tail_pre: bytes = b"", budget: float = 14.0, category: str = "weak") -> bool:
    body = wrap(kind, blob)
    sep = b"\n\n" + tail_pre if tail_pre else b"\n\n"
    data = HEAD.encode() + sep + body
    sm = segments.analyze(data)
    cands = ([K.KeyCand(value=key, source="测试显式提供", score=95)] if key else [])
    t = time.time()
    rep = auto.salvage(data, key_cands=cands or None, budget=budget)
    ok = bool(rep.hits) and any(PLAIN in h.out for h in rep.hits)
    detail = rep.hits[0].method[:45] if rep.hits else rep.summary()[:45]
    check(f"[{category}] {label}", ok,
          f"{time.time() - t:.1f}s split={sm.split.found} · {detail}")
    return ok


print("=== 大段明文头 + 加密体（外挂形态）===")
print(f"头部 {len(HEAD.encode())}B，明文 {len(PLAIN)}B\n")

print("-- 弱加密（要求 100%）--")
kw = KEY_WEAK.encode()
weak = [
    ("单字节XOR·裸字节", C.xor_bytes(PLAIN, b"\x5a"), "raw", None, b""),
    ("单字节XOR·base64", C.xor_bytes(PLAIN, b"\x5a"), "b64", None, b""),
    ("单字节XOR·hex", C.xor_bytes(PLAIN, b"\x5a"), "hex", None, b""),
    ("循环XOR·裸字节", C.xor_bytes(PLAIN, kw), "raw", KEY_WEAK, b""),
    ("循环XOR·base64", C.xor_bytes(PLAIN, kw), "b64", KEY_WEAK, b""),
    ("密钥XOR·裸字节", C.xor_bytes(PLAIN, kw), "raw", KEY_WEAK, b""),
    ("RC4·裸字节", C.rc4(PLAIN, kw), "raw", KEY_WEAK, b""),
    ("RC4·base64", C.rc4(PLAIN, kw), "b64", KEY_WEAK, b""),
    ("RC4-drop768", C.rc4(PLAIN, kw, drop=768), "raw", KEY_WEAK, b""),
    ("ROT13·base64", codecs.encode(PLAIN.decode("ascii"), "rot_13").encode(), "b64", None, b""),
    ("base64+标记前缀", C.xor_bytes(PLAIN, b"\x5a"), "b64", None, b"ENCRYPTED_DATA="),
    ("base64+引号包裹", C.xor_bytes(PLAIN, kw), "b64", KEY_WEAK, b'DATA = "'),
]
weak_ok = sum(run_case(*c, category="weak") for c in weak)

print("\n-- 中等加密（要求 >= 80%）--")
km = KEY_MID.encode()
iv0 = b"\x00" * 16
inner = struct.pack("<I", len(PLAIN)) + PLAIN
inner += b"\x00" * ((-len(inner)) % 4)
mid = [
    ("AES-128-ECB", C.aes_encrypt(PLAIN, km, "ECB"), "raw", KEY_MID, b""),
    ("AES-128-CBC·IV0", C.aes_encrypt(PLAIN, km, "CBC", iv0), "raw", KEY_MID, b""),
    ("AES-128-CBC·IV前置", iv0 + C.aes_encrypt(PLAIN, km, "CBC", iv0), "raw", KEY_MID, b""),
    ("AES-128-CBC·base64", C.aes_encrypt(PLAIN, km, "CBC", iv0), "b64", KEY_MID, b""),
    ("TEA", tea_enc(PLAIN + b"\x00" * ((-len(PLAIN)) % 8), km), "raw", KEY_MID, b""),
    ("XXTEA", C.xxtea_encrypt(inner, km), "raw", KEY_MID, b""),
]
mid_ok = sum(run_case(*c, category="mid") for c in mid)

print(f"\n弱加密 {weak_ok}/{len(weak)}，中等加密 {mid_ok}/{len(mid)}，"
      f"总 {weak_ok + mid_ok}/{len(weak) + len(mid)}")
check("弱加密破解率 100%", weak_ok == len(weak),
      f"{weak_ok}/{len(weak)}")
check("中等加密破解率 >= 80%", mid_ok >= len(mid) * 0.8,
      f"{mid_ok}/{len(mid)}")
check("总破解率 >= 90%", weak_ok + mid_ok >= (len(weak) + len(mid)) * 0.9)

if FAILED:
    print(f"\n失败 {len(FAILED)} 项：" + "、".join(FAILED))
    sys.exit(1)
print("\n全部通过")
