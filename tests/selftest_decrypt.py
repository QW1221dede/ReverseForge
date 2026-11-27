#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 tests/selftest_decrypt.py · 解密层自测（造样本真跑，不 mock）
============================================================================

    每组样本都用**真实加密**生成，再看自动试解能不能撞回来。
    判据不是"跑完了"，而是"解出来的内容与原文逐字节相同"。

    [1] 编码层：Base64 / Hex / zlib
    [2] 单字节 XOR
    [3] 循环密钥 XOR（密钥不在明文头里，靠频率分析破）
    [4] 密钥 XOR（密钥写在明文头里）
    [5] RC4
    [6] AES-256-CBC（IV 全 0 / IV 前置两种布局）
    [7] AES-256-ECB
    [8] OpenSSL Salted（口令）
    [9] 明文头 + 密文（最容易误判的混合文件）
    [10] XXTEA
    [11] 真·随机密文（必须老实报"解不出来"）
============================================================================
"""

from __future__ import annotations

import json
import os
import struct
import sys
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rf.analysis import garble, segments
from rf.decrypt import auto, ciphers as C, keys as K

OUT = Path(__file__).resolve().parent.parent / "_test_out" / "decrypt"
OUT.mkdir(parents=True, exist_ok=True)

PLAIN = (b'{"user":"admin","card":"123456","vip":true,"expire":"2099-12-31",'
         b'"note":"this is the license payload for testing"}')
FAILED: list[str] = []


def check(name: str, cond: bool, extra: str = "") -> None:
    mark = "✓" if cond else "✗"
    print(f"  {mark} {name}" + (f"  [{extra}]" if extra else ""))
    if not cond:
        FAILED.append(name)


def run(name: str, blob: bytes, expect_in: bytes = PLAIN, budget: float = 20.0,
        cands=None) -> object:
    p = OUT / f"{name}.bin"
    p.write_bytes(blob)
    rep = auto.salvage(p, key_cands=cands, budget=budget)
    hit = rep.best
    print(f"  · {name}: {rep.summary()}")
    if hit:
        print(f"    方法 {hit.method} 偏移 {hit.offset} 得分 {hit.score} "
              f"预览 {hit.preview[:50]!r}")
    ok = bool(hit) and expect_in in hit.out
    check(f"{name} 解出原文", ok,
          "" if ok else (hit.method if hit else "无结果"))
    return rep


def section(n: str, title: str) -> None:
    print(f"[{n}] {title}")


# ---------------------------------------------------------------------------
section("1", "编码层（Base64 / Hex / zlib）")
import base64
run("b64", base64.b64encode(PLAIN))
run("b64_multi", base64.b64encode(base64.b64encode(PLAIN)))
run("hex", PLAIN.hex().encode())
run("zlib", zlib.compress(PLAIN, 9))

# ---------------------------------------------------------------------------
section("2", "单字节 XOR")
run("xor_single", C.xor_single(PLAIN, 0x5A))

# ---------------------------------------------------------------------------
section("3", "循环密钥 XOR（无提示，靠频率分析破）")
big = (PLAIN + b" " + (b"the license key is correct and the card is accepted " * 20))
run("xor_repeat", C.xor_bytes(big[:520], b"Kx9mQ"))

# ---------------------------------------------------------------------------
section("4", "密钥 XOR（密钥写在明文头里）")
head = b"# encrypted config\nkey = \"hunter2key\"\nmode = xor\n\n"
run("xor_head_key", head + C.xor_bytes(big[:600], b"hunter2key"))

# ---------------------------------------------------------------------------
section("5", "RC4")
run("rc4", C.rc4(big[:600], b"123456"))

# ---------------------------------------------------------------------------
section("6", "AES-256-CBC")
key32 = b"0123456789abcdef0123456789abcdef"
zero_iv = b"\x00" * 16
KEYCAND = [K.KeyCand(value=key32.decode(), source="测试显式提供", kind="string", score=90)]

# 没有密钥线索的密文：数学上解不开，必须老实报失败
enc_bare = C.aes_encrypt(PLAIN * 3, key32, "CBC", zero_iv)
p_bare = OUT / "aes_cbc_no_key.bin"
p_bare.write_bytes(enc_bare)
rep_bare = auto.salvage(p_bare, budget=8)
print(f"  · aes_cbc_no_key: {rep_bare.summary()}")
check("无密钥时不谎报成功",
      not (rep_bare.best and rep_bare.best.score >= 62),
      f"最高分 {rep_bare.best.score if rep_bare.best else 0}")

# 显式给密钥 → 必须解出来
enc = C.aes_encrypt(PLAIN * 3, key32, "CBC", zero_iv)
rep = auto.salvage(enc, key_cands=KEYCAND, budget=20)
check("AES-CBC（IV=0，显式密钥）解出",
      bool(rep.best) and PLAIN in rep.best.out,
      rep.best.method if rep.best else "无结果")

# IV 前置
iv = b"fedcba9876543210"
enc2 = iv + C.aes_encrypt(PLAIN * 3, key32, "CBC", iv)
rep = auto.salvage(enc2, key_cands=KEYCAND, budget=20)
check("AES-CBC（IV 前置）解出",
      bool(rep.best) and PLAIN in rep.best.out,
      rep.best.method if rep.best else "无结果")

# 带明文头，头里写 key 和 iv（最真实的形态）
head2 = (b"config:\n  cipher: aes-256-cbc\n  key: \"fedcba9876543210fedcba9876543210\"\n"
         b"  iv: \"fedcba9876543210\"\n\n")
enc3 = C.aes_encrypt(PLAIN * 3, b"fedcba9876543210fedcba9876543210", "CBC", iv)
run("aes_head_key_iv", head2 + enc3, budget=25)

# ---------------------------------------------------------------------------
section("7", "AES-256-ECB")
rep = auto.salvage(C.aes_encrypt(PLAIN * 3, key32, "ECB"), key_cands=KEYCAND, budget=20)
check("AES-ECB 解出", bool(rep.best) and PLAIN in rep.best.out,
      rep.best.method if rep.best else "无结果")

# ---------------------------------------------------------------------------
section("8", "OpenSSL Salted（口令 123456）")
salt = b"\x01\x02\x03\x04\x05\x06\x07\x08"
k_, iv_ = C.evp_bytes_to_key(b"123456", salt, 32, 16)
body = C.aes_encrypt(PLAIN * 2, k_, "CBC", iv_)
run("openssl_salted", b"Salted__" + salt + body)

# ---------------------------------------------------------------------------
section("9", "明文头 + 密文（混合文件）")
head = b"# encrypted config\nkey = \"pass1234\"\nmode = rc4\n\n"
mixed = head + C.rc4(big[:700], b"pass1234")
p = OUT / "mixed.bin"
p.write_bytes(mixed)
sm = segments.analyze(mixed)
print(f"  · 分段：{sm.split.brief()}")
check("分界落在明文头末尾", sm.split.found and sm.split.head_len == len(head),
      f"head={sm.split.head_len} 期望={len(head)}")
rep = auto.salvage(p, budget=20)
check("混合文件解出原文", bool(rep.best) and PLAIN in rep.best.out,
      rep.best.method if rep.best else "无结果")

# ---------------------------------------------------------------------------
section("10", "XXTEA")
inner = big[:500]
data16 = struct.pack("<I", len(inner)) + inner
data16 = data16.ljust((len(data16) + 3) // 4 * 4, b"\x00")
encx = C.xxtea_encrypt(data16, b"1234567890123456")
check("XXTEA 加解密对称", C.xxtea_decrypt(encx, b"1234567890123456") == inner,
      f"{len(encx)}B")
rep = auto.salvage(encx, key_cands=[
    K.KeyCand(value="1234567890123456", source="测试显式提供", score=90)], budget=15)
check("XXTEA 自动试解", bool(rep.best) and inner[:80] in rep.best.out,
      rep.best.method if rep.best else "无结果")

# ---------------------------------------------------------------------------
section("11", "真随机密文（必须老实说解不出来）")
rand = os.urandom(4096)
p = OUT / "random.bin"
p.write_bytes(rand)
rep = auto.salvage(p, budget=8)
print(f"  · 结果：{rep.summary()}")
check("不乱报成功", not (rep.best and rep.best.score >= 62),
      f"最高分 {rep.best.score if rep.best else 0}")

# ---------------------------------------------------------------------------
section("12", "乱码判定")
g = garble.diagnose(PLAIN.decode())
check("正常文本判 clean", g.kind == garble.G_CLEAN, g.kind)
broken = "这是一段中文配置，密钥是 abc".encode("utf-8").decode("latin1")
g2 = garble.diagnose(broken)
check("Latin-1 乱码能识别并修复", g2.kind == garble.G_MOJIBAKE and "中文" in g2.fixed,
      f"{g2.kind}/{g2.fixed_by}")
pua = "".join(chr(0xE000 + i % 200) for i in range(300))
g3 = garble.diagnose(pua)
check("私有区判字体加密", g3.kind == garble.G_PUA, g3.kind)

# ---------------------------------------------------------------------------
section("13", "已知明文攻击（确定性，不靠猜）")
from rf.decrypt import crib as CR

# 短密钥：靠 3-4 字节 crib 就能反推
enc2b = C.xor_bytes(PLAIN, b"AB")
h2 = CR.crib_attack(enc2b, offsets=[0], scorer=auto.score_output)
check("2 字节密钥被 crib 攻破", any(PLAIN in h.plain for h in h2),
      f"{len(h2)} 个候选")
# 长密钥：默认 crib 不够长时**不能**谎报，但用户给格式就能解
enc12 = C.xor_bytes(PLAIN, b"SECRET123456")
h12 = CR.crib_attack(enc12, offsets=[0], scorer=auto.score_output)
check("12 字节密钥不乱报", not any(PLAIN in h.plain for h in h12),
      f"{len(h12)} 个候选")
h12b = CR.crib_attack(enc12, cribs=[PLAIN[:20]], offsets=[0],
                      scorer=auto.score_output)
check("给出已知明文后可解 12 字节密钥",
      bool(h12b) and PLAIN in h12b[0].plain and h12b[0].key == b"SECRET123456",
      h12b[0].key if h12b else "无")
# 密钥流复用：两段密文异或后能读出对方片段
a1 = b'{"user":"admin","vip":true}'
a2 = b'{"user":"guest","vip":false}'
c1, c2 = C.xor_bytes(a1, b"STREAMKEY"), C.xor_bytes(a2, b"STREAMKEY")
fr = CR.keystream_reuse(c1, c2, cribs=[b'{"user":"admin"'])
check("密钥流复用能读出另一段片段", bool(fr), f"{len(fr)} 段")

# ---------------------------------------------------------------------------
print()
if FAILED:
    print(f"失败 {len(FAILED)} 项：")
    for f in FAILED:
        print("  ✗", f)
    sys.exit(1)
print("全部通过")
