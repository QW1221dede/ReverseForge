#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 rf.decrypt.ciphers · 常见加密算法全集（能解的都在这儿）
============================================================================

【现实情况】
    小工具、外挂、注册机、脚本保护，能用的加密其实就那么几样，
    而且作者习惯用最简单的那个：
      · 单字节 XOR（"加密"了，但一个字节就能破）
      · 循环密钥 XOR（key 通常是 4/8/16 字节，或者干脆是密码字符串）
      · RC4（短小好写，到处都是）
      · AES-ECB（连 IV 都懒得给）
      · Base64 当"加密"用（占很大比例）
      · 自定义字母表的 Base64 / 换表 ROT
      · TEA / XXTEA（游戏存档、配置常见）
      · zlib 压一下再套一层（看着像密文，其实一解就开）
    真正用 AES-256-GCM + 每文件随机盐的，反而是少数。

【本模块提供】
    纯算法，不做编排：给 data + key，就吐明文。
    自动试解、候选密钥、偏移搜索在 auto.py 里。

    所有函数统一返回 (bytes, note) 或直接 bytes，失败返回 b""，
    不抛异常 —— 自动试解要跑几千次，不能因为一个算法参数不对就崩。

【关于偏移】
    AES/RC4 对起点极其敏感，差一个字节全废。
    这里所有解密函数都接受 offset 参数，由调用方扫。
    auto.py 会自动扫 0..64，覆盖"前面加了个自定义头"的常见做法。
============================================================================
"""

from __future__ import annotations

import base64
import binascii
import bz2
import gzip
import hashlib
import lzma
import math
import struct
import zlib
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# 可选依赖：pycryptodome
# ---------------------------------------------------------------------------

try:
    from Crypto.Cipher import AES as _AES
    from Crypto.Cipher import DES as _DES
    from Crypto.Cipher import DES3 as _DES3
    from Crypto.Cipher import ChaCha20 as _ChaCha20
    HAVE_CRYPTO = True
    CRYPTO_SRC = "pycryptodome"
except Exception:                                    # pragma: no cover
    _AES = _DES = _DES3 = _ChaCha20 = None
    HAVE_CRYPTO = False
    CRYPTO_SRC = "（未安装 pycryptodome，AES/DES/ChaCha20 不可用）"


# ---------------------------------------------------------------------------
# 基础度量（避免循环导入，这里自己算一份）
# ---------------------------------------------------------------------------

def shannon(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    h = 0.0
    for c in freq:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return h


def printable(data: bytes) -> float:
    if not data:
        return 0.0
    ok = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return ok / len(data)


# 已知容器/文本头 → 解对了就得给大加分
#   强魔数（二进制容器）：见到就是铁证，直接判成功
#   弱魔数（文本结构）：{ [ < 这类单字节特征太容易撞上，
#                     必须先确认文本本身可读，否则随机垃圾也能冒充 JSON
_MAGIC_BONUS = [
    (b"PK\x03\x04", "ZIP", 45),
    (b"\x7fELF", "ELF", 45),
    (b"MZ", "PE", 42),
    (b"dex\n", "DEX", 45),
    (b"\x1f\x8b\x08", "gzip", 40),
    (b"%PDF", "PDF", 45),
    (b"SQLite format 3", "SQLite", 45),
    (b"\x89PNG", "PNG", 45),
    (b"\xff\xd8\xff", "JPEG", 45),
    (b"Rar!\x1a\x07", "RAR", 45),
    (b"7z\xbc\xaf\x27\x1c", "7z", 45),
    (b"<?xml", "XML", 12),
    (b"#!", "脚本", 15),
    (b"{", "JSON", 10),
    (b"[", "JSON 数组", 8),
    (b"<", "XML/HTML", 5),
]

# 强魔数门槛：>= 这个值才允许"光凭文件头"判定成功
STRONG_MAGIC = 40


def magic_bonus(data: bytes) -> tuple[int, str]:
    """解出来的东西如果带标准文件头，基本可以直接判定成功。"""
    if not data:
        return 0, ""
    for magic, name, bonus in _MAGIC_BONUS:
        if data.startswith(magic):
            return bonus, name
    return 0, ""


# ---------------------------------------------------------------------------
# XOR
# ---------------------------------------------------------------------------

def xor_bytes(data: bytes, key: bytes) -> bytes:
    """循环密钥 XOR（key 为空返回空）。这是最经典的"加密"。"""
    if not key or not data:
        return b""
    k = len(key)
    return bytes(b ^ key[i % k] for i, b in enumerate(data))


def xor_single(data: bytes, k: int) -> bytes:
    return bytes(b ^ (k & 0xFF) for b in data)


def xor_keysize_hamming(data: bytes, max_key: int = 40, sample: int = 2048) -> list[tuple[int, float]]:
    """
    猜循环 XOR 的密钥长度：把数据按 keylen 分块，
    相邻块之间的汉明距离越小，说明长度猜对了（同位置字节相关性高）。

    坑：真实长度 5，候选 10/15/20 的距离也一样低（都是它的整数倍）。
    所以对同分候选要偏向**更短**的那个，否则会拿到一个 20 字节的"伪密钥"，
    解出来总有几位是错的。
    """
    blob = data[:sample]
    out: list[tuple[int, float]] = []
    for k in range(1, min(max_key, len(blob) // 2) + 1):
        blocks = [blob[i * k:(i + 1) * k] for i in range(min(4, len(blob) // k))]
        if len(blocks) < 2:
            break
        dists = []
        for a, b in zip(blocks, blocks[1:]):
            d = sum(bin(x ^ y).count("1") for x, y in zip(a, b))
            dists.append(d / k)
        if dists:
            avg = sum(dists) / len(dists)
            out.append((k, avg * (1 + 0.02 * k)))     # 轻微惩罚长密钥
    out.sort(key=lambda t: t[1])
    return out


def xor_reduce_key(key: bytes) -> bytes:
    """
    把"伪密钥"缩到真实周期。
    20 字节的伪密钥里，真正独立的只有前 5 个字节，剩下的都是重复。
    """
    n = len(key)
    for p in range(1, n):
        if n % p:
            continue
        if all(key[i] == key[i % p] for i in range(n)):
            return key[:p]
    return key


def xor_break_repeating(data: bytes, keylen: int) -> tuple[bytes, bytes]:
    """
    已知密钥长度，用单列频率分析求出每个密钥字节，再整体解密。
    返回 (明文, 密钥)。
    """
    if keylen <= 0 or keylen > len(data):
        return b"", b""
    key = bytearray()
    for col in range(keylen):
        column = data[col::keylen]
        best_k, best_s = 0, -1.0
        for cand in range(256):
            dec = xor_single(column[:4096], cand)
            s = _byte_score(dec)
            if s > best_s:
                best_k, best_s = cand, s
        key.append(best_k)
    return xor_bytes(data, bytes(key)), bytes(key)


# 单字节评分用的字符频率表（英文 + 常见代码/配置符号）
_FREQ = {
    ord(" "): 0.182, ord("e"): 0.102, ord("t"): 0.075, ord("a"): 0.065,
    ord("o"): 0.061, ord("i"): 0.057, ord("n"): 0.057, ord("s"): 0.053,
    ord("h"): 0.049, ord("r"): 0.049, ord("d"): 0.034, ord("l"): 0.033,
    ord("u"): 0.022, ord("c"): 0.022, ord("m"): 0.020, ord("f"): 0.018,
    ord("w"): 0.017, ord("g"): 0.016, ord("p"): 0.015, ord("y"): 0.014,
    ord("b"): 0.012, ord("v"): 0.008, ord("k"): 0.006, ord("x"): 0.002,
    ord("j"): 0.002, ord("q"): 0.001, ord("z"): 0.001,
    ord("."): 0.010, ord(","): 0.008, ord("\n"): 0.015, ord("="): 0.006,
    ord('"'): 0.005, ord(":"): 0.004, ord("/"): 0.004, ord("_"): 0.004,
    ord("-"): 0.003, ord("("): 0.003, ord(")"): 0.003, ord("0"): 0.004,
    ord("1"): 0.004, ord("2"): 0.003, ord("{"): 0.002, ord("}"): 0.002,
}


def _byte_score(b: bytes) -> float:
    """单字节暴力时给候选明文打分：像自然语言/代码得高分。"""
    if not b:
        return -1e9
    s = 0.0
    for ch in b:
        s += _FREQ.get(ch, -0.02)
    return s / len(b)


def xor_single_bruteforce(data: bytes, top: int = 8,
                          sample: int = 4096) -> list[tuple[int, float, bytes]]:
    """256 种单字节 XOR 全试，返回 [(密钥字节, 分数, 明文)]，分数降序。"""
    blob = data[:sample]
    scored = []
    for k in range(256):
        dec = xor_single(blob, k)
        sc = _byte_score(dec) * 100
        mb, _ = magic_bonus(dec)
        # 只认强魔数；`{` 这种弱标记会让人人都是 JSON
        if mb >= STRONG_MAGIC:
            sc += mb
        scored.append((k, sc, xor_single(data, k)))
    scored.sort(key=lambda t: -t[1])
    return scored[:top]


# ---------------------------------------------------------------------------
# RC4
# ---------------------------------------------------------------------------

def rc4(data: bytes, key: bytes, drop: int = 0) -> bytes:
    """
    RC4 流密码。drop = 丢弃前 N 字节密钥流（有的实现会先跑 768/3072 轮，
    对应 drop=768/3072，遇到解出来前一段乱、后面正常时可以调这个）。
    """
    if not key or not data:
        return b""
    S = list(range(256))
    j = 0
    klen = len(key)
    for i in range(256):
        j = (j + S[i] + key[i % klen]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = j = 0
    for _ in range(drop):
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
    out = bytearray(len(data))
    for n, b in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out[n] = b ^ S[(S[i] + S[j]) & 0xFF]
    return bytes(out)


# ---------------------------------------------------------------------------
# AES / DES / ChaCha20
# ---------------------------------------------------------------------------

AES_MODES = ("ECB", "CBC", "CFB", "OFB", "CTR")


def _aes_engine(mode: str, key: bytes, iv: bytes | None):
    if not HAVE_CRYPTO:
        return None
    m = mode.upper()
    if m == "ECB":
        return _AES.new(key, _AES.MODE_ECB)
    if m == "CBC":
        return _AES.new(key, _AES.MODE_CBC, iv or b"\x00" * 16)
    if m == "CFB":
        return _AES.new(key, _AES.MODE_CFB, iv or b"\x00" * 16, segment_size=128)
    if m == "OFB":
        return _AES.new(key, _AES.MODE_OFB, iv or b"\x00" * 16)
    if m == "CTR":
        return _AES.new(key, _AES.MODE_CTR, nonce=b"",
                        initial_value=(iv or b"\x00" * 16))
    return None


def aes_decrypt(data: bytes, key: bytes, mode: str = "CBC",
                iv: bytes | None = None, unpad: bool = True) -> tuple[bytes, str]:
    """
    AES 解密。返回 (明文, 说明)。
    unpad=True 时自动尝试去填充，去不干净就把原始结果返回（让调用方自己判）。
    """
    if not HAVE_CRYPTO:
        return b"", "未安装 pycryptodome"
    try:
        c = _aes_engine(mode, key, iv)
        if c is None:
            return b"", f"不支持的 AES 模式 {mode}"
        raw = c.decrypt(data[:len(data) - len(data) % 16])
        if not raw:
            return b"", "数据不足一个分组"
        if not unpad:
            return raw, ""
        cleaned, how = unpad_bytes(raw, 16)
        if cleaned:
            return cleaned, how
        return raw, "填充不合法（可能密钥/模式不对）"
    except Exception as e:                           # noqa: BLE001
        return b"", f"{type(e).__name__}: {e}"


def aes_encrypt(data: bytes, key: bytes, mode: str = "CBC",
                iv: bytes | None = None, pad: bool = True) -> bytes:
    """AES 加密（回写/自测用）。"""
    if not HAVE_CRYPTO:
        return b""
    src = pkcs7_pad(data, 16) if pad else data
    c = _aes_engine(mode, key, iv)
    return c.encrypt(src[:len(src) - len(src) % 16]) if c else b""


def des_decrypt(data: bytes, key: bytes, mode: str = "CBC",
                iv: bytes | None = None) -> tuple[bytes, str]:
    if not HAVE_CRYPTO:
        return b"", "未安装 pycryptodome"
    try:
        k = key.ljust(8, b"\x00")[:8]
        if mode.upper() == "ECB":
            c = _DES.new(k, _DES.MODE_ECB)
        else:
            c = _DES.new(k, _DES.MODE_CBC, iv or b"\x00" * 8)
        raw = c.decrypt(data[:len(data) - len(data) % 8])
        cleaned, how = unpad_bytes(raw, 8)
        return (cleaned or raw), how
    except Exception as e:                           # noqa: BLE001
        return b"", f"{type(e).__name__}: {e}"


def triple_des_decrypt(data: bytes, key: bytes, mode: str = "CBC",
                       iv: bytes | None = None) -> tuple[bytes, str]:
    if not HAVE_CRYPTO:
        return b"", "未安装 pycryptodome"
    try:
        k = key.ljust(24, b"\x00")[:24]
        if len(set(k)) == 1:
            return b"", "3DES 密钥退化成全同字节，跳过"
        if mode.upper() == "ECB":
            c = _DES3.new(k, _DES3.MODE_ECB)
        else:
            c = _DES3.new(k, _DES3.MODE_CBC, iv or b"\x00" * 8)
        raw = c.decrypt(data[:len(data) - len(data) % 8])
        cleaned, how = unpad_bytes(raw, 8)
        return (cleaned or raw), how
    except Exception as e:                           # noqa: BLE001
        return b"", f"{type(e).__name__}: {e}"


def chacha20_decrypt(data: bytes, key: bytes, nonce: bytes | None = None) -> tuple[bytes, str]:
    """ChaCha20（pycryptodome 的实现是 8 字节 nonce 起步的老接口）。"""
    if not HAVE_CRYPTO:
        return b"", "未安装 pycryptodome"
    try:
        k = key.ljust(32, b"\x00")[:32]
        c = _ChaCha20.new(key=k, nonce=(nonce or b"\x00" * 8)[:8].ljust(8, b"\x00"))
        return c.decrypt(data), ""
    except Exception as e:                           # noqa: BLE001
        return b"", f"{type(e).__name__}: {e}"


# ---------------------------------------------------------------------------
# TEA / XTEA / XXTEA（游戏存档、配置、老工具爱用）
# ---------------------------------------------------------------------------

_DELTA = 0x9E3779B9


def _u32(b: bytes, little: bool = True) -> list[int]:
    fmt = ("<" if little else ">") + "%dI" % (len(b) // 4)
    return list(struct.unpack(fmt, b[:len(b) // 4 * 4]))


def _p32(v: list[int], little: bool = True) -> bytes:
    fmt = ("<" if little else ">") + "%dI" % len(v)
    return struct.pack(fmt, *[x & 0xFFFFFFFF for x in v])


def tea_decrypt(data: bytes, key: bytes, rounds: int = 32, little: bool = True) -> bytes:
    """TEA（64 位分组）。"""
    if len(data) < 8:
        return b""
    fmt = ("<" if little else ">") + "2I"
    kfmt = ("<" if little else ">") + "4I"
    k = struct.unpack(kfmt, key.ljust(16, b"\x00")[:16])
    out = bytearray()
    for i in range(0, len(data) - len(data) % 8, 8):
        v0, v1 = struct.unpack(fmt, data[i:i + 8])
        s = (_DELTA * rounds) & 0xFFFFFFFF
        for _ in range(rounds):
            v1 = (v1 - ((((v0 << 4) + k[2]) & 0xFFFFFFFF) ^ ((v0 + s) & 0xFFFFFFFF)
                        ^ (((v0 >> 5) + k[3]) & 0xFFFFFFFF))) & 0xFFFFFFFF
            v0 = (v0 - ((((v1 << 4) + k[0]) & 0xFFFFFFFF) ^ ((v1 + s) & 0xFFFFFFFF)
                        ^ (((v1 >> 5) + k[1]) & 0xFFFFFFFF))) & 0xFFFFFFFF
            s = (s - _DELTA) & 0xFFFFFFFF
        out += struct.pack(fmt, v0, v1)
    return bytes(out)


def xtea_decrypt(data: bytes, key: bytes, rounds: int = 32, little: bool = True) -> bytes:
    """XTEA（TEA 的修正版，轮函数不同）。"""
    if len(data) < 8:
        return b""
    fmt = ("<" if little else ">") + "2I"
    kfmt = ("<" if little else ">") + "4I"
    k = struct.unpack(kfmt, key.ljust(16, b"\x00")[:16])
    out = bytearray()
    for i in range(0, len(data) - len(data) % 8, 8):
        v0, v1 = struct.unpack(fmt, data[i:i + 8])
        s = (_DELTA * rounds) & 0xFFFFFFFF
        for _ in range(rounds):
            v1 = (v1 - (((((v0 << 4) & 0xFFFFFFFF) ^ (v0 >> 5))
                         + v0) & 0xFFFFFFFF) ^ ((s + k[(s >> 11) & 3]) & 0xFFFFFFFF)) & 0xFFFFFFFF
            s = (s - _DELTA) & 0xFFFFFFFF
            v0 = (v0 - (((((v1 << 4) & 0xFFFFFFFF) ^ (v1 >> 5))
                         + v1) & 0xFFFFFFFF) ^ ((s + k[s & 3]) & 0xFFFFFFFF)) & 0xFFFFFFFF
        out += struct.pack(fmt, v0, v1)
    return bytes(out)


def xxtea_encrypt(data: bytes, key: bytes, little: bool = True) -> bytes:
    """XXTEA 加密（自测与"回写"用，算法与 decrypt 严格对称）。"""
    if len(data) < 8:
        return b""
    v = _u32(data, little)
    n = len(v)
    if n < 2:
        return b""
    k = _u32(key.ljust(16, b"\x00")[:16], little)
    rounds = 6 + 52 // n
    total = 0
    z = v[n - 1]
    while rounds > 0:
        total = (total + _DELTA) & 0xFFFFFFFF
        e = (total >> 2) & 3
        for p in range(n - 1):
            y = v[p + 1]
            mx = ((((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) & 0xFFFFFFFF) \
                ^ ((total ^ y) + (k[(p & 3) ^ e] ^ z) & 0xFFFFFFFF)
            v[p] = (v[p] + mx) & 0xFFFFFFFF
            z = v[p]
        y = v[0]
        mx = ((((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) & 0xFFFFFFFF) \
            ^ ((total ^ y) + (k[((n - 1) & 3) ^ e] ^ z) & 0xFFFFFFFF)
        v[n - 1] = (v[n - 1] + mx) & 0xFFFFFFFF
        z = v[n - 1]
        rounds -= 1
    return _p32(v, little)


def xxtea_decrypt(data: bytes, key: bytes, little: bool = True) -> bytes:
    """
    XXTEA（变长分组，最常用于存档/配置）。
    解完会自动检查前 4 字节是否是"原始长度"——XXTEA 的常见做法。
    """
    if len(data) < 8:
        return b""
    n = len(data) // 4
    v = _u32(data, little)
    if len(v) < 2:
        return b""
    n = len(v)
    k = _u32(key.ljust(16, b"\x00")[:16], little)
    rounds = 6 + 52 // n
    total = (rounds * _DELTA) & 0xFFFFFFFF
    y = v[0]
    while total:
        e = (total >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            mx = ((((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) & 0xFFFFFFFF) \
                ^ ((total ^ y) + (k[(p & 3) ^ e] ^ z) & 0xFFFFFFFF)
            v[p] = (v[p] - mx) & 0xFFFFFFFF
            y = v[p]
        z = v[n - 1]
        mx = ((((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) & 0xFFFFFFFF) \
            ^ ((total ^ y) + (k[0 ^ e] ^ z) & 0xFFFFFFFF)
        v[0] = (v[0] - mx) & 0xFFFFFFFF
        y = v[0]
        total = (total - _DELTA) & 0xFFFFFFFF

    out = _p32(v, little)
    # 常见长度头
    for endian in ("<", ">"):
        ln = struct.unpack(endian + "I", out[:4])[0]
        if 0 < ln <= len(out) - 4 and ln >= 1:
            cand = out[4:4 + ln]
            if printable(cand[:64]) > 0.85:
                return cand
    return out


# ---------------------------------------------------------------------------
# 编码层：Base64 / Base32 / Base85 / Hex
# ---------------------------------------------------------------------------

def b64_decode_any(data: bytes | str) -> tuple[bytes, str]:
    """
    Base64 全家桶：标准 / URL-safe / 缺填充 / 中间带换行 / 自定义字母表。
    返回 (解出的字节, 说明)。自定义字母表放在 auto.py 里做全排列（太贵，这里不试）。
    """
    if isinstance(data, bytes):
        try:
            s = data.decode("ascii").strip()
        except UnicodeDecodeError:
            return b"", "含非 ASCII 字节，不是 Base64"
    else:
        s = data.strip()
    s = "".join(s.split())
    if len(s) < 8:
        return b"", "太短"
    s2 = s.replace("-", "+").replace("_", "/").rstrip("=")
    if not s2:
        return b"", "空"
    for name, fn in (("标准", base64.b64decode), ("URL-safe", base64.urlsafe_b64decode)):
        for pad in ("", "=" * (-len(s2) % 4)):
            try:
                out = fn(s2 + pad)
            except (binascii.Error, ValueError):
                continue
            if out:
                return out, f"Base64（{name}{'，补填充' if pad else ''}）"
    return b"", "Base64 解码失败"


def b32_decode_any(data: bytes | str) -> tuple[bytes, str]:
    try:
        s = (data if isinstance(data, str) else data.decode("ascii")).strip()
        s = "".join(s.split()).upper().rstrip("=")
        for pad in ("", "=" * (-len(s) % 8)):
            try:
                out = base64.b32decode(s + pad)
                return out, "Base32"
            except (binascii.Error, ValueError):
                continue
    except (UnicodeDecodeError, ValueError):
        pass
    return b"", ""


def b85_decode_any(data: bytes | str) -> tuple[bytes, str]:
    try:
        s = data if isinstance(data, bytes) else data.encode("ascii", "ignore")
        for fn, name in ((base64.b85decode, "Base85(b85)"), (base64.a85decode, "Base85(ascii85)")):
            try:
                out = fn(s)
                if out:
                    return out, name
            except Exception:                        # noqa: BLE001
                continue
    except Exception:                                # noqa: BLE001
        pass
    return b"", ""


def hex_decode_any(data: bytes | str) -> tuple[bytes, str]:
    try:
        s = (data if isinstance(data, str) else data.decode("ascii")).strip()
        s = "".join(s.split())
        if len(s) >= 8 and len(s) % 2 == 0:
            return bytes.fromhex(s), "十六进制"
    except (UnicodeDecodeError, ValueError):
        pass
    return b"", ""


# ---------------------------------------------------------------------------
# 换表 / 简单位移
# ---------------------------------------------------------------------------

def rot(data: bytes, n: int = 13) -> bytes:
    """对字母做 ROT-n，其余字节不动。"""
    out = bytearray(data)
    for i, b in enumerate(out):
        if 65 <= b <= 90:
            out[i] = (b - 65 + n) % 26 + 65
        elif 97 <= b <= 122:
            out[i] = (b - 97 + n) % 26 + 97
    return bytes(out)


def atbash(data: bytes) -> bytes:
    out = bytearray(data)
    for i, b in enumerate(out):
        if 65 <= b <= 90:
            out[i] = 90 - (b - 65)
        elif 97 <= b <= 122:
            out[i] = 122 - (b - 97)
    return bytes(out)


def caesar_all(data: bytes, top: int = 3) -> list[tuple[int, bytes]]:
    """25 种凯撒位移，按可打印率排序。"""
    scored = [(n, rot(data, n)) for n in range(1, 26)]
    scored.sort(key=lambda t: -_byte_score(t[1][:2048]))
    return scored[:top]


# ---------------------------------------------------------------------------
# 填充
# ---------------------------------------------------------------------------

def pkcs7_pad(data: bytes, block: int = 16) -> bytes:
    n = block - len(data) % block
    return data + bytes([n]) * n


def unpad_bytes(data: bytes, block: int = 16) -> tuple[bytes, str]:
    """
    自动判断是哪种填充并去掉：
      PKCS#7 / Zero（\\x00 补齐）/ Space / ANSI X.923
    返回 (去填充后的数据, 用了哪种)。判不出来返回 ("", "")。
    """
    if not data:
        return b"", ""
    # PKCS#7
    n = data[-1]
    if 1 <= n <= block and data.endswith(bytes([n]) * n):
        return data[:-n], f"PKCS#7（去 {n} 字节）"
    # ANSI X.923：末尾 n 字节，前面全 0
    if 1 <= n <= block and data[-n:-1] == b"\x00" * (n - 1):
        return data[:-n], f"ANSI X.923（去 {n} 字节）"
    # 零填充
    stripped = data.rstrip(b"\x00")
    if len(stripped) >= len(data) - block and stripped:
        return stripped, "零填充"
    # 空格填充
    stripped = data.rstrip(b" ")
    if len(stripped) >= len(data) - block and stripped:
        return stripped, "空格填充"
    return b"", ""


# ---------------------------------------------------------------------------
# 压缩层（很多"加密"其实是压缩）
# ---------------------------------------------------------------------------

def decompress_auto(data: bytes) -> tuple[bytes, str]:
    """zlib / gzip / bz2 / lzma / raw deflate 全试一遍。"""
    if not data:
        return b"", ""
    for wbits, name in ((zlib.MAX_WBITS, "zlib"), (-zlib.MAX_WBITS, "raw deflate"),
                        (zlib.MAX_WBITS | 16, "gzip")):
        try:
            out = zlib.decompress(data, wbits)
            if out:
                return out, name
        except zlib.error:
            continue
    try:
        out = bz2.decompress(data)
        if out:
            return out, "bzip2"
    except (OSError, ValueError):
        pass
    try:
        out = lzma.decompress(data)
        if out:
            return out, "lzma/xz"
    except (lzma.LZMAError, OSError, ValueError):
        pass
    try:
        out = gzip.decompress(data)
        if out:
            return out, "gzip"
    except (OSError, ValueError):
        pass
    return b"", ""


# ---------------------------------------------------------------------------
# 密钥派生
# ---------------------------------------------------------------------------

def key_variants(text: str, size: int = 16) -> list[tuple[bytes, str]]:
    """
    把一段"密钥字符串"变成实际可用的字节密钥。
    作者写 key="abc123" 时，实际用法可能是：
      原文补齐 / MD5 / SHA256 截断 / hex 解 / base64 解
    全给出来，让自动试解去撞。
    """
    out: list[tuple[bytes, str]] = []
    if not text:
        return out
    raw = text.encode("utf-8", "ignore")
    b = raw.ljust(size, b"\x00")[:size]
    out.append((b, "原文补齐"))
    out.append((hashlib.md5(raw).digest(), "MD5"))
    out.append((hashlib.sha256(raw).digest()[:size], "SHA256 截断"))
    hx, _ = hex_decode_any(text)
    if hx and len(hx) >= 8:
        out.append((hx.ljust(size, b"\x00")[:size], "hex 解码"))
    b64, _ = b64_decode_any(text)
    if b64 and len(b64) >= 8:
        out.append((b64.ljust(size, b"\x00")[:size], "base64 解码"))
    # 去重
    seen, uniq = set(), []
    for k, how in out:
        if k in seen:
            continue
        seen.add(k)
        uniq.append((k, how))
    return uniq


# ---------------------------------------------------------------------------
# OpenSSL 格式（Salted__ 头）——真实文件里最常见的一种
# ---------------------------------------------------------------------------

def evp_bytes_to_key(password: bytes, salt: bytes,
                     key_len: int = 32, iv_len: int = 16) -> tuple[bytes, bytes]:
    """
    OpenSSL `enc` 命令用的密钥派生（EVP_BytesToKey + MD5）。
    这是"密码 + 文件"格式的事实标准，AES/DES 都走这套。
    """
    d = b""
    prev = b""
    while len(d) < key_len + iv_len:
        prev = hashlib.md5(prev + password + salt).digest()
        d += prev
    return d[:key_len], d[key_len:key_len + iv_len]


def openssl_decrypt(data: bytes, password: bytes | str,
                    key_len: int = 32) -> tuple[bytes, str]:
    """
    解 `openssl enc -aes-256-cbc -salt` 产生的文件。
    格式：`Salted__` + 8 字节盐 + 密文。
    """
    if isinstance(password, str):
        password = password.encode("utf-8", "ignore")
    if len(data) < 32 or not data.startswith(b"Salted__"):
        return b"", "不是 OpenSSL Salted 格式"
    salt = data[8:16]
    body = data[16:]
    key, iv = evp_bytes_to_key(password, salt, key_len, 16)
    raw, note = aes_decrypt(body, key, "CBC", iv, unpad=False)
    if not raw:
        return b"", note
    cleaned, how = unpad_bytes(raw, 16)
    return (cleaned or raw), f"OpenSSL AES-{key_len * 8}-CBC（{how or '未去填充'}）"


# ---------------------------------------------------------------------------
# 能力自检
# ---------------------------------------------------------------------------

def profile() -> dict:
    return {
        "pycryptodome": HAVE_CRYPTO,
        "source": CRYPTO_SRC,
        "aes": HAVE_CRYPTO,
        "des": HAVE_CRYPTO,
        "chacha20": HAVE_CRYPTO,
        "xor": True, "rc4": True, "tea": True, "xtea": True, "xxtea": True,
        "base64": True, "base32": True, "base85": True, "hex": True,
        "compress": True,
    }
