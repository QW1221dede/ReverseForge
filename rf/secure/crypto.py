#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 rf.secure · 本机高强度加密
============================================================================

用途有三个，都是这个工具真需要的：

  1) 把补丁配方 / 密钥清单 / 扫描结果落盘时加密（seal / open）
     —— 这些东西落到明文里，等于把"怎么绕过"写在便签上。
  2) 校验特征里遇到加密常量时，能自己复算做对照（HMAC / SHA / AES）
  3) 给脚本一块"拿来就能用"的强加密积木，而不是让用户去抄网上
     那些 ECB + 固定 IV 的错误示范

算法选择（全部是业界现役、无自创）：
  AES-256-GCM          对称加密 + 认证（默认，硬件 AES-NI 加速）
  ChaCha20-Poly1305    无 AES 硬件时的等价选择
  HMAC-SHA256          完整性 / 签名比对
  PBKDF2-HMAC-SHA512   口令派生（60 万轮，OWASP 2023 建议量级）
  scrypt               内存硬派生（抗 GPU）
  SHA-256              文件摘要

【重要】没有 pycryptodome 时 AES/ChaCha 不可用，但 HMAC/PBKDF2/scrypt/SHA
仍然可用（标准库）。profile() 会如实报告，绝不假装加密成功。
============================================================================
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:                                   # 可选依赖
    from Crypto.Cipher import AES as _AES
    from Crypto.Cipher import ChaCha20_Poly1305 as _CHACHA
    _HAS_PYCRYPTODOME = True
except Exception:                      # pragma: no cover
    _AES = None                        # type: ignore[assignment]
    _CHACHA = None                     # type: ignore[assignment]
    _HAS_PYCRYPTODOME = False

MAGIC = b"RFSEAL1\x00"
PBKDF2_ROUNDS = 600_000
NONCE_LEN = 12
TAG_LEN = 16


class CryptoError(Exception):
    """加密/解密失败（消息为中文，可直接展示）。"""


@dataclass
class Sealed:
    """加密信封：算法、参数、密文全在里头，自包含。"""
    alg: str
    kdf: str
    rounds: int
    salt: bytes
    nonce: bytes
    ciphertext: bytes
    tag: bytes = b""
    aad: bytes = b""

    def to_bytes(self) -> bytes:
        head = {
            "alg": self.alg, "kdf": self.kdf, "rounds": self.rounds,
            "salt": base64.b64encode(self.salt).decode(),
            "nonce": base64.b64encode(self.nonce).decode(),
            "tag": base64.b64encode(self.tag).decode(),
            "aad": base64.b64encode(self.aad).decode(),
        }
        hj = json.dumps(head, ensure_ascii=False, sort_keys=True).encode("utf-8")
        return MAGIC + len(hj).to_bytes(4, "big") + hj + self.ciphertext

    @classmethod
    def from_bytes(cls, blob: bytes) -> "Sealed":
        if not blob.startswith(MAGIC):
            raise CryptoError("不是本工具的加密信封（缺少 RFSEAL 标识）")
        off = len(MAGIC)
        if len(blob) < off + 4:
            raise CryptoError("信封被截断")
        hlen = int.from_bytes(blob[off:off + 4], "big")
        off += 4
        try:
            head = json.loads(blob[off:off + hlen].decode("utf-8"))
        except Exception as e:
            raise CryptoError(f"信封头损坏：{e}") from e
        return cls(
            alg=head["alg"], kdf=head["kdf"], rounds=int(head["rounds"]),
            salt=base64.b64decode(head["salt"]),
            nonce=base64.b64decode(head["nonce"]),
            tag=base64.b64decode(head.get("tag", "")),
            aad=base64.b64decode(head.get("aad", "")),
            ciphertext=blob[off + hlen:],
        )


# ---------------------------------------------------------------------------
# 能力
# ---------------------------------------------------------------------------

def profile() -> dict:
    """本机能用什么，如实报告。"""
    return {
        "aes_gcm": _HAS_PYCRYPTODOME,
        "chacha20_poly1305": _HAS_PYCRYPTODOME,
        "hmac_sha256": True,
        "pbkdf2_sha512": True,
        "scrypt": hasattr(hashlib, "scrypt"),
        "sha256": True,
        "source": "pycryptodome" if _HAS_PYCRYPTODOME else "stdlib-only",
        "python": os.sys.version.split()[0],
    }


def _need_aes() -> None:
    if not _HAS_PYCRYPTODOME:
        raise CryptoError("缺少 pycryptodome，AES/ChaCha 不可用；"
                          "执行 pip install pycryptodome 后重试")


# ---------------------------------------------------------------------------
# 口令派生
# ---------------------------------------------------------------------------

def derive_key(password: str | bytes, salt: bytes, *, alg: str = "pbkdf2",
               rounds: int = PBKDF2_ROUNDS, length: int = 32) -> bytes:
    pw = password.encode("utf-8") if isinstance(password, str) else password
    if not salt or len(salt) < 16:
        raise CryptoError("salt 至少 16 字节")
    if alg == "scrypt":
        if not hasattr(hashlib, "scrypt"):
            raise CryptoError("当前 Python 不支持 scrypt")
        return hashlib.scrypt(pw, salt=salt, n=2 ** 15, r=8, p=1,
                              dklen=length, maxmem=64 * 1024 * 1024)
    if alg != "pbkdf2":
        raise CryptoError(f"未知派生算法：{alg}")
    return hashlib.pbkdf2_hmac("sha512", pw, salt, max(10_000, rounds), dklen=length)


# ---------------------------------------------------------------------------
# 对称加密
# ---------------------------------------------------------------------------

def encrypt(plaintext: bytes, password: str, *, alg: str = "aes-gcm",
            kdf: str = "pbkdf2", aad: bytes = b"") -> Sealed:
    """加密并认证。每次随机 salt + nonce，绝不复用。"""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    salt = secrets.token_bytes(16)
    key = derive_key(password, salt, alg=kdf)
    nonce = secrets.token_bytes(NONCE_LEN)
    actual = alg

    if alg in ("aes-gcm", "aes256-gcm"):
        _need_aes()
        if not _HAS_PYCRYPTODOME:           # 逻辑上到不了，防御性写法
            raise CryptoError("AES 不可用")
        c = _AES.new(key, _AES.MODE_GCM, nonce=nonce, mac_len=TAG_LEN)
        if aad:
            c.update(aad)
        ct, tag = c.encrypt_and_digest(plaintext)
        actual = "aes-256-gcm"
    elif alg in ("chacha20-poly1305", "chacha"):
        _need_aes()
        c = _CHACHA.new(key=key, nonce=nonce)
        if aad:
            c.update(aad)
        ct, tag = c.encrypt_and_digest(plaintext)
        actual = "chacha20-poly1305"
    else:
        raise CryptoError(f"未知算法：{alg}")

    return Sealed(alg=actual, kdf=kdf, rounds=PBKDF2_ROUNDS if kdf == "pbkdf2" else 0,
                  salt=salt, nonce=nonce, ciphertext=ct, tag=tag, aad=aad)


def decrypt(env: Sealed, password: str) -> bytes:
    """解密并验证认证标签；口令错、密文被改，都会明确报错。"""
    key = derive_key(password, env.salt, alg=env.kdf, rounds=env.rounds or PBKDF2_ROUNDS)
    try:
        if env.alg == "aes-256-gcm":
            _need_aes()
            c = _AES.new(key, _AES.MODE_GCM, nonce=env.nonce, mac_len=TAG_LEN)
            if env.aad:
                c.update(env.aad)
            return c.decrypt_and_verify(env.ciphertext, env.tag)
        if env.alg == "chacha20-poly1305":
            _need_aes()
            c = _CHACHA.new(key=key, nonce=env.nonce)
            if env.aad:
                c.update(env.aad)
            return c.decrypt_and_verify(env.ciphertext, env.tag)
    except ValueError as e:
        raise CryptoError("解密失败：口令错误或数据被篡改（认证标签不匹配）") from e
    raise CryptoError(f"未知算法：{env.alg}")


# ---------------------------------------------------------------------------
# 摘要 / 签名
# ---------------------------------------------------------------------------

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def hmac_sign(data: bytes | str, key: str | bytes, *, alg: str = "sha256") -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    if isinstance(key, str):
        key = key.encode("utf-8")
    return hmac.new(key, data, getattr(hashlib, alg)).hexdigest()


def hmac_verify(data: bytes | str, key: str | bytes, tag: str,
                *, alg: str = "sha256") -> bool:
    """常数时间比较，避免时序侧信道。"""
    expect = hmac_sign(data, key, alg=alg)
    return hmac.compare_digest(expect, (tag or "").strip().lower())


# ---------------------------------------------------------------------------
# 便捷：加密存 JSON
# ---------------------------------------------------------------------------

def seal_json(obj: Any, password: str, path: str | Path,
              *, alg: str = "aes-gcm") -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8")
    env = encrypt(raw, password, alg=alg, aad=p.name.encode("utf-8"))
    p.write_bytes(env.to_bytes())
    return p


def open_json(path: str | Path, password: str) -> Any:
    p = Path(path)
    blob = p.read_bytes()
    env = Sealed.from_bytes(blob)
    raw = decrypt(env, password)
    return json.loads(raw.decode("utf-8"))


# ---------------------------------------------------------------------------
# 实测（不是 mock：真的加密、真的解密、真的比对耗时）
# ---------------------------------------------------------------------------

def selftest(rounds: int = 3, payload_kb: int = 64) -> dict:
    """
    跑一遍真实往返，返回每个算法的耗时与结论。

    这是"直接上实测"那条要求的落点：报告里的数字来自本机这次运行，
    换台机器跑出来的数会不一样，所以不允许写死。
    """
    payload = os.urandom(payload_kb * 1024)
    out: dict = {"profile": profile(), "cases": [], "ok": True}

    def run(name: str, fn_enc, fn_dec, verify) -> None:
        nonlocal out
        t0 = time.perf_counter()
        try:
            env = fn_enc()
            enc_ms = (time.perf_counter() - t0) * 1000
            t1 = time.perf_counter()
            back = fn_dec(env)
            dec_ms = (time.perf_counter() - t1) * 1000
            good = back == payload and verify(env)
            # 注意：这里的耗时包含 PBKDF2 派生（60 万轮，约 0.4s），
            # 所以"整链路吞吐"看起来很低，不代表 AES 本身慢。
            mb = payload_kb / 1024
            out["cases"].append({
                "算法": name, "含派生加密ms": round(enc_ms, 2),
                "含派生解密ms": round(dec_ms, 2),
                "整链路MB/s": round(mb / max(enc_ms / 1000, 1e-6), 2),
                "结果": "通过" if good else "数据不一致",
            })
            out["ok"] = out["ok"] and good
        except CryptoError as e:
            out["cases"].append({"算法": name, "结果": f"不可用：{e}"})
        except Exception as e:                       # pragma: no cover
            out["ok"] = False
            out["cases"].append({"算法": name, "结果": f"异常：{type(e).__name__}: {e}"})

    pw = "rf-selftest-" + secrets.token_hex(4)

    if _HAS_PYCRYPTODOME:
        run("AES-256-GCM",
            lambda: encrypt(payload, pw, alg="aes-gcm"),
            lambda e: decrypt(e, pw),
            lambda e: e.alg == "aes-256-gcm" and len(e.tag) == TAG_LEN)
        run("ChaCha20-Poly1305",
            lambda: encrypt(payload, pw, alg="chacha20-poly1305"),
            lambda e: decrypt(e, pw),
            lambda e: e.alg == "chacha20-poly1305")

    # 认证失败必须被拒绝 —— 这条比"能加密"更重要
    if _HAS_PYCRYPTODOME:
        env = encrypt(b"tamper-me", pw, alg="aes-gcm")
        env.ciphertext = bytes([env.ciphertext[0] ^ 0xFF]) + env.ciphertext[1:]
        try:
            decrypt(env, pw)
            out["cases"].append({"算法": "篡改检测", "结果": "失败：改过的密文竟然解开了"})
            out["ok"] = False
        except CryptoError:
            out["cases"].append({"算法": "篡改检测", "结果": "通过（拒绝了解密）"})

    # 纯密码吞吐：密钥已派生，排除 KDF 干扰，看的才是 AES 本身的速度
    if _HAS_PYCRYPTODOME:
        key = secrets.token_bytes(32)
        big = os.urandom(4 * 1024 * 1024)
        t0 = time.perf_counter()
        c = _AES.new(key, _AES.MODE_GCM, nonce=secrets.token_bytes(NONCE_LEN))
        ct, tag = c.encrypt_and_digest(big)
        ms = (time.perf_counter() - t0) * 1000
        out["cases"].append({
            "算法": "AES-256-GCM 纯加密 4MB",
            "耗时ms": round(ms, 1),
            "吞吐MB/s": round(4 / max(ms / 1000, 1e-6), 1),
            "结果": "通过" if len(ct) == len(big) and len(tag) == TAG_LEN else "异常",
        })

    # HMAC / 派生（标准库，必定可测）    t0 = time.perf_counter()
    tag = hmac_sign(payload, pw)
    ok_hmac = hmac_verify(payload, pw, tag) and not hmac_verify(payload + b"x", pw, tag)
    out["cases"].append({"算法": "HMAC-SHA256",
                         "耗时ms": round((time.perf_counter() - t0) * 1000, 3),
                         "结果": "通过" if ok_hmac else "不一致"})
    out["ok"] = out["ok"] and ok_hmac

    t0 = time.perf_counter()
    k1 = derive_key(pw, b"0123456789abcdef", rounds=50_000)
    k2 = derive_key(pw, b"0123456789abcdef", rounds=50_000)
    same = k1 == k2 and len(k1) == 32
    out["cases"].append({"算法": "PBKDF2-HMAC-SHA512(5万轮)",
                         "耗时ms": round((time.perf_counter() - t0) * 1000, 1),
                         "结果": "通过" if same else "派生不稳定"})
    out["ok"] = out["ok"] and same

    if hasattr(hashlib, "scrypt"):
        t0 = time.perf_counter()
        s1 = hashlib.scrypt(b"pw", salt=b"0123456789abcdef", n=2 ** 14, r=8, p=1, dklen=32)
        out["cases"].append({"算法": "scrypt(n=2^14)",
                             "耗时ms": round((time.perf_counter() - t0) * 1000, 1),
                             "结果": "通过" if len(s1) == 32 else "异常"})
    return out


if __name__ == "__main__":
    rep = selftest()
    for c in rep["cases"]:
        print(c)
    print("总体:", "通过" if rep["ok"] else "失败")
