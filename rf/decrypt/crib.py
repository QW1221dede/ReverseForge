#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 rf.decrypt.crib · 已知明文攻击（crib-drag）与密钥流复用
============================================================================

【为什么需要这一层】
    暴力试解有随机性：猜密钥长度、按列做频率分析，都可能差几位。
    但真实文件有一个确定的弱点 —— **明文格式是已知的**：
      · JSON 一定以 `{` 或 `[{` 开头
      · XML 一定以 `<?xml` 开头
      · ZIP/APK 一定以 `PK\\x03\\x04` 开头
      · PE 一定以 `MZ` 开头
      · 自己的配置文件可能以 `#`、`[`、`key=` 开头
    只要知道开头几个字节，XOR 类加密就**直接算出密钥流**，不需要猜。

【原理（一句话）】
    cipher[i] = plain[i] ^ key[i mod p]
    ⇒ key[i mod p] = cipher[i] ^ plain[i]
    已知 plain 的前 L 个字节，就拿到密钥流的前 L 个字节；
    如果 L ≥ 密钥长度 p，整个密钥就到手了，全文可解。

    从恢复出的密钥流里找最小周期，就是密钥本身。

【能解什么 / 不能解什么】
    能：循环 XOR（任意长度密钥）、单字节 XOR、带简单头的 XOR 变体
    不能：AES/RC4 这类真加密 —— 它们的密钥流不重复，
          crib 只能验证"猜对了"，不能反推密钥。这点必须说清楚。

【密钥流复用】
    同一条密钥流加密了两段明文时：
        c1 ^ c2 = p1 ^ p2
    在 c1^c2 上做 crib-drag，可以同时读出两边的片段。
    这是"多-time pad"的经典破法，比单个文件可解性强得多。
============================================================================
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

# 常见明文开头（按出现频率排）。长度 ≥3 才有足够辨识度
DEFAULT_CRIBS: list[bytes] = [
    b'{"', b'[{', b'{"v', b'<?xml', b'PK\x03\x04', b'MZ',
    b'{"user"', b'{"card"', b'{"key"', b'{"data"',
    b'{"code"', b'{"status"', b'{"msg"', b'{"result"',
    b'{\r\n', b'{\n', b'# ', b'key=', b'[conf', b'{"license"',
    b'{"password"', b'{"token"', b'{"name"', b'{"id"',
    b'"card"', b'"vip"', b'"expire"', b'"data"',
]


@dataclass
class CribHit:
    key: bytes = b""
    period: int = 0
    offset: int = 0
    crib: bytes = b""
    plain: bytes = b""
    score: int = 0
    note: str = ""


# ---------------------------------------------------------------------------
# 从恢复出的密钥流里找最小周期
# ---------------------------------------------------------------------------

def find_period(ks: bytes, max_period: int = 64) -> int:
    """
    找密钥流的最小周期。
    允许极少量不匹配（明文猜错一两个字节、或文件尾部有噪声），
    容错上限是 5%，超过就不认。
    """
    n = len(ks)
    for p in range(1, min(max_period, n) + 1):
        bad = 0
        tol = max(0, int((n - p) * 0.05))
        for i in range(p, n):
            if ks[i] != ks[i % p]:
                bad += 1
                if bad > tol:
                    break
        else:
            return p
    return 0


def derive_key(ks: bytes, period: int) -> bytes:
    """按周期取多数投票，抗一点点噪声。"""
    if period <= 0:
        return ks
    out = bytearray()
    for i in range(period):
        votes: dict[int, int] = {}
        for j in range(i, len(ks), period):
            votes[ks[j]] = votes.get(ks[j], 0) + 1
        out.append(max(votes.items(), key=lambda kv: kv[1])[0] if votes else 0)
    return bytes(out)


# ---------------------------------------------------------------------------
# 主攻击
# ---------------------------------------------------------------------------

def _candidate_periods(ks: bytes, max_period: int) -> list[int]:
    """
    从恢复出的密钥流片段推候选周期。

    坑：片段只有 4 字节时，任何 4 字节都能"自洽"，p=4 必然成立 ——
    如果拿它当结论，就会循环论证（用 crib 推出的密钥当然能让 crib 出现）。
    所以：片段 ≤4 字节时只认 p=L（当作完整密钥试一把），
    不假装能推断出更短的周期。验证交给调用方：**只看 crib 之外的区域**。
    """
    n = len(ks)
    if n <= 4:
        return [n]
    out: list[int] = []
    for p in range(1, min(max_period, n) + 1):
        bad = 0
        tol = max(0, int((n - p) * 0.02))
        for i in range(p, n):
            if ks[i] != ks[i % p]:
                bad += 1
                if bad > tol:
                    break
        else:
            out.append(p)
    return out or [n]


def _complete_key(data: bytes, off: int, ks: bytes, period: int) -> bytes:
    """
    周期大于已知密钥流长度时，用频率分析补全未知位置。

    crib 只给了 L 个字节的密钥流，真实周期 p 可能 > L（例如 7 字节 crib、
    8 字节密钥）。_candidate_periods 只认 p<=L 的自洽周期，于是 p=8 被漏掉。
    这里换个思路：对 p 的每个位置 j，收集密文中所有 i%p==j 的字节，
    已知位置用 crib 的约束，未知位置试 256 种密钥取"解密后最像英文"的。
    """
    key = bytearray(period)
    # 先填已知约束
    for i, k in enumerate(ks):
        key[i % period] = k
    # 频率补全（英文/JSON 里空格 e t a o 最常见）
    freq = b" etaoinshrdlcumwfgypbvkjxqz"
    for j in range(period):
        if j < len(ks):                      # 已被 crib 约束
            continue
        col = [data[off + i] for i in range(j, len(data) - off, period)
               if off + i < len(data)]
        if not col:
            key[j] = 0
            continue
        best_k, best_score = 0, -1e9
        for k in range(256):
            plaintext = [b ^ k for b in col]
            # 英文字符 + 常见 JSON 符号得分高，控制字符/高位字节扣分
            sc = sum((3 if c in (32, 34, 58, 44, 125) else
                      2 if 97 <= c <= 122 or 65 <= c <= 90 else
                      1 if 48 <= c <= 57 else
                      -3 if c < 32 or c > 126 else 0) for c in plaintext)
            if sc > best_score:
                best_score, best_k = sc, k
        key[j] = best_k
    return bytes(key)


def crib_attack(data: bytes, cribs: list[bytes] | None = None,
                offsets: list[int] | None = None,
                max_period: int = 64,
                scorer=None,
                min_rest_printable: float = 0.85) -> list[CribHit]:
    """
    已知明文攻击。返回按得分降序的候选。

    **验证方式**：只看 crib 覆盖范围**之外**的输出。
    因为用 crib 反推出的密钥，必然让 crib 本身正确出现在那个位置，
    拿它当验证等于自己证明自己（第一版就栽在这儿，所有结果都是 100 分）。

    所以真正的判据是：用这个密钥解出来的**其余部分**也得像人话。
    这只有密钥猜对了才可能发生。
    """
    if not data or len(data) < 12:
        return []
    use_cribs = list(cribs or DEFAULT_CRIBS)
    offs = list(dict.fromkeys(offsets or [0]))
    hits: list[CribHit] = []
    seen: set[bytes] = set()

    for off in offs:
        if off < 0 or off >= len(data) - 8:
            continue
        for crib in use_cribs:
            L = len(crib)
            if L < 3 or off + L > len(data):
                continue
            ks = bytes(a ^ b for a, b in zip(data[off:off + L], crib))

            periods = _candidate_periods(ks, max_period)
            # 补全：真实周期可能长于 crib（7字节crib + 8字节密钥）。
            # 只试常见密钥长度，且必须 >= L；全试 L+1..32 会拖垮时间预算。
            for p in (8, 12, 16, 24, 32, 6, 10, 20):
                if L < p <= max_period and p not in periods:
                    periods.append(p)
            for p in periods:
                if p <= L:
                    key = derive_key(ks, p)
                else:
                    key = _complete_key(data, off, ks, p)
                plain = _decrypt_all(data, key, off, p)

                # —— 关键：把 crib 覆盖的那一段剔掉再判 ——
                outside = plain[:off] + plain[off + L:]
                if len(outside) < 8:
                    continue
                rest = outside[:8192]
                pr = sum(1 for b in rest if 32 <= b < 127 or b in (9, 10, 13)) / len(rest)
                if pr < min_rest_printable:
                    continue

                sc = scorer(outside) if scorer else int(pr * 100)
                if sc < 45:
                    continue

                sig = hashlib.sha256(plain[:2048]).digest()
                if sig in seen:
                    continue
                seen.add(sig)

                hits.append(CribHit(
                    key=key, period=p, offset=off, crib=crib, plain=plain,
                    score=sc,
                    note=(f"已知明文 {crib[:8]!r}@{off} 反推密钥 "
                          f"{key.hex()}（{p} 字节）")))

    hits.sort(key=lambda h: -h.score)
    return hits


def _decrypt_all(data: bytes, key: bytes, offset: int, period: int) -> bytes:
    """
    用恢复的密钥解全文。
    注意相位：crib 在 offset 处命中的是 key[0]，所以 data[offset] 对应 key[0]，
    往前的位置要用负相位回推。
    """
    if not key:
        return b""
    n = len(key)
    out = bytearray(data)
    for i in range(len(data)):
        out[i] = data[i] ^ key[(i - offset) % n]
    return bytes(out)


def _decrypt_strict(data: bytes, ks: bytes, offset: int) -> bytes:
    """没有确认周期时，只用已知密钥流覆盖它自己的范围，其余保持原样。"""
    out = bytearray(data)
    for i, k in enumerate(ks):
        j = offset + i
        if j < len(data):
            out[j] = data[j] ^ k
    return bytes(out)


# ---------------------------------------------------------------------------
# 密钥流复用（many-time pad）
# ---------------------------------------------------------------------------

@dataclass
class ReuseFragment:
    offset: int = 0
    crib: bytes = b""
    other: bytes = b""       # 另一段明文在这个位置的片段
    printable: float = 0.0


def keystream_reuse(c1: bytes, c2: bytes, cribs: list[bytes] | None = None,
                    max_report: int = 20) -> list[ReuseFragment]:
    """
    两段密文用了同一条密钥流时的 crib-drag：
        c1 ^ c2 = p1 ^ p2
    假设 p1 在某处是 crib，就能算出 p2 同位置的片段。

    真实用途：同一个程序里加密了两份配置、或者版本 A/B 的同一文件。
    能读出片段就能反推密钥流，进而解全文（需要更多明文假设）。
    """
    use = list(cribs or DEFAULT_CRIBS)
    n = min(len(c1), len(c2))
    if n < 8:
        return []
    x = bytes(a ^ b for a, b in zip(c1[:n], c2[:n]))
    out: list[ReuseFragment] = []

    for off in range(0, n):
        for crib in use:
            L = len(crib)
            if off + L > n:
                continue
            frag = bytes(a ^ b for a, b in zip(x[off:off + L], crib))
            pr = sum(1 for b in frag if 32 <= b < 127) / L
            if pr >= 0.9:
                out.append(ReuseFragment(offset=off, crib=crib,
                                         other=frag, printable=pr))
                break
        if len(out) >= max_report:
            break
    return out
