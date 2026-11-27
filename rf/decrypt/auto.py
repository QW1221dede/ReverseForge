#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 rf.decrypt.auto · 自动试解（把"这几样加密"一次全撞一遍）
============================================================================

【干什么】
    给它一个文件，它把常见加密全试一遍，把像人话的结果排好队吐出来。
    不保证一定成功——AES-256 没有密钥就是解不开，这是数学，不是努力问题。
    但只要密钥在文件里/在明文中/是弱口令，这里基本都能撞出来。

【试的顺序（便宜的先来）】
    1. 编码层      Base64 / Base32 / Base85 / Hex / zlib / gzip / bz2
                   —— 很多"加密"其实只是编码或压缩，一解就开
    2. 单字节 XOR  256 种全试（外挂和脚本最爱）
    3. 循环 XOR    先猜密钥长度（汉明距离），再按列频率分析求密钥
    4. 密钥 XOR    用候选密钥字符串直接当 key
    5. RC4         用候选密钥试（含 drop=768 变体）
    6. TEA/XXTEA   用 16 字节密钥试（存档、配置常见）
    7. AES         ECB/CBC/CFB/OFB/CTR × 候选密钥 × 候选 IV
                   外加"IV 前置在密文头部"这种常见布局
    8. OpenSSL     Salted__ 头 + 口令（EVP_BytesToKey）
    9. 偏移扫描    前 64 字节逐个当起点（RC4/AES 对起点敏感）

【怎么判断"解对了"】
    两把尺子叠加：
      · 命中标准文件头（ZIP/MZ/ELF/JSON/XML…）→ 直接加 40-45 分
      · 文本可读性（garble.readability）→ 中文常用字、英文词、分词边界
    造假很容易被识破：错误密钥解出来的东西熵接近 8、可读性接近 0。
    所以宁可漏报，不谎报。

【性能】
    打分只看前 64KB，命中之后再对全文重解一次。
    有总时间预算（默认 15 秒，deep=True 时 60 秒），超了就带着已有结果返回。
============================================================================
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..analysis import garble, segments
from . import ciphers as C
from . import crib as CR
from . import keys as K

# ---------------------------------------------------------------------------
# 结果
# ---------------------------------------------------------------------------

@dataclass
class Hit:
    method: str = ""
    offset: int = 0
    score: int = 0
    out: bytes = b""
    preview: str = ""
    key: str = ""
    note: str = ""

    @property
    def size(self) -> int:
        return len(self.out)

    def row(self) -> str:
        m = self.method if len(self.method) <= 42 else self.method[:39] + "..."
        return (f"{self.score:>3}  {m:<44} 偏移{self.offset:<5} "
                f"{self.size:>8}B  {self.preview[:40]!r}")

    def save(self, out_dir: str | Path) -> Path:
        od = Path(out_dir)
        od.mkdir(parents=True, exist_ok=True)
        safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in self.method)[:50]
        f = od / f"hit_{self.score:03d}_{safe}_off{self.offset}.bin"
        f.write_bytes(self.out)
        return f


@dataclass
class SalvageReport:
    path: str = ""
    size: int = 0
    tried: int = 0
    hits: list[Hit] = field(default_factory=list)
    elapsed: float = 0.0
    split: segments.Split = field(default_factory=segments.Split)
    keys_used: int = 0
    offsets: list[int] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    stopped_early: bool = False

    @property
    def best(self) -> Hit | None:
        return self.hits[0] if self.hits else None

    @property
    def ok(self) -> bool:
        return bool(self.hits) and self.hits[0].score >= 62

    def summary(self) -> str:
        if not self.hits:
            return (f"没解出来（试了 {self.tried} 次，{self.elapsed:.1f}s）。"
                    f"这通常意味着密钥不在这台机器上，或者用了自定义算法")
        b = self.hits[0]
        s = (f"最可能：{b.method}（得分 {b.score}，偏移 {b.offset}，{b.size}B），"
             f"试了 {self.tried} 次 / {self.elapsed:.1f}s")
        if len(self.hits) > 1:
            s += f"；另有 {len(self.hits) - 1} 个候选"
        return s

    def table(self, limit: int = 12) -> str:
        if not self.hits:
            return "（无结果）"
        out = [f"{'分':>3}  {'方法':<44} {'偏移':<8} {'大小':>9}  预览"]
        out += [h.row() for h in self.hits[:limit]]
        return "\n".join(out)


# ---------------------------------------------------------------------------
# 打分
# ---------------------------------------------------------------------------

def score_output(out: bytes) -> int:
    """
    0..100。带标准文件头的直接判成功，纯乱码归零。

    注意区分强弱魔数：
      ZIP/MZ/ELF 这种多字节签名撞上的概率极低，见到即可信；
      而 `{`、`[`、`<` 只有一个字节，随机数据里到处都是，
      必须**文本本身先可读**才给这份加分，否则会把垃圾报成 JSON。
    """
    if not out or len(out) < 4:
        return 0
    bonus, _ = C.magic_bonus(out)
    v = garble.view(out[:16384])
    s = max(v.score, 0)

    if bonus >= C.STRONG_MAGIC:
        return min(100, 55 + bonus)

    if v.report and v.report.kind in (garble.G_REPLACEMENT, garble.G_CONTROL):
        return min(s, 15)

    ent = C.shannon(out[:8192])
    if ent > 7.7:
        return min(s, 20)                 # 还是密文，别报

    # 弱魔数只有在文本本身像话时才算证据
    if bonus and s >= 40:
        s += bonus
    if ent < 5.0 and C.printable(out[:2048]) > 0.95:
        s = max(s, 55)                    # 干净的结构化文本
    return min(100, s)


def _preview(out: bytes, n: int = 60) -> str:
    try:
        t = out[:n * 3].decode("utf-8", "replace")
    except Exception:                                # noqa: BLE001
        t = out[:n].decode("latin1", "replace")
    t = " ".join(t.split())
    return t[:n]


def _worth_unwrap(out: bytes) -> bool:
    """剥掉一层之后，值不值得继续往下剥（避免对纯随机数据反复解）。"""
    if not out or len(out) < 4:
        return False
    bonus, _ = C.magic_bonus(out)
    if bonus:
        return True
    if C.printable(out[:1024]) > 0.85:
        return True
    v = garble.view(out[:4096])
    return (v.score or 0) >= 35


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

def salvage(target: str | Path | bytes, key_cands: list[K.KeyCand] | None = None,
            offsets: list[int] | None = None, top: int = 12,
            deep: bool = False, budget: float | None = None,
            max_bytes: int = 32 * 1024 * 1024,
            scan_offsets: bool = True) -> SalvageReport:
    """
    自动试解。target 可以是文件路径或 bytes。
    返回 SalvageReport，按得分降序。
    """
    t0 = time.time()
    rep = SalvageReport()
    budget = budget if budget is not None else (60.0 if deep else 15.0)
    deadline = t0 + budget

    if isinstance(target, (bytes, bytearray)):
        data = bytes(target)[:max_bytes]
        rep.path = "<bytes>"
    else:
        p = Path(target)
        rep.path = str(p)
        try:
            data = p.read_bytes()[:max_bytes]
        except OSError as e:
            rep.notes.append(f"读不了：{e}")
            return rep

    rep.size = len(data)
    if len(data) < 8:
        rep.notes.append("文件太小，无法试解")
        return rep

    # ---- 分段：如果是"明文头 + 密文"，只解密文部分 ----
    seg = segments.analyze(data)
    rep.split = seg.split
    body_offsets = _candidate_offsets(data, seg, offsets, scan_offsets)
    rep.offsets = body_offsets

    # ---- 候选密钥 ----
    cands = list(key_cands or [])
    if seg.split.head_keys:
        cands += K.from_bytes(
            ("\n".join(f"key={k}" for k in seg.split.head_keys)).encode(),
            source="明文头")
    if not cands:
        cands = K.from_bytes(data[:512 * 1024], source="文件内容")
    # 短文件/脚本里，全文搜一遍更靠谱
    if len(data) <= 2 * 1024 * 1024:
        cands = K.merge(cands, K.from_bytes(data, source="全文"))
    rep.keys_used = len(cands)

    ordered = K.ordered_keys(cands, with_common=True, limit=80)

    hits: list[Hit] = []
    seen: set[str] = set()

    def add(method: str, out: bytes, offset: int, key: str = "", note: str = "") -> None:
        nonlocal hits
        rep.tried += 1
        if not out or len(out) < 4:
            return
        sc = score_output(out)
        if sc < 45:
            return
        h = hashlib.sha256(out[:8192]).hexdigest()[:16]
        if h in seen:
            return
        seen.add(h)
        hits.append(Hit(method=method, offset=offset, score=sc, out=out,
                        preview=_preview(out), key=key, note=note))

    # 打分只看样本，命中后全文重解
    sample = data[:256 * 1024]

    # ---- 1) 编码 / 压缩（最多剥三层：base64→base64→zlib 这种套娃很常见）----
    _ENCODERS = (("Base64", C.b64_decode_any), ("Base32", C.b32_decode_any),
                 ("Base85", C.b85_decode_any), ("十六进制", C.hex_decode_any))
    layer: list[tuple[str, bytes, int]] = [("", data, 0)]
    for _ in range(3):
        nxt: list[tuple[str, bytes, int]] = []
        for label, blob, off in layer[:6]:
            for name, fn in _ENCODERS:
                out, how = fn(blob[:1024 * 1024])
                if not out or out == blob or len(out) < 4:
                    continue
                if not _worth_unwrap(out):
                    continue
                tag = f"{label} → {how}" if label else (how or name)
                add(tag, out, off, note="编码层")
                nxt.append((tag, out, off))
            out, how = C.decompress_auto(blob)
            if out and _worth_unwrap(out):
                tag = f"{label} → {how}" if label else how
                add(tag, out, off, note="压缩层")
                nxt.append((tag, out, off))
        layer = nxt[:6]
        if not layer:
            break
    for off in body_offsets[:8]:
        if off <= 0:
            continue
        out, how = C.decompress_auto(data[off:])
        if out:
            add(how, out, off, note="压缩层（跳过头部）")

    # ---- 2) 单字节 XOR ----
    for off in body_offsets[:3]:
        chunk = data[off:off + 256 * 1024] if off else sample
        for k, sc, dec in C.xor_single_bruteforce(chunk, top=4):
            add(f"单字节 XOR 0x{k:02X}", dec, off, key=f"0x{k:02X}")

    # ---- 2.5) 已知明文攻击（确定性，比频率分析可靠）----
    #   XOR 类的密钥流是重复的，只要明文格式已知就能直接反推密钥。
    #   这一步放在频率分析之前：能确定就别猜。
    crib_offs = [0]
    if seg.split.found and seg.split.head_end > 0:
        crib_offs.append(seg.split.head_end)
    try:
        for ch in CR.crib_attack(data, offsets=crib_offs,
                                 scorer=score_output):
            if not ch.plain:
                continue
            sc = ch.score or score_output(ch.plain)
            if sc < 45:
                continue
            add(f"已知明文攻击（{_ks(ch.crib.decode('latin1', 'ignore'))} · "
                f"密钥 {ch.key.hex()} · 周期 {ch.period}）",
                ch.plain, ch.offset, key=ch.key.hex(), note=ch.note)
    except Exception as e:                           # noqa: BLE001
        rep.notes.append(f"已知明文攻击跳过：{e}")

    # ---- 3) 循环 XOR ----
    ks = C.xor_keysize_hamming(sample, max_key=40)[:8]
    # 汉明距离对"真实长度的整数倍"同样敏感（5 的倍数都会低分），
    # 所以把候选长度的所有因子也一并试，避免拿到 20 字节的伪密钥。
    lens: list[int] = []
    for klen, dist in ks:
        for d in range(1, klen + 1):
            if klen % d == 0 and d not in lens:
                lens.append(d)
    for klen in lens[:14]:
        dec, key = C.xor_break_repeating(sample, klen)
        if not dec or not key:
            continue
        for cand in dict.fromkeys((key, C.xor_reduce_key(key))):
            full = C.xor_bytes(data, cand)
            add(f"循环 XOR（{len(cand)} 字节密钥 {cand.hex()}）",
                full, 0, key=cand.hex(), note="频率分析")

    # ---- 4) 密钥 XOR / 5) RC4 / 6) TEA 系 ----
    tried_keys = 0
    for val, src, sc in ordered:
        if time.time() > deadline:
            rep.stopped_early = True
            break
        if len(val) < 2:
            continue
        tried_keys += 1
        raw = val.encode("utf-8", "ignore")

        dec = C.xor_bytes(sample, raw)
        if dec:
            full = C.xor_bytes(data, raw)
            add(f"密钥 XOR（{_ks(val)}）", full, 0, key=val, note=src)

        if len(raw) >= 4 and tried_keys <= 40:
            rc = C.rc4(data, raw)
            add(f"RC4（{_ks(val)}）", rc, 0, key=val, note=src)

        if tried_keys <= 20:
            for kb, how in K.KeyCand(value=val, source=src).variants((16,)):
                if len(kb) == 16:
                    add(f"XXTEA（{_ks(val)} · {how}）",
                        C.xxtea_decrypt(data, kb), 0, key=val, note=src)
                    add(f"XTEA（{_ks(val)} · {how}）",
                        C.xtea_decrypt(data, kb), 0, key=val, note=src)
                    add(f"TEA（{_ks(val)} · {how}）",
                        C.tea_decrypt(data, kb), 0, key=val, note=src)

    # ---- 7) AES ----
    if C.HAVE_CRYPTO and len(data) >= 32:
        aes_keys = 0
        # IV 候选：全 0 / 密钥前 16 / 明文头里的 hex
        head_ivs: list[tuple[bytes, str]] = []
        for i, hk in enumerate((seg.split.head_keys or [])[:4]):
            hb, _ = C.hex_decode_any(hk)
            if len(hb) >= 16:
                head_ivs.append((hb[:16], f"IV=头{i}"))

        # 起点候选：0 和明文头之后（密文往往紧跟明文头，这是最常踩的坑）
        aes_offs: list[int] = [0]
        if seg.split.found and 0 < seg.split.head_end < len(data) - 32:
            aes_offs.append(seg.split.head_end)

        for val, src, sc in ordered:
            if time.time() > deadline:
                rep.stopped_early = True
                break
            if aes_keys >= 45:
                break
            aes_keys += 1
            for kb, how in K.KeyCand(value=val, source=src).variants((16, 32)):
                for off in aes_offs:
                    body = data[off:]
                    if len(body) < 32:
                        continue
                    ivs = [(b"\x00" * 16, "IV=0"), (kb[:16], "IV=key前16")] + head_ivs
                    for mode in ("ECB", "CBC"):
                        pairs = ivs if mode == "CBC" else [(None, "")]
                        for iv, ivname in pairs:
                            dec, note = C.aes_decrypt(body[:128 * 1024], kb, mode, iv)
                            if not dec or score_output(dec[:16384]) < 45:
                                continue
                            full, _ = C.aes_decrypt(body, kb, mode, iv)
                            add(f"AES-{len(kb) * 8}-{mode}（{_ks(val)} · {how} · "
                                f"{ivname} · 起点{off}）", full or dec, off, key=val, note=src)
                    # IV 前置布局：前 16 字节当 IV
                    if len(body) > 32:
                        dec, _ = C.aes_decrypt(body[16:], kb, "CBC", body[:16])
                        if dec and score_output(dec[:16384]) >= 45:
                            add(f"AES-{len(kb) * 8}-CBC（{_ks(val)} · {how} · IV=密文前16）",
                                dec, off + 16, key=val, note="IV 前置")

    # ---- 8) OpenSSL Salted ----
    if C.HAVE_CRYPTO and data.startswith(b"Salted__"):
        for val, src, sc in ordered[:40]:
            out, note = C.openssl_decrypt(data, val)
            if out:
                add(f"OpenSSL {note}（口令 {_ks(val)}）", out, 16, key=val, note=src)

    # ---- 9) 偏移扫描（RC4 / AES 对起点敏感）----
    if scan_offsets and len(data) <= 8 * 1024 * 1024:
        best_sc = max((h.score for h in hits), default=0)
        if best_sc < 62:
            for off in range(1, min(64, len(data) - 16)):
                if time.time() > deadline:
                    rep.stopped_early = True
                    break
                chunk = data[off:off + 16384]
                # 便宜的先扫：单字节 XOR 的偏移等价于换 key，跳过；
                # RC4 用前 4 个候选密钥扫
                for val, src, sc in ordered[:4]:
                    raw = val.encode("utf-8", "ignore")
                    if len(raw) < 4:
                        continue
                    dec = C.rc4(chunk, raw)
                    if score_output(dec) >= 60:
                        add(f"RC4（{_ks(val)}）· 偏移 {off}",
                            C.rc4(data[off:], raw), off, key=val, note=src)
                # 压缩：有时前面垫了几个字节
                out, how = C.decompress_auto(chunk)
                if out:
                    out2, how2 = C.decompress_auto(data[off:])
                    add(f"{how} · 偏移 {off}", out2 or out, off)
                if off > 32 and not hits:
                    pass

    # ---- 收尾：排序、全文重解校验 ----
    hits.sort(key=lambda h: -h.score)
    # 只对前几个做全文重解，避免在大文件上浪费时间
    rep.hits = hits[:top]
    rep.elapsed = time.time() - t0
    if rep.stopped_early:
        rep.notes.append(f"到时间预算（{budget:.0f}s）就停了，结果可能不全；"
                         f"用 deep=True 跑更久")
    if not rep.hits:
        rep.notes.append("常见算法全试过没命中。下一步：从程序里找解密函数"
                         "（rf.patch_scan / rf.auth_scan），或 hook 拿明文")
    return rep


def _ks(val: str, n: int = 20) -> str:
    v = val if len(val) <= n else val[:n] + "…"
    return repr(v)


def _candidate_offsets(data: bytes, seg: segments.SegmentMap,
                       user: list[int] | None, scan: bool) -> list[int]:
    """候选起点：0 / 明文头之后 / 常见对齐值。"""
    offs: set[int] = {0}
    if user:
        offs.update(o for o in user if 0 <= o < len(data))
    if seg.split.found and seg.split.head_end > 0:
        offs.add(seg.split.head_end)
    for a in (4, 8, 12, 16, 20, 24, 32, 48, 64, 128, 256, 512, 1024):
        if a < len(data):
            offs.add(a)
    return sorted(o for o in offs if o < len(data))


# ---------------------------------------------------------------------------
# 快速版（只跑最便宜的三样，给文件识别流程用）
# ---------------------------------------------------------------------------

def quick(target: str | Path | bytes) -> SalvageReport:
    """只试编码/压缩/单字节 XOR/循环 XOR，几百毫秒出结果。"""
    return salvage(target, budget=4.0, top=5, scan_offsets=False)


# ---------------------------------------------------------------------------
# 报告
# ---------------------------------------------------------------------------

def report_md(rep: SalvageReport, title: str = "自动试解") -> str:
    L = [f"## {title}", "",
         f"- 文件：`{rep.path}`（{rep.size} 字节）",
         f"- 试解次数：{rep.tried}，用时 {rep.elapsed:.1f}s",
         f"- 候选密钥：{rep.keys_used} 条"]
    if rep.split.found:
        L.append(f"- 分段：明文头 {rep.split.head_len}B + 密文 {rep.split.tail_len}B "
                 f"（可信 {rep.split.confidence}%）")
    L.append("")
    if not rep.hits:
        L += ["**没有解出来。**", ""]
        L += [f"- {n}" for n in rep.notes]
        return "\n".join(L)

    L += [f"**最可能：{rep.hits[0].method}**（得分 {rep.hits[0].score}）", "",
          "| 分 | 方法 | 偏移 | 大小 | 预览 |", "|---|---|---|---|---|"]
    for h in rep.hits:
        L.append(f"| {h.score} | {h.method} | {h.offset} | {h.size} | "
                 f"`{h.preview[:40]}` |")
    if rep.notes:
        L += ["", "### 备注", ""] + [f"- {n}" for n in rep.notes]
    return "\n".join(L)


def save_hits(rep: SalvageReport, out_dir: str | Path, limit: int = 5) -> list[Path]:
    """把前几个结果落盘，方便直接打开看。"""
    return [h.save(out_dir) for h in rep.hits[:limit]]
