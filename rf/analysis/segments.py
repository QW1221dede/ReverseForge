#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 rf.analysis.segments · 混合文件分段（找"前明文 / 后密文"的分界）
============================================================================

【要解决的真实情况】
    作者做加密往往不老实，一个文件里能混三四种东西：
      · 前面几行明文配置（甚至夹着密钥），后面整段 AES —— 最常见
      · 前 16/32 字节自定义头（版本号、盐、长度），中间才是密文
      · 明文 → 压缩 → 加密 三层套娃
      · 加密结束又追加一段明文尾（校验值、签名）
    直接整文件丢给解密器，偏移差一个字节就全解不出来。
    所以必须先"量"出这个文件的段落结构。

【怎么量】
    滑窗熵 + 可打印率，两个指标交叉：
      · 熵 < 6.0 且可打印 > 0.90  → 明文（文本/代码/配置）
      · 熵 > 7.4                   → 密文或压缩流
      · 某段全是 0x00/0xFF         → 填充
      · 熵在 6.5–7.4 之间          → 压缩或已混淆

    单看一个窗口容易误判（二进制里也可能有一小段恰好可打印），
    所以判定"分界点"要满足：分界之后**连续多个窗口**都是高熵，直到文件尾。
    满足这条基本就是"前面明文、后面整体加密"。

【分界点还要精确到字节】
    窗口粒度是 KB 级，但解密器需要字节级偏移。
    做法：在候选分界附近，用 256 字节小块往外扫，
    找到最后一个"可打印率 > 0.9"的块，取它的末尾——那就是密文真正的起点。
    AES/RC4 这类算法对偏移极敏感，差一字节就废，所以这步不能省。

【顺带发现的宝贝】
    明文头里常常直接躺着密钥/IV/盐（作者图省事）。
    这里把头部当代码文本扫一遍，命中的 key=/iv=/secret= 会一并报出来，
    喂给解密器当候选密钥。
============================================================================
"""

from __future__ import annotations

import math
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# 段落类型
# ---------------------------------------------------------------------------

S_TEXT = "text"          # 可读文本（代码/配置/日志）
S_BINARY = "binary"      # 结构化二进制（有魔数、有节表）
S_CIPHER = "cipher"      # 高熵密文
S_COMPRESS = "compress"  # 压缩流
S_PADDING = "padding"    # 全 0 / 全 FF 填充
S_MIXED = "mixed"        # 说不清

S_CN = {S_TEXT: "明文", S_BINARY: "二进制结构", S_CIPHER: "密文",
        S_COMPRESS: "压缩流", S_PADDING: "填充", S_MIXED: "混合"}


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


# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------

@dataclass
class Segment:
    start: int = 0
    end: int = 0
    kind: str = S_TEXT
    entropy: float = 0.0
    printable: float = 0.0
    note: str = ""

    @property
    def size(self) -> int:
        return max(0, self.end - self.start)

    @property
    def kind_cn(self) -> str:
        return S_CN.get(self.kind, self.kind)

    def row(self) -> str:
        return (f"{self.start:>10} - {self.end:<10} {self.kind_cn:<8} "
                f"{self.size:>8}B  熵{self.entropy:>5.2f}  可读{self.printable:>6.1%}  {self.note}")


@dataclass
class Split:
    """明文头 → 密文体 的分界。"""
    found: bool = False
    head_end: int = 0          # 明文段结束位置 = 密文起点
    head_len: int = 0
    tail_len: int = 0
    head_kind: str = S_TEXT
    tail_entropy: float = 0.0
    confidence: int = 0
    head_keys: list[str] = field(default_factory=list)
    head_preview: str = ""
    note: str = ""

    def brief(self) -> str:
        if not self.found:
            return f"未发现明文头（{self.note}）"
        return (f"明文头 {self.head_len}B → 密文 {self.tail_len}B "
                f"@偏移 {self.head_end}（{self.head_kind}，可信 {self.confidence}%）")


@dataclass
class SegmentMap:
    path: str = ""
    size: int = 0
    segments: list[Segment] = field(default_factory=list)
    split: Split = field(default_factory=Split)
    embedded: list[tuple[int, str]] = field(default_factory=list)
    head_hex: str = ""
    elapsed: float = 0.0
    note: str = ""

    def ciphers(self, min_size: int = 64) -> list[Segment]:
        return [s for s in self.segments if s.kind in (S_CIPHER, S_COMPRESS) and s.size >= min_size]

    def texts(self, min_size: int = 16) -> list[Segment]:
        return [s for s in self.segments if s.kind == S_TEXT and s.size >= min_size]

    def brief(self) -> str:
        parts = [f"{len(self.segments)} 段", f"{self.size}B"]
        for s in self.segments:
            if s.size:
                parts.append(f"{s.kind_cn} {s.size}B")
        if self.split.found:
            parts.append(f"⚠ 明文头 {self.split.head_len}B + 密文 {self.split.tail_len}B")
        if self.embedded:
            parts.append(f"嵌套容器 {len(self.embedded)} 处")
        return "，".join(parts)

    def table(self, limit: int = 30) -> str:
        if not self.segments:
            return "（没有分段）"
        out = [f"{'起':>10} - {'止':<10} {'类型':<8} {'大小':>9}  熵     可读率   备注"]
        out += [s.row() for s in self.segments[:limit]]
        if len(self.segments) > limit:
            out.append(f"... 还有 {len(self.segments) - limit} 段")
        return "\n".join(out)


# ---------------------------------------------------------------------------
# 窗口扫描
# ---------------------------------------------------------------------------

def windows(data: bytes, window: int = 4096, step: int = 1024
            ) -> list[tuple[int, int, float, float]]:
    """滑窗统计：返回 [(起始, 结束, 熵, 可打印率)]。"""
    n = len(data)
    if n == 0:
        return []
    if n <= window:
        return [(0, n, shannon(data), printable(data))]
    out = []
    off = 0
    while off < n:
        end = min(off + window, n)
        chunk = data[off:end]
        if len(chunk) < 32:      # 尾巴太短不入统计，避免噪声
            break
        out.append((off, end, shannon(chunk), printable(chunk)))
        if end >= n:
            break
        off += step
    return out


def _classify(ent: float, pri: float) -> str:
    if ent < 6.0 and pri > 0.90:
        return S_TEXT
    if ent >= 7.4:
        return S_CIPHER
    if ent >= 6.5:
        return S_COMPRESS
    if pri > 0.75:
        return S_TEXT
    return S_MIXED


def _merge(segs: list[Segment], gap: int = 256) -> list[Segment]:
    """把相邻同类段合并，避免 KB 步长碎成一堆小段。"""
    if not segs:
        return []
    out = [segs[0]]
    for s in segs[1:]:
        last = out[-1]
        if s.kind == last.kind and s.start - last.end <= gap:
            last.end = s.end
            last.entropy = max(last.entropy, s.entropy)
            last.printable = last.printable
        else:
            out.append(s)
    # 合并后把跨度超过 200MB 的段也算正常
    return out


# ---------------------------------------------------------------------------
# 明文头 / 密文体的分界
# ---------------------------------------------------------------------------

# 头部里找密钥用的模式：key="..." / iv= / secret / salt / 直接一串 hex
_KEY_PAT = re.compile(
    r"""(?ix)
    (?:key|aes[_-]?key|secret|token|pass(?:wd|word)?|salt|iv|nonce|card|serial)
    \s*[:=]\s*
    (?:["']([^"'\r\n]{4,80})["']|([0-9a-fA-F]{16,128}))
    """)
_HEXLIKE = re.compile(r"^[0-9a-fA-F]{16,128}$")


def head_keys(head: bytes, limit: int = 8) -> list[str]:
    """从明文头里捞可能的密钥/IV/盐。作者偷懒直接写在这里的情况非常多。"""
    try:
        text = head.decode("utf-8", "replace")
    except Exception:
        return []
    found: list[str] = []
    for m in _KEY_PAT.finditer(text):
        val = m.group(1) or m.group(2) or ""
        if val and val not in found:
            found.append(val)
        if len(found) >= limit:
            break
    return found


def _refine_boundary(data: bytes, guess: int, block: int = 256) -> int:
    """
    把窗口级的大致分界，精确到字节。
    从 guess 前后各扩一个 block 开始，逐块看可打印率，
    取最后一个"仍然像明文"的块末尾。
    """
    n = len(data)
    lo = max(0, guess - block * 2)
    hi = min(n, guess + block * 4)
    last_text_end = lo
    off = lo
    while off < hi:
        chunk = data[off:min(off + block, n)]
        if printable(chunk) > 0.90 and shannon(chunk) < 6.2:
            last_text_end = off + len(chunk)
        elif last_text_end > lo:
            # 明文已经断了，再往后就是密的
            break
        off += block
    return last_text_end


def _ascii_run_end(data: bytes, limit: int = 8 * 1024 * 1024) -> int:
    """从偏移 0 开始的最长可打印 ASCII 串长度（含 \\t\\n\\r）。"""
    n = min(len(data), limit)
    i = 0
    while i < n and (32 <= data[i] < 127 or data[i] in (9, 10, 13)):
        i += 1
    return i


def _utf8_prefix_end(data: bytes, limit: int = 8 * 1024 * 1024) -> int:
    """
    最长可严格按 UTF-8 解码的前缀长度。
    中文头走这条：直接找第一个非法字节的位置。
    """
    blob = data[:limit]
    try:
        blob.decode("utf-8")
        return len(blob)
    except UnicodeDecodeError as e:
        return e.start


def _snap_boundary(data: bytes, approx: int, span: int = 64) -> int:
    """
    把近似的 UTF-8 分界吸附到真实边界。
    判据：该位置之后 96 字节基本不可打印，之前 8 字节还可打印。
    取范围内**最早**满足条件的位置 —— 明文段内部不可能满足
    （它后面 96 字节还是明文），所以第一个命中点就是真边界。
    """
    n = len(data)
    lo = max(0, approx - span)
    hi = min(n, approx + span)
    for p in range(lo, hi):
        nxt = data[p:p + 96]
        if len(nxt) < 32:
            break
        if printable(nxt) <= 0.45 and printable(data[max(0, p - 8):p]) >= 0.60:
            return p
    return approx


def _prefix_text_end(data: bytes) -> tuple[int, bool]:
    """
    从文件开头找"明文前缀"的结束位置。
    返回 (结束位置, 是否字节精确)。

    ASCII 串是最可靠的：可打印字节一直走到断掉，边界天然精确。
    UTF-8 只能靠"第一个非法字节"估，随机字节有可能凑巧组成合法多字节序列，
    所以结果只是近似，还得再吸附一次。
    """
    a = _ascii_run_end(data)
    if a >= 8:
        return a, True
    u = _utf8_prefix_end(data)
    return (u, False) if u >= 8 else (0, True)


def find_split(data: bytes, window: int = 4096, step: int | None = None,
               min_head: int = 8, min_tail: int = 128) -> Split:
    """
    找「前段明文 + 后段密文」的分界。

    做法是**从开头往后看**，不是从尾巴往回到：
    明文头可能只有几十字节（几行配置），比一个熵窗口小得多，
    用窗口法会被整段高熵吞掉，判成"整个文件都是密文"（踩过这个坑）。

    步骤：
      1. 从 0 开始量出明文前缀长度（ASCII 串 / UTF-8 可解前缀）
      2. 校验前缀之后确实是高熵、而且一直高到文件尾
      3. 把分界吸附到字节级真实边界
    """
    sp = Split()
    n = len(data)
    if n < min_head + min_tail:
        sp.note = "文件太小，无法分段"
        return sp

    head_end, exact = _prefix_text_end(data)
    if head_end < min_head:
        ent = shannon(data[:min(n, 131072)])
        if ent >= 7.2:
            sp.note = "整文件高熵，没有明文头"
            sp.head_end = 0
            sp.tail_len = n
            sp.tail_entropy = ent
            sp.confidence = 65
        else:
            sp.note = f"开头不是明文（熵 {ent:.2f}），也不像整体密文"
        return sp

    if head_end >= n - min_tail:
        sp.note = "整个文件都可读，没有密文尾"
        return sp

    tail = data[head_end:head_end + 262144]
    ent = shannon(tail)
    wins = windows(tail, 4096, 2048)
    pure = sum(1 for w in wins if w[2] >= 7.0) / max(1, len(wins))
    if ent < 6.8 and pure < 0.60:
        sp.note = f"明文头之后不是密文（尾部熵 {ent:.2f}，高熵窗口 {pure:.0%}）"
        return sp

    boundary = head_end if exact else _snap_boundary(data, head_end)
    if boundary <= 0:
        boundary = head_end

    sp.found = True
    sp.head_end = boundary
    sp.head_len = boundary
    sp.tail_len = n - boundary
    sp.tail_entropy = shannon(data[boundary:boundary + 131072])
    sp.head_kind = S_TEXT
    sp.head_preview = data[:boundary][:400].decode("utf-8", "replace")
    sp.head_keys = head_keys(data[:boundary])
    sp.confidence = int(min(96, 50 + pure * 45 + (10 if sp.head_keys else 0)))
    sp.note = f"分界之后 {pure:.0%} 的窗口为高熵，尾部熵 {sp.tail_entropy:.2f}"
    return sp


# ---------------------------------------------------------------------------
# 嵌套容器（自解压 / 文件拼接 / 尾部追加）
# ---------------------------------------------------------------------------

_EMBED_MAGICS: list[tuple[bytes, str]] = [
    (b"PK\x03\x04", "ZIP"),
    (b"\x7fELF", "ELF"),
    (b"dex\n", "DEX"),
    (b"\x1f\x8b\x08", "gzip"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"Rar!\x1a\x07", "RAR"),
    (b"%PDF", "PDF"),
    (b"SQLite format 3", "SQLite"),
]


def find_embedded(data: bytes, limit: int = 12, skip_head: int = 0) -> list[tuple[int, str]]:
    """找文件中间/尾部藏着的另一个容器（常见的拼接、自解压、图种）。"""
    out: list[tuple[int, str]] = []
    for magic, name in _EMBED_MAGICS:
        start = skip_head
        while True:
            idx = data.find(magic, start)
            if idx < 0 or len(out) >= limit:
                break
            out.append((idx, name))
            start = idx + 1
    # PE 只在非 0 偏移处找（0 处就是本体，不算嵌套）
    idx = data.find(b"MZ", 1)
    if idx > 0 and len(out) < limit:
        out.append((idx, "PE"))
    out.sort()
    # 去掉挨得太近的重复命中
    dedup: list[tuple[int, str]] = []
    for off, name in out:
        if dedup and off - dedup[-1][0] < 64:
            continue
        dedup.append((off, name))
    return dedup[:limit]


# ---------------------------------------------------------------------------
# 全量分析
# ---------------------------------------------------------------------------

def analyze(target: str | Path | bytes, window: int = 4096, step: int | None = None,
            max_bytes: int = 256 * 1024 * 1024) -> SegmentMap:
    """分析一个文件（或一段 bytes），给出段落表 + 分界 + 嵌套容器。"""
    t0 = time.time()
    sm = SegmentMap()
    if isinstance(target, (bytes, bytearray)):
        data = bytes(target)
        sm.path = "<bytes>"
    else:
        p = Path(target)
        sm.path = str(p)
        try:
            size = p.stat().st_size
            with p.open("rb") as f:
                data = f.read(min(size, max_bytes))
        except OSError as e:
            sm.note = f"读不了：{e}"
            return sm

    sm.size = len(data)
    if not data:
        sm.note = "空文件"
        return sm
    sm.head_hex = data[:32].hex(" ")

    step = step or max(256, window // 4)
    wins = windows(data, window, step)

    # 逐窗定性 → 合并
    raw: list[Segment] = []
    for off, end, ent, pri in wins:
        kind = _classify(ent, pri)
        raw.append(Segment(start=off, end=end, kind=kind, entropy=ent, printable=pri))
    segs = _merge(raw)

    # 填充段：单独识别（熵 0 的全 0/全 FF 会被 _classify 判成 text，要纠正）
    for s in segs:
        chunk = data[s.start:s.end]
        if chunk and (chunk.count(0) / len(chunk) > 0.95 or chunk.count(0xFF) / len(chunk) > 0.95):
            s.kind = S_PADDING
            s.note = "全 0x00" if chunk.count(0) > chunk.count(0xFF) else "全 0xFF"

    sm.segments = segs
    sm.split = find_split(data, window, step)
    sm.embedded = find_embedded(data)

    # 分界校准：明文头往往比一个熵窗口还小，会被整段高熵吞掉。
    # 既然已经量出精确分界，就把它单独切成一段，别让报告自相矛盾。
    if sm.split.found and sm.split.head_end > 0:
        he = sm.split.head_end
        head_seg = Segment(start=0, end=he, kind=S_TEXT,
                           entropy=shannon(data[:he]), printable=printable(data[:he]),
                           note="明文头" + ("（含疑似密钥）" if sm.split.head_keys else ""))
        rest: list[Segment] = []
        for s in segs:
            if s.end <= he:
                continue
            if s.start < he:
                s.start = he
                s.entropy = shannon(data[s.start:s.end])
                s.printable = printable(data[s.start:s.end])
            rest.append(s)
        sm.segments = [head_seg] + rest

    sm.elapsed = time.time() - t0
    return sm


# ---------------------------------------------------------------------------
# 提取
# ---------------------------------------------------------------------------

def carve(data: bytes, start: int, end: int) -> bytes:
    start = max(0, start)
    end = min(len(data), end)
    return data[start:end] if end > start else b""


def carve_tail(target: str | Path | SegmentMap, sm: SegmentMap | None = None,
               start: int | None = None) -> bytes:
    """取出"密文部分"的字节，直接喂解密器。"""
    if sm is None:
        sm = target if isinstance(target, SegmentMap) else analyze(target)
    if isinstance(target, (bytes, bytearray)):
        data = bytes(target)
    else:
        try:
            data = Path(sm.path).read_bytes()
        except OSError:
            return b""
    off = start if start is not None else (sm.split.head_end if sm.split.found else 0)
    return data[off:]


def carve_segments(target: str | Path, out_dir: str | Path,
                   sm: SegmentMap | None = None, min_size: int = 32) -> list[Path]:
    """把每段落成独立文件，方便单独丢给解密器/十六进制看。"""
    if sm is None:
        sm = analyze(target)
    data = Path(target).read_bytes()
    od = Path(out_dir)
    od.mkdir(parents=True, exist_ok=True)
    wrote: list[Path] = []
    for i, s in enumerate(sm.segments):
        if s.size < min_size:
            continue
        f = od / f"seg{i:02d}_{s.kind}_{s.start}_{s.size}.bin"
        f.write_bytes(carve(data, s.start, s.end))
        wrote.append(f)
    return wrote


def extract_strings(data: bytes, min_len: int = 5) -> list[str]:
    """从任意字节里拉可打印串（用于看头部到底写了什么）。"""
    out, cur = [], bytearray()
    for b in data:
        if 32 <= b < 127 or b in (9,):
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("latin1"))
            cur = bytearray()
    if len(cur) >= min_len:
        out.append(cur.decode("latin1"))
    return out


# ---------------------------------------------------------------------------
# 报告
# ---------------------------------------------------------------------------

def report_md(sm: SegmentMap, title: str = "文件分段") -> str:
    L = [f"## {title}", "",
         f"- 文件：`{sm.path}`（{sm.size} 字节）",
         f"- 头部：`{sm.head_hex}`",
         f"- 用时：{sm.elapsed:.2f}s", ""]

    if sm.split.found:
        L += ["### 明文头 / 密文体", "",
              f"- 明文头：{sm.split.head_len} 字节（偏移 0 – {sm.split.head_end}）",
              f"- 密文体：{sm.split.tail_len} 字节（偏移 {sm.split.head_end} – {sm.size}，"
              f"熵 {sm.split.tail_entropy:.2f}）",
              f"- 可信度：{sm.split.confidence}%",
              f"- 依据：{sm.split.note}"]
        if sm.split.head_keys:
            L.append(f"- **明文头里疑似密钥**：{'、'.join('`' + k + '`' for k in sm.split.head_keys)}")
        if sm.split.head_preview:
            L += ["", "明文头内容（前 400 字）：", "", "```text",
                  sm.split.head_preview.rstrip(), "```"]
    else:
        L += ["### 未发现明文头", "", f"原因：{sm.split.note}"]

    if sm.embedded:
        L += ["", "### 嵌套容器", ""]
        for off, name in sm.embedded:
            L.append(f"- 偏移 {off}：{name}")

    L += ["", "### 段落表", "",
          "| 起 | 止 | 类型 | 大小 | 熵 | 可读率 | 备注 |",
          "|---|---|---|---|---|---|---|"]
    for s in sm.segments:
        L.append(f"| {s.start} | {s.end} | {s.kind_cn} | {s.size} | "
                 f"{s.entropy:.2f} | {s.printable:.0%} | {s.note} |")
    return "\n".join(L)
