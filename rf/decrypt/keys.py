#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 rf.decrypt.keys · 候选密钥提取（哪儿都翻一遍）
============================================================================

【为什么单独一层】
    自动试解能不能成，八成取决于"候选密钥够不够准"。
    暴力穷举 AES-256 是不可能的，但只要密钥就写在这台机器上，
    翻出来的概率非常高——作者要自用，就必须把密钥放在客户端某处：
      · 明文头里（`key="..."`，最常见）
      · 脚本源码里的常量（`KEY = "..."`）
      · 配置文件（config.json / settings.ini）
      · 二进制里的字符串（编译期硬编码）
      · 甚至就写在文件名里

【捞什么】
    1. 上下文关键词 + 引号字符串：key/secret/iv/salt/token/password/aes/rc4/des
    2. 独立出现的长 hex（16/24/32/48/64 字符）—— 大概率是密钥或 IV
    3. Base64 形态、长度对得上密钥规格的串
    4. 常见弱口令表（很多人 key 就是 "123456"）
    5. 用户显式提供的

【排序】
    上下文命中 AES/Cipher 附近的 > 单纯 hex > 弱口令。
    试解时按这个顺序撞，先命中的先报，省时间。
============================================================================
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from . import ciphers as C

# ---------------------------------------------------------------------------
# 数据模型
# ---------------------------------------------------------------------------

@dataclass
class KeyCand:
    value: str = ""
    source: str = ""      # 出处：文件:行 / 说明
    kind: str = "string"  # string / hex / base64 / password / iv / salt
    score: int = 50

    def to_row(self) -> str:
        v = self.value if len(self.value) <= 48 else self.value[:45] + "..."
        return f"{v:<50} {self.kind:<9} {self.score:>4}  {self.source}"

    def variants(self, sizes: tuple[int, ...] = (16, 24, 32)) -> list[tuple[bytes, str]]:
        """转成实际密钥字节（原文补齐 / MD5 / SHA256 / hex / base64）。"""
        out: list[tuple[bytes, str]] = []
        for size in sizes:
            for kb, how in C.key_variants(self.value, size):
                out.append((kb, f"{how}/{size * 8}位"))
        return out


# ---------------------------------------------------------------------------
# 模式
# ---------------------------------------------------------------------------

# 关键词后面跟 = / : / ( 再跟引号串
_KW = (r"key|secret|aes[_-]?key|encrypt[_-]?key|decrypt[_-]?key|"
       r"iv|nonce|salt|token|password|passwd|pwd|pass|"
       r"card|serial|licen[cs]e|activate|auth|sign")
_RE_KEYSTR = re.compile(
    r"""(?ix)
    \b(?:%s)\b\s*[:=]\s*
    (?:["']([^"'\r\n]{1,120})["']|([0-9a-fA-F]{16,128}))
    """ % _KW)
# 也抓 `<key>value</key>` 这种 XML/配置写法
_RE_XMLKEY = re.compile(r"(?is)<(%s)>\s*([^<\r\n]{1,120}?)\s*</\1>" % _KW)
# 独立长 hex
_RE_HEX = re.compile(r"\b([0-9a-fA-F]{16}|[0-9a-fA-F]{24}|[0-9a-fA-F]{32}|"
                     r"[0-9a-fA-F]{40}|[0-9a-fA-F]{48}|[0-9a-fA-F]{64})\b")
# base64 形态（长度 >= 16，含 +/ 或大小写混排）
_RE_B64 = re.compile(r"\b([A-Za-z0-9+/]{16,88}={0,2})\b")

# 弱口令（很多人 key 就是这个）
COMMON_PASSWORDS: list[str] = [
    "", "123456", "12345678", "1234567890", "1234", "12345", "123456789",
    "password", "passwd", "admin", "admin123", "root", "toor", "000000",
    "111111", "666666", "888888", "abc123", "qwerty", "qwerty123",
    "1qaz2wsx", "iloveyou", "letmein", "welcome", "monkey", "dragon",
    "android", "test", "test123", "guest", "user", "pass", "secret", "key",
    "a123456", "1q2w3e4r", "zxcvbnm", "asdfgh", "changeme", "default",
    "123123", "112233", "5201314", "woaini", "qq123456", "a123456789",
    "kalong", "kali", "hack", "crack", "reverse", "ghidra", "frida",
]


# ---------------------------------------------------------------------------
# 从文本里捞
# ---------------------------------------------------------------------------

def from_text(text: str, source: str = "", min_score: int = 30) -> list[KeyCand]:
    """从任意文本（源码/配置/字符串表）里捞候选密钥。"""
    out: list[KeyCand] = []
    if not text:
        return out
    blob = text[:4_000_000]

    for m in _RE_KEYSTR.finditer(blob):
        val = (m.group(1) or m.group(2) or "").strip()
        if not val or len(val) < 2:
            continue
        kind = "string"
        if re.fullmatch(r"[0-9a-fA-F]{16,128}", val):
            kind = "hex"
        low = val.lower()
        if low in ("null", "none", "nil", "true", "false", "0", "1", "utf-8", "utf8"):
            continue
        line = blob.count("\n", 0, m.start()) + 1
        out.append(KeyCand(value=val, source=f"{source}:{line}", kind=kind, score=85))

    for m in _RE_XMLKEY.finditer(blob):
        val = m.group(2).strip()
        if len(val) >= 4:
            line = blob.count("\n", 0, m.start()) + 1
            out.append(KeyCand(value=val, source=f"{source}:{line}<xml>",
                               kind="string", score=75))

    for m in _RE_HEX.finditer(blob):
        val = m.group(1)
        if val.lower() in ("0123456789abcdef", "fedcba9876543210"):
            continue
        if val.isdigit():          # 纯数字长串多半是 ID/时间戳
            continue
        line = blob.count("\n", 0, m.start()) + 1
        out.append(KeyCand(value=val, source=f"{source}:{line}",
                           kind="hex", score=55))

    for m in _RE_B64.finditer(blob):
        val = m.group(1)
        if len(val) < 16:
            continue
        if not (re.search(r"[A-Z]", val) and re.search(r"[a-z]", val) and re.search(r"[0-9]", val)):
            continue
        if val.isdigit() or val.isalpha():
            continue
        try:
            raw = __import__("base64").b64decode(val + "=" * (-len(val) % 4))
        except Exception:                            # noqa: BLE001
            continue
        if len(raw) in (16, 24, 32):
            line = blob.count("\n", 0, m.start()) + 1
            out.append(KeyCand(value=val, source=f"{source}:{line}",
                               kind="base64", score=60))

    return _dedup([k for k in out if k.score >= min_score])


# ---------------------------------------------------------------------------
# 从文件 / 目录里捞
# ---------------------------------------------------------------------------

_TEXT_EXT = {".py", ".js", ".mjs", ".ts", ".lua", ".json", ".xml", ".ini",
             ".cfg", ".conf", ".txt", ".yaml", ".yml", ".properties", ".env",
             ".sh", ".bat", ".ps1", ".java", ".kt", ".cs", ".php", ".html",
             ".smali", ".gradle", ".pro", ".md", ".csproj", ".config"}


def from_file(path: str | Path, binary_ok: bool = True) -> list[KeyCand]:
    """单个文件捞一遍。文本按内容搜，二进制先抽可打印串再搜。"""
    p = Path(path)
    try:
        with p.open("rb") as f:                 # 只读前 8MB，别把几 GB 的 so 整个吞下
            raw = f.read(8 * 1024 * 1024)
    except OSError:
        return []
    if not raw:
        return []
    is_text = p.suffix.lower() in _TEXT_EXT or C.printable(raw[:4096]) > 0.90
    if is_text:
        try:
            text = raw.decode("utf-8", "replace")
        except Exception:                            # noqa: BLE001
            text = raw.decode("latin1", "replace")
        return from_text(text, source=p.name)
    if not binary_ok:
        return []
    # 二进制：抽可打印串拼起来再搜（这样上下文关键词还能用上）
    strings = []
    cur = bytearray()
    for b in raw:
        if 32 <= b < 127 or b == 9:
            cur.append(b)
        else:
            if len(cur) >= 4:
                strings.append(cur.decode("latin1"))
            cur = bytearray()
    if len(cur) >= 4:
        strings.append(cur.decode("latin1"))
    cands = from_text("\n".join(strings), source=f"{p.name}(字符串)")
    for c in cands:
        c.score = max(20, c.score - 10)      # 二进制里翻到的略降权
    return cands


def from_tree(root: str | Path, max_files: int = 800,
              exts: set[str] | None = None) -> list[KeyCand]:
    """目录递归捞（默认只扫文本类 + 小体积配置，避免把整个 APK 拖进来）。"""
    rp = Path(root)
    use = exts or _TEXT_EXT
    out: list[KeyCand] = []
    files = [rp] if rp.is_file() else list(rp.rglob("*"))
    n = 0
    for p in files:
        if n >= max_files:
            break
        try:
            if not p.is_file():
                continue
            if p.suffix.lower() not in use:
                continue
            if p.stat().st_size > 4 * 1024 * 1024:
                continue
        except OSError:
            continue
        out.extend(from_file(p))
        n += 1
    return _dedup(out)


def from_bytes(data: bytes, source: str = "<bytes>") -> list[KeyCand]:
    """直接从一段内存字节里捞（用于"前明文头"这种碎片）。"""
    try:
        text = data.decode("utf-8", "replace")
    except Exception:                                # noqa: BLE001
        text = data.decode("latin1", "replace")
    cands = from_text(text, source=source)
    # 头部短，hex 长串命中率更高，稍微提权
    for c in cands:
        if c.kind == "hex":
            c.score += 10
    return cands


def common() -> list[KeyCand]:
    return [KeyCand(value=p, source="弱口令表", kind="password", score=25)
            for p in COMMON_PASSWORDS if p]


# ---------------------------------------------------------------------------
# 排序与合并
# ---------------------------------------------------------------------------

def _dedup(items: list[KeyCand]) -> list[KeyCand]:
    """按值去重，保留分数最高的那条。"""
    best: dict[str, KeyCand] = {}
    for c in items:
        if not c.value:
            continue
        old = best.get(c.value)
        if old is None or c.score > old.score:
            best[c.value] = c
    out = list(best.values())
    out.sort(key=lambda c: (-c.score, -len(c.value)))
    return out


def merge(*groups: list[KeyCand], limit: int = 200) -> list[KeyCand]:
    items: list[KeyCand] = []
    for g in groups:
        items.extend(g)
    return _dedup(items)[:limit]


def ordered_keys(cands: list[KeyCand], with_common: bool = True,
                 limit: int = 120) -> list[tuple[str, str, int]]:
    """
    给自动试解的最终顺序：[(密钥字符串, 出处, 分数)]。
    分数高的先试，弱口令垫底。
    """
    pool = list(cands)
    if with_common:
        # 弱口令只保留跟已命中不重复的，且只取前 40 个（够用了）
        pool += common()[:40]
    seen: set[str] = set()
    out: list[tuple[str, str, int]] = []
    for c in _dedup(pool):
        if c.value in seen:
            continue
        seen.add(c.value)
        out.append((c.value, c.source, c.score))
        if len(out) >= limit:
            break
    return out


def report_table(cands: list[KeyCand], limit: int = 40) -> str:
    if not cands:
        return "（没找到候选密钥）"
    out = [f"{'值':<50} {'类型':<9} {'分':>4}  出处"]
    out += [c.to_row() for c in cands[:limit]]
    if len(cands) > limit:
        out.append(f"... 还有 {len(cands) - limit} 条")
    return "\n".join(out)
