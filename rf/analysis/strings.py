#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 rf.analysis.strings · 字符串提取与分类
============================================================================

【为什么不用 strings.exe】
    1. 它只出 ASCII/UTF-16LE 两路，中文 GBK 全靠运气
    2. 输出是纯文本，不能分类、不能聚合、不能给 GUI 做筛选
    3. 我们要的回答是「这个包里有哪些接口地址、哪些路径、哪些密钥」，
       而不是「这里有 12 万行字符串」

【三路提取】
    ASCII      —— 可打印连续段，抓 URL/路径/日志/类名
    UTF-16LE   —— Windows/Java 常量池常见（每字符后跟 \x00）
    GBK/UTF-8  —— 中文资源、提示语

【分类器】
    URL / IP / 域名 / 路径 / 邮箱 / 密钥候选 / Base64 / 哈希 / 类名 / 版本号 / 中文文本
============================================================================
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

_PRINTABLE = bytes(range(32, 127)) + b"\t"

# ---------------------------------------------------------------------------
# 提取
# ---------------------------------------------------------------------------

def extract_ascii(data: bytes, min_len: int = 5) -> list[str]:
    out: list[str] = []
    cur = bytearray()
    for b in data:
        if b in _PRINTABLE:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("ascii", "replace"))
            cur.clear()
    if len(cur) >= min_len:
        out.append(cur.decode("ascii", "replace"))
    return out


def extract_utf16le(data: bytes, min_len: int = 4) -> list[str]:
    """UTF-16LE：可打印字符 + 紧跟的 \\x00。"""
    out: list[str] = []
    cur: list[str] = []
    i, n = 0, len(data) - 1
    while i < n:
        c, z = data[i], data[i + 1]
        if 32 <= c < 127 and z == 0:
            cur.append(chr(c))
            i += 2
            continue
        if c == 0 and z == 0:
            i += 2
            continue
        if len(cur) >= min_len:
            out.append("".join(cur))
        cur = []
        i += 1
    if len(cur) >= min_len:
        out.append("".join(cur))
    return out


def extract_cjk(data: bytes, min_len: int = 2) -> list[str]:
    """粗提中文串（UTF-8 与 GBK 都试一遍，取解出来更长的）。"""
    out: list[str] = []
    for enc in ("utf-8", "gbk"):
        try:
            text = data.decode(enc, "ignore")
        except Exception:
            continue
        for m in re.finditer(r"[\u4e00-\u9fff][\u4e00-\u9fff\uff00-\uffef，。！？、：；（）《》“”]{1,60}",
                             text):
            s = m.group(0)
            if len(s) >= min_len:
                out.append(s)
    return out


# ---------------------------------------------------------------------------
# 分类
# ---------------------------------------------------------------------------

RULES: list[tuple[str, re.Pattern]] = [
    ("URL", re.compile(r"^(?:https?|ftp|ws|wss)://[^\s\"'<>]{4,300}$", re.I)),
    ("IP", re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?$")),
    ("域名", re.compile(r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+"
                        r"(?:com|cn|net|org|io|xyz|top|cc|me|app|dev|info|biz|tv|co)\b",
                        re.I)),
    ("邮箱", re.compile(r"^[\w.+\-]+@[\w\-]+\.[\w.\-]{2,}$")),
    ("文件路径", re.compile(r"^(?:[A-Za-z]:\\|/(?:data|system|sdcard|storage|proc|sys|vendor)/)"
                            r"[^\s:*?\"<>|]{0,200}$")),
    ("类路径", re.compile(r"^(?:[a-z][\w]*\.){2,}[A-Z][\w$]*$")),
    ("方法签名", re.compile(r"^L[\w/$]+;->[\w$<>]+\(.*\).*$")),
    ("AES/DES 密钥", re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{48}$|^[0-9a-fA-F]{64}$")),
    ("哈希", re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")),
    ("Base64", re.compile(r"^[A-Za-z0-9+/]{20,}={0,2}$")),
    ("SQL", re.compile(r"^(?:SELECT|INSERT|UPDATE|DELETE|CREATE|DROP)\s+.{4,}", re.I)),
    ("命令", re.compile(r"^(?:su|sh|bash|pm |am |setprop|getprop|chmod|mount|insmod)\b.*$")),
    ("版本号", re.compile(r"^v?\d+\.\d+(?:\.\d+)?(?:[-+]\w+)?$")),
    ("中文", re.compile(r"^[\u4e00-\u9fff].*$")),
]

# 高价值关键字：命中就单独归到"敏感"桶
SENSITIVE_WORDS = (
    "password", "passwd", "pwd", "secret", "token", "apikey", "api_key",
    "private", "credential", "auth", "session", "cookie", "sign",
    "root", "su", "superuser", "inject", "hook", "exploit", "payload",
    "decrypt", "encrypt", "license", "vip", "pay", "order",
)


@dataclass
class StringsResult:
    path: str = ""
    total: int = 0
    by_kind: dict[str, list[str]] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def add(self, kind: str, s: str, cap: int = 4000) -> None:
        bucket = self.by_kind.setdefault(kind, [])
        if len(bucket) < cap and s not in bucket:
            bucket.append(s)
            self.total += 1

    def summary(self) -> str:
        parts = [f"{k} {len(v)}" for k, v in
                 sorted(self.by_kind.items(), key=lambda x: -len(x[1]))]
        return " / ".join(parts) if parts else "（无）"

    def to_dict(self) -> dict:
        return {"path": self.path, "total": self.total, "by_kind": self.by_kind,
                "errors": self.errors}


def classify(s: str) -> str:
    for kind, rx in RULES:
        try:
            if rx.match(s):
                return kind
        except Exception:
            continue
    low = s.lower()
    if any(w in low for w in SENSITIVE_WORDS):
        return "敏感关键字"
    return "其他"


def scan_bytes(data: bytes, min_len: int = 5, with_cjk: bool = True,
               cap_per_kind: int = 4000) -> StringsResult:
    r = StringsResult()
    seen: set[str] = set()

    def feed(items):
        for s in items:
            if s in seen:
                continue
            seen.add(s)
            r.add(classify(s), s, cap_per_kind)

    feed(extract_ascii(data, min_len))
    feed(extract_utf16le(data, max(4, min_len - 1)))
    if with_cjk:
        feed(extract_cjk(data))
    return r


def scan_file(path: str | Path, min_len: int = 5, with_cjk: bool = True,
              cap_per_kind: int = 4000) -> StringsResult:
    p = Path(path)
    r = StringsResult(path=str(p))
    try:
        data = p.read_bytes()
    except OSError as e:
        r.errors.append(str(e))
        return r
    if len(data) > 64 << 20:
        data = data[:64 << 20]
        r.errors.append("文件超过 64MB，只扫前 64MB")
    got = scan_bytes(data, min_len, with_cjk, cap_per_kind)
    got.path = str(p)
    return got


def scan_tree(root: str | Path, exts: tuple[str, ...] = (".so", ".dex", ".jar", ".bin"),
              min_len: int = 5, max_files: int = 200) -> StringsResult:
    """扫一棵目录树，把各文件的字符串汇总到一份结果里。"""
    r = StringsResult(path=str(root))
    root = Path(root)
    n = 0
    for f in sorted(root.rglob("*")):
        if not f.is_file() or f.suffix.lower() not in exts:
            continue
        n += 1
        if n > max_files:
            r.errors.append(f"超过 {max_files} 个文件，提前停止")
            break
        part = scan_file(f, min_len)
        r.errors.extend(part.errors)
        for k, v in part.by_kind.items():
            for s in v:
                r.add(k, s)
    return r


def top_urls(r: StringsResult, limit: int = 30) -> list[str]:
    urls = list(r.by_kind.get("URL", []))
    # 按域名聚合，看主要通信对象
    dom = Counter()
    for u in urls:
        m = re.match(r"^\w+://([^/:\s]+)", u)
        if m:
            dom[m.group(1)] += 1
    out = [f"{d}  ×{c}" for d, c in dom.most_common(limit)]
    return out or urls[:limit]
