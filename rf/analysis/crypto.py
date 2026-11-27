#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 rf.analysis.crypto · 加密/压缩容器识别与解密尝试
============================================================================

【能做什么】
    1. 识别：按魔数判断文件到底是什么（真加密 / 只是压缩 / 伪装扩展名）
    2. 判强度：整文件香农熵。>7.5 且无已知头 → 强加密或压缩流
    3. 解 ZIP 系列：APK/JAR/DOCX 本质都是 ZIP，弱口令可直接开
    4. 试 7z/RAR：交给 7zr，字典攻击（内置常见口令表）
    5. 单字节 XOR：暴力 256 种，用"可打印率 + 明文关键字"打分

【诚实边界】
    AES-256 全文件加密（无密钥、无实现漏洞）**不可能**被暴力破解，
    这一步只能做字典/弱口令。命中不了就如实报告"无法解密"，
    绝不假装成功。真正的突破口在：找 key 硬编码在代码里、找解密函数、
    动态 hook 拿明文 —— 这些是后续流水线的事。
============================================================================
"""

from __future__ import annotations

import binascii
import io
import math
import re
import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# 魔数表
# ---------------------------------------------------------------------------

MAGICS: list[tuple[bytes, str, str]] = [
    (b"PK\x03\x04", "ZIP/APK/JAR", "zip"),
    (b"PK\x05\x06", "ZIP（空包）", "zip"),
    (b"Rar!\x1a\x07", "RAR 压缩包", "compress"),
    (b"7z\xbc\xaf\x27\x1c", "7z 压缩包", "compress"),
    (b"\x1f\x8b", "gzip", "compress"),
    (b"BZh", "bzip2", "compress"),
    (b"\xfd7zXZ\x00", "xz", "compress"),
    (b"\x28\xb5\x2f\xfd", "zstd", "compress"),
    (b"dex\n", "DEX 字节码", "android"),
    (b"cdex", "Compact DEX", "android"),
    (b"\x7fELF", "ELF 可执行/动态库", "binary"),
    (b"MZ", "PE 可执行文件", "binary"),
    (b"\xca\xfe\xba\xbe", "Java class / Mach-O fat", "binary"),
    (b"SQLite format 3\x00", "SQLite 数据库", "data"),
    (b"\x89PNG", "PNG 图片", "image"),
    (b"\xff\xd8\xff", "JPEG 图片", "image"),
    (b"GIF8", "GIF 图片", "image"),
    (b"RIFF", "RIFF（WAV/AVI/WebP）", "media"),
    (b"OggS", "Ogg 音频", "media"),
    (b"ID3", "MP3 音频", "media"),
    (b"%PDF", "PDF 文档", "doc"),
    (b"\xd0\xcf\x11\xe0", "OLE（旧 Office/DOC）", "doc"),
    (b"ustar", "TAR 归档", "archive"),
    (b"ANDROID!", "Android boot 镜像", "firmware"),
    (b"\x27\x05\x19\x56", "Android sparse image", "firmware"),
    # 加密容器头（不是标准，但常见工具会留签名）
    (b"Salted__", "OpenSSL enc 加密（含盐）", "encrypted"),
    (b"-----BEGIN", "PEM 证书/密钥（明文）", "key"),
]

WEAK_PASSWORDS: list[str] = [
    "", "123456", "12345678", "123456789", "1234", "12345", "password",
    "admin", "admin123", "root", "toor", "000000", "111111", "666666",
    "888888", "abc123", "qwerty", "1qaz2wsx", "iloveyou", "letmein",
    "android", "test", "guest", "user", "pass", "secret", "key",
    "a123456", "1q2w3e4r", "zxcvbnm", "asdfgh", "changeme", "default",
    "123123", "112233", "5201314", "woaini", "qq123456", "a123456789",
]


@dataclass
class IdentifyResult:
    path: str = ""
    size: int = 0
    kind: str = "unknown"        # zip / compress / encrypted / binary / ...
    label: str = "未知格式"
    entropy: float = 0.0
    encrypted: bool = False
    notes: list[str] = field(default_factory=list)
    zip_entries: int = 0
    zip_encrypted_entries: int = 0

    def brief(self) -> str:
        s = f"{Path(self.path).name}: {self.label}  {self.size / 1024:.0f}KB  熵 {self.entropy:.2f}"
        if self.encrypted:
            s += "  ⚠ 已加密"
        return s


@dataclass
class DecryptResult:
    ok: bool = False
    method: str = ""
    password: str = ""
    out_path: str = ""
    note: str = ""
    tried: int = 0


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


# ---------------------------------------------------------------------------
# 识别
# ---------------------------------------------------------------------------

def identify(path: str | Path) -> IdentifyResult:
    p = Path(path)
    r = IdentifyResult(path=str(p))
    if not p.exists():
        r.notes.append("文件不存在")
        return r
    r.size = p.stat().st_size
    try:
        with open(p, "rb") as f:
            head = f.read(4096)
            f.seek(0)
            sample = f.read(min(r.size, 1 << 20))
    except OSError as e:
        r.notes.append(f"读取失败：{e}")
        return r

    r.entropy = round(shannon(sample), 3)

    for magic, label, kind in MAGICS:
        if head.startswith(magic) or (magic == b"ustar" and head[257:262] == b"ustar"):
            r.label, r.kind = label, kind
            break
    else:
        # 没有魔数：靠熵与内容猜
        if r.entropy >= 7.8:
            r.kind, r.label = "encrypted", "高熵数据（强加密或已压缩，无已知头）"
        elif r.entropy >= 7.2:
            r.kind, r.label = "compressed", "压缩/加密数据（熵偏高）"
        elif _looks_text(sample):
            r.kind, r.label = "text", "文本文件"
        else:
            r.kind, r.label = "unknown", "未识别格式"

    # ZIP 系深查：条目数 + 是否逐条加密
    if r.kind == "zip" or head.startswith(b"PK"):
        try:
            with zipfile.ZipFile(io.BytesIO(sample) if r.size <= len(sample) else p) as z:
                infos = z.infolist()
                r.zip_entries = len(infos)
                r.zip_encrypted_entries = sum(1 for i in infos if i.flag_bits & 0x1)
                if r.zip_encrypted_entries:
                    r.encrypted = True
                    r.notes.append(f"{r.zip_encrypted_entries}/{r.zip_entries} 个条目被密码保护")
        except Exception as e:
            r.notes.append(f"ZIP 结构读取失败：{e}")

    # OpenSSL enc 头：Salted__ + 8 字节盐
    if head.startswith(b"Salted__"):
        r.encrypted = True
        r.kind = "encrypted"
        r.notes.append("OpenSSL enc 格式：可用 `openssl enc -d -<算法> -in <文件> -k <口令>` 尝试")

    if r.kind == "encrypted" and not r.notes:
        r.notes.append("无已知容器头且熵接近 8.0：大概率为整文件加密，需密钥或从代码中找解密路径")

    return r


def _looks_text(sample: bytes) -> bool:
    if not sample:
        return False
    printable = sum(1 for b in sample[:4096] if 32 <= b < 127 or b in (9, 10, 13))
    return printable / min(len(sample), 4096) > 0.92


# ---------------------------------------------------------------------------
# 解密：ZIP 弱口令
# ---------------------------------------------------------------------------

def _close_quiet(zf) -> None:
    try:
        zf.close()
    except Exception:                                   # noqa: BLE001
        pass


def try_zip_password(path: str | Path, passwords: list[str] | None = None,
                     out_dir: str | Path | None = None,
                     on_try=None) -> DecryptResult:
    p = Path(path)
    pw_list = passwords or WEAK_PASSWORDS
    res = DecryptResult()

    try:
        zf = zipfile.ZipFile(p)
    except Exception as e:
        res.note = f"无法打开 ZIP：{e}"
        return res

    infos = zf.infolist()
    enc = [i for i in infos if i.flag_bits & 0x1]
    if not enc:
        _close_quiet(zf)
        res.note = "该 ZIP 未加密，无需口令"
        res.ok = True
        res.method = "none"
        return res

    target = enc[0]
    for i, pw in enumerate(pw_list, 1):
        res.tried = i
        if on_try:
            try:
                on_try(pw, i, len(pw_list))
            except Exception:
                pass
        try:
            if pw:
                zf.setpassword(pw.encode())
            else:
                zf.setpassword(None)
            with zf.open(target) as f:
                f.read(64)
            res.ok = True
            res.password = pw
            res.method = "zip-弱口令"
            break
        except (RuntimeError, zipfile.BadZipFile, NotImplementedError):
            continue
        except Exception:
            continue

    if res.ok and out_dir:
        od = Path(out_dir)
        od.mkdir(parents=True, exist_ok=True)
        zf.setpassword(res.password.encode() if res.password else None)
        try:
            for info in enc:
                zf.extract(info, od)
            res.out_path = str(od)
            res.note = f"已解出 {len(enc)} 个加密条目到 {od}"
        except Exception as e:
            res.note = f"命中口令但解包失败：{e}"
    elif not res.ok:
        res.note = f"试了 {res.tried} 个常见口令未命中；ZIP 用的是 AES 或强口令，需字典/已知明文攻击"
    _close_quiet(zf)                       # 批量试口令时不显式关会攒句柄、锁住文件
    return res


# ---------------------------------------------------------------------------
# 解密：单字节 XOR
# ---------------------------------------------------------------------------

_PRINTABLE = set(range(32, 127)) | {9, 10, 13}
_MARKERS = (b"http", b"android", b"com.", b"public", b"class", b"{", b"}", b"<", b"PK\x03\x04")


def score_xor(data: bytes) -> float:
    """给一段解出来的字节打分：可打印率 + 明文特征命中。"""
    if not data:
        return 0.0
    printable = sum(1 for b in data if b in _PRINTABLE) / len(data)
    hits = sum(1 for m in _MARKERS if m in data)
    return printable * 100 + hits * 12


def try_single_byte_xor(path: str | Path, out_dir: str | Path | None = None,
                        min_score: float = 88.0) -> DecryptResult:
    """暴力 256 个单字节密钥，挑得分最高的。"""
    p = Path(path)
    res = DecryptResult()
    try:
        data = p.read_bytes()[:262144]
    except OSError as e:
        res.note = str(e)
        return res
    if not data:
        res.note = "空文件"
        return res

    best_k, best_score, best = 0, 0.0, b""
    for k in range(256):
        probe = bytes(b ^ k for b in data[:4096])
        s = score_xor(probe)
        if s > best_score:
            best_k, best_score = k, s
    res.tried = 256
    if best_score < min_score:
        res.note = f"最佳候选得分 {best_score:.1f}（阈值 {min_score}），不像单字节 XOR"
        return res

    best = bytes(b ^ best_k for b in data)
    res.ok = True
    res.method = f"单字节 XOR（key=0x{best_k:02x}）"
    res.password = f"0x{best_k:02x}"
    if out_dir:
        od = Path(out_dir)
        od.mkdir(parents=True, exist_ok=True)
        out = od / (p.stem + f"_xor{best_k:02x}" + p.suffix)
        out.write_bytes(best)
        res.out_path = str(out)
    res.note = f"可打印率 {best_score:.1f}，疑似命中"
    return res


# ---------------------------------------------------------------------------
# 7z / RAR 口令尝试（交给 7zr）
# ---------------------------------------------------------------------------

def try_7z_password(path: str | Path, out_dir: str | Path | None = None,
                    passwords: list[str] | None = None) -> DecryptResult:
    from ..tools.registry import registry
    from ..tools import runner

    p = Path(path)
    res = DecryptResult()
    reg = registry()
    if not reg.has("7z"):
        res.note = "未找到 7-Zip，无法尝试"
        return res
    t = reg.get("7z")
    od = Path(out_dir) if out_dir else p.parent / (p.stem + "_out")

    for i, pw in enumerate(passwords or WEAK_PASSWORDS, 1):
        res.tried = i
        od.mkdir(parents=True, exist_ok=True)
        r = runner.run(t.cmd("x", f"-p{pw}", "-y", f"-o{od}", p), timeout=60)
        if r.rc == 0:
            res.ok = True
            res.password = pw
            res.method = "7z/RAR 弱口令"
            res.out_path = str(od)
            res.note = f"命中口令，已解到 {od}"
            return res
    res.note = f"试了 {res.tried} 个口令未命中"
    return res


# ---------------------------------------------------------------------------
# 从代码里找硬编码密钥（配合 APK 分析用）
# ---------------------------------------------------------------------------

KEY_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("AES 密钥（16/24/32 字节 hex）", re.compile(rb"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{48}|[0-9a-fA-F]{64})(?![0-9a-fA-F])")),
    ("Base64 长串（可能为密钥）", re.compile(rb"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{32,200}={0,2}(?![A-Za-z0-9+/=])")),
    ("PEM 私钥", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("JWT", re.compile(rb"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")),
    ("硬编码口令字段", re.compile(rb"(?i)(?:password|passwd|pwd|secret|apikey|api_key|token)\s*[=:]\s*[\"']([^\"']{4,64})[\"']")),
]

# 源码里的字符串字面量：密钥通常在这些引号里，而类型描述符、注释不在
_STR_LIT = re.compile(r'"([^"\\\n]{6,300})"')

_TEXT_EXT = (".java", ".kt", ".smali", ".xml", ".js", ".json",
             ".properties", ".txt", ".cfg", ".ini", ".yml", ".yaml")


def _prep_source(data: bytes) -> bytes:
    """
    把源码文件"提纯"成一行行字符串字面量。

    直接拿源码字节跑正则会大量误报：
      * jadx 头注释里的 R8 映射 hash（64 位十六进制）
      * smali 类型描述符 Landroid/animation/ValueAnimator;（长得像 Base64）
    只保留引号内的内容，误报能少一个数量级。
    """
    try:
        text = data.decode("utf-8", "ignore")
    except Exception:
        return data
    keep = [ln for ln in text.splitlines()
            if "JADX INFO" not in ln and "r8-map-id" not in ln]
    lits = _STR_LIT.findall("\n".join(keep))
    return "\n".join(lits).encode("utf-8")


def _b64_like(s: str) -> bool:
    """Base64 的硬性特征：长度是 4 的倍数，且字符类别不止一种。"""
    if len(s) < 24 or len(s) % 4 != 0:
        return False
    cats = 0
    if any(c.isupper() for c in s):
        cats += 1
    if any(c.islower() for c in s):
        cats += 1
    if any(c.isdigit() for c in s):
        cats += 1
    if "+" in s or "=" in s:
        cats += 1
    return cats >= 2


def find_hardcoded_keys(path: str | Path, max_hits: int = 40) -> list[tuple[str, str]]:
    """
    在文件（或目录下所有文本/二进制）里找疑似硬编码密钥。

    返回 [(类型, 命中片段)]，片段截断到 80 字符。
    """
    hits: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    targets: list[Path] = []
    p = Path(path)
    if p.is_dir():
        for f in p.rglob("*"):
            if f.is_file() and f.suffix.lower() in _TEXT_EXT + (".so", ".dex"):
                targets.append(f)
            if len(targets) > 4000:
                break
    elif p.is_file():
        targets = [p]

    for f in targets:
        try:
            with f.open("rb") as fh:            # 大 so/dex 只扫前 4MB
                raw = fh.read(4_000_000)
        except OSError:
            continue

        # 源码只留字符串字面量；二进制（so/dex）直接扫字节
        data = _prep_source(raw) if f.suffix.lower() in _TEXT_EXT else raw
        if not data:
            continue

        for label, rx in KEY_PATTERNS:
            for m in rx.finditer(data):
                try:
                    frag = m.group(0).decode("utf-8", "replace")[:80]
                except Exception:
                    continue
                if not frag.strip():
                    continue
                if label.startswith("Base64"):
                    # 纯十六进制串是哈希/构建 ID，不是 Base64；
                    # 真正的 AES 密钥由上面那条 hex 规则负责报。
                    if re.fullmatch(r"[0-9a-fA-F]+", frag):
                        continue
                    if not _b64_like(frag):
                        continue
                key = (label, frag)
                if key in seen:
                    continue
                seen.add(key)
                hits.append((f"{label} @ {f.name}", frag))
                if len(hits) >= max_hits:
                    return hits
    return hits
