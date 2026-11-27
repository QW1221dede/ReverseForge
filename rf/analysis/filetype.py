#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 rf.analysis.filetype · 任意文件识别与路由（不止 APK）
============================================================================

【为什么需要这一层】
    真实目标里，校验逻辑从来不只是藏在 APK 里：
      · Windows 上的 EXE / DLL —— 注册码、机器码、试用期、看门狗
      · 客户端 .so / .dylib   —— JNI 校验、反调试、完整性自检
      · 脚本 .py/.js/.lua/.ps1/.bat/.ahk —— 卡密直接写死在源码里
      · JAR / class           —— Java 桌面工具（Minecraft 启动器那类）
      · 自定义容器/数据文件    —— 往往和主程序配套，本身就是加密的
    所以任何流水线的第一步都得是「这到底是什么」，再决定用哪套分析器。
    识别错了，后面全白干。

【判定顺序（可靠度从高到低）】
    1. 魔数（头部固定字节）—— 最硬，几乎不会骗人
    2. 容器内部结构     —— PE 的 e_lfanew 指针、ELF 的 e_type、ZIP 目录项
    3. 扩展名 + 内容特征 —— 只对脚本用，因为扩展名可以随便改
    4. 熵 + 可打印率     —— 前三样都失败时的兜底（熵 > 7.5 判疑似加密/压缩）

【关键区分：加密 vs 压缩】
    两者熵都很高。区别在于压缩有结构（ZIP 有目录、gzip 有头），
    而「裸密文」什么都不认。所以全部魔数都不中、熵又 > 7.5 → 判 encrypted。
    这是本工具最常遇到的一类目标：作者把数据 AES 之后直接扔进文件里。

【诚实边界】
    这里只回答「是什么」和「该用哪把刀」，不做破解。
    判不出来就老实报 unknown，不猜、不硬塞一个类型。
============================================================================
"""

from __future__ import annotations

import math
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# 分类常量（前端按这个上色/分组）
# ---------------------------------------------------------------------------

CAT_SCRIPT = "script"        # 解释型脚本
CAT_BINARY = "binary"        # 本地可执行 / 动态库
CAT_ANDROID = "android"      # apk / dex / so / aab
CAT_JAVA = "java"            # class / jar
CAT_ARCHIVE = "archive"      # 压缩包 / 归档
CAT_DATA = "data"            # 数据库 / 序列化数据
CAT_DOC = "doc"              # 文档
CAT_MEDIA = "media"          # 图片 / 音视频
CAT_KEY = "key"              # 证书 / 私钥（明文）
CAT_ENCRYPTED = "encrypted"  # 疑似密文（无结构高熵）
CAT_TEXT = "text"            # 纯文本 / 配置
CAT_UNKNOWN = "unknown"

CAT_CN = {
    CAT_SCRIPT: "脚本", CAT_BINARY: "本地程序", CAT_ANDROID: "安卓",
    CAT_JAVA: "Java", CAT_ARCHIVE: "压缩包", CAT_DATA: "数据",
    CAT_DOC: "文档", CAT_MEDIA: "媒体", CAT_KEY: "密钥/证书",
    CAT_ENCRYPTED: "疑似加密", CAT_TEXT: "文本", CAT_UNKNOWN: "未知",
}

# ---------------------------------------------------------------------------
# 魔数表
#   顺序有意义：更具体的放前面（如 ZIP 分卷在 ZIP 之前）
# ---------------------------------------------------------------------------

_MAGIC: list[tuple[bytes, str, str, str]] = [
    # data: 魔数 | 中文标签 | category | 机器标签(real)
    (b"PK\x03\x04", "ZIP 容器", CAT_ARCHIVE, "zip"),
    (b"PK\x05\x06", "ZIP（空包）", CAT_ARCHIVE, "zip"),
    (b"PK\x07\x08", "ZIP 分卷", CAT_ARCHIVE, "zip"),
    (b"Rar!\x1a\x07", "RAR 压缩包", CAT_ARCHIVE, "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z 压缩包", CAT_ARCHIVE, "7z"),
    (b"\x1f\x8b\x08", "gzip", CAT_ARCHIVE, "gzip"),
    (b"BZh", "bzip2", CAT_ARCHIVE, "bzip2"),
    (b"\xfd7zXZ\x00", "xz", CAT_ARCHIVE, "xz"),
    (b"\x28\xb5\x2f\xfd", "zstd", CAT_ARCHIVE, "zstd"),
    (b"\x5d\x00\x00", "LZMA 裸流", CAT_ARCHIVE, "lzma"),

    (b"\x7fELF", "ELF 可执行 / 动态库", CAT_BINARY, "elf"),
    (b"MZ", "PE（Windows 可执行）", CAT_BINARY, "pe"),
    (b"\xfe\xed\xfa\xce", "Mach-O 32 位大端", CAT_BINARY, "macho"),
    (b"\xce\xfa\xed\xfe", "Mach-O 32 位小端", CAT_BINARY, "macho"),
    (b"\xfe\xed\xfa\xcf", "Mach-O 64 位大端", CAT_BINARY, "macho"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64 位小端", CAT_BINARY, "macho"),
    (b"\xca\xfe\xba\xbe", "Java class / Mach-O 通用包", CAT_JAVA, "class"),
    (b"\x00asm", "WebAssembly 模块", CAT_BINARY, "wasm"),

    (b"dex\n", "DEX 字节码", CAT_ANDROID, "dex"),
    (b"cdex", "Compact DEX", CAT_ANDROID, "cdex"),
    (b"ANDROID!", "Android boot 镜像", CAT_ANDROID, "bootimg"),
    (b"\x27\x05\x19\x56", "Android sparse image", CAT_ANDROID, "sparse"),

    (b"\x1bLua", "Lua 字节码", CAT_SCRIPT, "luac"),
    (b"<?php", "PHP 源码", CAT_SCRIPT, "php"),
    (b"#!", "Shebang 脚本", CAT_SCRIPT, "shebang"),
    (b"@echo off", "批处理（无 shebang）", CAT_SCRIPT, "bat"),
    (b"@ECHO OFF", "批处理（无 shebang）", CAT_SCRIPT, "bat"),

    (b"SQLite format 3\x00", "SQLite 数据库", CAT_DATA, "sqlite"),
    (b"%PDF", "PDF 文档", CAT_DOC, "pdf"),
    (b"\xd0\xcf\x11\xe0", "OLE（旧 Office / MSI）", CAT_DOC, "ole"),
    (b"\x89PNG", "PNG 图片", CAT_MEDIA, "png"),
    (b"\xff\xd8\xff", "JPEG 图片", CAT_MEDIA, "jpeg"),
    (b"GIF8", "GIF 图片", CAT_MEDIA, "gif"),
    (b"RIFF", "RIFF（WAV/AVI/WebP）", CAT_MEDIA, "riff"),
    (b"OggS", "Ogg 音频", CAT_MEDIA, "ogg"),
    (b"ID3", "MP3 音频", CAT_MEDIA, "mp3"),

    (b"Salted__", "OpenSSL enc（带盐密文）", CAT_ENCRYPTED, "openssl"),
    (b"\x53\x61\x6c\x74\x65\x64\x5f\x5f", "OpenSSL enc（带盐密文）", CAT_ENCRYPTED, "openssl"),
    (b"-----BEGIN", "PEM 证书 / 私钥（明文）", CAT_KEY, "pem"),
    (b"ssh-rsa", "SSH 公钥", CAT_KEY, "sshkey"),
]

# 扩展名 → 脚本语言
_EXT_LANG: dict[str, str] = {
    ".py": "py", ".pyw": "py", ".pyc": "pyc", ".pyo": "pyc",
    ".js": "js", ".mjs": "js", ".cjs": "js", ".jsx": "js", ".ts": "js",
    ".lua": "lua", ".luac": "luac",
    ".ps1": "ps1", ".psm1": "ps1",
    ".bat": "bat", ".cmd": "bat",
    ".sh": "sh", ".bash": "sh", ".zsh": "sh", ".ksh": "sh",
    ".vbs": "vbs", ".vbe": "vbs", ".wsf": "vbs",
    ".au3": "au3", ".ahk": "ahk", ".tcl": "tcl", ".pl": "pl",
    ".rb": "rb", ".php": "php", ".nut": "nut", ".nsi": "nsi",
    ".jar": "jar", ".class": "class",
    ".pyz": "zip", ".whl": "zip", ".egg": "zip",
}

# shebang → 语言
_SHEBANG_ALIAS: dict[str, str] = {
    "python": "py", "python2": "py", "python3": "py", "pypy": "py", "pypy3": "py",
    "node": "js", "nodejs": "js", "deno": "js", "bun": "js",
    "sh": "sh", "bash": "sh", "zsh": "sh", "dash": "sh", "ksh": "sh",
    "perl": "pl", "ruby": "rb", "php": "php", "lua": "lua", "tclsh": "tcl",
    "pwsh": "ps1", "powershell": "ps1",
}

# 各类型建议用的分析器（GUI/脚本按这个提示下一步）
_ROUTE: dict[str, list[str]] = {
    "pe": ["pe", "strings", "ghidra", "authscan"],
    "elf": ["elf", "strings", "ghidra", "authscan"],
    "macho": ["strings", "ghidra"],
    "class": ["authscan", "strings"],
    "jar": ["authscan", "unpack", "strings"],
    "dex": ["dex", "strings", "patch_scan"],
    "apk": ["apk_info", "apk_unpack", "patch_scan"],
    "zip": ["unpack", "zip_password", "identify"],
    "py": ["authscan", "annotate"],
    "js": ["authscan", "annotate"],
    "lua": ["authscan", "strings"],
    "sh": ["authscan"],
    "bat": ["authscan"],
    "ps1": ["authscan"],
    "unknown": ["identify", "strings", "segments"],
}

_SCRIPT_LANGS = {"py", "pyc", "js", "lua", "luac", "sh", "bat", "ps1", "vbs",
                 "au3", "ahk", "tcl", "pl", "rb", "php", "nsi", "nut"}


# ---------------------------------------------------------------------------
# 基础度量
# ---------------------------------------------------------------------------

def shannon(data: bytes) -> float:
    """香农熵（bit/byte）。0=全同字节，8=完全随机。"""
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


def printable_ratio(data: bytes) -> float:
    """可打印率。9/10/13 也算可打印（换行/制表/回车）。"""
    if not data:
        return 0.0
    ok = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return ok / len(data)


def decode_text(data: bytes) -> str | None:
    """尽量按 UTF-8 / GBK 解出文本，全失败返回 None。"""
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    for enc in ("utf-8", "gb18030", "utf-16"):
        try:
            t = data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
        if t and "\x00" not in t:
            return t
    return None


# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------

@dataclass
class FileKind:
    """一个文件的识别结论。"""
    path: str = ""
    size: int = 0
    ext: str = ""
    real: str = "unknown"       # 机器标签：pe/elf/py/js/zip/encrypted...
    label: str = "未知格式"      # 中文标签
    category: str = CAT_UNKNOWN
    confidence: int = 0         # 0-100
    entropy: float = 0.0
    printable: float = 0.0
    lang: str = ""              # 脚本语言（脚本类才有）
    arch: str = ""              # x86/x64/ARM64...
    packed: bool = False        # 疑似加壳/自解压
    notes: list[str] = field(default_factory=list)
    route: list[str] = field(default_factory=list)

    @property
    def is_script(self) -> bool:
        return self.category == CAT_SCRIPT

    @property
    def is_binary(self) -> bool:
        return self.category in (CAT_BINARY, CAT_ANDROID, CAT_JAVA)

    @property
    def cat_cn(self) -> str:
        return CAT_CN.get(self.category, self.category)

    def brief(self) -> str:
        s = f"{Path(self.path).name}  {self.label}  {_human(self.size)}"
        s += f"  熵 {self.entropy:.2f}  可信 {self.confidence}%"
        if self.packed:
            s += "  ⚠ 疑似加壳"
        if self.category == CAT_ENCRYPTED:
            s += "  ⚠ 疑似加密"
        return s

    def to_row(self) -> str:
        name = Path(self.path).name
        if len(name) > 34:
            name = name[:31] + "..."
        flags = ""
        if self.packed:
            flags += "壳"
        if self.category == CAT_ENCRYPTED:
            flags += "密"
        return (f"{name:<36} {self.label:<18} {_human(self.size):>9}  "
                f"熵{self.entropy:>5.2f}  {self.confidence:>3}%  {flags}")


def _human(n: int) -> str:
    if n < 1024:
        return f"{n}B"
    if n < 1024 * 1024:
        return f"{n / 1024:.0f}KB"
    if n < 1024 * 1024 * 1024:
        return f"{n / 1024 / 1024:.1f}MB"
    return f"{n / 1024 / 1024 / 1024:.2f}GB"


# ---------------------------------------------------------------------------
# PE 细化（EXE vs DLL / .NET / 加壳）
# ---------------------------------------------------------------------------

# 常见加壳器的节名特征
_PACKER_SECTIONS = {
    b"UPX0": "UPX", b"UPX1": "UPX", b"UPX2": "UPX", b".UPX": "UPX",
    b".aspack": "ASPack", b".adata": "ASPack",
    b".themida": "Themida", b".vmp0": "VMProtect", b".vmp1": "VMProtect",
    b".enigma1": "Enigma", b".enigma2": "Enigma",
    b".petite": "Petite", b".packed": "未知壳",
    b".MPRESS1": "MPRESS", b".MPRESS2": "MPRESS",
}

_MACHINE = {0x014C: "x86", 0x8664: "x64", 0x01C0: "ARM", 0xAA64: "ARM64",
            0x01C4: "ARMv7", 0x0200: "IA64"}


def _pe_detail(data: bytes, more) -> tuple[str, str, bool, list[str]]:
    """
    解析 PE。返回 (label, arch, packed, notes)。
    more: 一个可调用对象，能按需读更多字节（用于 e_lfanew 很远的情况）。
    """
    notes: list[str] = []
    if len(data) < 0x40:
        return "PE（头被截断）", "", False, ["文件不足 64 字节，PE 头不完整"]
    try:
        lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    except struct.error:
        return "PE", "", False, notes
    need = lfanew + 24 + 240 + 40 * 4
    buf = data
    if lfanew + 24 > len(buf):
        buf = more(lfanew + 0x400)
    if len(buf) < lfanew + 24 or buf[lfanew:lfanew + 4] != b"PE\x00\x00":
        return "PE（签名缺失，可能是自解压头）", "", False, ["有 MZ 但没有 PE 签名"]
    machine, nsec = struct.unpack_from("<HH", buf, lfanew + 4)
    opt_size = struct.unpack_from("<H", buf, lfanew + 20)[0]
    chars = struct.unpack_from("<H", buf, lfanew + 22)[0]
    arch = _MACHINE.get(machine, f"0x{machine:04X}")

    is_dll = bool(chars & 0x2000)
    label = "PE 动态库（DLL）" if is_dll else "PE 可执行（EXE）"

    # .NET：可选头数据目录第 15 项（索引 14）CLR 运行时头
    dotnet = False
    opt_off = lfanew + 24
    if opt_size >= 224 and machine in (0x014C, 0x8664):
        magic = struct.unpack_from("<H", buf, opt_off)[0]
        dd = opt_off + (96 if magic == 0x10B else 112)
        if dd + 8 * 15 <= len(buf):
            clr_rva, clr_size = struct.unpack_from("<II", buf, dd + 8 * 14)
            dotnet = clr_rva != 0 and clr_size != 0
    if dotnet:
        label = ("C# / .NET 动态库" if is_dll else "C# / .NET 可执行")
        notes.append("托管程序集，可直接用 dnSpy/ILSpy 反编译")

    # 节名 → 加壳判定
    packed = False
    sec_off = opt_off + opt_size
    for i in range(min(nsec, 40)):
        off = sec_off + i * 40
        if off + 40 > len(buf):
            break
        name = buf[off:off + 8].rstrip(b"\x00")
        for sig, pname in _PACKER_SECTIONS.items():
            if name.startswith(sig):
                packed = True
                notes.append(f"节名 {name.decode('latin1')} → {pname} 壳")
    return label, arch, packed, notes


# ---------------------------------------------------------------------------
# ELF 细化
# ---------------------------------------------------------------------------

_ELF_TYPE = {0: "NONE", 1: "可重定位(.o)", 2: "可执行", 3: "共享库/PIE", 4: "core"}
_ELF_MACH = {0x03: "x86", 0x3E: "x64", 0x28: "ARM", 0xB7: "ARM64",
             0x08: "MIPS", 0xF3: "RISC-V"}


def _elf_detail(data: bytes) -> tuple[str, str, list[str]]:
    notes: list[str] = []
    if len(data) < 20:
        return "ELF（头被截断）", "", notes
    cls = data[4]           # 1=32 位 2=64 位
    endian = "<" if data[5] == 1 else ">"
    try:
        e_type = struct.unpack_from(endian + "H", data, 16)[0]
        e_mach = struct.unpack_from(endian + "H", data, 18)[0]
    except struct.error:
        return "ELF", "", notes
    arch = _ELF_MACH.get(e_mach, f"0x{e_mach:X}") + ("（64 位）" if cls == 2 else "（32 位）")
    t = _ELF_TYPE.get(e_type, str(e_type))
    if e_type == 3:
        label = "ELF 共享库（.so / PIE）"
    elif e_type == 2:
        label = "ELF 可执行"
    else:
        label = f"ELF {t}"
    return label, arch, notes


# ---------------------------------------------------------------------------
# 脚本语言推断
# ---------------------------------------------------------------------------

_SHEBANG_RE = re.compile(rb"^#!\s*(?:\S*/)?(?:env\s+)?([A-Za-z0-9_.+-]+)")


def _shebang_lang(data: bytes) -> str:
    m = _SHEBANG_RE.match(data[:200])
    if not m:
        return ""
    name = m.group(1).decode("latin1", "ignore").lower()
    if name.startswith("python"):
        return "py"
    return _SHEBANG_ALIAS.get(name, "")


def _content_lang(text: str) -> str:
    """没有 shebang / 扩展名可疑时，靠内容特征猜（只给中等可信度）。"""
    head = text[:4000]
    scores = {
        "py": len(re.findall(r"(?m)^\s*(?:import\s+\w+|from\s+\w+\s+import|def\s+\w+\s*\()", head)),
        "js": len(re.findall(r"\b(?:function\s*\w*|const\s+\w+\s*=|let\s+\w+\s*=|=>|require\(|module\.exports)", head)),
        "php": len(re.findall(r"<\?php|\$\w+\s*=", head)),
        "lua": len(re.findall(r"(?m)^\s*(?:local\s+\w+|function\s+\w+\s*\()|end\b", head)),
        "sh": len(re.findall(r"(?m)^\s*(?:#!/|if\s+\[|export\s+\w+=|fi\b|done\b)", head)),
        "bat": len(re.findall(r"(?i)(?m)^\s*(?:@echo|set\s+\w+=|goto\s+\w+|if\s+exist)", head)),
        "ps1": len(re.findall(r"(?i)\b(?:param\s*\(|\$\w+\s*=\s*Get-|Write-Host|function\s+\w+-\w+)", head)),
        "vbs": len(re.findall(r"(?i)(?m)^\s*(?:Dim\s+\w+|WScript\.|CreateObject\()", head)),
    }
    best = max(scores.items(), key=lambda kv: kv[1])
    return best[0] if best[1] >= 3 else ""


# ---------------------------------------------------------------------------
# 主识别
# ---------------------------------------------------------------------------

def sniff(path: str | Path, sample: int = 8192) -> FileKind:
    """识别单个文件。任何异常都兜成 unknown，不向上抛。"""
    p = Path(path)
    k = FileKind(path=str(p), ext=p.suffix.lower())
    try:
        k.size = p.stat().st_size
    except OSError as e:
        k.label = "无法读取"
        k.notes.append(str(e))
        return k

    if k.size == 0:
        k.label = "空文件"
        k.category = CAT_TEXT
        k.confidence = 100
        return k

    def _read(n: int) -> bytes:
        try:
            with p.open("rb") as f:
                return f.read(n)
        except OSError:
            return b""

    data = _read(sample)
    # 大文件按 3 个位置采样算熵，避免只读头部得出错误结论
    if k.size > sample * 4:
        chunks = [data]
        try:
            with p.open("rb") as f:
                for frac in (0.35, 0.7):
                    f.seek(int(k.size * frac))
                    chunks.append(f.read(4096))
                f.seek(max(0, k.size - 4096))
                chunks.append(f.read(4096))
        except OSError:
            pass
        blob = b"".join(chunks)
    else:
        blob = data
    k.entropy = shannon(blob)
    k.printable = printable_ratio(blob)

    # ---- 1) 魔数 ----
    for magic, label, cat, real in _MAGIC:
        if not data.startswith(magic):
            continue
        k.label, k.category, k.real = label, cat, real

        if real == "pe":
            label2, arch, packed, notes = _pe_detail(data, _read)
            k.label, k.arch, k.packed = label2, arch, packed
            k.notes.extend(notes)
            k.confidence = 97
        elif real == "elf":
            label2, arch, notes = _elf_detail(data)
            k.label, k.arch = label2, arch
            k.notes.extend(notes)
            k.confidence = 97
        elif real == "class":
            # Java class 的次版本后面跟 major，45..70 之间；否则是 Mach-O 通用包
            if len(data) >= 8:
                major = struct.unpack_from(">H", data, 6)[0]
                if 45 <= major <= 80:
                    k.real, k.label, k.category = "class", "Java class 字节码", CAT_JAVA
                    k.notes.append(f"class 版本 {major}.0"
                                   f"（{'Java ' + str(major - 44) if major > 48 else '很老的 JDK'}）")
                else:
                    k.real, k.label, k.category = "macho", "Mach-O 通用包", CAT_BINARY
            k.confidence = 92
        elif real == "zip":
            k.confidence = 95
            # ZIP 家族再细分：apk / jar / docx / 普通 zip
            sub = _zip_flavor(p, data)
            if sub:
                k.real, k.label, k.category = sub
                k.confidence = 96
        elif real == "shebang":
            lang = _shebang_lang(data)
            k.real, k.lang = (lang or "sh"), lang
            k.label = f"{_lang_cn(lang) or 'Shell'} 脚本"
            k.confidence = 95
        else:
            k.confidence = 95

        # 补充：PE/ELF 的扩展名一致性（伪装提醒）
        if k.ext and k.real in ("pe", "elf") and _ext_mismatch(k.ext, k.real):
            k.notes.append(f"扩展名 {k.ext} 与实际类型不符，可能是伪装")
        k.route = list(_ROUTE.get(k.real, []))
        return k

    # ---- 2) 没有魔数：按扩展名 + 内容判断脚本/文本 ----
    lang = _EXT_LANG.get(k.ext, "")
    if lang and lang not in ("jar", "class", "zip"):
        k.real, k.lang, k.category = lang, lang, CAT_SCRIPT
        k.label = f"{_lang_cn(lang)} 脚本"
        k.confidence = 80 if lang in _SCRIPT_LANGS else 60
        if k.entropy > 7.2:
            k.notes.append("熵很高，可能是加密过的脚本（先解密再看）")
            k.category = CAT_ENCRYPTED if k.entropy > 7.7 else CAT_SCRIPT
        k.route = list(_ROUTE.get(lang, _ROUTE["unknown"]))
        return k

    text = decode_text(data[:4096]) if k.printable > 0.85 else None
    if text is not None:
        guess = _content_lang(text)
        if guess:
            k.real, k.lang, k.category = guess, guess, CAT_SCRIPT
            k.label = f"{_lang_cn(guess)} 脚本（按内容推断）"
            k.confidence = 65
            k.notes.append("扩展名不可靠，按源码特征判定")
            k.route = list(_ROUTE.get(guess, []))
            return k
        k.real, k.category = "text", CAT_TEXT
        k.label = "纯文本 / 配置"
        k.confidence = 75
        k.route = ["strings", "authscan"]
        return k

    # ---- 3) 兜底：先看是不是"明文头 + 密文"（最常见的自定义容器形态） ----
    #   判据：开头有一段连续可打印 ASCII，后面整体熵很高。
    #   这种情况直接说"混合文件"，比笼统报"疑似加密"有用得多。
    head_run = 0
    limit = min(len(data), 8192)
    while head_run < limit and (32 <= data[head_run] < 127 or data[head_run] in (9, 10, 13)):
        head_run += 1
    if head_run >= 16 and k.entropy >= 7.2:
        k.category = CAT_ENCRYPTED
        k.real = "mixed"
        k.label = "明文头 + 密文（混合文件）"
        k.confidence = 75
        k.notes.append(f"前 {head_run} 字节可读，之后是高熵密文")
        k.notes.append("下一步：segments 量出准确分界（可能能捞到 key/iv）")
        k.route = ["segments", "keys_any", "decrypt_auto"]
        return k

    if k.entropy >= 7.5:
        k.category = CAT_ENCRYPTED
        k.real = "encrypted"
        k.label = "疑似加密数据（无结构高熵）"
        k.confidence = 70 if k.entropy >= 7.8 else 60
        k.notes.append("熵接近 8，且不匹配任何容器魔数 → 裸密文")
        k.notes.append("下一步：segments 找明文头，decrypt 自动试解")
        k.route = ["segments", "identify", "decrypt_auto"]
        return k
    if k.entropy >= 6.6:
        k.category = CAT_ENCRYPTED
        k.real = "obfuscated"
        k.label = "疑似混淆/压缩数据"
        k.confidence = 50
        k.route = ["segments", "strings", "decrypt_auto"]
        return k

    k.real = "unknown"
    k.label = "未知二进制"
    k.confidence = 40
    k.notes.append("魔数、扩展名、熵三条都没命中；可以试 strings / segments")
    k.route = list(_ROUTE["unknown"])
    return k


def _lang_cn(lang: str) -> str:
    return {
        "py": "Python", "pyc": "Python 字节码", "js": "JavaScript",
        "lua": "Lua", "luac": "Lua 字节码", "sh": "Shell", "bat": "批处理",
        "ps1": "PowerShell", "vbs": "VBScript", "au3": "AutoIt",
        "ahk": "AutoHotkey", "tcl": "Tcl", "pl": "Perl", "rb": "Ruby",
        "php": "PHP", "jar": "JAR", "class": "Java", "nsi": "NSIS",
        "nut": "Squirrel", "shebang": "Shell",
    }.get(lang, "")


def _ext_mismatch(ext: str, real: str) -> bool:
    fam = {
        "pe": {".exe", ".dll", ".sys", ".ocx", ".scr", ".cpl", ".drv"},
        "elf": {".so", ".elf", ".bin", ".ko", ".o", ".a"},
    }
    s = fam.get(real)
    return bool(s) and ext not in s and ext not in ("", ".bin", ".dat")


def _zip_flavor(p: Path, head: bytes) -> tuple[str, str, str] | None:
    """ZIP 家族细分：apk / jar / docx / xlsx / 普通 zip。"""
    try:
        if p.suffix.lower() in (".apk", ".aab", ".apks", ".xapk"):
            return ("apk", "APK 安装包", CAT_ANDROID)
        if p.suffix.lower() == ".jar":
            return ("jar", "JAR 包", CAT_JAVA)
        with p.open("rb") as f:
            # 只读中央目录尾部找特征文件名，避免全量解压
            f.seek(max(0, p.stat().st_size - 65536))
            tail = f.read()
        if b"classes.dex" in tail or b"AndroidManifest.xml" in tail:
            return ("apk", "APK 安装包（扩展名不符）", CAT_ANDROID)
        if b"META-INF/MANIFEST.MF" in tail and b".class" in tail:
            return ("jar", "JAR 包（扩展名不符）", CAT_JAVA)
        if b"word/" in tail:
            return ("docx", "Word 文档（OOXML）", CAT_DOC)
        if b"xl/" in tail:
            return ("xlsx", "Excel 文档（OOXML）", CAT_DOC)
        if b"ppt/" in tail:
            return ("pptx", "PowerPoint 文档（OOXML）", CAT_DOC)
    except OSError:
        pass
    return None


# ---------------------------------------------------------------------------
# 批量：整个目录扫一遍
# ---------------------------------------------------------------------------

@dataclass
class ScanResult:
    root: str = ""
    files: int = 0
    kinds: list[FileKind] = field(default_factory=list)
    by_category: dict[str, int] = field(default_factory=dict)
    by_real: dict[str, int] = field(default_factory=dict)
    encrypted: list[FileKind] = field(default_factory=list)
    scripts: list[FileKind] = field(default_factory=list)
    binaries: list[FileKind] = field(default_factory=list)
    skipped: int = 0
    elapsed: float = 0.0

    def summary(self) -> str:
        parts = [f"{self.files} 个文件，用时 {self.elapsed:.2f}s"]
        if self.by_category:
            top = sorted(self.by_category.items(), key=lambda kv: -kv[1])[:6]
            parts.append("分类 " + " / ".join(f"{CAT_CN.get(k, k)} {v}" for k, v in top))
        if self.encrypted:
            parts.append(f"疑似加密 {len(self.encrypted)} 个")
        if self.scripts:
            parts.append(f"脚本 {len(self.scripts)} 个")
        if self.skipped:
            parts.append(f"跳过 {self.skipped}")
        return "，".join(parts)

    def table(self, limit: int = 40, category: str = "") -> str:
        rows = self.kinds
        if category:
            rows = [k for k in rows if k.category == category]
        rows = sorted(rows, key=lambda k: -k.size)[:limit]
        if not rows:
            return "（没有匹配的文件）"
        out = [f"{'文件':<36} {'类型':<18} {'大小':>9}  熵    可信  备注"]
        out += [k.to_row() for k in rows]
        return "\n".join(out)


def scan_tree(root: str | Path, max_files: int = 4000,
              min_size: int = 1, follow_links: bool = False) -> ScanResult:
    """递归识别目录。超大目录按 max_files 截断（按大小优先保留大文件）。"""
    import time as _t
    t0 = _t.time()
    rp = Path(root)
    res = ScanResult(root=str(rp))

    if rp.is_file():
        cand = [rp]
    else:
        cand = []
        for p in rp.rglob("*"):
            if len(cand) >= max_files:
                res.skipped += 1
                continue
            try:
                if p.is_symlink() and not follow_links:
                    res.skipped += 1
                    continue
                if not p.is_file():
                    continue
                if p.stat().st_size < min_size:
                    res.skipped += 1
                    continue
            except OSError:
                res.skipped += 1
                continue
            cand.append(p)

    for p in cand:
        k = sniff(p)
        res.kinds.append(k)
        res.files += 1
        res.by_category[k.category] = res.by_category.get(k.category, 0) + 1
        res.by_real[k.real] = res.by_real.get(k.real, 0) + 1
        if k.category == CAT_ENCRYPTED:
            res.encrypted.append(k)
        elif k.category == CAT_SCRIPT:
            res.scripts.append(k)
        elif k.is_binary:
            res.binaries.append(k)

    res.elapsed = _t.time() - t0
    return res


def report_md(res: ScanResult) -> str:
    """输出 Markdown 报告（给 GUI 的"报告"页和脚本用）。"""
    L = [
        "# 文件类型清单",
        "",
        f"- 根目录：`{res.root}`",
        f"- 文件数：{res.files}（跳过 {res.skipped}）",
        f"- 用时：{res.elapsed:.2f}s",
        "",
        "## 分类统计",
        "",
        "| 分类 | 数量 |",
        "|---|---|",
    ]
    for k, v in sorted(res.by_category.items(), key=lambda kv: -kv[1]):
        L.append(f"| {CAT_CN.get(k, k)} | {v} |")

    L += ["", "## 明细（按体积）", "",
          "| 文件 | 类型 | 大小 | 熵 | 可信 | 备注 |", "|---|---|---|---|---|---|"]
    for k in sorted(res.kinds, key=lambda x: -x.size)[:200]:
        nb = "；".join(k.notes)[:80]
        L.append(f"| `{Path(k.path).name}` | {k.label} | {_human(k.size)} | "
                 f"{k.entropy:.2f} | {k.confidence}% | {nb} |")

    if res.encrypted:
        L += ["", "## 疑似加密（优先处理）", ""]
        for k in res.encrypted[:40]:
            L.append(f"- `{k.path}`（{_human(k.size)}，熵 {k.entropy:.2f}，{k.confidence}%）")
            L.append(f"  建议：`rf.segments(...)` 找明文头 → `rf.decrypt_auto(...)` 自动试解")

    return "\n".join(L)
