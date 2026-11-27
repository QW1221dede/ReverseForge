#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 rf.analysis.dex · DEX 文件解析器（纯 Python，无依赖）
============================================================================
    不调外部工具就能拿到 DEX 的硬指标：版本、类/方法/字段/字符串数量、
    以及完整字符串池。用于：
      * 快速判断 APK 规模（有多少类、多少方法，是不是多 dex）
      * 提前看出加固特征（字符串池里出现 libjiagu / 梆梆 / 腾讯乐固 之类）
      * 给"中文注释器"喂类名与方法名词根

    DEX 结构参考：https://source.android.com/docs/core/runtime/dex-format
    header 固定 0x70 = 112 字节，字段偏移全部按小端 uint32 读。
============================================================================
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

DEX_MAGIC = b"dex\n"
CDEX_MAGIC = b"cdex"      # Android 10+ 的 compact dex


@dataclass
class DexHeader:
    """DEX 头的关键字段。"""
    version: str = ""
    checksum: int = 0
    file_size: int = 0
    header_size: int = 0x70
    string_ids_size: int = 0
    string_ids_off: int = 0
    type_ids_size: int = 0
    proto_ids_size: int = 0
    field_ids_size: int = 0
    method_ids_size: int = 0
    class_defs_size: int = 0
    data_size: int = 0
    data_off: int = 0
    kind: str = "dex"


@dataclass
class DexInfo:
    path: str = ""
    size: int = 0
    header: DexHeader = field(default_factory=DexHeader)
    strings: list[str] = field(default_factory=list)
    warns: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return bool(self.header.version)

    def brief(self) -> str:
        h = self.header
        return (f"{Path(self.path).name}: {h.kind} v{h.version} | "
                f"类 {h.class_defs_size} 方法 {h.method_ids_size} "
                f"字段 {h.field_ids_size} 字符串 {h.string_ids_size}")


def is_dex(data: bytes) -> bool:
    return data[:4] == DEX_MAGIC or data[:4] == CDEX_MAGIC


def _read_uleb128(data: bytes, off: int) -> tuple[int, int]:
    """读 ULEB128，返回 (值, 新偏移)。DEX 的字符串长度就是这么存的。"""
    result = 0
    shift = 0
    while off < len(data):
        b = data[off]
        off += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
        if shift > 35:
            break
    return result, off


def _decode_mutf8(raw: bytes) -> str:
    """
    解码 MUTF-8（DEX 字符串编码）。

    与标准 UTF-8 的区别：空字符编码为 C0 80，增补平面字符用代理对。
    这里用"替换非法字节"的宽松策略，绝不因为一个坏字符丢掉整条字符串。
    """
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        pass
    # 手工清扫：C0 80 -> \0
    cleaned = raw.replace(b"\xc0\x80", b"\x00")
    try:
        return cleaned.decode("utf-8", "replace")
    except Exception:
        return cleaned.decode("latin-1", "replace")


def parse_header(data: bytes) -> DexHeader:
    """解析 112 字节头。任何越界都返回空头，不抛异常。"""
    h = DexHeader()
    if len(data) < 0x70:
        return h
    if data[:4] == DEX_MAGIC:
        h.version = data[4:7].decode("ascii", "replace")
    elif data[:4] == CDEX_MAGIC:
        h.kind = "cdex"
        h.version = data[4:7].decode("ascii", "replace")

    def u32(off: int) -> int:
        return struct.unpack_from("<I", data, off)[0]

    try:
        h.checksum = u32(0x08)
        h.file_size = u32(0x20)
        h.header_size = u32(0x24)
        h.string_ids_size = u32(0x38)
        h.string_ids_off = u32(0x3C)
        h.type_ids_size = u32(0x40)
        h.proto_ids_size = u32(0x48)
        h.field_ids_size = u32(0x50)
        h.method_ids_size = u32(0x58)
        h.class_defs_size = u32(0x60)
        h.data_size = u32(0x68)
        h.data_off = u32(0x6C)
    except struct.error:
        pass
    return h


def read_strings(data: bytes, h: DexHeader, limit: int = 0) -> list[str]:
    """
    读字符串池。

    limit=0 表示全部读。生产环境建议设个上限（几万条足够看特征），
    避免超大 dex 把内存吃穿。
    """
    out: list[str] = []
    if not h.string_ids_size or not h.string_ids_off:
        return out
    n = h.string_ids_size if limit <= 0 else min(limit, h.string_ids_size)
    base = h.string_ids_off
    for i in range(n):
        off_pos = base + i * 4
        if off_pos + 4 > len(data):
            break
        try:
            s_off = struct.unpack_from("<I", data, off_pos)[0]
        except struct.error:
            break
        if s_off >= len(data):
            continue
        _, p = _read_uleb128(data, s_off)          # 跳过 utf16 长度
        end = data.find(b"\x00", p)
        if end < 0:
            end = min(p + 512, len(data))
        out.append(_decode_mutf8(data[p:end]))
    return out


# 加固厂商的字符串/文件名特征。命中即为"大概率加固"，需要脱壳后才能看到真实逻辑。
PACKER_SIGNS: dict[str, tuple[str, ...]] = {
    "梆梆加固": ("libjiagu", "com/qihoo", "libbaiduprotect"),
    "腾讯乐固": ("libshella", "libshellx", "com/tencent/StubShell", "libtosprotection"),
    "爱加密": ("libexec.so", "libexecmain", "com/shell/supernatant", "ijiami"),
    "360加固": ("libjiagu_art", "libjiagu_ls", "com/qihoo/util"),
    "百度加固": ("libbaiduprotect", "com/baidu/protect"),
    "阿里聚安全": ("libmobisec", "libfakejni", "com/ali/mobisecenhance"),
    "网易易盾": ("libnesec", "com/netease/nis"),
    "腾讯御安全": ("libnesec", "libtup"),
    "娜迦": ("libchaosvmp", "libnagain"),
    "顶象": ("libwind", "com/dx/mobile"),
    "几维安全": ("libkwscmm", "libkwscr"),
    "百度/其他壳": ("libprotectClass", "libSecShell", "libsecexe"),
}


def detect_packer(entry_names: list[str], strings: list[str] | None = None) -> list[str]:
    """按文件名与字符串池猜加固方案，返回命中名单。"""
    blob = "\n".join(entry_names)
    if strings:
        blob += "\n" + "\n".join(strings[:20000])
    low = blob.lower()
    hits = []
    for name, keys in PACKER_SIGNS.items():
        if any(k.lower() in low for k in keys):
            hits.append(name)
    return hits


def parse(path: str | Path, want_strings: bool = True,
          string_limit: int = 60000) -> DexInfo:
    """解析单个 dex 文件。"""
    p = Path(path)
    info = DexInfo(path=str(p))
    try:
        data = p.read_bytes()
    except OSError as e:
        info.warns.append(f"读不到文件：{e}")
        return info
    info.size = len(data)
    if not is_dex(data):
        info.warns.append("不是 DEX 文件（魔数不匹配）")
        return info
    info.header = parse_header(data)
    if want_strings:
        info.strings = read_strings(data, info.header, string_limit)
    return info


def scan_dir(root: str | Path) -> list[DexInfo]:
    """扫一个目录下所有 .dex。"""
    out = []
    for p in sorted(Path(root).rglob("*.dex")):
        out.append(parse(p, want_strings=False))
    return out
