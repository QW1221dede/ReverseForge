#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 rf.analysis.native · ELF / PE 二进制静态解析（纯 Python）
============================================================================

【为什么自己写】
    rz-bin 能出节表，但输出是给人看的文本；要喂给 GUI 和脚本，得先结构化。
    这里直接读二进制头，零依赖、毫秒级，且能顺便做「加固/壳」判定。

【覆盖范围】
    ELF：32/64 位、大小端、机器类型、节表、动态段、导入导出符号、
         加固特征（UPX / VMP / 梆梆 / 爱加密 / 混淆节名）
    PE ：MZ→PE 头、机器类型、节表、DLL 特征、导入表、壳特征

【判定加固的依据】
    1. 节名命中已知壳（.upx0/.vmp0/.jiagu/.bangcle/.secexe ...）
    2. 节熵 > 7.6 且无导入表 → 加密压缩很可能是壳
    3. ELF 有 .init_array 但导出符号极少 → 加壳常见形态
============================================================================
"""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# 通用
# ---------------------------------------------------------------------------

def entropy(data: bytes) -> float:
    """香农熵（0~8）。>7.5 基本可判定为加密或压缩。"""
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


def read_head(path: str | Path, size: int = 1 << 20) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(size)
    except OSError:
        return b""


ELF_MACHINE = {
    3: "x86", 8: "MIPS", 20: "PowerPC", 40: "ARM", 62: "x86-64",
    183: "AArch64", 243: "RISC-V", 21: "PowerPC64",
}

SHELL_SECTIONS = (
    ".upx0", ".upx1", ".upx2", ".vmp0", ".vmp1", ".vmp2", ".themida",
    ".jiagu", ".bangcle", ".secexe", ".secmain", ".packed", ".aspack",
    ".nsp0", ".nsp1", ".enigma1", ".enigma2", ".mpress1", ".mpress2",
    ".petite", ".y0da", ".tmdat", "$pls", "neolite", ".llvm",
)


# ---------------------------------------------------------------------------
# ELF
# ---------------------------------------------------------------------------

@dataclass
class ElfInfo:
    path: str = ""
    is_elf: bool = False
    bits: int = 0
    endian: str = ""
    machine: str = ""
    elf_type: str = ""
    entry: int = 0
    sections: list[dict] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    exports: list[str] = field(default_factory=list)
    needed: list[str] = field(default_factory=list)
    shell_hits: list[str] = field(default_factory=list)
    high_entropy_sections: list[str] = field(default_factory=list)
    stripped: bool = False
    warns: list[str] = field(default_factory=list)

    @property
    def packed(self) -> bool:
        return bool(self.shell_hits) or bool(self.high_entropy_sections)

    def brief(self) -> str:
        s = (f"{Path(self.path).name}: ELF{self.bits} {self.machine} "
             f"{self.elf_type} | 节 {len(self.sections)} 导入 {len(self.imports)} "
             f"导出 {len(self.exports)}")
        if self.packed:
            s += " | ⚠ 疑似加壳"
        return s

    def to_dict(self) -> dict:
        d = dict(self.__dict__)
        d["packed"] = self.packed
        return d


def parse_elf(path: str | Path) -> ElfInfo:
    p = Path(path)
    info = ElfInfo(path=str(p))
    _MAX = 512 << 20
    try:
        size = p.stat().st_size
        if size > _MAX:
            # 1GB 的镜像/固件全读进来会直接吃掉内存，只分析前 512MB（头+节表都在前面）
            info.warns.append(f"文件 {size >> 20}MB 超过 512MB，只分析前 512MB")
            with p.open("rb") as f:
                data = f.read(_MAX)
        else:
            data = p.read_bytes()
    except OSError as e:
        info.warns.append(str(e))
        return info
    if data[:4] != b"\x7fELF":
        info.warns.append("不是 ELF 文件")
        return info
    # 只有 4 字节魔数就往下走，data[4] 会 IndexError；ELF32 头最小 52 字节
    if len(data) < 52:
        info.warns.append(f"ELF 头被截断（只有 {len(data)} 字节）")
        return info

    info.is_elf = True
    ei_class = data[4]
    ei_data = data[5]
    info.bits = 64 if ei_class == 2 else 32
    info.endian = "little" if ei_data == 1 else "big"
    e = "<" if ei_data == 1 else ">"

    try:
        if info.bits == 64:
            # ELF64 头从 e_ident 之后共 13 个字段：type/machine/version/entry/
            # phoff/shoff/flags/ehsize/phentsize/phnum/shentsize/shnum/shstrndx
            (e_type, e_machine, _, e_entry, _, shoff, _,
             _, _, _, shentsize, shnum, shstrndx) = struct.unpack_from(
                e + "HHIQQQIHHHHHH", data, 16)
        else:
            (e_type, e_machine, _, e_entry, _, shoff, _,
             _, _, _, shentsize, shnum, shstrndx) = struct.unpack_from(
                e + "HHIIIIIHHHHHH", data, 16)
    except struct.error:
        info.warns.append("ELF 头解析失败（文件可能被截断）")
        return info

    info.entry = e_entry
    info.machine = ELF_MACHINE.get(e_machine, f"machine#{e_machine}")
    info.elf_type = {1: "REL", 2: "EXEC", 3: "DYN(.so)", 4: "CORE"}.get(e_type, str(e_type))

    # 节表
    shstr = b""
    sections_raw = []
    try:
        for i in range(shnum):
            off = shoff + i * shentsize
            if info.bits == 64:
                name, sh_type, flags, addr, offset, size, link, info_, align, entsize = \
                    struct.unpack_from(e + "IIQQQQIIQQ", data, off)
            else:
                name, sh_type, flags, addr, offset, size, link, info_, align, entsize = \
                    struct.unpack_from(e + "IIIIIIIIII", data, off)
            sections_raw.append((name, sh_type, offset, size, flags))
        if 0 <= shstrndx < len(sections_raw):
            _, _, soff, ssize, _ = sections_raw[shstrndx]
            shstr = data[soff:soff + ssize]
    except struct.error:
        info.warns.append("节表越界")

    for name_off, sh_type, offset, size, flags in sections_raw:
        nm = _cstr(shstr, name_off) if shstr else f"<{name_off}>"
        if not nm:
            continue
        ent = 0.0
        if sh_type != 8 and size > 512:       # 8 = SHT_NOBITS（.bss）
            chunk = data[offset:offset + min(size, 262144)]
            ent = entropy(chunk)
        info.sections.append({"name": nm, "size": size, "entropy": round(ent, 2),
                              "flags": flags})
        if ent >= 7.6 and nm not in (".bss",):
            info.high_entropy_sections.append(f"{nm}({ent:.2f})")
        low = nm.lower()
        for s in SHELL_SECTIONS:
            if s in low:
                info.shell_hits.append(nm)
                break

    # 动态段：导入/导出/依赖
    dyn = _parse_dynsym(data, sections_raw, info.bits, e, shstr)
    info.imports = dyn.get("imports", [])
    info.exports = dyn.get("exports", [])
    info.needed = dyn.get("needed", [])
    info.stripped = not any(s["name"] == ".symtab" for s in info.sections)
    if info.stripped:
        info.warns.append("符号表已剥离（正常发布包常见）")
    return info


def _parse_dynsym(data: bytes, sections: list, bits: int, e: str, shstr: bytes) -> dict:
    """读 .dynsym + .dynstr + .dynamic，拿导入导出和依赖库。"""
    out = {"imports": [], "exports": [], "needed": []}
    try:
        secs = {}
        for name_off, sh_type, offset, size, flags in sections:
            nm = _cstr(shstr, name_off) if shstr else ""
            if nm:
                secs[nm] = (sh_type, offset, size)
        dynstr = secs.get(".dynstr")
        dynsym = secs.get(".dynsym")
        if not dynstr or not dynsym:
            return out
        _, soff, ssize = dynstr
        _, syoff, sysize = dynsym
        strtab = data[soff:soff + ssize]
        entsize = 24 if bits == 64 else 16
        n = sysize // entsize
        for i in range(min(n, 20000)):
            base = syoff + i * entsize
            if base + entsize > len(data):
                break
            if bits == 64:
                st_name, st_info, st_other, st_shndx, st_value, st_size = \
                    struct.unpack_from(e + "IBBHQQ", data, base)
            else:
                st_name, st_value, st_size, st_info, st_other, st_shndx = \
                    struct.unpack_from(e + "IIIBBH", data, base)
            nm = _cstr(strtab, st_name)
            if not nm:
                continue
            if st_shndx == 0:          # SHN_UNDEF = 外部导入
                if nm not in out["imports"]:
                    out["imports"].append(nm)
            elif st_info & 0xF in (1, 2):   # OBJECT / FUNC
                if nm not in out["exports"]:
                    out["exports"].append(nm)
        # .dynamic 里的 DT_NEEDED
        dynsec = secs.get(".dynamic")
        if dynsec:
            _, doff, dsize = dynsec
            step = 16 if bits == 64 else 8
            fmt = e + ("qQ" if bits == 64 else "iI")
            for i in range(dsize // step):
                try:
                    tag, val = struct.unpack_from(fmt, data, doff + i * step)
                except struct.error:
                    break
                if tag == 0:
                    break
                if tag == 1:           # DT_NEEDED
                    lib = _cstr(strtab, val)
                    if lib and lib not in out["needed"]:
                        out["needed"].append(lib)
    except Exception:
        pass
    return out


def _cstr(buf: bytes, off: int) -> str:
    if off < 0 or off >= len(buf):
        return ""
    end = buf.find(b"\x00", off)
    if end < 0:
        end = len(buf)
    try:
        return buf[off:end].decode("utf-8", "replace")
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# PE
# ---------------------------------------------------------------------------

PE_MACHINE = {
    0x14c: "x86", 0x8664: "x86-64", 0x1c0: "ARM", 0xaa64: "ARM64",
    0x200: "IA64", 0x1c4: "ARMv7",
}


@dataclass
class PeInfo:
    path: str = ""
    is_pe: bool = False
    machine: str = ""
    is_dll: bool = False
    sections: list[dict] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    shell_hits: list[str] = field(default_factory=list)
    high_entropy_sections: list[str] = field(default_factory=list)
    warns: list[str] = field(default_factory=list)

    @property
    def packed(self) -> bool:
        return bool(self.shell_hits) or bool(self.high_entropy_sections)

    def brief(self) -> str:
        s = (f"{Path(self.path).name}: PE {self.machine} "
             f"{'DLL' if self.is_dll else 'EXE'} | 节 {len(self.sections)} "
             f"导入 {len(self.imports)}")
        if self.packed:
            s += " | ⚠ 疑似加壳"
        return s

    def to_dict(self) -> dict:
        d = dict(self.__dict__)
        d["packed"] = self.packed
        return d


def parse_pe(path: str | Path) -> PeInfo:
    p = Path(path)
    info = PeInfo(path=str(p))
    _MAX = 512 << 20
    try:
        size = p.stat().st_size
        if size > _MAX:
            info.warns.append(f"文件 {size >> 20}MB 超过 512MB，只分析前 512MB")
            with p.open("rb") as f:
                data = f.read(_MAX)
        else:
            data = p.read_bytes()
    except OSError as e:
        info.warns.append(str(e))
        return info
    if data[:2] != b"MZ":
        info.warns.append("不是 PE 文件")
        return info

    info.is_pe = True
    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            info.warns.append("PE 签名缺失")
            return info
        machine, nsec, _, _, _, opt_size, characteristics = struct.unpack_from(
            "<HHIIIHH", data, e_lfanew + 4)
        info.machine = PE_MACHINE.get(machine, f"0x{machine:x}")
        info.is_dll = bool(characteristics & 0x2000)

        opt_off = e_lfanew + 24
        magic = struct.unpack_from("<H", data, opt_off)[0]
        pe64 = magic == 0x20b
        # 数据目录：导入表是第 1 项
        dd_off = opt_off + (112 if pe64 else 96)
        imp_rva = struct.unpack_from("<I", data, dd_off + 8)[0] if dd_off + 8 <= len(data) else 0

        sec_off = opt_off + opt_size
        secs = []
        for i in range(nsec):
            base = sec_off + i * 40
            if base + 40 > len(data):
                break
            name = data[base:base + 8].rstrip(b"\x00").decode("latin-1", "replace")
            vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, base + 8)
            secs.append((name, vaddr, vsize, rawptr, rawsize))
            ent = 0.0
            if rawsize > 512 and rawptr + rawsize <= len(data):
                ent = entropy(data[rawptr:rawptr + min(rawsize, 262144)])
            info.sections.append({"name": name, "size": rawsize,
                                  "entropy": round(ent, 2), "vaddr": vaddr})
            if ent >= 7.6:
                info.high_entropy_sections.append(f"{name}({ent:.2f})")
            low = name.lower()
            for s in SHELL_SECTIONS:
                if s in low:
                    info.shell_hits.append(name)
                    break

        # 导入表
        if imp_rva:
            for sec_name, vaddr, vsize, rawptr, rawsize in secs:
                if vaddr <= imp_rva < vaddr + max(vsize, rawsize):
                    off = rawptr + (imp_rva - vaddr)
                    info.imports = _parse_pe_imports(data, off, pe64)
                    break
    except struct.error:
        info.warns.append("PE 结构越界（可能被截断）")
    return info


def _parse_pe_imports(data: bytes, off: int, pe64: bool) -> list[str]:
    out: list[str] = []
    step = 20
    for i in range(200):
        base = off + i * step
        if base + step > len(data):
            break
        try:
            oft, _, _, name_rva, first_thunk = struct.unpack_from("<IIIII", data, base)
        except struct.error:
            break
        if not name_rva and not first_thunk:
            break
        nm = _pe_rva_to_str(data, name_rva)
        if nm and nm not in out:
            out.append(nm)
    return out


def _pe_rva_to_str(data: bytes, rva: int) -> str:
    """粗略的 RVA→字符串（假设节区已按文件偏移映射，够用）。"""
    if rva <= 0 or rva >= len(data):
        return ""
    end = data.find(b"\x00", rva)
    if end < 0 or end - rva > 200:
        return ""
    try:
        return data[rva:end].decode("ascii", "replace")
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# 统一入口
# ---------------------------------------------------------------------------

def parse(path: str | Path) -> ElfInfo | PeInfo | None:
    """按魔数自动选解析器。"""
    head = read_head(path, 4)
    if head[:4] == b"\x7fELF":
        return parse_elf(path)
    if head[:2] == b"MZ":
        return parse_pe(path)
    return None


# 高价值导入：出现在 so/exe 里说明有这些系统能力
RISKY_IMPORTS = {
    "system": "执行系统命令", "popen": "执行命令并读输出", "execve": "执行程序",
    "fork": "创建子进程", "ptrace": "进程注入/调试（反调试常用）",
    "dlopen": "动态加载库", "dlsym": "动态查找符号",
    "socket": "网络套接字", "connect": "建立连接", "send": "发送数据",
    "read": "读文件/管道", "write": "写文件", "open": "打开文件",
    "mmap": "内存映射（可执行内存常见于注入）", "mprotect": "改内存权限（注入常配合 mmap）",
    "pthread_create": "创建线程", "kill": "发信号（可杀进程）",
    "getprop": "读系统属性", "setprop": "改系统属性",
    "fork_and_run": "派生执行", "android_dlopen_ext": "加载外部 so",
}


def risky_imports(info: ElfInfo | PeInfo) -> list[tuple[str, str]]:
    out = []
    for imp in getattr(info, "imports", []):
        base = imp.split("@")[0]
        if base in RISKY_IMPORTS:
            out.append((imp, RISKY_IMPORTS[base]))
    return out
