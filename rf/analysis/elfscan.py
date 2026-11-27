# -*- coding: utf-8 -*-
"""
ELF 结构扫描（纯标准库，不依赖 pyelftools，便于 PyInstaller 打包）。

用途：解包/解密链路走到"得到一段二进制"之后，判断它到底是什么：
  · 哪个架构、什么类型（可执行 / 动态库 / 内核模块）
  · 是不是 UPX 加壳（本样本的第 3 层就是）
  · 文件里是不是拼接了多个 ELF（本样本两个 ELF 拼在一个文件里，
    旧版只认第一个头，25MB 主体被丢掉）
  · 导入了哪些库、导出了哪些有意思的符号、关键字符串是什么
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

ELF_MAGIC = b"\x7fELF"

EM_NAMES = {
    2: "SPARC", 3: "x86", 8: "MIPS", 20: "PowerPC", 21: "PowerPC64",
    40: "ARM(32)", 42: "SuperH", 50: "IA-64", 62: "x86-64", 183: "ARM64",
    243: "RISC-V", 258: "LoongArch",
}
ET_NAMES = {0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN(PIE/SO)", 4: "CORE"}

PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_NOTE = 1, 2, 3, 4
SHT_DYNSYM = 11
DT_NEEDED, DT_HASH, DT_STRTAB, DT_SYMTAB, DT_STRSZ, DT_SYMENT = 1, 4, 5, 6, 10, 11

# 业务上值得关注的字符串关键字（可按需扩充）
INTERESTING = (
    "/dev/", "/proc/", "/data/adb", "/system/", "su -c", "getprop", "chmod ",
    "http://", "https://", ".so", "libUE4", "libil2cpp", "unity", "il2cpp",
    "driver", "insmod", "kallsyms", "ptrace", "dlopen", "dlsym", "uinput",
    "root", "magisk", "zygisk", "frida", "emulator", "imei", "token", "card",
    "license", "api/", "/api", "decode", "verify", "decrypt", "encrypt",
)


@dataclass
class ELFInfo:
    offset: int = 0
    size: int = 0                     # 该 ELF 实际占用长度（段/节表推导）
    bit: int = 64
    endian: str = "little"
    machine: int = 0
    etype: int = 0
    entry: int = 0
    phnum: int = 0
    shnum: int = 0
    interp: str = ""
    needed: list[str] = field(default_factory=list)
    dynsyms: list[str] = field(default_factory=list)
    sections: list[str] = field(default_factory=list)
    upx: bool = False
    upx_tag: str = ""
    inner: bool = False          # 是否是别的 ELF 段内嵌的
    note: str = ""

    @property
    def machine_name(self) -> str:
        return EM_NAMES.get(self.machine, f"EM_{self.machine}")

    @property
    def type_name(self) -> str:
        return ET_NAMES.get(self.etype, f"ET_{self.etype}")

    def brief(self) -> str:
        bits = [f"{self.machine_name} {self.bit}位", self.type_name]
        if self.upx:
            bits.append(f"UPX加壳{self.upx_tag}")
        if self.needed:
            bits.append("依赖:" + ",".join(self.needed[:6]))
        if self.dynsyms:
            bits.append(f"导出符号{len(self.dynsyms)}")
        return " | ".join(bits)


def is_elf(data: bytes, off: int = 0) -> bool:
    return data[off:off + 4] == ELF_MAGIC


def _u(data: bytes, off: int, n: int, endian: str) -> int:
    if off < 0 or off + n > len(data):
        raise ValueError("越界读取")
    fmt = ("<" if endian == "little" else ">") + {1: "B", 2: "H", 4: "I", 8: "Q"}[n]
    return struct.unpack_from(fmt, data, off)[0]


def upx_tag(data: bytes) -> str:
    """检测 UPX 尾部标记：'UPX!' + 1 字节版本 + 1 字节 format。"""
    tail = data[-2048:]
    i = tail.rfind(b"UPX!")
    if i < 0:
        return ""
    ver = tail[i + 4] if i + 4 < len(tail) else 0
    fmt = tail[i + 5] if i + 5 < len(tail) else 0
    return f"(ver=0x{ver:02x},fmt=0x{fmt:02x})"


def parse(data: bytes, offset: int = 0, max_len: int | None = None) -> ELFInfo | None:
    """解析 offset 处的 ELF 头。失败返回 None。"""
    if not is_elf(data, offset):
        return None
    info = ELFInfo(offset=offset)
    try:
        ei_class = data[offset + 4]
        ei_data = data[offset + 5]
        info.bit = 64 if ei_class == 2 else 32
        info.endian = "little" if ei_data == 1 else "big"
        e = info.endian
        b = offset
        if info.bit == 64:
            info.etype = _u(data, b + 16, 2, e)
            info.machine = _u(data, b + 18, 2, e)
            info.entry = _u(data, b + 24, 8, e)
            phoff = _u(data, b + 32, 8, e)
            shoff = _u(data, b + 40, 8, e)
            phentsize = _u(data, b + 54, 2, e)
            info.phnum = _u(data, b + 56, 2, e)
            shentsize = _u(data, b + 58, 2, e)
            info.shnum = _u(data, b + 60, 2, e)
        else:
            info.etype = _u(data, b + 16, 2, e)
            info.machine = _u(data, b + 18, 2, e)
            info.entry = _u(data, b + 24, 4, e)
            phoff = _u(data, b + 28, 4, e)
            shoff = _u(data, b + 32, 4, e)
            phentsize = _u(data, b + 42, 2, e)
            info.phnum = _u(data, b + 44, 2, e)
            shentsize = _u(data, b + 46, 2, e)
            info.shnum = _u(data, b + 48, 2, e)
    except (ValueError, IndexError):
        return None

    limit = len(data) if max_len is None else min(len(data), offset + max_len)
    loads: list[tuple[int, int, int]] = []       # (vaddr, offset, filesz)
    dyn: dict[int, int] = {}
    end = offset

    # ---- program headers ----
    for i in range(min(info.phnum, 256)):
        base = offset + phoff + i * (phentsize or (56 if info.bit == 64 else 32))
        try:
            if info.bit == 64:
                p_type = _u(data, base, 4, e)
                p_off = _u(data, base + 8, 8, e)
                p_va = _u(data, base + 16, 8, e)
                p_fsz = _u(data, base + 32, 8, e)
                p_msz = _u(data, base + 40, 8, e)
            else:
                p_type = _u(data, base, 4, e)
                p_off = _u(data, base + 4, 4, e)
                p_va = _u(data, base + 8, 4, e)
                p_fsz = _u(data, base + 16, 4, e)
                p_msz = _u(data, base + 20, 4, e)
        except ValueError:
            continue
        if p_type == PT_LOAD:
            loads.append((p_va, p_off, p_fsz))
            end = max(end, offset + p_off + p_fsz)
        elif p_type == PT_INTERP:
            raw = data[offset + p_off: offset + p_off + 256].split(b"\x00")[0]
            info.interp = raw.decode("latin1", "ignore")
        elif p_type == PT_DYNAMIC:
            dyn["off"] = p_off
            dyn["size"] = p_fsz

    def v2o(va: int) -> int | None:
        for p_va, p_off, p_fsz in loads:
            if p_va <= va < p_va + p_fsz:
                return offset + p_off + (va - p_va)
        return None

    # ---- section headers（有就更好，能直接拿符号表）----
    symtab: tuple[int, int] | None = None      # (offset, count)
    strtab: tuple[int, int] | None = None      # (offset, 忽略)
    secs: list[tuple[int, int, int, int, int, int]] = []   # name,type,off,size,entsize,link
    for i in range(min(info.shnum, 512)):
        base = offset + shoff + i * (shentsize or (64 if info.bit == 64 else 40))
        try:
            sh_name = _u(data, base, 4, e)
            sh_type = _u(data, base + 4, 4, e)
            sh_off = _u(data, base + 24 if info.bit == 64 else base + 16, 8 if info.bit == 64 else 4, e)
            sh_size = _u(data, base + 32 if info.bit == 64 else base + 20, 8 if info.bit == 64 else 4, e)
            sh_link = _u(data, base + 40 if info.bit == 64 else base + 24, 4, e)
            sh_entsize = _u(data, base + 56 if info.bit == 64 else base + 36, 8 if info.bit == 64 else 4, e)
        except ValueError:
            continue
        secs.append((sh_name, sh_type, sh_off, sh_size, sh_entsize, sh_link))
        end = max(end, offset + sh_off + sh_size)

    # 符号名要从 .dynstr 读：sh_link 指向字符串表所在的节。
    # 之前这里写成 strtab = (offset+sh_off, 0)，把符号表自己当字符串表，
    # 算出来的 `st_name` 全部落在符号表数据里 → 符号名是乱码。
    for _n, s_type, s_off, s_size, s_entsize, s_link in secs:
        if s_type == SHT_DYNSYM and s_entsize:
            symtab = (offset + s_off, s_size // s_entsize)
            if 0 < s_link < len(secs):
                str_off = secs[s_link][2]
                if str_off:
                    strtab = (offset + str_off, 0)
            info.sections.append(".dynsym")
            break

    # ---- 解析动态段 ----
    # 注意：这不能塞进 `if symtab is None` 分支里。带节表的普通 .so 一定能
    # 从节表拿到 symtab，一旦整段被跳过，DT_NEEDED（依赖库）就永远是空的 ——
    # 而「这个 so 依赖什么」正是判断运行时崩溃原因的关键线索。
    if "off" in dyn:
        d_off = offset + dyn["off"]
        entsz = 16 if info.bit == 64 else 8
        entries: list[tuple[int, int]] = []
        for i in range(min(dyn["size"] // entsz, 512)):
            base = d_off + i * entsz
            try:
                if info.bit == 64:
                    tag = _u(data, base, 8, e)
                    val = _u(data, base + 8, 8, e)
                else:
                    tag = _u(data, base, 4, e)
                    val = _u(data, base + 4, 4, e)
            except ValueError:
                break
            if tag == 0:
                break
            entries.append((tag, val))
        vals = {t: v for t, v in entries}
        str_o = v2o(vals.get(DT_STRTAB, 0))
        sym_o = v2o(vals.get(DT_SYMTAB, 0))
        h_o = v2o(vals.get(DT_HASH, 0))

        for tag, val in entries:
            if tag == DT_NEEDED and str_o is not None:
                s = data[str_o + val: str_o + val + 128].split(b"\x00")[0]
                t = s.decode("latin1", "ignore")
                if t and t not in info.needed:
                    info.needed.append(t)

        # 没有节表时才需要靠 DT_HASH 推符号数量
        if symtab is None and sym_o is not None:
            count = 0
            if h_o is not None:
                try:
                    count = _u(data, h_o + 4, 4, e)      # nchain
                except ValueError:
                    count = 0
            if not count:
                count = 256                              # 保守估一个上限
            symtab = (sym_o, min(count, 20000))
            strtab = (str_o, 0) if str_o else None

    # ---- 读动态符号名 ----
    if symtab and strtab and strtab[0]:
        s_off = symtab[0]
        t_off = strtab[0]
        step = 24 if info.bit == 64 else 16
        for i in range(min(symtab[1], 8000)):
            base = s_off + i * step
            try:
                st_name = _u(data, base, 4, e)
            except ValueError:
                break
            if not st_name:
                continue
            p = t_off + st_name
            if p >= limit:
                continue
            raw = data[p:p + 160].split(b"\x00")[0]
            if 2 <= len(raw) <= 160:
                try:
                    info.dynsyms.append(raw.decode("latin1"))
                except UnicodeDecodeError:
                    pass

    info.size = max(0, end - offset)
    win = min(len(data), offset + max(info.size, 1) + (1 << 20))
    tag = upx_tag(data[offset:win])
    if tag:
        info.upx = True
        info.upx_tag = tag
    if info.interp:
        info.note = f"解释器 {info.interp}"
    return info


def find_all_elfs(data: bytes, min_size: int = 4096, limit: int = 8) -> list[ELFInfo]:
    """
    扫描文件中所有 ELF 头，并区分"并列拼接"与"内嵌在父 ELF 段里"两种情况。

    样本里常见：两个 ELF 直接拼在一起（都是可执行的顶层文件）；
    也常见：主程序某个 PT_LOAD 里塞了一个完整 .so（VMProtect 壳就是这么藏的）。
    """
    # 1) 收集候选偏移（先按头部字段做一次粗筛，避免随机数据误判）
    cands: list[int] = []
    pos = 0
    while True:
        i = data.find(ELF_MAGIC, pos)
        if i < 0:
            break
        pos = i + 4
        if i + 20 > len(data):
            break
        if data[i + 4] not in (1, 2) or data[i + 5] not in (1, 2):
            continue
        machine = struct.unpack_from("<H" if data[i + 5] == 1 else ">H", data, i + 18)[0]
        if machine not in EM_NAMES:
            continue
        cands.append(i)

    out: list[ELFInfo] = []
    covered: list[tuple[int, int]] = []
    for n, i in enumerate(cands):
        info = parse(data, i)
        if not info or info.size < min_size:
            continue
        start = i
        end = i + info.size
        nxt = cands[n + 1] if n + 1 < len(cands) else len(data)

        # UPX 壳：段表只覆盖加载段，尾部 trailer 在段外，必须把它算进文件长度
        if not info.upx:
            j = data.find(b"UPX!", end, min(end + (1 << 20), len(data)))
            if j >= 0:
                info.upx = True
                info.upx_tag = upx_tag(data[j:j + 64])
                end = min(j + 64, nxt)
        if end > len(data):
            end = len(data)
        if end <= start:
            continue

        info.offset = start
        info.size = end - start
        info.inner = any(s <= start < e for s, e in covered)
        if not info.inner:
            covered.append((start, end))
        out.append(info)
        if len(out) >= limit:
            break
    return out


def interesting_strings(blob: bytes, limit: int = 40) -> list[str]:
    """抽取与行为分析强相关的字符串（去重保序）。"""
    seen: set[str] = set()
    out: list[str] = []
    i, n = 0, len(blob)
    while i < n and len(out) < limit:
        j = i
        while j < n and 32 <= blob[j] < 127:
            j += 1
        if j - i >= 6:
            s = blob[i:j].decode("latin1")
            low = s.lower()
            if any(k.lower() in low for k in INTERESTING) and s not in seen:
                seen.add(s)
                out.append(s[:120])
        i = j + 1
    return out


def describe(info: ELFInfo) -> str:
    parts = [f"ELF@{info.offset:#x} {info.brief()} 长度 {info.size:,}B"]
    if info.entry:
        parts.append(f"入口 {info.entry:#x}")
    good = [s for s in info.dynsyms if len(s) > 3][:8]
    if good:
        parts.append("符号例:" + ", ".join(good))
    return "；".join(parts)
