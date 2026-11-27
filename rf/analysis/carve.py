"""
内嵌对象雕刻（carve）：不依赖文件头在偏移 0 的前提，
直接在任意文件的字节流里扫描已知格式的特征并整块抠出来。

覆盖场景：
- vdex / oat / odex：ART 产物里挖出原始 dex（可反编译）
- 固件 / 镜像 / 加壳 PE / 加固 APK 里残留的 zip、dex、so、png 等
- 加密 zip 失败后的已知明文材料定位
"""
from __future__ import annotations

import io
import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class CarvedObject:
    kind: str          # dex / cdex / zip / elf / gzip / bzip2 / xz / 7z / png / jpg / pdf / sqlite
    offset: int        # 在原文件中的起始偏移
    size: int          # 抠出的字节数（zip 为重建后大小）
    note: str = ""
    data: bytes = b""  # 抠出的原始内容（zip 为重建的可打开 zip 字节）

    @property
    def label(self) -> str:
        return f"{self.kind}@0x{self.offset:x} ({self.size} 字节)"


@dataclass
class CarveResult:
    path: str = ""
    total_size: int = 0
    objects: list[CarvedObject] = field(default_factory=list)

    def brief(self) -> str:
        if not self.objects:
            return "没有发现可雕刻的内嵌对象"
        by: dict[str, int] = {}
        for o in self.objects:
            by[o.kind] = by.get(o.kind, 0) + 1
        return "发现 " + "、".join(f"{v} 个 {k}" for k, v in sorted(by.items(),
                                                      key=lambda x: -x[1]))


# ---------------- 特征表 ----------------
# (magic, 是否校验) —— 校验函数再确认不是误报
def _looks_dex(data: bytes, off: int) -> bool:
    """dex 头合法性：file_size 字段合理、string_ids 非零。"""
    if len(data) < off + 0x70:
        return False
    try:
        fsize, _ = struct.unpack_from("<II", data, off + 0x20)
        sids, _ = struct.unpack_from("<II", data, off + 0x38)
    except struct.error:
        return False
    return 0x70 <= fsize <= len(data) - off and 0 < sids < 10_000_000


def _looks_zip(data: bytes, off: int) -> bool:
    """本地头后必须紧跟合法文件名区，避免把普通数据误当 zip。"""
    if len(data) < off + 30:
        return False
    try:
        _, _, _, _, _, _, csize, usize, nlen, elen = struct.unpack_from(
            "<IHHHHHIIIHH", data, off)[:10]
    except struct.error:
        return False
    return nlen > 0 and off + 30 + nlen <= len(data)


_MAGICS = (
    (b"dex\n", "dex", _looks_dex),
    (b"cdex", "cdex", _looks_dex),
    (b"\x7fELF", "elf", None),
    (b"\x1f\x8b\x08", "gzip", None),
    (b"BZh", "bzip2", None),
    (b"\xfd7zXZ\x00", "xz", None),
    (b"7z\xbc\xaf\x27\x1c", "7z", None),
    (b"Rar!\x1a\x07", "rar", None),
    (b"\x89PNG\r\n\x1a\n", "png", None),
    (b"\xff\xd8\xff", "jpg", None),
    (b"%PDF-", "pdf", None),
    (b"SQLite format 3\x00", "sqlite", None),
    (b"\x28\xb5\x2f\xfd", "zstd", None),
)
_ZSTD = (b"\x28\xb5\x2f\xfd",)
_SKIP_KINDS = {"jpg"}  # 太容易误报，只在其它证据充足时才要


# ---------------- 各格式整块抠出 ----------------
def _end_of_dex(data: bytes, off: int) -> int:
    try:
        fsize = struct.unpack_from("<I", data, off + 0x20)[0]
    except struct.error:
        fsize = len(data) - off
    return min(off + max(fsize, 0x70), len(data))


def _end_of_gzip(data: bytes, off: int) -> tuple[int, bytes]:
    """边解压边定界，容忍尾部垃圾（固件里 gzip 流后面常跟着别的段）。"""
    d = __import__("zlib").decompressobj(16 + 15)
    try:
        out = d.decompress(data[off:])
        end = off + len(data[off:]) - len(d.unused_data) if d.eof else len(data)
        return end, out
    except Exception:                                            # noqa: BLE001
        return off + 4096, b""


def _end_of_xz(data: bytes, off: int) -> tuple[int, bytes]:
    import lzma
    d = lzma.LZMADecompressor()
    try:
        out = d.decompress(data[off:])
        end = off + (len(data[off:]) - len(d.unused_data)) if d.eof else len(data)
        return end, out
    except Exception:                                            # noqa: BLE001
        return off + 4096, b""


def _end_of_bzip2(data: bytes, off: int) -> tuple[int, bytes]:
    import bz2
    d = bz2.BZ2Decompressor()
    try:
        out = d.decompress(data[off:])
        end = off + (len(data[off:]) - len(d.unused_data)) if d.eof else len(data)
        return end, out
    except Exception:                                            # noqa: BLE001
        return off + 4096, b""


def _carve_zip(data: bytes, off: int) -> CarvedObject | None:
    """内嵌 zip：找 EOCD → 解析中央目录 → 重建一个干净的 zip 字节。
    兼容前缀垃圾（自解压、壳、固件里的 zip 段）。"""
    eocd = data.find(b"PK\x05\x06", off)
    if eocd < 0:
        return None
    try:
        nent, cd_size, cd_off = struct.unpack_from("<HII", data, eocd + 10)
        if nent == 0 or nent > 65535 or cd_size > len(data):
            return None
        src = io.BytesIO(data)
        src.seek(eocd)                       # 把 EOCD 当文件尾 → zipfile 按前缀垃圾兼容读
        buf = io.BytesIO()
        rebuilt = 0
        with zipfile.ZipFile(src) as z, zipfile.ZipFile(
                buf, "w", zipfile.ZIP_DEFLATED) as out:
            for info in z.infolist():
                if info.is_dir():
                    continue
                out.writestr(info.filename, z.read(info))
                rebuilt += 1
        if rebuilt == 0:
            return None
        payload = buf.getvalue()
        return CarvedObject("zip", off, len(payload),
                            note=f"重建 {rebuilt} 个条目", data=payload)
    except Exception:                                            # noqa: BLE001
        return None


def carve(data: bytes, max_objects: int = 200) -> CarveResult:
    """在字节流里扫描所有已知特征并整块抠出。"""
    res = CarveResult()
    n = len(data)
    res.total_size = n
    seen: set[tuple[str, int]] = set()

    for magic, kind, checker in _MAGICS:
        start = 0
        while len(res.objects) < max_objects:
            off = data.find(magic, start)
            if off < 0:
                break
            start = off + 1
            if (kind, off) in seen:
                continue
            if checker and not checker(data, off):
                continue
            if kind == "zip":
                # PK\x03\x04 由下面专门处理（需要 EOCD 重建）
                continue
            if kind in ("dex", "cdex"):
                end = _end_of_dex(data, off)
                obj = CarvedObject(kind, off, end - off,
                                   data=data[off:end], note="ART 产物内嵌 dex，可反编译")
            elif kind == "gzip":
                end, payload = _end_of_gzip(data, off)
                if not payload:
                    continue
                obj = CarvedObject("gzip", off, end - off, data=data[off:end],
                                   note=f"解压出 {len(payload)} 字节")
            elif kind == "xz":
                end, payload = _end_of_xz(data, off)
                if not payload:
                    continue
                obj = CarvedObject("xz", off, end - off, data=data[off:end],
                                   note=f"解压出 {len(payload)} 字节")
            elif kind == "bzip2":
                end, payload = _end_of_bzip2(data, off)
                if not payload:
                    continue
                obj = CarvedObject("bzip2", off, end - off, data=data[off:end],
                                   note=f"解压出 {len(payload)} 字节")
            elif kind in ("7z", "rar", "zstd"):
                obj = CarvedObject(kind, off, min(len(data) - off, 64 << 20),
                                   note="整段抠出，需 7-Zip/工具继续拆", data=data[off:])
            elif kind == "elf":
                # ELF 结尾按 section header table 末尾估算，抠不出就整段
                try:
                    (_, _, _, _, _, ehsize, _, _, _, phentsize, phnum,
                     shentsize, shnum, shstrndx) = struct.unpack_from(
                        "<HHIQQQIHHHHHH", data, off + 16)
                    shoff = struct.unpack_from("<Q", data, off + 0x28)[0]
                    end = min(off + shoff + shentsize * max(shnum, 1),
                              len(data)) if shoff else len(data)
                except Exception:                                    # noqa: BLE001
                    end = len(data)
                obj = CarvedObject("elf", off, end - off, data=data[off:end],
                                   note="内嵌 ELF（so / so 壳）")
            else:
                obj = CarvedObject(kind, off, min(16 << 20, len(data) - off),
                                   data=data[off:off + (16 << 20)])
            if obj.size <= 0:
                continue
            res.objects.append(obj)
            seen.add((kind, off))
            # 大对象内部不再重复扫同一 magic 的紧邻副本
            if obj.size > 0x10000:
                start = max(start, off + min(obj.size, len(data) - off) - 0x10)

    # zip：每个 PK\x03\x04 尝试重建
    zstart = 0
    while len(res.objects) < max_objects:
        off = data.find(b"PK\x03\x04", zstart)
        if off < 0:
            break
        zstart = off + 4
        if _looks_zip(data, off) is False:
            continue
        obj = _carve_zip(data, off)
        if obj:
            res.objects.append(obj)
            zstart = off + 0x10000  # 重建成功就跳过这片区域，避免逐头重复

    res.objects.sort(key=lambda o: o.offset)
    return res


def carve_file(path: str | Path, out: str | Path | None = None,
               max_objects: int = 200) -> CarveResult:
    """雕刻文件并把对象落盘。返回结果；out 缺省为 <文件名>_carved/。"""
    p = Path(path)
    data = p.read_bytes()
    res = carve(data, max_objects=max_objects)
    res.path = str(p)
    if not res.objects:
        return res
    dst = Path(out) if out else p.with_name(p.stem + "_carved")
    dst.mkdir(parents=True, exist_ok=True)
    counters: dict[str, int] = {}
    for obj in res.objects:
        counters[obj.kind] = counters.get(obj.kind, 0) + 1
        name = f"{obj.kind}_{counters[obj.kind]:03d}_0x{obj.offset:x}"
        if obj.kind in ("gzip", "xz", "bzip2"):
            # 解压后内容直接落盘更好用
            if obj.kind == "gzip":
                _, payload = _end_of_gzip(data, obj.offset)
            elif obj.kind == "xz":
                _, payload = _end_of_xz(data, obj.offset)
            else:
                _, payload = _end_of_bzip2(data, obj.offset)
            if payload:
                (dst / (name + ".out")).write_bytes(payload)
                continue
        if obj.kind == "zip":
            (dst / (name + ".zip")).write_bytes(obj.data)
            continue
        ext = {"dex": ".dex", "cdex": ".dex", "elf": ".so"}.get(obj.kind, ".bin")
        (dst / (name + ext)).write_bytes(obj.data)
    return res
