# -*- coding: utf-8 -*-
"""
多层封装识别与自动拆解：makeself 自解压脚本 → gzip → UPX 壳 → 拼接 ELF。

为什么需要它：
  样本 `xxx.sh` 头部明写 `skip=50` / `tail -n +$skip | gzip -cd`，
  这是标准自解压协议，照做就能出包，**根本不用撞密钥**。
  解出后往往还有第二层（UPX）和第三层（多个 ELF 拼在一个文件里），
  只认第一个 ELF 头就会把真正的主体丢掉，最后误报"解不出来"。
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from . import elfscan

# makeself 头特征
_RE_SKIP = re.compile(rb"^\s*skip\s*=\s*(\d+)", re.M)
_RE_TAIL = re.compile(rb"tail\s+-n\s*\+\s*\$?\{?(\w+)\}?|tail\s+-n\s*\+\s*(\d+)")
_RE_COMP = re.compile(rb"gzip\s+-[dc]|gzip\s+--decompress|--gzip")


@dataclass
class Artifact:
    kind: str                 # makeself / gzip / upx / elf / concat / script
    name: str
    data: bytes
    note: str = ""
    depth: int = 0

    @property
    def size(self) -> int:
        return len(self.data)


@dataclass
class UnpackResult:
    artifacts: list[Artifact] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def add(self, a: Artifact) -> None:
        self.artifacts.append(a)

    def summary(self) -> str:
        if not self.artifacts:
            return "未发现自解压/封装结构"
        return "；".join(f"{a.kind}:{a.name}({a.size:,}B)" for a in self.artifacts)


def parse_makeself(data: bytes) -> dict | None:
    """识别 makeself 自解压脚本头，返回 {skip, offset, comp, label}。"""
    head = data[:65536]
    if b"makeself" not in head.lower() and not _RE_SKIP.search(head):
        return None
    m = _RE_SKIP.search(head)
    if not m:
        return None
    try:
        skip = int(m.group(1))
    except ValueError:
        return None
    if skip <= 0 or skip > 100000:
        return None
    has_tail = bool(_RE_TAIL.search(head)) or b"tail -n +" in head
    if not has_tail and not _RE_COMP.search(head):
        return None
    off = line_offset(data, skip)
    if off <= 0 or off >= len(data):
        return None
    label = ""
    lm = re.search(rb'MS_ARCHIVE_LABEL="?([^"\n]{1,80})', head)
    if lm:
        label = lm.group(1).decode("utf-8", "replace")
    return {"skip": skip, "offset": off, "label": label,
            "comp": "gzip" if _RE_COMP.search(head) or data[off:off + 2] == b"\x1f\x8b" else "?"}


def line_offset(data: bytes, lineno: int) -> int:
    """返回第 lineno 行（1-based）的起始偏移。"""
    if lineno <= 1:
        return 0
    off = 0
    for _ in range(lineno - 1):
        i = data.find(b"\n", off)
        if i < 0:
            return -1
        off = i + 1
    return off


def find_upx() -> str | None:
    """找 upx 可执行文件：环境变量 → PATH → 常见工具目录。"""
    env = os.environ.get("RF_UPX")
    if env and Path(env).is_file():
        return env
    for name in ("upx", "upx.exe"):
        p = shutil.which(name)
        if p:
            return p
    here = Path(__file__).resolve().parents[2]
    cands = [
        here / "tools" / "upx.exe", here / "upx.exe",
        here / "tools" / "upx" / "upx.exe",
        Path("E:/Tools/upx/upx-4.2.4-win64/upx.exe"),
        Path("C:/Tools/upx/upx.exe"),
    ]
    for c in cands:
        if c.is_file():
            return str(c)
    root = Path("E:/Tools/upx")
    if root.is_dir():
        for p in root.rglob("upx.exe"):
            return str(p)
    return None


def _try_decompress(blob: bytes) -> tuple[bytes, str]:
    from ..decrypt import ciphers as C          # 延迟导入，避免循环依赖
    try:
        return C.decompress_auto(blob)
    except Exception:                            # noqa: BLE001
        return b"", ""


def _upx_unpack(blob: bytes, upx: str, tmpdir: Path) -> tuple[bytes, str]:
    src = tmpdir / "packed.elf"
    src.write_bytes(blob)
    try:
        r = subprocess.run([upx, "-d", "-o", str(tmpdir / "unpacked.elf"), str(src)],
                           capture_output=True, timeout=180)
        out = tmpdir / "unpacked.elf"
        if out.is_file() and out.stat().st_size > 0:
            return out.read_bytes(), "upx -d"
        msg = (r.stderr or r.stdout or b"").decode("utf-8", "replace").strip().splitlines()
        return b"", (msg[-1] if msg else "upx 失败")
    except (OSError, subprocess.SubprocessError) as e:
        return b"", f"upx 调用失败：{e}"


def _trim_tail(blob: bytes) -> bytes:
    """去掉作者在两段之间塞的分隔填充（如 "\\n略略略\\n"）。

    UPX 对文件长度敏感，多一个字节都会报 NotPacked，所以这里把
    尾部的换行和"3 字节 UTF-8 中文字符"全部剥掉。
    """
    while blob:
        if blob.endswith(b"\n"):
            blob = blob[:-1]
            continue
        if (len(blob) >= 3 and 0xE4 <= blob[-3] <= 0xE9
                and 0x80 <= blob[-2] <= 0xBF and 0x80 <= blob[-1] <= 0xBF):
            blob = blob[:-3]
            continue
        break
    return blob


def deep_unpack(data: bytes, name: str = "", max_depth: int = 3,
                use_upx: bool = True) -> UnpackResult:
    """逐层拆：makeself → 压缩流 → 加壳 → 拼接 ELF。"""
    res = UnpackResult()
    _walk(data, name or "样本", res, 0, max_depth, use_upx)
    return res


def _walk(blob: bytes, name: str, res: UnpackResult, depth: int,
          max_depth: int, use_upx: bool) -> None:
    if depth > max_depth or not blob:
        return

    # ---- 1) makeself 自解压脚本 ----
    ms = parse_makeself(blob)
    if ms:
        payload = blob[ms["offset"]:]
        label = ms.get("label") or name
        res.notes.append(f"makeself 自解压：skip={ms['skip']}，"
                         f"第 {ms['skip']} 行起 {len(payload):,}B 为 {ms['comp']} 流")
        res.add(Artifact("makeself", f"{label}.payload", payload,
                         f"header {ms['offset']}B, skip={ms['skip']}", depth))
        out, how = _try_decompress(payload)
        if out:
            res.notes.append(f"{how} 解压成功：{len(out):,}B")
            res.add(Artifact("gzip", f"{label}.{how}", out, f"{how} 解压", depth + 1))
            _walk(out, f"{label}.{how}", res, depth + 1, max_depth, use_upx)
        else:
            res.notes.append("makeself 负载解压失败（可能不是标准 gzip）")
        return

    # ---- 2) 纯压缩流 ----
    elfs = elfscan.find_all_elfs(blob)
    if not elfs:
        out, how = _try_decompress(blob[:64 * 1024 * 1024])
        if out and len(out) >= 64:
            res.notes.append(f"{how} 解压：{len(blob):,}B → {len(out):,}B")
            res.add(Artifact("gzip", f"{name}.{how}", out, f"{how} 解压", depth + 1))
            _walk(out, f"{name}.{how}", res, depth + 1, max_depth, use_upx)
        return

    # ---- 3) ELF（并列拼接 / 内嵌 .so）----
    if len(elfs) > 1:
        res.notes.append(f"发现 {len(elfs)} 个 ELF：" + "、".join(
            f"{'内嵌' if e.inner else '顶层'}{e.machine_name}/{e.size:,}B" for e in elfs))
    for idx, info in enumerate(elfs):
        sub = blob[info.offset:info.offset + info.size]
        if info.upx:
            sub = _trim_tail(sub)
        tag = f"{name}.{'inner' if info.inner else 'elf'}{idx + 1}"
        if info.upx:
            res.notes.append(f"{tag} 是 UPX 加壳（{info.upx_tag}）")
            done = False
            if use_upx:
                upx = find_upx()
                if upx:
                    with tempfile.TemporaryDirectory(prefix="rf_upx_") as td:
                        out, how = _upx_unpack(sub, upx, Path(td))
                    if out:
                        res.add(Artifact("upx", f"{tag}.unpacked", out,
                                         f"UPX 脱壳（{how}）", depth + 1))
                        res.notes.append(f"{tag} 脱壳成功：{info.size:,}B → {len(out):,}B")
                        done = True
                    else:
                        res.notes.append(f"{tag} 脱壳失败：{how}")
                else:
                    res.notes.append(f"{tag} 需要 UPX，但没找到 upx 可执行文件"
                                     "（设置环境变量 RF_UPX 指向它即可自动脱壳）")
            if not done:
                res.add(Artifact("elf", f"{tag}.packed", sub, "UPX 加壳（未脱）", depth))
                continue
            # 脱壳结果里若还套着 ELF，再扫一层
            body = res.artifacts[-1].data
            for k, extra in enumerate(elfscan.find_all_elfs(body)):
                res.add(Artifact("elf", f"{tag}.sub{k + 1}",
                                 body[extra.offset:extra.offset + extra.size],
                                 elfscan.describe(extra), depth + 2))
        else:
            res.add(Artifact("elf", tag, sub, elfscan.describe(info), depth))
