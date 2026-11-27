#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 tests/selftest_selfextract.py · 自解压 / 多层封装拆解自测
============================================================================

    复现真实样本的形态（三角洲un破解版.sh）：
        makeself 脚本头（skip=N + tail -n +N | gzip -cd）
        → gzip 流
        → 两个 ARM64 ELF 拼在一起（中间夹 "\\n略略略\\n" 填充）

    验收：
      1. 能按 skip=N 精确切出 gzip 负载
      2. 能解压出 25MB 级内容（这里用合成数据）
      3. 能把拼接的两个 ELF 都识别出来（旧版只认第一个）
      4. salvage() 遇到这类样本必须直接走容器拆解，不再报"没解出来"
============================================================================
"""
from __future__ import annotations

import gzip
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from rf.analysis import elfscan, selfextract
from rf.decrypt import auto

FAILED: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"  [{'OK ' if ok else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
    if not ok:
        FAILED.append(name)


def make_elf(machine: int = 183, size: int = 8192, fill: bytes = b"\xaa") -> bytes:
    """造一个足够"像真的"最小 ELF（ET_DYN，一个 PT_LOAD，填充到 size）。"""
    hdr = bytearray(64)
    hdr[0:4] = b"\x7fELF"
    hdr[4] = 2           # 64 位
    hdr[5] = 1           # 小端
    hdr[6] = 1
    struct.pack_into("<H", hdr, 16, 3)              # ET_DYN
    struct.pack_into("<H", hdr, 18, machine)
    struct.pack_into("<Q", hdr, 24, 0x1000)         # entry
    struct.pack_into("<Q", hdr, 32, 64)             # phoff
    struct.pack_into("<Q", hdr, 40, 0)              # shoff（无节表）
    struct.pack_into("<H", hdr, 52, 64)             # ehsize
    struct.pack_into("<H", hdr, 54, 56)             # phentsize
    struct.pack_into("<H", hdr, 56, 1)              # phnum
    ph = struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, size, size, 0x1000)
    blob = bytes(hdr) + ph
    return blob + fill * (size - len(blob))


def make_makeself(payload: bytes, label: str = "SynthApp") -> bytes:
    """按 makeself 的格式造一个自解压脚本：skip=N 指向 payload 起始行。"""
    body_lines = [
        "#!/bin/sh",
        "# 自解压脚本（合成样本，用于回归测试）",
        'MS_ARCHIVE_LABEL="%s"' % label,
        "skip=0",                       # 下面按实际行数回填
        "echo extracting",
        'tail -n +$skip "$0" | gzip -cd > /tmp/payload.bin',
        "exit 0",
        "",
        "# padding 1",
        "# padding 2",
        "# padding 3",
        "# padding 4",
        "# padding 5",
        "# padding 6",
    ]
    # 头部 N 行 → payload 从第 N+1 行开始，skip 就等于 N+1
    body_lines[3] = f"skip={len(body_lines) + 1}"
    head = ("\n".join(body_lines) + "\n").encode()
    return head + payload


elf1 = make_elf(183, 8192, b"\x11")
elf2 = make_elf(183, 24576, b"\x22")
concat = elf1 + b"\n" + "略略略".encode() + b"\n" + elf2

print("[1] ELF 扫描：拼接多 ELF")
infos = elfscan.find_all_elfs(concat)
check("识别出 2 个 ELF", len(infos) == 2, f"{len(infos)} 个")
check("第一个偏移 0", bool(infos) and infos[0].offset == 0, f"{infos[0].offset if infos else '-'}")
check("第二个偏移正确", len(infos) > 1 and infos[1].offset == len(elf1) + 1 + 9 + 1,
      f"{infos[1].offset if len(infos) > 1 else '-'}")
check("架构识别为 ARM64", all(i.machine_name == "ARM64" for i in infos))

print("\n[2] makeself 解析")
gz = gzip.compress(concat, 6)
script = make_makeself(gz)
ms = selfextract.parse_makeself(script)
check("识别 makeself", ms is not None)
if ms:
    check("skip 指向负载首行", ms["skip"] == 15, str(ms["skip"]))
    check("offset 指向 gzip 魔数",
          script[ms["offset"]:ms["offset"] + 2] == b"\x1f\x8b",
          script[ms["offset"]:ms["offset"] + 2].hex())

print("\n[3] 多层拆解 deep_unpack")
res = selfextract.deep_unpack(script, "synth")
kinds = [a.kind for a in res.artifacts]
check("产出 makeself 层", "makeself" in kinds, ",".join(kinds))
check("产出 gzip 层", "gzip" in kinds, ",".join(kinds))
elfs = [a for a in res.artifacts if a.kind == "elf"]
check("产出 2 个 ELF", len(elfs) == 2, f"{len(elfs)} 个")
check("解压内容与原文一致",
      any(a.data == concat for a in res.artifacts if a.kind == "gzip"))

print("\n[4] salvage 端到端（应为容器拆解，不报没解出）")
rep = auto.salvage(script, budget=8)
check("有命中", bool(rep.hits), rep.summary()[:60])
check("命中里有 ELF", any(h.out[:4] == b"\x7fELF" for h in rep.hits),
      "、".join(h.method[:18] for h in rep.hits[:3]))
check("notes 记录了 makeself", any("makeself" in n for n in rep.notes),
      " / ".join(rep.notes[:2]))

if FAILED:
    print(f"\n失败 {len(FAILED)} 项：" + "、".join(FAILED))
    sys.exit(1)
print("\n全部通过")
