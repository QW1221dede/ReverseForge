# -*- coding: utf-8 -*-
"""
============================================================================
 rf.patch.native · ELF 原生层验证闸门补丁（通用版）
============================================================================

【为什么需要这一层】
    checkpoints.py 只扫 smali，看不到 native ELF 里的验证：
      .rodata 含 checktrue / api/login / 校验失败 / 请输入卡密
      .text   失败出口统一是  "打印错误串 → mov w0,#1 → bl exit"

【思路：不记地址，认结构】
    1. 统计 "mov w0,#1 + bl X" 出现最多的 X —— 那就是 exit 类函数
    2. 每个这样的调用点往前 0x60 字节，就是一段「失败块」
    3. 只处理卡密特征字符串引用点 ±0x200 内的条件跳转：
         · 不跳会掉进失败块  → 改成无条件跳过去
         · 跳进去就是失败块  → 改成 NOP，直行走成功路径
    结果：服务器返回什么、卡密输什么，都走不到 exit(1)。

【安全】
    * 有特征才动手，没有就拒绝（不盲改）
    * 改前备份 .bak，改后回读比对，不一致自动回滚
    * 输出补丁明细 + 前后 SHA256，可追溯可还原
============================================================================
"""
from __future__ import annotations

import hashlib
import json
import struct
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

NOP = 0xD503201F
FAIL_WINDOW = 0x60      # 失败块回溯窗口
ANCHOR_RANGE = 0x200    # 只处理卡密锚点附近的分支


def b_at(from_addr: int, to_addr: int) -> int:
    """无条件 B"""
    off = ((to_addr - from_addr) // 4) & 0x03FFFFFF
    return 0x14000000 | off


@dataclass
class NativeResult:
    ok: bool = False
    path: str = ""
    backup: str = ""
    exit_func: str = ""
    fail_blocks: int = 0
    log: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    before_sha: str = ""
    after_sha: str = ""

    def text(self) -> str:
        head = ("✓" if self.ok else "✗") + " ELF 原生闸门补丁"
        if self.exit_func:
            head += "（exit=%s，失败块 %d 处）" % (self.exit_func, self.fail_blocks)
        return "\n".join([head] + ["  " + x for x in self.log] +
                         ["  ! " + e for e in self.errors])


# --------------------------------------------------------------------------
# ELF 辅助
# --------------------------------------------------------------------------
def _sections(p: Path):
    from elftools.elf.elffile import ELFFile
    with p.open("rb") as f:
        elf = ELFFile(f)
        return {s.name: (s["sh_addr"], s["sh_offset"], s["sh_size"])
                for s in elf.iter_sections() if s.name}


def _find_ref(code: bytes, va0: int, target_va: int) -> list[int]:
    """找 ADRP+ADD 精确引用 target_va 的指令地址。"""
    out = []
    for i in range(0, len(code) - 8, 4):
        w1 = struct.unpack_from("<I", code, i)[0]
        if (w1 & 0x9F000000) != 0x90000000:
            continue
        a = va0 + i
        imm = (((w1 >> 5) & 0x7FFFF) << 2) | ((w1 >> 29) & 3)
        if imm & (1 << 20):
            imm -= 1 << 21
        pg = ((a & ~0xFFF) + (imm << 12)) & 0xFFFFFFFFFFFFFFFF
        w2 = struct.unpack_from("<I", code, i + 4)[0]
        if (w2 & 0x7F000000) == 0x11000000:
            if pg + ((w2 >> 10) & 0xFFF) == target_va:
                out.append(a)
    return out


def _is_w0_one(ins) -> bool:
    if ins.mnemonic not in ("mov", "movz"):
        return False
    s = ins.op_str.replace(" ", "").lower()
    return s.startswith("w0,#1") and "," not in s[4:]


# --------------------------------------------------------------------------
# 主流程
# --------------------------------------------------------------------------
def patch_native(path: str | Path, *, dry_run: bool = False,
                 backup: bool = True, require_features: bool = True) -> NativeResult:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

    R = NativeResult(path=str(path))
    p = Path(path)
    if not p.is_file():
        R.errors.append("文件不存在：" + str(p))
        return R

    raw = p.read_bytes()
    R.before_sha = hashlib.sha256(raw).hexdigest()

    if raw[:4] != b"\x7fELF":
        R.errors.append("不是 ELF 文件")
        return R

    # 必须有卡密/授权类特征，否则不动手
    feats = [b"checktrue", b"api/login",
             "校验失败".encode(), "请输入卡密".encode(), b"card_key", b"activate"]
    hit = [f for f in feats if f in raw]
    if require_features and not hit:
        R.errors.append("未发现授权类特征，拒绝盲改")
        return R
    R.log.append("命中特征：" + " / ".join(f.decode("utf-8", "replace") for f in hit))

    try:
        secs = _sections(p)
        tv, to, ts = secs[".text"]
        rv, ro, rs = secs[".rodata"]
    except Exception as e:
        R.errors.append("ELF 节定位失败：%r" % (e,))
        return R

    code = raw[to:to + ts]
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    insns = list(md.disasm(code, tv))
    if not insns:
        R.errors.append(".text 反汇编为空")
        return R
    R.log.append(".text 反汇编 %d 条指令" % len(insns))

    # ---- 1. 找 exit 类函数 ----
    cand = Counter()
    for i in range(len(insns) - 1):
        if _is_w0_one(insns[i]) and insns[i + 1].mnemonic == "bl":
            cand[insns[i + 1].op_str] += 1
    if not cand:
        R.errors.append("找不到 mov w0,#1 + bl 的失败出口")
        return R
    exit_op, exit_cnt = cand.most_common(1)[0]
    R.exit_func = exit_op
    R.log.append("exit 类函数 %s（%d 处调用）" % (exit_op, exit_cnt))

    # ---- 2. 失败块区间（回溯到控制流边界，取最靠前的 adrp 作块头）----
    fail_ranges = []
    for i in range(1, len(insns) - 1):
        if not _is_w0_one(insns[i]):
            continue
        call = insns[i + 1]
        if call.mnemonic != "bl" or call.op_str != exit_op:
            continue
        start = insns[i].address
        j = i
        while j > 0 and i - j <= 24:
            m = insns[j].mnemonic
            if m == "adrp":
                start = insns[j].address
            elif m == "bl":
                pass
            elif m in ("b", "ret", "br", "blr") or m.startswith("b.") \
                    or m in ("cbz", "cbnz", "tbz", "tbnz"):
                break
            j -= 1
        fail_ranges.append((start, call.address + 4))
    fail_ranges.sort()
    if not fail_ranges:
        R.errors.append("失败块为空")
        return R
    R.fail_blocks = len(fail_ranges)
    R.log.append("失败块 %d 段：%s" % (
        len(fail_ranges),
        " ".join("%X-%X" % (lo, hi) for lo, hi in fail_ranges)))

    def in_fail(a: int) -> bool:
        return any(lo <= a < hi for lo, hi in fail_ranges)

    # ---- 3. 卡密锚点 ----
    anchors: list[int] = []
    for f in feats:
        i = raw.find(f)
        if i < 0 or not (ro <= i < ro + rs):
            continue
        va = rv + (i - ro)
        anchors += _find_ref(code, tv, va)
    if not anchors:
        R.errors.append("卡密特征字符串没有代码引用")
        return R
    anchors = sorted(set(anchors))
    R.log.append("卡密锚点 %d 处：%s" % (
        len(anchors), " ".join("0x%X" % a for a in anchors[:6])))

    # ---- 4. 拦分支 ----
    plans: dict[int, tuple[int, str]] = {}
    for ins in insns:
        if not ins.mnemonic.startswith("b."):
            continue
        if not any(abs(ins.address - a) <= ANCHOR_RANGE for a in anchors):
            continue
        _t = ins.op_str.strip().lstrip("#")
        if not _t.startswith("0x"):
            continue
        try:
            tgt = int(_t, 16)
        except ValueError:
            continue
        ft = ins.address + 4
        t_in, f_in = in_fail(tgt), in_fail(ft)
        if f_in and not t_in:
            plans[ins.address] = (b_at(ins.address, tgt),
                                  "不跳即执行失败块 → 强制跳到通过点 0x%X" % tgt)
        elif t_in and not f_in:
            plans[ins.address] = (NOP, "跳转即失败块 → NOP，继续走通过路径")
        elif t_in and f_in:
            plans[ins.address] = (NOP, "两侧都是失败块 → NOP")

    if not plans:
        R.errors.append("锚点附近没有可补的条件分支（可能已打过补丁）")
        return R

    # ---- 5. 写盘 ----
    tmp = bytearray(raw)
    applied = []
    for addr, (new, note) in sorted(plans.items()):
        fo = to + (addr - tv)
        old = struct.unpack_from("<I", tmp, fo)[0]
        struct.pack_into("<I", tmp, fo, new)
        applied.append((fo, addr, old, new, note))
        R.log.append("0x%X: %08X → %08X  %s" % (addr, old, new, note))

    R.after_sha = hashlib.sha256(tmp).hexdigest()
    if dry_run:
        R.log.append("（DRY-RUN 未写盘，共 %d 处）" % len(applied))
        R.ok = True
        return R

    if backup:
        bp = p.with_suffix(p.suffix + ".bak")
        if not bp.exists():
            bp.write_bytes(raw)
            R.backup = str(bp)
            R.log.append("备份：" + bp.name)

    p.write_bytes(tmp)
    if p.read_bytes() != tmp:
        p.write_bytes(raw)
        R.errors.append("回读不一致，已回滚")
        return R

    lp = p.with_name(p.stem + ".patch_log.json")
    lp.write_text(json.dumps({
        "target": str(p), "before": R.before_sha, "after": R.after_sha,
        "exit_func": R.exit_func, "fail_blocks": R.fail_blocks,
        "patches": [{"addr": hex(a), "old": hex(o), "new": hex(n), "note": note}
                    for _, a, o, n, note in applied],
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    R.log.append("补丁日志：" + lp.name)
    R.ok = True
    return R


# --------------------------------------------------------------------------
# 目录批量（给自动化流程用）
# --------------------------------------------------------------------------
def patch_dir(root: str | Path, *, dry_run: bool = False,
              pattern: str = "*.bin") -> list[NativeResult]:
    """对目录下所有 ELF 产物尝试打补丁，返回有结果的。"""
    out = []
    for f in sorted(Path(root).rglob(pattern)):
        try:
            if f.read_bytes()[:4] != b"\x7fELF":
                continue
        except Exception:
            continue
        r = patch_native(f, dry_run=dry_run, require_features=True)
        if r.ok or r.log:
            out.append(r)
    return out
