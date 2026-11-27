#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 rf.patch.smali · smali 指令级改写
============================================================================

【一条纪律】
    补丁不是"按行号硬改"。行号会在不同 apktool 版本、不同解包参数下漂移，
    所以每次改写前都要拿原指令逐行核对：
        对得上 → 改
        对不上 → 在文件里全量搜索，唯一命中就自动校正行号（并记进日志）
        多处命中 → 拒绝改，报"目标不唯一"
    宁可失败，也不能把无关代码改坏 —— 这是"保证程序能跑"的前提。

【支持的操作】
    line     单行替换（分支反转、goto、const/4 改值）
    block    连续多行替换（方法体短路、代码块插入）
    method   方法体整体替换（自动保留 .method/.end method 与 .registers）

【写盘】
    原子写：先写 .tmp 再 os.replace，避免中途断电/杀进程留下半个文件。
============================================================================
"""

from __future__ import annotations

import os
import re
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

from ..analysis import validator
from .checkpoints import PatchOp


@dataclass
class ApplyOne:
    ok: bool
    file: str
    line: int
    msg: str
    shifted: bool = False


def rel(root: Path, file: str | Path) -> str:
    try:
        return str(Path(file).resolve().relative_to(Path(root).resolve())).replace("\\", "/")
    except ValueError:
        return str(file)


def resolve(root: Path, file: str | Path) -> Path:
    """
    把 op.file 解析成真实路径。

    三种情况都要认：
      绝对路径                    → 直接用
      相对 cwd 的路径（扫描时传的是相对目录） → 直接用
      相对 root 的路径（脚本里手写）          → 拼到 root 下
    """
    p = Path(file)
    if p.is_absolute():
        return p
    if p.exists():
        return p
    cand = Path(root) / p
    if cand.exists():
        return cand
    # 传进来的路径可能带着 root 的名字前缀（如 sample/smali/x.smali）
    parts = p.parts
    for i in range(1, len(parts)):
        alt = Path(root).joinpath(*parts[i:])
        if alt.exists():
            return alt
    return cand


def read_lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8", errors="replace").splitlines()


def atomic_write(path: Path, lines: list[str]) -> None:
    """原子写：同目录临时文件 + os.replace。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".rftmp")
    data = "\n".join(lines)
    if not data.endswith("\n"):
        data += "\n"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def _norm(s: str) -> str:
    return " ".join(s.split())


def _block_matches(lines: list[str], start: int, end: int, original: str) -> bool:
    """
    逐行核对一个范围（1 基、闭区间）。
    只比较非空行，允许空行数量不同 —— apktool 不同版本的空行策略有差异。
    """
    if start < 1 or end > len(lines) or start > end:
        return False
    want = [_norm(x) for x in original.splitlines() if x.strip()]
    got = [_norm(lines[i - 1]) for i in range(start, end + 1) if lines[i - 1].strip()]
    return want == got


def _find_unique(lines: list[str], original: str) -> int:
    """在全文件里找一段唯一匹配，返回起始行号；找不到或歧义返回 0。"""
    want = [_norm(x) for x in original.splitlines() if x.strip()]
    if not want:
        return 0
    hits = []
    n, m = len(lines), len(want)
    for i in range(n):
        if _norm(lines[i]) != want[0]:
            continue
        j, k = i, 0
        while j < n and k < m:
            if lines[j].strip():
                if _norm(lines[j]) != want[k]:
                    break
                k += 1
            j += 1
        if k == m:
            hits.append(i + 1)
    return hits[0] if len(hits) == 1 else 0


def apply_one(root: Path, op: PatchOp, *, strict: bool = True) -> ApplyOne:
    """应用单条操作。返回结果，不抛异常（除 IO 错误）。"""
    path = resolve(root, op.file)
    if not path.exists():
        return ApplyOne(False, str(path), op.line, "目标文件不存在")
    lines = read_lines(path)
    start, end = int(op.line), int(op.end_line or op.line)

    shifted = False
    if not _block_matches(lines, start, end, op.original):
        alt = _find_unique(lines, op.original)
        if alt:
            start = alt
            end = alt + len([x for x in op.original.splitlines() if x.strip()]) - 1
            # 原块里可能含空行，按实际匹配长度再校正一次
            if not _block_matches(lines, start, end, op.original):
                k = len([x for x in op.original.splitlines() if x.strip()])
                end = start + k - 1
            shifted = True
        else:
            actual = _norm(lines[start - 1]) if 0 < start <= len(lines) else "（越界）"
            msg = (f"原指令对不上：期望「{_norm(op.original.splitlines()[0])[:60]}」，"
                   f"第 {start} 行实际是「{actual[:60]}」；"
                   f"全文件也没有唯一匹配")
            return ApplyOne(False, str(path), start, msg)

    repl = op.replacement.splitlines()
    new = lines[:start - 1] + repl + lines[end:]
    atomic_write(path, new)

    vr = validator.validate_smali("\n".join(new), path.name)
    if not vr.ok:
        atomic_write(path, lines)          # 立刻还原
        first = vr.errors[0].text()
        return ApplyOne(False, str(path), start, f"改写后语法不通过，已还原：{first}")

    return ApplyOne(True, str(path), start,
                    ("行号已自动校正后应用" if shifted else "已应用"), shifted)


def backup_files(root: Path, ops: list[PatchOp], backup_dir: Path) -> dict[str, str]:
    """把涉及的文件备份到 backup_dir（保留相对路径），返回 {相对路径: 绝对路径}。"""
    done: dict[str, str] = {}
    for op in ops:
        p = resolve(root, op.file)
        if not p.exists():
            continue
        r = rel(root, p)
        if r in done:
            continue
        dst = backup_dir / r
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(p, dst)
        done[r] = str(p)
    return done


def restore(backup_dir: Path, root: Path) -> list[str]:
    """从备份目录整体还原，返回还原的文件列表。"""
    restored = []
    if not Path(backup_dir).exists():
        return restored
    for src in Path(backup_dir).rglob("*.smali"):
        r = src.relative_to(backup_dir)
        dst = Path(root) / r
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        restored.append(str(r).replace("\\", "/"))
    return restored


def method_end_line(path: Path, method_line: int) -> int:
    """给定 .method 行号，返回 .end method 的行号（找不到返回 0）。"""
    lines = read_lines(path)
    for i in range(method_line, len(lines)):
        if lines[i].strip().startswith(".end method"):
            return i + 1
    return 0


def stamp() -> str:
    return time.strftime("%Y%m%d_%H%M%S")


# 给 engine / 脚本用的公开别名（下划线版本是内部实现）
block_matches = _block_matches
find_unique = _find_unique
norm_line = _norm


# ---------------------------------------------------------------------------
# 字符串常量替换（卡密/口令/默认值）
# ---------------------------------------------------------------------------

_STR_LINE = re.compile(r'^(const-string(?:/jumbo)?\s+[vp]\d+,\s*)"(.*)"\s*$')


def escape_smali(s: str) -> str:
    """把普通字符串转成 smali 字面量内容（引号/反斜杠/换行）。"""
    bs = chr(92)
    return (s.replace(bs, bs + bs).replace('"', bs + '"')
             .replace(chr(10), bs + "n").replace(chr(13), bs + "r")
             .replace(chr(9), bs + "t"))


def find_string_ops(root: str | Path, old: str, new: str,
                    limit: int = 80) -> list[PatchOp]:
    """
    找出所有 `const-string vX, "old"` 并生成替换操作。

    用途：把写死的卡密/默认口令/测试密钥换成你要的值。
    注意：
        * 只改字面量，不改派生逻辑（如果程序比对的是 SHA-256，改原文没用，
          要改的是那个哈希，或者直接改比对结果）
        * 值必须完全一致，包括大小写
    """
    out: list[PatchOp] = []
    rootp = Path(root)
    files = [rootp] if rootp.is_file() else sorted(rootp.rglob("*.smali"))
    for f in files:
        try:
            lines = read_lines(f)
        except OSError:
            continue
        for i, line in enumerate(lines, 1):
            m = _STR_LINE.match(line.strip())
            if not m or m.group(2) != old:
                continue
            out.append(PatchOp(
                file=str(f), line=i, end_line=i,
                original=line.strip(),
                replacement=f'{m.group(1)}"{escape_smali(new)}"',
                reason=f"字符串替换：{old[:24]} → {new[:24]}",
                kind="line"))
            if len(out) >= limit:
                return out
    return out
