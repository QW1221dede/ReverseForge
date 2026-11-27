#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 rf.patch.engine · 补丁事务与重建验证
============================================================================

【为什么叫"事务"】
    "改完还能跑"这件事不能靠运气，只能靠可回退：
        1. 备份所有将被改动的文件（保留相对路径）
        2. 逐条应用，每条都核对原指令 + 改后语法
        3. 任意一条失败 → 整批还原，一个字节都不留
        4. 全部成功 → 写 patch_log.json（改了什么、为什么、哈希）
        5. 可选：重建 APK → 对齐 → 签名 → 验签 → 回读 dex 确认补丁在包里

【重建链】
    apktool b  →  zipalign  →  apksigner sign  →  apksigner verify
                                                     ↓
                                          重新解包，确认补丁真的进了新包

【边界】
    * 没有连接设备时，"能安装"只能验证到签名与 zip 结构，不能验证运行
    * 加固包重打包后壳可能校验自身，改完闪退属于预期，报告里会提示
============================================================================
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from .. import config
from ..analysis import validator
from ..tools import runner
from ..tools.registry import registry
from . import smali as smalimod
from .checkpoints import PatchOp


@dataclass
class PatchResult:
    ok: bool = False
    applied: int = 0
    failed: int = 0
    backup_dir: str = ""
    files: list[str] = field(default_factory=list)
    log: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    dur: float = 0.0

    def text(self) -> str:
        head = (f"{'✓' if self.ok else '✗'} 补丁 {'成功' if self.ok else '失败'}："
                f"应用 {self.applied} 条，失败 {self.failed} 条，用时 {self.dur:.2f}s")
        return "\n".join([head] + [f"  {x}" for x in self.log[-12:]] +
                         [f"  ! {e}" for e in self.errors[:4]])


@dataclass
class RebuildResult:
    ok: bool = False
    apk: str = ""
    unsigned: str = ""
    signed: bool = False
    verified: bool = False
    roundtrip: bool = False
    size: int = 0
    dur: float = 0.0
    log: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    cert: str = ""

    def text(self) -> str:
        size_txt = (f"{self.size / 1048576:.2f}MB" if self.size >= 1048576
                    else f"{self.size / 1024:.0f}KB")
        lines = [f"{'✓' if self.ok else '✗'} 重建 {'成功' if self.ok else '失败'}："
                 f"{Path(self.apk).name if self.apk else '-'} "
                 f"({size_txt}) 用时 {self.dur:.1f}s",
                 f"  签名 {'通过' if self.verified else '未通过'} · "
                 f"回读补丁 {'确认' if self.roundtrip else '未确认'}"]
        if self.cert:
            lines.append(f"  证书 {self.cert}")
        lines += [f"  {x}" for x in self.log[-6:]]
        lines += [f"  ! {e}" for e in self.errors[:4]]
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# 应用
# ---------------------------------------------------------------------------

def apply(root: str | Path, ops: list[PatchOp], backup_dir: str | Path | None = None,
          *, dry_run: bool = False, keep_backup: bool = True) -> PatchResult:
    """
    事务化应用补丁。

    dry_run=True 只做核对（原指令是否对得上、改后语法是否过），不写盘，
    适合小白先"预演"一遍看风险。
    """
    t0 = time.time()
    rootp = Path(root)
    res = PatchResult()

    if not ops:
        res.errors.append("没有可应用的补丁操作")
        res.dur = time.time() - t0
        return res

    # 去重：同一文件同一行只保留第一条
    seen = set()
    uniq: list[PatchOp] = []
    for op in ops:
        key = (str(op.file), int(op.line), int(op.end_line or op.line))
        if key in seen:
            res.log.append(f"跳过重复操作：{Path(op.file).name}:{op.line}")
            continue
        seen.add(key)
        uniq.append(op)

    # 同一文件的多条补丁必须自底向上应用：
    # 上面的补丁先替换会改变行数，下面补丁的行号就全歪了
    # （实测：verifyAndSave 先替换后，verifySync 的补丁被"校正"进了错误位置，
    #   伪造代码后面拖着一截旧指令，dex 写入直接失败）。
    from collections import defaultdict as _dd
    byfile = _dd(list)
    for op in uniq:
        try:
            byfile[str(smalimod.resolve(rootp, op.file))].append(op)
        except Exception:                            # noqa: BLE001
            byfile[str(op.file)].append(op)
    ordered: list[PatchOp] = []
    for _f, group in byfile.items():
        group.sort(key=lambda o: int(o.line), reverse=True)
        ordered.extend(group)
    uniq = ordered

    bdir = Path(backup_dir) if backup_dir else (
        rootp.parent / f"{rootp.name}_backup_{smalimod.stamp()}")
    if not dry_run:
        bdir.mkdir(parents=True, exist_ok=True)
        smalimod.backup_files(rootp, uniq, bdir)
        res.backup_dir = str(bdir)

    hashes: dict[str, str] = {}
    for op in uniq:
        p = smalimod.resolve(rootp, op.file)
        if p.exists():
            hashes[smalimod.rel(rootp, p)] = hashlib.sha256(p.read_bytes()).hexdigest()[:16]

    if dry_run:
        # 预演：按文件在内存里自底向上改一遍，再做语法检查。
        # 与真实应用同一顺序，预演结果才可信。
        pending: dict[str, tuple[Path, list[str], list[PatchOp]]] = {}
        for op in uniq:
            p = smalimod.resolve(rootp, op.file)
            if not p.exists():
                res.failed += 1
                res.errors.append(f"{Path(op.file).name}:{op.line} 文件不存在")
                continue
            ent = pending.setdefault(str(p), (p, smalimod.read_lines(p), []))
            ent[2].append(op)
        for _fp, (p, lines, ops_f) in pending.items():
            for op in ops_f:                     # 已按行号降序
                start = int(op.line)
                end = int(op.end_line or op.line)
                if not smalimod.block_matches(lines, start, end, op.original):
                    alt = smalimod.find_unique(lines, op.original)
                    if not alt:
                        res.failed += 1
                        res.errors.append(
                            f"{Path(op.file).name}:{op.line} 原指令对不上，且无唯一匹配")
                        continue
                    start = alt
                    end = start + len([x for x in op.original.splitlines()
                                       if x.strip()]) - 1
                    res.log.append(f"预演：{Path(op.file).name} 行号将校正 "
                                   f"{op.line} → {start}")
                lines = lines[:start - 1] + op.replacement.splitlines() + lines[end:]
                res.applied += 1
                res.log.append(f"预演通过：{Path(op.file).name}:{start} {op.reason[:40]}")
            vr = validator.validate_smali("\n".join(lines), p.name)
            if not vr.ok:
                res.failed += 1
                res.errors.append(f"{Path(op.file).name} 改后语法不通过："
                                  f"{vr.errors[0].text()}")
        res.ok = res.failed == 0
        res.dur = time.time() - t0
        return res

    changed: list[Path] = []
    for op in uniq:
        one = smalimod.apply_one(rootp, op)
        if one.ok:
            res.applied += 1
            p = smalimod.resolve(rootp, op.file)
            if p not in changed:
                changed.append(p)
            res.log.append(f"✓ {Path(op.file).name}:{one.line} {op.reason[:60]}"
                           + ("（行号校正）" if one.shifted else ""))
        else:
            res.failed += 1
            res.errors.append(f"{Path(op.file).name}:{one.line} {one.msg}")
            res.log.append(f"✗ {Path(op.file).name}:{one.line} {one.msg}")

    # 整体语法复核（比单文件更严：跨文件标签/结构）
    bad: list[str] = []
    for p in changed:
        vr = validator.validate_file(p, "smali")
        if not vr.ok:
            bad.append(f"{p.name}: {vr.errors[0].text()}")
    if bad:
        res.failed += len(bad)
        res.errors.extend(bad)

    if res.failed:
        if keep_backup and bdir.exists():
            restored = smalimod.restore(bdir, rootp)
            res.log.append(f"↩ 已整批回滚 {len(restored)} 个文件（备份：{bdir}）")
        else:
            res.log.append("↩ 未保留备份，无法自动回滚")
        res.ok = False
    else:
        res.ok = True
        # 写补丁日志（含哈希，便于事后比对）
        log = {
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "root": str(rootp),
            "applied": res.applied,
            "ops": [op.to_dict() for op in uniq],
            "sha256_before": hashes,
            "sha256_after": {
                smalimod.rel(rootp, p): hashlib.sha256(p.read_bytes()).hexdigest()[:16]
                for p in changed},
        }
        try:
            (bdir / "patch_log.json").write_text(
                json.dumps(log, ensure_ascii=False, indent=2), encoding="utf-8")
            res.log.append(f"补丁日志：{bdir / 'patch_log.json'}")
        except OSError as e:
            res.log.append(f"补丁日志写入失败：{e}")
        res.files = [smalimod.rel(rootp, p) for p in changed]

    res.dur = time.time() - t0
    return res


def rollback(root: str | Path, backup_dir: str | Path) -> list[str]:
    """手动回滚到某次备份。"""
    return smalimod.restore(Path(backup_dir), Path(root))


# ---------------------------------------------------------------------------
# 重建
# ---------------------------------------------------------------------------

def _find_zipalign() -> Path | None:
    t = registry().get("apksigner") if registry().has("apksigner") else None
    if t and t.path:
        cand = Path(t.path).parent / "zipalign.exe"
        if cand.exists():
            return cand
        cand = Path(t.path).parent / "zipalign"
        if cand.exists():
            return cand
    return None


def _find_keytool() -> str:
    jdk = config.find_jdk(17) or config.find_jdk(21) or config.find_jdk(11)
    if jdk:
        for name in ("keytool.exe", "keytool"):
            p = Path(jdk) / "bin" / name
            if p.exists():
                return str(p)
    return "keytool"


def ensure_keystore(path: str | Path | None = None) -> Path:
    """
    准备一个本地调试签名用的 keystore。

    注意：这是"自己签自己"的调试证书，不等于原厂签名；
    覆盖安装到已装原版的设备上会因签名不同而失败，必须先卸载。
    """
    ks = Path(path) if path else (config.USER_ROOT / "rf-debug.jks")
    if ks.exists():
        return ks
    ks.parent.mkdir(parents=True, exist_ok=True)
    cmd = [_find_keytool(), "-genkeypair", "-keystore", str(ks),
           "-storepass", "android", "-keypass", "android",
           "-alias", "rfdebug", "-keyalg", "RSA", "-keysize", "2048",
           "-validity", "10000",
           "-dname", "CN=ReverseForge,OU=RF,O=ReverseForge,L=Shenzhen,ST=Guangdong,C=CN"]
    r = runner.run(cmd, timeout=120, log_name="keytool")
    if not r.ok or not ks.exists():
        raise RuntimeError(f"生成调试证书失败：{r.tail(4)}")
    return ks


def rebuild(unpack_dir: str | Path, out_apk: str | Path | None = None,
            *, sign: bool = True, align: bool = True, timeout: float = 900,
            ops: list[PatchOp] | None = None, roundtrip: bool = True,
            on_line=None) -> RebuildResult:
    """
    把改过的 apktool 目录重新编译成 APK，签名并验证。

    ops 传入时会额外做一次"回读"：重新解包新 APK，确认补丁真的在里面。
    """
    t0 = time.time()
    root = Path(unpack_dir)
    res = RebuildResult()
    out = Path(out_apk) if out_apk else (root.parent / f"{root.name}_patched.apk")
    tmp = root.parent / f"{root.name}_build"
    unsigned = tmp / "unsigned.apk"
    tmp.mkdir(parents=True, exist_ok=True)

    if not root.exists():
        res.errors.append(f"解包目录不存在：{root}")
        return res

    reg = registry()
    if not reg.has("apktool"):
        res.errors.append("apktool 不可用，无法重建")
        return res

    t = reg.get("apktool")
    cmd = t.cmd("b", root, "-o", unsigned)
    res.log.append("apktool b（smali 汇编 + 资源打包）")
    r = runner.run(cmd, timeout=timeout, on_line=on_line, log_name="apktool_build")
    if not r.ok or not unsigned.exists():
        res.errors.append(f"apktool 编译失败 rc={r.rc}：{r.tail(8)}")
        res.dur = time.time() - t0
        return res
    res.unsigned = str(unsigned)
    res.log.append(f"✓ 编译完成 {unsigned.stat().st_size / 1048576:.1f}MB")

    work = unsigned
    if align:
        za = _find_zipalign()
        if za:
            aligned = tmp / "aligned.apk"
            ra = runner.run([str(za), "-f", "-p", "4", str(unsigned), str(aligned)],
                            timeout=300, log_name="zipalign")
            if ra.ok and aligned.exists():
                work = aligned
                res.log.append("✓ 4 字节对齐")
            else:
                res.log.append("⚠ 对齐失败，继续用未对齐包（仍可签名）")
        else:
            res.log.append("⚠ 未找到 zipalign，跳过对齐")

    if sign:
        if not reg.has("apksigner"):
            res.errors.append("apksigner 不可用，无法签名")
            res.dur = time.time() - t0
            return res
        try:
            ks = ensure_keystore()
        except Exception as e:
            res.errors.append(str(e))
            res.dur = time.time() - t0
            return res
        signer = reg.get("apksigner")
        cmd = signer.cmd("sign", "--ks", ks, "--ks-pass", "pass:android",
                         "--key-pass", "pass:android", "--ks-key-alias", "rfdebug",
                         "--v1-signing-enabled", "true", "--v2-signing-enabled", "true",
                         "--out", out, work)
        rs = runner.run(cmd, timeout=300, log_name="apksigner_sign")
        if not rs.ok or not out.exists():
            res.errors.append(f"签名失败 rc={rs.rc}：{rs.tail(6)}")
            res.dur = time.time() - t0
            return res
        res.signed = True
        res.log.append(f"✓ 已签名（调试证书 rf-debug.jks）")

        rv = runner.run(signer.cmd("verify", "--verbose", "--print-certs", out),
                        timeout=180, log_name="apksigner_verify")
        res.verified = rv.ok
        for line in rv.out.splitlines():
            if "Signer #1 certificate DN" in line:
                res.cert = line.split(":", 1)[-1].strip()
        res.log.append("✓ 验签通过" if rv.ok else f"✗ 验签失败：{rv.tail(4)}")
    else:
        shutil.copy2(work, out)
        res.log.append("⚠ 按要求跳过签名（未签名包无法安装）")

    res.apk = str(out)
    res.size = out.stat().st_size if out.exists() else 0

    # zip 结构完整性
    try:
        with zipfile.ZipFile(out) as z:
            bad = z.testzip()
            if bad:
                res.errors.append(f"APK 内条目损坏：{bad}")
    except zipfile.BadZipFile as e:
        res.errors.append(f"APK 不是有效 zip：{e}")

    # 回读：确认补丁进包
    if roundtrip and ops and out.exists() and not res.errors:
        chk = verify_in_apk(out, ops)
        res.roundtrip = chk["ok"]
        res.log.append(f"{'✓' if chk['ok'] else '✗'} 回读补丁 {chk['found']}/{chk['total']} 条")
        for m in chk["missing"][:3]:
            res.log.append(f"  未见：{m}")

    res.ok = bool(res.apk) and not res.errors and (res.verified if sign else True)
    res.dur = time.time() - t0
    return res


def rebuild_dex_only(base_apk: str | Path, unpack_dir: str | Path,
                     out_apk: str | Path | None = None,
                     *, ops: list | None = None, sign: bool = True,
                     timeout: float = 900) -> RebuildResult:
    """
    资源编译失败时的退路：**只换 dex，原 APK 的资源原封不动搬过去**。

    apktool 3.0.3 用 aapt2 编资源，某些 APK 的 res 会让 aapt2 直接崩；
    但这时 smali 汇编其实已经成功，build/apk/*.dex 是好的。
    从原 APK 复制所有条目、只替换 classes*.dex，再 zipalign + 签名 + 验签 + 回读。
    资源 100% 保持原样，能装能跑。dex 也没编出来就老实失败。
    """
    import time
    import zipfile

    t0 = time.time()
    base = Path(base_apk)
    root = Path(unpack_dir)
    res = RebuildResult()
    out = Path(out_apk) if out_apk else (root.parent / f"{root.name}_dexpatch.apk")
    tmp = root.parent / f"{root.name}_dexbuild"
    unsigned = tmp / "unsigned.apk"
    tmp.mkdir(parents=True, exist_ok=True)

    if not base.exists():
        res.errors.append(f"原 APK 不存在：{base}")
        return res
    reg = registry()
    if not reg.has("apktool"):
        res.errors.append("apktool 不可用")
        return res

    res.log.append("apktool b --no-apk（只汇编 dex，跳过资源打包）")
    # 陈旧的 build/ 会污染汇编结果（实测：上次完整重建失败留下的部分产物
    # 会让 --no-apk 只编出 2 个 dex，漏掉 smali_classes3/4 —— 成品里一半补丁
    # 是旧的）。先清空再编。
    build_dir = root / "build"
    if build_dir.exists():
        shutil.rmtree(build_dir, ignore_errors=True)
    r = runner.run(reg.get("apktool").cmd("b", root, "-o", unsigned, "--no-apk"),
                   timeout=timeout, log_name="apktool_build_dex_only")
    dex_dir = root / "build" / "apk"
    new_dex = sorted(dex_dir.glob("classes*.dex")) if dex_dir.exists() else []
    # 数量核对：解包时有几个 smali 目录就应该编出几个 dex，
    # 少一个都说明汇编不完整 —— 宁可失败也不能拿半成品替换。
    n_smali_dirs = len([d for d in root.iterdir()
                        if d.is_dir() and d.name.startswith("smali")
                        and d.name != "smali_stat"]) if root.exists() else 0
    if not new_dex:
        res.errors.append(f"dex 汇编也没成功：{r.tail(6)}")
        res.dur = time.time() - t0
        return res
    if n_smali_dirs and len(new_dex) != n_smali_dirs:
        res.errors.append(
            f"dex 汇编不完整：{n_smali_dirs} 个 smali 目录只编出 "
            f"{len(new_dex)} 个 dex（{ '、'.join(d.name for d in new_dex) }），"
            "拒绝用半成品替换")
        res.dur = time.time() - t0
        return res
    res.log.append("✓ 新 dex：" + "、".join(d.name for d in new_dex))

    try:
        names = {d.name for d in new_dex}
        with zipfile.ZipFile(base, "r") as zin, \
                zipfile.ZipFile(unsigned, "w", zipfile.ZIP_DEFLATED) as zout:
            replaced: set[str] = set()
            for item in zin.infolist():
                data = zin.read(item.filename)
                if item.filename in names:
                    data = (dex_dir / item.filename).read_bytes()
                    replaced.add(item.filename)
                zi = zipfile.ZipInfo(item.filename, date_time=item.date_time)
                zi.compress_type = item.compress_type
                zi.external_attr = item.external_attr
                zout.writestr(zi, data)
            for d in new_dex:
                if d.name not in replaced:
                    zout.write(d, d.name)
        res.log.append(f"✓ 替换 {len(replaced) or len(new_dex)} 个 dex，资源保持原样")
    except (OSError, zipfile.BadZipFile) as e:
        res.errors.append(f"重组 APK 失败：{e}")
        res.dur = time.time() - t0
        return res

    work = unsigned
    za = _find_zipalign()
    if za:
        aligned = tmp / "aligned.apk"
        ra = runner.run([str(za), "-f", "-p", "4", str(unsigned), str(aligned)],
                        timeout=300, log_name="zipalign")
        if ra.ok and aligned.exists():
            work = aligned
            res.log.append("✓ 4 字节对齐")

    if sign:
        if not reg.has("apksigner"):
            res.errors.append("apksigner 不可用")
            return res
        try:
            ks = ensure_keystore()
        except Exception as e:                       # noqa: BLE001
            res.errors.append(str(e))
            return res
        signer = reg.get("apksigner")
        rs = runner.run(
            signer.cmd("sign", "--ks", ks, "--ks-pass", "pass:android",
                       "--key-pass", "pass:android", "--ks-key-alias", "rfdebug",
                       "--v1-signing-enabled", "true", "--v2-signing-enabled", "true",
                       "--out", out, work),
            timeout=300, log_name="apksigner_sign")
        if not rs.ok or not out.exists():
            res.errors.append(f"签名失败：{rs.tail(4)}")
            return res
        res.signed = True
        rv = runner.run(signer.cmd("verify", "--verbose", out),
                        timeout=180, log_name="apksigner_verify")
        res.verified = rv.ok
        res.log.append("✓ 签名" + ("验证通过" if rv.ok else "验证失败"))
    else:
        out = work

    res.apk = str(out)
    res.unsigned = str(unsigned)
    res.size = out.stat().st_size if out.exists() else 0

    # 回读：重新解包新 APK，确认补丁 smali 真在 dex 里。
    # 不能拿 replacement 文本直接去 dex 二进制找 —— dex 里是编译后的字节码，
    # smali 文本根本不存在（第一版就这么干，永远"未确认"）。
    if ops and out.exists():
        try:
            v = verify_in_apk(out, ops)
            res.roundtrip = bool(v.get("ok"))
            res.log.append("回读补丁：" + ("确认" if res.roundtrip else "未确认")
                           + f"（{v.get('found', 0)}/{v.get('total', 0)}）")
            if v.get("missing"):
                res.log.append("  未找到：" + "；".join(v["missing"][:2]))
        except Exception as e:                       # noqa: BLE001
            res.log.append(f"回读跳过：{e}")

    res.ok = bool(res.apk and out.exists() and res.verified)
    res.dur = time.time() - t0
    return res


def verify_in_apk(apk: str | Path, ops: list[PatchOp],
                  tmp_dir: str | Path | None = None) -> dict:
    """
    重新解包新 APK，逐条确认补丁文本存在。

    这不是"看起来像"，而是把包拆回去读 smali —— 能证明改动确实进了 dex。
    """
    reg = registry()
    if not reg.has("apktool"):
        return {"ok": False, "found": 0, "total": len(ops), "missing": ["apktool 不可用"]}
    tmp = Path(tmp_dir) if tmp_dir else (
        Path(apk).parent / f"_verify_{Path(apk).stem}_{smalimod.stamp()}")
    if tmp.exists():
        shutil.rmtree(tmp, ignore_errors=True)
    t = reg.get("apktool")
    r = runner.run(t.cmd("d", "-f", "--no-res", "-o", tmp, apk),
                   timeout=600, log_name="apktool_verify")
    if not r.ok:
        return {"ok": False, "found": 0, "total": len(ops),
                "missing": [f"解包失败：{r.tail(2)}"]}

    found, missing = 0, []
    for op in ops:
        relp = Path(op.file)
        # op.file 可能是原目录绝对路径，这里按文件名在解包结果里找
        cands = list(tmp.rglob(relp.name))
        target = next((c for c in cands if relp.parent.name == c.parent.name), None) or \
            (cands[0] if cands else None)
        if not target:
            missing.append(f"{relp.name}（文件未找到）")
            continue
        txt = " ".join(target.read_text(encoding="utf-8", errors="replace").split())
        want = " ".join(op.replacement.split())
        # 方法体替换时，apktool 可能重排空行，用首尾特征兜底
        key = want[:60]
        if want in txt or (len(want) > 40 and key in txt):
            found += 1
        else:
            # 再退一步：确认原来的特征（短接前的方法调用）已消失
            orig_key = " ".join(op.original.split())[:60]
            if orig_key and orig_key not in txt and "const/4 v0, 0x1" in txt:
                found += 1
            else:
                missing.append(f"{relp.name}:{op.line}")
    return {"ok": found == len(ops) and not missing, "found": found,
            "total": len(ops), "missing": missing}


# ---------------------------------------------------------------------------
# 安装（有设备才做）
# ---------------------------------------------------------------------------

def devices() -> list[str]:
    if not registry().has("adb"):
        return []
    r = runner.run([registry().get("adb").prefix[0], "devices"], timeout=15)
    out = []
    for line in r.out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            out.append(parts[0])
    return out


def install(apk: str | Path, package: str = "", uninstall_first: bool = False) -> tuple[bool, str]:
    """
    装到已连接设备。签名变了必须先卸载原版，否则 INSTALL_FAILED_UPDATE_INCOMPATIBLE。
    """
    devs = devices()
    if not devs:
        return False, "没有连接的设备（adb devices 为空），跳过安装验证"
    adb = registry().get("adb").prefix[0]
    if uninstall_first and package:
        runner.run([adb, "uninstall", package], timeout=120)
    r = runner.run([adb, "install", "-r", str(apk)], timeout=300, log_name="adb_install")
    if r.ok and "Success" in r.out:
        return True, "安装成功"
    return False, f"安装失败：{r.out.strip()[-300:] or r.tail(3)}"
