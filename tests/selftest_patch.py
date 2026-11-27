#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 tests/selftest_patch.py · 补丁链路自测
============================================================================

不只跑通，还要能证明"改坏了会被拦住"：
    1. 识别：样本里的 LicenseManager.verify 必须被找到，且标记启动路径
    2. 预演：不写盘
    3. 应用：备份 + 语法校验
    4. 反向测试：故意给错原指令 → 必须失败且文件不变
    5. 重建：签名通过 + 回读补丁在包里
    6. 回滚：恢复成原始方法体
    7. 真实包：X-提权者 扫描（存在才跑）

    python tests/selftest_patch.py
============================================================================
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from rf.analysis import validator            # noqa: E402
from rf.patch import checkpoints as cp       # noqa: E402
from rf.patch import engine as pe            # noqa: E402
from rf.patch import smali as sm             # noqa: E402
from rf.tools import runner                  # noqa: E402
from rf.tools.registry import registry       # noqa: E402

OUT = ROOT / "_test_out" / "selftest"
FAILS: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    print(("  ✓ " if cond else "  ✗ ") + name + (f"  [{detail}]" if detail else ""))
    if not cond:
        FAILS.append(name)


def unpack(apk: Path, dst: Path) -> bool:
    reg = registry()
    reg.build()
    t = reg.get("apktool")
    r = runner.run(t.cmd("d", "-f", "--no-res", "-o", dst, apk), timeout=300)
    return r.ok and (dst / "smali").exists()


def main() -> int:
    apk = ROOT / "_test_out" / "sample_license.apk"
    if not apk.exists():
        print("样本不存在，先构建…")
        import build_sample_apk
        build_sample_apk.build()

    if OUT.exists():
        shutil.rmtree(OUT, ignore_errors=True)
    OUT.mkdir(parents=True)
    work = OUT / "unpack"
    print("[1] 解包样本")
    check("apktool 解包成功", unpack(apk, work))
    if FAILS:
        return 1

    print("[2] 识别启动前校验")
    rep = cp.analyze(work)
    print("   ", rep.summary())
    verify = next((p for p in rep.points if p.method == "verify"), None)
    check("找到 LicenseManager.verify", verify is not None)
    if verify:
        check("标记为启动路径", verify.pre_run, verify.chain)
        check("类别是授权校验", verify.category == "授权校验", verify.category)
        check("置信度 ≥ 70", verify.confidence >= 70, str(verify.confidence))
        check("有方法级建议", bool(verify.best) and verify.best.kind == "method_true",
              verify.best.kind if verify.best else "无")
    expired = next((p for p in rep.points if p.method == "isExpired"), None)
    check("isExpired 建议返回 false",
          bool(expired and expired.best and expired.best.kind == "method_false"),
          expired.best.kind if expired and expired.best else "无")

    ops = cp.to_plan(rep, ids=[p.cid for p in rep.points])
    check("生成 2 条操作", len(ops) == 2, str(len(ops)))

    print("[3] 预演（不写盘）")
    target = work / "smali" / "com" / "rf" / "demo" / "LicenseManager.smali"
    before = target.read_text(encoding="utf-8")
    dry = pe.apply(work, ops, dry_run=True)
    check("预演通过", dry.ok, dry.errors[0] if dry.errors else "")
    check("预演未改文件", target.read_text(encoding="utf-8") == before)

    print("[4] 反向测试：错误的原指令必须被拦住")
    bad = cp.PatchOp(file=str(target), line=1, end_line=1,
                     original=".method public static notExist()Z",
                     replacement="    return-void", reason="故意写错", kind="line")
    res_bad = pe.apply(work, [bad])
    check("错误补丁失败", not res_bad.ok)
    check("失败后文件未变", target.read_text(encoding="utf-8") == before)
    check("自动回滚已执行",
          any("回滚" in x for x in res_bad.log), "；".join(res_bad.log[-2:]))

    print("[5] 应用补丁")
    res = pe.apply(work, ops)
    check("应用成功", res.ok, res.text().splitlines()[0])
    after = target.read_text(encoding="utf-8")
    check("方法体已短路", "const/4 v0, 0x1" in after and
          "invoke-static {p0}" not in after.split(".method public static verify")[1]
          .split(".end method")[0])
    vr = validator.validate_smali(after)
    check("改后 smali 语法通过", vr.ok, vr.errors[0].text() if vr.errors else "")
    check("备份目录存在", bool(res.backup_dir) and Path(res.backup_dir).exists())
    check("补丁日志存在", (Path(res.backup_dir) / "patch_log.json").exists())

    re_rep = cp.analyze(work)
    check("复扫不再把 verify 当校验点",
          not any(p.method == "verify" for p in re_rep.pre_run),
          f"仍有 {len(re_rep.pre_run)} 个")

    print("[6] 重建 + 签名 + 回读")
    out_apk = OUT / "sample_patched.apk"
    rb = pe.rebuild(work, out_apk, ops=ops)
    print("   ", rb.text().replace("\n", "\n    "))
    check("重建成功", rb.ok)
    check("签名验证通过", rb.verified)
    check("回读补丁 2/2", rb.roundtrip)
    if out_apk.exists():
        import zipfile
        with zipfile.ZipFile(out_apk) as z:
            names = z.namelist()
        check("APK 含 classes.dex", "classes.dex" in names)
        check("APK 含 Manifest", "AndroidManifest.xml" in names)

    print("[7] 回滚")
    files = pe.rollback(work, res.backup_dir)
    check("回滚了文件", len(files) >= 1, f"{len(files)} 个")
    check("内容恢复原样", target.read_text(encoding="utf-8") == before)

    print("[8] 字符串常量替换（卡密）")
    const_ops = sm.find_string_ops(work, "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92",
                                   "0123456789abcdef")
    check("找到唯一常量", len(const_ops) == 1, f"{len(const_ops)} 处")
    if const_ops:
        cr = pe.apply(work, const_ops)
        check("常量替换应用成功", cr.ok, cr.errors[0] if cr.errors else "")
        txt = target.read_text(encoding="utf-8")
        check("新常量已写入", "deadbeef" not in txt and "0123456789abcdef" in txt)
        pe.rollback(work, cr.backup_dir)
        check("常量回滚成功", target.read_text(encoding="utf-8") == before)

    real = ROOT / "_test_out" / "x157"
    if real.exists():
        print("[9] 真实包扫描（X-提权者）")
        rr = cp.analyze(real)
        print("   ", rr.summary())
        check("扫到 100+ 文件", rr.files >= 100, str(rr.files))
        check("用时 < 10s", rr.elapsed < 10, f"{rr.elapsed:.1f}s")
        check("启动路径点都有链路",
              all(p.chain for p in rr.pre_run), "链缺失")
        check("无语法异常导致的空结果", len(rr.points) > 0)

    print()
    if FAILS:
        print(f"失败 {len(FAILS)} 项：" + "、".join(FAILS))
        return 1
    print("全部通过")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
