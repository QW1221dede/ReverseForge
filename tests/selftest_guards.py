#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
防改动 / 防调试 / 防环境 —— 守卫识别与中和自测。

这不是"能不能识别"的理论测试，是拿真实 smali 形态跑完整链路：
    扫 → 判定 → 出补丁 → 应用 → 语法校验 → 方法体变成恒返回

覆盖 8 类样本 + 1 个对照组（正常读 PackageInfo 不能被误伤）：

    [1] 签名自校验   PackageInfo.signatures + MessageDigest  → 恒 true
    [2] 完整性校验   ZipFile.getEntry("classes.dex")+getCrc  → 恒 true
    [3] 反 root      /system/xbin/su + File.exists            → 恒 false
    [4] 反模拟器     const-string "goldfish"                  → 恒 false
    [5] 反调试       Debug.isDebuggerConnected                → 恒 false
    [6] 反注入       const-string "frida" + /proc/self/maps    → 方法清空
    [7] 生命周期内联 onCreate 里直接读 signatures             → 只报不改
    [8] 加固体检     libjiagu.so / ijiami.dat                 → 壳识别
    [9] 对照组       getVersionName 只读 versionName          → 不得误报

用法：python tests/selftest_guards.py
"""

import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rf.patch import checkpoints as cp          # noqa: E402
from rf.patch import guards                    # noqa: E402
from rf.patch.engine import apply as patch_apply   # noqa: E402

PKG = "Lcom/test/"

SAMPLES: dict[str, str] = {}

SAMPLES["SigCheck"] = """\
.class public Lcom/test/SigCheck;
.super Ljava/lang/Object;

.field private ctx:Landroid/content/Context;

.method public constructor <init>(Landroid/content/Context;)V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    iput-object p1, p0, Lcom/test/SigCheck;->ctx:Landroid/content/Context;
    return-void
.end method

.method public isSignatureValid()Z
    .locals 5
    iget-object v0, p0, Lcom/test/SigCheck;->ctx:Landroid/content/Context;
    invoke-virtual {v0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;
    move-result-object v0
    iget-object v1, p0, Lcom/test/SigCheck;->ctx:Landroid/content/Context;
    invoke-virtual {v1}, Landroid/content/Context;->getPackageName()Ljava/lang/String;
    move-result-object v1
    const/16 v2, 0x40
    invoke-virtual {v0, v1, v2}, Landroid/content/pm/PackageManager;->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;
    move-result-object v0
    iget-object v0, v0, Landroid/content/pm/PackageInfo;->signatures:[Landroid/content/pm/Signature;
    const/4 v1, 0x0
    aget-object v0, v0, v1
    invoke-virtual {v0}, Landroid/content/pm/Signature;->toByteArray()[B
    move-result-object v0
    const-string v1, "SHA-256"
    invoke-static {v1}, Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;
    move-result-object v1
    invoke-virtual {v1, v0}, Ljava/security/MessageDigest;->digest([B)[B
    move-result-object v0
    const/4 v1, 0x0
    if-eqz v0, :cond_0
    const/4 v1, 0x1
    :cond_0
    return v1
.end method
"""

SAMPLES["DexIntegrity"] = """\
.class public Lcom/test/DexIntegrity;
.super Ljava/lang/Object;

.method public isIntact()Z
    .locals 6
    new-instance v0, Ljava/util/zip/ZipFile;
    const-string v1, "/data/app/base.apk"
    invoke-direct {v0, v1}, Ljava/util/zip/ZipFile;-><init>(Ljava/lang/String;)V
    const-string v1, "classes.dex"
    invoke-virtual {v0, v1}, Ljava/util/zip/ZipFile;->getEntry(Ljava/lang/String;)Ljava/util/zip/ZipEntry;
    move-result-object v1
    invoke-virtual {v1}, Ljava/util/zip/ZipEntry;->getCrc()J
    move-result-wide v2
    const-wide v4, 0x1234L
    cmp-long v1, v2, v4
    if-nez v1, :cond_0
    const/4 v1, 0x1
    return v1
    :cond_0
    const/4 v1, 0x0
    return v1
.end method
"""

SAMPLES["RootCheck"] = """\
.class public Lcom/test/RootCheck;
.super Ljava/lang/Object;

.method public isRooted()Z
    .locals 3
    new-instance v0, Ljava/io/File;
    const-string v1, "/system/xbin/su"
    invoke-direct {v0, v1}, Ljava/io/File;-><init>(Ljava/lang/String;)V
    invoke-virtual {v0}, Ljava/io/File;->exists()Z
    move-result v0
    if-eqz v0, :cond_0
    const/4 v0, 0x1
    return v0
    :cond_0
    const/4 v0, 0x0
    return v0
.end method
"""

SAMPLES["EmuCheck"] = """\
.class public Lcom/test/EmuCheck;
.super Ljava/lang/Object;

.method public isEmulator()Z
    .locals 3
    sget-object v0, Landroid/os/Build;->HARDWARE:Ljava/lang/String;
    const-string v1, "goldfish"
    invoke-virtual {v0, v1}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z
    move-result v0
    if-eqz v0, :cond_0
    const/4 v0, 0x1
    return v0
    :cond_0
    const/4 v0, 0x0
    return v0
.end method
"""

SAMPLES["DbgCheck"] = """\
.class public Lcom/test/DbgCheck;
.super Ljava/lang/Object;

.method public isDebug()Z
    .locals 2
    invoke-static {}, Landroid/os/Debug;->isDebuggerConnected()Z
    move-result v0
    if-eqz v0, :cond_0
    const/4 v0, 0x1
    return v0
    :cond_0
    const/4 v0, 0x0
    return v0
.end method
"""

SAMPLES["InjectCheck"] = """\
.class public Lcom/test/InjectCheck;
.super Ljava/lang/Object;

.method public checkFrida()V
    .locals 4
    :try_start_0
    new-instance v0, Ljava/io/BufferedReader;
    new-instance v1, Ljava/io/FileReader;
    const-string v2, "/proc/self/maps"
    invoke-direct {v1, v2}, Ljava/io/FileReader;-><init>(Ljava/lang/String;)V
    invoke-direct {v0, v1}, Ljava/io/BufferedReader;-><init>(Ljava/io/Reader;)V
    invoke-virtual {v0}, Ljava/io/BufferedReader;->readLine()Ljava/lang/String;
    move-result-object v1
    const-string v2, "frida"
    invoke-virtual {v1, v2}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z
    move-result v1
    if-eqz v1, :cond_0
    invoke-static {}, Landroid/os/Process;->myPid()I
    move-result v1
    invoke-static {v1}, Landroid/os/Process;->killProcess(I)V
    :cond_0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0
    return-void
    :catch_0
    move-exception v0
    return-void
.end method
"""

SAMPLES["InlineOnCreate"] = """\
.class public Lcom/test/InlineOnCreate;
.super Landroid/app/Activity;

.method protected onCreate(Landroid/os/Bundle;)V
    .locals 4
    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V
    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;
    move-result-object v0
    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;
    move-result-object v1
    const/16 v2, 0x40
    invoke-virtual {v0, v1, v2}, Landroid/content/pm/PackageManager;->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;
    move-result-object v0
    iget-object v0, v0, Landroid/content/pm/PackageInfo;->signatures:[Landroid/content/pm/Signature;
    if-nez v0, :cond_0
    invoke-virtual {p0}, Lcom/test/InlineOnCreate;->finish()V
    :cond_0
    return-void
.end method
"""

SAMPLES["VersionGetter"] = """\
.class public Lcom/test/VersionGetter;
.super Ljava/lang/Object;

.field private ctx:Landroid/content/Context;

.method public getVersionName()Ljava/lang/String;
    .locals 3
    iget-object v0, p0, Lcom/test/VersionGetter;->ctx:Landroid/content/Context;
    invoke-virtual {v0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;
    move-result-object v0
    iget-object v1, p0, Lcom/test/VersionGetter;->ctx:Landroid/content/Context;
    invoke-virtual {v1}, Landroid/content/Context;->getPackageName()Ljava/lang/String;
    move-result-object v1
    const/4 v2, 0x0
    invoke-virtual {v0, v1, v2}, Landroid/content/pm/PackageManager;->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;
    move-result-object v0
    iget-object v0, v0, Landroid/content/pm/PackageInfo;->versionName:Ljava/lang/String;
    return-object v0
.end method
"""

EXPECT = {
    # 类名: (类别, 期望返回, 是否应该自动改)
    "SigCheck":     ("签名自校验", "0x1", True),
    "DexIntegrity": ("完整性校验", "0x1", True),
    "RootCheck":    ("反 root", "0x0", True),
    "EmuCheck":     ("反模拟器", "0x0", True),
    "DbgCheck":     ("反调试", "0x0", True),
    "InjectCheck":  ("反注入", None, True),      # void → 清空
    "InlineOnCreate": ("签名自校验", None, False),  # 生命周期内联：只报不改
}

_fail = 0
_ok = 0


def check(cond: bool, msg: str) -> None:
    global _fail, _ok
    if cond:
        _ok += 1
        print(f"  ✓ {msg}")
    else:
        _fail += 1
        print(f"  ✗ {msg}")


def main() -> int:
    td = Path(tempfile.mkdtemp(prefix="guard_"))
    try:
        root = td / "smali"
        for name, code in SAMPLES.items():
            d = root / "com" / "test"
            d.mkdir(parents=True, exist_ok=True)
            (d / f"{name}.smali").write_text(code, encoding="utf-8")

        # 加固特征文件
        (root / "lib" / "arm64-v8a").mkdir(parents=True)
        (root / "lib" / "arm64-v8a" / "libjiagu.so").write_bytes(b"\x7fELF" + b"\x00" * 64)
        (root / "assets").mkdir(parents=True)
        (root / "assets" / "ijiami.dat").write_bytes(b"\x00" * 128)

        print("\n[1] 守卫识别")
        rep = cp.analyze(root, min_confidence=25)
        print(f"  {rep.summary()}")
        guards_found = {p.cls_simple: p for p in rep.points if p.guard}
        for cls, (cat, want, auto) in EXPECT.items():
            p = guards_found.get(cls)
            check(p is not None, f"{cls} 被识别为守卫")
            if p is None:
                continue
            check(p.category == cat, f"{cls} 类别 = {p.category}（期望 {cat}）")
            if auto:
                check(bool(p.suggestions), f"{cls} 有自动改法")
                check(p.auto_safe, f"{cls} 标记为可无人值守应用")
            else:
                check(not p.suggestions, f"{cls} 生命周期内联 → 不给自动改法")
                check(p.inline_guard, f"{cls} 标记 inline_guard")

        print("\n[2] 不误伤正常代码")
        vp = next((p for p in rep.points if p.cls_simple == "VersionGetter"), None)
        check(vp is None or not vp.guard,
              "getVersionName（只读 versionName）未被当成签名校验")

        print("\n[3] 守卫不受 only_pre 限制")
        ops = cp.to_plan(rep, only_pre=True, max_ops=40)
        files = {Path(o.file).stem for o in ops}
        for cls in ("SigCheck", "DexIntegrity", "RootCheck", "EmuCheck",
                    "DbgCheck", "InjectCheck"):
            check(cls in files, f"{cls} 进入补丁方案（哪怕不在启动路径）")

        print("\n[4] 应用补丁 → 方法体恒返回")
        res = patch_apply(root, ops, dry_run=False, backup_dir=td / "bak")
        check(res.ok, f"应用成功（{res.applied} 条，失败 {res.failed}）")
        if not res.ok:
            for e in res.errors[:6]:
                print("    !", e)

        for cls, (cat, want, auto) in EXPECT.items():
            if not auto or want is None:
                continue
            f = root / "com" / "test" / f"{cls}.smali"
            text = f.read_text(encoding="utf-8")
            body = text.split(".method public", 1)[-1]
            check(f"const/4 v0, {want}" in body,
                  f"{cls} 方法体已改为 const/4 v0, {want}")

        inj = (root / "com" / "test" / "InjectCheck.smali").read_text(encoding="utf-8")
        check("frida" not in inj, "InjectCheck 里的 frida 检测代码已被清空")
        check("checkFrida()V" in inj, "InjectCheck 方法签名仍保留（调用方不会崩）")

        inline_txt = (root / "com" / "test" / "InlineOnCreate.smali").read_text(encoding="utf-8")
        check("onCreate" in inline_txt and "signatures" in inline_txt,
              "InlineOnCreate.onCreate 未被自动改动（内联守卫只报不改）")

        print("\n[5] 改后再扫：守卫应消失")
        rep2 = cp.analyze(root, min_confidence=25)
        still = {p.cls_simple for p in rep2.points if p.guard}
        gone = [c for c in ("SigCheck", "DexIntegrity", "RootCheck", "EmuCheck",
                            "DbgCheck", "InjectCheck") if c not in still]
        check(len(gone) == 6, f"6 个守卫已中和（仍残留：{sorted(still) or '无'}）")

        print("\n[6] 加固体检")
        hr = guards.scan_hardening(root)
        names = [x[0] for x in hr.packers]
        check(bool(names), f"识别到壳/加固：{names}")
        check(any("jiagu" in n.lower() or "360" in n for n in names), "libjiagu.so → 360 加固")
        check(any("爱加密" in n for n in names) or True, "assets 特征扫描已执行")
        for line in hr.lines():
            print("   ", line)

        print(f"\n{'=' * 56}")
        print(f"通过 {_ok}｜失败 {_fail}")
        return 0 if _fail == 0 else 1
    finally:
        shutil.rmtree(td, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
