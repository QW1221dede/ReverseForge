#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
"检测到就不让跑" —— 终结动作摘除自测。

核心命题：检测手法可以千变万化，但"不让程序跑"这个结果只有那么几条路。
所以除了把检测改成恒返回"通过"，还要把终结动作本身摘掉。

样本（都是真实外挂/加固包里见过的写法）：

    [1] AntiTamper   签名不符 → System.exit(0)          守卫上下文，两层都该中和
    [2] RootGuard    检测到 su → killProcess(myPid)     守卫上下文
    [3] Killer       包装函数 Utils.kill() → System.exit  无检测特征，靠兜底层摘
    [4] DeepKill     三层包装 a→b→c 最后 killProcess     验证"套多少层都没用"
    [5] Crash$H      uncaughtException 里 killProcess     正常善后，必须跳过
    [6] Splash       onCreate 里 finish()                 生命周期内联，不自动改
    [7] Toast       正常业务的 System.exit（退出按钮）      默认也摘，但要能计数
    [8] Hang         while(true) / sleep(Long.MAX)        只报不改，进 Frida 脚本

验收：
    · exit / killProcess 调用点 100% 被换成 nop（除崩溃处理器）
    · 应用后语法通过
    · 崩溃处理器原样保留
    · finish / throw / hang 只报告不硬改

用法：python tests/selftest_terminators.py
"""

import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rf.patch import checkpoints as cp          # noqa: E402
from rf.patch import guards                    # noqa: E402
from rf.patch.engine import apply as patch_apply   # noqa: E402

_ok = _fail = 0


def check(cond, msg: str) -> None:
    global _ok, _fail
    if cond:
        _ok += 1
        print(f"  ✓ {msg}")
    else:
        _fail += 1
        print(f"  ✗ {msg}")


SAMPLES: dict[str, str] = {}

# ---------------------------------------------------------------------------
SAMPLES["AntiTamper"] = """\
.class public Lcom/test/AntiTamper;
.super Ljava/lang/Object;

.field private ctx:Landroid/content/Context;

.method public constructor <init>(Landroid/content/Context;)V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    iput-object p1, p0, Lcom/test/AntiTamper;->ctx:Landroid/content/Context;
    return-void
.end method

.method public check()V
    .locals 4
    iget-object v0, p0, Lcom/test/AntiTamper;->ctx:Landroid/content/Context;
    invoke-virtual {v0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;
    move-result-object v0
    iget-object v1, p0, Lcom/test/AntiTamper;->ctx:Landroid/content/Context;
    invoke-virtual {v1}, Landroid/content/Context;->getPackageName()Ljava/lang/String;
    move-result-object v1
    const/16 v2, 0x40
    invoke-virtual {v0, v1, v2}, Landroid/content/pm/PackageManager;->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;
    move-result-object v0
    iget-object v0, v0, Landroid/content/pm/PackageInfo;->signatures:[Landroid/content/pm/Signature;
    const/4 v1, 0x0
    aget-object v0, v0, v1
    invoke-virtual {v0}, Landroid/content/pm/Signature;->toCharsString()Ljava/lang/String;
    move-result-object v0
    const-string v1, "3082010a02820101"
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
    move-result v0
    if-nez v0, :pass
    const/4 v0, 0x0
    invoke-static {v0}, Ljava/lang/System;->exit(I)V
    return-void
    :pass
    return-void
.end method
"""

SAMPLES["RootGuard"] = """\
.class public Lcom/test/RootGuard;
.super Ljava/lang/Object;

.method public static checkRoot()V
    .locals 2
    new-instance v0, Ljava/io/File;
    const-string v1, "/system/xbin/su"
    invoke-direct {v0, v1}, Ljava/io/File;-><init>(Ljava/lang/String;)V
    invoke-virtual {v0}, Ljava/io/File;->exists()Z
    move-result v0
    if-eqz v0, :done
    invoke-static {}, Landroid/os/Process;->myPid()I
    move-result v0
    invoke-static {v0}, Landroid/os/Process;->killProcess(I)V
    :done
    return-void
.end method
"""

# 无任何检测特征的普通包装函数 —— 兜底层必须也能摘
SAMPLES["Killer"] = """\
.class public Lcom/test/Killer;
.super Ljava/lang/Object;

.method public static bye()V
    .locals 1
    const/4 v0, 0x0
    invoke-static {v0}, Ljava/lang/System;->exit(I)V
    return-void
.end method
"""

# 三层包装：a 调 b，b 调 c，c 才真的杀
SAMPLES["DeepA"] = """\
.class public Lcom/test/DeepA;
.super Ljava/lang/Object;

.method public static run()V
    .locals 0
    invoke-static {}, Lcom/test/DeepB;->go()V
    return-void
.end method
"""

SAMPLES["DeepB"] = """\
.class public Lcom/test/DeepB;
.super Ljava/lang/Object;

.method public static go()V
    .locals 0
    invoke-static {}, Lcom/test/DeepC;->now()V
    return-void
.end method
"""

SAMPLES["DeepC"] = """\
.class public Lcom/test/DeepC;
.super Ljava/lang/Object;

.method public static now()V
    .locals 2
    invoke-static {}, Landroid/os/Process;->myPid()I
    move-result v0
    invoke-static {v0}, Landroid/os/Process;->killProcess(I)V
    return-void
.end method
"""

# 崩溃处理器：正常善后，不能摘
SAMPLES["Crash$H"] = """\
.class public Lcom/test/Crash$H;
.super Ljava/lang/Object;
.implements Ljava/lang/Thread$UncaughtExceptionHandler;

.method public uncaughtException(Ljava/lang/Thread;Ljava/lang/Throwable;)V
    .locals 1
    invoke-static {}, Landroid/os/Process;->myPid()I
    move-result v0
    invoke-static {v0}, Landroid/os/Process;->killProcess(I)V
    return-void
.end method
"""

# 生命周期内联 finish：不自动改（改了就白屏）
SAMPLES["Splash"] = """\
.class public Lcom/test/Splash;
.super Landroid/app/Activity;

.method protected onCreate(Landroid/os/Bundle;)V
    .locals 3
    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V
    invoke-virtual {p0}, Lcom/test/Splash;->getPackageName()Ljava/lang/String;
    move-result-object v0
    const-string v1, "com.orig.pkg"
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
    move-result v0
    if-nez v0, :go
    const/4 v0, 0x0
    invoke-static {v0}, Ljava/lang/System;->exit(I)V
    invoke-virtual {p0}, Lcom/test/Splash;->finish()V
    :go
    return-void
.end method
"""

# 正常业务的退出按钮（无检测特征）
SAMPLES["QuitBtn"] = """\
.class public Lcom/test/QuitBtn;
.super Landroid/app/Activity;

.method public onQuitClick(Landroid/view/View;)V
    .locals 1
    const/4 v0, 0x0
    invoke-static {v0}, Ljava/lang/System;->exit(I)V
    return-void
.end method
"""

# 静默挂起：不崩不退，白屏装死
SAMPLES["Hang"] = """\
.class public Lcom/test/Hang;
.super Ljava/lang/Object;

.method public static stall()V
    .locals 3
    const-wide v0, 0x7fffffffffffffffL
    invoke-static {v0, v1}, Ljava/lang/Thread;->sleep(J)V
    return-void
.end method
"""


def _write(root: Path) -> None:
    d = root / "com" / "test"
    d.mkdir(parents=True, exist_ok=True)
    for name, code in SAMPLES.items():
        (d / f"{name}.smali").write_text(code, encoding="utf-8")


def main() -> int:
    td = Path(tempfile.mkdtemp(prefix="rfterm_"))
    try:
        root = td / "smali"
        _write(root)

        print("[1] 终结动作识别")
        hits = {}
        for f in (root / "com" / "test").glob("*.smali"):
            methods, *_ = cp._parse_file(f)
            for m in methods:
                body = [t for _, t in m.body]
                g = bool(guards.scan_method("\n".join(body), " ".join(m.calls), m.strings))
                for t in guards.find_terminators(body, guarded=g):
                    hits.setdefault(f.stem, []).append((t.kind, t.nop_safe, g))
        check("exit_proc" in [k for v in hits.values() for k, _, _ in v],
              f"识别到进程自杀：{sorted({k for v in hits.values() for k, _, _ in v})}")
        check("kill_self" in [k for v in hits.values() for k, _, _ in v], "识别到强杀进程")
        _hm, *_ = cp._parse_file(root / "com" / "test" / "Hang.smali")
        _hbody = [t for _, t in _hm[0].body]
        check(any(t.kind == "hang" for t in guards.find_terminators(_hbody, guarded=True)),
              "静默挂起在守卫上下文里被认出")
        check(not guards.find_terminators(_hbody, guarded=False),
              "无守卫特征时不乱认 sleep（正常延时不受影响）")
        check(len(hits.get("RootGuard", [])) >= 1, "RootGuard 里的 killProcess 被认出")
        check(all(not safe for k, safe, _ in hits.get("Splash", [])
                  if k in ("finish_kill", "throw_fatal")),
              "Splash 的 finish/exit 标为不可直接 nop（生命周期）")

        print("\n[2] 兜底摘除（不看是不是校验点）")
        ops, stat = cp.plan_terminators(root)
        print("    统计：", stat)
        files = {Path(o.file).stem for o in ops}
        check(stat["applied"] >= 6, f"生成 {stat['applied']} 条摘除补丁")
        check("AntiTamper" in files, "守卫里的 exit 被摘（AntiTamper）")
        check("RootGuard" in files, "守卫里的 kill 被摘（RootGuard）")
        check("Killer" in files, "无检测特征的包装函数也被摘（Killer）")
        check("DeepC" in files, "三层包装最底层被摘（DeepC）")
        check("QuitBtn" in files, "退出按钮的 exit 也摘（默认彻底，可关）")
        check("Crash$H" not in files, "崩溃处理器跳过（不敢动正常善后）")
        check(stat["skipped_crash_handler"] == 1, "崩溃处理器计数为 1")

        print("\n[3] 应用补丁 + 语法校验")
        res = patch_apply(root, ops, backup_dir=td / "bak")
        check(res.ok, f"应用结果：{res.text().splitlines()[0] if res.text() else res.ok}")
        if not res.ok:
            for e in res.errors[:4]:
                print("      !", e)

        for stem, want_gone in (("AntiTamper", "Ljava/lang/System;->exit"),
                                ("RootGuard", "killProcess"),
                                ("Killer", "Ljava/lang/System;->exit"),
                                ("DeepC", "killProcess")):
            txt = (root / "com" / "test" / f"{stem}.smali").read_text(encoding="utf-8")
            check(want_gone not in txt, f"{stem} 的 {want_gone.split('->')[-1]} 已摘除")
            check("nop" in txt, f"{stem} 出现 nop 占位")

        crash = (root / "com" / "test" / "Crash$H.smali").read_text(encoding="utf-8")
        check("killProcess" in crash, "崩溃处理器的 killProcess 原样保留")

        splash = (root / "com" / "test" / "Splash.smali").read_text(encoding="utf-8")
        check("System;->exit" not in splash and "Activity;->finish" not in splash,
              "生命周期内联的 exit/finish 也被摘（摘调用不动方法结构，界面照样起）")
        check("onCreate" in splash and "invoke-super" in splash,
              "onCreate 骨架完整保留（没被整段清空）")

        hang = (root / "com" / "test" / "Hang.smali").read_text(encoding="utf-8")
        check("Thread;->sleep" in hang, "静默挂起未硬改（交 Frida）")

        print("\n[4] keep_exit 开关")
        _write(root)                                   # 复原
        ops2, stat2 = cp.plan_terminators(root, keep_exit=True)
        check(stat2["applied"] == 0, f"keep_exit=True 时不动 exit/kill（{stat2['applied']} 条）")

        print("\n[5] 两层同时生效（判定 + 处置）")
        _write(root)
        rep = cp.analyze(root, min_confidence=25)
        gpts = [p for p in rep.points if p.guard]
        check(bool(gpts), f"守卫仍被识别 {len(gpts)} 个（改判定那层不受影响）")
        ops3 = cp.to_plan(rep, only_pre=True, max_ops=40)
        term3, _ = cp.plan_terminators(root)
        both = ops3 + term3
        files3 = {Path(o.file).stem for o in both}
        check("AntiTamper" in files3 and "RootGuard" in files3,
              "同一个类既改判定又摘终结动作（双保险）")

        print(f"\n{'=' * 56}")
        print(f"通过 {_ok}｜失败 {_fail}")
        return 0 if _fail == 0 else 1
    finally:
        shutil.rmtree(td, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
