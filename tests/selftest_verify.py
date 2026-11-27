#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
selftest_verify — ⑥ 安装 + 启动验证

只测不依赖真机的部分：包名解析、无设备降级、崩溃栈分类。
真机路径需要插手机，跑不了就如实跳过（不冒充通过）。
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rf.patch.engine import crash_hints, launch, package_of   # noqa: E402

OK = 0
BAD = 0


def chk(name: str, cond: bool, extra: str = "") -> None:
    global OK, BAD
    if cond:
        OK += 1
        print(f"  ✓ {name}")
    else:
        BAD += 1
        print(f"  ✗ {name} {extra}")


def _mk(manifest: str | None) -> Path:
    d = Path(tempfile.mkdtemp())
    if manifest is not None:
        (d / "AndroidManifest.xml").write_text(manifest, encoding="utf-8")
    return d


APKTOOL = ('<?xml version="1.0" encoding="utf-8"?>\n'
           '<manifest xmlns:android="http://schemas.android.com/apk/res/android"\n'
           '    package="com.ace.center" android:versionCode="20"\n'
           '    android:versionName="2.0">\n'
           '  <application android:label="ACE" />\n'
           '</manifest>\n')


def test_package() -> None:
    print("包名解析")
    chk("标准 apktool 清单", package_of(_mk(APKTOOL)) == "com.ace.center")
    chk("没有清单 → 空", package_of(_mk(None)) == "")
    chk("目录不存在 → 空", package_of(Path(tempfile.mkdtemp()) / "nope") == "")
    chk("platformBuildVersionName 不误取",
        package_of(_mk('<manifest package="a.b.c" '
                       'platformBuildVersionName="13"/>')) == "a.b.c")
    chk("带斜杠的脏值丢掉",
        package_of(_mk('<manifest package="com.x/y"/>')) == "")


def test_launch_nogear() -> None:
    print("无设备降级（不抛异常、不冒充成功）")
    r = launch("com.ace.center", wait=1)
    chk("ok=False", r["ok"] is False)
    chk("alive=False", r["alive"] is False)
    chk("有 msg 说明原因", bool(r["msg"]))
    chk("结构完整",
        set(r) >= {"ok", "started", "alive", "pid", "crash", "log", "msg"})
    chk("空包名不崩", launch("", wait=1)["ok"] is False)


def test_hint() -> None:
    print("崩溃栈 → 崩因分类")
    h1 = "\n".join(crash_hints(
        ["FATAL EXCEPTION: main",
         "java.lang.SecurityException: Signature check failed"], ""))
    chk("签名崩因命中", "签名" in h1, h1)
    h2 = "\n".join(crash_hints(["Fatal signal 11 (SIGSEGV), code 1"], ""))
    chk("原生层崩因命中", "原生层" in h2, h2)
    h3 = "\n".join(crash_hints(["java.lang.VerifyError: Rejecting class"], ""))
    chk("补丁自身崩因命中", "补丁自身" in h3, h3)
    h4 = "\n".join(crash_hints([], ""))
    chk("无栈时给兜底话术", "发我" in h4, h4)
    h5 = "\n".join(crash_hints(["java.lang.RuntimeException: x",
                                "MessageDigest digest mismatch"], ""))
    chk("完整性崩因命中", "完整性" in h5, h5)


if __name__ == "__main__":
    test_package()
    test_launch_nogear()
    test_hint()
    print("=" * 56)
    print(f"通过 {OK}｜失败 {BAD}")
    sys.exit(1 if BAD else 0)
