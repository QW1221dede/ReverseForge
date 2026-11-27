#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 tests/build_sample_apk.py · 造一个带卡密校验的测试 APK
============================================================================

为什么不用真实应用做回归？
    真实应用不能反复改、也不能保证"改完应该是什么行为"。
    这个小样本的校验逻辑是我们自己写的，所以能精确断言：
        · 识别器必须找到 LicenseManager.verify
        · 必须标记为启动路径（App.onCreate / MainActivity.onCreate 都调它）
        · 补丁后必须返回 true，且重建包能验签

构建链（全部用本机已有工具，不引入 Gradle）：
    javac → d8 → aapt2 link → 塞 classes.dex → zipalign → apksigner
============================================================================
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from rf import config                     # noqa: E402
from rf.tools import runner               # noqa: E402
from rf.tools.registry import registry    # noqa: E402

SDK = Path("D:/android_tools/sdk")
JAR = next(iter(sorted((SDK / "platforms").glob("*/android.jar"))), None)
BUILD_TOOLS = SDK / "build-tools"
APK_OUT = ROOT / "_test_out" / "sample_license.apk"


def _bt(name: str) -> Path:
    for d in sorted(BUILD_TOOLS.iterdir(), reverse=True):
        for ext in (".exe", ".bat", ""):
            p = d / (name + ext)
            if p.exists():
                return p
    raise FileNotFoundError(f"build-tools 里找不到 {name}")


def build() -> Path:
    if JAR is None:
        raise SystemExit("没有 android.jar，先装 Android SDK platform")
    java_home = config.find_java()
    if not java_home:
        raise SystemExit("没有 JDK")
    javac = Path(java_home) / "bin" / "javac.exe"
    if not javac.exists():
        javac = Path(java_home) / "bin" / "javac"
    if not javac.exists():
        raise SystemExit(f"JDK 里找不到 javac：{java_home}")
    env = {"JAVA_HOME": str(java_home)}

    work = ROOT / "_test_out" / "sample_build"
    if work.exists():
        shutil.rmtree(work)
    (work / "classes").mkdir(parents=True)
    (work / "dex").mkdir()

    src = ROOT / "tests" / "sample_app"
    files = [str(p) for p in (src / "src").rglob("*.java")]
    print(f"[1/6] javac {len(files)} 个源文件")
    r = runner.run([str(javac), "-source", "8", "-target", "8", "-encoding", "UTF-8",
                    "-bootclasspath", str(JAR), "-d", str(work / "classes")] + files,
                   timeout=180, env_extra=env)
    if not r.ok:
        raise SystemExit("javac 失败：\n" + r.tail(12))

    print("[2/6] d8 → classes.dex")
    class_files = [str(p) for p in (work / "classes").rglob("*.class")]
    r = runner.run([str(_bt("d8")), "--lib", str(JAR), "--min-api", "21",
                    "--output", str(work / "dex")] + class_files, timeout=180,
                   env_extra=env)
    if not r.ok:
        raise SystemExit("d8 失败：\n" + r.tail(12))

    print("[3/6] aapt2 compile + link → base.apk")
    manifest = src / "AndroidManifest.xml"
    base = work / "base.apk"
    res_zip = work / "res.zip"
    r = runner.run([str(_bt("aapt2")), "compile", "--dir", str(src / "res"),
                    "-o", str(res_zip)], timeout=180)
    if not r.ok:
        raise SystemExit("aapt2 compile 失败：\n" + r.tail(12))
    r = runner.run([str(_bt("aapt2")), "link", "-o", str(base), "-I", str(JAR),
                    "--manifest", str(manifest), "--min-sdk-version", "21",
                    "--target-sdk-version", "35", "--version-code", "1",
                    "--version-name", "1.0", str(res_zip)], timeout=180)
    if not r.ok:
        raise SystemExit("aapt2 失败：\n" + r.tail(12))

    print("[4/6] 塞入 classes.dex")
    dex = work / "dex" / "classes.dex"
    with zipfile.ZipFile(base, "a", zipfile.ZIP_DEFLATED) as z:
        z.write(dex, "classes.dex")

    print("[5/6] zipalign")
    aligned = work / "aligned.apk"
    r = runner.run([str(_bt("zipalign")), "-f", "-p", "4", str(base), str(aligned)],
                   timeout=120)
    if not r.ok:
        print("  对齐失败，跳过：", r.tail(2))
        shutil.copy2(base, aligned)

    print("[6/6] apksigner（调试证书）")
    from rf.patch.engine import ensure_keystore
    ks = ensure_keystore()
    APK_OUT.parent.mkdir(parents=True, exist_ok=True)
    r = runner.run([str(_bt("apksigner")), "sign", "--ks", str(ks),
                    "--ks-pass", "pass:android", "--key-pass", "pass:android",
                    "--ks-key-alias", "rfdebug", "--out", str(APK_OUT), str(aligned)],
                   timeout=180)
    if not r.ok:
        raise SystemExit("apksigner 失败：\n" + r.tail(12))
    print(f"✓ 样本 APK：{APK_OUT} ({APK_OUT.stat().st_size / 1024:.0f} KB)")
    return APK_OUT


if __name__ == "__main__":
    registry().build()
    build()
