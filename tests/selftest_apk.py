#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
自检：拿一个真实 APK 跑完整拆解流水线，验证 apktool / jadx / dex 统计 / 报告全链路。

    python tests/selftest_apk.py <apk路径> [输出目录]
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import rf                                   # noqa: E402
from rf.analysis import apk as apkmod       # noqa: E402


def main() -> int:
    target = sys.argv[1] if len(sys.argv) > 1 else r"D:\android_tools\tmp\dfroot\X-提权者-1.57-赞赏版.apk"
    out = sys.argv[2] if len(sys.argv) > 2 else str(ROOT / "_test_out" / "apk1")

    rf.bootstrap()
    print(f"目标: {target}")
    print(f"输出: {out}\n")

    # 只把关键行进度的行打到控制台，完整日志流水进 result.log
    p = apkmod.ApkPipeline(target, out)

    def on_line(s: str) -> None:
        if s.startswith(("──", "✓", "✗", "⚠")):
            print(s, flush=True)

    p.on_line = on_line
    t0 = time.time()
    res = p.run()

    print("\n" + "=" * 68)
    print(f"耗时 {time.time() - t0:.1f}s")
    print(f"apktool 成功: {res.ok_apktool}    jadx 成功: {res.ok_jadx}")
    print(f"资源目录: {res.apktool_dir}")
    print(f"源码目录: {res.sources_dir}")
    if res.errors:
        print("\n错误:")
        for e in res.errors:
            print("  -", e)
    print("\n画像摘要:")
    print(p.manifest_summary())

    # 产物清点
    print("\n产物清点:")
    for sub in ("apktool", "jadx", "report"):
        d = Path(out) / sub
        if d.exists():
            n = sum(1 for _ in d.rglob("*") if _.is_file())
            print(f"  {sub:<8} {n} 个文件")
        else:
            print(f"  {sub:<8} 缺失")
    return 0 if (res.ok_apktool or res.ok_jadx) else 1


if __name__ == "__main__":
    raise SystemExit(main())
