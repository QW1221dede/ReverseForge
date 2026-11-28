# -*- coding: utf-8 -*-
"""
 rf.fakepacket.capture · 抓包解析 CLI

 用法：
     python -m rf.fakepacket.capture rf_capture.log
     python -m rf.fakepacket.capture rf_capture.log --json
     python -m rf.fakepacket.capture rf_capture.log -o 结果.json

 出来什么：
     真实服务器地址、请求原文、响应原文、真签名、请求里的卡密字段
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from rf.fakepacket.hijack import parse_capture, render_capture


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m rf.fakepacket.capture",
        description="解析 rf_hook.so 录下的抓包文件")
    ap.add_argument("file", help="抓包文件路径（rf_capture.log）")
    ap.add_argument("--json", action="store_true", help="输出原始 JSON")
    ap.add_argument("-o", "--out", default="", help="同时把 JSON 写到指定文件")
    a = ap.parse_args(argv)

    rep = parse_capture(a.file)
    if a.json:
        print(json.dumps(rep, ensure_ascii=False, indent=2))
    else:
        print(render_capture(rep))

    if a.out:
        Path(a.out).write_text(json.dumps(rep, ensure_ascii=False, indent=2),
                               encoding="utf-8")
        print("\n已写出：" + a.out)
    return 0 if rep.get("ok") else 2


if __name__ == "__main__":
    sys.exit(main())
