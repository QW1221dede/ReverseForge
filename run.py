#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 ReverseForge · 逆锻台   启动入口
============================================================================

    python run.py                启动图形界面
    python run.py --tools        只打印工具链状态（排障用）
    python run.py --script X.py  不开界面，命令行跑脚本
    python run.py --selfcheck    环境自检（工具 + 目录 + 依赖）
============================================================================
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

# 窗口版 exe 里 sys.stdout 可能是 None，任何 print 都会炸。
# 在导入其它模块之前先兜住。
if sys.stdout is None:
    sys.stdout = open(os.devnull, "w", encoding="utf-8")     # noqa: SIM115
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w", encoding="utf-8")     # noqa: SIM115

ROOT = Path(__file__).resolve().parent
if getattr(sys, "frozen", False):
    # 打包后：资源在 sys._MEIPASS，代码在 exe 同目录
    ROOT = Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def cmd_tools() -> int:
    import rf
    rf.bootstrap()
    reg = rf.registry()
    print(reg.summary())
    print("-" * 78)
    for d in reg.status():
        mark = "OK  " if d["available"] else "MISS"
        print(f"[{mark}] {d['id']:<10} {d['category']:<8} {d['version'][:40]:<42} {d['path']}")
    print("-" * 78)
    miss = reg.missing_required()
    if miss:
        print("缺必需工具：", "、".join(miss))
        return 1
    return 0


def cmd_selfcheck() -> int:
    import rf
    from rf import config

    print(f"Python  {sys.version.split()[0]}  ({sys.executable})")
    print(f"程序根  {config.APP_ROOT}")
    print(f"用户目录 {config.USER_ROOT}")
    config.ensure_dirs()
    ok = True
    for name, p in (("工作区", config.WORKSPACE_ROOT), ("日志", config.LOG_ROOT),
                    ("用户脚本", config.SCRIPT_ROOT)):
        exists = p.exists()
        ok &= exists
        print(f"{'✓' if exists else '✗'} {name:<8} {p}")

    scripts = list(config.BUILTIN_SCRIPT_ROOT.glob("*.py")) if config.BUILTIN_SCRIPT_ROOT.exists() else []
    print(f"{'✓' if scripts else '✗'} 内置脚本 {len(scripts)} 个：{config.BUILTIN_SCRIPT_ROOT}")

    print("\n工具链：")
    rc = cmd_tools()

    print("\nGUI 依赖：")
    try:
        import tkinter
        print("✓ tkinter", tkinter.TkVersion)
    except Exception as e:
        print("✗ tkinter", e)
        ok = False
    print("\n新增能力：")
    try:
        from rf.snippets import get_library
        st = get_library().stats()
        print(f"✓ 代码积木 {st['total']} 块（语法异常 {st['invalid']}）")
        if st["invalid"]:
            ok = False
    except Exception as e:
        print("✗ 积木库", e)
        ok = False
    try:
        from rf.secure import crypto
        prof = crypto.profile()
        print(f"✓ 加密 AES-GCM={prof['aes_gcm']} 来源={prof['source']}")
    except Exception as e:
        print("✗ 加密模块", e)
        ok = False
    try:
        from rf.patch import checkpoints, engine  # noqa: F401
        print("✓ 校验点识别 / 补丁引擎")
    except Exception as e:
        print("✗ 补丁模块", e)
        ok = False
    try:
        from rf.analysis import authscan, filetype, garble, segments  # noqa: F401
        # 真跑一遍，确认不是空壳。用 sys.executable：打包后 __file__ 在
        # 临时解包目录里，可能根本不存在
        target = sys.executable or __file__
        k = filetype.sniff(target)
        print(f"✓ 任意文件识别（判为 {k.label}）")
        _ = segments.analyze(b"key=abc\n" + bytes(range(256)) * 40)
        print("✓ 明暗分段 / 乱码判定")
    except Exception as e:
        print("✗ 任意文件模块", e)
        ok = False
    try:
        from rf.decrypt import auto, ciphers, keys  # noqa: F401
        prof = ciphers.profile()
        print(f"✓ 解密层（AES={prof['aes']} 来源={prof['source']}）")
        r = auto.salvage(ciphers.xor_single(b'{"ok":true,"card":"123456"}', 0x5A),
                         budget=6)
        print(f"✓ 自动试解（单字节 XOR 命中：{bool(r.hits)}）")
        if not r.hits:
            ok = False
    except Exception as e:
        print("✗ 解密层", e)
        ok = False
    try:
        from rf.engine.repl import Repl
        rp = Repl(timeout=12)
        rp.start()
        out = rp.run("print(6*7)").out.strip()
        rp.stop()
        print(f"✓ 代码终端（6*7={out or '无输出'}）")
        if out != "42":
            ok = False
    except Exception as e:
        print("✗ 代码终端", e)
        ok = False
    try:
        from rf.agent import orchestrator as ag
        p = ag.plan("这几个文件能解密吗", ["x"])
        print(f"✓ 指令编排（{p.intent_cn} · {len(p.steps)} 步）")
    except Exception as e:
        print("✗ 指令编排", e)
        ok = False
    try:
        from rf.server import ApiServer, TOOLS
        srv = ApiServer(port=8781).start()
        import urllib.request
        with urllib.request.urlopen(f"http://127.0.0.1:{srv.port}/health",
                                    timeout=5) as r:
            up = b'"ok": true' in r.read()
        srv.stop()
        print(f"✓ 本地 API（{len(TOOLS)} 个工具，健康检查 {'通过' if up else '失败'}）")
        if not up:
            ok = False
    except Exception as e:
        print("✗ 本地 API", e)
        ok = False
    try:
        import tkinterdnd2  # noqa: F401
        print("✓ 拖拽组件（tkinterdnd2）")
    except Exception as e:
        print("· 拖拽组件不可用（不影响其它功能）：", e)
    return 0 if (ok and rc == 0) else 1


def cmd_api(allow_write: bool = False, port: int = 8765) -> int:
    """
    无界面启动本地 API，让 AI/外部脚本直接调用。
    只监听 127.0.0.1，带 token，写操作默认关闭。
    """
    from rf import config
    from rf.server import ApiServer

    config.ensure_dirs()
    srv = ApiServer(port=port, allow_write=allow_write).start()
    print("=" * 62)
    print(" ReverseForge 本地 API 已启动")
    print("=" * 62)
    print(f"  地址   ：http://127.0.0.1:{srv.port}/")
    print(f"  token  ：{srv.token}")
    print(f"  写操作 ：{'已开放（小心）' if allow_write else '已禁用'}")
    print(f"  清单   ：GET /tools")
    print(f"  调用   ：POST /call    {{\"tool\":\"file_type\",\"args\":{{...}}}}")
    print(f"  一句话 ：POST /analyze {{\"paths\":[...],\"task\":\"...\"}}")
    print(f"  token 文件：{config.USER_ROOT / 'api_token.txt'}")
    print("=" * 62)
    print(" Ctrl+C 停止")
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n正在停止 …")
    finally:
        srv.stop()
    return 0


def main() -> int:
    argv = sys.argv[1:]

    # 窗口版 exe 没有控制台：用环境变量把自检结果写到文件，便于排障
    if os.environ.get("RF_SELFCHECK"):
        out = Path(os.environ.get("RF_SELFCHECK_FILE")
                   or (Path(os.environ.get("TEMP", ".")) / "rf_selfcheck.txt"))
        with open(out, "w", encoding="utf-8") as f:
            sys.stdout = f
            sys.stderr = f
            try:
                rc = cmd_selfcheck()
            except Exception as e:
                print("自检异常：", e)
                rc = 1
            f.flush()
        return rc

    if "--tools" in argv:
        return cmd_tools()
    if "--selfcheck" in argv:
        return cmd_selfcheck()
    if "--script" in argv:
        i = argv.index("--script")
        rest = argv[i + 1:]
        if not rest:
            print("用法：python run.py --script <脚本> [k=v ...]")
            return 2
        from rf.engine.script_runtime import run_cli
        return run_cli(rest[0], rest[1:])

    # 无界面起本地 API：给 AI / 外部脚本调用
    if "--api" in argv:
        return cmd_api(allow_write="--api-write" in argv)

    from rf.ui.app import App
    app = App()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
