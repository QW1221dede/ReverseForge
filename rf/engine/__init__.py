#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rf.engine · 引擎层（脚本运行时 / 流水线 / 任务）。

注意：这里刻意不 import script_runtime 的子模块内容。
    因为 `python -m rf.engine.script_runtime` 会先执行本 __init__，
    若在此处导入同名模块会触发 runpy 的 RuntimeWarning。
    需要 ScriptRun 的地方直接 `from rf.engine.script_runtime import ScriptRun`。
"""

from __future__ import annotations

__all__ = ["script_runtime"]
