#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ReverseForge · 逆锻台
=====================
桌面端逆向工作台核心包。

    import rf
    rf.registry()                      # 工具注册表
    rf.config.load_settings()          # 用户配置
    rf.tools.runner.run([...])         # 统一执行器

外部脚本一般不需要 import 这个包 —— 脚本运行时会把门面对象 `rf` 直接注进
脚本全局命名空间，写法见 scripts/ 下的示例。
"""

from __future__ import annotations

__version__ = "1.0.1"
__all__ = ["config", "tools", "registry", "runner"]

from . import config                       # noqa: E402
from .tools import runner                  # noqa: E402
from .tools.registry import registry, REGISTRY   # noqa: E402


def bootstrap() -> None:
    """进程启动时调用一次：建目录、探工具。"""
    config.ensure_dirs()
    REGISTRY.build()
