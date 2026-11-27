#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rf.patch · 校验点识别与补丁

  checkpoints  精确识别启动前校验（证据 / 置信度 / 补丁建议）
  smali        指令级补丁（分支、返回值、方法体短路）
  engine       事务化应用：备份 → 改 → 校验 → 重建 → 回滚
"""

from . import checkpoints, engine, smali

__all__ = ["checkpoints", "engine", "smali"]
