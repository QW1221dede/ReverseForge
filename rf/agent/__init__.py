#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 rf.agent · 指令层（自然语言 → 计划 → 调用工具）
============================================================================

    from rf.agent import orchestrator as ag
    plan = ag.make_plan("这几个文件能解密吗", ["a.bin"])
    out  = ag.run(plan, ["a.bin"], on_event=print)

默认用规则引擎（离线、零延迟、可复现）；
在 settings.json 里配了 llm.base_url / api_key / model 才会走模型规划。
============================================================================
"""

from . import orchestrator

__all__ = ["orchestrator"]
