#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 rf.fakepacket · 假包层（把解密出来的片段串成线索 → 推导怎么发 → 造包）
============================================================================

和 rf.decrypt 是同一套方法论：

    解密：候选密钥/偏移 → 试解 → 打分 → 排序 → 报告 → 落盘
    假包：明文片段/字段 → 提线索 → 判协议 → 打分 → 报告 → 造包

模块分工：
    clues     —— 从任意文件/解包目录里捞协议线索（URL、字段名、成功标志、
                 卡密路径、心跳、状态码、签名方式、时序），每条带证据偏移
    protocol  —— 线索链判定协议类型（T3 卡密 / 通用 HTTP 状态 / 本地缓存…），
                 推导「发到哪里、发什么字段、什么时候发、怎么算成功」
    builder   —— 按判定的协议造三种假包：
                 ① 请求假包（发给服务器，骗它当成合法验证）
                 ② 响应假包（本地伪造服务器回包，骗客户端）
                 ③ 时序脚本（启动时发 / 心跳定期发）
    replay    —— 发假包 → 从响应抓真签名 → 回填 → 用真签名重发
    live      —— 真机收割：内卡密注入 → 程序真发包 → frida 抓设备现算的签名
                 （签名在设备私钥里，样本里没有，静态造不出来）
    report    —— 线索表 + 方案表 + 可直接执行的发包脚本

脚本里通常只用一个：

    rep = rf.fakepacket_build("样本.sh")     # 全自动：提线索→判协议→造包
    print(rep.table())                       # 看线索和方案
    rf.fakepacket_save(rep, "out/")          # 落盘（假包 + 发包脚本 + 报告）
============================================================================
"""

from .clues import Clue, ClueChain, extract
from .protocol import Proto, infer, PROTOCOLS
from .builder import Packet, build, render_script
from .report import report_md
from .plaintext import PlaintextMap, build as plaintext_map
from .replay import (ReplayReport, Harvest, replay, render_replay_script,
                     _extract_signatures, capture_signatures)
from .live import (CardKey, find_cards, pick_card, guess_package,
                   LiveCapture, LiveReport, SigPair,
                   parse_log, harvest, merge_into_body, run_live,
                   install_card, launch, devices, hook_js,
                   render_live_script)

__all__ = [
    "Clue", "ClueChain", "extract",
    "Proto", "infer", "PROTOCOLS",
    "Packet", "build", "render_script",
    "report_md",
    "PlaintextMap", "plaintext_map",
    "ReplayReport", "Harvest", "replay", "render_replay_script",
    "_extract_signatures", "capture_signatures",
    "CardKey", "find_cards", "pick_card", "guess_package",
    "LiveCapture", "LiveReport", "SigPair",
    "parse_log", "harvest", "merge_into_body", "run_live",
    "install_card", "launch", "devices", "hook_js", "render_live_script",
]
