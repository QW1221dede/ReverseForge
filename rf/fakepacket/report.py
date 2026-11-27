#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""假包报告：线索表 → 协议判定表 → 方案表，跟解密报告同一套排版。"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .clues import ClueChain
    from .protocol import Proto
    from .builder import Packet


def report_md(chain: "ClueChain", protocols: list["Proto"],
              packets: list["Packet"], target: str = "") -> str:
    L = ["# 假包方案报告", "",
         f"- 目标：`{target or chain.source}`",
         f"- 扫描：{chain.files_scanned} 个文件 / {chain.bytes_scanned:,} 字节",
         f"- 线索：{chain.summary()}（总权重 {chain.score}）", ""]

    L += ["## 一、解出来的线索（脚本自动串的）", "",
          "```", chain.table(80), "```", ""]

    L += ["## 二、判定：怎么发 / 什么时候发", ""]
    if not protocols:
        L.append("没判定出协议 —— 样本里没有足够的字段/URL 线索，"
                 "先跑「12 任意文件画像」和「13 自动解密」把明文挖出来再试。")
    for p in protocols:
        L += [p.detail(), ""]

    L += ["## 三、造出来的假包", ""]
    if not packets:
        L.append("（没有可造的包）")
    else:
        L += ["| 类型 | 文件 | 大小 | 说明 |", "|---|---|---:|---|"]
        for p in packets:
            L.append(f"| {p.kind} | `{p.name}` | {p.size}B | {p.note} |")
        L.append("")
    if any(c.kind == "secret" for c in chain.clues):
        L += ["## 签名来源（决定假包能不能过）", "",
              "样本里有密钥/证书线索：" +
              "、".join(c.text[:50] for c in chain.of("secret")[:6]) + "。",
              "服务器验签时，先抓一份真请求重放；不改请求、改响应是最稳的路。", ""]
    L += ["## 四、顺序（别搞反）", "",
          "先发请求假包探服务器 → 看它回什么 → 再用假响应包把客户端的判决改掉。", "",
          "1. 先用假请求包打服务器，看它回什么码 —— 这一步决定要不要改客户端。",
          "2. 服务器真发权益：把假请求包发出去即可，客户端不用动。",
          "3. 服务器只回「成功/失败」：用假响应包把客户端判决改成成功。",
          "4. 有心跳：按发包时序.md 定期补发，否则会话过期又被踢回登录页。", ""]
    if chain.notes:
        L += ["## 备注", ""] + [f"- {n}" for n in chain.notes[:20]] + [""]
    return "\n".join(L)
