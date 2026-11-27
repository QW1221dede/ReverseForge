#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 rf.decrypt · 解密层
============================================================================

    ciphers —— 算法本身（XOR/RC4/AES/DES/ChaCha20/TEA/XXTEA/编码/压缩/填充）
    keys    —— 候选密钥提取（明文头、源码常量、配置、弱口令表）
    auto    —— 自动试解编排（按便宜到贵排，打分排序，带时间预算）

脚本里通常只需要这两个：

    rep = rf.decrypt_auto("secret.bin")      # 全自动
    print(rep.table())                       # 看候选
    rf.decrypt_save(rep, "out/")             # 落盘

    ks = rf.keys("apk_dir/")                 # 只捞密钥
============================================================================
"""

from . import auto, ciphers, keys

__all__ = ["auto", "ciphers", "keys"]
