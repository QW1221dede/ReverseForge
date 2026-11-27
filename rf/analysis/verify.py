#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 rf.analysis.verify · 校验点特征库
============================================================================

【为什么单独一个模块】
    "这是不是校验点"这个判断，注释器要用（决定标不标 ⚑），
    依赖图也要用（决定算不算核心节点）。两边共用一份规则，
    否则会出现"注释说这是校验点、报告里却不收录"的矛盾。

【规则从哪来】
    不是拍脑袋：这四类信号是逆向时判断"功能开关在哪"的通用经验——
      命名：checkLicense / verifySignature / isVip / isRooted
      字面量：/api/verify、X-Root、sha256=
      API：MessageDigest、Cipher、getPackageInfo(GET_SIGNATURES)
      结构：被多个入口调用、返回值决定后续分支

【已知局限（必须写清楚）】
    R8 混淆后名称变成 a/b/c，命名信号全失效，只剩 API 和字面量；
    加固壳把真实逻辑藏在 so 里，静态分析看不到；
    服务端校验在本地只留一个 HTTP 调用，判断依据只有 URL。
    以上情况本模块都会漏判 —— 它给的是"线索优先级"，不是"保证"。
============================================================================
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .annotate import ClassNote

# (类别, 正则, 说明)
VERIFY_RULES: list[tuple[str, str, str]] = [
    ("授权校验", r"licen[cs]e|activat|serial|cdkey|cd_key|product_?key|keygen",
     "授权/激活判定"),
    ("付费校验", r"receipt|purchase|subscri|entitle|premium|\bvip\b|paywall|billing|sku|\biap\b",
     "内购/订阅权益判定"),
    ("签名校验", r"signature|app_?sign|getsignatures|signinginfo|checksign|verifysign|cert_?hash",
     "应用签名比对"),
    ("完整性校验", r"integrity|tamper|checksum|\bcrc\b|digest|sha256|\bmd5\b|filehash",
     "文件/包完整性比对"),
    ("环境检测", r"\broot(ed)?\b|magisk|supersu|superuser|xposed|frida|emulator|"
                 r"isdebuggerconnected|ptrace|virtualapp|dual_?app",
     "Root/模拟器/调试器检测"),
    ("身份鉴权", r"\btoken\b|\bjwt\b|oauth|bearer|session_?id|refreshtoken|login|signin",
     "登录态/令牌校验"),
    ("有效期", r"expire|expiry|valid_?until|deadline|trial_?end|remain_?days",
     "到期时间判定"),
    ("服务端校验", r"https?://[^\"'\s]*(verify|activate|license|auth|check)",
     "服务端校验接口"),
]

COMPILED = [(cat, re.compile(p, re.I), desc) for cat, p, desc in VERIFY_RULES]

_CJK = re.compile(r"[\u4e00-\u9fff]")
_CODE_LITERAL = re.compile(r"^[-\w./:?=&%{}$@+~#\[\]]{4,80}$")


def code_like(s: str) -> bool:
    """
    这个字面量是不是"代码里写死的标识/地址"，而不是给人看的文案。

    必须过滤中文：中文 UI 文案里到处是 "root"、"登录"、"授权"，
    拿它当校验特征，一次扫描就能把整个界面层标成校验点。
    """
    if not s or _CJK.search(s):
        return False
    if " " in s or "(" in s or '"' in s:
        return False
    return bool(_CODE_LITERAL.match(s))


def match_name(name: str) -> tuple[str, str] | None:
    """名字（类/方法/字段）命中哪条规则 → (类别, 说明)"""
    for cat, rx, desc in COMPILED:
        if rx.search(name):
            return cat, desc
    return None


def match_method(name: str) -> tuple[str, str] | None:
    """
    方法名命中判定。比 match_name 多一层过滤：
    `getRootView` / `setRootView` 这种 UI 方法不算环境检测。
    """
    hit = match_name(name)
    if not hit:
        return None
    cat, desc = hit
    if cat == "环境检测" and re.search(r"(?i)^(set|get)(root|view)", name):
        if not re.search(r"(?i)(check|is|detect|has)", name):
            return None
    return hit


_UI_ROOT = re.compile(r"(?i)^(m_?)?root(view|layout|group|container|fl|ll)?$")


def match_field(name: str) -> tuple[str, str] | None:
    """
    字段名命中判定。
    `root` / `mRootView` 是界面控件根节点，不是 Root 权限 —— 必须排掉，
    否则每个 Activity 的 ViewBinding 类都会被标成"环境检测"。
    """
    hm = match_name(name)
    if not hm:
        return None
    cat, desc = hm
    if cat == "环境检测" and _UI_ROOT.match(name):
        return None
    return hm


def score_class(cls: "ClassNote") -> tuple[str, int, list[str]]:
    """
    给一个类打"校验语义"分。返回 (类别, 分数, 命中项)。

    权重：
        类名 30          名字直接叫 LicenseChecker，基本不会错
        方法名 12/个（上限 24）
        字段名 6/个（上限 12）   持有 mLicenseChecker 这种引用
        代码型字面量 8/个（上限 16）
        API 8            MessageDigest / Cipher / 读签名
    """
    cat, score, hits = "", 0, []

    for c, rx, desc in COMPILED:
        if rx.search(cls.name):
            cat = cat or c
            score += 30
            hits.append(f"类名 → {desc}")
            break

    mhits = 0
    for m in cls.methods:
        hm = match_method(m.name)
        if hm:
            c, desc = hm
            cat = cat or c
            if mhits < 2:
                score += 12
                mhits += 1
                hits.append(f"方法 {m.name}() → {desc}")

    fhits = 0
    for fname in cls.fields:
        hm = match_field(fname)
        if hm:
            c, desc = hm
            cat = cat or c
            if fhits < 2:
                score += 6
                fhits += 1
                hits.append(f"字段 {fname} → {desc}")

    shits = 0
    for m in cls.methods:
        for s in m.strings:
            if not code_like(s):
                continue
            hm = match_name(s)
            if hm:
                c, desc = hm
                cat = cat or c
                if shits < 2:
                    score += 8
                    shits += 1
                    hits.append(f"字面量「{s[:34]}」→ {desc}")

    for desc, _risk in cls.apis:
        if any(k in desc for k in ("摘要", "加解密", "读取设备唯一标识", "枚举已安装应用")):
            score += 8
            hits.append(f"API：{desc}")
            break

    return cat, min(score, 100), hits
