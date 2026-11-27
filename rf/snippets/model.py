#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 rf.snippets.model · 积木的数据模型
============================================================================

一块积木要回答的问题，和一份好的说明书是一样的：

    它干什么         purpose（一句话，不许写"处理数据"这种空话）
    什么时候用       when（典型场景）
    吃什么           needs（需要哪些变量/文件）
    吐什么           gives（产出什么）
    贴哪里           code（可直接粘进脚本，缩进正确）
    会不会炸         risk（需要先备份 / 会改原文件 / 需要联网）
    用之前要懂什么   level（1 入门 / 2 进阶 / 3 高阶）

【自动语法校验】
    每块积木加载时都跑一遍 ast.parse。写错了不会静默消失，
    而是变成一条 "积木本身有语法错" 的提示 —— 积木库自己也不能免检。
============================================================================
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..analysis import validator


LEVEL_NAMES = {1: "入门", 2: "进阶", 3: "高阶"}


@dataclass
class Snippet:
    sid: str
    title: str
    category: str
    level: int
    purpose: str
    code: str
    when: str = ""
    needs: list[str] = field(default_factory=list)
    gives: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    depends: list[str] = field(default_factory=list)
    risk: str = "无"
    source: str = "内置"
    valid: bool = True
    errors: list[str] = field(default_factory=list)

    @property
    def level_name(self) -> str:
        return LEVEL_NAMES.get(self.level, "进阶")

    def check(self) -> "Snippet":
        r = validator.validate(self.code, "python", self.sid)
        self.valid = r.ok
        self.errors = [i.text() for i in r.errors]
        return self

    def to_dict(self) -> dict:
        return {
            "id": self.sid, "title": self.title, "category": self.category,
            "level": self.level, "level_name": self.level_name,
            "purpose": self.purpose, "when": self.when,
            "needs": self.needs, "gives": self.gives, "tags": self.tags,
            "depends": self.depends, "risk": self.risk, "source": self.source,
            "valid": self.valid, "errors": self.errors,
            "lines": len(self.code.splitlines()),
        }

    def card(self) -> str:
        """终端/报告里的一张小卡片。"""
        needs = "、".join(self.needs) or "无"
        gives = "、".join(self.gives) or "无"
        return (f"[{self.sid}] {self.title}  ·  {self.category} / {self.level_name}\n"
                f"  作用：{self.purpose}\n"
                f"  需要：{needs}   产出：{gives}\n"
                f"  风险：{self.risk}" + ("\n  ⚠ 语法未通过：" + "；".join(self.errors)
                                         if not self.valid else ""))


@dataclass
class Category:
    name: str
    desc: str
    level: int

    def to_dict(self) -> dict:
        return {"name": self.name, "desc": self.desc,
                "level": self.level, "level_name": LEVEL_NAMES.get(self.level, "")}


CATEGORIES: list[Category] = [
    Category("入门", "日志、参数、计时、异常保护 —— 先让脚本能跑起来", 1),
    Category("侦察", "看包、看 so、看字符串、找密钥 —— 先搞清楚目标长什么样", 2),
    Category("校验", "找启动前的卡密/授权/签名判定，并给出补丁建议", 2),
    Category("补丁", "改 smali、重建、签名、回滚 —— 改完要能跑", 3),
    Category("解密", "ZIP/XOR/AES —— 处理被加密的资源与配置", 2),
    Category("运行期", "Frida / ADB —— 不改包先验一下改哪里有用", 3),
    Category("报告", "把结论写成人能看懂的中文报告", 1),
    Category("工程", "自检、工具状态、产物整理", 1),
]


def parse_user_snippet(path: str | Path) -> Snippet | None:
    """
    读取用户积木。

    文件格式（头部注释 + 空行 + 代码）：
        # @id      my.rule
        # @title   自定义校验规则
        # @category 校验
        # @level   3
        # @purpose 一句话说清作用
        # @needs   smali_dir
        # @gives   hits
        # @tags    smali,规则
        # @depends intro.log
        <code...>
    """
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    meta: dict[str, str] = {}
    body_start = 0
    for i, line in enumerate(text.splitlines()):
        s = line.strip()
        if not s:
            body_start = i + 1
            continue
        if not s.startswith("#"):
            body_start = i
            break
        if "@" not in s:
            body_start = i + 1
            continue
        key, _, val = s.lstrip("#").strip().partition(" ")
        meta[key.lstrip("@").lower()] = val.strip()
        body_start = i + 1
    code = "\n".join(text.splitlines()[body_start:]).strip("\n")
    if not code:
        return None
    sid = meta.get("id") or p.stem
    try:
        level = int(meta.get("level", "2"))
    except ValueError:
        level = 2
    sn = Snippet(
        sid=sid, title=meta.get("title", p.stem),
        category=meta.get("category", "工程"), level=max(1, min(3, level)),
        purpose=meta.get("purpose", "（用户积木，未写说明）"),
        code=code, when=meta.get("when", ""),
        needs=[x.strip() for x in meta.get("needs", "").split(",") if x.strip()],
        gives=[x.strip() for x in meta.get("gives", "").split(",") if x.strip()],
        tags=[x.strip() for x in meta.get("tags", "").split(",") if x.strip()],
        depends=[x.strip() for x in meta.get("depends", "").split(",") if x.strip()],
        risk=meta.get("risk", "未标注"), source=str(p),
    )
    return sn.check()


def analyze_code(code: str) -> dict[str, Any]:
    """给界面用：代码行数、是否可解析、用到了哪些 rf 方法。"""
    import ast
    import re as _re
    r = validator.validate(code, "python")
    used = sorted(set(_re.findall(r"\brf\.(\w+)", code)))
    return {"ok": r.ok, "errors": [i.text() for i in r.errors],
            "lines": len(code.splitlines()), "rf_calls": used}
