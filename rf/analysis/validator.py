#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 rf.analysis.validator · 语法与结构校验器
============================================================================

【为什么需要它】
    积木能被"随便拆、随便加"，前提是每次拼完都有人替你检查一遍语法。
    这个模块就是那道检查：写错了立刻告诉你第几行、错在哪、怎么改，
    而不是等 apktool 编译到一半丢一坨看不懂的 smali 报错。

【覆盖范围】
    python  ast + compile 双重校验（积木脚本、生成的脚本）
    smali   指令表 + 标签引用 + 寄存器 + .method 配对（补丁后必过）
    java    括号/引号/注释剥离后的结构校验（注释产物粗检）
    json    json.loads
    xml     ElementTree 解析（AndroidManifest）

【设计原则】
    1) 只报"确定错"的，不猜。宁少报，不误报 —— 误报会让小白不敢改。
    2) 每条错误都带中文 hint，说明"通常是什么原因"。
    3) 纯标准库，无第三方依赖，打包后也能用。
============================================================================
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# 结果模型
# ---------------------------------------------------------------------------

LEVELS = ("error", "warning", "info")


@dataclass
class Issue:
    level: str                 # error / warning / info
    line: int                  # 1 基行号；0 表示整体性问题
    msg: str                   # 出了什么问题
    hint: str = ""             # 通常怎么改
    code: str = ""             # 相关代码片段

    def text(self) -> str:
        loc = f"第 {self.line} 行" if self.line else "整体"
        s = f"[{self.level}] {loc}：{self.msg}"
        if self.hint:
            s += f"（{self.hint}）"
        return s


@dataclass
class Result:
    kind: str = "text"
    ok: bool = True
    issues: list[Issue] = field(default_factory=list)
    stats: dict = field(default_factory=dict)

    @property
    def errors(self) -> list[Issue]:
        return [i for i in self.issues if i.level == "error"]

    @property
    def warnings(self) -> list[Issue]:
        return [i for i in self.issues if i.level == "warning"]

    def brief(self) -> str:
        if self.ok and not self.warnings:
            return f"{self.kind} 语法通过"
        if self.ok:
            return f"{self.kind} 语法通过（{len(self.warnings)} 条提醒）"
        return f"{self.kind} 语法错误 {len(self.errors)} 处"

    def to_dict(self) -> dict:
        return {
            "kind": self.kind, "ok": self.ok,
            "errors": [i.text() for i in self.errors],
            "warnings": [i.text() for i in self.warnings],
            "stats": self.stats,
        }


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------

_PY_HINTS = (
    ("expected ':'", "这一行末尾少了冒号，if/for/def/class 后面都要有 :"),
    ("invalid character", "有中文标点（，。；：“”）或全角空格混进了代码"),
    ("unexpected indent", "缩进多了，检查是否和上一层对齐"),
    ("expected an indented block", "冒号下面缺缩进，或者只剩注释"),
    ("unindent does not match", "缩进层级对不上，统一用 4 个空格"),
    ("unterminated string", "字符串引号没闭合（三引号也算）"),
    ("'(' was never closed", "括号没闭合"),
    ("']' was never closed", "方括号没闭合"),
    ("'}' was never closed", "花括号没闭合"),
    ("invalid syntax", "语法不合法，先看这一行有没有漏括号/逗号/引号"),
    ("cannot assign to", "等号左边不是可赋值的东西"),
    ("was never closed", "括号/引号没闭合"),
)


def _py_hint(msg: str) -> str:
    low = msg.lower()
    for key, hint in _PY_HINTS:
        if key.lower() in low:
            return hint
    return ""


def validate_python(text: str, filename: str = "<snippet>") -> Result:
    """AST 解析 + 编译，取第一条语法错的精确位置。"""
    import ast

    r = Result(kind="python")
    lines = text.splitlines()
    r.stats = {"lines": len(lines), "chars": len(text)}

    # 常见硬伤先自查，给出比解释器更直白的话
    for i, raw in enumerate(lines, 1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for bad, why in (("，", "中文逗号"), ("：", "中文冒号"), ("；", "中文分号"),
                         ("（", "中文左括号"), ("）", "中文右括号"),
                         ("“", "中文引号"), ("”", "中文引号")):
            # 只有出现在代码区（不在字符串里）才算错，粗略判断：引号外
            if bad in _strip_strings(raw):
                r.issues.append(Issue("error", i, f"代码里出现{why}「{bad}」",
                                      "换成半角英文符号", raw.strip()[:80]))
                r.ok = False
                break

    try:
        tree = ast.parse(text, filename=filename)
    except SyntaxError as e:
        ln = int(e.lineno or 0)
        snippet = (e.text or "").strip()
        r.issues.append(Issue("error", ln, f"语法错误：{e.msg}",
                              _py_hint(e.msg or ""), snippet[:120]))
        r.ok = False
        # 附带上下文，方便定位
        if 0 < ln <= len(lines):
            r.stats["context"] = "\n".join(lines[max(0, ln - 2):ln + 1])
        return r
    except ValueError as e:
        r.issues.append(Issue("error", 0, f"源码无法解析：{e}"))
        r.ok = False
        return r

    try:
        compile(text, filename, "exec")
    except (SyntaxError, ValueError) as e:
        r.issues.append(Issue("error", int(getattr(e, "lineno", 0) or 0),
                              f"编译失败：{e}", "检查 return/yield 是否在函数内"))
        r.ok = False
        return r

    # 轻量提醒：能跑但容易踩坑
    for i, raw in enumerate(lines, 1):
        if "\t" in raw and raw.startswith(" "):
            r.issues.append(Issue("warning", i, "缩进里混了 Tab 和空格",
                                  "统一成 4 个空格，否则换编辑器就报错"))
            break
    top_defs = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef))]
    r.stats["defs"] = len(top_defs)
    r.stats["imports"] = sum(1 for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom)))
    return r


# ---------------------------------------------------------------------------
# Smali
# ---------------------------------------------------------------------------

# Dalvik 指令表（按族分组；不追求 100% 覆盖，覆盖逆向产物里 99% 的指令）
_OPCODES = set("""
nop move move/from16 move/16 move-wide move-wide/from16 move-wide/16
move-object move-object/from16 move-object/16 move-result move-result-wide
move-result-object move-exception move-exception-object
return return-wide return-object return-void
const const/4 const/16 const/high16 const-wide const-wide/4 const-wide/16
const-wide/high16 const-wide/32 const-string const-string/jumbo const-class
const-method-handle const-method-type
monitor-enter monitor-exit
check-cast instance-of array-length new-instance new-array filled-new-array
filled-new-array/range fill-array-data throw throw-verification-error
goto goto/16 goto/32 packed-switch sparse-switch
cmpl-float cmpg-float cmpl-double cmpg-double cmp-long
if-eq if-ne if-lt if-ge if-gt if-le if-eqz if-nez if-ltz if-gez if-gtz if-lez
aget aget-wide aget-object aget-boolean aget-byte aget-char aget-short
aput aput-wide aput-object aput-boolean aput-byte aput-char aput-short
iget iget-wide iget-object iget-boolean iget-byte iget-char iget-short
iput iput-wide iput-object iput-boolean iput-byte iput-char iput-short
sget sget-wide sget-object sget-boolean sget-byte sget-char sget-short
sput sput-wide sput-object sput-boolean sput-byte sput-char sput-short
invoke-virtual invoke-super invoke-direct invoke-static invoke-interface
invoke-virtual/range invoke-super/range invoke-direct/range invoke-static/range
invoke-interface/range invoke-virtual-quick invoke-super-quick
invoke-polymorphic invoke-polymorphic/range invoke-custom invoke-custom/range
neg-int not-int neg-long not-long neg-float neg-double
int-to-long int-to-float int-to-double long-to-int long-to-float long-to-double
float-to-int float-to-long float-to-double double-to-int double-to-long double-to-float
int-to-byte int-to-char int-to-short
add-int sub-int mul-int div-int rem-int and-int or-int xor-int shl-int shr-int ushr-int
add-long sub-long mul-long div-long rem-long and-long or-long xor-long shl-long shr-long ushr-long
add-float sub-float mul-float div-float rem-float
add-double sub-double mul-double div-double rem-double
add-int/2addr sub-int/2addr mul-int/2addr div-int/2addr rem-int/2addr and-int/2addr
or-int/2addr xor-int/2addr shl-int/2addr shr-int/2addr ushr-int/2addr
add-long/2addr sub-long/2addr mul-long/2addr div-long/2addr rem-long/2addr
and-long/2addr or-long/2addr xor-long/2addr shl-long/2addr shr-long/2addr ushr-long/2addr
add-float/2addr sub-float/2addr mul-float/2addr div-float/2addr rem-float/2addr
add-double/2addr sub-double/2addr mul-double/2addr div-double/2addr rem-double/2addr
add-int/lit16 rsub-int mul-int/lit16 div-int/lit16 rem-int/lit16 and-int/lit16
or-int/lit16 xor-int/lit16 add-int/lit8 rsub-int/lit8 mul-int/lit8 div-int/lit8
rem-int/lit8 and-int/lit8 or-int/lit8 xor-int/lit8 shl-int/lit8 shr-int/lit8 ushr-int/lit8
add-int/lit16/2addr rsub-int/2addr mul-int/lit16/2addr div-int/lit16/2addr
rem-int/lit16/2addr and-int/lit16/2addr or-int/lit16/2addr xor-int/lit16/2addr
add-int/lit8/2addr mul-int/lit8/2addr div-int/lit8/2addr rem-int/lit8/2addr
and-int/lit8/2addr or-int/lit8/2addr xor-int/lit8/2addr shl-int/lit8/2addr
shr-int/lit8/2addr ushr-int/lit8/2addr
execute-inline invoke-direct-empty invoke-object-init/range
""".split())

_REG_RE = re.compile(r"\b([vp])(\d+)\b")
_LABEL_DEF = re.compile(r"^\s*(:[A-Za-z_][\w$]*)\s*$")
_LABEL_REF = re.compile(r":([A-Za-z_][\w$]*)")
_DIRECTIVE = re.compile(r"^\s*\.")


def _strip_strings(line: str) -> str:
    """去掉字符串字面量与 # 注释，便于做符号检查（不追求完美转义）。"""
    out = []
    i, n = 0, len(line)
    quote = ""
    while i < n:
        c = line[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = ""
            i += 1
            continue
        if c in "\"'":
            quote = c
            i += 1
            continue
        if c == "#":
            break
        out.append(c)
        i += 1
    return "".join(out)


def validate_smali(text: str, filename: str = "<smali>") -> Result:
    """
    检查 smali 的结构性问题：

      * 有没有 .class
      * .method / .end method 是否配对（补丁最常破坏这里）
      * 跳转标签是否都有定义
      * 指令拼写是否在指令表里（拼错一个大写字母，apktool 会报得很远）
      * .registers 声明是否够用
    """
    r = Result(kind="smali")
    lines = text.splitlines()
    r.stats = {"lines": len(lines)}

    has_class = False
    in_annotation = 0
    method_name = ""
    method_line = 0
    depth_methods = 0
    regs_declared = -1
    max_reg = -1
    labels_defined: set[str] = set()
    labels_used: dict[str, int] = {}
    methods = 0
    fields = 0

    for i, raw in enumerate(lines, 1):
        s = raw.strip()
        if not s or s.startswith("#"):
            continue

        # .annotation 块（类/字段/参数注解）：里面的 "value = ..." 不是指令
        if s.startswith(".annotation"):
            in_annotation += 1
            continue
        if s.startswith(".end annotation"):
            in_annotation = max(0, in_annotation - 1)
            continue
        # .array-data 块：里面是 0x6et / -0x5t 这类数组字面量，不是指令
        if s.startswith(".array-data"):
            in_annotation += 1
            continue
        if s.startswith(".end array-data"):
            in_annotation = max(0, in_annotation - 1)
            continue
        if in_annotation:
            continue

        if s.startswith(".class"):
            has_class = True
            continue
        if s.startswith(".method"):
            depth_methods += 1
            method_line = i
            method_name = s.split()[-1] if len(s.split()) > 1 else "?"
            regs_declared, max_reg = -1, -1
            labels_defined, labels_used = set(), {}
            methods += 1
            continue
        if s.startswith(".end method"):
            depth_methods -= 1
            if depth_methods < 0:
                r.issues.append(Issue("error", i, "多余的 .end method",
                                      "前面没有对应的 .method", s[:80]))
                r.ok = False
                depth_methods = 0
            # 方法结束时核对标签
            for lab, (ln, code) in labels_used.items():
                if lab not in labels_defined:
                    r.issues.append(Issue(
                        "error", ln, f"跳转目标 :{lab} 在本方法里没有定义",
                        f"方法 {method_name} 缺少标签定义，补丁改跳转时必须保留原标签",
                        code[:80]))
                    r.ok = False
            continue
        if s.startswith(".field"):
            fields += 1
            continue

        m = re.match(r"^\.registers\s+(\d+)", s)
        if m:
            regs_declared = int(m.group(1))
            continue
        m = re.match(r"^\.locals\s+(\d+)", s)
        if m:
            regs_declared = int(m.group(1))
            continue

        lab = _LABEL_DEF.match(s)
        if lab:
            labels_defined.add(lab.group(1)[1:])
            continue

        if _DIRECTIVE.match(s):
            continue

        # 指令行
        code = _strip_strings(s)
        op = code.split()[0] if code.split() else ""
        op = op.split("{")[0].strip()
        if op and op not in _OPCODES and not op.startswith("."):
            # 允许厂商扩展：只提示不判死
            r.issues.append(Issue("error", i, f"未知指令「{op}」",
                                  "检查拼写；自定义扩展指令可忽略这条", s[:80]))
            r.ok = False

        # 字段/方法引用必须带 "->"：iput v1, v0, Lcls;->field:I
        # 漏了箭头 apktool 汇编会报 missing ARROW（预演就该拦下）
        if op.startswith(("invoke", "iget", "iput", "sget", "sput")) \
                and "->" not in code and "L" in code:
            r.issues.append(Issue("error", i, "字段/方法引用缺少「->」",
                                  "形如 L包/类;->字段:类型 或 L包/类;->方法(参数)返回",
                                  s[:80]))
            r.ok = False

        for lab2 in _LABEL_REF.findall(code):
            # :label 只出现在跳转类指令里；类型描述符 Lcom/x; 不会被这个正则命中
            if op.startswith(("goto", "if-", "packed-switch", "sparse-switch")):
                labels_used.setdefault(lab2, (i, s))

        for kind, num in _REG_RE.findall(code):
            idx = int(num)
            if kind == "v" and idx > max_reg:
                max_reg = idx

    if depth_methods > 0:
        r.issues.append(Issue("error", method_line,
                              f"方法 {method_name} 没有 .end method",
                              "补丁插入代码时容易把 .end method 挤掉，补一行即可"))
        r.ok = False

    if not has_class:
        r.issues.append(Issue("error", 0, "缺少 .class 声明",
                              "这不是一个完整的 smali 类文件，剪贴时可能丢了头部"))
        r.ok = False

    if regs_declared >= 0 and max_reg >= regs_declared:
        r.issues.append(Issue(
            "warning", 0,
            f"用到 v{max_reg}，但只声明了 {regs_declared} 个寄存器",
            "把 .registers 调大，或检查是否误用了越界寄存器"))
    r.stats.update({"methods": methods, "fields": fields,
                    "labels": len(labels_defined), "registers": regs_declared})
    return r


# ---------------------------------------------------------------------------
# Java（只做结构粗检：注释产物、反编译源码）
# ---------------------------------------------------------------------------

def _strip_java(text: str) -> str:
    """去掉 // 与 /* */ 注释、字符串与字符字面量，保留换行以便定位。"""
    out = []
    i, n = 0, len(text)
    state = ""      # "", "line", "block", "str", "char"
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if state == "":
            if c == "/" and nxt == "/":
                state = "line"
                i += 2
                continue
            if c == "/" and nxt == "*":
                state = "block"
                i += 2
                continue
            if c == '"':
                state = "str"
                out.append(" ")
                i += 1
                continue
            if c == "'":
                state = "char"
                out.append(" ")
                i += 1
                continue
            out.append(c)
            i += 1
            continue
        if state == "line":
            if c == "\n":
                state = ""
                out.append("\n")
            i += 1
            continue
        if state == "block":
            if c == "*" and nxt == "/":
                state = ""
                i += 2
                continue
            if c == "\n":
                out.append("\n")
            i += 1
            continue
        if state in ("str", "char"):
            if c == "\\":
                i += 2
                continue
            if (state == "str" and c == '"') or (state == "char" and c == "'"):
                state = ""
            if c == "\n":
                out.append("\n")
            i += 1
            continue
    return "".join(out)


def validate_java(text: str, filename: str = "<java>") -> Result:
    r = Result(kind="java")
    clean = _strip_java(text)
    lines = clean.splitlines()
    r.stats = {"lines": len(text.splitlines())}

    stack: list[tuple[str, int]] = []
    pairs = {")": "(", "]": "[", "}": "{"}
    for i, line in enumerate(lines, 1):
        for ch in line:
            if ch in "([{":
                stack.append((ch, i))
            elif ch in ")]}":
                if not stack:
                    r.issues.append(Issue("error", i, f"多余的右括号「{ch}」",
                                          "删掉它，或补上左边缺的开括号"))
                    r.ok = False
                else:
                    op, ln = stack.pop()
                    if op != pairs[ch]:
                        r.issues.append(Issue("error", i, f"括号不配对：{op} 对应 {ch}",
                                              f"第 {ln} 行开的是「{op}」，这里却关了「{ch}」"))
                        r.ok = False
    for op, ln in stack[-5:]:
        r.issues.append(Issue("error", ln, f"开括号「{op}」一直没有闭合",
                              "常见于复制代码时漏了最后几行"))
        r.ok = False

    if not re.search(r"\b(class|interface|enum)\b", clean):
        r.issues.append(Issue("warning", 0, "没找到 class/interface/enum 声明",
                              "确认这是 Java 源码而不是片段"))
    if not re.search(r"\bpackage\s+[\w.]+\s*;", clean):
        r.issues.append(Issue("info", 0, "没有 package 声明（默认包）"))
    # 方法体级别的最低要求：有分号或有花括号
    if clean.count(";") == 0 and clean.count("{") == 0:
        r.issues.append(Issue("error", 0, "既没有分号也没有花括号",
                              "这更像一段说明文字，不是 Java 代码"))
        r.ok = False
    return r


# ---------------------------------------------------------------------------
# JSON / XML
# ---------------------------------------------------------------------------

def validate_json(text: str) -> Result:
    r = Result(kind="json")
    try:
        obj = json.loads(text)
        r.stats = {"type": type(obj).__name__,
                   "keys": len(obj) if isinstance(obj, dict) else "-"}
    except json.JSONDecodeError as e:
        r.ok = False
        hint = "检查是否多了尾逗号、用了单引号、或者少了右括号"
        if "Expecting property name" in e.msg:
            hint = "对象里多了一个逗号，或者键没加双引号"
        r.issues.append(Issue("error", e.lineno, f"JSON 解析失败：{e.msg}", hint))
    return r


def validate_xml(text: str) -> Result:
    r = Result(kind="xml")
    try:
        root = ET.fromstring(text)
        r.stats = {"root": root.tag, "children": len(list(root))}
    except ET.ParseError as e:
        r.ok = False
        ln = e.position[0] if getattr(e, "position", None) else 0
        r.issues.append(Issue("error", ln, f"XML 解析失败：{e}",
                              "标签没闭合、属性没加引号、或用了未转义的 & <"))
    return r


# ---------------------------------------------------------------------------
# 统一入口
# ---------------------------------------------------------------------------

_EXT_KIND = {
    ".py": "python", ".smali": "smali", ".java": "java", ".kt": "java",
    ".json": "json", ".xml": "xml", ".txt": "text", ".md": "text",
}


def detect_kind(path: str | Path) -> str:
    return _EXT_KIND.get(Path(path).suffix.lower(), "text")


def validate(text: str, kind: str = "python", filename: str = "") -> Result:
    """按类型分派。未知类型直接返回通过（不做无意义的猜测）。"""
    k = (kind or "text").lower()
    if k in ("py", "python"):
        return validate_python(text, filename or "<python>")
    if k == "smali":
        return validate_smali(text, filename or "<smali>")
    if k in ("java", "kt"):
        return validate_java(text, filename or "<java>")
    if k == "json":
        return validate_json(text)
    if k in ("xml", "manifest"):
        return validate_xml(text)
    r = Result(kind=k)
    r.issues.append(Issue("info", 0, "该类型不做语法校验"))
    return r


def validate_file(path: str | Path, kind: str = "") -> Result:
    p = Path(path)
    r = Result(kind=kind or detect_kind(p))
    if not p.exists():
        r.ok = False
        r.issues.append(Issue("error", 0, f"文件不存在：{p}"))
        return r
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        r.ok = False
        r.issues.append(Issue("error", 0, f"读取失败：{e}"))
        return r
    return validate(text, kind or detect_kind(p), str(p))


def validate_tree(root: str | Path, pattern: str = "**/*.smali",
                  limit: int = 4000) -> Result:
    """批量校验一棵目录（补丁后整体过一遍），合并结果。"""
    r = Result(kind="tree")
    files = sorted(Path(root).rglob(pattern))[:limit]
    bad = 0
    for f in files:
        one = validate_file(f)
        if not one.ok:
            bad += 1
            for i in one.errors[:3]:
                r.issues.append(Issue("error", 0, f"{f.name}: {i.text()}"))
    r.ok = bad == 0
    r.stats = {"files": len(files), "bad": bad}
    return r
