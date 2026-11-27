#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 rf.analysis.authscan · 跨类型校验点标注（脚本 / 可执行 / class / smali）
============================================================================

【要解决什么】
    一个工具包/外挂/脚本，启动时先要卡密、密码、授权码。
    这些校验可能藏在：
      · 脚本源码里      `if password == "abc123":`        ← 直接能看到
      · EXE/DLL 里       字符串 + strcmp 调用              ← 要定位偏移
      · JAR/class 里     `equals("...")` / MessageDigest   ← 反编译后能看到
      · APK/smali 里     布尔闸门                          ← 走 checkpoints
    目标不是"扫一堆关键词"，而是**精确指出哪一行、哪一条、怎么改**，
    并且给出可以直接替换的 old→new 文本，让人一键改掉。

【精确的含义】
    每条命中必须满足：有具体位置（文件+行号/偏移）+ 有上下文代码 + 有可执行改法。
    只命中关键词但给不出改法的，降权到 note 级，不当校验点报。

【改法怎么给】
    脚本类（可逆、无损）：
        `if password == "abc123":`  →  `if True:` 然后留注释记下原条件
        `if (pwd === "x") {`        →  `if (true) {`
        `if [ "$p" = "x" ]; then`   →  `if [ 1 = 1 ]; then`
    二进制类：
        只能定位（偏移 + 上下文），改机器码交给补丁引擎或 Ghidra，不在这里瞎猜。

【和 checkpoints 的分工】
    checkpoints 专精 smali（布尔闸门、调用图、置信度打分）；
    这里管"非 APK 的一切"，并把 smali 的结果并进来统一输出。
============================================================================
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# 校验类型
# ---------------------------------------------------------------------------

K_PASSWORD = "password"
K_CARD = "card_key"
K_LICENSE = "license"
K_HASH = "hash"
K_SERIAL = "serial"
K_TRIAL = "trial"
K_ENV = "environment"
K_TOKEN = "token"
K_UNKNOWN = "unknown"

K_CN = {
    K_PASSWORD: "口令校验", K_CARD: "卡密校验", K_LICENSE: "授权校验",
    K_HASH: "哈希比对", K_SERIAL: "机器码/序列号", K_TRIAL: "试用期",
    K_ENV: "环境检测", K_TOKEN: "令牌校验", K_UNKNOWN: "未知校验",
}

# 语言标签
L_PY, L_JS, L_LUA, L_SH, L_BAT, L_PS1, L_PHP, L_VBS, L_AHK, L_JAVA = (
    "py", "js", "lua", "sh", "bat", "ps1", "php", "vbs", "ahk", "java")
L_PE, L_ELF, L_SMALI, L_TEXT = "pe", "elf", "smali", "text"

# 脚本语言 → 该用哪套比较语法
SCRIPT_MAP = {
    ".py": L_PY, ".pyw": L_PY,
    ".js": L_JS, ".mjs": L_JS, ".cjs": L_JS, ".ts": L_JS,
    ".lua": L_LUA, ".sh": L_SH, ".bash": L_SH, ".zsh": L_SH,
    ".bat": L_BAT, ".cmd": L_BAT, ".ps1": L_PS1, ".psm1": L_PS1,
    ".php": L_PHP, ".vbs": L_VBS, ".vbe": L_VBS, ".ahk": L_AHK,
    ".java": L_JAVA, ".kt": L_JAVA, ".cs": L_JAVA,
}

# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------

@dataclass
class AuthPoint:
    aid: str = ""
    file: str = ""
    line: int = 0              # 脚本行号；二进制为 0
    offset: int = 0            # 二进制偏移；脚本为 0
    lang: str = ""
    kind: str = K_UNKNOWN
    confidence: int = 0
    pre_run: bool = False      # 是否在启动路径上
    code: str = ""             # 原始代码行（或二进制上下文）
    evidence: str = ""
    ctx: list[str] = field(default_factory=list)
    fix_old: str = ""          # 可直接替换的原文（空 = 只标注不改）
    fix_new: str = ""          # 替换成什么
    fix_note: str = ""
    note: str = ""

    @property
    def kind_cn(self) -> str:
        return K_CN.get(self.kind, self.kind)

    @property
    def loc(self) -> str:
        f = Path(self.file).name if self.file else "?"
        return f"{f}:{self.line}" if self.line else f"{f}+0x{self.offset:X}"

    def row(self) -> str:
        flag = "启" if self.pre_run else " "
        c = self.code.strip()
        if len(c) > 46:
            c = c[:43] + "..."
        return f"{self.aid} {flag} {self.loc:<28} {self.kind_cn:<10} {self.confidence:>3}  {c}"

    def to_dict(self) -> dict:
        return {
            "aid": self.aid, "file": self.file, "line": self.line,
            "offset": self.offset, "lang": self.lang, "kind": self.kind,
            "confidence": self.confidence, "pre_run": self.pre_run,
            "code": self.code, "fix_old": self.fix_old, "fix_new": self.fix_new,
            "fix_note": self.fix_note, "note": self.note,
        }


@dataclass
class AuthReport:
    root: str = ""
    files: int = 0
    points: list[AuthPoint] = field(default_factory=list)
    by_kind: dict[str, int] = field(default_factory=dict)
    by_lang: dict[str, int] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    elapsed: float = 0.0

    @property
    def pre_run(self) -> list[AuthPoint]:
        return [p for p in self.points if p.pre_run]

    @property
    def fixable(self) -> list[AuthPoint]:
        return [p for p in self.points if p.fix_old and p.fix_new]

    def summary(self) -> str:
        s = (f"{self.files} 个文件，{len(self.points)} 个校验点"
             f"（启动路径 {len(self.pre_run)}，可自动改 {len(self.fixable)}）")
        if self.by_kind:
            top = sorted(self.by_kind.items(), key=lambda kv: -kv[1])[:5]
            s += "：" + "、".join(f"{K_CN.get(k, k)} {v}" for k, v in top)
        s += f"，用时 {self.elapsed:.2f}s"
        return s

    def table(self, limit: int = 30, only_pre: bool = False) -> str:
        rows = self.pre_run if only_pre else self.points
        if not rows:
            return "（没扫到校验点）"
        out = [f"{'编号':<6} 启 {'位置':<28} {'类型':<10} {'分':>3}  代码"]
        out += [p.row() for p in rows[:limit]]
        if len(rows) > limit:
            out.append(f"... 还有 {len(rows) - limit} 条")
        return "\n".join(out)


# ---------------------------------------------------------------------------
# 关键词（用于判类型 + 二进制字符串扫描）
# ---------------------------------------------------------------------------

# (正则, 类型, 权重)
_KIND_HINTS: list[tuple[str, str, int]] = [
    (r"(?i)\b(card[_-]?key|card|卡密|卡号|激活码|充值码|注册码|授权码)\b", K_CARD, 30),
    (r"(?i)\b(licen[cs]e|activate|activation|授权|激活|正版)\b", K_LICENSE, 26),
    (r"(?i)\b(password|passwd|pwd|口令|密码|请输入密码)\b", K_PASSWORD, 26),
    (r"(?i)\b(serial|机器码|序列号|硬件码|machine[_-]?code|hwid)\b", K_SERIAL, 24),
    (r"(?i)\b(expire|expired|trial|试用|到期|有效期|剩余天数)\b", K_TRIAL, 24),
    (r"(?i)\b(md5|sha1|sha256|hash|digest|checksum)\b", K_HASH, 18),
    (r"(?i)\b(token|auth[_-]?key|api[_-]?key|bearer)\b", K_TOKEN, 16),
    (r"(?i)\b(root|emulator|frida|debug|tamper|检测到|环境异常|虚拟机)\b", K_ENV, 12),
]


def _guess_kind(text: str) -> tuple[str, int]:
    """按出现的词判类型，返回 (类型, 加分)。"""
    best, best_w = K_UNKNOWN, 0
    for pat, kind, w in _KIND_HINTS:
        if re.search(pat, text):
            if w > best_w:
                best, best_w = kind, w
    return best, best_w


# ---------------------------------------------------------------------------
# 脚本：逐行匹配
# ---------------------------------------------------------------------------

# 通用"变量 与 字面量 比较"，各语言都长得差不多
_RE_CMP = re.compile(
    r"""(?x)
    (?P<var>[A-Za-z_$][\w$.\[\]'"]{0,40})
    \s*
    (?:===|!==|==|!=|=~|\.equals\s*\(|\.Equals\s*\(|-eq|-ceq|-ne|\beq\b|\bne\b)
    \s*
    ["'](?P<lit>[^"'\r\n]{1,80})["']
    """)

# 反过来的写法：字面量在前
_RE_CMP_REV = re.compile(
    r"""["'](?P<lit>[^"'\r\n]{1,80})["']\s*(?:===|!==|==|!=|-eq|-ceq|\beq\b)\s*(?P<var>[\w$.]{1,40})""")

# 两边都带引号的写法（批处理/Shell 常见）：`if "%pwd%"=="CARD-9999" (`
_RE_CMP_QUOTED = re.compile(
    r"""["']\s*%?(?P<var>[\w$.]{1,40})%?\s*["']\s*
    (?:===|!==|==|!=|-eq|-ceq|-ne|\beq\b|\bne\b)\s*
    ["']?(?P<lit>[^"'\r\n]{1,80})["']""", re.X)

_RE_IF = re.compile(r"^\s*(?:if|elif|elseif|else\s+if|while|unless|switch|case)\b", re.I)
_RE_EXIT = re.compile(
    r"(?i)\b(sys\.exit|exit\s*\(|os\._exit|raise\s+\w+|die\s*\(|quit\s*\(|"
    r"Environment\.Exit|process\.exit|return\s+(?:false|0|1)|抛出|退出程序)")
_RE_HASH_CALL = re.compile(
    r"(?i)(md5|sha1|sha256|sha512|hashlib|MessageDigest|crypto\.createHash|"
    r"getInstance\s*\(\s*[\"'](?:MD5|SHA))")
_RE_INPUT = re.compile(
    r"(?i)(input\s*\(|raw_input|prompt\s*\(|readline|ReadLine|gets\s*\(|"
    r"read\s*\(|getpass|Scanner|TextIO|Get-Content|StdIn)")
_RE_LITERAL_LOGIN = re.compile(
    r"(?i)(password|passwd|pwd|pass|key|card|serial|licen[cs]e)\s*"
    r"(?:==|===|!=|!==|=)\s*[\"']([^\"'\r\n]{2,64})[\"']")

# 脚本里"这行本身就算一次校验"的强特征
_RE_HARDCODED = re.compile(
    r"""(?ix)
    (?:password|passwd|pwd|card[_-]?key|card|licen[cs]e[_-]?key|license|
       serial|activation|auth[_-]?code|token|vip[_-]?code|
       卡密|注册码|激活码|授权码)\s*(?:=|:|==|===|===)\s*["']([^"'\r\n]{2,64})["']""")


def _strip_comment(line: str, lang: str) -> tuple[str, str]:
    """拆出代码和注释，避免把注释里的示例当成校验。"""
    s = line
    if lang in (L_PY, L_SH, L_PS1):
        idx = s.find("#")
    elif lang in (L_JS, L_LUA, L_PHP, L_JAVA, L_AHK):
        idx = s.find("//")
        if idx < 0:
            idx = s.find("/*")
    elif lang in (L_BAT, L_VBS):
        idx = s.lower().find("rem ") if s.lower().startswith("rem ") else -1
        if idx < 0:
            idx = s.find("'")
    else:
        idx = -1
    if idx < 0:
        return s, ""
    return s[:idx], s[idx:]


def _make_fix(line: str, lang: str) -> tuple[str, str, str]:
    """
    给一行 if 条件造"改法"：把条件换成恒真。
    返回 (原文, 新文, 说明)。造不出来就返回 ("","","")。
    保留缩进和行尾语法（冒号/花括号/then），只动条件本身。
    """
    raw = line.rstrip("\r\n")
    m = re.match(r"^(\s*)(if|elif|elseif|else\s+if|unless)(\s*)", raw, re.I)
    if not m:
        return "", "", ""
    indent, kw, _ = m.group(1), m.group(2), m.group(3)
    rest = raw[m.end():]

    # 找条件的终点：Python 是冒号，JS/PHP/Java 是 {，Lua 是 then，Shell 是 ; then
    if lang == L_PY:
        cut = rest.rstrip()
        if cut.endswith(":"):
            # 冒号必须留着，注释放在冒号后面；写丢了就是语法错误（自测抓到过一次）
            new = f"{indent}{kw} True:  # RF: 原条件已短路"
            return raw, new, "条件恒真（保留冒号）"
        return "", "", ""
    if lang == L_LUA:
        idx = rest.find(" then")
        if idx >= 0:
            return raw, f"{indent}{kw} true{rest[idx:]}", "条件恒 true"
        return "", "", ""
    if lang in (L_JS, L_PHP, L_JAVA):
        idx = rest.find("{")
        tail = rest[idx:] if idx >= 0 else " {"
        return raw, f"{indent}{kw} (true) {tail}", "条件恒 true"
    if lang in (L_SH,):
        idx = rest.find(";")
        tail = rest[idx:] if idx >= 0 else "; then"
        return raw, f"{indent}{kw} [ 1 = 1 ]{tail}", "条件恒真（1=1）"
    if lang == L_BAT:
        # if "%1"=="x" (  →  if 1==1 (
        idx = rest.find("(")
        tail = rest[idx:] if idx >= 0 else " ("
        return raw, f"{indent}{kw} 1==1 {tail}", "条件恒真（1==1）"
    if lang == L_PS1:
        idx = rest.find("{")
        tail = rest[idx:] if idx >= 0 else " {"
        return raw, f"{indent}{kw} ($true) {tail}", "条件恒 $true"
    if lang == L_VBS:
        idx = rest.lower().find("then")
        tail = rest[idx:] if idx >= 0 else " Then"
        return raw, f"{indent}{kw} True {tail}", "条件恒 True"
    return "", "", ""


def _scan_script(path: Path, lang: str, aid_start: int,
                 min_conf: int) -> list[AuthPoint]:
    """扫一个脚本文件。逐行找比较运算 + 关键词，交叉定级。"""
    points: list[AuthPoint] = []
    try:
        text = path.read_text("utf-8", errors="replace")
    except OSError as e:
        return points
    lines = text.splitlines()
    if len(lines) > 20000:
        lines = lines[:20000]

    # 先找出所有"退出/失败"行，作为上下文证据
    exits = [i for i, ln in enumerate(lines) if _RE_EXIT.search(ln)]

    for i, raw in enumerate(lines):
        code, comment = _strip_comment(raw, lang)
        if not code.strip():
            continue
        s = code.strip()
        if len(s) > 400:
            continue

        # 跳过明显的资源行（UI 文案、日志格式串）
        if re.search(r"(?i)(toast|alert|messagebox|console\.log|print\s*\(|"
                     r"printf|Write-Host|echo\s)", s) and "if" not in s.lower():
            continue

        conf = 0
        ev: list[str] = []
        kind, kw = _guess_kind(raw)
        if kw:
            conf += kw
            ev.append(f"关键词权重 +{kw}")

        # 比较运算
        m = (_RE_CMP.search(code) or _RE_CMP_REV.search(code)
             or _RE_CMP_QUOTED.search(code))
        if m:
            conf += 22
            lit = m.group("lit")
            ev.append(f"与字面量比较 {lit[:24]!r}")
            # 硬编码的账号/卡密本身就是证据
            if _RE_HARDCODED.search(raw):
                conf += 18
                ev.append("硬编码凭据")
            if _RE_HASH_CALL.search(code):
                kind = K_HASH
                conf += 14
                ev.append("哈希比对")
            if _RE_INPUT.search(code):
                conf += 10
                ev.append("来自用户输入")

        # if 条件 + 附近有退出 → 典型的"校验失败就退"
        if _RE_IF.search(code):
            near = [j for j in exits if 0 <= j - i <= 6]
            if near:
                conf += 16
                ev.append(f"条件成立后退出（第 {near[0] + 1} 行）")

        if conf < min_conf:
            continue

        # 是否启动路径：文件顶层（无缩进）或 main/init 里
        indent = len(raw) - len(raw.lstrip())
        top_level = indent == 0
        in_main = False
        for j in range(i, max(-1, i - 200), -1):
            prev = lines[j]
            if re.search(r"(?m)^\s*(?:def\s+main|if\s+__name__|async\s+def\s+main|"
                         r"function\s+main|public\s+static\s+void\s+main)", prev):
                in_main = True
                break
            if j < i and len(prev) - len(prev.lstrip()) == 0 and prev.strip() and \
                    not re.match(r"^\s*(#|//|/\*|\*)", prev) and \
                    not re.match(r"^\s*(import|from|package|using|require)", prev):
                break
        pre_run = top_level or in_main

        old, new, note = _make_fix(raw, lang) if _RE_IF.search(code) else ("", "", "")
        if not old and m:
            # 不是 if 语句（比如 return password == "x"），给"改常量"的提示
            lit = m.group("lit")
            note = f"可把字面量 {lit[:20]!r} 改成你已知的值"

        ctx = [lines[k].rstrip() for k in range(max(0, i - 2), min(len(lines), i + 3))]
        points.append(AuthPoint(
            aid=f"A{aid_start + len(points) + 1:03d}",
            file=str(path), line=i + 1, lang=lang, kind=kind,
            confidence=min(98, conf), pre_run=pre_run,
            code=raw.rstrip(), evidence="；".join(ev), ctx=ctx,
            fix_old=old, fix_new=new, fix_note=note,
            note=comment.strip()[:80],
        ))
    return points


# ---------------------------------------------------------------------------
# 二进制：字符串 + 偏移
# ---------------------------------------------------------------------------

# 值钱的关键词（命中即加分，权重高的是"这就是校验"的证据）
#   注意：这里用 str，扫的是已经解码出来的可打印串，不是原始字节
_BIN_KEYWORDS: list[tuple[str, str, int]] = [
    ("card key", K_CARD, 26), ("cardkey", K_CARD, 26), ("CardKey", K_CARD, 26),
    ("license key", K_LICENSE, 24), ("LicenseKey", K_LICENSE, 24),
    ("activation", K_LICENSE, 20), ("activate", K_LICENSE, 18),
    ("serial", K_SERIAL, 20), ("Serial", K_SERIAL, 18),
    ("password", K_PASSWORD, 22), ("Password", K_PASSWORD, 22),
    ("passwd", K_PASSWORD, 20), ("pwd", K_PASSWORD, 14),
    ("expired", K_TRIAL, 18), ("trial", K_TRIAL, 16),
    ("unauthorized", K_LICENSE, 20), ("Unauthorized", K_LICENSE, 20),
    ("invalid key", K_LICENSE, 22), ("InvalidKey", K_LICENSE, 22),
    ("md5", K_HASH, 10), ("sha256", K_HASH, 10),
]

_BIN_CN: list[tuple[str, str, int]] = [
    ("卡密", K_CARD, 30), ("注册码", K_CARD, 28), ("激活码", K_CARD, 28),
    ("授权码", K_LICENSE, 26), ("序列号", K_SERIAL, 24), ("机器码", K_SERIAL, 24),
    ("密码", K_PASSWORD, 24), ("请输入密码", K_PASSWORD, 28),
    ("未授权", K_LICENSE, 24), ("授权失败", K_LICENSE, 26),
    ("试用", K_TRIAL, 18), ("已过期", K_TRIAL, 22), ("有效期", K_TRIAL, 18),
    ("验证失败", K_LICENSE, 22), ("校验失败", K_LICENSE, 22),
]

# 比较函数导入（有这些 + 有 password 字符串 = 几乎肯定是口令校验）
_CMP_IMPORTS = (b"strcmp", b"lstrcmp", b"memcmp", b"wcscmp", b"_stricmp",
                b"CompareString", b"lstrcmpiA", b"lstrcmpW")

_RE_HEX32 = re.compile(rb"\b[0-9a-fA-F]{32}\b")
_RE_HEX64 = re.compile(rb"\b[0-9a-fA-F]{64}\b")


def _strings_with_off(data: bytes, min_len: int = 5, limit: int = 200000
                      ) -> list[tuple[int, str]]:
    """抽 ASCII 串并记录偏移（只抽一次，供多处复用）。"""
    out: list[tuple[int, str]] = []
    cur = bytearray()
    start = 0
    for i, b in enumerate(data):
        if 32 <= b < 127 or b == 9:
            if not cur:
                start = i
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append((start, cur.decode("latin1")))
                if len(out) >= limit:
                    return out
            cur = bytearray()
    if len(cur) >= min_len:
        out.append((start, cur.decode("latin1")))
    return out


def _scan_binary(path: Path, lang: str, aid_start: int,
                 min_conf: int) -> list[AuthPoint]:
    """扫 PE/ELF：字符串定位 + 关键词判类型 + 比较函数导入做佐证。"""
    points: list[AuthPoint] = []
    try:
        data = path.read_bytes()
    except OSError:
        return points
    if not data:
        return points

    strs = _strings_with_off(data[:64 * 1024 * 1024])
    has_cmp = any(imp in data for imp in _CMP_IMPORTS)

    # UTF-16LE：.NET / WinForms 外挂的中文卡密提示全是这个编码。
    # 只按 ASCII 抽的话，"请输入卡密"在字节里是 卡\x00密\x00 形态，完全看不见。
    # 按字符位置 ×2 反推字节偏移（decode 用 errors=ignore，偏移可能有 ±1 漂移，
    # 对定位足够）。
    try:
        head16 = data[:24 * 1024 * 1024]
        if len(head16) % 2:
            head16 = head16[:-1]
        text16 = head16.decode("utf-16-le", "ignore")
        n16 = 0
        for m in re.finditer(
                r"[\u4e00-\u9fff\u3400-\u4dbf\w]{4,80}", text16):
            s = m.group(0)
            if not any(ch in s for ch in ("卡密", "授权", "注册", "激活",
                                          "密码", "机器码", "序列")):
                continue
            off = m.start() * 2
            conf, kind, ev = 0, K_UNKNOWN, []
            for kw, k, weight in _CARD_WORDS:
                w = kw.decode("utf-8", "ignore")
                if w in s or w.lower() in s.lower():
                    if weight > conf:
                        conf, kind = weight, k
            if conf:
                conf += 14
                ev.append("UTF-16LE 字符串（.NET/WinForms 常见）")
                if has_cmp:
                    conf += 8
                    ev.append("导入了 strcmp 系列比较函数")
                strs.append((off, s))
                if conf >= min_conf:
                    points.append(AuthPoint(
                        aid="A?", file=str(path), offset=off, lang=lang,
                        kind=kind, confidence=min(94, conf), pre_run=True,
                        code=s[:100], evidence="；".join(ev),
                        ctx=[], fix_note="UTF-16 字符串定位；改机器码要走补丁引擎",
                        note=f"文件偏移 0x{off:X}（UTF-16LE）",
                    ))
                    n16 += 1
                    if n16 >= 30:
                        break
    except Exception:                                # noqa: BLE001
        pass

    # 1) 关键词串
    for off, s in strs:
        low = s.lower()
        hit_kind, hit_w = K_UNKNOWN, 0
        for kw, kind, w in _BIN_KEYWORDS:
            if kw in s or kw in low:
                if w > hit_w:
                    hit_kind, hit_w = kind, w
        for kw, kind, w in _BIN_CN:
            if kw in s:
                if w > hit_w:
                    hit_kind, hit_w = kind, w
        if hit_w < 14:
            continue

        conf = hit_w
        ev = [f"字符串 {s[:40]!r}"]
        if has_cmp:
            conf += 14
            ev.append("导入了 strcmp 系列比较函数")
        # 附近有 "错误/失败/Error" 说明这是失败分支的提示语
        near = " ".join(d for o, d in strs if abs(o - off) < 512)
        if re.search(r"(?i)(error|invalid|wrong|failed|错误|失败|无效|不对)", near):
            conf += 8
            ev.append("邻近有失败提示")
        if conf < min_conf:
            continue

        ctx = [d for o, d in strs if abs(o - off) < 160][:5]
        points.append(AuthPoint(
            aid=f"A{aid_start + len(points) + 1:03d}",
            file=str(path), offset=off, lang=lang, kind=hit_kind,
            confidence=min(96, conf), pre_run=True,
            code=s[:120], evidence="；".join(ev), ctx=ctx,
            fix_note="二进制无法直接改文本，需定位比较指令后打补丁（见 patch 引擎）",
            note=f"文件偏移 0x{off:X}",
        ))
        if len(points) >= 40:
            break

    # 2) 独立的长 hex（多半是"正确卡密的哈希"，本身不构成校验点，作为线索）
    for m in _RE_HEX64.finditer(data[:8 * 1024 * 1024]):
        s = m.group(0).decode("latin1")
        if len(set(s)) < 6:
            continue
        points.append(AuthPoint(
            aid=f"A{aid_start + len(points) + 1:03d}",
            file=str(path), offset=m.start(), lang=lang, kind=K_HASH,
            confidence=58, pre_run=False, code=s,
            evidence="64 位 hex，疑似 SHA-256 密文/正确值", ctx=[],
            fix_note="若是校验目标值，可用同样的哈希算法算出你自己的卡密哈希替换",
            note=f"文件偏移 0x{m.start():X}",
        ))
        if len(points) >= 60:
            break

    # UTF-16 分支和 ASCII 关键词分支会命中同一处，按偏移去重
    # （UTF-16 的偏移可能有 ±1 漂移，所以用 offset±2 当键）
    seen: set[tuple[int, str]] = set()
    uniq: list[AuthPoint] = []
    for p in sorted(points, key=lambda x: -x.confidence):
        key = (p.offset // 4, p.code.strip()[:12])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(p)
    return uniq


# ---------------------------------------------------------------------------
# smali：复用 checkpoints
# ---------------------------------------------------------------------------

def _scan_smali(root: Path, aid_start: int, min_conf: int) -> tuple[list[AuthPoint], list[str]]:
    pts: list[AuthPoint] = []
    errs: list[str] = []
    try:
        from ..patch import checkpoints as cp
    except Exception as e:                           # noqa: BLE001
        return pts, [f"checkpoints 不可用：{e}"]
    try:
        rep = cp.analyze(root, min_confidence=min_conf)
    except Exception as e:                           # noqa: BLE001
        return pts, [f"smali 扫描失败：{e}"]
    errs.extend(rep.errors)
    kind_of = {
        "授权校验": K_LICENSE, "卡密": K_CARD, "口令": K_PASSWORD,
        "有效期": K_TRIAL, "哈希": K_HASH, "机器码": K_SERIAL,
        "环境检测": K_ENV,
    }
    for p in rep.points:
        kind = kind_of.get(p.category, K_UNKNOWN)
        fix_old = fix_new = ""
        note = ""
        if p.best and p.best.op:
            op = p.best.op
            fix_old = op.original.strip()
            fix_new = op.replacement.strip()
            note = p.best.why
        pts.append(AuthPoint(
            aid=f"A{aid_start + len(pts) + 1:03d}",
            file=p.file, line=p.line, lang=L_SMALI, kind=kind,
            confidence=p.confidence, pre_run=p.pre_run,
            code=f"{p.cls_simple}.{p.method}", evidence="；".join(p.evidence[:3]),
            ctx=[p.signature], fix_old=fix_old, fix_new=fix_new, fix_note=note,
            note=p.note,
        ))
    return pts, errs


# ---------------------------------------------------------------------------
# 总入口
# ---------------------------------------------------------------------------

def scan(target: str | Path, min_confidence: int = 45, max_files: int = 3000,
         include_smali: bool = True) -> AuthReport:
    """
    扫描目标（文件或目录），标出所有校验点。
    按文件类型自动分派：脚本走逐行匹配，PE/ELF 走字符串+偏移，smali 走 checkpoints。
    """
    t0 = time.time()
    rep = AuthReport(root=str(target))
    root = Path(target)
    if not root.exists():
        rep.errors.append(f"路径不存在：{target}")
        return rep

    if root.is_dir():
        smali_dirs = [p for p in root.rglob("smali*") if p.is_dir()][:3]
        if include_smali and smali_dirs:
            for sd in smali_dirs:
                pts, errs = _scan_smali(sd, len(rep.points), min_confidence)
                rep.points.extend(pts)
                rep.errors.extend(errs)
                rep.files += sum(1 for _ in sd.rglob("*.smali"))
            # 把 smali 目录排除在普通文件扫描外
            files = [p for p in root.rglob("*")
                     if p.is_file() and "smali" not in p.parts[:len(root.parts) + 2]]
        else:
            files = [p for p in root.rglob("*") if p.is_file()]
    else:
        files = [root]

    n = 0
    for p in files:
        if n >= max_files:
            break
        n += 1
        suffix = p.suffix.lower()
        lang = SCRIPT_MAP.get(suffix, "")
        try:
            size = p.stat().st_size
        except OSError:
            continue

        if lang and size < 4 * 1024 * 1024:
            pts = _scan_script(p, lang, len(rep.points), min_confidence)
        elif suffix in (".apk", ".dex") or _looks_apk_or_dex(p):
            # APK / DEX：卡密逻辑在 classes*.dex 里，中文是 UTF-8，
            # 光扫 PE 字符串的 ASCII 抽取根本看不见（实测 ACE 外挂漏报就在这）
            pts = _scan_apk_dex(p, len(rep.points), min_confidence)
        elif suffix == ".asar" or _looks_asar(p):
            # Electron 应用：逻辑在 app.asar 的 JS 里
            pts = _scan_asar(p, len(rep.points), min_confidence)
        elif suffix in (".exe", ".dll", ".sys", ".so", ".dylib", ".elf", ".bin", ".node") \
                or _looks_pe_or_elf(p):
            if size > 96 * 1024 * 1024:
                continue
            pts = _scan_binary(p, L_PE if suffix in (".exe", ".dll", ".sys") else L_ELF,
                               len(rep.points), min_confidence)
        elif suffix in (".jar", ".class"):
            pts = _scan_java_container(p, len(rep.points), min_confidence)
        else:
            continue

        if pts:
            rep.points.extend(pts)
            rep.files += 1
            rep.by_lang[lang or suffix] = rep.by_lang.get(lang or suffix, 0) + len(pts)

    # 重新编号（各分派器并行编号会重复）
    for i, pt in enumerate(rep.points):
        pt.aid = f"A{i + 1:03d}"
        rep.by_kind[pt.kind] = rep.by_kind.get(pt.kind, 0) + 1

    rep.points.sort(key=lambda x: (not x.pre_run, -x.confidence))
    rep.elapsed = time.time() - t0
    return rep


def _looks_pe_or_elf(p: Path) -> bool:
    try:
        with p.open("rb") as f:
            head = f.read(4)
    except OSError:
        return False
    return head[:2] == b"MZ" or head[:4] == b"\x7fELF"


def _looks_apk_or_dex(p: Path) -> bool:
    """按魔数认 APK（用户重命名成 .apk.1 也能认）和 DEX。"""
    try:
        with p.open("rb") as f:
            head = f.read(8)
    except OSError:
        return False
    if head[:4] == b"PK\x03\x04":
        # ZIP 不一定是 APK，得看里面有没有 classes*.dex / AndroidManifest.xml
        try:
            import zipfile
            with zipfile.ZipFile(p) as z:
                names = z.namelist()[:200]
            return any(n.startswith("classes") and n.endswith(".dex")
                       for n in names) or "AndroidManifest.xml" in names
        except Exception:                            # noqa: BLE001
            return False
    return head[:4] in (b"dex\n", b"dey\n")


def _looks_asar(p: Path) -> bool:
    try:
        with p.open("rb") as f:
            return f.read(4) in (b"\x04\x00\x00\x00", b"\x02\x00\x00\x00")
    except OSError:
        return False


# ---------------------------------------------------------------------------
# APK / DEX —— 卡密逻辑真正在的地方
# ---------------------------------------------------------------------------

# DEX 里的 MUTF-8 串：长度前缀 + UTF-8 字节，中文不会被 ASCII 抽取器看见。
# 这里按 UTF-8 范围直接抠连续可打印段，中文算有效字符。
_RE_MUTF8 = re.compile(
    rb"(?:[\x20-\x7e]|[\xc2-\xf4][\x80-\xbf]{1,3}|\xe0\xa0-\xbf[\x80-\xbf]){4,}")

_CARD_WORDS: list[tuple[bytes, str, int]] = [
    ("卡密".encode(), K_CARD, 32), ("注册码".encode(), K_CARD, 30),
    ("激活码".encode(), K_CARD, 30), ("授权码".encode(), K_LICENSE, 28),
    ("授权".encode(), K_LICENSE, 20), ("机器码".encode(), K_SERIAL, 26),
    ("序列号".encode(), K_SERIAL, 24), ("卡号".encode(), K_CARD, 20),
    ("有效期".encode(), K_TRIAL, 18), ("过期".encode(), K_TRIAL, 18),
    ("激活".encode(), K_LICENSE, 16), ("解绑".encode(), K_CARD, 16),
    (b"password", K_PASSWORD, 22), (b"license", K_LICENSE, 18),
    (b"cardkey", K_CARD, 25), (b"cdkey", K_CARD, 25),
    (b"verifycard", K_CARD, 28), (b"checkcard", K_CARD, 28),
    (b"validkey", K_LICENSE, 24), (b"authcode", K_LICENSE, 24),
]

# 只有这些"动作型"短语才算强证据；光一个"授权"可能是免责声明/系统权限
_STRONG_PHRASES = (
    "卡密无效", "卡密验证", "卡密激活", "卡密解绑", "卡密有效期", "卡密格式",
    "请输入卡密", "卡密错误", "注册码无效", "激活码无效", "授权码无效",
    "机器码", "trial expired", "invalid license", "invalid key",
)


def _scan_apk_dex(p: Path, aid_start: int, min_conf: int) -> list[AuthPoint]:
    """扫 APK（含被改后缀的 .apk.1）和裸 DEX 里的卡密/授权字符串。"""
    pts: list[AuthPoint] = []
    blobs: list[tuple[str, bytes]] = []
    try:
        if _looks_apk_or_dex(p):
            import zipfile
            with zipfile.ZipFile(p) as z:
                for n in z.namelist():
                    if n.startswith("classes") and n.endswith(".dex"):
                        blobs.append((n, z.read(n)))
    except Exception:                                # noqa: BLE001
        # BadZipFile 不继承 ValueError/OSError，扫目录时碰到损坏 zip 会冒泡
        pass
    if not blobs and p.suffix.lower() == ".dex":
        try:
            blobs = [(p.name, p.read_bytes())]
        except OSError:
            return []

    for name, blob in blobs:
        for m in _RE_MUTF8.finditer(blob):
            raw = m.group(0)
            try:
                s = raw.decode("utf-8", "ignore")
            except UnicodeDecodeError:
                continue
            low = s.lower()
            kind, w = K_UNKNOWN, 0
            for kw, k, weight in _CARD_WORDS:
                # kw 是 bytes：ASCII 词也拿 utf-8 字符串比，中文词直接 in s
                word = kw.decode("utf-8", "ignore")
                if word in s or word in low:
                    if weight > w:
                        kind, w = k, weight
            if w < 16:
                continue

            conf = w
            ev: list[str] = []
            if any(x in s for x in _STRONG_PHRASES) or \
                    any(x in low for x in _STRONG_PHRASES):
                conf += 26
                ev.append("命中卡密动作短语（强证据）")
            # DEX 里的字符串池：同一片区域挤着一堆相关字符串，就是校验逻辑的证据
            around = blob[max(0, m.start() - 300):m.end() + 300]
            cnt = sum(around.count(kw) for kw, _, _ in _CARD_WORDS)
            if cnt >= 3:
                conf += 10
                ev.append(f"邻近 {cnt} 处卡密相关串（字符串池）")
            if conf < min_conf:
                continue

            ctx = []
            for om in _RE_MUTF8.finditer(blob[max(0, m.start() - 240):m.end() + 240]):
                t = om.group(0).decode("utf-8", "ignore")
                if len(t) >= 3:
                    ctx.append(t)
                if len(ctx) >= 6:
                    break

            pts.append(AuthPoint(
                aid="A?", file=f"{p.name}:{name}", offset=m.start(),
                lang="dex", kind=kind, confidence=min(96, conf), pre_run=True,
                code=s[:100], evidence="；".join(ev) or "DEX 字符串",
                ctx=ctx,
                fix_note="DEX 里只是提示串；真正判断在 smali 方法里，"
                         "解包后跑 patch_scan 定位布尔闸门",
                note=f"DEX 偏移 0x{m.start():X}",
            ))
            if len(pts) >= 50:
                return pts
    return pts


# ---------------------------------------------------------------------------
# Electron app.asar
# ---------------------------------------------------------------------------

def _scan_asar(p: Path, aid_start: int, min_conf: int) -> list[AuthPoint]:
    """
    asar = 4 字节头长 + pickle + JSON 文件表 + 原始数据。
    只扫应用自己的 JS（dist/、main.js），跳过 node_modules 的 LICENSE 注释，
    否则 6589 个 "@license React" 会把报告淹掉。
    """
    import json
    import struct

    pts: list[AuthPoint] = []
    try:
        data = p.read_bytes()
        jlen = struct.unpack_from("<I", data, 12)[0]
        header = json.loads(data[16:16 + jlen].decode("utf-8", "replace"))
        base = 16 + jlen
    except Exception as e:                           # noqa: BLE001
        return [AuthPoint(file=str(p), lang="asar", kind=K_UNKNOWN,
                          confidence=0, code="", evidence=f"asar 解析失败：{e}")]

    def walk(node: dict, prefix: str = ""):
        for name, ent in (node or {}).items():
            if "files" in ent:
                yield from walk(ent["files"], prefix + name + "/")
            else:
                yield prefix + name, ent

    for name, ent in walk(header.get("files", {})):
        if not name.endswith((".js", ".mjs", ".cjs", ".ts")):
            continue
        if name.startswith("node_modules/") or "license" in name.lower():
            continue
        sz = int(ent.get("size", 0))
        if not (0 < sz < 4 * 1024 * 1024):
            continue
        off = base + int(ent.get("offset", 0))
        raw = data[off:off + sz]
        low = raw.lower()
        # 真正的中文卡密词优先；只是代码标识符 key/license 不算
        strong = sum(1 for k in (b"\xe5\x8d\xa1\xe5\xaf\x86",  # 卡密
                                 b"\xe6\xb3\xa8\xe5\x86\x8c\xe7\xa0\x81",  # 注册码
                                 b"\xe6\xbf\x80\xe6\xb4\xbb\xe7\xa0\x81",  # 激活码
                                 b"cardkey", b"cdkey", b"verifycard",
                                 b"invalidkey", b"checklicense")
                     if k in raw or k in low)
        if not strong:
            continue
        text = raw.decode("utf-8", "replace")
        hay = text.lower()
        kind, w = K_UNKNOWN, 0
        for kw, k, weight in _CARD_WORDS:
            word = kw.decode("utf-8", "ignore")
            if word in text or word in hay:
                if weight > w:
                    kind, w = k, weight
        conf = w + 18 + strong * 8
        if conf < min_conf:
            continue

        # 从 JS 里挑出真正相关的几行，别整段塞进报告
        lines = text.splitlines()
        picked = []
        for i, ln in enumerate(lines):
            if any(x in ln.lower() for x in ("cardkey", "cdkey", "卡密", "注册码",
                                             "激活码", "license", "password", "key")):
                picked.append(ln.strip()[:110])
                if len(picked) >= 4:
                    break
        pts.append(AuthPoint(
            aid="A?", file=f"{p.name}:{name}", offset=off, lang=L_JS,
            kind=kind, confidence=min(94, conf), pre_run=True,
            code=picked[0] if picked else name,
            evidence=f"asar 内 JS 命中 {strong} 类卡密特征",
            ctx=picked,
            fix_note="Electron 的 JS 逻辑在 asar 里；用 asar 解包后改代码再打包",
            note=f"asar 内偏移 0x{off:X}",
        ))
        if len(pts) >= 30:
            break
    return pts


def _scan_java_container(p: Path, aid_start: int, min_conf: int) -> list[AuthPoint]:
    """JAR/ZIP 里的 .class 逐个当文本扫（常量池里字符串是明文，能直接看）。"""
    import zipfile
    pts: list[AuthPoint] = []
    try:
        if p.suffix.lower() == ".class":
            blobs = [(p.name, p.read_bytes())]
        else:
            with zipfile.ZipFile(p) as z:
                # 先按名字截断，再逐个读 —— 不能先读全部再 [:300]
                names = [n for n in z.namelist() if n.endswith(".class")][:300]
                blobs = [(n, z.read(n)) for n in names]
    except (OSError, zipfile.BadZipFile) as e:
        return [AuthPoint(aid="A?", file=str(p), lang=L_JAVA, kind=K_UNKNOWN,
                          confidence=0, code="", evidence=f"读不了：{e}")]

    for name, blob in blobs:
        # class 常量池里的字符串是 UTF-8，直接按串扫
        for off, s in _strings_with_off(blob, min_len=4, limit=20000):
            kind, w = _guess_kind(s)
            if w < 20:
                continue
            conf = w + (10 if re.search(r"(?i)(equals|MessageDigest|digest)", s) else 0)
            if conf < min_conf:
                continue
            pts.append(AuthPoint(
                aid="A?", file=f"{p.name}:{name}", offset=off, lang=L_JAVA,
                kind=kind, confidence=min(92, conf), pre_run=False,
                code=s[:100], evidence="class 常量池字符串", ctx=[],
                fix_note="用 jadx 反编译后改 Java 源码再回编译",
                note=f"类内偏移 0x{off:X}",
            ))
            if len(pts) >= 40:
                break
    return pts


# ---------------------------------------------------------------------------
# 改法：事务化替换脚本里的校验
# ---------------------------------------------------------------------------

@dataclass
class PatchResult:
    ok: bool = False
    changed: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    backup: str = ""
    note: str = ""


def apply_points(report: AuthReport, ids: list[str] | None = None,
                 backup_dir: str | Path | None = None,
                 dry_run: bool = False) -> PatchResult:
    """
    把脚本里的校验点改成恒真。
    规矩和 smali 补丁一致：先备份 → 逐条确认原文唯一 → 原子写 → 出错整批回滚。
    """
    import hashlib
    import os
    import shutil

    res = PatchResult()
    targets = [p for p in report.points if p.fix_old and p.fix_new]
    if ids:
        want = {i.upper() for i in ids}
        targets = [p for p in targets if p.aid.upper() in want]
    if not targets:
        res.note = "没有可自动修改的校验点（二进制类只能手工打补丁）"
        return res

    by_file: dict[str, list[AuthPoint]] = {}
    for p in targets:
        by_file.setdefault(p.file, []).append(p)

    bdir = Path(backup_dir) if backup_dir else Path(report.root) / "_rf_backup"
    stamp = time.strftime("%Y%m%d_%H%M%S")
    bdir = bdir / stamp
    originals: dict[str, bytes] = {}

    for f, pts in by_file.items():
        fp = Path(f)
        try:
            raw = fp.read_bytes()
        except OSError as e:
            res.skipped.append(f"{fp.name}: 读不了 {e}")
            continue
        originals[f] = raw
        text = raw.decode("utf-8", "replace")
        lines = text.splitlines(keepends=True)
        changed = 0
        for p in pts:
            idx = p.line - 1
            if not (0 <= idx < len(lines)):
                res.skipped.append(f"{p.aid}: 行号越界")
                continue
            cur = lines[idx]
            o, n = p.fix_old, p.fix_new
            if o.strip() and cur.strip() != o.strip():
                # 行内容漂移了，全文件找唯一匹配
                hits = [i for i, ln in enumerate(lines) if ln.strip() == o.strip()]
                if len(hits) != 1:
                    res.skipped.append(f"{p.aid}: 原文不唯一（{len(hits)} 处），跳过")
                    continue
                idx = hits[0]
                cur = lines[idx]
            ending = "\r\n" if cur.endswith("\r\n") else "\n"
            lines[idx] = n + ending
            changed += 1
        if not changed:
            continue
        new_text = "".join(lines)
        if dry_run:
            res.changed.append(f"{fp.name}: 预演 {changed} 处")
            continue
        # 备份
        try:
            rel = fp.name
            bdir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(fp, bdir / rel)
            # 原子写
            tmp = fp.with_suffix(fp.suffix + ".rf.tmp")
            tmp.write_text(new_text, encoding="utf-8")
            os.replace(tmp, fp)
            res.changed.append(f"{fp.name}: 改了 {changed} 处"
                               f"（sha256 {hashlib.sha256(raw).hexdigest()[:12]} → "
                               f"{hashlib.sha256(new_text.encode()).hexdigest()[:12]}）")
        except OSError as e:
            res.skipped.append(f"{fp.name}: 写失败 {e}")
            # 回滚这一批
            for ff, blob in originals.items():
                try:
                    Path(ff).write_bytes(blob)
                except OSError:
                    pass

    res.ok = bool(res.changed) and not res.skipped
    res.backup = str(bdir)
    if dry_run:
        res.note = "预演模式，没有写盘"
    return res


# ---------------------------------------------------------------------------
# 报告
# ---------------------------------------------------------------------------

def report_md(rep: AuthReport, title: str = "校验点清单") -> str:
    L = [f"## {title}", "",
         f"- 目标：`{rep.root}`",
         f"- 概况：{rep.summary()}", ""]
    if rep.errors:
        L += ["### 错误", ""] + [f"- {e}" for e in rep.errors] + [""]

    pre = rep.pre_run
    L += ["### 启动路径上的校验", ""]
    if not pre:
        L.append("（无）")
    for p in pre[:30]:
        L.append(f"**{p.aid}** `{p.loc}` · {p.kind_cn} · 置信度 {p.confidence}")
        L.append("")
        L.append("```" + (p.lang if p.lang in ("py", "js", "lua", "sh", "bat", "java") else "text"))
        for c in p.ctx or [p.code]:
            L.append(c)
        L.append("```")
        if p.fix_old and p.fix_new:
            L += ["改法：", "", "```diff", f"- {p.fix_old.strip()}",
                  f"+ {p.fix_new.strip()}", "```"]
        elif p.fix_note:
            L.append(f"> {p.fix_note}")
        L.append("")

    others = [p for p in rep.points if not p.pre_run]
    if others:
        L += ["### 其他校验点（非启动路径）", "",
              "| 编号 | 位置 | 类型 | 置信度 | 内容 |", "|---|---|---|---|---|"]
        for p in others[:60]:
            L.append(f"| {p.aid} | `{p.loc}` | {p.kind_cn} | {p.confidence} | "
                     f"`{p.code.strip()[:50]}` |")
    return "\n".join(L)
