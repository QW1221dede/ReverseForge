#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 rf.patch.checkpoints · 启动前校验点的精确识别
============================================================================

【要解决的具体问题】
    "程序运行之前"的校验，和"点开某个页面才触发"的校验，处理方式完全不同：
    前者错了程序直接起不来，后者错了只是少个功能。所以扫描不能只给
    一张"疑似校验"的清单，必须回答三个问题：

        1) 它是不是在启动路径上（入口可达）？
        2) 它凭什么被判定为校验（证据，而不是黑盒分数）？
        3) 改哪一行、改成什么（可直接执行的补丁建议）？

【怎么做到"精确"】
    不用关键词一扫了事，而是四路证据交叉：

      结构  方法的返回值是否直接决定 if 分支 / 是否 return 常量布尔
      命名  类名·方法名·字段名是否命中授权/卡密/签名/环境规则
      常量  方法里是否出现代码型字面量（URL、key、sha256=、卡密提示）
      接口  MessageDigest / Cipher / getPackageInfo / HTTP 调用

    再用调用图做一次 BFS：从 Application/Activity/Service 的
    onCreate/attachBaseContext/<clinit> 出发，能走到的才算 pre_run。

【已知边界（写清楚，免得误判被当成保证）】
    * 加固壳把逻辑搬进 so：这里看不到，只能从 JNI 声明与加载点给线索
    * 服务端校验：本地只有一个 HTTP 调用，改本地只能"骗过界面"，
      真正的权益仍在服务端 —— 报告会明确标出这一点
    * 反射/动态代理调用：静态调用图断链，会漏；此时 confidence 会降低
============================================================================
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

from ..analysis import verify
from . import guards

# ---------------------------------------------------------------------------
# 数据模型
# ---------------------------------------------------------------------------

@dataclass
class PatchOp:
    """一条可执行的补丁操作：把 file 的 [line, end_line] 换成 replacement。"""
    file: str
    line: int
    end_line: int
    original: str
    replacement: str
    reason: str = ""
    kind: str = "line"          # line / block / method

    def to_dict(self) -> dict:
        return {"file": self.file, "line": self.line, "end_line": self.end_line,
                "original": self.original, "replacement": self.replacement,
                "reason": self.reason, "kind": self.kind}


@dataclass
class Suggestion:
    kind: str                   # method_true / branch_goto / const_flag / invert
    label: str                  # 给人看的一句话
    risk: str                   # 低 / 中 / 高
    why: str
    op: PatchOp


@dataclass
class Checkpoint:
    cid: str
    cls: str                    # Lcom/x/License;
    cls_simple: str             # License
    method: str
    signature: str              # (Landroid/content/Context;)Z
    file: str                   # 绝对路径
    line: int                   # .method 所在行
    category: str
    confidence: int
    pre_run: bool
    evidence: list[str] = field(default_factory=list)
    chain: str = ""             # 入口 → ... → 本方法
    returns: str = ""           # Z / V / I ...
    suggestions: list[Suggestion] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)   # 调用的外部方法
    note: str = ""
    auto_safe: bool = False      # 首选建议是否适合无人值守自动应用
    guard: bool = False          # 是否是"防改动/防调试/防环境"守卫
    guard_kind: str = ""         # apk_sig / integrity / antidebug / antiinject …
    guard_neutral: str = ""      # pass(要"通过") / false(要"未命中") / none
    inline_guard: bool = False   # 守卫内联在生命周期方法里（不能整体清空）
    indirect: bool = False       # 通过反射/字符串点名被调用（调用图断链）

    @property
    def best(self) -> Suggestion | None:
        return self.suggestions[0] if self.suggestions else None

    def brief(self) -> str:
        tag = "启动前" if self.pre_run else "运行中"
        b = self.best.label if self.best else "仅识别，无自动建议"
        return (f"{self.cls_simple}.{self.method} —— {self.category}"
                f"（{tag}，置信度 {self.confidence}）→ {b}")

    def to_dict(self) -> dict:
        return {
            "id": self.cid, "class": self.cls, "method": self.method,
            "signature": self.signature, "file": self.file, "line": self.line,
            "category": self.category, "confidence": self.confidence,
            "pre_run": self.pre_run, "evidence": self.evidence,
            "chain": self.chain, "returns": self.returns,
            "strings": self.strings[:6], "note": self.note,
            "guard": self.guard, "guard_kind": self.guard_kind,
            "guard_neutral": self.guard_neutral,
            "inline_guard": self.inline_guard, "indirect": self.indirect,
            "suggestions": [
                {"kind": s.kind, "label": s.label, "risk": s.risk, "why": s.why,
                 "file": s.op.file, "line": s.op.line, "end_line": s.op.end_line,
                 "original": s.op.original, "replacement": s.op.replacement}
                for s in self.suggestions
            ],
        }


@dataclass
class CheckpointReport:
    smali_root: str
    files: int = 0
    classes: int = 0
    methods: int = 0
    entries: list[str] = field(default_factory=list)
    points: list[Checkpoint] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    elapsed: float = 0.0

    @property
    def pre_run(self) -> list[Checkpoint]:
        return [p for p in self.points if p.pre_run]

    def get(self, cid: str) -> Checkpoint | None:
        return next((p for p in self.points if p.cid == cid), None)

    def summary(self) -> str:
        n_pre = len(self.pre_run)
        n_guard = len([p for p in self.points if p.guard])
        guard_txt = f"，其中防改动守卫 {n_guard} 个" if n_guard else ""
        return (f"扫描 {self.files} 个 smali / {self.classes} 类 / {self.methods} 方法，"
                f"命中 {len(self.points)} 个校验点（启动路径 {n_pre} 个{guard_txt}），"
                f"用时 {self.elapsed:.1f}s")

    def table(self, only_pre: bool = False, limit: int = 20) -> str:
        rows = self.pre_run if only_pre else self.points
        if not rows:
            return "（没有命中校验点）"
        out = [f"{'ID':<5}{'启动':<5}{'置信':<5}{'类别':<10}方法"]
        for p in rows[:limit]:
            out.append(f"{p.cid:<5}{'✓' if p.pre_run else ' ':<5}"
                       f"{p.confidence:<5}{p.category:<10}"
                       f"{p.cls_simple}.{p.method}")
        return "\n".join(out)


# ---------------------------------------------------------------------------
# smali 解析
# ---------------------------------------------------------------------------

_CLASS_RE = re.compile(r"^\.class\s+(.*?)(L[^\s;]+;)\s*$")
_SUPER_RE = re.compile(r"^\.super\s+(L[^\s;]+;)")
_IMPL_RE = re.compile(r"^\.implements\s+(L[^\s;]+;)")
_METHOD_RE = re.compile(r"^\.method\s+(.*?)([\w$<>]+)\(([^)]*)\)(\S+)\s*$")
_CONST_CLASS_RE = re.compile(r"^const-class\s+([vp]\d+),\s*(L[^;]+;)")
_START_ACTIVITY_RE = re.compile(r"->startActivity\(")
_FIELD_RE = re.compile(r"^\.field\s+(.*?)([\w$]+):(\S+)")
_STRING_RE = re.compile(r'const-string(?:/jumbo)?\s+[vp]\d+,\s*"((?:[^"\\]|\\.)*)"')
_INVOKE_RE = re.compile(r"^invoke-\S+\s+\{[^}]*\},\s*(L[^\s;]+;)->([\w$<>]+)\(([^)]*)\)(\S+)")
_CONST_RE = re.compile(r"^const(?:/4|/16|/high16)?\s+([vp]\d+),\s*(0x[0-9a-fA-F]+|-?\d+)")
_BRANCH_RE = re.compile(r"^(if-\w+|goto(?:/\d+)?)\s+([vp]\d+),\s*(:[\w$]+)$")
_GOTO_RE = re.compile(r"^goto(?:/\d+)?\s+(:[\w$]+)$")
_RETURN_RE = re.compile(r"^return(?:-wide|-object|-void)?(?:\s+([vp]\d+))?$")
_LABEL_RE = re.compile(r"^(:[\w$]+)$")

ENTRY_NAMES = {
    "onCreate", "attachBaseContext", "onAttach", "onStart", "onResume",
    "onCreateView", "onReceive", "onBind", "onStartCommand", "<clinit>",
    "main", "onActivityCreated", "onWindowFocusChanged",
}
ENTRY_SUPERS = {
    "Landroid/app/Application;", "Landroid/app/Activity;",
    "Landroid/app/Service;", "Landroid/content/BroadcastReceiver;",
    "Landroid/content/ContentProvider;", "Landroid/app/Fragment;",
    "Landroidx/fragment/app/Fragment;", "Landroid/app/backup/BackupAgent;",
    "Landroid/app/backup/BackupAgentHelper;", "Landroid/accounts/AccountAuthenticator;",
}
UI_ACTIVITY_PREFIX = ("Landroidx/", "Landroid/support/", "Lcom/google/android/material/")

# 回调接口 → 回调方法名。卡密闸门最常见的藏身处就是匿名内部类：
#   Splash 决定"进主界面还是卡密页"的逻辑写在 Runnable.run() 里，
#   "验证并进入"按钮写在 OnClickListener.onClick() 里 ——
#   它们不是 Activity 生命周期，老入口集合完全够不着。
CALLBACK_ENTRIES: dict[str, set[str]] = {
    "Ljava/lang/Runnable;": {"run"},
    "Landroid/view/View$OnClickListener;": {"onClick"},
    "Landroid/content/DialogInterface$OnClickListener;": {"onClick"},
    "Landroid/content/DialogInterface$MultiChoiceClickListener;": {"onClick"},
    "Landroid/view/View$OnLongClickListener;": {"onLongClick"},
    "Landroid/view/View$OnTouchListener;": {"onTouch"},
    "Ljava/util/concurrent/Callable;": {"call"},
    "Lio/reactivestorms/functions/Action;": {"run"},
    "Lretrofit2/Callback;": {"onResponse", "onFailure"},
    "Lokhttp3/Callback;": {"onResponse", "onFailure"},
}

# 中文/英文常量 → 类别（只用于"代码型字面量"，UI 文案已在 verify.code_like 里过滤）
_CAT_WORDS: list[tuple[str, re.Pattern]] = [
    ("授权校验", re.compile(r"卡密|激活码|兑换码|序列号|授权码|注册码|licen[cs]e|serial|cdkey", re.I)),
    ("口令校验", re.compile(r"密码|口令|pin\b|passw|passcode", re.I)),
    ("签名校验", re.compile(r"签名|signature|sha1|sha256|cert", re.I)),
    ("有效期", re.compile(r"到期|过期|剩余|有效期|expire|trial", re.I)),
    ("环境检测", re.compile(r"root|magisk|xposed|frida|模拟器|emulator", re.I)),
    ("服务端校验", re.compile(r"https?://|/api/|verify|activate", re.I)),
]

_BLOCK_HINTS = re.compile(r"(?i)finish\(|System\.exit|throw |Process\.killProcess|Toast")
_CRYPTO_APIS = re.compile(r"(?i)MessageDigest|Cipher|getPackageInfo|getSignatures|"
                          r"HttpURLConnection|OkHttp|SharedPreferences|Runtime\.exec")

# 界面/绘制/日志类方法：天然含分支和字符串，但不是校验。
# 这一层过滤是"精确"的关键 —— 不然每个 Activity 都会被标成环境检测。
_UI_WORDS = re.compile(
    r"(?i)(mask|style|render|draw|paint|layout|view|adapter|item|button|btn|label|"
    r"text|toast|menu|dialog|tab|page|anim|color|theme|icon|font|padding|margin|"
    r"header|footer|title|subtitle|banner|snack|hint|placeholder|"
    r"click|touch|swipe|scroll|focus|keyboard|"
    r"save_?log|append_?log|write_?log|log_?line|print|format|display|show_?|hide_?|"
    r"first_?run|notice|guide|welcome|splash|permission_?ui)")

# 生命周期：是校验的"调用者"，不是校验本身。除非名字直接命中规则
# （如 onLicenseCheck），否则不当作校验点。
_LIFECYCLE = re.compile(r"^(on[A-Z]|<init>|<clinit>|main$)")

# 校验动词：即使没命中具体规则，这类名字也直接算强证据
_VERB_NAME = re.compile(
    r"(?i)^(verify|validate|authorize|authenticate|activate|"
    r"is_?valid|is_?licensed|is_?activated|is_?authorized|is_?unlocked|"
    r"has_?license|has_?access|has_?permission|"
    r"verify_?license|check_?license|check_?card|check_?key|check_?serial|"
    r"check_?activate|check_?expire)")

# 中文卡密文案：出现即说明这个方法所在界面就是关卡页
_GATE_CN = re.compile(
    r"卡密|激活码?|授权码|兑换码|序列号|注册码|机器码|续费|"
    r"验证并进入|请输入卡密|卡号|密钥")

# 服务端"复核/失效"处理：卡密失效后停功能的杀招，名字特征明显
_KILLSWITCH_NAME = re.compile(
    r"(?i)(onlicense|licen[cs]einvalid|invalidat|recheck|re_?valid|"
    r"expirecheck|checkexpire|licen[cs]echeck|kick|disable_?all)")

# 结果类字段：服务器校验结果的"成功标志"与"到期"字段
_RESULT_OK_FIELDS = ("state", "code", "status", "ok")
_RESULT_EXPIRE_FIELDS = ("expire", "expiry", "valid_until", "deadline")


@dataclass
class _Method:
    cls: str
    cls_simple: str
    name: str
    params: str
    ret: str
    flags: str
    line: int
    file: str
    body: list[tuple[int, str]] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)
    branch: bool = False
    const_returns: dict[str, int] = field(default_factory=dict)  # "0"/"1" -> line
    exit_block: bool = False

    @property
    def key(self) -> str:
        return f"{self.cls}->{self.name}({self.params}){self.ret}"


def _parse_file(path: Path) -> tuple[list[_Method], str, str, list[str], list[tuple[str, str]]]:
    """返回 (方法表, 类描述符, 父类, 实现的接口, 实例字段)；解析失败返回空。"""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [], "", "", [], []
    cls, sup = "", ""
    impls: list[str] = []
    fields: list[tuple[str, str]] = []
    methods: list[_Method] = []
    cur: _Method | None = None
    in_annotation = 0

    for i, raw in enumerate(text.splitlines(), 1):
        s = raw.strip()
        if s.startswith(".annotation"):
            in_annotation += 1
            continue
        if s.startswith(".end annotation"):
            in_annotation = max(0, in_annotation - 1)
            continue
        if in_annotation:
            # 注解行保留在方法体里（补丁行范围要覆盖整个方法原文），
            # 只是注解值里的字符串不当作代码字面量收集。
            if cur is not None:
                cur.body.append((i, s))
            continue

        if cur is None:
            m = _CLASS_RE.match(s)
            if m:
                cls = m.group(2)
                continue
            m = _SUPER_RE.match(s)
            if m:
                sup = m.group(1)
                continue
            m = _IMPL_RE.match(s)
            if m:
                impls.append(m.group(1))
                continue
            fm = _FIELD_RE.match(s)
            if fm:
                fields.append((fm.group(2), fm.group(3)))
                continue

        m = _METHOD_RE.match(s)
        if m:
            name = m.group(2)
            simple = cls.rstrip(";").split("/")[-1] if cls else path.stem
            cur = _Method(cls=cls, cls_simple=simple, name=name,
                          params=m.group(3), ret=m.group(4), flags=m.group(1),
                          line=i, file=str(path))
            methods.append(cur)
            continue
        if s.startswith(".end method"):
            cur = None
            continue
        if cur is None:
            continue

        cur.body.append((i, s))
        m = _STRING_RE.search(s)
        if m:
            cur.strings.append(m.group(1))
        m = _INVOKE_RE.match(s)
        if m:
            cur.calls.append(f"{m.group(1)}->{m.group(2)}({m.group(3)}){m.group(4)}")
        if _BLOCK_HINTS.search(s):
            cur.exit_block = True
        if re.match(r"^if-", s):
            cur.branch = True
        m = _CONST_RE.match(s)
        if m:
            val = m.group(2).lower()
            if val in ("0x0", "0x1", "0", "1"):
                cur.const_returns[val] = i
    return methods, cls, sup, impls, fields


def _param_regs(params: str, flags: str) -> int:
    """参数占用的寄存器数（long/double 占 2；非 static 的 this 占 1）。"""
    n = 0 if "static" in flags.split() else 1
    i = 0
    while i < len(params):
        c = params[i]
        if c in "JD":
            n += 2
            i += 1
        elif c == "L":
            j = params.find(";", i)
            n += 1
            i = (j + 1) if j != -1 else i + 1
        elif c == "[":
            i += 1
            while i < len(params) and params[i] == "[":
                i += 1
            if i < len(params) and params[i] == "L":
                j = params.find(";", i)
                i = (j + 1) if j != -1 else i + 1
            else:
                i += 1
            n += 1
        else:
            n += 1
            i += 1
    return n


def _bool_returns(m: _Method) -> bool:
    """
    方法体里是否同时出现“返回 0”和“返回 1”（典型布尔闸门）。

    两种常见形态都要认：
        A.  const/4 v0, 0x0 ... return v0        多个 return，各自常量
        B.  const/4 p0, 0x1 / goto :end
            const/4 p0, 0x0 / :end / return p0   三元式合并到一个寄存器

    做法：先找出所有被 return 的寄存器，再看这些寄存器是否被赋过 0 和 1。
    只看“最后一次赋值”会漏掉 B（最后一条 const 是 0，但 1 也存在）。
    """
    ret_regs = set()
    for _ln, raw in m.body:
        rm = _RETURN_RE.match(raw.strip())
        if rm and rm.group(1):
            ret_regs.add(rm.group(1))
    if not ret_regs:
        return False
    has0 = has1 = False
    for _ln, raw in m.body:
        cm = _CONST_RE.match(raw.strip())
        if not cm or cm.group(1) not in ret_regs:
            continue
        v = cm.group(2).lower()
        if v in ("0x0", "0"):
            has0 = True
        elif v in ("0x1", "1"):
            has1 = True
    return has0 and has1


def _method_body_range(m: _Method) -> tuple[int, int]:
    if not m.body:
        return m.line, m.line
    return m.body[0][0], m.body[-1][0]


def _method_const_op(m: _Method, value: bool) -> PatchOp | None:
    NL = chr(10)
    """
    方法体整体短路：保留签名/参数，只留 `const/4 v0, 0x1|0x0` + `return v0`。

    寄存器声明行要保留并保证够用：
      .locals N     → 至少 1 个局部寄存器
      .registers N  → 至少 参数寄存器数 + 1
    直接把 .registers 改成 2 会让带参方法汇编失败 —— 这是实测踩过的坑。
    """
    if m.ret != "Z" or not m.body:
        return None
    params = _param_regs(m.params, m.flags)
    directive = None
    for _ln, s in m.body:
        t = s.strip()
        if t.startswith(".locals") or t.startswith(".registers"):
            directive = t
            break
    if directive is None:
        directive = ".locals 1"
    if directive.startswith(".locals"):
        try:
            n = int(directive.split()[1])
        except (IndexError, ValueError):
            n = 1
        if n < 1:
            directive = ".locals 1"
    else:
        try:
            n = int(directive.split()[1])
        except (IndexError, ValueError):
            n = params + 1
        if n < params + 1:
            directive = f".registers {params + 1}"

    start, end = _method_body_range(m)
    original = NL.join(s for _, s in m.body)
    val = "0x1" if value else "0x0"
    repl = (f"    {directive}{NL}"
            f"{NL}"
            f"    const/4 v0, {val}{NL}"
            f"{NL}"
            f"    return v0")
    return PatchOp(file=m.file, line=start, end_line=end, original=original,
                   replacement=repl, kind="method",
                   reason=f"布尔闸门整体短路：保留方法签名，直接返回 {'true' if value else 'false'}")


def _branch_ops(m: _Method) -> list[Suggestion]:
    """
    分支级建议。只处理最常见的形态：

        if-eqz vX, :label      ; 条件不成立 → 跳到失败分支
        ...
        :label
        ...
        return 0

    两种改法：
        goto :label            强制走失败分支（让校验"必然失败"，用于验证逻辑）
        if-ne → if-eq 反转     结果取反（对偶校验、双重否定场景）
    """
    out: list[Suggestion] = []
    labels = {s for _, s in m.body if _LABEL_RE.match(s)}
    for i, (ln, s) in enumerate(m.body):
        bm = _BRANCH_RE.match(s)
        if not bm:
            continue
        op, reg, lab = bm.group(1), bm.group(2), bm.group(3)
        if lab not in labels:
            continue
        # 该分支之后 6 行内是否有"返回常量"或退出调用
        tail = " ".join(t for _, t in m.body[i:i + 8])
        if not (re.search(r"return", tail) or _BLOCK_HINTS.search(tail)):
            continue
        if op == "if-eqz":
            inv = "if-nez"
        elif op == "if-nez":
            inv = "if-eqz"
        elif op == "if-eq":
            inv = "if-ne"
        elif op == "if-ne":
            inv = "if-eq"
        else:
            inv = ""
        if inv:
            out.append(Suggestion(
                kind="invert",
                label=f"反转判定：{op} → {inv}",
                risk="中",
                why="把分支结果取反。适合“双重否定/反调试”场景；"
                    "若原逻辑是失败分支，这一步等于放行。",
                op=PatchOp(file=m.file, line=ln, end_line=ln,
                           original=s, replacement=s.replace(op, inv, 1),
                           reason="分支取反")))
        out.append(Suggestion(
            kind="branch_goto",
            label=f"强制跳转：{op} … {lab}",
            risk="中",
            why=f"无条件跳到 {lab}。若 {lab} 正是失败分支，程序会稳定走失败；"
                f"若目标是跳过校验，应改用“反转判定”。",
            op=PatchOp(file=m.file, line=ln, end_line=ln,
                       original=s, replacement=f"goto {lab}",
                       reason="强制控制流")))
    return out


_NEG_WORDS = re.compile(
    r"(?i)(expire|invalid|illegal|rooted|root|debug|emulator|tamper|blocked|banned|"
    r"locked|fake|hook|clone|modified|jailbreak|vpn|proxy|trace|attach|risk)")


def _is_negative(m: _Method) -> bool:
    """
    判定方向：这个名字"为真"是坏事还是好事？

        isExpired() / isRooted() / isDebug()   → true = 坏事（负面闸门）
        verify()   / isVip()    / canRun()     → true = 好事（正面闸门）

    方向搞反，补丁就会把程序改得更坏 —— 所以单独一个函数负责这件事。
    """
    if re.search(r"(?i)(unlock|bypass|remove|disable|fix)", m.name):
        return False
    return bool(_NEG_WORDS.search(m.name))


def _const_flag_ops(m: _Method) -> list[Suggestion]:
    """
    只改一个返回点的常量，影响面最小。

    正面闸门（verify/isVip）：0x0 → 0x1，让"失败"变"成功"
    负面闸门（isExpired/isRooted）：0x1 → 0x0，让"命中"变"未命中"
    """
    out: list[Suggestion] = []
    neg = _is_negative(m)
    src_val, dst_val = ("0x1", "0x0") if neg else ("0x0", "0x1")
    for idx, (ln, s) in enumerate(m.body):
        cm = _CONST_RE.match(s)
        if not cm or cm.group(2).lower() not in (src_val, src_val.lstrip("0x")):
            continue
        for fwd in range(idx + 1, min(len(m.body), idx + 4)):
            rm = _RETURN_RE.match(m.body[fwd][1])
            if rm and rm.group(1) == cm.group(1):
                out.append(Suggestion(
                    kind="const_flag",
                    label=f"改返回值：{cm.group(1)} {src_val} → {dst_val}（第 {ln} 行）",
                    risk="低",
                    why=("负面闸门：把「命中」改成「未命中」。"
                         if neg else "正面闸门：把「失败」改成「成功」。")
                        + "只改这一处返回常量，不动控制流；"
                          "多返回点的方法要逐个确认。",
                    op=PatchOp(file=m.file, line=ln, end_line=ln,
                               original=s,
                               replacement=s.replace(cm.group(2), dst_val, 1),
                               reason="布尔返回值翻转")))
                break
    return out[:4]


# 卡密路由里的"关卡页"类名特征：LicenseActivity / KeyActivity / LoginActivity…
_GATE_CLASS_NAME = re.compile(
    r"(?i)(licen[cs]e|activat|register|cdkey|serial|auth|login|keydlg|keytask|"
    r"paywall|gate|unlock)[\w$]*;")
# 非业务包前缀（框架类，不可能"改道"目标）
_FRAMEWORK_PREFIX = ("Landroid/", "Ljava/", "Lkotlin", "Landroidx/",
                     "Lcom/google/", "Lorg/")


def _reroute_ops(m: _Method) -> list[Suggestion]:
    """
    路由闸门：一个方法里同时出现两个 const-class + startActivity ——
    典型形态（SplashActivity$6.run）：

        invoke Cfg.license(...) → 空不空？
        if-lez v2, :cond_1
        const-class v2, Lcom/x/MainActivity;      ← 有卡密：进主界面
        goto :goto_0
        :cond_1
        const-class v2, Lcom/x/LicenseActivity;   ← 没卡密：进卡密页
        :goto_0 startActivity(v2)

    改法：把"关卡页"的 const-class 换成主界面的 —— 两个分支都进主界面。
    判断哪边是关卡页靠类名特征，哪边是主界面靠"非框架包"。
    """
    out: list[Suggestion] = []
    consts: list[tuple[int, str, str]] = []       # (行号, 寄存器, 类描述符)
    for ln, s in m.body:
        cm = _CONST_CLASS_RE.match(s)
        if cm:
            consts.append((ln, cm.group(1), cm.group(2)))
    if len(consts) < 2:
        return out
    if not any(_START_ACTIVITY_RE.search(t) for _, t in m.body):
        return out
    gate_hits = [c for c in consts if _GATE_CLASS_NAME.search(c[2])]
    plain_hits = [c for c in consts
                  if not _GATE_CLASS_NAME.search(c[2])
                  and not c[2].startswith(_FRAMEWORK_PREFIX)]
    if len(gate_hits) != 1 or len(plain_hits) != 1:
        return out
    g = gate_hits[0]
    tgt = plain_hits[0][2]
    out.append(Suggestion(
        kind="reroute",
        label=f"路由改道：{g[2].rstrip(';').split('/')[-1]} → "
              f"{tgt.rstrip(';').split('/')[-1]}（没卡密也直接进主界面）",
        risk="低",
        why="启动路由按「卡密是否为空」选页面。把卡密页的 const-class 换成主界面，"
            "两个分支都进主界面 —— 不碰校验逻辑本身，栈结构不变，最稳。",
        op=PatchOp(file=m.file, line=g[0], end_line=g[0],
                   original=f"const-class {g[1]}, {g[2]}",
                   replacement=f"const-class {g[1]}, {tgt}",
                   reason="启动路由改道")))
    return out


def _string_gate_ops(m: _Method) -> list[Suggestion]:
    """
    字符串闸门：`Cfg.license(ctx)` 这类方法从 SP 读卡密，读不到给默认 ""。
    调用方全部用 `trim().length() > 0` 判断 —— 空默认值就是总闸。

    改法：把空字符串默认值改成非空标记，一次改动让所有调用方的"卡密为空"
    判断全部通过。比逐个补调用方分支稳得多。

    只对名字本身就带授权语义的方法给这条建议 —— sha256/deviceId 这类
    工具方法里也有空串字面量，改了会把哈希/设备号算坏。
    """
    out: list[Suggestion] = []
    if m.ret != "Ljava/lang/String;" or not m.body:
        return out
    if not re.search(r"(?i)(licen|cdkey|serial|activ|token|cardkey|card_?key"
                     r"|authkey|auth_?key)", m.name):
        return out
    for idx, (ln, s) in enumerate(m.body):
        t = s.strip()
        sm = re.match(r'^const-string\s+([vp]\d+),\s*""$', t)
        if not sm:
            continue
        reg = sm.group(1)
        for fwd in range(idx + 1, min(len(m.body), idx + 6)):
            bt = m.body[fwd][1]
            rm = re.match(r"^return-object\s+" + re.escape(reg) + r"$", bt)
            im = re.match(r"invoke-\S+\s+\{[^}]*" + re.escape(reg), bt)
            if rm or im:
                out.append(Suggestion(
                    kind="const_string",
                    label=f"空卡密默认值 → 非空（第 {ln} 行），所有「卡密为空」判断直接通过",
                    risk="低",
                    why="方法从存储里读卡密，读不到时给默认空串；"
                        "调用方几乎都是拿「是否为空」当闸门。把默认值改成非空标记，"
                        "一处改动覆盖全部调用方。",
                    op=PatchOp(file=m.file, line=ln, end_line=ln,
                               original=s,
                               replacement=(s[:s.index('""')] + '"RF-OK"'
                                            + s[s.index('""') + 2:]),
                               reason="字符串闸门默认值改写")))
                break
    return out[:3]


def _directive_for(m: _Method, min_locals: int) -> str:
    """拿方法的寄存器声明行，并保证局部寄存器数量够用。"""
    directive = None
    for _ln, s in m.body:
        t = s.strip()
        if t.startswith(".locals") or t.startswith(".registers"):
            directive = t
            break
    if directive is None:
        directive = ".locals 1"
    if directive.startswith(".locals"):
        try:
            n = int(directive.split()[1])
        except (IndexError, ValueError):
            n = 1
        if n < min_locals:
            directive = f".locals {min_locals}"
    else:
        params = _param_regs(m.params, m.flags)
        try:
            n = int(directive.split()[1])
        except (IndexError, ValueError):
            n = params + min_locals
        if n < params + min_locals:
            directive = f".registers {params + min_locals}"
    return directive


def _void_noop_op(m: _Method) -> PatchOp | None:
    """
    void 方法整体清空：只留寄存器声明 + return-void。

    适用"失效处理/复核"类杀招（onLicenseInvalid / recheckLicense）——
    服务器判定卡密失效后调它停功能。清空后复核结果直接被无视，
    拦截/主功能照常运行。void 方法清空不会破坏调用方的栈平衡。
    """
    if m.ret != "V" or not m.body:
        return None
    directive = _directive_for(m, 0)
    start, end = _method_body_range(m)
    original = chr(10).join(s for _, s in m.body)
    repl = f"    {directive}{chr(10)}{chr(10)}    return-void"
    return PatchOp(file=m.file, line=start, end_line=end, original=original,
                   replacement=repl, kind="method",
                   reason="失效处理短路：方法清空，服务器判定失效也不停功能")


def _fabricate_result_op(m: _Method, rcls: str,
                         ok_fields: list[str],
                         expire_fields: list[str]) -> PatchOp | None:
    """
    服务器校验结果伪造：verifySync() 这类方法返回 Result 对象。
    直接构造一个"成功"的 Result 返回，网络请求根本不发。

        new-instance v0, Lcom/x/Lic$Result;
        invoke-direct {v0}, Lcom/x/Lic$Result;-><init>()V
        const/4 v1, 0x1
        iput v1, v0, Lcom/x/Lic$Result;->state:I
        const-string v1, "2099-12-31"
        iput-object v1, v0, Lcom/x/Lic$Result;->expire:Ljava/lang/String;
        return-object v0

    只写"成功标志"和"到期"字段；URL 之类的字段保持默认，避免破坏规则下载。
    """
    if not m.body or not rcls.startswith("L") or not rcls.endswith(";"):
        return None
    NL2 = chr(10)
    directive = _directive_for(m, 2)
    lines = [
        f"    {directive}",
        "",
        f"    new-instance v0, {rcls}",
        f"    invoke-direct {{v0}}, {rcls}-><init>()V",
    ]
    for fname, ftype in ok_fields:
        if ftype == "I":
            lines += [f"    const/4 v1, 0x1",
                      f"    iput v1, v0, {rcls}->{fname}:I"]
        elif ftype == "Z":
            lines += [f"    const/4 v1, 0x1",
                      f"    iput-boolean v1, v0, {rcls}->{fname}:Z"]
    for fname, ftype in expire_fields:
        if ftype == "Ljava/lang/String;":
            lines += [f'    const-string v1, "2099-12-31"',
                      f"    iput-object v1, v0, {rcls}->{fname}:Ljava/lang/String;"]
    lines += ["    return-object v0"]
    start, end = _method_body_range(m)
    original = NL2.join(s for _, s in m.body)
    return PatchOp(file=m.file, line=start, end_line=end, original=original,
                   replacement=NL2.join(lines), kind="method",
                   reason="服务端校验结果伪造：直接返回成功结果，不发网络请求")


# ---------------------------------------------------------------------------
# 分类与打分
# ---------------------------------------------------------------------------

def _category(m: _Method, hits: list[tuple[str, str]]) -> str:
    for cat, _desc in hits:
        if cat:
            return cat
    blob = " ".join([m.cls_simple, m.name] + m.strings[:12])
    for cat, rx in _CAT_WORDS:
        if rx.search(blob):
            return cat
    return "通用判定"


def _score(m: _Method, strong: list[tuple[str, str]], weak: list[tuple[str, str]],
           bool_gate: bool, pre_run: bool, blocked: bool) -> tuple[int, list[str]]:
    """
    打分只看"强证据"，弱证据（字面量、API）只加分不改判定。

    强：类名/方法名命中授权、签名、卡密等规则
    闸门：返回值是常量布尔，或分支后接 return/exit
    """
    score, ev = 0, []
    if strong:
        cat, desc = strong[0]
        score += 35
        ev.append(f"命名 → {desc}")
        if len(strong) > 1:
            score += 8
            ev.append(f"另有 {len(strong) - 1} 处命名命中")
    if bool_gate:
        score += 25
        ev.append("结构 → 方法体内同时返回 0/1，是布尔闸门")
    elif m.branch:
        score += 8
        ev.append("结构 → 含条件分支，返回值决定走向")
    if m.exit_block:
        score += 10
        ev.append("结构 → 失败分支里有 finish/exit/throw 一类终止动作")
    code_strings = [s for s in m.strings if verify.code_like(s)]
    if code_strings:
        score += min(16, 8 * len(code_strings))
        ev.append("常量 → " + "、".join(f"「{s[:26]}」" for s in code_strings[:2]))
    if _CRYPTO_APIS.search(" ".join(m.calls) + " " + " ".join(t for _, t in m.body)):
        score += 10
        ev.append("接口 → 摘要/签名/网络/存储调用")
    if pre_run:
        score += 12
        ev.append("可达 → 启动路径上会被调用")
    if blocked:
        score += 5
        ev.append("可达 → 返回值参与启动阻断")
    if weak and not strong:
        score -= 6          # 只有字面量/字段命中，降权
    return max(0, min(score, 97)), ev



# ---------------------------------------------------------------------------
# 主分析
# ---------------------------------------------------------------------------

def analyze(smali_root: str | Path, max_files: int = 6000,
            min_confidence: int = 25) -> CheckpointReport:
    """
    扫描 smali 目录，返回按"启动前 + 置信度"排序的校验点。

    smali_root 一般是 apktool 解包目录（含 smali/ smali_classes2/ ...）。
    """
    import time
    t0 = time.time()
    root = Path(smali_root)
    rep = CheckpointReport(smali_root=str(root))

    if not root.exists():
        rep.errors.append(f"目录不存在：{root}")
        return rep

    # 允许直接传 apktool 根目录（smali / smali_classes2 / ...）或单个 smali 目录
    if root.name.startswith("smali"):
        dirs = [root]
    else:
        try:
            dirs = [d for d in root.iterdir()
                    if d.is_dir() and d.name.startswith("smali")]
        except OSError as e:
            rep.errors.append(f"读不了目录：{e}")
            return rep
        if not dirs:
            dirs = [root]

    files: list[Path] = []
    for d in dirs:
        files.extend(sorted(d.rglob("*.smali")))
    files = files[:max_files]
    rep.files = len(files)
    if not files:
        rep.errors.append("没有找到 .smali 文件。先用 apktool 解包 APK。")
        rep.elapsed = time.time() - t0
        return rep

    all_methods: list[_Method] = []
    supers: dict[str, str] = {}
    impls: dict[str, list[str]] = {}
    fields_of: dict[str, list[tuple[str, str]]] = {}
    for f in files:
        ms, cls, sup, imps, flds = _parse_file(f)
        all_methods.extend(ms)
        if cls:
            supers[cls] = sup
            if imps:
                impls[cls] = imps
            if flds:
                fields_of[cls] = flds
            rep.classes += 1
    rep.methods = len(all_methods)
    index = {m.key: m for m in all_methods}

    # 结果类：同时具备 ok()Z 方法和 int 成功标志字段的类（服务器校验结果）
    okz_cls = {mm.cls for mm in all_methods if mm.name == "ok" and mm.ret == "Z"
               and not mm.params}
    result_like: dict[str, tuple[list, list]] = {}
    for rcls in okz_cls:
        flds = fields_of.get(rcls, [])
        ok_f = [(n, t) for n, t in flds if n in _RESULT_OK_FIELDS]
        exp_f = [(n, t) for n, t in flds if n in _RESULT_EXPIRE_FIELDS]
        if ok_f:
            result_like[rcls] = (ok_f, exp_f)

    # ---- 调用图 ----
    callees: dict[str, set[str]] = {}
    callers: dict[str, set[str]] = {}
    for m in all_methods:
        for c in m.calls:
            callees.setdefault(m.key, set()).add(c)
            callers.setdefault(c, set()).add(m.key)

    # ---- 入口 ----
    entries: list[_Method] = []
    for m in all_methods:
        sup = supers.get(m.cls, "")
        is_entry_cls = sup in ENTRY_SUPERS or sup.startswith(UI_ACTIVITY_PREFIX)
        # 回调入口：Runnable.run / OnClickListener.onClick / 网络回调 onResponse…
        # 卡密闸门最常藏在这些匿名内部类里，生命周期入口够不着它们。
        is_cb = any(m.name in names
                    for itf, names in CALLBACK_ENTRIES.items()
                    if itf in impls.get(m.cls, ()))
        if m.name in ENTRY_NAMES and (is_entry_cls or m.name == "main"):
            entries.append(m)
        elif is_cb:
            entries.append(m)
    if not entries:
        entries = [m for m in all_methods if m.name == "main"][:50]
    rep.entries = [f"{m.cls_simple}.{m.name}" for m in entries[:12]]

    # BFS：记录最短链路与深度（深度即"离启动有多远"）
    depth: dict[str, int] = {}
    path: dict[str, str] = {}
    dq: deque[_Method] = deque()
    for e in entries:
        if e.key not in depth:
            depth[e.key] = 0
            path[e.key] = e.name
            dq.append(e)
    while dq:
        cur = dq.popleft()
        d = depth[cur.key]
        if d >= 6:
            continue
        for callee in callees.get(cur.key, ()):
            if callee in depth and depth[callee] <= d + 1:
                continue
            depth[callee] = d + 1
            path[callee] = f"{path[cur.key]} → {index[callee].name if callee in index else callee.split('->')[-1]}"
            if callee in index:
                dq.append(index[callee])

    # ---- 反射派发：混淆器把校验方法名藏进字符串，再用 Method.invoke 调 ----
    # 静态调用图在这里必断（invoke 的 Method 对象是运行时构造的），
    # 卡密判定就会"扫不到"。所以先把被点名的名字收齐，再在方法-level 认领。
    _REFLECT_NAME = re.compile(r"^[A-Za-z_$][\w$]{1,40}$")
    reflect_names: set[str] = set()
    for m in all_methods:
        for s in m.strings:
            t = s.strip()
            if not _REFLECT_NAME.match(t):
                continue
            if _VERB_NAME.match(t) or verify.match_method(t):
                reflect_names.add(t)

    # ---- 逐方法判定 ----
    cand: list[Checkpoint] = []
    for m in all_methods:
        strong: list[tuple[str, str]] = []
        weak: list[tuple[str, str]] = []
        # 类名只作"上下文"，不作单方法的强证据：
        # 否则 LicenseManager 里的 sha256/readCard 也会被当成校验点。
        cls_hit = verify.match_name(m.cls_simple)
        if cls_hit:
            weak.append(cls_hit)
        method_hit = verify.match_method(m.name)
        if method_hit:
            strong.append(method_hit)
        elif _VERB_NAME.match(m.name):
            strong.append(("授权校验", "方法名是校验动词（verify/check/isValid 一类）"))
        # 调用边证据传播：run()/onClick() 这类回调自己名字没特征，
        # 但它调用了 Cfg.license / isActivated —— 证据沿调用边传给调用者。
        seen_callees: set[str] = set()
        for call in m.calls[:40]:
            cname = call.split("->")[-1].split("(")[0]
            if cname in seen_callees or cname == m.name:
                continue
            seen_callees.add(cname)
            ch = verify.match_method(cname)
            if ch:
                callee_cls = call.split("->")[0].rstrip(";").split("/")[-1]
                strong.append((ch[0], f"调用了校验方法 {callee_cls}.{cname}"))
                if len(strong) >= 4:
                    break
        for s in m.strings[:20]:
            if not verify.code_like(s):
                continue
            hs = verify.match_name(s)
            if hs and hs not in weak:
                weak.append(hs)

        bool_gate = _bool_returns(m) if m.ret == "Z" else False
        api_hit = bool(_CRYPTO_APIS.search(" ".join(m.calls) + " "
                                          + " ".join(t for _, t in m.body)))

        # --- 防改动/防调试/防环境守卫 ---
        # 这类方法往往名字毫无特征（a/b/c 或 run），靠"它调了什么 API、
        # 比了什么常量"来认。重打包必然改变签名与 dex 字节，所以这些守卫
        # 一旦命中就必须中和，否则包能装、一开就退。
        body_text = "\n".join(t for _, t in m.body)
        ghits = guards.scan_method(body_text, " ".join(m.calls), m.strings)
        # 只有"会做判定"的方法才算守卫：算哈希/取签名串的工具方法（返回
        # String/byte[]）是守卫的**零件**，改它等于改坏别人的哈希结果。
        guard_hit = bool(ghits) and (m.ret in ("Z", "V", "I", "J")
                                     or bool(m.exit_block))
        if guard_hit:
            g0 = ghits[0]
            strong.insert(0, (g0.category, g0.why))
            for g in ghits[1:]:
                if (g.category, g.why) not in weak:
                    weak.append((g.category, g.why))

        # 反射派发点：方法名被常量点名 → 说明有地方在 invoke 它。
        # 这类逻辑改的是"被调的方法"本身，所以照样能中和，只是不进启动 BFS。
        reflect_hit = (m.name in reflect_names
                       and m.ret in ("Z", "V", "Ljava/lang/String;"))
        if reflect_hit and not strong:
            strong.append(("反射调用",
                           f"方法名被 const-string 点名（{m.name}），代码走反射调用"))

        # 中文卡密文案直接出现（"请输入卡密"/"验证并进入"）——
        # 这个方法所在的界面就是关卡页，比任何命名规则都硬。
        for s in m.strings[:20]:
            if _GATE_CN.search(s):
                strong.append(("授权校验", f"含卡密/激活类文案「{s[:18]}」"))
                break

        # 界面/日志类方法排除（除非名字本身就是校验命名）
        if not strong and _UI_WORDS.search(m.name):
            continue
        # 生命周期是"调用者"，不是校验点本身
        if not strong and _LIFECYCLE.match(m.name):
            continue
        # 纯 getter/setter 不参与（命名误报的主要来源）
        if m.name.startswith(("get", "set", "access$")) and not bool_gate:
            continue
        if m.name in ("<init>", "toString", "hashCode", "equals"):
            continue

        # 必须存在"闸门"：常量布尔返回 / 分支后接 return/终止 /
        # 名字就是"失效处理/复核"杀招（直线代码，没分支也要收）/
        # 名字带授权语义的 String 读取（Cfg.license 这类直线 SP 读取）/
        # 返回结果对象且名字是校验动词（verifySync 这类 try/catch 网络校验）
        killswitch = bool(strong) and bool(_KILLSWITCH_NAME.search(m.name))
        string_gate = (m.ret == "Ljava/lang/String;" and bool(strong))
        result_gate = (m.ret in result_like and bool(_VERB_NAME.match(m.name)))
        gate = (bool_gate or killswitch or string_gate or result_gate or guard_hit
                or reflect_hit
                or (m.branch and (bool(strong) or m.exit_block)))
        if not gate:
            continue
        # 证据最低要求：命名强命中，或 API+字面量双证
        if not (strong or bool_gate or (api_hit and weak)):
            continue
        # 非布尔返回值：命名强命中即可；对象返回还要能给出"改法"才纳入
        obj_gate = (m.ret == "Ljava/lang/String;"
                    or m.ret in result_like
                    or m.ret == "V")
        if m.ret not in ("Z", "I", "J", "V") and not obj_gate \
                and not _VERB_NAME.match(m.name):
            continue

        pre_run = m.key in depth
        blocked = False
        if pre_run:
            for ck in callers.get(m.key, ()):
                cm = index.get(ck)
                if cm and cm.branch:
                    blocked = True
                    break

        score, ev = _score(m, strong, weak, bool_gate, pre_run, blocked)
        if guard_hit:
            # 守卫不靠命名靠 API/常量，权重必须补上来 —— 漏掉一个
            # 签名自校验，整个重打包的包就是"装了必退"。
            score = min(97, score + 25)
            ev.append("守卫 → " + "；".join(
                f"{g.category}（{g.evidence[:24]}）" for g in ghits[:3]))
        if reflect_hit:
            score = min(97, score + 20)
            ev.append("反射 → 方法名出现在 const-string 里（调用图断链，靠点名认领）")
        if score < min_confidence:
            continue

        sugs: list[Suggestion] = []
        neg = _is_negative(m)
        # 生命周期方法里内联的守卫：清空 = 界面起不来，分支取反 = 可能正好改反。
        # 这种只报不改，留给人工/Frida，绝不放进无人值守的补丁方案。
        inline_guard = bool(guard_hit and _LIFECYCLE.match(m.name)
                            and m.ret == "V")
        if guard_hit and not inline_guard:
            g0 = ghits[0]
            if m.ret == "Z":
                # 方向：pass 型守卫（签名/完整性）要"通过"，false 型（root/模拟器/
                # 调试器）要"未命中"；名字是负面语义时把 pass 反过来。
                want = (g0.neutral == "pass") and not neg
                mt = _method_const_op(m, want)
                if mt:
                    sugs.append(Suggestion(
                        kind="guard_short",
                        label=f"{g0.category}中和：{m.name}() 恒返回 "
                              f"{'true' if want else 'false'}（{g0.evidence[:26]}）",
                        risk="低",
                        why=f"这是「{g0.category}」守卫：{g0.why}。"
                            "重打包必然改变签名与 dex 字节，这类判定一旦触发就是"
                            "闪退/弹窗/锁功能。整体短路保留方法签名与参数，"
                            "只让判定恒为「无问题」，调用方逻辑完全不受影响。",
                        op=mt))
            elif m.ret == "V":
                vp = _void_noop_op(m)
                if vp:
                    sugs.append(Suggestion(
                        kind="guard_noop",
                        label=f"{g0.category}中和：{m.name}() 清空 —— "
                              f"检测到也不再处置（{g0.evidence[:24]}）",
                        risk="低",
                        why=f"这是「{g0.category}」守卫，命中后的动作是"
                            "退出/弹窗/锁功能。清空方法体后检测照跑但不再执行处置；"
                            "void 方法清空不破坏调用方栈平衡，不会引起崩溃。",
                        op=vp))
        # ① 路由改道（const-class 换）：没卡密也直接进主界面，最稳
        sugs.extend(_reroute_ops(m))
        # ② 字符串闸门：空卡密默认值 → 非空，一处改动覆盖全部调用方
        if strong:
            sugs.extend(_string_gate_ops(m))
        # ③ 布尔闸门整体短路（方向按方法名区分）
        mt = _method_const_op(m, not neg)
        if mt and bool_gate:
            sugs.append(Suggestion(
                kind="method_false" if neg else "method_true",
                label=("整个方法强制返回 false（让 "
                       f"{m.name} 永远判否）") if neg else "整个方法强制返回 true",
                risk="低",
                why="保留方法签名与参数，只替换方法体。启动路径上的布尔校验用这招最稳，"
                    "不会破坏调用处的栈平衡。判定方向已按方法名区分："
                    + ("isExpired/isRooted 这类负面闸门要返回 false。"
                       if neg else "verify/isVip 这类正面闸门返回 true。"),
                op=mt))
        sugs.extend(_const_flag_ops(m) if not bool_gate else [])
        # ⑤ 服务端结果伪造：verify 类方法返回 Result 对象 → 直接造成功结果
        rlike = result_like.get(m.ret)
        if rlike and _VERB_NAME.match(m.name):
            fab = _fabricate_result_op(m, m.ret, rlike[0], rlike[1])
            if fab:
                sugs.append(Suggestion(
                    kind="fabricate_result",
                    label="服务器校验结果伪造：直接返回「已授权」结果，不发网络请求",
                    risk="中",
                    why="带服务器的卡密会先本地判断、再网络校验。伪造结果对象后，"
                        "服务器拒绝也当成功处理；配合「失效处理短路」补丁，"
                        "运行中的服务器复核同样被拦截。",
                    op=fab))
        # ⑥ 失效处理/复核杀招短路：服务器判失效也不停功能
        if m.ret == "V" and strong and (_KILLSWITCH_NAME.search(m.name)
                                        or (m.branch and _VERB_NAME.match(m.name)
                                            and not bool_gate)):
            vp = _void_noop_op(m)
            if vp:
                sugs.append(Suggestion(
                    kind="void_noop",
                    label=f"失效处理短路：{m.name}() 清空 —— 复核/失效判定不再执行",
                    risk="中",
                    why="带服务器的卡密在运行中会定期向服务器复核；判定失效就停功能。"
                        "把处理方法清空后，无论服务器怎么答，本地都照常运行。",
                    op=vp))
        sugs.extend(_branch_ops(m))
        # 去重（同一行只留一个建议）
        seen_lines = set()
        uniq = []
        for s in sugs:
            k = (s.op.line, s.kind)
            if k in seen_lines:
                continue
            seen_lines.add(k)
            uniq.append(s)

        cat = _category(m, strong + weak)
        note = ""
        if cat == "通用判定":
            note = ("未命中授权/卡密/签名等强特征，可能是功能开关或设备能力判定；"
                    "改之前先确认它是否真的决定启动。")
        if cat == "服务端校验":
            note = "本地只看到 HTTP 调用，改本地只能骗过界面，权益仍在服务端。"
        if inline_guard:
            # 生命周期内联守卫：给建议就会有人（或自动化）照着改，
            # 而这里最稳的改法恰恰是"别整体动它"。所以清空建议，只保留报告。
            uniq = []
            note = ("⚠ 防改动守卫内联在生命周期方法里（"
                    + "、".join(g.category for g in ghits) + "）。"
                    "整体清空会让界面起不来，自动补丁不敢碰；"
                    "要么用 Frida hook，要么手工找到判定分支单独放行。")
        if m.ret == "V" and not uniq:
            note = (note + " " if note else "") + "返回 void，无法直接短路；" \
                    "优先考虑改调用处的分支或 hook。"

        # 无人值守安全性：一键全流程只敢自动应用"确定性"补丁。
        # 路由改道/字符串闸门/结果伪造/失效短路是结构性的，直接放行；
        # 布尔闸门要看类别（通用判定/规则匹配类改了会误伤功能）；
        # invert/goto 只作人工备选，绝不自动应用。
        first = uniq[0].kind if uniq else ""
        _SAFE_KINDS = {"reroute", "const_string", "fabricate_result", "void_noop",
                       "guard_short", "guard_noop"}
        if first in _SAFE_KINDS:
            auto_safe = True
        elif first in ("method_true", "method_false", "const_flag"):
            auto_safe = (cat not in ("通用判定",)
                         or m.cls in result_like
                         or bool_gate and bool(strong))
        else:
            auto_safe = False

        cand.append(Checkpoint(
            cid="", cls=m.cls, cls_simple=m.cls_simple, method=m.name,
            signature=f"({m.params}){m.ret}", file=m.file, line=m.line,
            category=cat, confidence=score, pre_run=pre_run, evidence=ev,
            chain=path.get(m.key, ""), returns=m.ret, suggestions=uniq,
            strings=m.strings[:6], note=note.strip(),
            auto_safe=auto_safe,
            guard=guard_hit, guard_kind=(ghits[0].kind if ghits else ""),
            guard_neutral=(ghits[0].neutral if ghits else ""),
            inline_guard=inline_guard, indirect=reflect_hit))

    # 排序：守卫最前（漏一个就装了必退）→ 启动前优先 → 置信度 → 建议可用性
    cand.sort(key=lambda c: (not c.guard, not c.pre_run, -c.confidence,
                             not c.suggestions))
    for i, c in enumerate(cand, 1):
        c.cid = f"P{i:03d}"
    rep.points = cand
    rep.elapsed = time.time() - t0
    return rep


# ---------------------------------------------------------------------------
# 输出：补丁配方 / Frida 脚本 / 报告
# ---------------------------------------------------------------------------

def to_plan(rep: CheckpointReport, ids: list[str] | None = None,
            only_pre: bool = False, max_ops: int = 20,
            safe_only: bool = False,
            min_confidence: int = 0,
            include_running: bool = False,
            guards_only: bool = False) -> list[PatchOp]:
    """
    把选中的校验点变成补丁操作序列。

    safe_only=True 只收"无人值守安全"的点（不含 invert/goto 误伤类）；
    include_running=True 把非启动路径的杀招（服务器复核/失效处理）也收进来
    —— 那些不在启动 BFS 里，但运行中一定会触发。
    guards_only=True 只出防改动/防调试守卫（用于"我只要守卫"的场景，
    或指定 ids 时把守卫单独补进来 —— 漏一个守卫，包就是装了必退）。
    """
    if ids:
        pts = [rep.get(i) for i in ids]
    else:
        pts = []
        if only_pre:
            pts.extend(rep.pre_run)
            # 守卫与反射派发点必须无条件纳入：签名/调试器检测常跑在后台线程，
            # 卡密方法也可能被反射调用 —— 静态调用图断链 → 它们不在 pre_run 里，
            # 但一味漏掉就是"装了必退"或"改了没用"。
            have = {p.cid for p in pts}
            pts.extend(p for p in rep.points
                       if (p.guard or p.indirect) and p.cid not in have)
        if include_running:
            have = {p.cid for p in pts}
            pts.extend(p for p in rep.points if p.cid not in have)
        if not pts and not only_pre:
            pts = rep.points
    if guards_only:
        pts = [p for p in pts if p and p.guard]
    ops: list[PatchOp] = []
    for p in pts:
        if not p or not p.best:
            continue
        if safe_only and not p.auto_safe:
            continue
        if min_confidence and p.confidence < min_confidence:
            continue
        op = p.best.op
        op.reason = f"[{p.cid}] {p.category} · {p.cls_simple}.{p.method}：{p.best.label}"
        ops.append(op)
        if len(ops) >= max_ops:
            break
    return ops


# ---------------------------------------------------------------------------
# 兜底：摘除"拒绝运行"的终结动作
# ---------------------------------------------------------------------------
def plan_terminators(root: str | Path, *, keep_exit: bool = False,
                     keep_finish: bool = False,
                     max_ops: int = 240) -> tuple[list[PatchOp], dict]:
    """
    全包扫描终结动作，生成"换成 nop"的补丁。

    **与 patch_scan / to_plan 的根本区别**：不看这个方法有没有被识别成校验点。
    只要里面有 exit / killProcess，就摘。理由是：

        检测手法可以千变万化（换特征、加反射、藏 native、每次更新换一套），
        但"不让程序跑"这个结果，物理上只有那么几条路可走。

    所以这是兜底层：改判定那一层漏了、认错了、被加固挡住了，都还有这一层
    保底 —— 退出动作已经不存在，程序只能继续往下走。

    连带好处：中间套多少层包装都无效。作者写 Utils.check() → guard() →
    native 判定 → System.exit(0)，前面全是黑的，最后这一句还是白的。

    返回 (补丁列表, 统计)。
    """
    rt = Path(root)
    ops: list[PatchOp] = []
    stat = {"files": 0, "methods": 0, "exit": 0, "kill": 0, "finish": 0,
            "throw": 0, "hang": 0, "guarded_methods": 0, "applied": 0,
            "skipped_crash_handler": 0}

    if not rt.is_dir():
        return ops, stat

    for f in sorted(rt.rglob("*.smali")):
        try:
            methods, *_ = _parse_file(f)
        except Exception:                              # noqa: BLE001
            continue
        if not methods:
            continue
        stat["files"] += 1
        for m in methods:
            stat["methods"] += 1
            if not m.body:
                continue
            # 崩溃处理器里的 killProcess 是正常善后（进程已经要死了，
            # 杀掉是为了触发系统回收），摘掉它反而会让崩溃后卡成白屏。
            # 作者很少拿 uncaughtException 当反破解开关 —— 真要用也是
            # "检测到就主动 throw"，那种在调用侧，不在 handler 里。
            if m.name == "uncaughtException" or "uncaughtException" in m.params:
                stat["skipped_crash_handler"] += 1
                continue
            body_lines = [t for _, t in m.body]
            # 守卫上下文：这个方法自己就在做检测（决定 finish/throw 算不算）
            guarded = bool(guards.scan_method("\n".join(body_lines),
                                              " ".join(m.calls), m.strings))
            if guarded:
                stat["guarded_methods"] += 1
            for term in guards.find_terminators(body_lines, guarded=guarded):
                if term.kind in ("exit_proc", "kill_self"):
                    stat["exit" if term.kind == "exit_proc" else "kill"] += 1
                elif term.kind == "finish_kill":
                    stat["finish"] += 1
                elif term.kind == "throw_fatal":
                    stat["throw"] += 1
                elif term.kind == "hang":
                    stat["hang"] += 1

                # 只摘"换成 nop 一定安全"的：invoke 返回 void，后面没有 move-result
                if not term.nop_safe:
                    continue
                if keep_exit and term.kind in ("exit_proc", "kill_self"):
                    continue
                if keep_finish and term.kind == "finish_kill":
                    continue
                abs_line = m.body[term.line - 1][0]
                where = f"{m.cls_simple}.{m.name}"
                ops.append(PatchOp(
                    file=str(f), line=abs_line, end_line=abs_line,
                    original=term.text, replacement="    nop",
                    reason=f"摘除{term.category} · {where}（{term.why[:34]}）",
                    kind="nop_call"))
                stat["applied"] += 1
                if len(ops) >= max_ops:
                    return ops, stat
    return ops, stat


def _js_type(desc: str) -> str:
    """Java 类型描述符 → Frida overload 用的名字。"""
    prim = {"Z": "boolean", "B": "byte", "C": "char", "S": "short", "I": "int",
            "J": "long", "F": "float", "D": "double", "V": "void"}
    if desc in prim:
        return prim[desc]
    if desc.startswith("["):
        return _js_type(desc[1:]) + "[]"
    if desc.startswith("L") and desc.endswith(";"):
        return desc[1:-1].replace("/", ".")
    return desc


def _split_params(params: str) -> list[str]:
    out, i = [], 0
    while i < len(params):
        c = params[i]
        if c == "[":
            j = i
            while j < len(params) and params[j] == "[":
                j += 1
            if j < len(params) and params[j] == "L":
                k = params.find(";", j)
                k = len(params) - 1 if k == -1 else k
                out.append(params[i:k + 1])
                i = k + 1
            else:
                out.append(params[i:j + 1])
                i = j + 1
            continue
        if c == "L":
            k = params.find(";", i)
            k = len(params) - 1 if k == -1 else k
            out.append(params[i:k + 1])
            i = k + 1
            continue
        out.append(c)
        i += 1
    return out


def to_frida(rep: CheckpointReport, ids: list[str] | None = None) -> str:
    """
    生成 Frida 覆盖脚本（不改包，运行时替换返回值）。

    什么时候必须用它：包加了壳 / 代码抽取 / 守卫内联在 onCreate ——
    这些 smali 改不动，或者一改界面就起不来。挂这个脚本能先让程序跑起来，
    也能用来验证"改这里到底有没有用"。

    方向：守卫按 guard_neutral（pass→true / false→false），
    其他按方法名（isExpired/isRooted → false，verify/isVip → true）。
    void 守卫挂成空实现（检测照跑，不再弹窗/退出）。
    """
    if ids:
        pts = [rep.get(i) for i in ids]
    else:
        pts = list(rep.pre_run)
        have = {p.cid for p in pts if p}
        pts.extend(p for p in rep.points
                   if (p.guard or p.indirect) and p.cid not in have)
    lines = [
        "// ReverseForge 生成 · 校验点运行时覆盖",
        "// 用法：frida -U -f <包名> -l this.js --no-pause",
        "// 说明：布尔守卫恒返回「无问题」；void 守卫挂成空实现。",
        "Java.perform(function () {",
    ]
    n = 0
    for p in pts:
        if not p:
            continue
        if p.returns not in ("Z", "V"):
            continue
        cls = p.cls.strip("L;").replace("/", ".")
        params = _split_params(p.signature.split(")")[0].lstrip("("))
        overload = ", ".join(f'"{_js_type(x)}"' for x in params)
        if p.returns == "V":
            want = None
            body = "      console.log(\"[RF] " + p.cls_simple + "." + p.method + " 被调用（已空实现）\");"
        else:
            if p.guard and p.guard_neutral == "pass":
                want = True
            elif p.guard and p.guard_neutral == "false":
                want = False
            else:
                want = not bool(_NEG_WORDS.search(p.method))
            body = (f'      console.log("[RF] {p.cls_simple}.{p.method} 被调用，'
                    f'已返回 {"true" if want else "false"}");')
        var = f"C{p.cid[1:]}"
        lines.append(f"  // {p.cid} {p.category} 置信度 {p.confidence}"
                     + ("（守卫）" if p.guard else ""))
        lines.append("  try {")
        lines.append(f'    var {var} = Java.use("{cls}");')
        if overload:
            lines.append(f"    {var}.{p.method}.overload({overload}).implementation = function () {{")
        else:
            lines.append(f"    {var}.{p.method}.implementation = function () {{")
        lines.append(body)
        lines.append("      return" + (f" {'true' if want else 'false'};" if want is not None else ";"))
        lines.append("    };")
        lines.append(f"  }} catch (e) {{ console.log('[RF] 覆盖失败 {p.cid}：' + e); }}")
        n += 1
    lines.append(f"  console.log('[RF] 已挂载 {n} 个校验点');")
    lines.append("});")
    return chr(10).join(lines)


def report_md(rep: CheckpointReport, limit: int = 40) -> str:
    L = [f"# 校验点识别报告", "",
         f"> {rep.summary()}", ""]
    if rep.errors:
        L += ["## 问题", ""] + [f"- {e}" for e in rep.errors] + [""]
    if rep.entries:
        L += ["## 启动入口", "", "、".join(f"`{e}`" for e in rep.entries), ""]
    guards = [p for p in rep.points if p.guard]
    if guards:
        L += ["## 防改动 / 防调试守卫", "",
              "> 重打包必然改变签名与 dex 字节，这些判定一旦触发就是闪退/弹窗/锁功能。",
              ""]
        for p in guards[:limit]:
            tag = "（生命周期内联，只报不改）" if p.inline_guard else ""
            L.append(f"- {p.cid} `{p.cls_simple}.{p.method}` · {p.category}"
                     f" · 置信度 {p.confidence}{tag} → "
                     f"{p.best.label if p.best else '无自动改法'}")
        L.append("")
    L += ["## 启动路径上的校验点", ""]
    pre = rep.pre_run
    if not pre:
        L.append("（没有在启动路径上发现校验点；下面列出运行期命中项）")
    for p in pre[:limit]:
        L += [f"### {p.cid} · {p.cls_simple}.{p.method}", "",
              f"- 类别：{p.category}",
              f"- 置信度：{p.confidence}",
              f"- 签名：`{p.signature}`",
              f"- 位置：`{Path(p.file).name}:{p.line}`",
              f"- 链路：{p.chain or '（入口本身）'}"]
        if p.evidence:
            L.append("- 证据：" + "；".join(p.evidence))
        if p.note:
            L.append(f"- 注意：{p.note}")
        if p.best:
            L += ["", f"**建议**：{p.best.label}（风险 {p.best.risk}）", "",
                  "```smali", p.best.op.original.strip()[:600], "── 改为 ──",
                  p.best.op.replacement.strip()[:600], "```"]
        L.append("")
    rest = [p for p in rep.points if not p.pre_run][:limit]
    if rest:
        L += ["## 运行期命中（非启动路径）", ""]
        for p in rest:
            L.append(f"- {p.cid} `{p.cls_simple}.{p.method}` · {p.category} · "
                     f"置信度 {p.confidence} · {p.best.label if p.best else '仅识别'}")
    L += ["", "## 边界说明", "",
          "- 加固壳内的逻辑在 so 里，本报告看不到",
          "- 服务端校验改本地只能骗过界面",
          "- 反射/动态代理调用会让静态调用图断链，此时可结合 Frida 脚本验证"]
    return "\n".join(L)
