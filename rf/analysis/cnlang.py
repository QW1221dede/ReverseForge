#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 rf.analysis.cnlang · Java 表达式 → 中文伪代码
============================================================================

【它解决什么问题】
    方法头注释只能告诉你"这个方法是校验授权的"，但逆向时真正要看的是**条件**：
        为什么这里 return？哪个分支才是放行路径？阈值到底是多少？
    这些都在 if / for / switch 的括号里，全是英文和符号：

        if (mLicense == null || !mLicense.isValid() || System.currentTimeMillis() > exp) return false;

    本模块把它变成：

        如果 「授权对象」 等于 空 或 不是 「授权对象」.是否有效() 或 当前时间戳 大于 「到期时间」
        则返回 假

【翻译策略：结构优先，语义兜底】
    1. 先按运算符优先级拆（|| → && → 比较 → 加减），保证括号里的逻辑关系不翻错。
    2. 原子部分交给词典（lexicon）。
    3. 词典查不到（R8 混淆后的 a/b/c）就原样保留 —— 保留原名比编一个中文名字更有用。

【必须说明的边界】
    这是**词法级**翻译，不是语义理解：
      · 语序照英文顺序保留，读起来是"电报体"，不是通顺句子
      · 变量名混淆（a、x0）时，翻译结果里就是 a、x0，语义无从推断
      · 平台方法靠 METHOD_CN 表覆盖，表里没有的会保留英文方法名
    所以注释里凡是推断出来的内容，都带「」标注，和"结构事实"区分开。
============================================================================
"""

from __future__ import annotations

import re

from .lexicon import translate_name

# ---------------------------------------------------------------------------
# Java 标准方法名 → 中文（这些出现频率极高，逐词拼会很别扭）
# ---------------------------------------------------------------------------

METHOD_CN: dict[str, str] = {
    "equals": "等于", "equalsIgnoreCase": "忽略大小写等于",
    "length": "长度", "size": "个数", "isEmpty": "是否为空",
    "contains": "包含", "startsWith": "以…开头", "endsWith": "以…结尾",
    "matches": "匹配", "indexOf": "首次位置", "substring": "截取子串",
    "trim": "去首尾空白", "toLowerCase": "转小写", "toUpperCase": "转大写",
    "split": "按分隔符切开", "replace": "替换", "replaceAll": "全部替换",
    "getString": "取字符串", "getInt": "取整数", "getLong": "取长整数",
    "getBoolean": "取布尔值", "getFloat": "取浮点数",
    "putString": "存字符串", "putInt": "存整数", "putBoolean": "存布尔值",
    "putBool": "存布尔值", "getBool": "取布尔值", "putLong": "存长整数",
    "getLong": "取长整数", "putFloat": "存浮点数", "getFloat": "取浮点数",
    "getOrDefault": "取或默认", "computeIfAbsent": "缺失时计算并写入",
    "charAt": "取第几个字符", "isDigit": "是否数字", "isLetter": "是否字母",
    "getBytes_": "取字节", "hashCode": "取哈希值", "compareTo": "比较",
    "toCharArray": "转字符数组", "getCanonicalPath": "取规范路径",
    "putLong": "存长整数", "getAll": "取全部", "remove": "移除", "clear": "清空",
    "apply": "提交保存", "commit": "提交并等待落盘",
    "valueOf": "转成", "parseInt": "转整数", "parseLong": "转长整数",
    "toString": "转字符串", "getBytes": "取字节数组", "toByteArray": "转字节数组",
    "getMessage": "取异常消息", "printStackTrace": "打印堆栈",
    "getCause": "取原因", "getClass": "取类",
    "now": "当前时间", "currentTimeMillis": "当前时间戳",
    "getInstance": "获取实例", "getDefault": "获取默认实例",
    "format": "格式化", "append": "追加", "insert": "插入",
    "close": "关闭", "flush": "刷新缓冲区", "read": "读取", "write": "写入",
    "exists": "是否存在", "mkdirs": "创建目录", "delete": "删除", "renameTo": "重命名",
    "run": "执行", "call": "调用", "execute": "执行", "start": "启动",
    "join": "等待线程结束", "sleep": "休眠", "wait": "等待", "notify": "唤醒",
    "log": "记录日志", "d": "调试日志", "e": "错误日志", "i": "信息日志",
    "w": "警告日志", "v": "详细日志", "println": "打印一行",
    "show": "显示", "dismiss": "关闭", "finish": "结束页面",
    "findViewById": "按 ID 找控件", "setText": "设置文本", "getText": "取文本",
    "setVisibility": "设置可见性", "setOnClickListener": "设置点击监听",
    "getPackageName": "取包名", "getPackageInfo": "取包信息",
    "getSignature": "取签名", "toCharsString": "转十六进制字符串",
    "checkPermission": "检查权限", "checkSelfPermission": "检查自身权限",
    "getSystemService": "取系统服务", "getSharedPreferences": "取偏好设置",
    "getApplicationContext": "取应用上下文", "getResources": "取资源",
    "getAssets": "取资产目录", "openFileOutput": "打开私有输出流",
    "getFileStreamPath": "取私有文件路径", "loadLibrary": "加载原生库",
    "exec": "执行命令", "getRuntime": "取运行时", "exit": "退出进程",
    "getProperty": "取系统属性", "getenv": "取环境变量",
}

# 平台常量/静态字段：整串命中优先于逐段翻译
CONST_CN: dict[str, str] = {
    "Build.VERSION.SDK_INT": "系统版本号",
    "Build.MODEL": "机型",
    "Build.BRAND": "品牌",
    "Build.MANUFACTURER": "厂商",
    "Build.DEVICE": "设备代号",
    "Build.SERIAL": "设备序列号",
    "Build.FINGERPRINT": "系统指纹",
    "Build.PRODUCT": "产品名",
    "Build.HARDWARE": "硬件名",
    "Build.TAGS": "构建标签",
    "Build.TYPE": "构建类型",
    "Integer.MAX_VALUE": "整数最大值",
    "Integer.MIN_VALUE": "整数最小值",
    "Long.MAX_VALUE": "长整数最大值",
    "Boolean.TRUE": "真",
    "Boolean.FALSE": "假",
    "TextUtils.isEmpty": "是否为空",
    "System.currentTimeMillis": "当前时间戳",
    "System.nanoTime": "高精度计时",
    "SystemClock.elapsedRealtime": "开机以来毫秒数",
    "Looper.getMainLooper": "主线程 Looper",
    "Thread.currentThread": "当前线程",
    "String.format": "格式化字符串",
    "Log.i": "信息日志", "Log.d": "调试日志", "Log.e": "错误日志",
    "Log.w": "警告日志", "Log.v": "详细日志",
    "PackageManager.GET_SIGNATURES": "取签名标志",
    "PackageManager.GET_SIGNING_CERTIFICATES": "取签名证书标志",
    "Context.MODE_PRIVATE": "私有模式",
}

# 比较运算符 → 中文（长的必须在前，否则 `>` 会先把 `>=` 吃掉）
_CMP_OPS: list[tuple[str, str]] = [
    (">=", " 大于或等于 "), ("<=", " 小于或等于 "),
    ("==", " 等于 "), ("!=", " 不等于 "),
    (">", " 大于 "), ("<", " 小于 "),
]

_ARITH_OPS: list[tuple[str, str]] = [
    ("+=", "+="), ("-=", "-="), ("*=", "*="), ("/=", "/="), ("%=", "%="),
    ("+", " 加 "), ("-", " 减 "), ("*", " 乘 "), ("/", " 除以 "), ("%", " 对 ",),
]

# 表达式里出现这些词，说明是校验/鉴权语境，注释可以加一句用途提示
_VERIFY_HINT: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(?i)licen[cs]|activat|serial|cdkey|receipt|purchase|subscri|entitle|vip|premium|trial"),
     "授权/付费判定"),
    (re.compile(r"(?i)signature|sign|digest|sha|md5|crc|integrity|tamper|checksum"),
     "签名/完整性判定"),
    (re.compile(r"(?i)\broot\b|magisk|xposed|frida|emulator|debugger|ptrace|hook"),
     "运行环境判定（防逆向/防多开）"),
    (re.compile(r"(?i)token|auth|session|login|jwt|oauth|bearer"),
     "身份鉴权判定"),
    (re.compile(r"(?i)expire|expiry|valid_?until|deadline|remain"),
     "有效期判定"),
]


# ---------------------------------------------------------------------------
# 词法工具
# ---------------------------------------------------------------------------

def _strip_outer(s: str) -> str:
    """去掉整串外层括号：(a && b) → a && b"""
    s = s.strip()
    while s.startswith("(") and s.endswith(")"):
        depth = 0
        ok = True
        for i, ch in enumerate(s):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0 and i != len(s) - 1:
                    ok = False
                    break
        if not ok:
            break
        s = s[1:-1].strip()
    return s


def _split_top(s: str, op: str) -> list[str]:
    """
    在括号/字符串之外按 op 切分（保留嵌套）。
    "a && (b || c)" 按 "&&" 切 → ["a ", " (b || c)"]
    """
    parts: list[str] = []
    depth = 0
    buf: list[str] = []
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c == '"':
            buf.append(c)
            i += 1
            while i < n:
                buf.append(s[i])
                if s[i] == "\\":
                    if i + 1 < n:
                        buf.append(s[i + 1])
                    i += 2
                    continue
                if s[i] == '"':
                    i += 1
                    break
                i += 1
            continue
        if c == "'":
            j = i + 1
            while j < n and s[j] != "'":
                j += 1
            buf.append(s[i:j + 1])
            i = j + 1
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        if depth == 0 and s.startswith(op, i):
            # `==` 不能被 `=` 之类误切：op 由调用方保证顺序
            parts.append("".join(buf))
            buf = []
            i += len(op)
            continue
        buf.append(c)
        i += 1
    parts.append("".join(buf))
    return parts


def _split_args(s: str) -> list[str]:
    """按顶层逗号切参数表。"""
    return [x for x in _split_top(s, ",") if x.strip()]


def _split_chain(s: str) -> list[str]:
    """
    在顶层（括号/方括号/字符串之外）按 '.' 切开调用链。
    getPackageManager().getPackageInfo(x, 64)
        → ["getPackageManager()", "getPackageInfo(x, 64)"]
    注意不切 1.5 这种小数：含 '.' 且两侧都是数字时跳过。
    """
    parts: list[str] = []
    depth = 0
    buf: list[str] = []
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c == '"':
            j = i + 1
            while j < n:
                if s[j] == "\\":
                    j += 2
                    continue
                if s[j] == '"':
                    break
                j += 1
            buf.append(s[i:j + 1])
            i = j + 1
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        if c == "." and depth == 0:
            prev = s[i - 1] if i else ""
            nxt = s[i + 1] if i + 1 < n else ""
            if prev.isdigit() and nxt.isdigit():
                buf.append(c)
                i += 1
                continue
            parts.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(c)
        i += 1
    parts.append("".join(buf))
    return [p for p in parts if p.strip()]


# ---------------------------------------------------------------------------
# 原子翻译
# ---------------------------------------------------------------------------

# 这些标识符翻成中文没信息量，反而让读者无法和代码对应：
#   `if (str == null)` 注释成"如果 字符串 等于 空"，回头找不到 str 在哪
_KEEP_RAW = frozenset({
    "str", "strs", "string", "obj", "o", "v", "val", "value_",
    "sb", "buf", "tmp", "t", "e", "ex", "it", "iterator",
})


def _cn_ident(chain: str) -> str:
    """标识符链：a.b.c / mLicense.isValid / Build.VERSION.SDK_INT"""
    chain = chain.strip()
    if chain in CONST_CN:
        return CONST_CN[chain]
    # 去掉 this. 前缀
    if chain.startswith("this."):
        chain = chain[5:]
    if chain == "this":
        return "本对象"
    if chain == "null":
        return "空"
    if chain == "true":
        return "真"
    if chain == "false":
        return "假"

    segs = chain.split(".")
    out: list[str] = []
    for idx, seg in enumerate(segs):
        if not seg:
            continue
        if seg in CONST_CN:
            out.append(CONST_CN[seg])
            continue
        if len(seg) == 1 or seg in _KEEP_RAW:
            # 单字母：循环变量 i/j/k，或 R8 混淆名。翻译它只会出错
            # （METHOD_CN 里 "i" 是 Log.i 的"信息日志"，会把 `i + 1` 读成"信息日志+1"）
            out.append(seg)
            continue
        cn = METHOD_CN.get(seg) or translate_name(seg)
        out.append(cn if cn else seg)
    # 变量名（首段）如果没翻出来，加「」表示这是个代号，不是词
    if out and out[0] == segs[0] and len(segs) > 1 and re.match(r"^[a-z_$][\w$]*$", segs[0]):
        out[0] = f"「{segs[0]}」"
    return ".".join(out)


def cn_expr(expr: str, _depth: int = 0) -> str:
    """
    表达式 → 中文。_depth 限制递归深度，防止异常输入把栈打穿。
    """
    s = _strip_outer(expr)
    if not s:
        return ""
    if _depth > 6:
        return s

    # 三元 a ? b : c
    if "?" in s and ":" in s:
        left, _, rest = s.partition("?")
        mid, _, right = rest.rpartition(":")
        if left.strip() and right.strip():
            return (f"若 {cn_expr(left, _depth + 1)} 则为 {cn_expr(mid, _depth + 1)}，"
                    f"否则 {cn_expr(right, _depth + 1)}")

    # 逻辑或 → 且（优先级最低的先拆）
    for op, word in (("||", " 或 "), ("&&", " 且 ")):
        parts = _split_top(s, op)
        if len(parts) > 1:
            return word.join(_nonempty(cn_expr(p, _depth + 1) for p in parts))

    # instanceof
    m = re.match(r"^(.+?)\s+instanceof\s+([\w.$\[\]<>]+)$", s)
    if m:
        return f"{cn_expr(m.group(1), _depth + 1)} 是否属于 {m.group(2)}"

    # 比较
    for op, word in _CMP_OPS:
        parts = _split_top(s, op)
        if len(parts) == 2:
            a = cn_expr(parts[0], _depth + 1)
            b = cn_expr(parts[1], _depth + 1)
            if a and b:
                return f"{a}{word}{b}"

    # 取反
    if s.startswith("!") and not s.startswith("!="):
        return "不是 " + cn_expr(s[1:], _depth + 1)

    # 算术 / 赋值
    for op, word in _ARITH_OPS:
        parts = _split_top(s, op)
        if len(parts) == 2:
            a = cn_expr(parts[0], _depth + 1)
            b = cn_expr(parts[1], _depth + 1)
            if a and b:
                return f"{a}{word}{b}"

    # new X(...)
    m = re.match(r"new\s+([\w.$]+)\s*(\((.*)\))?$", s, re.S)
    if m:
        t = m.group(1).split(".")[-1]
        args = _split_args(m.group(3) or "")
        if args:
            return f"新建 {t}（{'、'.join(_nonempty(cn_expr(a, _depth + 1) for a in args))}）"
        return f"新建 {t}"

    # 强转 (Type) x
    m = re.match(r"^\(\s*([A-Z][\w.$]*)\s*\)\s*(.+)$", s, re.S)
    if m:
        return f"把 {cn_expr(m.group(2), _depth + 1)} 视为 {m.group(1).split('.')[-1]}"

    # 调用链：getPackageManager().getPackageInfo(...) —— 必须先把顶层点切开，
    # 否则正则会把第一个括号当成整个表达式的参数表，后半截漏成英文
    if "(" in s:
        chain = _split_chain(s)
        if len(chain) > 1:
            return ".".join(_nonempty(cn_expr(p, _depth + 1) for p in chain))

    # 方法调用：接收者.方法(参数)
    m = re.match(r"^([\w.$\[\]]+)\s*\((.*)\)$", s, re.S)
    if m:
        callee, args_s = m.group(1), m.group(2)
        args = _split_args(args_s)
        args_cn = ", ".join(_nonempty(cn_expr(a, _depth + 1) for a in args))

        # 整串在常量表里（TextUtils.isEmpty / System.currentTimeMillis）
        # 必须先查，否则会被拆成"文本工具.是否为空"，读起来像另一个东西
        if callee in CONST_CN:
            return f"{CONST_CN[callee]}({args_cn})" if args else f"{CONST_CN[callee]}()"

        if "." in callee:
            recv, _, meth = callee.rpartition(".")
            recv_cn = _cn_ident(recv)
            meth_cn = (meth if len(meth) == 1
                       else (METHOD_CN.get(meth) or translate_name(meth) or meth))
            head = f"{recv_cn}.{meth_cn}"
        else:
            head = (callee if len(callee) == 1
                    else (METHOD_CN.get(callee) or translate_name(callee) or callee))
        if args:
            return f"{head}({args_cn})"
        return f"{head}()"

    # 字符串字面量
    m = re.match(r'^"((?:[^"\\]|\\.)*)"$', s)
    if m:
        txt = m.group(1).replace("\\n", " ").replace("\\t", " ").strip()
        return f"「{txt[:30]}」" if txt else "空串"

    # 括号内还剩表达式
    if s.startswith("(") and s.endswith(")"):
        return cn_expr(s[1:-1], _depth + 1)

    # 数字 / 普通标识符
    if re.match(r"^-?\d+(\.\d+)?[LlFfDd]?$", s):
        return s.rstrip("LlFfDd")
    if re.match(r"^[A-Za-z_$][\w$.]*$", s):
        return _cn_ident(s)

    return s


def _nonempty(it) -> list[str]:
    return [x for x in it if x]


def cn_verify_hint(expr: str) -> str:
    """判断表达式属于哪类校验语境，给注释加一句用途。"""
    for rx, hint in _VERIFY_HINT:
        if rx.search(expr):
            return hint
    return ""


# ---------------------------------------------------------------------------
# 语句 → 中文
# ---------------------------------------------------------------------------

_LOOP_FOR = re.compile(
    r"^for\s*\(\s*([\w.$<>\[\]]+)\s+(\w+)\s*=\s*([^;]+);\s*"
    r"(\w+)\s*(<=?|>=?)\s*([^;]+);\s*([\w.$]+)\s*(\+\+|--|\+=\s*\d+|-=\s*\d+)?\s*\)"
)
_LOOP_EACH = re.compile(r"^for\s*\(\s*([\w.$<>\[\]]+)\s+(\w+)\s*:\s*(.+?)\s*\)")
_IF = re.compile(r"^(?:\}\s*)?if\s*\((.*)\)\s*\{?\s*$")
_ELSE_IF = re.compile(r"^(?:\}\s*)?else\s+if\s*\((.*)\)\s*\{?\s*$")
_WHILE = re.compile(r"^while\s*\((.*)\)\s*\{?\s*$")
_DO = re.compile(r"^do\s*\{?\s*$")
_SWITCH = re.compile(r"^switch\s*\((.*)\)\s*\{?\s*$")
_CASE = re.compile(r"^case\s+(.+?)\s*:\s*$")
_CATCH = re.compile(r"^(?:\}\s*)?catch\s*\(\s*([\w.$]+)\s+(\w+)\s*\)\s*\{?\s*$")
_THROW = re.compile(r"^throw\s+(.+?);\s*$")
_RETURN = re.compile(r"^return\s*(.*?);\s*$")
_SYNC = re.compile(r"^synchronized\s*\((.*)\)\s*\{?\s*$")
_IF_RET = re.compile(r"^if\s*\((.*)\)\s*(return[ 	]*[^;]*;|throw[ 	]*[^;]*;)\s*$")


def _loop_desc(m: re.Match) -> str:
    var = m.group(2)
    start = cn_expr(m.group(3))
    op = m.group(5)
    end = cn_expr(m.group(6))
    step = m.group(8) or ""
    step_cn = "每次 +1" if step == "++" else ("每次 -1" if step == "--" else (f"每次 {step}" if step else ""))
    rel = "小于" if op == "<" else ("小于或等于" if op == "<=" else ("大于" if op == ">" else "大于或等于"))
    tail = f"，{step_cn}" if step_cn else ""
    return f"循环：{var} 从 {start} 开始，直到 {var} {rel} {end}{tail}"


def cn_stmt(line: str, indent_hint: bool = True) -> str | None:
    """
    一行 Java 语句 → 中文说明。返回 None 表示这行不值得注释（不插注释）。

    只处理控制流与返回/抛出，不处理普通赋值 —— 那种注释是噪音。
    """
    s = line.strip()
    if not s or s in ("{", "}", "};"):
        return None
    # 去掉行尾注释已经由上游处理；这里只保证行首关键字能对上
    s = re.sub(r"\s*\{\s*$", " {", s)

    if _IF_RET.match(s):
        m = _IF_RET.match(s)
        cond = cn_expr(m.group(1))
        act = m.group(2)
        if act.startswith("return"):
            rhs = act[6:].strip().rstrip(";").strip()
            tail = "（即不通过）" if rhs in ("false", "null", "0", "-1", '""') else ""
            return f"如果 {cond} 则直接返回 {cn_expr(rhs) if rhs else '空'}{tail}"
        return f"如果 {cond} 则抛出异常：{cn_expr(act[5:].strip().rstrip(';'))}"

    block = s.rstrip().endswith("{")
    m = _ELSE_IF.match(s)
    if m:
        h = cn_verify_hint(m.group(1))
        tail = " 则走下列分支" if block else " 则执行下一句"
        return f"否则如果 {cn_expr(m.group(1))}{tail}" + (f" —— {h}" if h else "")
    m = _IF.match(s)
    if m:
        h = cn_verify_hint(m.group(1))
        tail = " 则进入下列分支" if block else " 则执行下一句"
        return f"如果 {cn_expr(m.group(1))}{tail}" + (f" —— {h}" if h else "")
    if s.startswith("else") and "{" in s:
        return "否则（以上条件都不满足）"

    m = _LOOP_FOR.match(s)
    if m:
        return _loop_desc(m)
    m = _LOOP_EACH.match(s)
    if m:
        return f"遍历 {cn_expr(m.group(3))}，逐个取出 {m.group(2)}"
    m = _WHILE.match(s)
    if m:
        return f"当 {cn_expr(m.group(1))} 时反复执行"
    if _DO.match(s):
        return "先执行一遍，再按 while 条件决定是否继续"
    m = _SWITCH.match(s)
    if m:
        return f"按 {cn_expr(m.group(1))} 的值分支处理"
    m = _CASE.match(s)
    if m:
        raw = m.group(1).strip()
        if raw == "default":
            return None
        return f"分支 {cn_expr(raw)}："

    m = _CATCH.match(s)
    if m:
        return f"捕获到 {m.group(1).split('.')[-1]}（{m.group(2)}）时走这里"
    if s.startswith("try") and "{" in s:
        return "尝试执行（异常由后续 catch 接住）"
    if s.startswith("finally") and "{" in s:
        return "收尾：无论成败都会执行"

    m = _THROW.match(s)
    if m:
        return f"抛出异常：{cn_expr(m.group(1))}"
    m = _RETURN.match(s)
    if m:
        rhs = m.group(1).strip()
        if not rhs:
            return "直接返回"
        return f"返回 {cn_expr(rhs)}"

    m = _SYNC.match(s)
    if m:
        return f"加锁 {cn_expr(m.group(1))} 后执行"

    return None


def cn_call_brief(expr: str) -> str:
    """
    把一个调用表达式压成短语，用于方法体的"步骤摘要"。
    getSharedPreferences("cfg", 0) → 取偏好设置(「cfg」、0)
    """
    return cn_expr(expr.strip())
