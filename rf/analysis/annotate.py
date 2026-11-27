#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 rf.analysis.annotate · 中文注释器
============================================================================

【它做什么】
    给 jadx 反编译出来的 Java 源码，按「类 / 方法」两级插入中文注释：

        // 【类】a —— 疑似 R8 混淆的合成类
        //   实现：Runnable（异步任务包装）
        //   推断：R8 把 lambda 折叠成的合成类，真正逻辑在外部 lambda$ 方法里
        //
        // 【方法 run】异步任务主体
        //   调用：BootReceiver.lambda$onReceive$0, MainActivity.lambda$downloadAndInstall$37
        //   ⚠ 风险：下载并安装 APK（静默安装/提权）

    注释是**插在原有代码行之前**，一行源码都不改 —— 保证改完还能编译、能对照。

【怎么推断（三层，从硬到软）】
    第一层 · 结构事实（100% 可靠）
        类名、父类、实现接口、字段类型、方法签名、@Override 目标。
        这些直接写进注释，不叫"推断"，叫"陈述"。
    第二层 · API 调用特征（可靠度高）
        方法体里出现 Cipher.getInstance → 加解密；
        Runtime.exec / ProcessBuilder → 执行系统命令；
        Class.forName + getDeclaredMethod → 反射；
        DexClassLoader → 动态加载代码（脱壳/插件化/恶意载荷常用）。
        命中就给对应中文描述，并附风险等级。
    第三层 · 命名语义（仅供参考）
        把方法名拆词查词典（downloadAndInstall → 下载 并 安装）。
        混淆后的名字（a/b/c、x0/y1）会标成「混淆名，无语义」。

【关于"翻译出源码"的边界】
    jadx 产出的是**等价 Java 源码**（从字节码还原），不是开发者的原始文件：
    局部变量名、注释、泛型细节、原始类名都会丢失或被重命名。
    这个模块是让还原结果**可读**，不是把混淆名变回原名 —— 后者理论上做不到。
============================================================================
"""

from __future__ import annotations

import re
from bisect import bisect_right
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

# 词典与命名翻译独立成模块（cnlang 也要用，放这里会循环导入）。
# 下面这几个名字在本模块内继续可直接使用，老的调用方不受影响。
from .lexicon import PHRASE_CN, WORD_CN, cn_literal, split_words, translate_name

# ---------------------------------------------------------------------------
# API 特征库：(正则, 中文说明, 风险等级)
#   风险等级："" 中性 / "注意" / "高危"
# ---------------------------------------------------------------------------

API_RULES: list[tuple[str, str, str]] = [
    # ——— 危险能力 ———
    (r"\bRuntime\.getRuntime\(\)\.exec|\bProcessBuilder\b", "执行系统命令（shell/exec）", "高危"),
    (r"\bsu\b\s*[\"']|\bsuperuser\b|/system/(x)?bin/su", "提权到 root（调用 su）", "高危"),
    (r"\bDexClassLoader\b|\bPathClassLoader\b|\bInMemoryDexClassLoader\b", "动态加载外部代码（DEX/APK 热更新或载荷）", "高危"),
    (r"\bClass\.forName\b|\bgetDeclaredMethod\b|\bgetDeclaredField\b|\bsetAccessible\s*\(\s*true", "反射调用（常用来隐藏真实调用目标）", "注意"),
    (r"\bAccessibilityService\b|\bperformGlobalAction\b|\bdispatchGesture\b", "无障碍服务（可模拟点击/读取屏幕内容）", "高危"),
    (r"DeviceAdminReceiver|\bDevicePolicyManager\b|\bresetPassword\b|\blockNow\b", "设备管理器（锁屏/改密码/擦除）", "高危"),
    (r"\bContentResolver\b.*sms|\bSmsManager\b|content://sms", "短信读写/发送", "高危"),
    (r"\bNotificationListenerService\b", "监听全部通知", "高危"),
    (r"android\.provider\.Settings\$System|\bWRITE_SECURE_SETTINGS\b", "修改系统设置", "高危"),
    (r"\bMediaRecorder\b|\bAudioRecord\b", "录音", "注意"),
    (r"\bCameraManager\b|android\.hardware\.Camera", "调用相机", "注意"),
    (r"\bLocationManager\b|FusedLocationProvider|\brequestLocationUpdates\b", "获取定位", "注意"),
    (r"\bgetDeviceId\b|\bgetImei\b|\bgetSubscriberId\b|\bgetSimSerialNumber\b", "读取设备唯一标识", "注意"),
    (r"\bgetInstalledPackages\b|\bgetInstalledApplications\b", "枚举已安装应用", "注意"),
    (r"\bClipboardManager\b|\bgetPrimaryClip\b", "读取剪贴板", "注意"),
    (r"android\.accounts|\bAccountManager\b", "读取账号列表", "注意"),
    (r"\bPackageInstaller\b|ACTION_INSTALL_PACKAGE|\binstallPackage\b", "安装应用（可能静默）", "高危"),
    (r"\bpm\s+(install|uninstall)\b|\bpm grant\b|\bsetprop\b", "通过 shell 改包状态/属性", "高危"),
    # ——— 加解密 ———
    (r"\bCipher\.getInstance\b", "对称/非对称加解密（Cipher）", ""),
    (r"\bMessageDigest\.getInstance\b", "计算消息摘要（MD5/SHA）", ""),
    (r"\bSecretKeySpec\b|\bIvParameterSpec\b|\bGCMParameterSpec\b", "构造密钥/初始向量", ""),
    (r"\bKeyStore\b|\bKeyGenerator\b|\bKeyPairGenerator\b", "密钥库/密钥生成", ""),
    (r"\bBase64\b", "Base64 编解码（常见于混淆载荷）", ""),
    (r"\bMac\.getInstance\b|\bHmacSHA", "HMAC 校验", ""),
    # ——— 网络 ———
    (r"\bHttpURLConnection\b|\bOkHttpClient\b|\bRetrofit\b|\bVolley\b", "发起 HTTP 网络请求", ""),
    (r"\bSocket\b|\bServerSocket\b|\bDatagramSocket\b", "原始 Socket 通信", "注意"),
    (r"\bWebView\b|\bloadUrl\b|\baddJavascriptInterface\b", "内置浏览器（addJavascriptInterface 有注入风险）", "注意"),
    (r"\bSSLSocketFactory\b|\bTrustManager\b|\bHostnameVerifier\b", "自定义 TLS 校验（可能关闭证书校验）", "注意"),
    # ——— 存储 / 文件 ———
    (r"\bSharedPreferences\b", "键值对配置存储", ""),
    (r"\bSQLiteDatabase\b|\bSQLiteOpenHelper\b", "本地数据库读写", ""),
    (r"\bFileInputStream\b|\bFileOutputStream\b|\bRandomAccessFile\b", "文件读写", ""),
    (r"\bgetExternalStorageDirectory\b|\bEnvironment\.getExternal", "访问外部存储", ""),
    (r"\bZipInputStream\b|\bZipOutputStream\b|\bZipFile\b", "ZIP 打包/解包", ""),
    # ——— 界面 / 生命周期 ———
    (r"\bAlertDialog\b|\bsetPositiveButton\b", "弹对话框", ""),
    (r"\bToast\.makeText\b", "弹提示条", ""),
    (r"\bstartActivity\b|\bstartActivityForResult\b", "跳转页面", ""),
    (r"\bsendBroadcast\b|\bregisterReceiver\b", "广播收发", ""),
    (r"\bHandler\b|\bpostDelayed\b|\brunOnUiThread\b", "线程间消息投递", ""),
    (r"\bAsyncTask\b|\bExecutorService\b|\bThread\s*\(", "后台线程执行", ""),
    # ——— 系统 ———
    (r"\bPowerManager\b|\bWakeLock\b|\bnewWakeLock\b", "电源管理/唤醒锁（保持 CPU 不休眠）", ""),
    (r"\bAlarmManager\b|\bsetRepeating\b|\bsetExactAndAllowWhileIdle\b", "定时任务/闹钟（常驻后台）", "注意"),
    (r"\bJobScheduler\b|\bJobService\b|\bWorkManager\b", "系统调度任务", ""),
    (r"\bBuild\.(MODEL|BRAND|MANUFACTURER|SERIAL)\b", "读取机型/品牌/序列号（设备指纹）", ""),
    (r"\bTelephonyManager\b", "读取运营商/网络信息", "注意"),
    (r"\bWifiManager\b|\bgetConnectionInfo\b", "读取 WiFi 信息", "注意"),
    (r"\bActivityManager\b|\bgetRunningAppProcesses\b", "读取运行中进程", "注意"),
    (r"\bUsageStatsManager\b", "读取应用使用记录", "注意"),
    (r"\bInstrumentation\b|\battachBaseContext\b", "进程/上下文接管（加固壳常见入口）", "注意"),
    (r"\bSystem\.loadLibrary\b|\bnative\s+\w+\s*\(", "加载原生库/JNI 调用（逻辑可能藏在 so 里）", "注意"),
    (r"\bString\.decrypt\b|\bdecryptString\b|\bdecrypt\s*\(", "字符串解密（常见于加固/混淆）", "注意"),
]

_API_COMPILED = [(re.compile(p), d, r) for p, d, r in API_RULES]

# 类级：父类/接口 → 角色
SUPER_ROLE: dict[str, str] = {
    "Activity": "界面页（有生命周期，UI 逻辑）",
    "AppCompatActivity": "界面页（兼容库）",
    "Fragment": "界面片段",
    "Service": "后台服务（无界面长期运行）",
    "IntentService": "后台服务（处理完自停）",
    "JobService": "系统调度服务",
    "BroadcastReceiver": "广播接收器（监听系统/应用事件）",
    "ContentProvider": "数据提供者（跨应用数据共享）",
    "Application": "应用入口（全局初始化，常为加固壳入口）",
    "Thread": "线程",
    "Runnable": "可执行任务（常为 lambda 合成体）",
    "AsyncTask": "异步任务",
    "View": "自定义控件",
    "Adapter": "列表适配器",
    "Handler": "消息处理器",
    "Exception": "异常类型",
    "Throwable": "异常类型",
    "Object": "普通对象",
}

# 混淆名判定：单/双小写字母，或 a0/x1 这类。
# 只认小写：大写的 R（资源表）、T（泛型）、IO 都是正常名字，
# 一刀切会把 R 标成"混淆名"，很蠢。
_OBF_RE = re.compile(r"^[a-z]{1,2}\d*$")


# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------

@dataclass
class MethodNote:
    name: str
    line: int
    cn: str = ""
    calls: list[str] = field(default_factory=list)
    apis: list[tuple[str, str]] = field(default_factory=list)   # (说明, 风险)
    strings: list[str] = field(default_factory=list)

    # ——— 以下供依赖图与语句级注释使用 ———
    ret: str = ""                                    # 返回类型（简单名）
    mods: str = ""                                   # 修饰符原文
    params: list[tuple[str, str]] = field(default_factory=list)   # (类型, 名字)
    body_from: int = 0                               # 方法体 '{' 所在行（1 基）
    body_to: int = 0                                 # 方法体 '}' 所在行（1 基）
    recv_calls: list[tuple[str, str]] = field(default_factory=list)  # (接收者, 方法名)
    local_types: dict[str, str] = field(default_factory=dict)        # 局部变量 → 类型
    returns: list[str] = field(default_factory=list)                 # 各处 return 的表达式
    throws: list[str] = field(default_factory=list)                  # 抛出的异常类型
    is_ctor: bool = False                                            # 是否构造函数

    def sig_key(self) -> str:
        """类内唯一键：名字 + 参数个数（Java 允许重载，只靠名字会串）。"""
        return f"{self.name}/{len(self.params)}"

    @property
    def risk(self) -> str:
        if any(r == "高危" for _, r in self.apis):
            return "高危"
        if any(r == "注意" for _, r in self.apis):
            return "注意"
        return ""


@dataclass
class ClassNote:
    name: str
    kind: str = "class"
    supers: list[str] = field(default_factory=list)
    methods: list[MethodNote] = field(default_factory=list)
    obfuscated: bool = False
    apis: list[tuple[str, str]] = field(default_factory=list)

    # ——— 以下供依赖图使用 ———
    pkg: str = ""
    fields: dict[str, str] = field(default_factory=dict)   # 字段名 → 类型简单名
    file: str = ""                                          # 相对路径（由调用方填）
    is_inner: bool = False

    def method_by_name(self, name: str) -> MethodNote | None:
        for m in self.methods:
            if m.name == name:
                return m
        return None

    @property
    def risk(self) -> str:
        risks = [m.risk for m in self.methods]
        if "高危" in risks:
            return "高危"
        if "注意" in risks:
            return "注意"
        return ""


@dataclass
class AnnotateResult:
    files_total: int = 0
    files_done: int = 0
    methods_annotated: int = 0
    classes_annotated: int = 0
    out_root: str = ""
    errors: list[str] = field(default_factory=list)
    index: dict = field(default_factory=dict)     # 类名 -> 摘要，供 GUI 树用
    verify_points: list[dict] = field(default_factory=list)  # 校验点清单
    graph_summary: str = ""                       # 依赖图摘要
    density: str = "full"                         # 注释密度


# ---------------------------------------------------------------------------
# 命名翻译
# ---------------------------------------------------------------------------

_CLASS_RE = re.compile(
    r"^\s*(?:public|private|protected|static|final|abstract|synthetic|\s)*"
    r"(class|interface|enum)\s+([A-Za-z_$][\w$]*)"
    r"(?:\s*<[^>]{0,80}>)?"
    r"(?:\s+extends\s+([\w.$]+))?"
    r"(?:\s+implements\s+([\w.$,\s]+?))?"
    r"\s*\{",
    re.M,
)

# 方法声明：修饰符 + 返回类型 + 名字 + 参数表（不含分号结尾）
# 方法声明（单行版本）：修饰符 + 返回类型 + 名字 + "("
# 用 match() 对单行匹配，不再对全文 search —— 这是性能关键
_METHOD_LINE_RE = re.compile(
    r"^[ \t]*(?!(?:if|for|while|switch|catch|synchronized|return|else|do|try|case|throw|assert|new)\b)"
    r"((?:public|private|protected|static|final|abstract|native|synchronized|default|strictfp)[\w\s]{0,40}?)?"
    r"([\w.$<>\[\], ?]{1,120}?)\s+"
    r"([A-Za-z_$][\w$]*)\s*\("
)

# 构造函数：没有返回类型，`名字(` 且名字必须等于类名
_CTOR_RE = re.compile(
    r"^[ \t]*(?:(?:public|private|protected|static|final|synchronized)\s+)*"
    r"([A-Za-z_$][\w$]*)\s*\("
)

_CALL_RE = re.compile(r"\b([A-Z][\w$]*)\.([a-zA-Z_$][\w$]*)\s*\(")
_THIS_CALL_RE = re.compile(r"(?<![\w.])this\.([a-zA-Z_$][\w$]*)\s*\(")
_STR_RE = re.compile(r'"((?:[^"\\]|\\.){2,200})"')
# 返回值与抛出的异常：判断"这个方法有几个出口、哪个是放行"靠它
_RET_RE = re.compile(r"\breturn\s+([^;]+);")
_THROW_RE = re.compile(r"\bthrow\s+new\s+([\w.$]+)")


def _strip_strings_and_comments(text: str) -> str:
    """
    把字符串/注释替换成同长度的占位，便于用正则找结构而不被内容干扰。

    长度保持不变 → 行号、偏移都不受影响。
    """
    out = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == '"':
                    j += 1
                    break
                j += 1
            out.append('"' + "_" * max(0, j - i - 2) + '"')
            i = j
        elif c == "'":
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == "'":
                    j += 1
                    break
                j += 1
            out.append("'__'")
            i = j
        elif text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            seg = text[i:j]
            out.append("".join("\n" if ch == "\n" else " " for ch in seg))
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _match_brace(text: str, open_pos: int) -> int:
    """从 '{' 位置开始，返回配对 '}' 之后的位置。跳过字符串与注释。"""
    depth = 0
    i, n = open_pos, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == '"':
                    break
                i += 1
        elif c == "'":
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == "'":
                    break
                i += 1
        elif c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        elif c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


def _scan_apis(code: str) -> list[tuple[str, str]]:
    """在方法体里匹配 API 特征，去重保序。"""
    hits: list[tuple[str, str]] = []
    seen = set()
    for rx, desc, risk in _API_COMPILED:
        if rx.search(code) and desc not in seen:
            seen.add(desc)
            hits.append((desc, risk))
    return hits


_PKG_RE = re.compile(r"^\s*package\s+([\w.]+)\s*;", re.M)

# 类级字段：修饰符 + 类型 + 名字（后面跟 = 或 ;）
_FIELD_RE = re.compile(
    r"^\s*(?:(?:public|private|protected|static|final|volatile|transient)\s+)*"
    r"([A-Z][\w$.]*(?:\s*<[^;{}()]*>)?(?:\s*\[\s*\])?)\s+"
    r"([A-Za-z_$][\w$]*)\s*(?:=|;)"
)

# 带接收者的调用：foo.bar( —— 接收者可能是字段、局部变量或类名
_RECV_CALL_RE = re.compile(r"\b([A-Za-z_$][\w$]*)\s*\.\s*([A-Za-z_$][\w$]*)\s*\(")

# 不带接收者的调用：bar( —— 是 this.bar()
_PLAIN_CALL_RE = re.compile(r"(?<![\w$.\)\]])([A-Za-z_$][\w$]*)\s*\(")

# 局部变量声明：类型 名字 = / ; / ,
_LOCAL_RE = re.compile(
    r"^\s*(?:final\s+)?([A-Z][\w$.]*(?:\s*<[^<>;()]*>)?(?:\s*\[\s*\])?)\s+"
    r"([a-z_$][\w$]*)\s*(?:=|;|,)",
    re.M,
)

# 这些不是方法调用，是语法关键字
_JAVA_KEYWORDS = frozenset({
    "if", "for", "while", "switch", "catch", "synchronized", "return",
    "new", "throw", "else", "do", "try", "case", "assert", "super", "this",
    "instanceof", "finally",
})


def _simple_type(t: str) -> str:
    """java.util.Map<String, Foo>[] → Map"""
    t = (t or "").strip()
    t = re.sub(r"<.*>", "", t, flags=re.S)
    t = t.replace("[]", "").replace("...", "")
    t = t.strip().split(".")[-1]
    return t


def _parse_params(sig: str) -> list[tuple[str, str]]:
    """
    "String a, int b, Map<String, Object> c" → [(String,a), (int,b), (Map,c)]

    只为依赖图服务，所以只要类型和名字，注解/泛型细节都丢掉。
    """
    out: list[tuple[str, str]] = []
    if not sig.strip():
        return out
    depth = 0
    cur: list[str] = []
    parts: list[str] = []
    for ch in sig:
        if ch in "<([":
            depth += 1
        elif ch in ">)]":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
            continue
        cur.append(ch)
    parts.append("".join(cur))

    for p in parts:
        p = p.strip()
        if not p:
            continue
        p = re.sub(r"@\w+(\([^)]*\))?\s*", "", p)      # 去掉注解
        p = re.sub(r"\bfinal\s+", "", p)
        toks = p.split()
        if len(toks) < 2:
            continue
        out.append((_simple_type(" ".join(toks[:-1])), toks[-1]))
    return out


def parse_source(text: str) -> ClassNote | None:
    """
    解析一个 Java 文件，抽出类结构：成员字段、方法清单、每个方法的调用与局部类型。

    【性能要点】
        旧写法对每个方法都 `clean.count("\\n", 0, pos)` 重算行号，是 O(n²)：
        一个 120KB 的 MainActivity 要 88 秒。现在改成
          * 一次 O(n) 建行起点索引，行号查询 O(log n)
          * 方法发现改为「逐行匹配」，不再对全文反复 search
        同一个文件降到毫秒级。
    """
    clean = _strip_strings_and_comments(text)
    m = _CLASS_RE.search(clean)
    if not m:
        return None

    kind, name, sup, impl = m.group(1), m.group(2), m.group(3), m.group(4)
    c = ClassNote(name=name, kind=kind)
    pm = _PKG_RE.search(clean)
    if pm:
        c.pkg = pm.group(1)
    if sup:
        c.supers.append(sup.split(".")[-1])
    if impl:
        c.supers.extend(x.strip().split(".")[-1] for x in impl.split(",") if x.strip())
    c.obfuscated = bool(_OBF_RE.match(name))

    body_start = clean.find("{", m.end() - 1)
    if body_start < 0:
        body_start = m.end()
    body_end = _match_brace(clean, body_start)

    # ---- 行起点索引（一次 O(n)）----
    line_starts = [0]
    k = clean.find("\n")
    while k >= 0:
        line_starts.append(k + 1)
        k = clean.find("\n", k + 1)
    n_lines = len(line_starts)

    def line_of(pos: int) -> int:
        """偏移 → 1 基行号。"""
        return bisect_right(line_starts, pos)

    # ---- 每行起始处的花括号深度（用来区分"类级声明"和"方法体内的语句"）----
    depth_at: list[int] = []
    d = 0
    for ln in clean.splitlines():
        depth_at.append(d)
        d += ln.count("{") - ln.count("}")

    def depth_of_line(idx: int) -> int:
        return depth_at[idx] if 0 <= idx < len(depth_at) else 99

    # ---- 内部类区间：这些区间里的方法是"内部类的方法"，不算外部类的 ----
    inner_ranges: list[tuple[int, int]] = []
    for cm2 in _CLASS_RE.finditer(clean):
        if cm2.start() == m.start():
            continue
        bs2 = clean.find("{", cm2.end() - 1)
        if bs2 < 0:
            continue
        inner_ranges.append((cm2.start(), _match_brace(clean, bs2)))

    # ---- 逐行找方法声明 ----
    i = max(0, bisect_right(line_starts, body_start) - 1)
    while i < n_lines:
        start = line_starts[i]
        if start >= body_end:
            break

        # 落在内部类里 → 整段跳过
        skip_to = -1
        for a, b in inner_ranges:
            if a <= start < b:
                skip_to = bisect_right(line_starts, b) - 1
                break
        if skip_to >= 0:
            i = max(i + 1, skip_to)
            continue

        stop = line_starts[i + 1] if i + 1 < n_lines else len(clean)
        line = clean[start:stop]

        mname = None
        ret = ""
        mods = ""
        mm = _METHOD_LINE_RE.match(line)
        if mm:
            ret = (mm.group(2) or "").strip()
            mods = (mm.group(1) or "").strip()
            if ret and ret not in ("new", "return", "else", "case", "throw"):
                mname = mm.group(3)

        if not mname:
            # 构造函数：<类名>( —— 没有返回类型，必须单独认
            cm = _CTOR_RE.match(line)
            if cm and cm.group(1) == name:
                mname = name
                mods = line[:len(line) - len(line.lstrip())].strip()

        if not mname:
            i += 1
            continue

        p_in_line = line.find("(")
        if p_in_line < 0:
            i += 1
            continue
        paren_off = start + p_in_line
        pclose = _match_paren(clean, paren_off)
        if pclose < 0 or pclose >= body_end + 1:
            i += 1
            continue

        # 参数表之后：找方法体 '{' 或声明结束 ';'
        window = clean[pclose:pclose + 800]
        brace_rel = window.find("{")
        semi_rel = window.find(";")
        has_body = brace_rel >= 0 and (semi_rel < 0 or brace_rel < semi_rel)

        mn = MethodNote(name=mname, line=line_of(start))
        mn.cn = translate_name(mname)
        mn.is_ctor = (mname == name)
        mn.ret = "" if mn.is_ctor else _simple_type(ret)      # 构造函数没有返回类型
        mn.mods = mods
        mn.params = _parse_params(clean[paren_off + 1:pclose])

        if has_body:
            brace = pclose + brace_rel
            bend = _match_brace(clean, brace)
            seg = text[brace:bend]
            cseg = clean[brace:bend]      # 同长度，但字符串/注释已抹平
            mn.calls = [f"{a}.{b}" for a, b in _CALL_RE.findall(cseg)][:12]
            mn.apis = _scan_apis(seg)
            mn.strings = [s for s in _STR_RE.findall(seg) if len(s) >= 3][:6]
            mn.returns = [x.strip() for x in _RET_RE.findall(cseg)][:6]
            mn.throws = [x.split(".")[-1] for x in _THROW_RE.findall(cseg)][:3]
            mn.body_from = line_of(brace)
            mn.body_to = line_of(max(brace, bend - 1))

            # 调用关系（依赖图用）：带接收者的 + this 隐式调用
            rc = [(r, mt) for r, mt in _RECV_CALL_RE.findall(cseg)]
            rc += [("this", mt) for mt in _PLAIN_CALL_RE.findall(cseg)
                   if mt not in _JAVA_KEYWORDS and not mt[0].isupper()]
            mn.recv_calls = rc
            # 局部变量类型（把 foo.bar() 里的 foo 还原成类名就靠它）
            for t, v in _LOCAL_RE.findall(cseg):
                mn.local_types[v] = _simple_type(t)
            i = max(i + 1, bisect_right(line_starts, bend) - 1)
        else:
            # 抽象/接口方法：跳过这一行即可
            i += 1
        c.methods.append(mn)

    # ---- 类级字段（只要花括号深度为 1 的行，方法体里的不算）----
    for idx, ln in enumerate(clean.splitlines()):
        s = ln.strip()
        if not s or s.startswith(("import ", "package ", "//", "*", "/*", "}")):
            continue
        if depth_of_line(idx) != 1:
            continue
        if not s.endswith(";"):
            continue
        fm = _FIELD_RE.match(ln)
        if fm:
            c.fields[fm.group(2)] = _simple_type(fm.group(1))

    # 类级 API（整文件扫一遍，覆盖字段初始化等）
    c.apis = _scan_apis(text)
    return c


def _match_paren(text: str, open_pos: int) -> int:
    depth = 0
    i, n = open_pos, len(text)
    while i < n:
        c = text[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        elif c == '"':
            i += 1
            while i < n and text[i] != '"':
                i += 2 if text[i] == "\\" else 1
        i += 1
    return -1


# ---------------------------------------------------------------------------
# 注释生成
# ---------------------------------------------------------------------------

BAR = "// " + "─" * 66


def _short(items, n: int = 4) -> str:
    items = list(dict.fromkeys(x for x in items if x))
    if not items:
        return ""
    return "、".join(items[:n]) + ("…" if len(items) > n else "")


def _returns_desc(m: MethodNote) -> str:
    """
    根据 return 语句的分布，说清"这个方法有几个出口、哪个像拒绝分支"。

    只说代码里看得见的事实，不臆断极性：
      · 只有 true/false 两个值  → 典型的放行/拦截结构
      · 出现 false / null       → 提示这通常是拒绝分支
      · 其它值（0、-1、对象）   → 只报出口，极性交给调用方判断
    """
    vals = [v for v in m.returns if v]
    uniq = list(dict.fromkeys(vals))
    if not uniq:
        return "无返回值（void 或全部抛异常）"
    if len(uniq) == 1:
        v = uniq[0]
        if v in ("false", "null", "0", "-1"):
            return f"只有一条出口：返回 {v}（通常是拒绝/失败分支）"
        return f"只有一条出口：返回 {v}"

    s = set(uniq)
    shown = "、".join(v if len(v) <= 36 else v[:36] + "…" for v in uniq[:4])
    if s <= {"true", "false"}:
        return f"true / false 两条出口（典型放行/拦截结构）"
    if s <= {"0", "1"}:
        return "0 / 1 两条出口（1 通常表示通过，0 表示拒绝）"
    if "false" in s or "null" in s:
        return f"{len(uniq)} 条出口：{shown} —— false/null 通常是拒绝分支"
    return f"{len(uniq)} 条出口：{shown}"


def _steps(m: MethodNote, limit: int = 6) -> list[str]:
    """从调用序列推断"这个方法的操作步骤"，用于方法头摘要。"""
    from .cnlang import METHOD_CN

    out: list[str] = []
    for _recv, meth in m.recv_calls:
        if len(out) >= limit * 2:
            break
        if meth in _JAVA_KEYWORDS:
            continue
        cn = METHOD_CN.get(meth) or translate_name(meth)
        if not cn or cn in out:
            continue
        out.append(cn)

    # 纯读取动作（取…/是否…）信息量低，有足够的其它步骤时就去掉，
    # 否则"①取整数 ②取长整数 ③存整数"这种摘要等于没说
    substantive = [x for x in out if not x.startswith(("取", "是否", "获取"))]
    if len(substantive) >= 3:
        out = substantive
    return out[:limit]


def class_comment(c: ClassNote, stat=None, nlines: int = 0) -> list[str]:
    """
    类头注释：这是什么、在哪、被谁用、是不是核心/校验点。

    依赖与校验信息来自跨文件依赖图（stat），没有图时自动省略这些行。
    """
    L = [BAR]
    head = f"// 【类】{c.name}"
    cn = translate_name(c.name)
    if cn:
        head += f"  {cn}"
    if c.obfuscated:
        head += "（混淆名，无语义）"
    L.append(head)

    meta = []
    if c.pkg:
        meta.append(f"包 {c.pkg}")
    if c.methods:
        meta.append(f"方法 {len(c.methods)}")
    if c.fields:
        meta.append(f"字段 {len(c.fields)}")
    if nlines:
        meta.append(f"{nlines} 行")
    if meta:
        L.append("//   " + " ｜ ".join(meta))

    if c.supers:
        L.append(f"//   继承/实现：{', '.join(c.supers)}")
        roles = [SUPER_ROLE[s] for s in c.supers if s in SUPER_ROLE]
        if roles:
            L.append(f"//   角色：{'；'.join(dict.fromkeys(roles))}")

    if stat is not None:
        if stat.fan_in:
            named = [x for x in stat.callers if not _OBF_RE.match(x)]
            L.append(f"//   被依赖：{stat.fan_in} 个类（{_short(named, 3) or '多为混淆名'}）")
        if stat.fan_out:
            named = [x for x in stat.callees if not _OBF_RE.match(x)]
            L.append(f"//   依赖他人：{stat.fan_out} 个类（{_short(named, 3) or '多为混淆名'}）")
        if stat.is_entry:
            L.append("//   ⚑ 入口类：系统或用户操作可直接触达这里")

    # —— 核心依赖 ——
    if stat is not None and stat.criticality == "核心":
        why = []
        if stat.verify_score:
            why.append(f"校验特征 {stat.verify_score} 分")
        if stat.fan_in >= 4:
            why.append(f"入度 {stat.fan_in}")
        L.append(f"//   ⚑ 核心依赖（{'，'.join(why) or '综合判定'}）"
                 " —— 改动波及多处，逆向时优先读这里")

    # —— 校验点 ——
    if stat is not None and stat.is_verify:
        L.append(f"//   ⚑ 校验点：{stat.verify_cat or '校验行为'}")
        for h in stat.verify_hits[:3]:
            L.append(f"//       · {h}")
        if stat.chains:
            chain = stat.chains[0]
            if len(chain) > 5:
                chain = chain[:2] + ["…"] + chain[-2:]
            L.append("//   校验链：" + " → ".join(chain))
    elif stat is not None and stat.criticality == "重要":
        L.append(f"//   · 重要类：被 {stat.fan_in} 个类依赖")

    if c.apis:
        L.append("//   关键能力：")
        for desc, risk in c.apis[:5]:
            mark = "⚠ " if risk == "高危" else ("· " if risk else "  ")
            L.append(f"//     {mark}{desc}" + (f"【{risk}】" if risk else ""))

    if c.risk == "高危":
        L.append("//   ⚠ 本类含高危行为（提权/静默安装/无障碍等），优先看")
    L.append(BAR)
    return L


# 方法体里出现这些调用 → 对应一句话。按 (阶段序号, 判定词, 说法) 组织，
# 序号决定句子里的先后，读起来才像"先…再…最后…"而不是堆词。
_STORY_RULES: list[tuple[int, tuple[str, ...], str]] = [
    (10, ("isnull", "isempty", "length", "size", "trim", "equalsnull"),
     "检查参数是否为空或长度是否合法"),
    (15, ("checkpermission", "checkSelfPermission", "isgranted", "requestpermissions"),
     "检查调用方权限"),
    (20, ("getsharedpreferences", "getstring", "readcard", "getint", "prefs",
          "sqlite", "query", "cursor", "getlong"),
     "从本地读配置或卡密"),
    (25, ("inputstream", "fileinputstream", "readallbytes",
          "readtext", "getassets", "filedir", "filesdir"),
     "读取文件"),
    (30, ("sha256", "sha1", "md5", "digest", "messageDigest", "cipher",
          "encrypt", "decrypt", "hmac", "base64"),
     "做摘要或加解密计算"),
    (40, ("currenttimemillis", "currenttime", "now", "date", "calendar",
          "gettime", "timestamp"),
     "取当前时间做时间判定"),
    (42, ("isexpired", "expire", "expired", "trial", "daysleft", "deadline"),
     "判断是否过期"),
    (45, ("isrooted", "checksu", "emulator", "isfrida", "isdebug",
          "debuggable", "tamper", "signature"),
     "做环境或完整性检测"),
    (50, ("http", "okhttp", "urlconnection", "socket", "retrofit",
          "volley", "websocket", "httppost", "httpget"),
     "与服务器通信"),
    (55, ("outputstream", "putstring", "commit", "apply", "insertdata"),
     "把结果写回本地"),
    (60, ("logd", "logi", "loge", "println", "toast", "showtoast"),
     "写日志或给用户提示"),
]

_PHASE_HEAD = {10: "先", 15: "先", 20: "再", 25: "再", 30: "然后",
               40: "接着", 42: "据此", 45: "同时", 50: "之后", 55: "最后"}


def method_story(m: MethodNote) -> str:
    """
    把方法的零散线索拼成**一句人话**。

    为什么需要它：
        原来的注释是词对词翻译（"如果 授权 等于 空"），一行一行读还行，
        连着读就是电报体 —— 那些是"词的堆叠"，不是"句子"。
        这里按代码里**真实发生过的调用**（recv_calls / calls / local_types）
        把动作按先后串起来，输出一句能直接读懂的话。

    只根据真实存在的信号拼；拼不出来就老实说"没有明显副作用"，不硬编。
    """
    # 信号来源：优先 recv_calls（能拿到 ctx.getSharedPreferences 这种真实调用）
    sig_parts: list[str] = []
    for recv, name in m.recv_calls:
        sig_parts.append(name.lower())
        sig_parts.append(recv.lower())
    sig_parts += [c.lower() for c in m.calls]
    sig_parts += [t.lower() for t in m.local_types.values()]
    sig = " ".join(sig_parts)
    # 方法名本身也是信号（isExpired / verifyCard 这类）
    sig += " " + m.name.lower()

    hit: list[tuple[int, str]] = []
    seen: set[str] = set()
    for order, keys, phrase in _STORY_RULES:
        if phrase in seen:
            continue
        if any(k.lower() in sig for k in keys):
            hit.append((order, phrase))
            seen.add(phrase)

    if not hit:
        if m.returns:
            return "这个方法没有明显副作用，主要做计算并返回结果。"
        return "这个方法没有明显副作用（可能只调整了内部状态）。"

    hit.sort(key=lambda x: x[0])
    # 连接词按顺序轮换：老是一个"再"会读成清单，不像句子
    if len(hit) == 1:
        body = hit[0][1]
    else:
        conn = ["先", "再", "然后", "接着", "最后"]
        words = []
        for i, (_order, phrase) in enumerate(hit[:5]):
            words.append(conn[min(i, len(conn) - 1)] + phrase)
        body = "，".join(words)

    tail = ""
    rs = " ".join(m.returns).lower()
    if "true" in rs and "false" in rs:
        tail = "；两条出口分别返回 true/false，是典型的放行与拦截结构"
    elif "true" in rs:
        tail = "；最终返回 true 表示通过"
    elif "false" in rs:
        tail = "；最终返回 false 表示拒绝"
    elif m.throws:
        tail = "；异常路径会抛 " + "、".join(dict.fromkeys(m.throws))[:30]
    elif m.ret and m.ret not in ("void", ""):
        tail = f"；最后返回 {m.ret}"

    return f"这个方法{body}{tail}。"


def method_comment(m: MethodNote, callers: list[tuple[str, str]] | None = None,
                   indent: str = "    ") -> list[str]:
    """
    方法头注释：一句话总结 + 签名 + 出口 + 调用者 + 步骤。

    「一句话总结」由 method_story 按语义拼接，解决"词对词翻译读不成句"的问题；
    后面几行是证据（签名/出口/API），用来核对这句话对不对。
    """
    from . import verify

    title = f"【{m.name}】"
    if m.cn:
        title += f" {m.cn}"
    elif _OBF_RE.match(m.name):
        title += "（混淆名，语义未知）"
    L = [indent + "// " + title]
    # 先给结论，再给证据 —— 读的人先知道"它在干嘛"，需要时再看细节
    try:
        L.append(indent + "//   总述：" + method_story(m))
    except Exception:                                # noqa: BLE001
        pass

    sig = (f"{m.name}(" if m.is_ctor else
           f"{m.ret or 'void'} {m.name}(") + ", ".join(
        f"{t} {n}".strip() for t, n in m.params) + ")"
    L.append(indent + "//   签名：" + sig)

    if m.returns:
        L.append(indent + "//   出口：" + _returns_desc(m))
    if m.throws:
        L.append(indent + "//   抛出：" + "、".join(dict.fromkeys(m.throws)) + "（异常路径）")

    vh = verify.match_method(m.name)
    if vh:
        _cat, desc = vh
        L.append(indent + f"//   ⚑ 核心校验点：{desc}（按命名判定）")

    # 被谁调用：改这个方法前必须先看的清单
    if callers:
        L.append(indent + "//   被调用：" + _short([f"{c}.{mm}" for c, mm in callers], 4))

    steps = _steps(m)
    if steps:
        marks = "①②③④⑤⑥"
        L.append(indent + "//   步骤：" + "  ".join(
            f"{marks[i]}{s}" for i, s in enumerate(steps[:6])))

    if m.apis:
        for desc, risk in m.apis[:4]:
            mark = "⚠ " if risk == "高危" else ("· " if risk else "  ")
            L.append(indent + f"//   {mark}{desc}" + (f"【{risk}】" if risk else ""))
    return L


def _stmt_inserts(lines: list[str], m: MethodNote, budget: int) -> list[tuple[int, str]]:
    """
    在方法体内给控制流语句逐条插中文注释。

    只注 if / else / for / while / switch / case / try / catch / return / throw ——
    这三类才承载"为什么走这条路"的信息。
    普通赋值和属性调用不注，否则整篇都是噪音，反而没人看。
    """
    from .cnlang import cn_stmt

    out: list[tuple[int, str]] = []
    if budget <= 0 or not m.body_from:
        return out
    lo = m.body_from - 1
    hi = min(m.body_to, len(lines))
    in_text_block = False
    for idx in range(lo, hi):
        raw = lines[idx]
        # Java 文本块（"""…"""）：里面的内容会被当成字符串，
        # 往里插注释就把代码写坏了，整段跳过
        quotes = raw.count('"""')
        if in_text_block:
            if quotes % 2:
                in_text_block = False
            continue
        if quotes % 2:
            in_text_block = True
            continue
        s = raw.strip()
        if not s or s.startswith("//"):
            continue
        txt = cn_stmt(s)
        if not txt:
            continue
        if len(txt) > 88:
            txt = txt[:88] + "…"
        ind = re.match(r"^[ \t]*", raw).group(0)
        # 注意必须是 [str]：切片赋值给字符串会把注释按字符拆成一堆行
        out.append((idx, [f"{ind}// · {txt}"]))
        if len(out) >= budget:
            break
    return out


def annotate_text(text: str,
                  note: ClassNote | None = None,
                  stat=None,
                  density: str = "full",
                  max_stmt: int = 60) -> tuple[str, ClassNote | None]:
    """
    给单份源码加注释，返回 (新文本, 解析结果)。

    density：
        "full" —— 类头 + 方法头 + 方法体内语句级注释
        "lite" —— 只加类头与方法头（大工程只要速览时用）

    插入策略：从后往前按行号插，避免行号漂移。
    """
    c = note or parse_source(text)
    if not c:
        return text, None

    lines = text.splitlines()
    inserts: list[tuple[int, list[str]]] = []    # (行下标, 注释行)

    # 类注释插在 "class X" 那一行之前（跳过 package/import 与既有头注释）
    cls_line = None
    for i, ln in enumerate(lines):
        if re.search(rf"\b(class|interface|enum)\s+{re.escape(c.name)}\b", ln):
            cls_line = i
            break
    if cls_line is not None:
        inserts.append((cls_line, class_comment(c, stat, len(lines))))

    full = density == "full"
    for m in c.methods:
        idx = m.line - 1
        if not (0 <= idx < len(lines)):
            continue
        indent = re.match(r"^[ \t]*", lines[idx]).group(0)
        callers = None
        if stat is not None and hasattr(stat, "_callers"):
            try:
                callers = stat._callers(m.name)
            except Exception:
                callers = None
        inserts.append((idx, method_comment(m, callers, indent)))
        if full:
            inserts.extend(_stmt_inserts(lines, m, max_stmt))

    # 从后往前插（同一行多次插入时按原顺序保持）
    for idx, block in sorted(inserts, key=lambda x: x[0], reverse=True):
        lines[idx:idx] = block

    return "\n".join(lines) + ("\n" if text.endswith("\n") else ""), c


# ---------------------------------------------------------------------------
# 批量
# ---------------------------------------------------------------------------

LIB_PREFIX = ("android", "androidx", "kotlin", "kotlinx", "java", "javax")

# 这里只列"确定是第三方库"的包前缀。
# 不能简单把 org/ 整目录排除 —— 应用自己的包很可能就叫 org.xxx，
# 一刀切会把目标代码全跳过，注释出来一片空白。
_LIB_PKGS = {
    ("com", "google"), ("com", "facebook"), ("com", "squareup"),
    ("com", "bumptech"), ("com", "airbnb"), ("com", "scwang"),
    ("org", "apache"), ("org", "jetbrains"), ("org", "json"),
    ("org", "intellij"), ("org", "greenrobot"), ("org", "reactnative"),
}


def is_library_path(rel: Path) -> bool:
    """这个相对路径是不是标准库/常见三方库（不必注释）。"""
    parts = rel.parts
    if not parts:
        return False
    if parts[0] in ("android", "androidx", "kotlin", "kotlinx", "java", "javax"):
        return True
    if len(parts) >= 2 and (parts[0], parts[1]) in _LIB_PKGS:
        return True
    return False


def annotate_tree(
    src_root: str | Path,
    out_root: str | Path | None = None,
    on_progress: Callable[[int, int, str], None] | None = None,
    skip_dirs: Iterable[str] = LIB_PREFIX,
    density: str = "full",
    max_stmt: int = 60,
    use_graph: bool = True,
) -> AnnotateResult:
    """
    批量注释一棵源码树。

    两遍扫描：
        第一遍只解析结构 → 建跨文件依赖图（没有图就说不出"谁依赖谁"）
        第二遍才写注释 —— 此时入度、校验链、调用者都已知

    out_root 为 None 时原地加注释（会先备份为 *.orig）。
    默认跳过 androidx/kotlin/java 标准库 —— 它们不是分析目标，注释它们纯属浪费。
    """
    from . import depgraph

    src = Path(src_root)
    res = AnnotateResult()
    if not src.exists():
        res.errors.append(f"源码目录不存在：{src}")
        return res

    files = sorted(src.rglob("*.java"))
    res.files_total = len(files)
    dst_root = Path(out_root) if out_root else src
    res.out_root = str(dst_root)
    res.density = density

    skip = set(skip_dirs)
    targets: list[tuple[Path, Path, ClassNote]] = []

    # ---- 第一遍：结构解析 ----
    for f in files:
        rel = f.relative_to(src)
        if (rel.parts and rel.parts[0] in skip) or is_library_path(rel):
            continue
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
            c = parse_source(text)
        except Exception as e:
            res.errors.append(f"{rel}: {e}")
            continue
        if not c:
            continue
        c.file = str(rel)
        targets.append((f, rel, c))

    # ---- 建图 ----
    graph = None
    if use_graph and targets:
        try:
            graph = depgraph.build_from_notes({c.name: c for _f, _r, c in targets})
            res.graph_summary = graph.summary()
            for n in graph.verify_nodes()[:12]:
                res.verify_points.append({
                    "class": n.name,
                    "category": n.verify_cat,
                    "score": n.verify_score,
                    "fan_in": n.fan_in,
                    "hits": n.verify_hits[:3],
                    "chain": " → ".join(n.chains[0]) if n.chains else "",
                })
        except Exception as e:
            res.errors.append(f"依赖图构建失败：{e}")

    # ---- 第二遍：写注释 ----
    for i, (f, rel, c) in enumerate(targets, 1):
        stat = graph.stat(c.name) if graph else None
        # 调用者清单挂到 stat 上，供方法头使用
        callers_map: dict[str, list[tuple[str, str]]] = {}
        if graph:
            for m in c.methods:
                cs = graph.method_callers(c.name, m.name)
                if cs:
                    callers_map[m.name] = cs

        try:
            text = f.read_text(encoding="utf-8", errors="replace")
            new, cnote = annotate_text(text, note=c, stat=_StatProxy(stat, callers_map),
                                       density=density, max_stmt=max_stmt)
            target = dst_root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            if out_root is None:
                bak = f.with_suffix(".java.orig")
                if not bak.exists():
                    bak.write_text(text, encoding="utf-8")
            target.write_text(new, encoding="utf-8")
            if cnote:
                res.classes_annotated += 1
                res.methods_annotated += len(cnote.methods)
                res.index[cnote.name] = {
                    "file": str(rel),
                    "kind": cnote.kind,
                    "supers": cnote.supers,
                    "methods": len(cnote.methods),
                    "risk": cnote.risk,
                    "obfuscated": cnote.obfuscated,
                    "criticality": stat.criticality if stat else "普通",
                    "verify_cat": stat.verify_cat if stat else "",
                    "fan_in": stat.fan_in if stat else 0,
                }
        except Exception as e:
            res.errors.append(f"{rel}: {e}")
        res.files_done += 1
        if on_progress:
            try:
                on_progress(i, len(targets), str(rel))
            except Exception:
                pass
    return res


class _StatProxy:
    """
    把"类统计"和"方法→调用者"两样东西打包给 annotate_text。

    用代理而不是改 MethodNote：依赖图是外部信息，不该塞进结构对象里，
    否则解析器和图就耦合死了。
    """

    def __init__(self, stat, callers_map: dict[str, list[tuple[str, str]]]):
        self._stat = stat
        self._callers_map = callers_map
        if stat is not None:
            for k in ("fan_in", "fan_out", "callers", "callees", "is_entry",
                      "verify_cat", "verify_score", "verify_hits", "chains"):
                setattr(self, k, getattr(stat, k))

    @property
    def criticality(self) -> str:
        return self._stat.criticality if self._stat else "普通"

    @property
    def is_verify(self) -> bool:
        return self._stat.is_verify if self._stat else False

    def _callers(self, method: str):
        return self._callers_map.get(method)

    def __getattr__(self, item):
        # 未知属性一律当成"没有"，注释器会自然省略对应行
        return None


def summarize_index(index: dict) -> str:
    """把索引渲染成一段可读摘要（GUI 侧栏 / 报告用）。"""
    if not index:
        return "（无）"
    hi = [k for k, v in index.items() if v.get("risk") == "高危"]
    ob = [k for k, v in index.items() if v.get("obfuscated")]
    core = [k for k, v in index.items() if v.get("criticality") == "核心"]
    ver = [(k, v.get("verify_cat")) for k, v in index.items() if v.get("verify_cat")]
    L = [f"类 {len(index)} 个，其中混淆名 {len(ob)} 个，含高危行为 {len(hi)} 个"]
    if core:
        L.append("核心依赖：" + "、".join(core[:10]) + ("…" if len(core) > 10 else ""))
    if ver:
        L.append("校验点：" + "、".join(f"{k}（{c}）" for k, c in ver[:8]))
    if hi:
        L.append("高危类：" + "、".join(hi[:10]) + ("…" if len(hi) > 10 else ""))
    return "\n".join(L)
