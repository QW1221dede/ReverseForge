#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
防改动 / 防调试 / 防环境 —— 开发者"精明劲儿"的集中营。

重打包这件事本身就会抹掉三样东西，而这三样恰好是最省事、最有效的
反破解手段：

    ① 原签名（apksigner 用新 key 重签）
    ② 原 dex 的 CRC / SHA-256（apktool 重编，字节全变）
    ③ 原 assets 的哈希（同上）

于是"聪明的"开发者只要在启动路径上放一句
    if (!签名一致) finish();
就能让任何重打包的包一装就退。再叠上 root / 模拟器 / 调试器 / frida
四件套，就把"能装但跑不起来"做成了常态。

这个模块只干一件事：把这些守卫**找出来**，并告诉引擎该往哪个方向中和。
改法由 checkpoints.py 生成（它才有 _Method 结构）：

    返回 boolean 的守卫     → 整个方法恒返回"通过"值（true/false 按语义）
    返回 void 的非生命周期 → 方法体清空（检测到也不再执行处置）
    生命周期方法内联的守卫   → 不自动改（清空 onCreate 会白屏），只报出来

另一部分是**加固体检**：壳、动态加载 dex、抽代码 —— 这些改 smali 没用，
必须脱壳，所以要如实报出来，不能让自动化假装"处理完了"。

--------------------------------------------------------------------------
第二层：终结动作（terminator）—— 比改判定更狠的一刀
--------------------------------------------------------------------------
上面那套是"改判定"：把检测方法改成恒返回"通过"。但它有个前提 ——
必须先认出检测点。而聪明的作者可以：
    · 用一百种姿势检测（时间差、内存指纹、类加载顺序、so 里算）
    · 把检测藏进反射 / 动态代理 / native
    · 每次更新换一套特征

但"不让程序跑"这件事，**物理上只有那么几条路可走**：

    System.exit / Runtime.halt / Process.killProcess     进程自杀
    Activity.finish / finishAffinity                     界面强退
    throw new RuntimeException/SecurityException         未捕获异常崩溃
    while(true) / Thread.sleep(Long.MAX)                 静默挂起（白屏装死）

中间套多少层包装（Utils.kill()、反射调 exit、native 调 _exit）都没用 ——
最底层那个调用一定长得一样。所以除了改判定，还把**终结动作本身**摘掉：

    行级替换成 nop：invoke-static {v0}, Ljava/lang/System;->exit(I)V
                 →  nop

这条 invoke 是 3 字节，nop 汇编后长度不同也没关系 —— smali 的标签、
try/catch、debug 信息都是符号化的，apktool 汇编时统一重算偏移。
System.exit 返回 void，后面不会有 move-result，所以直接 nop 安全。

于是"检测到就退"这条链被物理切断：判定没改成功也没关系，
退出的动作已经不存在了，程序只能继续往下跑。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# 单方法级规则
# ---------------------------------------------------------------------------
# (kind, 类别, 正则, 中和方向, 权重, 人话说明)
#   中和方向：
#     "pass"  恒返回"校验通过"（true）—— 签名/完整性这类正面判定
#     "false" 恒返回"未命中"（false）—— root/模拟器/调试器这类负面判定
#     "none"  只诊断不改
#   正则作用在 "方法体全文 + 调用串 + 常量串" 上，smali 原文匹配。
_RULES: list[tuple[str, str, re.Pattern, str, int, str]] = [
    # ---- ① 签名自校验：重打包必踩 ----
    ("apk_sig", "签名自校验",
     re.compile(r"Landroid/content/pm/PackageInfo;->signatures?:|"
                r"Landroid/content/pm/Signature;->to(ByteArray|CharsString)\(|"
                r"PackageManager;->checkSignatures\(|"
                r"Landroid/content/pm/PackageInfo;->(firstInstallTime|lastUpdateTime):"),
     "pass", 62,
     "读取 APK 签名/安装时间并与硬编码值比对（重打包后签名与时间都变）"),

    # ---- ② 文件/资源完整性：dex CRC、so 哈希、assets 哈希 ----
    # 这里不放 MessageDigest.digest 单条 —— 任何哈希工具方法都会中，
    # 而"算哈希"本身不是守卫。摘要必须与自身路径一起出现才算（见 _COMBO_RULES）。
    ("integrity", "完整性校验",
     re.compile(r"Ljava/util/zip/ZipEntry;->getCrc\(\)|"
                r"Landroid/content/pm/ApplicationInfo;->sourceDir:|"
                r"PackageManager;->getPackageCodePath\("),
     "pass", 55,
     "读取自身 dex/so 的 CRC 做完整性比对（重打包后必然不一致）"),

    # ---- ③ 调试器检测 ----
    ("antidebug", "反调试",
     re.compile(r"Landroid/os/Debug;->isDebuggerConnected\(\)|"
                r"Landroid/os/Debug;->waitingForDebugger\(\)|"
                r"Landroid/os/Debug;->isDebuggerConnected|TracerPid|"
                r"Landroid/os/Debug;->getWaitingForDebugger\("),
     "false", 66,
     "检测调试器是否连接（Debug.isDebuggerConnected / TracerPid）"),

    # ---- ④ 注入/框架检测：frida、xposed、magisk 模块 ----
    ("antiinject", "反注入",
     re.compile(r"(?i)(frida|xposed|substrate|zygisk|riru|lspd|edxposed|"
                r"sandhook|pine\.io|libghost|gum-js-loop|linjector)|"
                r"Lde/robv/android/xposed/|Lcom/saurik/substrate/"),
     "false", 68,
     "扫描 frida / xposed / magisk 注入痕迹（进程名、maps、类名）"),

    # ---- ⑤ 模拟器检测 ----
    # 注意：只认"模拟器特征串"，不把 Build.FINGERPRINT 单列 —— 正常 App 也会
    # 读指纹打日志/做统计，单凭字段会大面积误报。要判模拟器，必然要拿特征串比。
    ("anti_emulator", "反模拟器",
     re.compile(r"(?i)(goldfish|ranchu|vbox86|genymotion|bluestacks|"
                r"nox_?app|microvirt|ttvm|andy_?os|qemu\.|qemu_|"
                r"droid4x|memu|ldplayer|mumu)"),
     "false", 56,
     "按 goldfish/qemu/vbox 等特征串判断是否跑在模拟器里"),

    # ---- ⑥ root 检测 ----
    ("anti_root", "反 root",
     re.compile(r"(?i)(/system/(bin|xbin)/su|/sbin/su|/su/bin/su|"
                r"/data/local/(bin|tmp)/su|Superuser\.apk|/data/adb/|"
                r"test-keys|busybox|magisk|/system/app/Superuser)"),
     "false", 58,
     "按 su 路径 / test-keys / Superuser 判断设备是否已 root"),

    # ---- ⑦ 动态加载 dex：逻辑不在静态 dex 里 ----
    ("dyn_dex", "动态加载",
     re.compile(r"Ldalvik/system/(DexClassLoader|InMemoryDexClassLoader|"
                r"BaseDexClassLoader|DexFile);|"
                r"Ldalvik/system/DexFile;->loadDex\(|"
                r"Ldalvik/system/InMemoryDexClassLoader;-><init>"),
     "none", 50,
     "运行时解密并加载 classes.dex（静态 smali 里看不到真实逻辑）"),
]

# 常量串级别的补充规则：光有 API 不够，得看它比的是什么
_STRING_RULES: list[tuple[str, str, re.Pattern, str, int, str]] = [
    ("integrity", "完整性校验",
     re.compile(r"(?i)classes\d*\.dex$|^\.dex$|^assets/.*\.(dat|bin|so)$"),
     "pass", 50, "常量里出现自身 dex / assets 路径，配合摘要调用即完整性比对"),
    ("anti_root", "反 root",
     re.compile(r"(?i)^su$|^magisk$|^superuser"),
     "false", 45, "常量里出现 su / magisk 字样"),
]

# 组合规则：单看 API 不够，必须两个特征同现（避免误伤正常用 PackageManager 的代码）
_COMBO_RULES: list[tuple[str, str, re.Pattern, re.Pattern, str, int, str]] = [
    ("apk_sig", "签名自校验",
     re.compile(r"PackageManager;->getPackageInfo\(|PackageManager;->getPackageArchiveInfo\("),
     re.compile(r"signatures?:|Signatures"),
     "pass", 60,
     "取 PackageInfo 后又读 signatures 字段 —— 典型的签名指纹比对"),
    ("integrity", "完整性校验",
     re.compile(r"Ljava/security/MessageDigest;->digest\(|Ljava/util/zip/ZipFile;"),
     re.compile(r"sourceDir|getPackageCodePath|classes\d*\.dex|getEntry\("),
     "pass", 58,
     "对自身 APK/dex 做摘要计算 —— 典型的完整性自校验"),
]


# ---------------------------------------------------------------------------
# 终结动作：检测到问题之后"不让程序跑"的实际执行指令
# ---------------------------------------------------------------------------
# (kind, 类别, 正则, 默认摘除?, 权重, 人话说明)
#   默认摘除：
#      True  → 无条件摘（这些 API 正常业务几乎不用，退登录也很少真退进程）
#      False → 只在"守卫上下文"里摘（finish 太常见，正常关页面也用它）
_TERMINATORS: list[tuple[str, str, re.Pattern, bool, int, str]] = [
    # ① 进程自杀：最直接、也最常见的一招
    ("exit_proc", "进程自杀",
     re.compile(r"Ljava/lang/System;->exit\(I\)V|"
                r"Ljava/lang/Runtime;->(?:exit|halt)\(I\)V"),
     True, 78,
     "直接 System.exit / Runtime.halt 杀掉整个进程 —— 一装就退最省事的写法"),

    # ② 杀进程：比 exit 更隐晦，绕开一些 exit hook
    ("kill_self", "强杀进程",
     re.compile(r"Landroid/os/Process;->(?:killProcess|killProcessQuiet)\(I\)V|"
                r"Landroid/os/Process;->sendSignal\(II\)V"),
     True, 76,
     "Process.killProcess(myPid) / sendSignal(SIGKILL) 强杀自己"),

    # ③ 界面强退：App 没死，但退到桌面，看起来就是"不让用"
    ("finish_kill", "强退界面",
     re.compile(r"invoke-\w+(?:/\w+)?\s+\{[^}]*\},\s*L[^;]*Activity;->(finish|finishAffinity|finishAndRemoveTask)\(\)V"),
     False, 62,
     "调用 finish / finishAffinity 把界面关掉（检测不过就退回桌面）"),

    # ④ 致命抛出：未捕获 → 进程崩溃，日志里还看不出原因
    ("throw_fatal", "抛异常崩溃",
     re.compile(r"throw\s+p\d+|^\s*throw\s+v\d+"),
     False, 56,
     "throw 未捕获异常让 App 崩掉（常配 SecurityException / IllegalStateException）"),

    # ⑤ 静默挂起：不崩不退，就是白屏 / 转圈不动
    ("hang", "静默挂起",
     re.compile(r"invoke-\w+(?:/\w+)?\s+\{[^}]*\},\s*Ljava/lang/Thread;->sleep\(J\)V|"
                r"Ljava/util/concurrent/CountDownLatch;->await\(\)V|"
                r"Ljava/lang/Object;->wait\(\)V"),
     False, 50,
     "sleep(Long.MAX) / latch.await() 让线程永久阻塞 —— 界面白屏，看着像卡死"),
]

# 这些常量出现在 throw 附近，说明是"检测不通过"的崩溃，不是正常业务异常
_FATAL_WORDS = re.compile(
    r"(?i)(检测|校验|签名|非法|破解|篡改|外挂|作弊|debug|frida|xposed|root|"
    r"signature|integrity|tamper|hack|cheat|invalid|unauthor|verify)")


@dataclass
class Terminator:
    """一个"不让程序跑"的具体动作。"""
    kind: str
    category: str
    line: int                  # 1 基行号
    text: str                  # 原始指令（去首尾空白）
    weight: int
    why: str
    guarded: bool = False      # 是否处在守卫上下文（方法里有检测特征）

    @property
    def nop_safe(self) -> bool:
        """能不能安全地换成 nop。"""
        return self.kind in ("exit_proc", "kill_self")


def find_terminators(lines: list[str], *, guarded: bool = False) -> list[Terminator]:
    """
    扫一个 smali 方法，找出所有"拒绝运行"的终结动作。

        lines    方法体切行（1 基行号 = 下标+1）
        guarded  这个方法是否已判定为守卫（决定 finish/throw 要不要算）

    只看单行，不做跨行推断 —— 宁可漏报，不能把正常逻辑改坏。
    """
    out: list[Terminator] = []
    for i, raw in enumerate(lines, 1):
        t = raw.strip()
        if not t or t.startswith(("#", ".", ":")):
            continue
        for kind, cat, rx, unconditional, weight, why in _TERMINATORS:
            if not rx.search(t):
                continue
            # 有条件摘除的类别：只认守卫上下文
            if not unconditional and not guarded:
                continue
            out.append(Terminator(kind, cat, i, t, weight, why, guarded))
            break
    return out


def is_fatal_throw(lines: list[str], idx: int, strings: list[str]) -> bool:
    """
    这行 throw 是不是"检测不通过"的崩溃。

    idx 是 0 基下标。判据：往前 12 行内 new-instance 的是 SecurityException /
    IllegalStateException / RuntimeException，且方法常量里有校验类字眼。
    """
    head = "\n".join(lines[max(0, idx - 12):idx + 1])
    if not re.search(r"SecurityException|IllegalStateException|RuntimeException|"
                     r"IllegalArgumentException|AssertionError", head):
        return False
    return any(_FATAL_WORDS.search(s) for s in strings)


@dataclass
class GuardHit:
    kind: str
    category: str
    neutral: str          # pass / false / none
    weight: int
    why: str
    evidence: str = ""




def scan_method(code: str, calls: str, strings: list[str]) -> list[GuardHit]:
    """
    扫一个方法的守卫特征。

        code    方法体全文（含 .locals / 指令 / 标签）
        calls   该方法发起的所有调用，空格连接
        strings 该方法里的 const-string 字面量
    """
    blob = code + "\n" + calls + "\n" + "\n".join(strings)
    hits: list[GuardHit] = []
    seen: set[str] = set()

    for kind, cat, rx, neutral, weight, why in _RULES:
        if kind in seen:
            continue
        m = rx.search(blob)
        if m:
            seen.add(kind)
            hits.append(GuardHit(kind, cat, neutral, weight, why, m.group(0)[:48]))

    for kind, cat, rx, neutral, weight, why in _STRING_RULES:
        if kind in seen:
            continue
        for s in strings:
            m = rx.search(s)
            if m:
                seen.add(kind)
                hits.append(GuardHit(kind, cat, neutral, weight, why, s[:48]))
                break

    for kind, cat, rx_a, rx_b, neutral, weight, why in _COMBO_RULES:
        if kind in seen:
            continue
        ma = rx_a.search(blob)
        mb = rx_b.search(blob)
        if ma and mb:
            seen.add(kind)
            hits.append(GuardHit(kind, cat, neutral, weight, why,
                                 f"{ma.group(0)[:30]} + {mb.group(0)[:24]}"))

    return hits


# ---------------------------------------------------------------------------
# 目录级：加固 / 壳体检
# ---------------------------------------------------------------------------
_PACKERS: list[tuple[str, re.Pattern, str]] = [
    ("360 加固", re.compile(r"(?i)libjiagu|com/qihoo/util|jiagu\.dat|libjiagu_art"), "需脱壳（frida-dexdump / FRIDA-DEXDump）"),
    ("腾讯乐固", re.compile(r"(?i)libshella|StubShell|com/tencent/StubShell|libshellx"), "需脱壳"),
    ("梆梆加固", re.compile(r"(?i)libDexHelper|com/secneo/apkwrapper|libsecexe|libsecmain"), "需脱壳"),
    ("网易易盾", re.compile(r"(?i)libnesec|com/netease/nis"), "需脱壳"),
    ("阿里聚安全", re.compile(r"(?i)libmobisec|com/ali/mobisecenhance|aliprotect"), "需脱壳"),
    ("百度加固", re.compile(r"(?i)libbaiduprotect|com/baidu/protect"), "需脱壳"),
    ("爱加密", re.compile(r"(?i)libexecmain|s/h/e/l/o|ijiami"), "需脱壳"),
    ("VMP / 虚拟化壳", re.compile(r"(?i)libvmprotect|libvmp|vmprotect"), "需动态跟踪，静态改不动"),
    ("Unity IL2CPP", re.compile(r"(?i)libil2cpp|UnityPlayer"), "逻辑在 libil2cpp.so，dex 只是壳"),
    ("Flutter", re.compile(r"(?i)libflutter|libapp\.so"), "逻辑在 libapp.so（Dart AOT），dex 只是壳"),
    ("Cocos / 其他引擎", re.compile(r"(?i)libcocos|cocos2d"), "逻辑在 so 与 assets 脚本里"),
]


@dataclass
class HardeningReport:
    packers: list[tuple[str, str, str]] = field(default_factory=list)  # (名字, 证据, 建议)
    dyn_dex: list[str] = field(default_factory=list)
    nop_ratio: float = 0.0
    stripped_dex: bool = False
    native_libs: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def is_packed(self) -> bool:
        return bool(self.packers) or self.stripped_dex

    def lines(self) -> list[str]:
        L: list[str] = []
        if self.packers:
            for name, ev, adv in self.packers:
                L.append(f"- 壳/加固：**{name}**（证据 `{ev[:40]}`）→ {adv}")
        if self.stripped_dex:
            L.append(f"- **代码抽取壳特征**：方法体 nop 占比 {self.nop_ratio:.0%}"
                     "（真实逻辑不在静态 dex 里）→ 需脱壳后再改")
        if self.dyn_dex:
            L.append("- 动态加载 dex：" + "、".join(self.dyn_dex[:6])
                     + " → 运行时才有真实类，静态补丁只能改壳")
        if self.native_libs:
            L.append(f"- 自带 so {len(self.native_libs)} 个："
                     + "、".join(self.native_libs[:6])
                     + "（卡密若在 so 里，dex 补丁无效，需 Ghidra/Frida）")
        return L


def scan_hardening(root: str | Path, max_files: int = 6000) -> HardeningReport:
    """扫解包目录：壳 / 抽取 / 动态加载 / 原生库。只读，不改任何东西。"""
    r = HardeningReport()
    rt = Path(root)
    if not rt.is_dir():
        return r

    # ① 文件名与路径特征（so、assets）
    try:
        for p in rt.rglob("*"):
            if not p.is_file():
                continue
            name = p.name
            rel = str(p.relative_to(rt)).replace("\\", "/")
            if name.endswith(".so"):
                if len(r.native_libs) < 40:
                    r.native_libs.append(name)
            if rel.startswith(("lib/", "assets/")):
                for pname, rx, adv in _PACKERS:
                    if rx.search(name) or rx.search(rel):
                        if all(pname != x[0] for x in r.packers):
                            r.packers.append((pname, rel, adv))
    except OSError:
        pass

    # ② smali 内容特征 + nop 占比
    nop = ins = 0
    dex_seen: set[str] = set()
    scanned = 0
    for f in sorted(rt.rglob("*.smali")):
        scanned += 1
        if scanned > max_files:
            break
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        low = text.lower()
        for pname, rx, adv in _PACKERS:
            if all(pname != x[0] for x in r.packers) and rx.search(low):
                r.packers.append((pname, str(f.relative_to(rt)), adv))
        for m in re.finditer(r"Ldalvik/system/(\w*DexClassLoader|DexFile);|"
                             r"Ldalvik/system/InMemoryDexClassLoader;", text):
            dex_seen.add(m.group(1) or m.group(0))
        if f.name.startswith(("StubApp", "StubShell")):
            r.notes.append(f"存在壳入口类 {f.name}")
        for line in text.splitlines():
            t = line.strip()
            if t.startswith(("nop", "invoke-", "const", "iget", "iput", "sget",
                             "sput", "move", "new-", "if-", "goto", "return")):
                ins += 1
                if t == "nop":
                    nop += 1
    if ins:
        r.nop_ratio = nop / ins
        # 抽取壳：方法体被抽空，只剩 nop 与少量 return
        r.stripped_dex = r.nop_ratio > 0.55 and ins > 500
    r.dyn_dex = sorted(dex_seen)
    if r.stripped_dex:
        r.notes.append("nop 占比过高：方法体被抽取，需 dump 出真实 dex")
    return r
