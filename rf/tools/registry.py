#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 rf.tools.registry · 工具注册表
============================================================================

【设计思路】
    「内部集成了大量工具」这句话落地下来就是这张表：
      每个工具 = 一条记录（怎么调、要什么环境、能干什么、在不在）。

    上层（脚本 API / GUI / 流水线）只认 tool_id，不关心它到底是
    java -jar 还是 exe，也不关心路径在哪台机器上。换机器只需要重新探测。

【工具分类】
    android  —— APK / DEX / 资源 / 签名
    native   —— SO / ELF / PE / 反汇编 / 反编译
    archive  —— 解包、压缩包、固件镜像
    crypto   —— 加密识别与解密（部分是纯 Python 内部实现）
    net      —— 端口、协议
    internal —— 本工具自带，纯 Python 实现，永远可用

【探测结果缓存】
    探测要起子进程，慢。第一次 build() 后缓存住，GUI 手动"重新探测"才刷新。
============================================================================
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .. import config
from . import runner


# ---------------------------------------------------------------------------
# 版本缓存
#   探测版本要起子进程 —— jadx/apktool 每次都得拉起一个 JVM，17 个工具下来
#   十几秒就没了。把 (路径 → 版本) 落盘缓存，路径没变就直接用缓存。
#   换机器/换工具版本时点「重新探测」走 force=True 刷新。
# ---------------------------------------------------------------------------

def _ver_cache_path() -> Path:
    return config.USER_ROOT / "tool_versions.json"


def _ver_cache_read() -> dict:
    p = _ver_cache_path()
    try:
        if p.exists():
            return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


def _ver_cache_write(data: dict) -> None:
    try:
        config.ensure_dirs()
        _ver_cache_path().write_text(
            json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    except OSError:
        pass


@dataclass
class Tool:
    """一个可调用工具的描述。"""
    id: str
    name: str
    category: str                       # android / native / archive / crypto / net / internal
    desc: str = ""
    path: Path | None = None            # 主可执行文件（exe / bat / jar）
    prefix: list[str] = field(default_factory=list)
    # 完整调用前缀，如 ["java","-jar","apktool.jar"] 或 ["...jadx.bat"]
    version_args: list[str] = field(default_factory=lambda: ["--version"])
    jdk_major: int = 0                  # 0=不需要 Java；17/21=需要对应 JDK
    caps: list[str] = field(default_factory=list)
    internal: bool = False              # 纯 Python 实现
    _version: str | None = None
    _checked: bool = False
    _err: str = ""

    # ---- 状态 ----
    @property
    def available(self) -> bool:
        if self.internal:
            return True
        return self.path is not None and self.path.exists()

    def cmd(self, *args: str | Path) -> list[str]:
        """拼出完整命令行。"""
        return [str(x) for x in (self.prefix + [str(a) for a in args])]

    def check(self, force: bool = False) -> tuple[bool, str]:
        """
        探测可用性与版本。返回 (可用, 版本或错误)。

        结果缓存到磁盘，force=True 时重探（换工具版本后点「重新探测」）。
        """
        if self._checked and not force:
            return self.available, self._version or self._err
        self._checked = True

        if self.internal:
            self._version = "builtin"
            return True, "builtin"

        if not self.available:
            self._err = "未找到"
            return False, "未找到"

        # ---- 缓存命中：路径没变就直接用，省掉一次 JVM 启动 ----
        if not force:
            c = _ver_cache_read().get(self.id)
            if c and c.get("path") == str(self.path) and c.get("version"):
                self._version = c["version"]
                return True, self._version

        # Ghidra 这类大工具：读 properties 比跑程序快得多
        if self.id == "ghidra":
            v = _read_ghidra_version()
            if v:
                self._version = v
                self._remember(v)
                return True, v

        env_extra = {}
        if self.jdk_major:
            jdk = config.find_jdk(self.jdk_major)
            if not jdk:
                self._err = f"缺 JDK{self.jdk_major}"
                return True, self._err
            env_extra = runner.java_env(jdk)

        res = runner.run(self.cmd(*self.version_args), timeout=20, env_extra=env_extra)
        text = (res.out or "").strip()
        if not text:
            self._err = "版本未知"
            return True, "版本未知"

        # 版本行必须是"真正的版本行"：跳过 JVM 噪音、Npcap 警告、空行
        for line in text.splitlines():
            s = line.strip()
            if not s or runner.is_noise(s):
                continue
            if s.lower().startswith(("warning", "error:", "could not")):
                continue
            self._version = s[:80]
            self._remember(self._version)
            return True, self._version

        self._err = "版本未知"
        return True, "版本未知"

    def _remember(self, version: str) -> None:
        """把探测结果写进磁盘缓存。"""
        try:
            data = _ver_cache_read()
            data[self.id] = {"path": str(self.path), "version": version}
            _ver_cache_write(data)
        except Exception:
            pass

    def env(self) -> dict:
        """该工具需要的运行环境变量。"""
        if self.jdk_major:
            return runner.java_env(config.find_jdk(self.jdk_major))
        return {}

    def to_dict(self) -> dict:
        ok, ver = self.check()
        return {
            "id": self.id, "name": self.name, "category": self.category,
            "desc": self.desc, "path": str(self.path) if self.path else "",
            "available": ok, "version": ver, "caps": self.caps,
            "internal": self.internal,
        }


def _read_ghidra_version() -> str:
    h = config.find_ghidra_headless()
    if not h:
        return ""
    # <ghidra>/support/analyzeHeadless.bat -> <ghidra>/Ghidra/application.properties
    root = h.parent.parent
    prop = root / "Ghidra" / "application.properties"
    if prop.exists():
        try:
            for line in prop.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.startswith("application.version"):
                    return "Ghidra " + line.split("=", 1)[-1].strip()
        except OSError:
            pass
    return root.name


class Registry:
    """工具注册表。"""

    def __init__(self):
        self.tools: dict[str, Tool] = {}
        self._built = False

    # ---- 构建 ----
    def build(self, force: bool = False) -> "Registry":
        if self._built and not force:
            return self
        self.tools = {}
        s = config.load_settings()
        overrides = s.get("tool_overrides", {}) or {}

        def add(t: Tool):
            ov = overrides.get(t.id)
            if ov and Path(ov).exists():
                t.path = Path(ov)
                t.prefix = _prefix_for(t.id, t.path)
            self.tools[t.id] = t

        java = config.find_java()
        jrun = [str(java / "bin" / "java.exe")] if java else ["java"]

        # ---------- Android ----------
        jadx = config.find_jadx_bin()
        add(Tool(
            id="jadx", name="jadx", category="android",
            desc="DEX/APK → Java 源码反编译，支持去混淆命名、资源解码",
            path=jadx, prefix=[str(jadx)] if jadx else [],
            version_args=["--version"], jdk_major=17,
            caps=["dex2java", "deobf", "resources", "search"],
        ))

        apktool = config.find_apktool_jar()
        add(Tool(
            id="apktool", name="Apktool", category="android",
            desc="APK 解包/重打包：resources.arsc 解码、Manifest 反编译为可读 XML",
            path=apktool, prefix=jrun + ["-jar", str(apktool)] if apktool else [],
            version_args=["--version"], jdk_major=17,
            caps=["unpack", "repack", "resources", "manifest", "smali"],
        ))

        apksigner = config.find_apksigner()
        add(Tool(
            id="apksigner", name="apksigner", category="android",
            desc="APK 签名与签名校验（v1/v2/v3）",
            path=apksigner,
            prefix=[str(apksigner)] if apksigner else [],
            version_args=["--version"], jdk_major=17,
            caps=["sign", "verify"],
        ))

        adb = _find_adb()
        add(Tool(
            id="adb", name="adb", category="android",
            desc="设备连接、拉取 APK、查看进程与内存映射",
            path=adb, prefix=[str(adb)] if adb else [],
            version_args=["version"], caps=["pull", "shell", "install"],
        ))

        aapt2 = _find_aapt2()
        add(Tool(
            id="aapt2", name="aapt2", category="android",
            desc="读取 APK 包信息：包名、版本、SDK、权限（badging）",
            path=aapt2, prefix=[str(aapt2)] if aapt2 else [],
            version_args=["version"], caps=["badging", "dump"],
        ))

        # ---------- Native ----------
        rizin = config.find_rizin_bin()
        add(Tool(
            id="rizin", name="rizin", category="native",
            desc="反汇编引擎：SO/ELF/PE 反汇编、函数识别、交叉引用、字符串",
            path=rizin, prefix=[str(rizin)] if rizin else [],
            version_args=["-v"], caps=["disasm", "functions", "xrefs", "strings", "patch"],
        ))

        rzb = config.find_rz_bin()
        add(Tool(
            id="rz-bin", name="rz-bin", category="native",
            desc="二进制元信息：段表、节表、导入导出符号、依赖库",
            path=rzb, prefix=[str(rzb)] if rzb else [],
            version_args=["-v"], caps=["sections", "imports", "exports", "libs", "info"],
        ))

        gh = config.find_ghidra_headless()
        add(Tool(
            id="ghidra", name="Ghidra Headless", category="native",
            desc="重量级反编译器：输出类 C 伪代码，需 JDK21，单函数数十秒",
            path=gh, prefix=[str(gh)] if gh else [],
            version_args=[], jdk_major=21,
            caps=["decompile", "pcode", "callgraph", "types"],
        ))

        # ---------- Archive ----------
        sz = config.find_7zr()
        add(Tool(
            id="7z", name="7-Zip", category="archive",
            desc="通用解包：zip/apk/tar/tgz/7z/iso/img，可列出加密包结构",
            path=sz, prefix=[str(sz)] if sz else [],
            version_args=[], caps=["extract", "list", "test"],
        ))

        # ---------- Net ----------
        nmap = _find_nmap()
        add(Tool(
            id="nmap", name="nmap", category="net",
            desc="端口与服务识别（部分环境会被拦截，可用纯 Python 扫描替代）",
            path=nmap, prefix=[str(nmap)] if nmap else [],
            version_args=["--version"], caps=["portscan", "service"],
        ))

        # ---------- Internal（纯 Python，永在） ----------
        for tid, tname, tdesc, caps in (
            ("dex", "DEX 解析器", "DEX 魔数/版本/类与方法计数/字符串池（自研）", ["info", "strings", "classes"]),
            ("elf", "ELF 解析器", "ELF 头、段、节、符号、加固特征（自研）", ["info", "sections", "harden"]),
            ("pe", "PE 解析器", "PE 头、节、导入表、壳特征（自研）", ["info", "imports", "packer"]),
            ("crypto", "加密识别", "按魔数/熵/结构识别加密与压缩容器，尝试弱口令解密（自研）", ["detect", "decrypt", "entropy"]),
            ("strings", "字符串提取", "多编码字符串提取（ASCII/UTF-16/GBK）并分类（URL/路径/密钥）", ["extract", "classify"]),
            ("hash", "哈希与熵", "MD5/SHA1/SHA256/CRC32 与香农熵（自研）", ["hash", "entropy"]),
            ("annotate", "中文注释器", "给反编译源码插入方法级中文注释与用途推断（自研）", ["annotate", "infer"]),
        ):
            add(Tool(
                id=tid, name=tname, category="internal", desc=tdesc,
                internal=True, caps=caps, version_args=[],
            ))

        self._built = True
        return self

    # ---- 查询 ----
    def get(self, tid: str) -> Tool:
        if not self._built:
            self.build()
        if tid not in self.tools:
            raise KeyError(f"未注册的工具：{tid}")
        return self.tools[tid]

    def has(self, tid: str) -> bool:
        if not self._built:
            self.build()
        t = self.tools.get(tid)
        return bool(t and t.available)

    def by_category(self, cat: str) -> list[Tool]:
        if not self._built:
            self.build()
        return [t for t in self.tools.values() if t.category == cat]

    def all(self) -> list[Tool]:
        if not self._built:
            self.build()
        return list(self.tools.values())

    def status(self) -> list[dict]:
        return [t.to_dict() for t in self.all()]

    def summary(self) -> str:
        """一行摘要，GUI 顶栏用。"""
        ok = sum(1 for t in self.all() if t.available)
        total = len(self.tools)
        return f"工具 {ok}/{total} 可用"

    def missing_required(self) -> list[str]:
        """跑核心 APK 流水线所必需、但当前缺失的工具。"""
        need = ["jadx", "apktool", "7z"]
        return [t for t in need if not self.has(t)]


# ---------------------------------------------------------------------------
# 辅助探测
# ---------------------------------------------------------------------------

def _prefix_for(tid: str, path: Path) -> list[str]:
    """用户手动指定路径后，重建调用前缀。"""
    if path.suffix.lower() == ".jar":
        java = config.find_java()
        jrun = [str(java / "bin" / "java.exe")] if java else ["java"]
        return jrun + ["-jar", str(path)]
    if path.suffix.lower() in (".bat", ".cmd", ".exe") or not path.suffix:
        return [str(path)]
    return [str(path)]


def _find_adb() -> Path | None:
    for v in config.vendor_dirs():
        for c in (v / "platform-tools/adb.exe", v / "adb.exe", v / "bin/adb.exe"):
            if c.exists():
                return c
    for base in (r"D:\android_tools\sdk\platform-tools", r"E:\Tools\platform-tools",
                 r"C:\Android\Sdk\platform-tools"):
        p = Path(base) / "adb.exe"
        if p.exists():
            return p
    w = runner.which("adb")
    return Path(w) if w else None


def _find_aapt2() -> Path | None:
    for v in config.vendor_dirs():
        hits = sorted(v.glob("build-tools/*/aapt2.exe"), reverse=True)
        if hits:
            return hits[0]
        for c in (v / "aapt2.exe", v / "bin/aapt2.exe"):
            if c.exists():
                return c
    for sdk in (r"D:\android_tools\sdk", r"C:\Android\Sdk"):
        hits = sorted(Path(sdk).glob("build-tools/*/aapt2.exe"), reverse=True)
        if hits:
            return hits[0]
        hits = sorted(Path(sdk).glob("build-tools/*/aapt.exe"), reverse=True)
        if hits:
            return hits[0]
    w = runner.which("aapt2") or runner.which("aapt")
    return Path(w) if w else None


def _find_nmap() -> Path | None:
    for base in (r"D:\android_tools\tools\nmap", r"E:\Tools\nmap"):
        hits = sorted(Path(base).glob("**/nmap.exe"))
        if hits:
            return hits[0]
    for p in (r"C:\Program Files (x86)\Nmap\nmap.exe", r"C:\Program Files\Nmap\nmap.exe"):
        if Path(p).exists():
            return Path(p)
    w = runner.which("nmap")
    return Path(w) if w else None


# 全局单例
REGISTRY = Registry()


def registry() -> Registry:
    return REGISTRY.build()
