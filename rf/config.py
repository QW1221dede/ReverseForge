#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 rf.config · 全局配置与工具链路径探测
============================================================================

【职责】
    1. 定位本机已安装的逆向工具（jadx / apktool / rizin / Ghidra / 7zr / nmap ...）
    2. 决定 JDK 用哪一个（jadx 要 JDK17+，Ghidra 12 要 JDK21）
    3. 维护工作区目录（每个分析目标一个独立子目录，产物不互相污染）
    4. 读写用户配置 JSON

【设计原则】
    * 探测顺序：显式配置 > 环境变量 > 候选路径 > PATH 查找。
    * 版本目录名带版本号（如 ghidra_12.2_PUBLIC），一律用通配匹配，不硬编码。
    * 任何一项探测失败都不抛异常，只返回 None —— 让上层决定降级策略。
============================================================================
"""

from __future__ import annotations

import functools
import json
import os
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# 基础目录
# ---------------------------------------------------------------------------

APP_NAME = "ReverseForge"
APP_CN = "逆锻台"
APP_VERSION = "1.0.1"


def _user_root() -> Path:
    """用户级数据目录，不放在程序目录里，避免打包成 exe 后写不进去。"""
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
    if base:
        return Path(base) / APP_NAME
    return Path.home() / ("." + APP_NAME.lower())


USER_ROOT: Path = _user_root()
WORKSPACE_ROOT: Path = USER_ROOT / "workspace"      # 每次分析一个子目录
LOG_ROOT: Path = USER_ROOT / "logs"                 # 运行日志
SCRIPT_ROOT: Path = USER_ROOT / "scripts"           # 用户自定义脚本
CONFIG_FILE: Path = USER_ROOT / "settings.json"     # 用户配置

# 程序自带资源（打包后指向 sys._MEIPASS）
def _app_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
    return Path(__file__).resolve().parent.parent


APP_ROOT: Path = _app_root()
BUILTIN_SCRIPT_ROOT: Path = APP_ROOT / "scripts"


def ensure_dirs() -> None:
    """确保所有运行期目录存在。启动时调用一次。"""
    for d in (USER_ROOT, WORKSPACE_ROOT, LOG_ROOT, SCRIPT_ROOT):
        try:
            d.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# 工具链根目录候选
# ---------------------------------------------------------------------------

# 这台机器上的实际布局，同时兼顾别人的机器
TOOLCHAIN_ROOTS: list[Path] = [
    Path(r"D:\android_tools\tools"),
    Path(r"D:\android_tools"),
    Path(r"E:\Tools"),
    Path(r"C:\Tools"),
    Path(r"D:\Tools"),
]

# ---------------------------------------------------------------------------
# 内置工具目录（vendor）
#
# "开箱即用"的落地方式：安装脚本把 jdk/apktool/adb/aapt2/apksigner/7zr
# 装到这里，程序优先用它，完全不依赖系统里装了什么。
#
# 三个位置都要认：
#   1. RF_VENDOR 环境变量（调试/便携版用）
#   2. 程序目录/vendor         （绿色版：整目录拷走就能用）
#   3. %LOCALAPPDATA%/ReverseForge/vendor （安装版：install.ps1 装到这里）
# ---------------------------------------------------------------------------

def vendor_dirs() -> list[Path]:
    ds: list[Path] = []
    env = os.environ.get("RF_VENDOR", "").strip()
    if env:
        ds.append(Path(env))
    exe_dir = Path(sys.executable).parent
    ds.append(exe_dir / "vendor")
    ds.append(APP_ROOT / "vendor")
    ds.append(USER_ROOT / "vendor")
    seen: set[str] = set()
    out: list[Path] = []
    for d in ds:
        try:
            key = str(d.resolve()).lower()
        except OSError:
            continue
        if key in seen:
            continue
        seen.add(key)
        if d.is_dir():
            out.append(d)
    return out


def _vendor_sub(*parts: str) -> list[Path]:
    """在 vendor 下按相对路径展开成候选（存在才返回）。"""
    out: list[Path] = []
    for v in vendor_dirs():
        p = v.joinpath(*parts)
        if p.exists():
            out.append(p)
    return out


# 把 vendor 塞到搜索列表最前面 —— 内置的优先于系统装的，
# 版本可控，也不会因为用户机器上有个旧 JDK 就跑不起来。
_VENDOR0 = vendor_dirs()
if _VENDOR0:
    TOOLCHAIN_ROOTS = _VENDOR0 + TOOLCHAIN_ROOTS

JDK_CANDIDATES: list[Path] = [
    *[v / "jdk" for v in _VENDOR0],
    *[p for v in _VENDOR0 for p in sorted(v.glob("jdk*")) if p.is_dir()],
    Path(r"D:\android_tools\jdk21"),
    Path(r"D:\android_tools\jdk17"),
    Path(r"C:\Program Files\Eclipse Adoptium"),
    Path(r"C:\Program Files\Java"),
    Path(r"C:\Program Files\Microsoft"),
]


def _glob_dir(root: Path, pattern: str) -> Path | None:
    """
    在 root 下按通配找目录，取"版本号最大"的那个。

    版本号排序用朴素的分段数字比较，不做完整 semver 解析 —— 够用。
    """
    if not root.is_dir():
        return None
    hits = [p for p in root.glob(pattern) if p.is_dir()]
    if not hits:
        return None

    def _key(p: Path):
        parts = []
        for seg in p.name.replace("-", ".").replace("_", ".").split("."):
            parts.append((0, int(seg), "") if seg.isdigit() else (1, 0, seg))
        return parts

    try:
        hits.sort(key=_key)
    except Exception:
        pass
    return hits[-1]


def find_jdk(major: int) -> Path | None:
    """
    找一个指定大版本的 JDK 根目录（含 bin/java.exe）。

    major=17 给 jadx/apktool；major=21 给 Ghidra 12。
    """
    env_key = f"JAVA_HOME_{major}"
    if os.environ.get(env_key):
        p = Path(os.environ[env_key])
        if (p / "bin" / "java.exe").exists():
            return p

    patterns = [
        f"jdk{major}*", f"jdk-{major}*", f"*jdk*{major}*",
        f"jdk-{major}.0*", f"jdk{major}.0*",
    ]
    for root in JDK_CANDIDATES:
        for pat in patterns:
            hit = _glob_dir(root, pat)
            if hit and (hit / "bin" / "java.exe").exists():
                return hit
            # 有的目录是 jdk-21.0.13+9 这种，再下钻一层
            if hit:
                for sub in hit.iterdir() if hit.is_dir() else []:
                    if sub.is_dir() and (sub / "bin" / "java.exe").exists():
                        return sub

    # 最后看 PATH 里的 java
    java = shutil.which("java")
    if java:
        home = Path(java).resolve().parent.parent
        try:
            out = run_quiet([str(Path(java)), "-version"])
            if f'version "{major}.' in out or f"version {major}." in out:
                return home
        except Exception:
            pass
    return None


def find_java() -> Path | None:
    """通用 java（优先 17，其次任意在 PATH 里的）。"""
    return find_jdk(17) or find_jdk(21)


def run_quiet(cmd: list[str], timeout: int = 8) -> str:
    """跑一条命令，只取输出文本；失败返回空串。用于版本探测。"""
    import subprocess

    flags = 0
    if sys.platform == "win32":
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        p = subprocess.run(
            cmd, capture_output=True, timeout=timeout, creationflags=flags,
        )
        raw = (p.stdout or b"") + (p.stderr or b"")
        for enc in ("utf-8", "gbk", "cp936"):
            try:
                return raw.decode(enc)
            except UnicodeDecodeError:
                continue
        return raw.decode("utf-8", "replace")
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# 工具路径探测
# ---------------------------------------------------------------------------

def _first_existing(paths: list[Path]) -> Path | None:
    for p in paths:
        if p.exists():
            return p
    return None


def find_jadx_bin() -> Path | None:
    """jadx 命令行入口（.bat / .exe / 无扩展的 shell 脚本）。"""
    roots = list(TOOLCHAIN_ROOTS)
    cands: list[Path] = list(_vendor_sub("jadx", "bin", "jadx.bat"))
    cands += _vendor_sub("jadx", "bin", "jadx.exe")
    for r in roots:
        for sub in ("jadx/bin", "tools/jadx/bin", "jadx"):
            cands.append(r / sub / "jadx.bat")
            cands.append(r / sub / "jadx.exe")
            cands.append(r / sub / "jadx")
    # 通配一层（jadx-1.5.6 之类）
    for r in roots:
        for pat in ("jadx*/bin/jadx.bat", "tools/jadx*/bin/jadx.bat"):
            cands.extend(sorted(r.glob(pat)))
    hit = _first_existing(cands)
    if hit:
        return hit
    w = shutil.which("jadx") or shutil.which("jadx.bat")
    return Path(w) if w else None


def find_apktool_jar() -> Path | None:
    roots = list(TOOLCHAIN_ROOTS)
    cands: list[Path] = list(_vendor_sub("apktool.jar"))
    cands += _vendor_sub("apktool", "apktool.jar")
    for r in roots:
        cands += [r / "apktool.jar", r / "tools/apktool.jar"]
        cands += sorted(r.glob("apktool*.jar"))
        cands += sorted(r.glob("tools/apktool*.jar"))
    return _first_existing(cands)


# 全盘找工具时必须跳过的目录：SDK / 语言运行时 / 依赖缓存，
# 这些里面绝不会有我们要的逆向工具，但文件数占九成以上。
_SKIP_DIRS = {
    "sdk", "cmdline-tools", "rustup", "node_modules", ".git", ".svn",
    "platforms", "build-tools", "system-images", "emulator", "sources",
    "jdk17", "jdk21", "__pycache__", "site-packages", "system32",
}


def _find_by_name(root: Path, filename: str, max_depth: int = 5,
                  limit: int = 8) -> list[Path]:
    """
    按文件名查找，带深度上限 + 跳过无关大目录。

    比 Path.glob("**/x") 快几十倍 —— 后者会把整个 Android SDK
    的几万个文件都遍历一遍（实测单个 glob 19 秒）。
    """
    if not root.is_dir():
        return []
    want = filename.lower()
    out: list[Path] = []
    base = len(root.parts)
    try:
        for dirpath, dirnames, filenames in os.walk(root):
            d = Path(dirpath)
            if len(d.parts) - base >= max_depth:
                dirnames[:] = []
            else:
                dirnames[:] = [x for x in dirnames if x.lower() not in _SKIP_DIRS]
            if want in {f.lower() for f in filenames}:
                out.append(d / filename)
                if len(out) >= limit:
                    break
    except OSError:
        pass
    return out


def find_rizin_bin() -> Path | None:
    cands: list[Path] = []
    for r in TOOLCHAIN_ROOTS:
        cands += [r / "rizin" / "bin" / "rizin.exe", r / "tools/rizin/bin/rizin.exe"]
        cands += _find_by_name(r, "rizin.exe")
        if len(cands) >= 8:
            break
    hit = _first_existing(cands)
    if hit:
        return hit
    w = shutil.which("rizin")
    return Path(w) if w else None


def find_rz_bin() -> Path | None:
    rz = find_rizin_bin()
    if rz:
        sib = rz.with_name("rz-bin.exe")
        if sib.exists():
            return sib
    w = shutil.which("rz-bin")
    return Path(w) if w else None


def find_ghidra_headless() -> Path | None:
    cands: list[Path] = []
    for r in TOOLCHAIN_ROOTS:
        cands += [r / "ghidra/support/analyzeHeadless.bat"]
        cands += _find_by_name(r, "analyzeHeadless.bat", max_depth=6)
        if len(cands) >= 8:
            break
    return _first_existing(cands)


def find_7zr() -> Path | None:
    roots = list(TOOLCHAIN_ROOTS)
    cands: list[Path] = _vendor_sub("7zr.exe") + _vendor_sub("7z.exe")
    for r in roots:
        cands += [r / "7zr.exe", r / "tools/7zr.exe", r / "7z.exe", r / "tools/7z.exe"]
    hit = _first_existing(cands)
    if hit:
        return hit
    for name in ("7zr", "7z"):
        w = shutil.which(name)
        if w:
            return Path(w)
    for p in (r"C:\Program Files\7-Zip\7z.exe", r"C:\Program Files (x86)\7-Zip\7z.exe"):
        if Path(p).exists():
            return Path(p)
    return None


def find_apksigner() -> Path | None:
    cands: list[Path] = []
    for v in vendor_dirs():
        cands += sorted(v.glob("build-tools/*/apksigner.bat"), reverse=True)
        cands += sorted(v.glob("build-tools/*/lib/apksigner.jar"), reverse=True)
        cands += [v / "apksigner.bat", v / "bin/apksigner.bat"]
    for sdk in (r"D:\android_tools\sdk", r"C:\Android\Sdk", r"E:\Tools\AndroidBuild"):
        cands += sorted(Path(sdk).glob("build-tools/*/apksigner.bat"), reverse=True)
        cands += sorted(Path(sdk).glob("build-tools/*/lib/apksigner.jar"), reverse=True)
    return _first_existing(cands)


def python_exe() -> str:
    """当前解释器路径 —— 脚本里要起 Python 子进程时用。"""
    return sys.executable or "python"


# ---------------------------------------------------------------------------
# 用户配置
# ---------------------------------------------------------------------------

DEFAULT_SETTINGS: dict = {
    "tool_overrides": {},          # {"jadx": "D:/xx/jadx.bat"}
    "last_target": "",
    "auto_open_output": True,
    "term_font_size": 10,
    "code_font_size": 11,
    "annotate": {
        "enable": True,
        "max_methods_per_file": 200,
        "infer_from_api": True,
        "mark_obfuscated": True,
    },
    "llm": {
        "enable": False,
        "base_url": "",
        "api_key": "",
        "model": "",
    },
}


@dataclass
class Settings:
    data: dict = field(default_factory=dict)

    def __post_init__(self):
        merged = json.loads(json.dumps(DEFAULT_SETTINGS))
        _deep_merge(merged, self.data or {})
        self.data = merged

    def get(self, key: str, default=None):
        cur = self.data
        for seg in key.split("."):
            if not isinstance(cur, dict) or seg not in cur:
                return default
            cur = cur[seg]
        return cur

    def set(self, key: str, value) -> None:
        segs = key.split(".")
        cur = self.data
        for seg in segs[:-1]:
            cur = cur.setdefault(seg, {})
        cur[segs[-1]] = value

    def save(self) -> None:
        ensure_dirs()
        try:
            CONFIG_FILE.write_text(
                json.dumps(self.data, ensure_ascii=False, indent=2), encoding="utf-8"
            )
        except OSError:
            pass


def _deep_merge(dst: dict, src: dict) -> None:
    for k, v in src.items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            _deep_merge(dst[k], v)
        else:
            dst[k] = v


def load_settings() -> Settings:
    if CONFIG_FILE.exists():
        try:
            return Settings(json.loads(CONFIG_FILE.read_text(encoding="utf-8")))
        except Exception:
            pass
    return Settings()


# ---------------------------------------------------------------------------
# 进程内缓存
#   工具路径探测要遍历磁盘，一次几十毫秒到几百毫秒。同一进程里重复调用
#   （注册表构建、每个工具取 JDK、脚本里反复 tool()）没必要重复扫。
# ---------------------------------------------------------------------------
for _fn in (
    find_jdk, find_java, find_jadx_bin, find_apktool_jar,
    find_rizin_bin, find_rz_bin, find_ghidra_headless, find_7zr, find_apksigner,
):
    globals()[_fn.__name__] = functools.lru_cache(maxsize=None)(_fn)
del _fn
