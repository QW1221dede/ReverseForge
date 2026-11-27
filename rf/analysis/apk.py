#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 rf.analysis.apk · APK 拆解流水线
============================================================================

【一条命令走完的六步】
    1. 预检        校验是合法 zip、读出条目清单（用标准库 zipfile，不靠外部工具）
    2. 包信息      aapt2 dump badging → 包名/版本/SDK/权限/组件/label
    3. 资源解包    apktool d → 可读 AndroidManifest.xml、res/、smali/
    4. 源码反编译  jadx → Java 源码（sources/），失败自动降级只出 smali
    5. 规模统计    逐个 dex 解析类/方法/字符串，扫 lib/*.so
    6. 加固判定    文件名 + 字符串池双路匹配，命中即明确告知"需脱壳"

【为什么 apktool 和 jadx 都要跑】
    两者产出的东西不重叠：
      apktool → 资源、Manifest、smali（字节码级，改包必需）
      jadx    → Java 源码（读逻辑必需，但可能因混淆/加固不完整）
    只跑一个都算残废。

【失败降级策略】
    apktool 失败 → 继续 jadx（源码比资源重要）
    jadx 失败   → 保留 smali，报告里标注"需人工/换工具"
    全程不抛异常，所有错误进 result.errors，GUI 逐条展示。
============================================================================
"""

from __future__ import annotations

import json
import os
import re
import shutil
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .. import config
from ..tools import runner
from ..tools.registry import registry
from . import dex as dexmod


# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------

@dataclass
class ApkInfo:
    """APK 的静态画像。"""
    path: str = ""
    size: int = 0
    valid: bool = False
    package: str = ""
    version_name: str = ""
    version_code: str = ""
    label: str = ""
    min_sdk: str = ""
    target_sdk: str = ""
    permissions: list[str] = field(default_factory=list)
    activities: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    receivers: list[str] = field(default_factory=list)
    providers: list[str] = field(default_factory=list)
    native_libs: list[str] = field(default_factory=list)
    dex_files: list[str] = field(default_factory=list)
    entry_count: int = 0
    packers: list[str] = field(default_factory=list)
    dex_stats: dict = field(default_factory=dict)   # {"classes":n,"methods":n,...}
    errors: list[str] = field(default_factory=list)
    warns: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            k: v for k, v in self.__dict__.items()
        }


@dataclass
class UnpackResult:
    """拆解产物路径与状态。"""
    workdir: str = ""
    apktool_dir: str = ""
    jadx_dir: str = ""
    sources_dir: str = ""
    ok_apktool: bool = False
    ok_jadx: bool = False
    dur: float = 0.0
    errors: list[str] = field(default_factory=list)
    log: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return dict(self.__dict__)


# ---------------------------------------------------------------------------
# 预检
# ---------------------------------------------------------------------------

def inspect(apk: str | Path) -> ApkInfo:
    """
    不调用任何外部工具，纯标准库拿到 APK 的基本画像。

    这一步必须快（<1s），GUI 里选中文件就能立刻显示信息。
    """
    p = Path(apk)
    info = ApkInfo(path=str(p))
    if not p.exists():
        info.errors.append("文件不存在")
        return info
    info.size = p.stat().st_size
    if not zipfile.is_zipfile(p):
        info.errors.append("不是合法 ZIP/APK（可能是分片、加密包或已损坏）")
        return info

    info.valid = True
    try:
        with zipfile.ZipFile(p) as z:
            names = z.namelist()
            info.entry_count = len(names)
            info.dex_files = sorted(n for n in names if re.match(r"^classes\d*\.dex$", n))
            info.native_libs = sorted(n for n in names if n.startswith("lib/") and n.endswith(".so"))
            info.warns.extend(_zip_warns(z, names))
            # 加密包：条目被标记为加密，标准库读不了
            enc = [zi.filename for zi in z.infolist() if zi.flag_bits & 0x1]
            if enc:
                info.warns.append(f"有 {len(enc)} 个条目为加密状态（zipcrypto/AES），需先解密才能解包")
    except Exception as e:
        info.errors.append(f"读 ZIP 失败：{e}")
        return info

    # badging：拿包名等信息，失败不影响整体
    bad = _aapt_badging(p)
    if bad:
        info.package = bad.get("package", "")
        info.version_name = bad.get("versionName", "")
        info.version_code = bad.get("versionCode", "")
        info.label = bad.get("label", "")
        info.min_sdk = bad.get("sdkVersion", "")
        info.target_sdk = bad.get("targetSdkVersion", "")
        info.permissions = bad.get("permissions", [])
        info.activities = bad.get("activities", [])
        info.services = bad.get("services", [])
        info.receivers = bad.get("receivers", [])
        info.providers = bad.get("providers", [])
    else:
        info.warns.append("aapt2 不可用，包名等信息需解包后从 Manifest 读")

    # 加固判定：文件名 + 少量 dex 字符串
    strs: list[str] = []
    try:
        with zipfile.ZipFile(p) as z:
            for n in info.dex_files[:2]:
                try:
                    data = z.read(n)[:2_000_000]
                    h = dexmod.parse_header(data)
                    strs.extend(dexmod.read_strings(data, h, 8000))
                except Exception:
                    pass
    except Exception:
        pass
    info.packers = dexmod.detect_packer(
        [n for n in (info.native_libs + info.dex_files)], strs
    )
    return info


def _zip_warns(z: zipfile.ZipFile, names: list[str]) -> list[str]:
    w = []
    if "AndroidManifest.xml" not in names:
        w.append("缺少 AndroidManifest.xml —— 可能不是完整 APK")
    if "resources.arsc" not in names:
        w.append("缺少 resources.arsc —— 资源可能被剥离或加密")
    if any(n.startswith("assets/") and n.endswith(".dex") for n in names):
        w.append("assets/ 下存在 dex —— 典型加固/多 dex 特征")
    return w


def _aapt_badging(apk: Path) -> dict | None:
    """解析 aapt2 dump badging 输出。"""
    reg = registry()
    if not reg.has("aapt2"):
        return None
    t = reg.get("aapt2")
    res = runner.run(t.cmd("dump", "badging", apk), timeout=60)
    if not res.out:
        return None

    out: dict = {"permissions": [], "activities": [], "services": [],
                 "receivers": [], "providers": []}
    for line in res.out.splitlines():
        line = line.strip()
        try:
            if line.startswith("package:"):
                m = re.search(r"name='([^']*)'", line)
                if m:
                    out["package"] = m.group(1)
                m = re.search(r"versionCode='([^']*)'", line)
                if m:
                    out["versionCode"] = m.group(1)
                m = re.search(r"versionName='([^']*)'", line)
                if m:
                    out["versionName"] = m.group(1)
            elif line.startswith("sdkVersion:"):
                out["sdkVersion"] = line.split(":", 1)[1].strip().strip("'")
            elif line.startswith("targetSdkVersion:"):
                out["targetSdkVersion"] = line.split(":", 1)[1].strip().strip("'")
            elif line.startswith("application-label:"):
                out["label"] = line.split(":", 1)[1].strip().strip("'")
            elif line.startswith("uses-permission:"):
                m = re.search(r"name='([^']*)'", line)
                if m:
                    out["permissions"].append(m.group(1))
            elif line.startswith(("launchable-activity:", "activity:")):
                m = re.search(r"name='([^']*)'", line)
                if m and m.group(1) not in out["activities"]:
                    out["activities"].append(m.group(1))
            elif line.startswith("service:"):
                m = re.search(r"name='([^']*)'", line)
                if m:
                    out["services"].append(m.group(1))
            elif line.startswith("receiver:"):
                m = re.search(r"name='([^']*)'", line)
                if m:
                    out["receivers"].append(m.group(1))
            elif line.startswith("provider:"):
                m = re.search(r"name='([^']*)'", line)
                if m:
                    out["providers"].append(m.group(1))
        except Exception:
            continue
    return out


# ---------------------------------------------------------------------------
# 流水线
# ---------------------------------------------------------------------------

class ApkPipeline:
    """
    APK 全流程拆解。

    用法：
        pipe = ApkPipeline("x.apk", "out/xxx")
        pipe.on_line = print
        res = pipe.run()
    """

    def __init__(self, apk: str | Path, workdir: str | Path | None = None):
        self.apk = Path(apk)
        self.workdir = Path(workdir) if workdir else self._default_workdir()
        self.on_line: Callable[[str], None] | None = None
        self.on_step: Callable[[str, int, str], None] | None = None   # (步骤, 百分比, 说明)
        self.info: ApkInfo | None = None
        self.result = UnpackResult(workdir=str(self.workdir))
        self._t0 = 0.0

    # ---- 输出 ----
    def _default_workdir(self) -> Path:
        stem = re.sub(r"[^\w\-.]+", "_", self.apk.stem)[:60]
        ts = time.strftime("%Y%m%d_%H%M%S")
        return config.WORKSPACE_ROOT / f"{stem}_{ts}"

    def log(self, msg: str) -> None:
        self.result.log.append(msg)
        if self.on_line:
            try:
                self.on_line(msg)
            except Exception:
                pass

    def step(self, name: str, pct: int, detail: str = "") -> None:
        self.log(f"── [{pct:>3}%] {name}" + (f" · {detail}" if detail else ""))
        if self.on_step:
            try:
                self.on_step(name, pct, detail)
            except Exception:
                pass

    # ---- 主流程 ----
    def run(self, do_apktool: bool = True, do_jadx: bool = True,
            do_annotate: bool = False) -> UnpackResult:
        self._t0 = time.time()
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.step("预检", 2, self.apk.name)

        self.info = inspect(self.apk)
        if not self.info.valid:
            self.result.errors.extend(self.info.errors)
            self.log("✗ 预检失败：" + "；".join(self.info.errors))
            self.result.dur = time.time() - self._t0
            return self.result

        self.log(f"✓ 包名 {self.info.package or '未知'}  版本 {self.info.version_name or '?'}"
                 f"  大小 {self.info.size / 1048576:.1f}MB  条目 {self.info.entry_count}")
        if self.info.packers:
            self.log(f"⚠ 疑似加固：{'、'.join(self.info.packers)} —— 反编译结果会大量缺失，需先脱壳")

        # 3. apktool
        if do_apktool:
            self.step("资源解包", 12, "apktool d")
            self._run_apktool()
        # 4. jadx
        if do_jadx:
            self.step("源码反编译", 40, "jadx -d")
            self._run_jadx()

        # 5. 统计
        self.step("规模统计", 82, "dex / so")
        self._collect_stats()

        # 6. 落盘报告
        self.step("写报告", 94)
        self._write_reports()

        self.result.dur = time.time() - self._t0
        self.step("完成", 100, f"{self.result.dur:.1f}s")
        return self.result

    # ---- 各步实现 ----
    def _run_apktool(self) -> None:
        reg = registry()
        if not reg.has("apktool"):
            self.result.errors.append("apktool 不可用，跳过资源解包")
            self.log("✗ apktool 不可用，跳过")
            return
        t = reg.get("apktool")
        out = self.workdir / "apktool"
        cmd = t.cmd("d", "-f", "--no-debug-info", "-o", out, self.apk)
        res = runner.run(cmd, timeout=900, on_line=self._stream("apktool"),
                         env_extra=t.env(), log_name=f"apktool_{self.apk.stem}")
        self.result.ok_apktool = res.ok and (out / "AndroidManifest.xml").exists()
        self.result.apktool_dir = str(out) if out.exists() else ""
        if not self.result.ok_apktool:
            msg = f"apktool 失败 rc={res.rc} {res.tail(8)}"
            self.result.errors.append(msg)
            self.log("✗ " + msg)
        else:
            n_smali = len(list(out.rglob("*.smali")))
            self.log(f"✓ 资源解包完成：smali {n_smali} 个，Manifest "
                     f"{'已解码' if self.result.ok_apktool else '未解码'}")

    def _run_jadx(self) -> None:
        reg = registry()
        if not reg.has("jadx"):
            self.result.errors.append("jadx 不可用，跳过源码反编译")
            self.log("✗ jadx 不可用，跳过")
            return
        t = reg.get("jadx")
        out = self.workdir / "jadx"
        # --no-res：资源交给 apktool，避免重复
        # --show-bad-code：反编译失败的类也保留可读骨架，不整类丢弃
        cmd = t.cmd("-d", out, "--no-res", "--show-bad-code",
                    "-j", "4", "--log-level", "warn", self.apk)
        res = runner.run(cmd, timeout=1800, on_line=self._stream("jadx"),
                         env_extra=t.env(), log_name=f"jadx_{self.apk.stem}")
        src = out / "sources"
        self.result.jadx_dir = str(out) if out.exists() else ""
        self.result.sources_dir = str(src) if src.exists() else ""
        n_java = len(list(src.rglob("*.java"))) if src.exists() else 0
        self.result.ok_jadx = n_java > 0
        if self.result.ok_jadx:
            self.log(f"✓ 源码反编译完成：{n_java} 个 .java")
        else:
            msg = f"jadx 未产出源码 rc={res.rc} {res.tail(8)}"
            self.result.errors.append(msg)
            self.log("✗ " + msg)

    def _stream(self, tag: str):
        """把子进程输出转成 GUI 行，过滤噪音。"""
        def cb(line: str) -> None:
            if runner.is_noise(line):
                return
            # jadx 进度行带 \r，压成一行
            self.log(f"[{tag}] {line}"[:400])
        return cb

    def _collect_stats(self) -> None:
        info = self.info
        assert info is not None
        # 优先用解出来的 dex；没有就直接从 zip 里读
        dex_paths: list[Path] = []
        if self.result.apktool_dir:
            dex_paths = sorted(Path(self.result.apktool_dir).glob("*.dex"))
        stats = {"dex_count": 0, "classes": 0, "methods": 0, "fields": 0, "strings": 0}
        if not dex_paths:
            try:
                with zipfile.ZipFile(self.apk) as z:
                    for n in info.dex_files:
                        h = dexmod.parse_header(z.read(n)[:0x70])
                        stats["dex_count"] += 1
                        stats["classes"] += h.class_defs_size
                        stats["methods"] += h.method_ids_size
                        stats["fields"] += h.field_ids_size
                        stats["strings"] += h.string_ids_size
            except Exception as e:
                stats["error"] = str(e)
        else:
            for p in dex_paths:
                d = dexmod.parse(p, want_strings=False)
                if d.ok:
                    stats["dex_count"] += 1
                    stats["classes"] += d.header.class_defs_size
                    stats["methods"] += d.header.method_ids_size
                    stats["fields"] += d.header.field_ids_size
                    stats["strings"] += d.header.string_ids_size

        stats["so_count"] = len(info.native_libs)
        stats["arch"] = sorted({n.split("/")[1] for n in info.native_libs if n.count("/") >= 2})
        stats["java_files"] = (len(list(Path(self.result.sources_dir).rglob("*.java")))
                               if self.result.sources_dir else 0)
        info.dex_stats = stats
        self.log(f"✓ dex {stats['dex_count']} 个 / 类 {stats['classes']} / "
                 f"方法 {stats['methods']} / so {stats['so_count']} / "
                 f"Java {stats['java_files']}")

    def _write_reports(self) -> None:
        info = self.info
        assert info is not None
        rd = self.workdir / "report"
        rd.mkdir(parents=True, exist_ok=True)

        payload = {
            "apk": info.to_dict(),
            "unpack": self.result.to_dict(),
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "tool": f"{config.APP_NAME} {config.APP_VERSION}",
        }
        try:
            (rd / "report.json").write_text(
                json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        except OSError as e:
            self.result.errors.append(f"写 report.json 失败：{e}")

        (rd / "report.md").write_text(_render_md(info, self.result), encoding="utf-8")
        self.log(f"✓ 报告已写入 {rd}")

    # ---- 只读汇总 ----
    def manifest_summary(self) -> str:
        """给 GUI 用的一屏摘要。"""
        i = self.info
        if not i:
            return "尚未分析"
        lines = [
            f"文件      {Path(i.path).name}  ({i.size / 1048576:.1f} MB)",
            f"包名      {i.package or '—'}",
            f"版本      {i.version_name or '—'} ({i.version_code or '—'})",
            f"应用名    {i.label or '—'}",
            f"SDK       min {i.min_sdk or '—'} / target {i.target_sdk or '—'}",
            f"权限      {len(i.permissions)} 个",
            f"组件      活动 {len(i.activities)} / 服务 {len(i.services)} / "
            f"广播 {len(i.receivers)} / 提供者 {len(i.providers)}",
            f"dex       {i.dex_stats.get('dex_count', 0)} 个，"
            f"类 {i.dex_stats.get('classes', 0)}",
            f"so        {len(i.native_libs)} 个，架构 {','.join(i.dex_stats.get('arch', [])) or '—'}",
            f"加固      {'、'.join(i.packers) if i.packers else '未检出'}",
        ]
        if i.warns:
            lines.append("提示      " + "；".join(i.warns))
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Markdown 报告
# ---------------------------------------------------------------------------

def _render_md(i: ApkInfo, r: UnpackResult) -> str:
    bs = "`"
    L: list[str] = []
    L.append(f"# {i.label or Path(i.path).stem} · 拆解报告\n")
    L.append(f"> 目标：{bs}{i.path}{bs}  \n> 生成：{time.strftime('%Y-%m-%d %H:%M:%S')}  "
             f"by {config.APP_NAME} {config.APP_VERSION}\n")

    L.append("## 基本信息\n")
    L.append("| 项 | 值 |")
    L.append("|---|---|")
    for k, v in (
        ("包名", i.package), ("版本名", i.version_name), ("版本号", i.version_code),
        ("应用名", i.label), ("minSdk", i.min_sdk), ("targetSdk", i.target_sdk),
        ("大小", f"{i.size / 1048576:.2f} MB"), ("ZIP 条目", str(i.entry_count)),
    ):
        L.append(f"| {k} | {v or '—'} |")
    L.append("")

    if i.packers:
        L.append("## ⚠ 加固判定\n")
        L.append(f"命中：**{'、'.join(i.packers)}**\n")
        L.append("DEX 已被壳保护，直接反编译只能看到壳的入口代码。"
                 "需要先内存 dump 出真实 dex（脱壳）再反编译。\n")

    st = i.dex_stats or {}
    L.append("## 规模\n")
    L.append("| dex | 类 | 方法 | 字段 | 字符串 | Java 文件 | so | 架构 |")
    L.append("|---|---|---|---|---|---|---|---|")
    L.append(f"| {st.get('dex_count', 0)} | {st.get('classes', 0)} | {st.get('methods', 0)} "
             f"| {st.get('fields', 0)} | {st.get('strings', 0)} | {st.get('java_files', 0)} "
             f"| {st.get('so_count', 0)} | {','.join(st.get('arch', [])) or '—'} |")
    L.append("")

    if i.permissions:
        L.append("## 权限\n")
        for p in i.permissions:
            L.append(f"- {bs}{p}{bs}")
        L.append("")

    for title, items in (("Activity", i.activities), ("Service", i.services),
                         ("Receiver", i.receivers), ("Provider", i.providers)):
        if items:
            L.append(f"## {title}（{len(items)}）\n")
            for x in items[:60]:
                L.append(f"- {bs}{x}{bs}")
            if len(items) > 60:
                L.append(f"- …… 另 {len(items) - 60} 个")
            L.append("")

    if i.native_libs:
        L.append("## Native 库\n")
        for x in i.native_libs[:80]:
            L.append(f"- {bs}{x}{bs}")
        if len(i.native_libs) > 80:
            L.append(f"- …… 另 {len(i.native_libs) - 80} 个")
        L.append("")

    L.append("## 产物\n")
    L.append("| 类型 | 路径 | 状态 |")
    L.append("|---|---|---|")
    L.append(f"| 资源/Manifest/smali | {bs}{r.apktool_dir or '—'}{bs} | "
             f"{'成功' if r.ok_apktool else '失败'} |")
    L.append(f"| Java 源码 | {bs}{r.sources_dir or '—'}{bs} | "
             f"{'成功' if r.ok_jadx else '失败'} |")
    L.append(f"\n耗时 {r.dur:.1f}s\n")

    if r.errors:
        L.append("## 错误\n")
        for e in r.errors:
            L.append(f"- {e}")
        L.append("")
    return "\n".join(L)


# ---------------------------------------------------------------------------
# 便捷函数
# ---------------------------------------------------------------------------

def unpack(apk: str | Path, out: str | Path | None = None,
           on_line: Callable[[str], None] | None = None) -> UnpackResult:
    """一行拆一个 APK。脚本里最常用的入口。"""
    p = ApkPipeline(apk, out)
    p.on_line = on_line
    return p.run()


def info(apk: str | Path) -> ApkInfo:
    """只要画像，不拆包。"""
    return inspect(apk)
