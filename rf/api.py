#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 rf.api · 脚本门面（脚本里那个 `rf`）
============================================================================

【这一层干什么】
    把「注册表 + 执行器 + 各分析器」缝成一个扁平、好记的 API，
    让脚本作者不必知道内部模块结构：

        rf.log("开始")                       打日志到界面
        rf.step("拆包", 20)                  推进度条
        rf.apk_info("a.apk")                 静态画像
        rf.apk_unpack("a.apk")               解包 + 反编译
        rf.annotate(src, dst)                中文注释
        rf.elf("libx.so")                    ELF 分析
        rf.strings("classes.dex")            字符串提取
        rf.identify("secret.bin")            识别加密类型
        rf.zip_password("x.zip")             试弱口令
        rf.xor("blob.bin")                   单字节 XOR
        rf.keys("apk_dir")                   找硬编码密钥
        rf.run(["jadx","--version"])         任意命令
        rf.tool("ghidra")                    拿工具对象（有 .cmd()/.env()）

【约定】
    所有方法只返回结果对象或抛 RfError（带中文说明），
    不打印、不弹窗 —— 输出统一走 rf.log，GUI 才能收到。
============================================================================
"""

from __future__ import annotations

import os
import re
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

from . import config
from .tools import runner
from .tools.registry import registry
from .analysis import apk as apkmod
from .analysis.filetype import human_size
from .analysis import crypto as cryptomod
from .analysis import dex as dexmod
from .analysis import native as nativemod
from .analysis import strings as strmod
from .analysis import annotate as annotmod
from .analysis import authscan as authmod
from .analysis import filetype as ftmod
from .analysis import garble as garblemod
from .analysis import carve as carvemod
from .analysis import segments as segmod
from .analysis import validator as validatormod
from .decrypt import auto as decauto
from .decrypt import ciphers as decC
from .decrypt import keys as deckeys
from .fakepacket import extract as fp_extract, infer as fp_infer, build as fp_build
from .fakepacket import render_script as fp_script, report_md as fp_report
from .fakepacket import plaintext_map as fp_plaintext
from .patch import checkpoints as cpmod
from .patch import engine as patchmod
from .patch import netcheck as netmod
from .patch import smali as smalimod


class RfError(Exception):
    """脚本里能捕获的业务异常（消息是中文，可直接展示给用户）。"""


@dataclass
class Ctx:
    """
    脚本运行时上下文：谁在跑、产物放哪、怎么回传消息。

    GUI 会塞自己的实现；命令行跑脚本时用默认实现（print）。
    """
    workdir: Path = None            # type: ignore[assignment]
    on_log: Callable[[str], None] | None = None
    on_step: Callable[[str, int], None] | None = None
    quiet: bool = False

    def __post_init__(self):
        if self.workdir is None:
            self.workdir = Path(config.WORKSPACE_ROOT) / time.strftime("run_%Y%m%d_%H%M%S")
        self.workdir = Path(self.workdir)
        self.workdir.mkdir(parents=True, exist_ok=True)

    def log(self, msg: str) -> None:
        if self.quiet:
            return
        if self.on_log:
            try:
                self.on_log(msg)
            except Exception:
                pass
        else:
            print(msg, flush=True)

    def step(self, name: str, pct: int) -> None:
        # 有 on_step 回调节目（GUI 进度条）时不再重复写日志行，
        # 否则同一个进度会在终端里出现两次。
        if self.on_step:
            try:
                self.on_step(name, pct)
            except Exception:
                pass
        else:
            self.log(f"── [{pct:>3}%] {name}")


# ---------------------------------------------------------------------------
# 门面
# ---------------------------------------------------------------------------

class Api:
    """
    脚本可用的全部能力。实例由运行时创建并注入脚本全局变量 `rf`。
    """

    def __init__(self, ctx: Ctx | None = None):
        self.ctx = ctx or Ctx()
        self._out_seq = 0

    # =================== 日志与进度 ===================
    def log(self, msg: Any) -> None:
        self.ctx.log(str(msg))

    def step(self, name: str, pct: int = 0) -> None:
        self.ctx.step(name, pct)

    def note(self, title: str, body: str = "") -> None:
        """在日志里画一条醒目的分节标题。"""
        bar = "═" * 58
        self.log(bar)
        self.log(f"  {title}")
        if body:
            for line in str(body).splitlines():
                self.log(f"  {line}")
        self.log(bar)

    # =================== 工具 ===================
    @property
    def tools(self):
        return registry()

    def tool(self, tid: str):
        t = registry().get(tid)
        if not t.available:
            raise RfError(f"工具 {tid} 未就绪：{t.check()[1]}")
        return t

    def has(self, tid: str) -> bool:
        return registry().has(tid)

    def status(self) -> list[dict]:
        return registry().status()

    def tools_table(self) -> str:
        rows = []
        for d in self.status():
            rows.append(f"{'OK ' if d['available'] else 'MISS'} "
                        f"{d['id']:<10} {d['version'][:40]:<42} {d['path']}")
        return "\n".join(rows)

    # =================== 命令执行 ===================
    def run(self, cmd: Iterable[str | Path], cwd: str | Path | None = None,
            timeout: float | None = 600, check: bool = False,
            echo: bool = True, env_extra: dict | None = None) -> runner.RunResult:
        """执行命令，实时回传输出到界面。"""
        cmd = [str(c) for c in cmd]
        if echo:
            self.log("$ " + " ".join(cmd))

        def cb(line: str) -> None:
            if echo and not runner.is_noise(line):
                self.log("  " + line[:400])

        res = runner.run(cmd, cwd=cwd, timeout=timeout, on_line=cb,
                         env_extra=env_extra, log_name=Path(cmd[0]).stem)
        if check and not res.ok:
            raise RfError(f"命令失败 rc={res.rc}：{' '.join(cmd[:4])}\n{res.tail(6)}")
        return res

    def shell(self, cmdline: str, cwd: str | Path | None = None,
              timeout: float | None = 600, check: bool = False) -> runner.RunResult:
        """按 shell 规则拆一行命令（引号会被正确处理）。"""
        import shlex
        return self.run(shlex.split(cmdline, posix=False), cwd=cwd,
                        timeout=timeout, check=check)

    def which(self, name: str) -> str | None:
        return runner.which(name)

    # =================== 工作区 ===================
    @property
    def out_dir(self) -> Path:
        """本次任务的产物目录。"""
        return Path(self.ctx.workdir)

    def sub(self, name: str) -> Path:
        """在产物目录下开一个子目录。"""
        p = self.out_dir / name
        p.mkdir(parents=True, exist_ok=True)
        return p

    def tmp(self, name: str = "") -> Path:
        self._out_seq += 1
        p = self.out_dir / "tmp" / (name or f"t{self._out_seq}")
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    # =================== APK ===================
    def apk_info(self, path: str | Path, quiet: bool = False) -> apkmod.ApkInfo:
        """APK 静态画像。quiet=True 时不打日志（批量扫描用）。"""
        p = self._need_file(path)
        if not quiet:
            self.log(f"读取 APK 画像：{p.name}")
        info = apkmod.inspect(p)
        if not info.valid:
            raise RfError("APK 无效：" + "；".join(info.errors))
        if not quiet:
            self.log(f"  包名 {info.package or '未知'} / 版本 {info.version_name or '?'} / "
                     f"{human_size(info.size)}")
            if info.packers:
                self.log(f"  ⚠ 疑似加固：{'、'.join(info.packers)}")
        return info

    def apk_unpack(self, path: str | Path, out: str | Path | None = None,
                   apktool: bool = True, jadx: bool = True,
                   annotate: bool = False) -> apkmod.UnpackResult:
        """拆解 APK：资源解包 + 源码反编译（+ 可选中文注释）。"""
        p = self._need_file(path)
        dst = Path(out) if out else (self.out_dir / p.stem)
        pipe = apkmod.ApkPipeline(p, dst)

        pipe.on_line = self.ctx.log

        def on_step(name: str, pct: int, detail: str) -> None:
            # 映射到全局 0-100：拆包占 0-85，注释占 85-100
            scale = 0.85 if annotate else 1.0
            self.ctx.step(name, int(pct * scale))

        pipe.on_step = on_step
        res = pipe.run(do_apktool=apktool, do_jadx=jadx)

        if annotate and res.sources_dir:
            self.ctx.step("中文注释", 90)
            a = annotmod.annotate_tree(res.sources_dir,
                                       Path(res.sources_dir).parent / "sources_cn")
            self.log(f"✓ 注释完成：{a.classes_annotated} 类 / {a.methods_annotated} 方法")
            if a.verify_points:
                self.log("  校验点：" + "、".join(
                    f"{v['class']}({v['category']})" for v in a.verify_points[:5]))
            for e in a.errors[:5]:
                self.log(f"  ! {e}")
        self.ctx.step("完成", 100)
        return res

    # =================== DEX ===================
    def dex(self, path: str | Path, want_strings: bool = True) -> dexmod.DexInfo:
        p = self._need_file(path)
        d = dexmod.parse(p, want_strings=want_strings)
        if not d.ok:
            raise RfError(f"不是有效 DEX：{p.name}")
        self.log(d.brief())
        return d

    # =================== 原生二进制 ===================
    def elf(self, path: str | Path) -> nativemod.ElfInfo:
        p = self._need_file(path)
        e = nativemod.parse_elf(p)
        if not e.is_elf:
            raise RfError(f"不是 ELF：{p.name}")
        self.log(e.brief())
        risky = nativemod.risky_imports(e)
        for imp, why in risky[:8]:
            self.log(f"  ⚠ 导入 {imp} —— {why}")
        return e

    def pe(self, path: str | Path) -> nativemod.PeInfo:
        p = self._need_file(path)
        x = nativemod.parse_pe(p)
        if not x.is_pe:
            raise RfError(f"不是 PE：{p.name}")
        self.log(x.brief())
        return x

    def native(self, path: str | Path):
        p = self._need_file(path)
        n = nativemod.parse(p)
        if n is None:
            raise RfError(f"既不是 ELF 也不是 PE：{p.name}")
        self.log(n.brief())
        return n

    def disasm(self, path: str | Path, func: str | None = None,
               limit: int = 400) -> str:
        """用 rizin 反汇编：给了函数名就只反汇编那个函数。"""
        p = self._need_file(path)
        t = self.tool("rizin")
        if func:
            res = self.run([t.prefix[0], "-q", "-c", f"aa;pdf @ sym.{func}", p])
        else:
            res = self.run([t.prefix[0], "-q", "-c", "aa;pd " + str(limit), p])
        return res.out

    def functions(self, path: str | Path, limit: int = 300) -> list[str]:
        """列出函数符号（rizin afl）。"""
        p = self._need_file(path)
        t = self.tool("rizin")
        res = self.run([t.prefix[0], "-q", "-c", "aa;afl", p])
        out = []
        for line in res.out.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[0].startswith("0x"):
                out.append(" ".join(parts[:5]))
        return out[:limit]

    def ghidra_decompile(self, path: str | Path, timeout: float = 3600) -> Path:
        """
        用 Ghidra headless 把 native 库反编译成 C 伪代码。

        重量级操作：Ghidra 要先做完整分析（函数识别、类型推导），
        一个几 MB 的 so 可能要几分钟到几十分钟。需要 JDK21。

        返回导出目录（每个函数一个 .c）。
        """
        p = self._need_file(path)
        t = self.tool("ghidra")
        proj = self.sub("ghidra_proj")
        out = self.sub("ghidra_out")
        script_dir = config.APP_ROOT / "scripts" / "ghidra"

        if not script_dir.exists():
            raise RfError(f"Ghidra 导出脚本缺失：{script_dir}/DecompileToFile.py")

        cmd = [
            t.prefix[0], str(proj), re.sub(r"[^\w]", "_", p.stem)[:40],
            "-import", str(p),
            "-scriptPath", str(script_dir),
            "-postScript", "DecompileToFile.py", str(out),
            "-deleteProject",
        ]
        self.log("启动 Ghidra headless（完整分析，可能要几分钟，请耐心）")
        res = self.run(cmd, timeout=timeout, env_extra=t.env())
        if not res.ok:
            raise RfError(f"Ghidra 执行失败 rc={res.rc}：{res.tail(6)}")

        n = len(list(out.glob("*.c"))) if out.exists() else 0
        self.log(f"✓ Ghidra 导出 {n} 个函数的伪代码 → {out}")
        return out

    # =================== 加密 / 容器 ===================
    def identify(self, path: str | Path) -> cryptomod.IdentifyResult:
        p = self._need_file(path)
        r = cryptomod.identify(p)
        self.log(r.brief())
        for n in r.notes:
            self.log("  " + n)
        return r

    def zip_password(self, path: str | Path, out: str | Path | None = None,
                     passwords: list[str] | None = None) -> cryptomod.DecryptResult:
        p = self._need_file(path)
        dst = out or (self.out_dir / (p.stem + "_unlocked"))
        r = cryptomod.try_zip_password(p, passwords, dst)
        self.log(("✓ " if r.ok else "✗ ") + r.note)
        return r

    def xor(self, path: str | Path, out: str | Path | None = None) -> cryptomod.DecryptResult:
        p = self._need_file(path)
        dst = out or (self.out_dir / "xor")
        r = cryptomod.try_single_byte_xor(p, dst)
        self.log(("✓ " if r.ok else "✗ ") + (r.method or "") + " " + r.note)
        return r

    def keys(self, path: str | Path, limit: int = 40) -> list[tuple[str, str]]:
        """在源码/二进制里找硬编码密钥与口令。"""
        p = self._need_path(path)
        hits = cryptomod.find_hardcoded_keys(p, limit)
        self.log(f"找到 {len(hits)} 处疑似密钥/口令")
        for label, frag in hits[:10]:
            self.log(f"  · {label}: {frag[:60]}")
        return hits

    # =================== 字符串 ===================
    def strings(self, path: str | Path, min_len: int = 5) -> strmod.StringsResult:
        p = self._need_path(path)
        r = strmod.scan_file(p, min_len) if p.is_file() else strmod.scan_tree(p)
        self.log(f"字符串 {r.total} 条：{r.summary()}")
        return r

    # =================== 注释 ===================
    def annotate(self, src: str | Path, out: str | Path | None = None,
                 density: str = "full", use_graph: bool = True) -> annotmod.AnnotateResult:
        """
        给 Java 源码加中文注释。

        density="full" 时，方法体内的 if/for/try 等语句也会逐条翻译成中文；
        "lite" 只加类头与方法头（大工程速览用）。
        注释里会带跨文件依赖与校验链 —— 这是它比普通注释器多出来的部分。
        """
        s = self._need_path(src)
        dst = Path(out) if out else (s.parent / (s.name + "_cn"))

        def prog(i: int, n: int, name: str) -> None:
            if n and i % max(1, n // 20) == 0:
                self.ctx.step(f"注释 {i}/{n}", 85 + int(i / n * 15))

        r = annotmod.annotate_tree(s, dst, on_progress=prog,
                                   density=density, use_graph=use_graph)
        self.log(f"✓ 注释 {r.classes_annotated} 类 / {r.methods_annotated} 方法 → {r.out_root}")
        if r.graph_summary:
            for line in r.graph_summary.splitlines():
                self.log("  " + line)
        if r.verify_points:
            self.log("  校验点（按依赖与语义推断）：")
            for v in r.verify_points[:6]:
                self.log(f"    ⚑ {v['class']} —— {v['category']}（入度 {v['fan_in']}）")
                if v["chain"]:
                    self.log(f"       链：{v['chain']}")
        return r

    # =================== 依赖图 ===================
    def deps(self, src: str | Path):
        """
        只建依赖图，不加注释。用于"先看结构、再决定从哪下手"。

        返回 DepGraph：nodes（每类的入度/校验特征/链路）、edges（调用边）。
        """
        from .analysis import depgraph

        s = self._need_path(src)
        if s.is_file():
            s = s.parent
        self.ctx.step("建依赖图", 30)
        g = depgraph.build(s)
        self.log(g.summary())
        self.ctx.step("依赖图完成", 100)
        return g

    # =================== 文件 ===================
    def read_text(self, path: str | Path, limit: int = 1 << 20) -> str:
        p = Path(path)
        if not p.exists():
            raise RfError(f"文件不存在：{p}")
        return p.read_text(encoding="utf-8", errors="replace")[:limit]

    def write_text(self, path: str | Path, text: str) -> Path:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        return p

    def copy(self, src: str | Path, dst: str | Path) -> Path:
        s, d = Path(src), Path(dst)
        d.parent.mkdir(parents=True, exist_ok=True)
        if s.is_dir():
            shutil.copytree(s, d, dirs_exist_ok=True)
        else:
            shutil.copy2(s, d)
        return d

    def list(self, path: str | Path, pattern: str = "*") -> list[Path]:
        p = Path(path)
        if not p.exists():
            return []
        return sorted(p.rglob(pattern)) if p.is_dir() else [p]

    def size(self, path: str | Path) -> int:
        p = Path(path)
        if p.is_file():
            return p.stat().st_size
        return sum(f.stat().st_size for f in p.rglob("*") if f.is_file())

    # =================== 校验点 / 补丁 ===================
    def _smali_root(self, path) -> Path:
        """把用户给的路径收敛成「含 smali 的目录」。"""
        p = Path(path)
        if not p.exists():
            raise RfError(f"路径不存在：{p}")
        if p.is_file():
            p = p.parent
        if p.name.startswith("smali"):
            return p
        if (p / "smali").is_dir():
            return p
        if any(d.is_dir() and d.name.startswith("smali") for d in p.iterdir()):
            return p
        raise RfError(f"{p} 里没有 smali 目录。先 apk_unpack() 解包，再传解包目录。")

    def patch_scan(self, target: str | Path, min_confidence: int = 25,
                   max_files: int = 6000) -> cpmod.CheckpointReport:
        """
        精确扫描启动前的校验点。

        target 可以是 apktool 解包目录，也可以是其中的 smali 目录。
        返回 CheckpointReport：points 里带证据、置信度、是否启动路径、建议改法。
        """
        root = self._smali_root(target)
        self.ctx.step("扫描校验点", 20)
        rep = cpmod.analyze(root, max_files=max_files, min_confidence=min_confidence)
        self.log(rep.summary())
        if rep.errors:
            for e in rep.errors:
                self.log("  ! " + e)
            raise RfError(rep.errors[0])
        self.log(rep.table(only_pre=True, limit=12))
        for p in rep.pre_run[:5]:
            self.log(f"  ⚑ {p.cid} {p.cls_simple}.{p.method} · {p.category} · "
                     f"置信度 {p.confidence}")
            if p.best:
                self.log(f"      建议：{p.best.label}（风险 {p.best.risk}）")
            if p.note:
                self.log(f"      注意：{p.note}")
        self.ctx.step("扫描完成", 45)
        return rep

    def patch_plan(self, report_or_dir, ids: list[str] | None = None,
                   only_pre: bool = True, max_ops: int = 20,
                   safe_only: bool = False, min_confidence: int = 0,
                   include_running: bool = False) -> list[cpmod.PatchOp]:
        """把校验点变成可执行补丁；每个点只取最稳的一条建议。"""
        rep = report_or_dir
        if not isinstance(rep, cpmod.CheckpointReport):
            rep = self.patch_scan(rep)
        ops = cpmod.to_plan(rep, ids=ids, only_pre=only_pre, max_ops=max_ops,
                            safe_only=safe_only, min_confidence=min_confidence,
                            include_running=include_running)
        self.log(f"补丁方案：{len(ops)} 条")
        for op in ops:
            self.log(f"  · {op.reason}  @{Path(op.file).name}:{op.line}")
        if not ops:
            self.log("  （没有可自动应用的建议，可用 patch_apply 手写 PatchOp）")
        return ops

    def patch_terminators(self, smali_root: str | Path, *,
                          keep_exit: bool = False, keep_finish: bool = False,
                          max_ops: int = 240
                          ) -> tuple[list[cpmod.PatchOp], dict]:
        """
        兜底摘除"拒绝运行"的终结动作（exit / killProcess 等换成 nop）。

        不看它是不是校验点 —— 只认"这一句会让程序停"。
        返回 (补丁, 统计)。统计里有 exit/kill/finish/throw/hang 各自命中数。
        """
        ops, stat = cpmod.plan_terminators(smali_root, keep_exit=keep_exit,
                                           keep_finish=keep_finish, max_ops=max_ops)
        self.log(f"终结动作摘除：{stat['applied']} 条 "
                 f"（exit {stat['exit']} / kill {stat['kill']} / "
                 f"finish {stat['finish']} / throw {stat['throw']} / "
                 f"挂起 {stat['hang']}）")
        return ops, stat

    def patch_network(self, smali_root: str | Path, *, scope: str = "check",
                      max_ops: int = 60) -> tuple[list[cpmod.PatchOp], dict]:
        """
        联网校验：让客户端认为服务器一直同意。

        scope="check" 只改疑似授权/登录的方法（默认）；
        scope="all"   全包改（连业务接口的 404 也当 200，慎用）。

        改法是在 getResponseCode / code() 的返回值上就地覆盖，
        不认判断写法（==200 / >=200 / >=400 判错三种都能覆盖）。
        """
        ops, stat = netmod.plan_network(smali_root, scope=scope, max_ops=max_ops)
        self.log(f"联网校验点：{stat['points']} 个（状态码 {stat['code']} / "
                 f"成功标志 {stat['ok']}），出补丁 {stat['patched']} 条")
        for op in ops[:12]:
            self.log(f"  · {op.reason}  @{Path(op.file).name}:{op.line}")
        return ops, stat

    def frida_net(self, out: str | Path) -> Path:
        """单独生成联网覆盖脚本（状态码/成功标志/返回体洗白）。"""
        p = netmod.write_frida_net(out)
        self.log(f"联网覆盖脚本 → {p}")
        return p

    def patch_apply(self, smali_root: str | Path, ops: list[cpmod.PatchOp],
                    dry_run: bool = False, backup: str | Path | None = None
                    ) -> patchmod.PatchResult:
        """
        事务化应用补丁：备份 → 逐条核对原指令 → 原子写 → 语法校验 → 失败整批回滚。

        dry_run=True 只预演，不写盘。
        """
        root = self._smali_root(smali_root)
        self.ctx.step("预演补丁" if dry_run else "应用补丁", 55)
        res = patchmod.apply(root, ops, backup_dir=backup, dry_run=dry_run)
        for line in res.log[-10:]:
            self.log("  " + line)
        for e in res.errors[:6]:
            self.log("  ! " + e)
        self.log(("✓ " if res.ok else "✗ ") + res.text().splitlines()[0])
        return res

    def replace_strings(self, smali_root: str | Path, old: str, new: str,
                        dry_run: bool = False) -> patchmod.PatchResult:
        """
        把写死的卡密/默认口令/测试密钥替换成指定值。

        注意：只改字面量。如果程序比对的是 SHA-256，改原文没有用 ——
        要改的是那个哈希值，或者直接改比对结果（patch_apply）。
        """
        root = self._smali_root(smali_root)
        ops = smalimod.find_string_ops(root, old, new)
        self.log(f"字符串「{old[:40]}」命中 {len(ops)} 处")
        if not ops:
            raise RfError("没有找到完全一致的字符串字面量（大小写/空格都要一致）")
        return self.patch_apply(root, ops, dry_run=dry_run)

    def patch_rebuild(self, unpack_dir: str | Path, out: str | Path | None = None,
                      ops: list[cpmod.PatchOp] | None = None,
                      sign: bool = True, install: bool = False,
                      package: str = "") -> patchmod.RebuildResult:
        """重建 APK → 对齐 → 签名 → 验签 → 回读补丁。"""
        root = self._smali_root(unpack_dir)
        self.ctx.step("重建 APK", 70)
        rb = patchmod.rebuild(root, out, sign=sign, ops=ops)
        for line in rb.log[-8:]:
            self.log("  " + line)
        for e in rb.errors[:4]:
            self.log("  ! " + e)
        self.log(("✓ " if rb.ok else "✗ ") + rb.text().splitlines()[0])
        if install and rb.ok:
            ok, msg = patchmod.install(rb.apk, package, uninstall_first=True)
            self.log(("✓ " if ok else "⚠ ") + msg)
        self.ctx.step("完成", 100)
        return rb

    def patch_rebuild_dex(self, base_apk: str | Path, unpack_dir: str | Path,
                          out: str | Path | None = None, ops: list | None = None,
                          sign: bool = True) -> patchmod.RebuildResult:
        """
        资源重建失败时的退路：只换 dex，保留原 APK 资源，再签名验签回读。
        """
        self.ctx.step("重建（只换 dex）", 70)
        rb = patchmod.rebuild_dex_only(base_apk, unpack_dir, out,
                                       ops=ops, sign=sign)
        for line in rb.log[-8:]:
            self.log("  " + line)
        for e in rb.errors[:4]:
            self.log("  ! " + e)
        self.log(("✓ " if rb.ok else "✗ ") + rb.text().splitlines()[0])
        return rb

    def patch_rollback(self, smali_root: str | Path, backup_dir: str | Path) -> list[str]:
        """从备份目录整体还原 smali。"""
        root = self._smali_root(smali_root)
        files = patchmod.rollback(root, backup_dir)
        self.log(f"↩ 已还原 {len(files)} 个文件")
        return files

    def frida(self, report, ids: list[str] | None = None,
              out: str | Path | None = None) -> Path:
        """根据校验点生成 Frida 覆盖脚本（不改包，运行时验证）。"""
        rep = report
        if not isinstance(rep, cpmod.CheckpointReport):
            rep = self.patch_scan(report)
        js = cpmod.to_frida(rep, ids=ids)
        p = Path(out) if out else (self.out_dir / "hook.js")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(js, encoding="utf-8")
        self.log(f"✓ Frida 脚本：{p}")
        return p

    def patch_install(self, apk: str | Path, package: str = "",
                      uninstall_first: bool = False) -> tuple[bool, str]:
        p = self._need_file(apk)
        ok, msg = patchmod.install(p, package, uninstall_first)
        self.log(("✓ " if ok else "⚠ ") + msg)
        return ok, msg

    def patch_package(self, root: str | Path) -> str:
        """从解包目录的 AndroidManifest.xml 读包名。"""
        return patchmod.package_of(root)

    def patch_launch(self, package: str, wait: int = 5) -> dict:
        """装完真跑一次：拉起 launcher → 查进程存活 → 抓崩溃栈。"""
        res = patchmod.launch(package, wait)
        self.log(("✓ " if res.get("ok") else "⚠ ") + str(res.get("msg", "")))
        return res

    def patch_crash_hint(self, crash: list, log: str = "") -> list:
        """崩溃栈 → 崩因分类（签名/完整性/原生层/环境检测/补丁自身）。"""
        return patchmod.crash_hints(crash, log)

    def adb_logcat(self, lines: int = 200, package: str = "") -> str:
        """抓设备日志（需要 adb 与已连接设备）。"""
        if not self.has("adb"):
            raise RfError("adb 不可用")
        adb = registry().get("adb").prefix[0]
        cmd = [adb, "logcat", "-d", "-t", str(max(1, lines))]
        r = self.run(cmd, timeout=60, echo=False)
        text = r.out
        if package:
            text = "\n".join(x for x in text.splitlines() if package in x)
        return text

    # =================== 语法校验 ===================
    def validate(self, target: str | Path, kind: str = ""):
        """
        校验语法。目标可以是文件路径，也可以直接是一段代码。

            rf.validate("a.py")                 按扩展名自动判断
            rf.validate("def f(:\n  pass", "python")
        """
        p = Path(target)
        if p.exists():
            r = validatormod.validate_file(p, kind)
            self.log(f"{p.name}：{r.brief()}")
            for i in r.errors[:5]:
                self.log("  ! " + i.text())
            return r
        r = validatormod.validate(str(target), kind or "python")
        self.log(r.brief())
        for i in r.errors[:5]:
            self.log("  ! " + i.text())
        return r

    def validate_tree(self, root: str | Path, pattern: str = "**/*.smali"):
        r = validatormod.validate_tree(root, pattern)
        self.log(f"{r.brief()}（{r.stats.get('files', 0)} 个文件）")
        for i in r.errors[:8]:
            self.log("  ! " + i.text())
        return r

    # =================== 代码积木 ===================
    def snippets(self, keyword: str = "", category: str = "", level: int = 0):
        """列出积木：按关键词/分类/难度过滤，返回 Snippet 列表。"""
        from .snippets import get_library
        lib = get_library()
        return lib.search(keyword) if keyword else lib.all(category, level)

    def snippet(self, sid: str):
        from .snippets import get_library
        return get_library().get(sid)

    def snippet_catalog(self, out: str | Path | None = None) -> Path:
        from .snippets import get_library
        lib = get_library()
        p = Path(out) if out else (self.out_dir / "积木目录.md")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(lib.markdown(), encoding="utf-8")
        st = lib.stats()
        self.log(f"✓ 积木目录：{p}（{st['total']} 块，语法异常 {st['invalid']}）")
        return p

    def compose(self, ids: list[str], out: str | Path | None = None) -> str:
        """把多块积木按依赖排序拼成一份可运行脚本。"""
        from .snippets import get_library
        code = get_library().compose(ids, out)
        self.log(f"✓ 已拼装 {len(ids)} 块" + (f" → {out}" if out else ""))
        return code

    # =================== 本机强加密 ===================
    @property
    def crypto(self):
        """rf.crypto.encrypt / decrypt / hmac_sign / sha256_file / seal_json …"""
        from .secure import crypto
        return crypto

    def crypto_test(self, payload_kb: int = 64) -> dict:
        """真跑 AES/HMAC/PBKDF2 往返，返回本机实测结果。"""
        from .secure import crypto
        rep = crypto.selftest(payload_kb=payload_kb)
        for case in rep["cases"]:
            self.log("  " + str(case))
        self.log("加密自检：" + ("通过" if rep["ok"] else "失败"))
        return rep

    # =================== 任意文件（不止 APK） ===================
    def file_type(self, path: str | Path) -> ftmod.FileKind:
        """识别单个文件到底是什么（PE/ELF/脚本/密文…），并给出建议分析器。"""
        k = ftmod.sniff(self._need_file(path))
        self.log(k.brief())
        if k.route:
            self.log("  建议：" + " → ".join(k.route))
        return k

    def scan_any(self, target: str | Path, max_files: int = 4000,
                 quiet: bool = False) -> ftmod.ScanResult:
        """扫一个目录，按类型分类（脚本/本地程序/压缩包/疑似加密…）。"""
        res = ftmod.scan_tree(self._need_path(target), max_files=max_files)
        self.log(res.summary())
        if not quiet:
            self.log(res.table(limit=15))
        return res

    # =================== 通用拆解（不止 APK） ===================
    # Python zipfile 原生可解的 ZIP 家族（含 JAR / OOXML / wheel）
    _ZIP_REALS = ("zip", "jar", "docx", "xlsx", "pptx", "whl", "pyz", "egg",
                  "ipa", "appx", "msix", "crx", "xpi", "epub", "nupkg",
                  "vsix", "aar", "war", "ear", "odt", "ods", "odp", "sketch",
                  "ota")
    # 7-Zip（完整版）才认识的容器：压缩 / 归档 / 磁盘镜像 / 安装器 / OLE / CHM
    _7Z_REALS = ("rar", "7z", "zstd", "lzma", "lz4", "lzip", "lzop", "z",
                 "iso", "dmg", "msi", "wim", "cab", "vhd", "vhdx",
                 "ar", "rpm", "squashfs",
                 "ole", "doc", "xls", "ppt", "msg", "mdb", "one", "chm")
    # Python 原生 tar/gzip/lzma 就能拆的
    _NATIVE_REALS = ("tar", "tgz", "gzip", "bzip2", "xz")
    # 有专用重武器（apktool/jadx）的类型，先走 APK 全流程
    _APK_REALS = ("apk",)

    def unpack_any(self, path: str | Path, out: str | Path | None = None,
                   deep: bool = False) -> dict:
        """
        通用拆解：按识别出的类型自动选最合适的拆法。

        - APK/AAB/APKS/XAPK → apktool + jadx 全流程（同 apk_unpack）
        - ZIP/RAR/7z/gzip/xz/tar/ISO/DMG/MSI/JAR/OOXML → 7-Zip 全量解出
        - EXE/DLL（PE）→ 7-Zip 抽资源节 + 字符串清单
        - 其它（ELF/脚本/密文…）→ 分段 + 字符串画像落盘

        返回 dict：type/output/files/method/notes。
        """
        import zipfile as _zf

        p = self._need_file(path)
        kind = ftmod.sniff(p)
        real = kind.real
        dst = Path(out) if out else (self.out_dir / ("unpack_" + p.stem))
        dst.mkdir(parents=True, exist_ok=True)
        notes: list[str] = []
        res = {"type": f"{kind.label}（{real}）", "output": str(dst),
               "files": 0, "method": "", "notes": notes}

        # ---- 1) APK 家族 → 现有全流程 ----
        if real in self._APK_REALS:
            res["method"] = "apktool+jadx（APK 全流程）"
            ur = self.apk_unpack(p, dst)
            res["files"] = ur.files if hasattr(ur, "files") else -1
            res["notes"].append("APK 走专用链路：资源解包 + 源码反编译")
            # 脱壳辅助：加固壳常把原始 dex 藏在 lib/*.so 或残留段里，
            # 对解包目录里的 so / 大文件做内嵌 dex 雕刻，能捞回就捞
            try:
                fat = [f for f in dst.rglob("*")
                       if f.is_file() and f.suffix.lower() in
                       (".so", ".dat", ".bin") and 1 << 20 < f.stat().st_size < 1 << 30]
                for f in fat[:8]:
                    cr = carvemod.carve_file(f, f.parent / (f.name + "_carved"),
                                             max_objects=20)
                    dexes = [o for o in cr.objects if o.kind in ("dex", "cdex")]
                    if dexes:
                        res["notes"].append(
                            f"⚠ 疑似加固脱壳辅助：{f.name} 里雕出 "
                            f"{len(dexes)} 个内嵌 dex → {f.name}_carved/，"
                            "可丢进 APK 页反编译")
            except Exception:                                       # noqa: BLE001
                pass
            return res

        # ---- 2) 多 APK 打包体（APKS/XAPK/AAB）：先解出内层 APK ----
        if p.suffix.lower() in (".apks", ".xapk") or real == "aab":
            res["method"] = "7z 解容器 → 内层 APK 再走全流程"
            seven = self._tool("7z")
            if seven and seven.available:
                runner.run(seven.cmd("x", p, f"-o{dst}", "-y"),
                           timeout=600, on_line=self.ctx.log, log_name="unpack_any_7z")
            inner = list(dst.rglob("*.apk"))[:3]
            if inner:
                notes.append("内层 APK：" + "、".join(a.name for a in inner)
                             + "（可分别丢进来走 APK 全流程）")
            else:
                notes.append("容器里没找到内层 .apk，请人工检查 " + str(dst))
            self._count_files(res, dst)
            return res

        # ---- 2.5) ZIP 家族 → Python 原生解压（不依赖外部 7z） ----
        if real in self._ZIP_REALS:
            self.ctx.step("解压 ZIP 家族", 30)
            fixed = 0
            try:
                with _zf.ZipFile(p) as z:
                    for info in z.infolist():
                        # 非 UTF-8 标志位的文件名按 cp437 解出的是乱码，修成中文
                        name = info.filename
                        if info.flag_bits & 0x800 == 0:
                            try:
                                name = name.encode("cp437").decode("gbk")
                                fixed += 1
                            except (UnicodeEncodeError, UnicodeDecodeError):
                                name = info.filename
                        target = (dst / name)
                        if name.endswith("/") or name.endswith("\\"):
                            target.mkdir(parents=True, exist_ok=True)
                            continue
                        # 防路径穿越（zip-slip）
                        if not str(target.resolve()).startswith(str(dst.resolve())):
                            notes.append(f"跳过越界条目：{name}")
                            continue
                        target.parent.mkdir(parents=True, exist_ok=True)
                        with z.open(info) as src, open(target, "wb") as fout:
                            shutil.copyfileobj(src, fout, 1 << 20)
                res["method"] = f"原生解压（ZIP 家族：{real}）"
                self._count_files(res, dst)
                if fixed:
                    notes.append(f"修复了 {fixed} 个中文文件名的乱码")
                if real in ("docx", "xlsx", "pptx"):
                    notes.append("OOXML 已拆开：正文在 word/ xl/ ppt/ 子目录，"
                                 "核心内容是 XML，可直接检索")
                if real == "jar":
                    notes.append("JAR 已解开；若含 .dex/.class，丢进 APK 页可用 "
                                 "jadx 反编译")
                return res
            except Exception as e:                                  # noqa: BLE001
                notes.append(f"原生解压失败（可能加密包）：{e}")
                if real == "zip":
                    self.ctx.step("尝试弱口令解密", 60)
                    try:
                        r = self.zip_password(p, out=dst / "_decrypted")
                        if getattr(r, "ok", False) or (
                                r.password and (dst / "_decrypted").exists()):
                            res["method"] = "弱口令解密（ZIP 家族）"
                            self._count_files(res, dst / "_decrypted")
                            notes.append(f"口令命中：{r.password}")
                            return res
                        notes.append("弱口令未命中；可在「识别」页用已知明文攻击")
                    except Exception as e2:                          # noqa: BLE001
                        notes.append(f"弱口令尝试失败：{e2}")

        # ---- 2.6) tar / tar.gz / tar.bz2 / tar.xz / 裸 gzip、bzip2、xz ----
        # tarfile 原生通吃三种压缩，零外部依赖
        if real in self._NATIVE_REALS:
            import tarfile as _tf
            import gzip as _gz
            import lzma as _lz
            import bz2 as _bzip
            self.ctx.step("原生解压 tar 家族", 30)
            extracted = False
            try:
                with _tf.open(p, "r:*") as t:          # 自动认 gz/bz2/xz/裸 tar
                    t.extractall(dst, filter="data")
                extracted = True
                res["method"] = "原生解压（tar 家族，tarfile 自动认压缩）"
            except _tf.ReadError:
                # 不是 tar 的裸压缩流（单文件）：解出原名
                stem = p.name
                for suf in (".gz", ".bz2", ".xz", ".tgz", ".bz"):
                    if stem.lower().endswith(suf):
                        stem = stem[: -len(suf)]
                        break
                if stem == p.name:
                    stem += ".out"
                if real == "xz":
                    opener = _lz.open
                elif real == "bzip2":
                    opener = _bzip.open
                else:
                    opener = _gz.open
                try:
                    with opener(p, "rb") as src, open(dst / stem, "wb") as fout:
                        shutil.copyfileobj(src, fout, 1 << 20)
                    extracted = True
                    res["method"] = f"原生解压（裸 {real} 流 → {stem}）"
                except (OSError, EOFError, _lz.LZMAError) as e:
                    notes.append(f"原生解压失败：{e}")
            if extracted:
                self._count_files(res, dst)
                notes.append("tar 家族拆解不依赖 7-Zip，任何机器都能跑")
                return res

        # ---- 3) 7-Zip 通吃的容器（优先完整版 7z.exe，7zr 只认 .7z） ----
        seven = self._tool("7z")
        seven_cmd = self._seven_cmd(seven)

        def _seven_extract(dest: Path, fmt: str = "") -> bool:
            if not seven_cmd:
                notes.append("未找到可用的 7-Zip（需要完整版 7z.exe，"
                             "7zr.exe 只认 .7z）；一键安装会带齐")
                return False
            r = runner.run(list(seven_cmd) + ["x", str(p), f"-o{dest}", "-y"],
                           timeout=900, on_line=self.ctx.log,
                           log_name="unpack_any_7z")
            if dest.exists() and any(dest.iterdir()):
                return True
            notes.append(f"7-Zip 退出码 {r.rc}（{fmt or real}），可能加密/损坏："
                         + r.tail(3).replace("\n", " / "))
            return False

        if (real in self._7Z_REALS) and seven and seven.available:
            self.ctx.step("7-Zip 解压", 30)
            if _seven_extract(dst):
                res["method"] = f"7-Zip（{real} 容器全量解出）"
                self._count_files(res, dst)
                # gzip/bzip2/xz 解出来的还是 tar 的话，再拆一层
                inner_tars = list(dst.glob("*.tar"))[:1]
                if inner_tars and seven_cmd:
                    sub = dst / (inner_tars[0].stem or "tar_inner")
                    if _seven_extract(sub, "tar"):
                        notes.append(f"内层 tar 也拆了 → {sub.name}/")
                return res

        # ---- 4) PE（EXE/DLL/SYS）：7-Zip 能直接抽资源节 ----
        if real == "pe" and seven_cmd:
            self.ctx.step("抽取 PE 资源", 40)
            r = runner.run(list(seven_cmd) + ["x", str(p),
                                              f"-o{dst / 'resources'}", "-y"],
                           timeout=300, log_name="unpack_any_pe")
            if (dst / "resources").exists() and any((dst / "resources").iterdir()):
                notes.append("PE 资源已抽出（图标/版本/内嵌文件常在这）")
                res["method"] = "7-Zip PE 资源抽取"
            else:
                notes.append("资源节为空或加密壳，改看字符串与分段")
            from rf.analysis import strings as _strings
            try:
                sf = dst / "字符串清单.txt"
                rows = _strings.extract(p) if hasattr(_strings, "extract") else []
                sf.write_text("\n".join(rows[:5000]), encoding="utf-8", errors="replace")
                res["files"] = sum(1 for _ in dst.rglob("*") if _.is_file())
                notes.append(f"字符串清单 → {sf.name}（URL/密钥/提示文案常在这）")
                return res
            except Exception as e:                                  # noqa: BLE001
                notes.append(f"字符串抽取失败：{e}")
                self._count_files(res, dst)
                return res

        # ---- 4.5) ART 产物（vdex / oat / dex / cdex / odex）→ 雕刻内嵌 dex ----
        # vdex/oat 里真正能反编译的是内嵌 dex，必须格式专属提取，通用解压拆不开
        if real in ("vdex", "oat", "dex", "cdex", "odex"):
            self.ctx.step("雕刻内嵌 dex", 40)
            try:
                cr = carvemod.carve_file(p, dst / "carved")
                if cr.objects:
                    res["method"] = "内嵌 dex 雕刻（格式专属提取）"
                    ndex = sum(1 for o in cr.objects if o.kind in ("dex", "cdex"))
                    self._count_files(res, dst)
                    notes.append(f"{cr.brief()}；dex 已抠出 → carved/")
                    if ndex:
                        notes.append("抠出的 .dex 直接丢进 APK 页可用 jadx 反编译")
                    return res
                notes.append("未雕刻出对象，改走分段画像")
            except Exception as e:                                  # noqa: BLE001
                notes.append(f"雕刻失败：{e}")

        # ---- 5) 兜底：分段 + 画像 + 内嵌对象雕刻 ----
        res["method"] = "分段 + 画像 + 内嵌雕刻（该类型没有容器结构可拆）"
        notes.append("已产出：分段图 / 熵分布 / 字符串画像；"
                     "若是密文，接「一键解密」")
        rep = dst / "拆解报告.md"
        lines = ["# 拆解报告", "", f"- 文件：{p}", f"- 识别：{kind.brief()}",
                 f"- 熵：{kind.entropy:.2f}", ""]
        try:
            sm = segmod.analyze(p)
            lines.append("## 分段")
            lines.append(f"- {sm.brief()}")
            if sm.split.found:
                lines.append(f"- 明暗分界：{sm.split.brief()}")
        except Exception as e:                                      # noqa: BLE001
            lines.append(f"分段失败：{e}")
        # 内嵌对象雕刻：固件 / 加壳 PE / 混合文件里常埋着 zip、dex、so
        try:
            cr = carvemod.carve_file(p, dst / "carved")
            if cr.objects:
                lines.append("## 内嵌对象")
                for o in cr.objects[:50]:
                    lines.append(f"- {o.label}" + (f" —— {o.note}" if o.note else ""))
                notes.append(f"{cr.brief()} → carved/（内嵌对象已抠出）")
        except Exception as e:                                      # noqa: BLE001
            lines.append(f"雕刻失败：{e}")
        rep.write_text("\n".join(lines), encoding="utf-8")
        res["files"] = 1
        notes.append(f"报告 → {rep}")
        return res

    # =================== 按原类型重建成品（进什么出什么） ===================
    _OUT_ARCHIVE = ("zip", "jar", "7z", "rar", "iso", "tar", "tgz", "gzip",
                    "bzip2", "xz", "zst", "lz4", "cab", "wim", "msi", "dmg",
                    "squashfs", "ar", "rpm", "apk", "ipa", "aab", "apks",
                    "xapk", "war", "ear", "whl", "egg", "epub", "docx",
                    "xlsx", "pptx", "odt", "ods", "odp", "msix", "appx")

    def repack_any(self, target: str | Path, out: str | Path,
                   patched_payload: bytes | None = None) -> dict:
        """
        把成品按**原类型**重建：进去是 .sh，出来还是能直接 sh 跑的 .sh；
        进去是程序/脚本，出来还是同后缀的单文件。

            rf.repack_any("a.sh", "out/a_已处理.sh")
            rf.repack_any("a.sh", "out/a_已处理.sh", patched_payload=新payload)
            rf.repack_any("a.zip", "out/a_已处理.zip")     # 归档得自己在外层压

        返回 {path, kind, method, ok, note}。归档类的实际打包不在这里做
        （要压的是解包目录），脚本里自行 zip/tar —— 这里只管「单文件保真」。
        """
        from .analysis import selfextract as sxmod

        p = self._need_file(target)
        kind = ftmod.sniff(p)
        dst = Path(out)
        dst.parent.mkdir(parents=True, exist_ok=True)
        size = p.stat().st_size
        data = p.read_bytes() if size <= (256 << 20) else b""
        notes: list[str] = []

        # ---- makeself 自解压脚本：保留原头，只处理数据段 ----
        ms = sxmod.parse_makeself(data) if data else None
        if ms and ms.get("comp") == "gzip":
            blob, how = sxmod.rebuild_makeself(data, patched_payload)
            dst.write_bytes(blob)
            ok, chk = sxmod.verify_makeself(dst.read_bytes())
            notes.append(f"头 {ms['offset']}B 原样保留（skip={ms['skip']}），"
                         "手机端仍按 `tail -n +skip | gzip -cd` 解")
            notes.append(chk)
            if not ok:
                raise RfError("重建后的 .sh 自检没过：" + chk)
            self.log(f"  ✓ 成品 .sh 重建：{dst.name}（{how}）")
            return {"path": str(dst), "kind": "makeself 自解压脚本（.sh）",
                    "method": how, "ok": ok, "note": "；".join(notes)}

        # ---- 归档类：提示调用方去压目录，这里只返回类型 ----
        if kind.real in self._OUT_ARCHIVE:
            return {"path": "", "kind": f"归档（{kind.real}）", "method": "需按归档打包",
                    "ok": False,
                    "note": "归档类成品请把解包目录重新压成同族压缩包"}

        # ---- 其余单文件：原样复制，后缀保持 ----
        shutil.copy2(p, dst)
        self.log(f"  ✓ 成品单文件复制：{dst.name}（{kind.label}）")
        return {"path": str(dst), "kind": kind.label,
                "method": "原样复制（后缀与类型保持）", "ok": dst.exists(),
                "note": "单文件样本无需重打包"}

    def carve(self, path: str | Path, out: str | Path | None = None) -> dict:
        """
        内嵌对象雕刻：不依赖文件头在偏移 0，直接扫字节流里的
        zip / dex / cdex / ELF / gzip / xz / bzip2 / 7z / png / jpg / pdf /
        sqlite / zstd 特征并整块抠出。vdex/oat 挖 dex、固件扒段、
        加壳 PE 找资源都靠这一层。
        返回 dict：type/found/output/objects。
        """
        p = self._need_file(path)
        self.ctx.step("扫描内嵌对象", 40)
        cr = carvemod.carve_file(p, out)
        objs = [{"kind": o.kind, "offset": o.offset, "size": o.size,
                 "note": o.note} for o in cr.objects]
        res = {"type": p.name, "found": bool(cr.objects), "objects": objs}
        if cr.objects:
            dst = Path(out) if out else p.with_name(p.stem + "_carved")
            res["output"] = str(dst)
            self.log(f"  {cr.brief()} → {dst}")
        else:
            self.log("  没有发现可雕刻的内嵌对象")
        return res

    def _tool(self, tid: str):
        """取注册表工具，不可用返回 None。"""
        try:
            t = registry().get(tid)
            return t if (t and t.available) else None
        except Exception:                                           # noqa: BLE001
            return None

    @staticmethod
    def _seven_cmd(seven) -> list[str] | None:
        """7-Zip 命令：优先完整版 7z.exe（支持 zip/rar/iso/chm/ole 等），
        7zr.exe 只认 .7z 格式，拿不到完整版时返回 None。"""
        if not seven or not getattr(seven, "available", False):
            return None
        exe = Path(seven.path or "")
        if exe.name.lower() == "7z.exe":
            return list(seven.cmd)
        full = exe.with_name("7z.exe")
        if full.exists():
            return [str(full)] + list(seven.cmd)[1:]
        # 系统 PATH 与常见安装位置找完整版
        from shutil import which
        found = which("7z") or which("7za")
        if not found:
            for cand in (r"C:\Program Files\7-Zip\7z.exe",
                         r"C:\Program Files (x86)\7-Zip\7z.exe"):
                if Path(cand).exists():
                    found = cand
                    break
        if found:
            return [found] + list(seven.cmd)[1:]
        return None

    @staticmethod
    def _count_files(res: dict, dst: Path) -> None:
        res["files"] = sum(1 for f in dst.rglob("*") if f.is_file())

    def segments(self, target: str | Path) -> segmod.SegmentMap:
        """
        分段：找出「前面明文 / 后面密文」的分界点，并尝试从明文头里捞密钥。
        这一步是解密前的必备动作——整文件直接丢给解密器，偏移差一字节就废。
        """
        sm = segmod.analyze(self._need_file(target))
        self.log(sm.brief())
        if sm.split.found:
            self.log("  " + sm.split.brief())
            if sm.split.head_keys:
                self.log("  头里疑似密钥：" + "、".join(sm.split.head_keys[:5]))
        return sm

    def garble(self, target: str | Path) -> garblemod.GarbleReport:
        """
        判断"看不懂"到底是哪种：菱形问号（非法 UTF-8）、方块（字体加密）、
        还是一片乱码（编码错位，可自动修）。
        """
        p = Path(target)
        if p.exists() and p.is_file():
            v = garblemod.view(p.read_bytes()[:65536])
            rep = v.report or garblemod.GarbleReport()
        else:
            rep = garblemod.diagnose(str(target))
        self.log(f"{garblemod.G_CN.get(rep.kind, rep.kind)} · 可读性 {rep.score}")
        if rep.note:
            self.log("  " + rep.note)
        if rep.fixed:
            self.log("  已修复：" + rep.fixed[:80])
        return rep

    # =================== 自动解密 ===================
    def decrypt_auto(self, target: str | Path | bytes, keys: list | None = None,
                     deep: bool = False, budget: float | None = None,
                     top: int = 12) -> decauto.SalvageReport:
        """
        常见加密全撞一遍：编码/压缩/XOR/RC4/AES/TEA/XXTEA/OpenSSL。
        keys 可以给字符串列表（比如你已知的密码），也可以不给（自动从文件里找）。
        """
        cands: list[deckeys.KeyCand] = []
        for k in (keys or []):
            if isinstance(k, deckeys.KeyCand):
                cands.append(k)
            else:
                cands.append(deckeys.KeyCand(value=str(k), source="用户提供",
                                             kind="string", score=95))
        rep = decauto.salvage(target, key_cands=cands or None, deep=deep,
                              budget=budget, top=top)
        self.log(rep.summary())
        if rep.hits:
            self.log(rep.table(6))
        for n in rep.notes:
            self.log("  " + n)
        return rep

    def decrypt_save(self, rep, out_dir: str | Path | None = None,
                     limit: int = 5, min_score: int = 0) -> list[Path]:
        """
        把试解结果落盘（前几个候选各存一份，方便打开看）。

        min_score 用来挡掉低分噪音 —— 1791B 的 Caesar/XOR「解出」一段
        大概是原文明文头的东西，分数不高但会挤满目录，默认不挡（0）。
        """
        od = Path(out_dir) if out_dir else self.out_dir / "decrypted"
        hits = [h for h in getattr(rep, "hits", [])
                if getattr(h, "score", 0) >= int(min_score)]
        files: list[Path] = []
        for h in hits[:limit]:
            try:
                files.append(h.save(od))
            except Exception as e:                          # noqa: BLE001
                self.log(f"  ! 落盘失败：{e}")
        for f in files:
            self.log(f"  → {f}")
        return files

    # =================== 假包（线索 → 协议 → 发包方案） ===================
    def fakepacket_build(self, target: str | Path) -> dict:
        """
        和 decrypt_auto 同一套流程，只是产物从「明文」变成「假包」：

            解出来的明文片段 → 提线索 → 判协议 → 造请求/响应/时序包 → 报告

        返回 {chain, protocols, packets, report, script}。
        """
        p = self._need_path(target)
        self.ctx.step("提取协议线索", 20)
        chain = fp_extract(p)
        self.ctx.step("判定协议与发包时机", 50)
        protos = fp_infer(chain)
        self.ctx.step("构造假包", 75)
        packs = fp_build(chain, protos)
        script = fp_script(protos[0], packs) if protos else "# 没判定出协议，没有发包脚本"
        rep = fp_report(chain, protos, packs, str(p))
        # 解出来的明文片段 → 可读线索图（用户口径「后面一大串加密没明文展现」）
        pmap = None
        try:
            pmap = fp_plaintext(p)
            rep += "\n\n## 五、明文线索图（二进制里藏的可读片段）\n\n" + pmap.markdown()
        except Exception as e:                              # noqa: BLE001
            rep += f"\n\n## 五、明文线索图\n\n抽取失败：{e}\n"
        self.log(chain.summary())
        if protos:
            self.log(f"判定：{protos[0].name}（置信 {protos[0].confidence}%）"
                     f" → {protos[0].endpoint}")
            self.log(f"  什么时候发：{protos[0].timing}")
        else:
            self.log("没判定出协议 —— 先跑解密把明文挖出来")
        return {"chain": chain, "protocols": protos, "packets": packs,
                "report": rep, "script": script, "plaintext": pmap}

    def fakepacket_save(self, result: dict,
                        out_dir: str | Path | None = None) -> list[Path]:
        """把假包、发包脚本和报告落盘。"""
        od = Path(out_dir) if out_dir else self.out_dir / "fakepacket"
        od.mkdir(parents=True, exist_ok=True)
        files: list[Path] = []
        md = od / "假包方案报告.md"
        md.write_text(result.get("report", ""), encoding="utf-8")
        files.append(md)
        sc = od / "发包脚本.py"
        sc.write_text(result.get("script", ""), encoding="utf-8")
        files.append(sc)
        pmap = result.get("plaintext")
        if pmap is not None:
            try:
                files.append(pmap.save(od))
            except Exception as e:                          # noqa: BLE001
                self.log(f"  明文完整清单落盘失败：{e}")
        for pk in result.get("packets", []):
            f = od / pk.name
            f.write_text(pk.content, encoding="utf-8")
            files.append(f)
        self.log(f"假包已落盘：{od}")
        return files

    def keys_any(self, target: str | Path, limit: int = 120) -> list:
        """从文件/目录里翻候选密钥（明文头、源码常量、配置、长 hex）。"""
        p = self._need_path(target)
        if p.is_dir():
            cands = deckeys.from_tree(p)
        else:
            cands = deckeys.from_file(p)
            if p.stat().st_size < 32 * 1024 * 1024:
                sm = segmod.analyze(p)
                if sm.split.head_keys:
                    cands = deckeys.merge(
                        cands, deckeys.from_bytes(
                            "\n".join(f"key={k}" for k in sm.split.head_keys).encode(),
                            source="明文头"))
        cands = cands[:limit]
        self.log(f"候选密钥 {len(cands)} 条")
        if cands:
            self.log(deckeys.report_table(cands, 10))
        return cands

    def cipher_profile(self) -> dict:
        """本机可用的解密算法清单（pycryptodome 缺了会如实说）。"""
        prof = decC.profile()
        self.log(f"AES/DES/ChaCha20：{'可用' if prof['pycryptodome'] else '不可用'} · "
                 f"{prof['source']}")
        return prof

    # =================== 跨类型校验点 ===================
    def auth_scan(self, target: str | Path, min_confidence: int = 45,
                  max_files: int = 3000):
        """
        找所有类型的密码/卡密/授权校验：脚本源码、PE/ELF 字符串、class 常量池、smali。
        每条都带文件+行号/偏移，能给改法的直接给 old→new。
        """
        rep = authmod.scan(self._need_path(target), min_confidence=min_confidence,
                           max_files=max_files)
        self.log(rep.summary())
        if rep.points:
            self.log(rep.table(only_pre=True, limit=12))
        for e in rep.errors[:3]:
            self.log("  ! " + e)
        return rep

    def auth_apply(self, report, ids: list[str] | None = None,
                   dry_run: bool = False, backup_dir: str | Path | None = None):
        """把脚本里的校验改成恒真（有备份、可回滚、默认先预演）。"""
        res = authmod.apply_points(report, ids=ids, backup_dir=backup_dir,
                                   dry_run=dry_run)
        for c in res.changed:
            self.log("  " + c)
        for s in res.skipped:
            self.log("  跳过 " + s)
        if res.backup and not dry_run:
            self.log("  备份：" + res.backup)
        return res

    # =================== 终端 ===================
    def terminal(self, timeout: float = 60.0):
        """拿一个常驻 Python 终端（变量跨次保留），脚本里也能用。"""
        from .engine.repl import Repl
        r = Repl(timeout=timeout)
        r.start()
        return r

    # =================== 报告 ===================
    def report(self, title: str, sections: dict[str, Any],
               name: str = "report.md") -> Path:
        """把任意 dict 渲染成中文 Markdown 报告。"""
        L = [f"# {title}\n",
             f"> 生成时间 {time.strftime('%Y-%m-%d %H:%M:%S')} · "
             f"{config.APP_NAME} {config.APP_VERSION}\n"]
        for head, body in sections.items():
            L.append(f"\n## {head}\n")
            if isinstance(body, dict):
                L.append("| 项 | 值 |")
                L.append("|---|---|")
                for k, v in body.items():
                    L.append(f"| {k} | {v} |")
            elif isinstance(body, (list, tuple)):
                for x in body:
                    L.append(f"- {x}")
            else:
                L.append(str(body))
        p = self.out_dir / "report" / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("\n".join(L), encoding="utf-8")
        self.log(f"✓ 报告：{p}")
        return p

    # =================== 内部 ===================
    def _need_file(self, path) -> Path:
        p = Path(path)
        if not p.exists():
            raise RfError(f"文件不存在：{p}")
        if not p.is_file():
            raise RfError(f"不是文件：{p}")
        return p

    def _need_path(self, path) -> Path:
        p = Path(path)
        if not p.exists():
            raise RfError(f"路径不存在：{p}")
        return p


# ---------------------------------------------------------------------------
# 给脚本用的全局实例（运行时会被替换为带 GUI 回调的版本）
# ---------------------------------------------------------------------------

def make_api(ctx: Ctx | None = None) -> Api:
    return Api(ctx or Ctx(quiet=True))
