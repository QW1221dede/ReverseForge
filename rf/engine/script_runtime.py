#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 rf.engine.script_runtime · 脚本运行时
============================================================================

【它解决什么】
    让「所有工作靠脚本运行」这句话成立：
      * 脚本是普通 .py 文件，但预置了 `rf`（工具门面）和 `args`（参数）
      * 脚本里的 print / rf.log 全部实时进 GUI 终端
      * 脚本能在后台线程跑，界面不卡，可随时看进度
      * 脚本崩了要能看懂原因 —— 异常翻译成中文 + 原始堆栈

【脚本头部元信息（可选，但强烈建议写）】
    # @name  拆解 APK 全家桶
    # @desc  解包 + 反编译 + 中文注释 + 报告
    # @param apk   目标 APK 路径  [file]
    # @param note  是否加中文注释  [bool:true]
    # @param jobs  并发数         [int:4]
    # @param mode  模式           [choice:fast,full:full]
    GUI 会据此自动生成参数表单 —— 不写也不影响运行。

【安全取向】
    这是本地工具，脚本就是作者自己写的代码，不做沙箱限制（沙箱只会让
    「调 Ghidra 分析 40 分钟」这类正常需求变得不可能）。
    唯一的纪律是：脚本的 stdout 与 `rf` 调用全部走受控通道，方便回放与复现。
============================================================================
"""

from __future__ import annotations

import contextlib
import io
import queue
import re
import sys
import threading
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from ..api import Api, Ctx, RfError


# ---------------------------------------------------------------------------
# 元信息
# ---------------------------------------------------------------------------

@dataclass
class Param:
    name: str
    label: str = ""
    ptype: str = "str"          # str / file / dir / int / bool / choice
    default: Any = ""
    choices: list[str] = field(default_factory=list)

    def __post_init__(self):
        self.label = self.label or self.name


@dataclass
class ScriptMeta:
    name: str = ""
    desc: str = ""
    params: list[Param] = field(default_factory=list)
    out: str = ""
    file: str = ""


_META_RE = {
    "name": re.compile(r"^#\s*@name\s+(.+)$", re.M),
    "desc": re.compile(r"^#\s*@desc\s+(.+)$", re.M),
    "out": re.compile(r"^#\s*@out\s+(.+)$", re.M),
}
_PARAM_RE = re.compile(r"^#\s*@param\s+(\w+)\s*(.*)$", re.M)


def parse_meta(path: str | Path) -> ScriptMeta:
    """从脚本头部注释里读元信息。读不到就用文件名兜底。"""
    p = Path(path)
    meta = ScriptMeta(file=str(p), name=p.stem)
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return meta
    head = "\n".join(text.splitlines()[:40])

    for key, rx in _META_RE.items():
        m = rx.search(head)
        if m:
            setattr(meta, key, m.group(1).strip())

    for m in _PARAM_RE.finditer(head):
        pname, rest = m.group(1), (m.group(2) or "").strip()
        ptype, default, choices = "str", "", []
        tm = re.search(r"\[(\w+)(?::([^\]]*))?\]", rest)
        if tm:
            ptype = tm.group(1).lower()
            spec = (tm.group(2) or "").strip()
            rest = rest[:tm.start()].strip()
            if ptype == "bool":
                default = spec.lower() not in ("false", "0", "no", "")
            elif ptype == "int":
                try:
                    default = int(spec)
                except ValueError:
                    default = 0
            elif ptype == "choice":
                # 语法：[choice:a,b,c] 或 [choice:a,b,c:b]（最后一段带 :默认值）
                parts = [c.strip() for c in spec.split(",") if c.strip()]
                dflt = ""
                if parts and ":" in parts[-1]:
                    last, dflt = parts[-1].split(":", 1)
                    parts[-1] = last.strip()
                    dflt = dflt.strip()
                choices = parts
                default = dflt or (choices[0] if choices else "")
            else:
                default = spec
        meta.params.append(Param(name=pname, label=rest or pname,
                                 ptype=ptype, default=default, choices=choices))
    return meta


def discover_scripts(roots: list[str | Path] | None = None) -> list[ScriptMeta]:
    """扫描脚本目录，返回所有可用脚本的元信息。"""
    from .. import config
    if roots is None:
        roots = [config.BUILTIN_SCRIPT_ROOT, config.SCRIPT_ROOT]
    seen = set()
    out: list[ScriptMeta] = []
    for r in roots:
        p = Path(r)
        if not p.exists():
            continue
        for f in sorted(p.glob("*.py")):
            if f.name.startswith("_"):
                continue
            key = f.name
            if key in seen:
                continue
            seen.add(key)
            try:
                out.append(parse_meta(f))
            except Exception:
                continue
    return out


# ---------------------------------------------------------------------------
# 事件
# ---------------------------------------------------------------------------

@dataclass
class ScriptEvent:
    kind: str          # log / step / done / error
    text: str = ""
    pct: int = 0
    ok: bool = False
    dur: float = 0.0
    traceback: str = ""


# ---------------------------------------------------------------------------
# 运行时
# ---------------------------------------------------------------------------

class _StdoutTee(io.TextIOBase):
    """把脚本里的 print 转成事件，同时留一份文本供报告使用。"""

    def __init__(self, emit: Callable[[str], None]):
        self._emit = emit
        self._buf: list[str] = []

    def write(self, s: str) -> int:
        if not s:
            return 0
        for line in s.splitlines():
            if line.strip():
                self._emit(line)
                self._buf.append(line)
        return len(s)

    def flush(self) -> None:
        pass

    def getvalue(self) -> str:
        return "\n".join(self._buf)


class ScriptRun:
    """
    一次脚本执行。GUI 侧用法：

        run = ScriptRun("scripts/x.py", {"apk": "a.apk"}, workdir)
        run.start()
        # 主线程轮询
        while run.alive: events = run.poll()
    """

    def __init__(self, script: str | Path, params: dict | None = None,
                 workdir: str | Path | None = None,
                 on_event: Callable[[ScriptEvent], None] | None = None):
        self.script = Path(script)
        self.params = params or {}
        self.on_event = on_event
        self.meta = parse_meta(self.script)
        self.events: "queue.Queue[ScriptEvent]" = queue.Queue()
        self.result: dict = {}
        self._t0 = 0.0
        self._thread: threading.Thread | None = None
        self.ctx = Ctx(workdir=Path(workdir) if workdir else None,
                       on_log=self._emit_log, on_step=self._emit_step)
        self.api = Api(self.ctx)
        self.output: list[str] = []

    # ---- 事件 ----
    def _push(self, ev: ScriptEvent) -> None:
        self.events.put(ev)
        if self.on_event:
            try:
                self.on_event(ev)
            except Exception:
                pass

    def _emit_log(self, msg: str) -> None:
        self.output.append(msg)
        self._push(ScriptEvent(kind="log", text=str(msg)))

    def _emit_step(self, name: str, pct: int) -> None:
        self._push(ScriptEvent(kind="step", text=name, pct=int(pct)))

    def poll(self) -> list[ScriptEvent]:
        """非阻塞取事件。"""
        out = []
        while True:
            try:
                out.append(self.events.get_nowait())
            except queue.Empty:
                break
        return out

    @property
    def alive(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    # ---- 执行 ----
    def start(self) -> "ScriptRun":
        self._thread = threading.Thread(target=self._work, daemon=True)
        self._thread.start()
        return self

    def wait(self, timeout: float | None = None) -> dict:
        if self._thread:
            self._thread.join(timeout)
        return self.result

    def _work(self) -> None:
        self._t0 = time.time()
        path = self.script
        try:
            raw = path.read_bytes()
        except OSError as e:
            self._fail(f"读不到脚本：{e}")
            return
        # 脚本可能是 UTF-8（带/不带 BOM）或 GBK —— 用户在记事本里存过一次
        # 就变 GBK，直接 read_text(utf-8) 会抛 UnicodeDecodeError（不是 OSError，
        # 原来的 except 接不住），线程静默死掉，GUI 永远停在"运行中"。
        src = ""
        for enc in ("utf-8-sig", "gb18030"):
            try:
                src = raw.decode(enc)
                break
            except UnicodeDecodeError:
                continue
        if not src:
            self._fail("脚本编码无法识别（既不是 UTF-8 也不是 GBK），另存为 UTF-8 再试")
            return

        self._emit_log(f"▶ 运行脚本 {path.name}")
        if self.meta.desc:
            self._emit_log(f"  {self.meta.desc}")

        # 参数：脚本里可直接用同名的全局变量
        args = dict(self.params)
        for p in self.meta.params:
            args.setdefault(p.name, p.default)

        globs: dict[str, Any] = {
            "__name__": "__rf_script__",
            "__file__": str(path),
            "rf": self.api,
            "args": args,
            "out_dir": str(self.ctx.workdir),
            "meta": self.meta,
        }
        globs.update(args)

        # 给脚本注入自己的 print —— 不用 redirect_stdout。
        # redirect_stdout 是全局的，主线程打印日志时会被同一个 tee 捕获，
        # 形成"打印 → 事件 → 打印"的自激循环，把脚本拖慢十几倍。
        def _print(*a, sep: str = " ", end: str = "\n", **kw) -> None:
            text = sep.join(str(x) for x in a)
            if text.strip():
                self._emit_log(text)

        globs["print"] = _print

        ok, err = False, ""
        try:
            code = compile(src, str(path), "exec")
            exec(code, globs)
            ok = True
        except SystemExit as e:
            ok = (e.code in (0, None))
            err = "" if ok else f"脚本主动退出 code={e.code}"
        except RfError as e:
            err = f"业务错误：{e}"
        except FileNotFoundError as e:
            err = f"文件不存在：{e.filename or e}"
        except PermissionError as e:
            err = f"权限不足：{e.filename or e}（检查是否被占用/需管理员）"
        except KeyboardInterrupt:
            err = "被用户中断"
        except Exception as e:
            err = f"{type(e).__name__}: {e}\n\n{traceback.format_exc()}"

        dur = time.time() - self._t0
        self.result = {
            "ok": ok, "error": err, "dur": dur,
            "output": "\n".join(self.output),
            "workdir": str(self.ctx.workdir),
        }
        if ok:
            self._emit_step("完成", 100)
            self._emit_log(f"✓ 脚本结束，用时 {dur:.1f}s，产物在 {self.ctx.workdir}")
            self._push(ScriptEvent(kind="done", ok=True, dur=dur,
                                   text=str(self.ctx.workdir)))
        else:
            self._emit_log("✗ 脚本失败：" + err.splitlines()[0])
            self._push(ScriptEvent(kind="error", text=err, dur=dur))
            self._push(ScriptEvent(kind="done", ok=False, dur=dur, text=err))

    def _fail(self, msg: str) -> None:
        self._emit_log("✗ " + msg)
        self._push(ScriptEvent(kind="error", text=msg))
        # 必须补一条 done：只发 error 的话 GUI 永远停在"运行中"，
        # 开始按钮永久禁用，整页没有任何恢复入口。
        self._push(ScriptEvent(kind="done", ok=False,
                               dur=max(0.0, time.time() - self._t0), text=msg))


# ---------------------------------------------------------------------------
# 命令行直接跑（便于在没有 GUI 的环境验证脚本）
# ---------------------------------------------------------------------------

def run_cli(script: str, kv: list[str] | None = None) -> int:
    """python -m rf.engine.script_runtime <script.py> k=v ..."""
    import queue as _q

    params = {}
    for item in kv or []:
        if "=" in item:
            k, v = item.split("=", 1)
            params[k] = v

    # 命令行传的永远是字符串：bool("false") 是 True，这个坑会把
    # to_desktop=false 之类的开关变成反的。按脚本元信息里的类型真转换。
    if params:
        try:
            meta = parse_meta(script)
            types = {p.name: p.ptype for p in meta.params}
            for k, v in list(params.items()):
                t = types.get(k)
                if t == "bool":
                    params[k] = str(v).strip().lower() not in ("false", "0", "no", "", "off")
                elif t == "int":
                    try:
                        params[k] = int(str(v).strip())
                    except ValueError:
                        pass
        except Exception:                            # noqa: BLE001
            pass
    run = ScriptRun(script, params)
    run.start()

    # 用阻塞取事件，不要忙等 —— 忙等会抢 GIL，把脚本线程拖慢好几倍
    while True:
        try:
            ev = run.events.get(timeout=0.2)
        except _q.Empty:
            if not run.alive:
                break
            continue
        if ev.kind == "log":
            print(ev.text, flush=False)
        elif ev.kind == "step":
            print(f"── [{ev.pct:>3}%] {ev.text}", flush=True)
        elif ev.kind == "error":
            print("ERROR:", ev.text, flush=True)
        elif ev.kind == "done":
            run.wait(timeout=5)
            break
    return 0 if run.result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(run_cli(sys.argv[1], sys.argv[2:]))
