#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 rf.tools.runner · 统一子进程执行器
============================================================================

【它解决什么问题】
    逆向工具全是命令行程序，输出格式五花八门：
      * jadx 进度刷在 stderr，坑
      * apktool 用 cp936/gbk 输出中文
      * ghidra headless 会吐几千行日志
      * 有的工具卡住不返回
    这一层把它们统一成：流式回调 + 超时 + 编码自动回退 + 落盘留证。

【核心 API】
    run(cmd, cwd=None, timeout=None, on_line=None, env_extra=None) -> RunResult
    run_bg(...)      后台执行，返回句柄
    which(name)      在注册的 PATH 里找可执行文件

【编码策略】
    先 utf-8 严格解码，失败逐行退回 gbk / cp936 / latin-1。
    Windows 上工具输出经常是混合编码，宁可乱码也不能丢行。
============================================================================
"""

from __future__ import annotations

import os
import queue
import re
import shlex
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Sequence

from .. import config

IS_WIN = sys.platform == "win32"
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0) if IS_WIN else 0

# 这些前缀的行视为"噪音"，GUI 里折叠或降级显示
_NOISE_PATTERNS = (
    re.compile(r"^Picked up (JAVA|_JAVA)_OPTIONS"),
    re.compile(r"^WARNING: A restricted method"),
    re.compile(r"^WARNING: Use --enable-native-access"),
    # jadx 对复杂 try 块的已知无害告警，一个包能刷几千行
    re.compile(r"No support yet for finding bottom block"),
    # jadx 自己的进度行，我们用百分比进度替代
    re.compile(r"^\s*(INFO|DEBUG)\s+-\s+progress:"),
    re.compile(r"^\s*$"),
)


@dataclass
class RunResult:
    """一次子进程执行的完整结果。"""
    cmd: list[str]
    rc: int = -1
    out: str = ""
    dur: float = 0.0
    timed_out: bool = False
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.rc == 0 and not self.timed_out and not self.error

    def tail(self, n: int = 40) -> str:
        lines = self.out.strip().splitlines()
        return "\n".join(lines[-n:])

    def __str__(self) -> str:
        state = "OK" if self.ok else f"FAIL(rc={self.rc})"
        return f"[{state} {self.dur:.1f}s] {' '.join(self.cmd[:6])}..."


# ---------------------------------------------------------------------------
# 全局子进程登记表 —— 让「停止」按钮真的能杀掉正在跑的 jadx/apktool
# ---------------------------------------------------------------------------
_RUNNING: "set[subprocess.Popen]" = set()
_RUN_LOCK = threading.Lock()


def kill_all() -> int:
    """杀掉所有正在执行的子进程。返回杀掉的个数。"""
    with _RUN_LOCK:
        procs = list(_RUNNING)
    n = 0
    for p in procs:
        try:
            p.kill()
            n += 1
        except Exception:
            pass
    return n


def running_count() -> int:
    with _RUN_LOCK:
        return len(_RUNNING)


def _decoder_stream(pipe, on_line: Callable[[str], None] | None, buf: list[str]) -> None:
    """
    逐行读 pipe，做编码回退，回调并把结果塞进 buf。

    用 readline 而不是 read()：工具输出可能是长任务，必须实时看到。
    """
    for raw in iter(pipe.readline, b""):
        text = _decode_line(raw)
        if text is None:
            continue
        buf.append(text)
        if on_line:
            try:
                on_line(text)
            except Exception:
                pass
    try:
        pipe.close()
    except Exception:
        pass


def _decode_line(raw: bytes) -> str | None:
    """单行解码。空行返回 None（不往 GUI 灌空行）。"""
    if not raw:
        return None
    for enc in ("utf-8", "gbk", "cp936"):
        try:
            text = raw.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    else:
        text = raw.decode("latin-1")
    text = text.rstrip("\r\n")
    if not text.strip():
        return None
    return text


def is_noise(line: str) -> bool:
    return any(p.search(line) for p in _NOISE_PATTERNS)


def run(
    cmd: Sequence[str | Path],
    cwd: str | Path | None = None,
    timeout: float | None = None,
    on_line: Callable[[str], None] | None = None,
    env_extra: dict | None = None,
    log_name: str | None = None,
) -> RunResult:
    """
    执行一条命令，阻塞到结束。

    timeout 为 None 表示不限时（长任务如 Ghidra 分析可能跑几十分钟）。
    """
    cmd_list = [str(c) for c in cmd]
    res = RunResult(cmd=cmd_list)

    # 日志落盘：每个任务一份，方便事后翻
    log_path = None
    if log_name:
        config.ensure_dirs()
        safe = re.sub(r"[^\w\-.]+", "_", log_name)[:80]
        log_path = config.LOG_ROOT / f"{safe}_{time.strftime('%Y%m%d_%H%M%S')}.log"

    env = os.environ.copy()
    if env_extra:
        env.update({k: str(v) for k, v in env_extra.items()})
    # 注意：不要设 JAVA_TOOL_OPTIONS="" —— 那反而会让 JVM 打印
    # "Picked up JAVA_TOOL_OPTIONS:" 到 stderr，污染版本探测和日志。

    t0 = time.time()
    try:
        proc = subprocess.Popen(
            cmd_list,
            cwd=str(cwd) if cwd else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,     # 合并，保证时序不乱
            stdin=subprocess.DEVNULL,     # 绝不等待输入
            env=env,
            creationflags=_NO_WINDOW,
            bufsize=0,
        )
    except FileNotFoundError as e:
        res.error = f"找不到可执行文件：{cmd_list[0]}"
        res.dur = time.time() - t0
        _write_log(log_path, res)
        return res
    except OSError as e:
        res.error = f"启动失败：{e}"
        res.dur = time.time() - t0
        _write_log(log_path, res)
        return res

    buf: list[str] = []
    t = threading.Thread(
        target=_decoder_stream, args=(proc.stdout, on_line, buf), daemon=True
    )
    t.start()

    with _RUN_LOCK:
        _RUNNING.add(proc)

    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        res.timed_out = True
        try:
            proc.kill()
        except Exception:
            pass
        try:
            proc.wait(timeout=5)
        except Exception:
            pass

    with _RUN_LOCK:
        _RUNNING.discard(proc)

    t.join(timeout=5)
    res.rc = proc.returncode if proc.returncode is not None else -1
    res.out = "\n".join(buf)
    res.dur = time.time() - t0
    _write_log(log_path, res)
    return res


def _write_log(path: Path | None, res: RunResult) -> None:
    if not path:
        return
    try:
        head = "$ " + " ".join(shlex.quote(c) for c in res.cmd) + "\n"
        head += f"# rc={res.rc} dur={res.dur:.2f}s timeout={res.timed_out}\n\n"
        path.write_text(head + res.out, encoding="utf-8", errors="replace")
    except OSError:
        pass


class BackgroundJob:
    """
    后台任务句柄 —— 给 GUI 用，不阻塞主线程。

    on_line 会在**工作线程**里被调用，GUI 层必须自己往队列里塞、由主线程消费。
    """

    def __init__(self, cmd, cwd=None, on_line=None, env_extra=None, log_name=None):
        self.cmd = [str(c) for c in cmd]
        self.cwd = cwd
        self.on_line = on_line
        self.env_extra = env_extra
        self.log_name = log_name
        self.result: RunResult | None = None
        self._q: queue.Queue = queue.Queue()
        self._thread = threading.Thread(target=self._work, daemon=True)

    def start(self) -> "BackgroundJob":
        self._thread.start()
        return self

    def _work(self):
        def _cb(line):
            self._q.put(line)
            if self.on_line:
                try:
                    self.on_line(line)
                except Exception:
                    pass

        self.result = run(
            self.cmd, cwd=self.cwd, on_line=_cb,
            env_extra=self.env_extra, log_name=self.log_name,
        )
        self._q.put(None)   # 结束哨兵

    def poll(self) -> list[str]:
        """取走当前已产生的所有行（非阻塞）。"""
        out = []
        while True:
            try:
                item = self._q.get_nowait()
            except queue.Empty:
                break
            if item is None:
                break
            out.append(item)
        return out

    def wait(self, timeout: float | None = None) -> RunResult | None:
        self._thread.join(timeout=timeout)
        return self.result

    @property
    def alive(self) -> bool:
        return self._thread.is_alive()


def run_bg(cmd, cwd=None, on_line=None, env_extra=None, log_name=None) -> BackgroundJob:
    return BackgroundJob(cmd, cwd, on_line, env_extra, log_name).start()


def which(name: str) -> str | None:
    """在 PATH 里找可执行文件。"""
    from shutil import which as _w
    return _w(name)


def java_env(jdk_root: Path | None) -> dict:
    """
    生成给 Java 系工具用的环境变量。

    jadx 要 JAVA_HOME 指向 JDK17+；Ghidra 要 JDK21，不能混用。
    """
    if not jdk_root:
        return {}
    return {
        "JAVA_HOME": str(jdk_root),
        "PATH": f"{jdk_root / 'bin'}{os.pathsep}" + os.environ.get("PATH", ""),
    }
