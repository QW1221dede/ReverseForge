#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 rf.engine.repl · 常驻代码终端（跨次保留变量）
============================================================================

【为什么不用 exec()】
    界面上"运行一段代码"最省事的做法是 exec(code) 然后抓 stdout。
    但那样每次都是全新命名空间：上一块积木算出来的 rep、ops、smali_dir
    在下一块里全没了，等于每跑一块都得重头扫一遍 APK。
    这里改成**常驻子进程**，变量活到进程结束，跟真终端一样。

【怎么保证不卡死界面】
    子进程一个线程读输出，队列传回主线程；
    超时就杀掉重建（宁可丢状态，不能让界面挂住）。

【编码协议】
    父 → 子：一行 `RUN <base64(utf-8 源码)>`
    子 → 父：输出正文 + 一行 `@@RF_END@@ ok=1`
    用 base64 是为了躲开"多行代码 + 中文 + 长度算不准"这三个坑
    （按字节数读会错位，按字符数读会截断，base64 一行搞定）。

【注入的东西】
    子进程预先注入 `rf`（脚本门面），所以终端里可以直接
        rf.patch_scan("unpack")
        rep = rf.patch_scan("unpack")
        print(rep.summary())
    和写脚本完全一致，调试完的代码可以直接存成积木。
============================================================================
"""

from __future__ import annotations

import base64
import os
import queue
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path

# ---------------------------------------------------------------------------
# 子进程引导脚本
# ---------------------------------------------------------------------------

_BOOT = r'''
import sys, io, os, ast, base64, traceback

ns = {"__name__": "__main__", "__doc__": None}
ns["ns"] = ns          # 让终端里能直接看命名空间（查变量、清变量）

# 注入脚本门面，方便直接调
try:
    sys.path.insert(0, os.environ.get("RF_HOME", ""))
    from rf.api import make_api
    ns["rf"] = make_api()

    # 终端里没有界面回调，rf.log/rf.step 原本会被吞掉。
    # 这里把它们接到 stdout，积木代码原样丢进来就能看到输出。
    def _t_log(*a, **k):
        print(*a)

    def _t_step(name, pct=0):
        print("[%3d%%] %s" % (pct, name))

    def _t_note(title, body=""):
        print("── %s ──" % title)
        if body:
            print(body)

    ns["rf"].log = _t_log
    ns["rf"].step = _t_step
    try:
        ns["rf"].note = _t_note
    except Exception:
        pass
except Exception as _e:
    ns["_rf_error"] = repr(_e)


def _run(src):
    """按 REPL 语义执行：最后一行是表达式就打印它的值。"""
    tree = ast.parse(src, "<rf-terminal>", "exec")
    last = None
    if tree.body and isinstance(tree.body[-1], ast.Expr):
        last = ast.Expression(tree.body.pop().value)
    if tree.body:
        exec(compile(tree, "<rf-terminal>", "exec"), ns)
    if last is not None:
        val = eval(compile(last, "<rf-terminal>", "eval"), ns)
        if val is not None:
            print(repr(val))


def main():
    out = sys.stdout
    while True:
        line = sys.stdin.readline()
        if not line:
            break
        line = line.rstrip("\n")
        if line == "QUIT":
            break
        if not line.startswith("RUN "):
            continue
        try:
            src = base64.b64decode(line[4:]).decode("utf-8")
        except Exception:
            out.write("协议解析失败\n@@RF_END@@ ok=0\n")
            out.flush()
            continue

        buf = io.StringIO()
        old_o, old_e = sys.stdout, sys.stderr
        sys.stdout = sys.stderr = buf
        ok = True
        try:
            _run(src)
        except SystemExit:
            pass
        except BaseException:
            ok = False
            traceback.print_exc(file=buf)
        finally:
            sys.stdout, sys.stderr = old_o, old_e

        text = buf.getvalue()
        if text:
            out.write(text if text.endswith("\n") else text + "\n")
        out.write("@@RF_END@@ ok=%d\n" % (1 if ok else 0))
        out.flush()


main()
'''


@dataclass
class ReplResult:
    ok: bool = False
    out: str = ""
    err: str = ""
    elapsed: float = 0.0
    restarted: bool = False

    @property
    def text(self) -> str:
        return self.out if self.out else self.err


class Repl:
    """
    常驻 Python 终端。
    用法：
        r = Repl()
        r.start()
        print(r.run("a = 1+1").out)
        print(r.run("a * 10").out)      # 20，变量还在
        r.stop()
    """

    def __init__(self, python: str | None = None, cwd: str | Path | None = None,
                 timeout: float = 30.0, home: str | Path | None = None):
        self.python = python or sys.executable
        self.cwd = str(cwd or Path(__file__).resolve().parent.parent.parent)
        self.timeout = timeout
        self.home = str(home or self.cwd)
        self.proc: subprocess.Popen | None = None
        self._q: queue.Queue = queue.Queue()
        self._boot_file: Path | None = None
        self.runs = 0
        # 打包成 exe 后找不到可用解释器时，退化成"本进程内持久命名空间"
        self._inproc = False
        self._ns: dict = {}

    # ---- 生命周期 ----
    @property
    def alive(self) -> bool:
        if self._inproc:
            return True
        return self.proc is not None and self.proc.poll() is None

    def _pick_python(self) -> str:
        """
        决定用哪种执行方式。

        源码运行：起一个真子进程 —— 变量隔离、能强杀、超时可控。
        打包成 exe：**直接用进程内模式**。
          原因有两个：
            1. sys.executable 指向 exe 自己，拿它跑引导脚本只会再弹一个主窗口；
            2. 就算机器上装了 python，exe 目录里也没有 rf 源码树，
               子进程里 `from rf.api import make_api` 会失败，终端就残了。
          进程内模式拿到的是真 rf 门面，代价是不能强杀（死循环只能等或关窗口），
          这个取舍写在 README 里，不藏着。
        """
        if getattr(sys, "frozen", False):
            return ""
        return self.python

    def start(self) -> "Repl":
        if self.alive:
            return self
        exe = self._pick_python()
        if not exe:
            self._inproc = True
            self._init_inproc()
            return self

        fd, path = tempfile.mkstemp(prefix="rf_repl_", suffix=".py")
        os.close(fd)
        self._boot_file = Path(path)
        self._boot_file.write_text(_BOOT, encoding="utf-8")

        env = dict(os.environ)
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUNBUFFERED"] = "1"
        env["RF_HOME"] = self.home
        env["PYTHONPATH"] = self.home + os.pathsep + env.get("PYTHONPATH", "")

        flags = 0
        if os.name == "nt":
            flags = 0x08000000              # CREATE_NO_WINDOW：打包后不弹黑框
        try:
            self.proc = subprocess.Popen(
                [exe, "-u", str(self._boot_file)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=self.cwd, env=env, creationflags=flags,
            )
        except OSError:
            # 起不来也别报废，直接退化成进程内模式
            self._inproc = True
            self._init_inproc()
            return self

        self._q = queue.Queue()
        threading.Thread(target=self._reader, daemon=True).start()
        return self

    def _reader(self) -> None:
        if not self.proc or not self.proc.stdout:
            return
        try:
            for raw in self.proc.stdout:
                self._q.put(raw.decode("utf-8", "replace").rstrip("\n"))
        except (ValueError, OSError):
            pass
        finally:
            self._q.put(None)

    def stop(self) -> None:
        self._inproc = False
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.stdin and self.proc.stdin.write(b"QUIT\n")
                self.proc.stdin and self.proc.stdin.flush()
            except (OSError, ValueError):
                pass
            try:
                self.proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.proc = None

    def restart(self) -> "Repl":
        if self._inproc:
            self._ns.clear()
            self._init_inproc()
            return self
        self.stop()
        if self._boot_file and self._boot_file.exists():
            try:
                self._boot_file.unlink()
            except OSError:
                pass
        return self.start()

    # ---- 进程内退化模式（打包后找不到解释器时用）----
    def _init_inproc(self) -> None:
        """
        没有可用解释器时，在本进程里开一个持久命名空间执行。
        差别：变量照样跨次保留，但**不能杀**（没法中断死循环），
        也不会真正重启进程 —— 这点在界面上会如实提示。
        """
        self._ns = {"__name__": "__main__", "__doc__": None}
        self._ns["ns"] = self._ns
        try:
            from ..api import make_api
            api = make_api()
            api.log = lambda *a, **k: print(*a)
            api.step = lambda name, pct=0: print("[%3d%%] %s" % (pct, name))
            self._ns["rf"] = api
        except Exception as e:                       # noqa: BLE001
            self._ns["_rf_error"] = repr(e)

    def _run_inproc(self, code: str) -> ReplResult:
        import ast
        import contextlib
        import io
        import traceback

        t0 = time.time()
        res = ReplResult()
        buf = io.StringIO()
        ns = self._ns
        try:
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                tree = ast.parse(code, "<rf-terminal>", "exec")
                last = None
                if tree.body and isinstance(tree.body[-1], ast.Expr):
                    last = ast.Expression(tree.body.pop().value)
                if tree.body:
                    exec(compile(tree, "<rf-terminal>", "exec"), ns)
                if last is not None:
                    val = eval(compile(last, "<rf-terminal>", "eval"), ns)
                    if val is not None:
                        print(repr(val))
            res.ok = True
        except SystemExit:
            res.ok = True
        except BaseException:                        # noqa: BLE001
            res.ok = False
            traceback.print_exc(file=buf)
        res.out = buf.getvalue()
        if not res.ok:
            res.err = res.out
        res.elapsed = time.time() - t0
        self.runs += 1
        return res

    # ---- 执行 ----
    def run(self, code: str, timeout: float | None = None) -> ReplResult:
        t0 = time.time()
        res = ReplResult()
        code = (code or "").rstrip()
        if not code:
            res.ok = True
            return res

        if not self.alive:
            try:
                self.start()
                res.restarted = True
            except RuntimeError as e:
                res.err = str(e)
                return res

        if self._inproc:
            return self._run_inproc(code)

        payload = base64.b64encode(code.encode("utf-8")).decode("ascii")
        try:
            assert self.proc and self.proc.stdin
            self.proc.stdin.write(("RUN " + payload + "\n").encode("utf-8"))
            self.proc.stdin.flush()
        except (OSError, ValueError, AssertionError) as e:
            res.err = f"写入失败：{e}"
            self.restart()
            res.restarted = True
            return res

        limit = timeout if timeout is not None else self.timeout
        lines: list[str] = []
        ok = False
        deadline = time.time() + limit
        while True:
            left = deadline - time.time()
            if left <= 0:
                res.err = (lines and "\n".join(lines) or "") + \
                          f"\n[超时 {limit:.0f}s，已强制重启终端（变量丢失）]"
                self.restart()
                res.restarted = True
                res.elapsed = time.time() - t0
                return res
            try:
                item = self._q.get(timeout=left)
            except queue.Empty:
                continue
            if item is None:
                res.err = "\n".join(lines) + "\n[终端进程已退出，已重启]"
                self.restart()
                res.restarted = True
                res.elapsed = time.time() - t0
                return res
            if item.startswith("@@RF_END@@"):
                ok = "ok=1" in item
                break
            lines.append(item)

        res.ok = ok
        res.out = "\n".join(lines)
        if not ok:
            res.err = res.out
        res.elapsed = time.time() - t0
        self.runs += 1
        return res

    # ---- 便捷方法 ----
    def shell(self, cmdline: str, timeout: float = 60.0) -> ReplResult:
        """跑一条系统命令（不进 Python 终端，直接在 cwd 里执行）。"""
        t0 = time.time()
        res = ReplResult()
        try:
            p = subprocess.run(cmdline, shell=True, cwd=self.cwd,
                               capture_output=True, timeout=timeout)
            res.ok = p.returncode == 0
            res.out = p.stdout.decode("utf-8", "replace")
            res.err = p.stderr.decode("utf-8", "replace")
        except subprocess.TimeoutExpired:
            res.err = f"命令超时（{timeout:.0f}s）"
        except OSError as e:
            res.err = str(e)
        res.elapsed = time.time() - t0
        return res

    def variables(self, limit: int = 60) -> list[tuple[str, str]]:
        """列出当前命名空间里的变量（名, 类型+摘要）。"""
        code = (
            "_rf_vars = [(k, type(v).__name__, repr(v)[:60]) "
            "for k, v in list(ns.items()) if not k.startswith('__')]"
        )
        r = self.run(code + "\nprint(_rf_vars)")
        if not r.ok:
            return []
        try:
            import ast as _ast
            data = _ast.literal_eval(r.out.strip().splitlines()[-1])
            return [(k, f"{t} = {v}") for k, t, v in data][:limit]
        except Exception:                            # noqa: BLE001
            return []

    def reset_namespace(self) -> None:
        self.run("ns.clear(); ns['__name__'] = '__main__'")


def quick_run(code: str, timeout: float = 30.0) -> ReplResult:
    """一次性执行（临时终端，用完销毁）。脚本/自测用。"""
    r = Repl()
    try:
        r.start()
        return r.run(code, timeout=timeout)
    finally:
        r.stop()
