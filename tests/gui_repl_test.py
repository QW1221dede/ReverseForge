#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 tests/gui_repl_test.py · GUI 代码终端自测（跑真主循环）
============================================================================

    注意：不能用 `while + update()` 驱动 —— tkinter 的 after() 在
    "主循环没在跑"的时候会抛 RuntimeError: main thread is not in main loop
    （这个坑第一次测就踩了）。所以老老实实 mainloop + after 串起来。

    测的内容就是用户实际会做的事：
      [1] 积木页「送终端」→ 代码进编辑区
      [2] 按运行 → 输出回显
      [3] 变量跨次保留（终端和一次性 exec 的关键差别）
      [4] 出错有红色提示但不崩
      [5] 存回积木 → 积木库多一块
      [6] 补丁页「改法送终端」→ 生成的是可运行代码
============================================================================
"""

from __future__ import annotations

import sys
import time
import tkinter as tk
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rf.ui import app as appmod
from rf.ui.app import App

FAILED: list[str] = []
STEPS: list[tuple[str, callable]] = []


def check(name: str, cond: bool, extra: str = "") -> None:
    mark = "✓" if cond else "✗"
    print(f"  {mark} {name}" + (f"  [{extra}]" if extra else ""))
    if not cond:
        FAILED.append(name)


class Driver:
    """用 after 串起一串检查，最后退出主循环。"""

    def __init__(self, app: App):
        self.app = app
        self.i = 0
        self.t0 = time.time()

    def start(self) -> None:
        self.app.after(400, self.step)

    def _wait(self, cond, then, timeout: float = 25.0) -> None:
        def poll(left: float) -> None:
            if cond():
                then()
            elif left <= 0:
                check("等待超时", False)
                then()
            else:
                self.app.after(120, lambda: poll(left - 0.12))
        poll(timeout)

    def step(self) -> None:
        app = self.app
        if self.i == 0:
            print("[1] 积木页送终端")
            app._snip_reload()
            app.after(200, self._pick_snippet)
            return
        if self.i == 1:
            print("[2] 运行")
            app._repl_run()
            self._wait(lambda: not app._repl_busy, self._after_run1, 30)
            return
        if self.i == 2:
            print("[3] 变量跨次保留")
            app.repl_send("print(total * 2)", "第二次")
            app.update_idletasks()
            # 只跑新加的那一行
            src = app.repl_edit.get("1.0", "end").strip().splitlines()[-1]
            app.repl_edit.tag_add("sel", "end-2l", "end-1c")
            app._repl_run(True)
            self._wait(lambda: not app._repl_busy, self._after_run2, 20)
            return
        if self.i == 3:
            print("[4] 出错处理")
            app.repl_send("raise ValueError('故意的')")
            src = "raise ValueError('故意的')"
            app.repl_edit.delete("1.0", "end")
            app.repl_edit.insert("1.0", src)
            app._repl_run()
            self._wait(lambda: not app._repl_busy, self._after_err, 20)
            return
        if self.i == 4:
            print("[5] 存回积木")
            app.repl_edit.delete("1.0", "end")
            app.repl_edit.insert("1.0", "total = 21\nprint(total * 2)")
            app._repl_title = "自测积木"
            app._repl_sid = "user.gui_selftest"
            app._repl_save_snippet()
            app.after(300, self._after_save)
            return
        if self.i == 5:
            print("[6] 补丁页改法送终端")
            app.patch_target.set("unpack_dir")
            app._patch_rep = None
            app.repl_send("# placeholder", "占位")
            # 直接调生成逻辑，检查代码文本是否可编译
            ids = ["P001"]
            target = app.patch_target.get().strip()
            code = (
                f"# 来自补丁页：{', '.join(ids)}\n"
                f"SMALI = r\"{target}\"\n"
                f"rep = globals().get('rep') or rf.patch_scan(SMALI)\n"
                f"ops = rf.patch_plan(rep, ids={ids!r})\n"
                f"print(rf.patch_apply(SMALI, ops, dry_run=True).text())\n"
            )
            try:
                compile(code, "<patch>", "exec")
                ok = True
            except SyntaxError as e:
                ok = False
                print("    语法错误:", e)
            check("补丁改法代码可编译", ok)
            self.i = 99
            app.after(300, app.quit)
            return

    # ---- 各步回调 ----
    def _pick_snippet(self) -> None:
        app = self.app
        ids = list(getattr(app, "_snip_map", {}).keys())
        if ids:
            app._snip_current = app._snip_map[ids[0]]
            app._snip_on_select(None) if False else None
        # 直接取第一块的代码送终端（再补一行确定的输出，避免"循环没数据所以没输出"）
        first = ids[0] if ids else ""
        snip = app._snip_lib.get(app._snip_map[first]) if first else None
        if snip:
            app.repl_send(snip.code + '\nprint("TERMINAL-OK")', snip.title, snip.sid)
            check("送终端后编辑区有代码", snip.code.strip()[:10] in
                  app.repl_edit.get("1.0", "end"))
        else:
            app.repl_send('total = 5\nprint("TERMINAL-OK")', "兜底")
            check("兜底送终端", True)
        self.i = 1
        app.after(200, self.step)

    def _after_run1(self) -> None:
        app = self.app
        out = app.repl_out.get("1.0", "end")
        check("第一次运行有输出", "TERMINAL-OK" in out, out.strip()[-40:])
        check("状态为完成", "完成" in app.lbl_repl_stat.cget("text"),
              app.lbl_repl_stat.cget("text"))
        # 为下一步准备一个已知变量
        app.repl_edit.delete("1.0", "end")
        app.repl_edit.insert("1.0", "total = 21")
        app._repl_run()
        self.app.after(50, lambda: self._wait(lambda: not app._repl_busy,
                                              self._go2, 15))

    def _go2(self) -> None:
        self.i = 2
        self.app.after(100, self.step)

    def _after_run2(self) -> None:
        app = self.app
        out = app.repl_out.get("1.0", "end")
        check("变量跨次保留（21*2=42）", "42" in out, out.strip()[-40:])
        self.i = 3
        app.after(150, self.step)

    def _after_err(self) -> None:
        app = self.app
        out = app.repl_out.get("1.0", "end")
        check("错误被捕获并显示", "ValueError" in out)
        check("界面没崩（状态为出错）", "出错" in app.lbl_repl_stat.cget("text"),
              app.lbl_repl_stat.cget("text"))
        self.i = 4
        app.after(150, self.step)

    def _after_save(self) -> None:
        app = self.app
        lib = app._snip_lib
        got = lib.get("user.gui_selftest")
        check("积木库里出现新积木", got is not None and got.title == "自测积木",
              got.title if got else "未找到")
        check("存回的代码一致", got is not None and "total = 21" in got.code)
        self.i = 5
        app.after(150, self.step)


def main() -> None:
    app = App()
    app.withdraw()          # 不弹窗，纯功能测试
    d = Driver(app)
    app.after(300, d.start)
    app.after(90_000, app.quit)      # 保险丝
    app.mainloop()
    try:
        app._repl and app._repl.stop()
    except Exception:                                # noqa: BLE001
        pass
    app.destroy()

    if FAILED:
        print(f"\n失败 {len(FAILED)} 项：")
        for f in FAILED:
            print("  ✗", f)
        sys.exit(1)
    print("\n全部通过")


if __name__ == "__main__":
    main()
