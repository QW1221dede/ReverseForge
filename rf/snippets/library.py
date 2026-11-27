#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 rf.snippets.library · 积木库
============================================================================

【能力】
    all()            全部积木（内置 + 用户）
    get(id)          按 ID 取
    search(kw)       按标题/作用/标签搜
    compose(ids)     按依赖排序拼成一份可运行脚本，并做语法校验
    check()          重新校验全部积木（用户改了文件后调用）
    markdown()       生成完整目录（给文档/界面用）
    reload()         重新扫盘

【用户积木放哪】
    <用户目录>/snippets/*.py      （菜单「文件 → 打开用户脚本目录」的上一级）
    文件头写 @id/@title/@category/@purpose 等注释即可，格式见 model.py。

【拼装原则】
    * 依赖在前：A depends B → B 的代码先出现
    * 缺依赖不报错，只记一条提醒（积木本来就允许单独用）
    * 拼完必须过 Python 语法校验；不过就抛 ValueError，绝不交付半截脚本
============================================================================
"""

from __future__ import annotations

import time
from pathlib import Path

from .. import config
from ..analysis import validator
from . import builtin
from .model import CATEGORIES, Snippet, parse_user_snippet


class Library:
    def __init__(self, extra_dirs: list[str | Path] | None = None):
        self.items: dict[str, Snippet] = {}
        self.warnings: list[str] = []
        self.extra_dirs = [Path(p) for p in (extra_dirs or [])]
        self.reload()

    # ---- 加载 ----
    def _dirs(self) -> list[Path]:
        dirs = [config.USER_ROOT / "snippets", config.APP_ROOT / "snippets"]
        dirs.extend(self.extra_dirs)
        return dirs

    def reload(self) -> "Library":
        self.items = {s.sid: s for s in builtin.BUILTIN}
        self.warnings = [f"{s.sid}：{s.errors[0]}" for s in builtin.BUILTIN if not s.valid]
        for d in self._dirs():
            if not d.exists():
                try:
                    d.mkdir(parents=True, exist_ok=True)
                except OSError:
                    continue
            for f in sorted(d.glob("*.py")):
                if f.name.startswith("_"):
                    continue
                sn = parse_user_snippet(f)
                if sn is None:
                    continue
                if sn.sid in self.items and self.items[sn.sid].source != "内置":
                    self.warnings.append(f"{sn.sid} 重复，后者覆盖前者：{f}")
                self.items[sn.sid] = sn
                if not sn.valid:
                    self.warnings.append(f"{sn.sid}（{f.name}）语法未通过")
        return self

    # ---- 查询 ----
    def all(self, category: str = "", level: int = 0,
            only_valid: bool = True) -> list[Snippet]:
        out = list(self.items.values())
        if category:
            out = [s for s in out if s.category == category]
        if level:
            out = [s for s in out if s.level == level]
        if only_valid:
            out = [s for s in out if s.valid]
        order = {c.name: i for i, c in enumerate(CATEGORIES)}
        out.sort(key=lambda s: (order.get(s.category, 99), s.level, s.sid))
        return out

    def get(self, sid: str) -> Snippet:
        if sid not in self.items:
            near = [s for s in self.items if sid.lower() in s.sid.lower()
                    or sid.lower() in s.title.lower()]
            hint = ("；相近的有：" + "、".join(s.sid for s in near[:4])) if near else ""
            raise KeyError(f"没有这块积木：{sid}{hint}")
        return self.items[sid]

    def categories(self) -> list[dict]:
        out = []
        for c in CATEGORIES:
            items = self.all(c.name)
            if items:
                out.append({**c.to_dict(), "count": len(items),
                            "ids": [s.sid for s in items]})
        return out

    def search(self, kw: str) -> list[Snippet]:
        kw = (kw or "").strip().lower()
        if not kw:
            return self.all()
        out = []
        for s in self.items.values():
            blob = " ".join([s.sid, s.title, s.purpose, s.when,
                             " ".join(s.tags), s.category]).lower()
            if kw in blob:
                out.append(s)
        return sorted(out, key=lambda s: (s.category, s.level, s.sid))

    def check(self) -> list[Snippet]:
        bad = []
        for s in self.items.values():
            s.check()
            if not s.valid:
                bad.append(s)
        return bad

    # ---- 拼装 ----
    def _order(self, ids: list[str]) -> tuple[list[str], list[str]]:
        seen: list[str] = []
        missing: list[str] = []

        def visit(sid: str, stack: set[str]) -> None:
            if sid in seen:
                return
            if sid in stack:
                self.warnings.append(f"依赖成环：{sid}")
                return
            sn = self.items.get(sid)
            if not sn:
                missing.append(sid)
                return
            for dep in sn.depends:
                visit(dep, stack | {sid})
            seen.append(sid)

        for sid in ids:
            visit(sid, set())
        return seen, missing

    def compose(self, ids: list[str], out: str | Path | None = None,
                *, header: bool = True, order: list[str] | None = None,
                args: dict | None = None) -> str:
        """
        按依赖排序拼装，返回完整代码；给了 out 就落盘。

        order：显式顺序（用户在拼装工作台里上下调过的顺序）。
               不在 order 里的 id 补在后面，不丢块。
        args ：运行参数兜底。生成的代码里用 try/except NameError 注入，
               所以在脚本运行器里不会覆盖真实参数，直接丢进终端也能跑。
               —— 这是"拼完就能跑"的关键。
        """
        ids = [x.strip() for x in ids if x.strip()]
        if order:
            ordered = [x for x in order if x in ids]
            ordered += [x for x in ids if x not in ordered]
            missing = []
        else:
            ordered, missing = self._order(ids)
        if not ordered:
            raise ValueError("没有可拼装的积木：" + "、".join(missing or ids))

        blocks: list[str] = []
        if header:
            blocks.append(
                "# " + "=" * 70 + "\n"
                f"# ReverseForge 拼装脚本\n"
                f"# 生成时间：{time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"# 积木：{'、'.join(ordered)}\n"
                "# 每块都可单独删掉；删之前确认后面的块没用到它产出的变量。\n"
                "# " + "=" * 70 + "\n")

        if args is not None:
            # try/except 而不是直接赋值：脚本运行器已注入真参数时不要覆盖它
            blocks.insert(1 if header else 0,
                          "# ── 运行参数兜底（直接丢进终端也能跑）──\n"
                          "try:\n    args\nexcept NameError:\n    args = "
                          + repr(dict(args)) + "\n")

        need_vars: list[str] = []
        for sid in ordered:
            sn = self.items[sid]
            need_vars.extend(x for x in sn.needs
                             if x not in need_vars and x not in (args or {}))
            head = (f"# ── [{sn.sid}] {sn.title} · {sn.category}/{sn.level_name} "
                    f"──\n")
            note = f"# 作用：{sn.purpose}\n"
            if sn.risk and sn.risk != "无":
                note += f"# 风险：{sn.risk}\n"
            blocks.append(head + note + sn.code + "\n")

        code = "\n".join(blocks)
        if header and need_vars:
            code += ("\n# 运行前请确保这些变量已就位：" + "、".join(need_vars) + "\n")

        vr = validator.validate(code, "python", "<composed>")
        if not vr.ok:
            raise ValueError("拼装结果语法不通过：" + vr.errors[0].text())

        if out:
            p = Path(out)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(code, encoding="utf-8")
        return code

    # ---- 文档 ----
    def save_user(self, sid: str, title: str, code: str, category: str = "工程",
                  level: int = 2, purpose: str = "", needs: list[str] | None = None,
                  gives: list[str] | None = None, tags: list[str] | None = None,
                  depends: list[str] | None = None, risk: str = "无",
                  when: str = "") -> Path:
        """
        把代码存成「用户积木」，下次加载立刻生效。

        这是「终端改完 → 存回积木」那一步的落地：
        终端里调通的代码，不该再复制粘贴到别处，直接变成一块可复用积木。
        文件落在用户目录（不污染程序自带的内置积木）。
        """
        import re as _re

        d = self._dirs()[0]
        d.mkdir(parents=True, exist_ok=True)
        safe = _re.sub(r"[^\w.\-]", "_", sid or "user.snippet")[:60]
        p = d / f"{safe}.py"

        lines = [
            "# @id      " + (sid or safe),
            "# @title   " + (title or safe),
            "# @category " + (category or "工程"),
            "# @level   " + str(max(1, min(3, int(level or 2)))),
            "# @purpose " + (" ".join((purpose or "自定义积木").split())),
        ]
        if when:
            lines.append("# @when    " + " ".join(when.split()))
        if needs:
            lines.append("# @needs   " + ",".join(needs))
        if gives:
            lines.append("# @gives   " + ",".join(gives))
        if tags:
            lines.append("# @tags    " + ",".join(tags))
        if depends:
            lines.append("# @depends " + ",".join(depends))
        lines.append("# @risk    " + (risk or "无"))
        lines.append("")
        lines.append((code or "").rstrip() + "\n")

        p.write_text("\n".join(lines), encoding="utf-8")
        self.reload()
        return p

    def stats(self) -> dict:
        by_cat: dict[str, int] = {}
        by_level: dict[str, int] = {}
        for s in self.items.values():
            by_cat[s.category] = by_cat.get(s.category, 0) + 1
            by_level[s.level_name] = by_level.get(s.level_name, 0) + 1
        return {"total": len(self.items), "by_category": by_cat,
                "by_level": by_level,
                "invalid": sum(1 for s in self.items.values() if not s.valid)}

    def markdown(self) -> str:
        st = self.stats()
        L = ["# 代码积木目录", "",
             f"> 共 {st['total']} 块 · 入门 {st['by_level'].get('入门', 0)} / "
             f"进阶 {st['by_level'].get('进阶', 0)} / 高阶 {st['by_level'].get('高阶', 0)}", ""]
        for c in self.categories():
            L += [f"## {c['name']}（{c['count']} 块）", "", f"{c['desc']}", ""]
            for s in self.all(c["name"]):
                L.append(f"### `{s.sid}` {s.title}")
                L.append("")
                L.append(f"- 作用：{s.purpose}")
                if s.needs:
                    L.append(f"- 需要：{'、'.join(s.needs)}")
                if s.gives:
                    L.append(f"- 产出：{'、'.join(s.gives)}")
                if s.depends:
                    L.append(f"- 依赖：{'、'.join(s.depends)}")
                L.append(f"- 风险：{s.risk}")
                L.append("")
                L += ["```python", s.code, "```", ""]
        return "\n".join(L)


_LIB: Library | None = None


def get_library(reload: bool = False) -> Library:
    global _LIB
    if _LIB is None:
        _LIB = Library()
    elif reload:
        _LIB.reload()
    return _LIB
