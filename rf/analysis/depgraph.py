#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 rf.analysis.depgraph · 跨文件依赖图与核心校验点识别
============================================================================

【为什么必须有这一层】
    单文件注释永远回答不了逆向时最关键的两个问题：
        1. 这个类是"核心"还是"边角料"？ —— 只能看它被多少地方依赖。
        2. 授权校验到底卡在哪一环？ —— 必须顺着调用链从入口走到判定点。

    所以这一层干三件事：
      · 建图：类 → 类、方法 → 方法的有向调用边（含字段类型依赖）
      · 定级：按入度（被依赖次数）、入口可达性、语义特征给每个类打分
      · 找链：从 Activity/Service 入口出发，把通往校验点的路径还原出来

【怎么把调用关系连起来（这一步决定图的准确性）】
    Java 里 `foo.bar()` 的 foo 是字段、参数还是局部变量，光看这一行不知道。
    本模块做**有限类型推断**：
        foo 是字段（ClassNote.fields）      → 用它声明的类型
        foo 是局部变量（MethodNote.local_types） → 用声明类型
        foo 首字母大写                       → 当作类名（静态调用）
        foo == this / 无接收者               → 类内部调用
        foo == super                        → 父类
    推不出来的一律丢掉，不猜 —— 宁可少一条边，也不要指错人。

【"核心依赖"的判定依据（这是推断，不是事实）】
    语义分（命中校验类特征）+ 结构分（入度高）+ 可达性（从入口能走到）。
    三者都写进注释，读者能看出"为什么它被标成核心"。
    它不等于"这是程序的唯一关键点"—— R8 混淆后名字全丢，
    只靠命名和 API 特征判断，必然有漏判。
============================================================================
"""

from __future__ import annotations

import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path

from . import verify
from .annotate import ClassNote, MethodNote, parse_source

# ---------------------------------------------------------------------------
# 语义特征：什么样的东西算"校验"
#   逆向时真正要动的就是这些点，其它都是外围
# ---------------------------------------------------------------------------

# 校验特征规则放在 verify.py —— 注释器和依赖图共用同一套判定，
# 否则会出现"注释标了校验点、报告里却不收录"的矛盾。
MAX_CHAIN = 6            # 回溯链最大长度（再多就不是"链路"，是"整个程序"）
MAX_CHAINS = 3           # 每个核心点最多给几条链
MAX_GRAPH_FILES = 12000  # 防御：超大工程只建前 N 个文件的图

# 这些父类说明类是"入口"——从系统/用户操作能直接触达
ENTRY_BASES = {
    "Activity", "AppCompatActivity", "FragmentActivity", "Fragment",
    "Service", "IntentService", "JobService", "BroadcastReceiver",
    "ContentProvider", "Application", "View", "DialogFragment",
}


# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------

@dataclass
class Edge:
    caller: str
    caller_method: str
    callee: str
    callee_method: str
    kind: str = "call"        # call / field / super


@dataclass
class NodeStat:
    """一个类的图统计与判定结果。"""
    name: str
    file: str = ""
    pkg: str = ""
    fan_in: int = 0                    # 被多少个不同类依赖
    fan_out: int = 0                   # 依赖了多少个不同类
    callers: list[str] = field(default_factory=list)
    callees: list[str] = field(default_factory=list)
    is_entry: bool = False
    reachable_from_entry: bool = False
    verify_cat: str = ""               # 命中哪类校验
    verify_score: int = 0
    verify_hits: list[str] = field(default_factory=list)   # 具体命中项（名字/字面量/API）
    chains: list[list[str]] = field(default_factory=list)  # 入口 → 本类的路径

    # 判定阈值。语义分与入度是两条独立证据：
    #   语义 → 这是"校验点"（功能开关所在）
    #   入度 → 这是"结构枢纽"（改它会波及一大片）
    CORE_SCORE = 30      # 语义分达到这个值直接算核心
    CORE_FANIN = 6       # 被 6 个以上类依赖，也算核心
    WARN_SCORE = 15

    @property
    def criticality(self) -> str:
        """核心度分档：核心 / 重要 / 普通"""
        if self.verify_score >= self.CORE_SCORE or self.fan_in >= self.CORE_FANIN:
            return "核心"
        if self.fan_in >= 2 or self.verify_score >= self.WARN_SCORE:
            return "重要"
        return "普通"

    @property
    def is_verify(self) -> bool:
        return self.verify_score >= 15


@dataclass
class DepGraph:
    nodes: dict[str, NodeStat] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    notes: dict[str, ClassNote] = field(default_factory=dict)   # 类名 → 结构
    dup_names: list[str] = field(default_factory=list)          # 同名类（跨包冲突）
    files_scanned: int = 0

    # ---------- 查询 ----------

    def stat(self, name: str) -> NodeStat | None:
        return self.nodes.get(name)

    def verify_nodes(self) -> list[NodeStat]:
        return sorted((n for n in self.nodes.values() if n.is_verify),
                      key=lambda n: (-n.verify_score, -n.fan_in))

    def core_nodes(self) -> list[NodeStat]:
        return sorted((n for n in self.nodes.values() if n.criticality == "核心"),
                      key=lambda n: (-n.verify_score, -n.fan_in))

    def hubs(self, top: int = 12) -> list[NodeStat]:
        return sorted(self.nodes.values(), key=lambda n: -n.fan_in)[:top]

    def method_callers(self, cls: str, method: str) -> list[tuple[str, str]]:
        """谁调用了 X.method —— 改这个方法前必须看的清单。"""
        out = []
        for e in self.edges:
            if e.callee == cls and (e.callee_method == method or not method):
                out.append((e.caller, e.caller_method))
        return out

    # ---------- 输出 ----------

    def to_index(self) -> dict:
        """给注释器/报告用的轻量索引。"""
        return {
            n.name: {
                "file": n.file,
                "fan_in": n.fan_in,
                "fan_out": n.fan_out,
                "callers": n.callers[:8],
                "criticality": n.criticality,
                "verify_cat": n.verify_cat,
                "chains": ["→".join(c) for c in n.chains],
            }
            for n in self.nodes.values()
        }

    def summary(self) -> str:
        if not self.nodes:
            return "（未建立依赖图）"
        ent = [n.name for n in self.nodes.values() if n.is_entry]
        core = self.core_nodes()
        ver = self.verify_nodes()
        L = [
            f"扫描 {self.files_scanned} 个文件，类 {len(self.nodes)} 个，调用边 {len(self.edges)} 条",
            f"入口类 {len(ent)} 个：{'、'.join(ent[:6])}" + ("…" if len(ent) > 6 else ""),
        ]
        if core:
            L.append(f"核心类 {len(core)} 个：{'、'.join(n.name for n in core[:8])}")
        if ver:
            L.append("校验点：" + "；".join(
                f"{n.name}（{n.verify_cat}，入度 {n.fan_in}）" for n in ver[:5]))
        return "\n".join(L)

    def report_md(self) -> str:
        """Markdown 版报告：校验点在前（最有用），结构枢纽在后。"""
        L: list[str] = []

        vers = self.verify_nodes()
        core = [n for n in self.core_nodes() if not n.is_verify]
        hubs = [n for n in self.hubs(10) if n.fan_in > 0]

        # ---- 校验点 ----
        L.append("## 校验点（功能开关所在，优先看这里）")
        L.append("")
        if vers:
            L.append("| 类 | 类别 | 分数 | 被依赖 | 判定依据 |")
            L.append("|---|---|---|---|---|")
            for n in vers:
                hits = "；".join(n.verify_hits[:3]) or "—"
                L.append(f"| `{n.name}` | {n.verify_cat} | {n.verify_score} | {n.fan_in} | {hits} |")
        else:
            L.append("未识别出校验类。常见原因：")
            L.append("")
            L.append("- 加固壳把真实 DEX 加密了，反编译出来的只是壳入口")
            L.append("- 校验在原生 so 里（看 `lib/` 下的 .so，跑 elf 分析）")
            L.append("- 校验完全在服务端，本地只留一个 HTTP 调用")
        L.append("")

        # ---- 调用链 ----
        L.append("## 调用链（从入口走到校验点）")
        L.append("")
        any_chain = False
        for n in vers:
            if n.is_entry and not n.chains:
                L.append(f"- **{n.name}**：本类即入口，系统直接启动它")
                any_chain = True
            for ch in n.chains[:2]:
                any_chain = True
                L.append(f"- **{n.name}**：" + " → ".join(f"`{x}`" for x in ch))
        if not any_chain:
            L.append("- 未还原出路径。静态调用图连不上反射、接口回调、"
                     "以及由系统直接触发的生命周期，这些要靠动态调试补。")
        L.append("")

        # ---- 核心依赖（结构枢纽）----
        L.append("## 核心依赖（改动风险最高的类）")
        L.append("")
        L.append("| 类 | 被依赖 | 依赖他人 | 说明 |")
        L.append("|---|---|---|---|")
        seen: set[str] = set()
        for n in core + hubs:
            if n.name in seen:
                continue
            seen.add(n.name)
            why = n.verify_cat or ("入口类" if n.is_entry else "结构枢纽")
            L.append(f"| `{n.name}` | {n.fan_in} | {n.fan_out} | {why} |")
        L.append("")

        # ---- 边界 ----
        L.append("## 判定依据与边界")
        L.append("")
        L.append(f"「核心」= 校验特征分 ≥ {NodeStat.CORE_SCORE}，"
                 f"或被 {NodeStat.CORE_FANIN} 个以上的类依赖。")
        L.append("")
        L.append("校验特征来自三处：类名/方法名/字段名命中关键词、"
                 "代码型字面量（URL、标识、路径）、摘要与加解密 API。")
        L.append("")
        L.append("这是**静态推断**，三类情况必漏：")
        L.append("")
        L.append("1. R8 混淆后名字变成 a/b/c，命名信号归零，只剩 API 与字面量")
        L.append("2. 加固壳把真实逻辑藏在加密 DEX 或 so 里，调用图会断")
        L.append("3. 反射、接口回调、系统生命周期回调，静态分析连不上边")
        L.append("")
        L.append("命中的点要用动态调试复核（hook 住返回值为 true/false 的那个方法），"
                 "才算坐实。")
        return "\n".join(L)

        L.append("| 类 | 判定 | 类别 | 被引用 | 依据 |")
        L.append("|---|---|---|---|---|")
        for n in core:
            hits = "；".join(n.verify_hits[:3]) or "入度高"
            L.append(f"| `{n.name}` | {n.criticality} | {n.verify_cat or '—'} | {n.fan_in} | {hits} |")
        L.append("")
        L.append("### 调用链（从入口到校验点）")
        L.append("")
        any_chain = False
        for n in core:
            for ch in n.chains:
                any_chain = True
                L.append(f"- **{n.name}**：`" + "` → `".join(ch) + "`")
        if not any_chain:
            L.append("- 未还原出完整路径（入口类可能不在本次反编译范围内，"
                     "或调用经过反射/接口回调，静态分析连不上）")
        L.append("")
        L.append("### 判定依据说明")
        L.append("")
        L.append("「核心」= 语义特征（命名/字面量/API 命中校验关键词）"
                 "或 入度 ≥ 4（被 4 个以上的类依赖）。")
        L.append("这是**静态推断**：R8 混淆会抹掉命名语义，加固壳会让图断裂，"
                 "两种情况都会漏判。命中结果要用动态调试复核。")
        return "\n".join(L)


# ---------------------------------------------------------------------------
# 建图
# ---------------------------------------------------------------------------

def _resolve_receiver(recv: str, cls: ClassNote, m: MethodNote,
                      index: dict[str, ClassNote]) -> str | None:
    """
    把一个调用的接收者还原成类名。推不出来就返回 None（不猜）。
    """
    if recv in ("this", ""):
        return cls.name
    if recv == "super":
        return cls.supers[0] if cls.supers else None

    t = m.local_types.get(recv) or cls.fields.get(recv)
    if t:
        return t if t in index else None

    # 首字母大写 → 当作类名（静态调用 Xxx.method()）
    if recv[:1].isupper():
        return recv if recv in index else None
    return None


_score_verify = verify.score_class


def build_from_notes(notes: dict[str, ClassNote]) -> DepGraph:
    """
    用已解析好的 ClassNote 建图（避免二次读盘/二次解析）。

    notes 的键是类名，值里带 file 字段。
    """
    g = DepGraph(notes=notes, files_scanned=len(notes))

    # 同名类冲突：跨包同名很常见（a.a.a），只保留第一个并记账
    seen: dict[str, ClassNote] = {}
    for name, c in notes.items():
        if name in seen:
            g.dup_names.append(name)
            continue
        seen[name] = c

    # 节点
    for name, c in seen.items():
        g.nodes[name] = NodeStat(name=name, file=c.file, pkg=c.pkg)

    # 入口标记
    for name, c in seen.items():
        if any(s in ENTRY_BASES for s in c.supers):
            g.nodes[name].is_entry = True

    # 边：调用 + 字段类型
    for name, c in seen.items():
        for m in c.methods:
            for recv, meth in m.recv_calls:
                tgt = _resolve_receiver(recv, c, m, seen)
                if tgt and tgt in seen:
                    if tgt == name and meth == m.name:
                        continue        # 递归自己，不算依赖
                    g.edges.append(Edge(name, m.name, tgt, meth))
        # 字段类型依赖（弱边）：xxManager.xxx() 的来源
        for fname, ftype in c.fields.items():
            if ftype in seen and ftype != name:
                g.edges.append(Edge(name, "", ftype, "", "field"))

    # 统计入度/出度
    callers: dict[str, set[str]] = defaultdict(set)
    callees: dict[str, set[str]] = defaultdict(set)
    for e in g.edges:
        if e.caller != e.callee:
            callers[e.callee].add(e.caller)
            callees[e.caller].add(e.callee)
    for name, n in g.nodes.items():
        n.callers = sorted(callers.get(name, ()))
        n.callees = sorted(callees.get(name, ()))
        n.fan_in = len(n.callers)
        n.fan_out = len(n.callees)

    # 校验语义打分
    for name, c in seen.items():
        cat, score, hits = _score_verify(c)
        n = g.nodes[name]
        n.verify_cat, n.verify_score, n.verify_hits = cat, min(score, 100), hits

    # 从入口正向 BFS，标记可达性 + 记录到核心点的最短链
    _mark_reachable_and_chains(g)
    return g


def _mark_reachable_and_chains(g: DepGraph) -> None:
    """
    从所有入口类出发做 BFS：
      · 标记哪些类是可从外部触达的（可达性）
      · 给每个校验点找一条从入口过来的最短路径（渲染成"谁调了谁"）
    """
    adj: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
    for e in g.edges:
        if e.caller == e.callee:
            continue
        adj[e.caller].append((e.callee, e.caller_method, e.callee_method))

    entries = [n.name for n in g.nodes.values() if n.is_entry]
    # 没有入口类（比如只是个库）就拿入度为 0 的类当起点
    if not entries:
        entries = [n.name for n in g.nodes.values() if n.fan_in == 0][:8]

    for ep in entries:
        prev: dict[str, str] = {}
        # 每个节点"被谁用什么方法调进来"+"它自己哪个方法发起了下一跳"
        # 只存 prev 会丢掉终点，链就会停在调用者身上（读起来像"校验发生在别人家里"）
        frame_in: dict[str, str] = {}
        frame_out: dict[str, str] = {}
        depth = {ep: 0}
        dq = deque([ep])
        while dq:
            cur = dq.popleft()
            if depth[cur] >= MAX_CHAIN:
                continue
            for nxt, cm, nm in adj.get(cur, ()):
                if nxt in depth:
                    continue
                depth[nxt] = depth[cur] + 1
                prev[nxt] = cur
                frame_in[nxt] = nm      # 被调进来的那个方法（在 nxt 里）
                frame_out[cur] = cm     # 发起调用的方法（在 cur 里）
                dq.append(nxt)

        for name in depth:
            g.nodes[name].reachable_from_entry = True

        # 给可达的校验点补一条链（每个点最多 MAX_CHAINS 条，来自不同入口）
        for name, n in g.nodes.items():
            if not n.is_verify or name not in prev:
                continue
            if len(n.chains) >= MAX_CHAINS:
                continue
            frames: list[str] = []
            cur = name
            guard = 0
            while True:
                meth = frame_out.get(cur) if cur != name else frame_in.get(name, "")
                frames.append(f"{cur}.{meth}()" if meth else cur)
                if cur not in prev or guard >= MAX_CHAIN:
                    break
                cur = prev[cur]
                guard += 1
            frames.reverse()
            if frames not in n.chains:
                n.chains.append(frames)


def _entry_method(g: DepGraph, ep: str) -> str:
    """入口类里挑一个最有代表性的方法：生命周期优先，其次公开方法。"""
    c = g.notes.get(ep)
    if not c:
        return "…"
    for want in ("onCreate", "onStartCommand", "onReceive", "attachBaseContext", "onAttach"):
        if c.method_by_name(want):
            return want
    for m in c.methods:
        if "public" in m.mods:
            return m.name
    return c.methods[0].name if c.methods else "…"


def build(src_root: str | Path,
          skip_dirs: tuple[str, ...] = ("android", "androidx", "kotlin", "kotlinx",
                                        "java", "javax")) -> DepGraph:
    """从源码目录建图。"""
    src = Path(src_root)
    notes: dict[str, ClassNote] = {}
    if not src.exists():
        return DepGraph()

    files = sorted(src.rglob("*.java"))[:MAX_GRAPH_FILES]
    from .annotate import is_library_path

    skip = set(skip_dirs)
    for f in files:
        rel = f.relative_to(src)
        if (rel.parts and rel.parts[0] in skip) or is_library_path(rel):
            continue
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
            c = parse_source(text)
        except Exception:
            continue
        if not c:
            continue
        c.file = str(rel)
        if c.name in notes:
            continue
        notes[c.name] = c

    return build_from_notes(notes)


def chains_text(g: DepGraph, cls: str) -> str:
    """给注释器用：把某类的调用链渲染成一行。"""
    n = g.stat(cls)
    if not n or not n.chains:
        return ""
    return " → ".join(n.chains[0])
