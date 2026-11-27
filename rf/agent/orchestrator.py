#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 rf.agent.orchestrator · 指令 → 计划 → 实际调用工具
============================================================================

【它解决什么】
    用户说一句话："这几个文件看看是什么，能解密就解开，脚本里的卡密找出来"。
    工具不该要求人先选脚本、再填参数、再点开始 —— 应该直接干活。

    这一层做三件事：
      1. 听懂意图（规则引擎，离线可用；配了 LLM 端点则交给模型规划）
      2. 把意图翻成**步骤序列**（哪一步用哪个工具、参数是什么）
      3. 按顺序真跑，边跑边出中文结果，最后汇总

【为什么默认用规则而不是 LLM】
    · 这句话的意图空间很小：识别 / 分段 / 解密 / 找校验 / 注释 / 打补丁
    · 规则引擎 0 延迟、不花钱、断网可用、结果可复现
    · LLM 只在"任务描述很绕"时才明显更强，而我们这里大多是直白指令
    所以：**规则优先，LLM 可选**。配置了 llm.base_url + api_key 才走模型，
    走不通自动退回规则，并在结果里写明"这次用的是规则引擎"，不装神弄鬼。

【配置 LLM 的方式】
    %LOCALAPPDATA%\\ReverseForge\\settings.json:
        {"llm": {"base_url": "https://api.xxx.com/v1", "api_key": "sk-...",
                 "model": "gpt-4o-mini"}}
    兼容 OpenAI /chat/completions 协议（含 function calling）。
============================================================================
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .. import config

# ---------------------------------------------------------------------------
# 意图
# ---------------------------------------------------------------------------

I_DECRYPT = "decrypt"
I_IDENTIFY = "identify"
I_AUTH = "auth"
I_ANNOTATE = "annotate"
I_APK = "apk"
I_PATCH = "patch"
I_REPORT = "report"
I_FULL = "full"

I_CN = {
    I_DECRYPT: "解密与分段",
    I_IDENTIFY: "识别类型",
    I_AUTH: "找密码/卡密校验",
    I_ANNOTATE: "中文注释",
    I_APK: "APK 分析",
    I_PATCH: "打补丁",
    I_REPORT: "出报告",
    I_FULL: "全流程分析",
}

# (关键词, 意图, 权重) —— 权重高的优先
_HINTS: list[tuple[tuple[str, ...], str, int]] = [
    (("解密", "解开", "密文", "加密的", "还原明文", "decrypt", "破译"), I_DECRYPT, 40),
    (("卡密", "密码", "注册码", "授权", "校验", "激活", "license", "password",
      "crack", "绕过"), I_AUTH, 38),
    (("注释", "中文注释", "annotate", "看懂代码", "讲解代码"), I_ANNOTATE, 36),
    (("补丁", "patch", "改掉", "修改判断", "强制返回"), I_PATCH, 34),
    (("apk", "安卓", "smali", "dex", "重打包", "反编译"), I_APK, 30),
    (("报告", "汇总", "总结", "report"), I_REPORT, 22),
    (("是什么", "类型", "识别", "格式", "identify", "什么文件"), I_IDENTIFY, 26),
    (("分析", "看看", "检查", "处理一下", "全流程", "analyze"), I_FULL, 12),
]


def guess_intent(task: str) -> tuple[str, list[str]]:
    """
    从一句话里判意图。返回 (意图, 命中的关键词)。
    多意图并存时取权重最高的；"分析"这种泛词只在没别的命中时才用。
    """
    t = (task or "").lower()
    best, best_w, hits = I_FULL, -1, []

    # 多个强意图并存（"卡密验证 + 解密"）→ 走全流程，不能只挑权重最高的那个。
    # 用户丢外挂时说的就是"看看有没有卡密，有就解开"，只走 decrypt 会漏掉校验点。
    strong = {intent for words, intent, w in _HINTS if w >= 30
              for x in words if x.lower() in t}
    if len(strong) >= 2:
        return I_FULL, [x for words, intent, w in _HINTS if intent in strong
                        for x in words if x.lower() in t][:6]

    for words, intent, w in _HINTS:
        got = [x for x in words if x.lower() in t]
        if got and w > best_w:
            best, best_w, hits = intent, w, got
        elif got:
            hits.extend(got)
    if not t.strip():
        return I_FULL, []
    return best, hits


# ---------------------------------------------------------------------------
# 计划
# ---------------------------------------------------------------------------

@dataclass
class Step:
    tool: str
    args: dict = field(default_factory=dict)
    why: str = ""
    per_file: bool = True       # True: 每个目标各跑一次；False: 只跑一次

    @property
    def name(self) -> str:
        return self.tool


@dataclass
class Plan:
    task: str = ""
    intent: str = I_FULL
    hits: list[str] = field(default_factory=list)
    steps: list[Step] = field(default_factory=list)
    engine: str = "规则"
    notes: list[str] = field(default_factory=list)

    @property
    def intent_cn(self) -> str:
        return I_CN.get(self.intent, self.intent)

    def describe(self) -> str:
        L = [f"【意图】{self.intent_cn}"
             + (f"（关键词：{'、'.join(self.hits[:4])}）" if self.hits else ""),
             f"【规划】{self.engine}引擎 · {len(self.steps)} 个步骤"]
        for i, s in enumerate(self.steps, 1):
            L.append(f"  {i}. {s.tool:<14} {s.why}")
        for n in self.notes:
            L.append(f"  · {n}")
        return "\n".join(L)


@dataclass
class RunOut:
    ok: bool = True
    text: str = ""
    items: list[dict] = field(default_factory=list)
    elapsed: float = 0.0
    errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# 规则规划
# ---------------------------------------------------------------------------

def plan(task: str, targets: list[str]) -> Plan:
    """把一句话 + 目标列表，翻成步骤序列。"""
    intent, hits = guess_intent(task)
    p = Plan(task=task, intent=intent, hits=hits)
    need_seg = intent in (I_DECRYPT, I_FULL, I_IDENTIFY)

    p.steps.append(Step("file_type", {"path": "{file}"},
                        "先认类型：决定后面用哪套分析器", per_file=True))
    if need_seg:
        p.steps.append(Step("segments", {"target": "{file}"},
                            "分段：找明文头/密文分界，顺手捞密钥", per_file=True))
    if intent in (I_DECRYPT, I_FULL):
        p.steps.append(Step("decrypt_auto", {"target": "{file}"},
                            "自动试解（编码/压缩/XOR/RC4/AES/TEA/OpenSSL）",
                            per_file=True))
    if intent in (I_AUTH, I_FULL, I_PATCH):
        p.steps.append(Step("auth_scan", {"target": "{file}"},
                            "找密码/卡密/授权校验点（脚本按行、二进制按偏移）",
                            per_file=True))
    if intent == I_ANNOTATE:
        p.steps.append(Step("annotate", {"src": "{file}"},
                            "给源码加中文注释", per_file=True))
    if intent == I_APK:
        p.steps.append(Step("apk_info", {"path": "{file}"}, "APK 画像", per_file=True))
        p.steps.append(Step("patch_scan", {"target": "{file}"},
                            "扫启动前校验点", per_file=True))
    if intent == I_PATCH:
        p.steps.append(Step("patch_scan", {"target": "{file}"},
                            "先生成补丁方案（不落盘）", per_file=True))

    if not targets:
        p.notes.append("没有目标文件，只做规划")
    if intent == I_FULL:
        p.notes.append("任务描述较宽泛 → 按全流程走")
    return p


# ---------------------------------------------------------------------------
# LLM 规划（可选）
# ---------------------------------------------------------------------------

def _llm_config() -> dict:
    try:
        raw = config.CONFIG_FILE.read_text(encoding="utf-8")
        data = json.loads(raw)
        llm = data.get("llm") or {}
        if llm.get("base_url") and llm.get("api_key") and llm.get("model"):
            return llm
    except (OSError, ValueError):
        pass
    return {}


def llm_ready() -> bool:
    return bool(_llm_config())


def llm_plan(task: str, targets: list[str], timeout: float = 30.0) -> Plan | None:
    """
    用 OpenAI 兼容端点做 function calling 规划。
    没有配置 / 网络失败 / 返回不合法 → 返回 None，上层退回规则引擎。
    """
    cfg = _llm_config()
    if not cfg:
        return None
    try:
        from ..server.api_server import tool_schema
        tools = tool_schema()
    except Exception:                                # noqa: BLE001
        return None

    sys_prompt = (
        "你是逆向分析助手的规划器。根据用户任务和文件列表，选择要调用的工具。"
        "只选真正需要的；不要输出解释文字，直接调用工具。"
        f"可用的文件：{targets[:20]}"
    )
    payload = {
        "model": cfg["model"],
        "messages": [{"role": "system", "content": sys_prompt},
                     {"role": "user", "content": task}],
        "tools": [{"type": "function", "function": t} for t in tools],
        "tool_choice": "auto",
        "temperature": 0,
    }
    url = cfg["base_url"].rstrip("/") + "/chat/completions"
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {cfg['api_key']}"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8"))
    except (urllib.error.URLError, ValueError, OSError):
        return None

    try:
        calls = data["choices"][0]["message"].get("tool_calls") or []
    except (KeyError, IndexError, TypeError):
        return None

    p = Plan(task=task, intent=I_FULL, engine="LLM")
    for c in calls:
        fn = c.get("function") or {}
        name = fn.get("name") or ""
        try:
            args = json.loads(fn.get("arguments") or "{}")
        except ValueError:
            args = {}
        if name:
            p.steps.append(Step(name, args, "模型选择", per_file=False))
    if not p.steps:
        return None
    p.notes.append("本计划由 LLM 生成；参数按原始 JSON 执行")
    return p


def make_plan(task: str, targets: list[str], use_llm: bool = True) -> Plan:
    """对外入口：优先 LLM（若可用），否则规则。"""
    if use_llm and llm_ready():
        got = llm_plan(task, targets)
        if got:
            return got
        p = plan(task, targets)
        p.notes.append("LLM 规划失败或返回空，已退回规则引擎")
        return p
    return plan(task, targets)


# ---------------------------------------------------------------------------
# 执行
# ---------------------------------------------------------------------------

def _fmt_result(name: str, res: Any) -> list[str]:
    """把一个工具的结果压成人能读的几行。"""
    L: list[str] = []
    if res is None:
        return L
    if name == "file_type":
        L.append(f"   类型：{getattr(res, 'label', '?')} · {getattr(res, 'cat_cn', '')}"
                 f" · 熵 {getattr(res, 'entropy', 0):.2f}"
                 f" · 可信 {getattr(res, 'confidence', 0)}%")
        for n in (getattr(res, "notes", None) or [])[:2]:
            L.append(f"   说明：{n}")
    elif name == "segments":
        L.append(f"   分段：{res.brief()}")
        sp = getattr(res, "split", None)
        if sp is not None and getattr(sp, "found", False):
            L.append(f"   明暗分界：明文 {sp.head_len}B + 密文 {sp.tail_len}B"
                     f"（可信 {sp.confidence}%）")
            if getattr(sp, "head_keys", None):
                L.append(f"   头部密钥：{'、'.join(sp.head_keys[:4])}")
    elif name == "decrypt_auto":
        if getattr(res, "hits", None):
            best = res.hits[0]
            L.append(f"   解密：{best.method}（得分 {best.score}，"
                     f"偏移 {best.offset}）")
            L.append(f"   预览：{best.preview[:60]}")
        else:
            L.append("   解密：未命中（密钥可能不在本机，需从程序里找解密函数）")
    elif name == "auth_scan":
        L.append(f"   校验点：{res.summary()}")
        for pt in (getattr(res, "pre_run", None) or [])[:4]:
            L.append(f"   · {pt.loc} {pt.kind_cn} {pt.confidence}%  {pt.code.strip()[:40]}")
    elif name == "patch_scan":
        L.append(f"   smali 校验点：{res.summary()}")
    elif name == "annotate":
        L.append(f"   注释：{res}" if not hasattr(res, "total") else
                 f"   注释：{getattr(res, 'total', '')} 处")
    elif name == "strings":
        n = len(getattr(res, "items", []) or [])
        L.append(f"   字符串：{n} 条")
    else:
        s = str(res)
        L.append("   " + (s[:160] if s else "（无输出）"))
    return L


def run(plan_: Plan, targets: list[str],
        on_event: Callable[[str], None] | None = None) -> RunOut:
    """
    按计划执行。on_event 用来把进度实时推给界面。
    每个步骤的异常都被单独捕获 —— 一步失败不影响后面几步。
    """
    from ..api import make_api

    t0 = time.time()
    api = make_api()
    out = RunOut()
    logs: list[str] = []

    def emit(s: str) -> None:
        logs.append(s)
        if on_event:
            try:
                on_event(s)
            except Exception:                        # noqa: BLE001
                pass

    emit(f"【意图】{plan_.intent_cn}　【引擎】{plan_.engine}")
    emit(f"【目标】{len(targets)} 个")

    for idx, target in enumerate(targets[:40], 1):
        p = Path(target)
        emit(f"\n── {idx}/{min(len(targets), 40)}　{p.name or p}")
        ctx = {"file": str(p), "parent": str(p.parent if p.is_file() else p)}
        for step in plan_.steps:
            if not step.per_file and idx > 1:
                continue
            args = {}
            for k, v in step.args.items():
                args[k] = v.format(**ctx) if isinstance(v, str) else v
            fn = getattr(api, step.tool, None)
            if fn is None:
                emit(f"   [{step.tool}] 未实现，跳过")
                out.errors.append(f"{step.tool}: 未实现")
                continue
            try:
                res = fn(**args)
                lines = _fmt_result(step.tool, res)
                for ln in lines:
                    emit(ln)
                out.items.append({"file": str(p), "tool": step.tool,
                                  "ok": True, "result": _safe(res)})
            except Exception as e:                   # noqa: BLE001
                msg = f"{type(e).__name__}: {e}"
                emit(f"   [{step.tool}] 失败：{msg}")
                out.errors.append(f"{p.name}/{step.tool}: {msg}")
                out.items.append({"file": str(p), "tool": step.tool,
                                  "ok": False, "error": msg})

    out.elapsed = time.time() - t0
    out.ok = not out.errors
    emit(f"\n【完成】{len(out.items)} 个步骤，{out.elapsed:.1f}s"
         + (f"，{len(out.errors)} 处失败" if out.errors else "，全部成功"))
    out.text = "\n".join(logs)
    return out


def _safe(res: Any) -> Any:
    """结果压成 JSON 安全的形状（给 API 和界面复用）。"""
    if res is None or isinstance(res, (bool, int, float, str)):
        return res
    for attr in ("to_dict", "brief"):
        fn = getattr(res, attr, None)
        if callable(fn):
            try:
                v = fn()
                if isinstance(v, (str, dict, list, int, float, bool)):
                    return v
            except Exception:                        # noqa: BLE001
                pass
    if isinstance(res, (list, tuple)):
        return [_safe(x) for x in res[:50]]
    return str(res)[:400]


# ---------------------------------------------------------------------------
# 命令行：一条指令直接跑
# ---------------------------------------------------------------------------

def main() -> int:
    import sys
    argv = sys.argv[1:]
    if not argv:
        print("用法：python -m rf.agent.orchestrator \"任务描述\" 文件1 [文件2 ...]")
        return 2
    task, targets = argv[0], argv[1:]
    p = make_plan(task, targets)
    print(p.describe())
    out = run(p, targets, on_event=print)
    return 0 if out.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
