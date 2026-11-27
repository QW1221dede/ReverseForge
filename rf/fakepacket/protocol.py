#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""协议判定：把线索链翻译成「发哪里、发什么、什么时候发、怎么算成功」。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .clues import ClueChain


@dataclass
class Proto:
    name: str
    score: int
    confidence: int          # 0-100
    endpoint: str = ""
    method: str = "POST"
    fields: dict[str, str] = field(default_factory=dict)
    timing: str = ""
    success_rule: str = ""
    note: str = ""
    evidence: list[str] = field(default_factory=list)

    def row(self) -> str:
        return (f"{self.score:>3}  {self.name:<26} 置信{self.confidence:>3}%  "
                f"{self.endpoint[:42]:<42} {self.timing}")

    def detail(self) -> str:
        lines = [f"【{self.name}】置信 {self.confidence}%　得分 {self.score}"]
        if self.endpoint:
            lines.append(f"  发到：{self.method} {self.endpoint}")
        if self.fields:
            lines.append("  带字段：" + "、".join(f"{k}={v}" for k, v in self.fields.items()))
        if self.timing:
            lines.append(f"  什么时候发：{self.timing}")
        if self.success_rule:
            lines.append(f"  怎么算成功：{self.success_rule}")
        if self.note:
            lines.append(f"  说明：{self.note}")
        if self.evidence:
            lines.append("  证据：" + "；".join(self.evidence[:6]))
        return "\n".join(lines)


def _first(chain: "ClueChain", kind: str) -> str:
    cs = chain.of(kind)
    return cs[0].text if cs else ""


def _fields(chain: "ClueChain") -> dict[str, str]:
    """协议字段去重 + 小写归一；大小写变体（Success/success）只留一个。"""
    out: dict[str, str] = {}
    for c in chain.clues:
        if c.kind not in ("card_field", "status_field", "sign_field",
                          "device", "param", "secret"):
            continue
        t = c.text.strip()
        if not t.isidentifier() or len(t) > 24 or "_" not in t and not t.islower():
            # 全大写或含非标识字符的（Success/Code=）跳过，保留小写规范名
            if t != t.lower() or not t.isidentifier():
                continue
        k = t.lower()
        label = ("伪造" if c.kind not in ("status_field",) else "成功码")
        out.setdefault(k, label)
    return out


def _card_path(chain: "ClueChain") -> str:
    """本地卡密路径优先：名字里带 card/key/license 的才是，别选 netns。"""
    for c in chain.of("card_path"):
        if any(w in c.text.lower() for w in ("card", "key", "license", "cdkey")):
            return c.text
    return _first(chain, "card_path")


def _endpoints(chain: "ClueChain") -> list[str]:
    return [c.text.rstrip("/") for c in chain.of("endpoint")]


def _contain(chain: "ClueChain", kind: str, word: str) -> bool:
    return any(word in c.text.lower() or word in c.note.lower()
               for c in chain.of(kind))


# ---------------------------------------------------------------------------
# 协议识别器：每个返回 Proto | None。得分 = 命中证据的权重和。
# ---------------------------------------------------------------------------

def _t3_card(chain: "ClueChain") -> Proto | None:
    """T3 卡密验证：POST kami + timestampsign → statecode，启动验 + 心跳。"""
    if not chain.has("card_field") or not chain.has("status_field"):
        return None
    eps = [e for e in _endpoints(chain)
           if "t3yanzheng" in e or "t3data" in e]
    if not eps and not _contain(chain, "vendor", "t3"):
        return None
    score = 0
    ev: list[str] = []
    for c in chain.clues:
        if c.kind in ("endpoint", "card_field", "status_field", "sign_field",
                      "card_path", "heartbeat", "device", "vendor", "secret"):
            score += c.weight
            if len(ev) < 8:
                ev.append(f"{c.kind}={c.text[:36]}")
    fields = _fields(chain)
    timing = "① 启动时「正在验证卡密」发一次；② 运行中按 heartbeat/lease 周期发心跳"
    if chain.has("card_path"):
        timing += "；③ 本地有缓存时先读卡密再发"
    return Proto(
        name="T3 卡密验证（远程鉴权 + 心跳）",
        score=score,
        confidence=min(95, 45 + score // 2),
        endpoint=(next((e for e in eps if "t3yanzheng.com" in e and "/w" not in e),
                       next((e for e in eps if "t3yanzheng.com" in e),
                            eps[0] if eps else ""))),
        fields=fields,
        timing=timing,
        success_rule="响应 statecode 为成功码（如 200/0/1）且 msg 无「过期/失效/设备不匹配」",
        note="服务器真发卡给客户端时，光改客户端没用 —— 必须发假包骗它判成功；"
             "纯本地判定的包则伪造响应即可。",
        evidence=ev,
    )


def _local_cache(chain: "ClueChain") -> Proto | None:
    """本地缓存判定：卡密写在本地文件，改文件/缓存即过。"""
    if not chain.has("card_path"):
        return None
    score = sum(c.weight for c in chain.clues
                if c.kind in ("card_path", "success", "failure", "secret"))
    ev = [c.text for c in chain.of("card_path")[:4]]
    return Proto(
        name="本地卡密缓存（离线判定）",
        score=score,
        confidence=min(90, 40 + score),
        endpoint="（不发网络，改本地文件）",
        fields={"卡密文件": _card_path(chain)},
        timing="启动读取本地卡密文件时",
        success_rule=f"出现「{_first(chain, 'success') or '验证成功'}」",
        note="这类不需要发假包：直接改缓存或让读文件分支恒真。",
        evidence=ev,
    )


def _generic_http(chain: "ClueChain") -> Proto | None:
    """通用 HTTP 校验：有 URL + 状态码/成功标志，但认不出厂商。"""
    eps = _endpoints(chain)
    if not eps or not (chain.has("status_field") or chain.has("success")):
        return None
    score = sum(c.weight for c in chain.clues
                if c.kind in ("endpoint", "status_field", "sign_field",
                              "success", "failure", "param"))
    return Proto(
        name="通用 HTTP 鉴权",
        score=score,
        confidence=min(80, 35 + score // 2),
        endpoint=eps[0],
        fields={k: v for k, v in _fields(chain).items()
                if k in ("kami", "card", "statecode", "code", "status", "sign")},
        timing="发出鉴权请求时",
        success_rule=f"状态码 200 且响应含「{_first(chain, 'success') or '成功'}」",
        note="字段靠线索猜，先用假包试探服务器响应再定。",
        evidence=[e for e in eps[:4]],
    )


PROTOCOLS = [_t3_card, _local_cache, _generic_http]


def infer(chain: "ClueChain") -> list[Proto]:
    """按得分降序返回所有判定结果，跟解密的 hits 一样。"""
    out: list[Proto] = []
    for fn in PROTOCOLS:
        try:
            p = fn(chain)
        except Exception:                                    # noqa: BLE001
            p = None
        if p and p.score > 0:
            out.append(p)
    out.sort(key=lambda p: -p.score)
    return out
