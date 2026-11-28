#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 rf.secure.gate_shield · 授权服务器防护层（2026-11-28）
============================================================================

隧道一开公网，服务就会被扫描器/爆破党盯上。本模块做七层防护：

  1. 客户端 IP 提取（优先 CF-Connecting-IP，隧道场景）
  2. 速率限制：滑动窗口，默认 6 次/分钟/IP
  3. 坏请求累计封禁：连续 8 次坏请求 → 封 1 小时（内存，重启清空）
  4. 请求体长度硬限 8KB；超限直接 413，不读不解析
  5. UA 校验：必须是 ReverseForge-Gate/2
  6. nonce 去重：同一申请码不重复触发人工审批
  7. 审计日志：所有请求（含拒绝/封禁）写 logs/gate_shield.jsonl

设计原则：**任何异常都往"拒绝"方向走，不降级、不放行。**
"""
from __future__ import annotations

import json
import threading
import time
from collections import defaultdict, deque
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
AUDIT = ROOT / "logs" / "gate_shield.jsonl"

MAX_BODY = 8 * 1024
RATE_LIMIT = 6                    # 每 IP 每分钟最多 6 次
RATE_WINDOW = 60.0
BAD_LIMIT = 8                     # 连续坏请求上限
BAN_SECONDS = 3600
EXPECTED_UA = "ReverseForge-Gate/2"

_LOCK = threading.Lock()
_HITS: dict[str, deque] = defaultdict(deque)
_BAD: dict[str, int] = defaultdict(int)
_BANS: dict[str, float] = {}
_SEEN: dict[str, float] = {}


def client_ip(headers, remote: str = "") -> str:
    """隧道场景优先 CF-Connecting-IP；否则 X-Forwarded-For；最后 remote。"""
    for k in ("CF-Connecting-IP", "X-Forwarded-For", "X-Real-IP"):
        v = headers.get(k) or ""
        if v:
            return v.split(",")[0].strip()[:64]
    return (remote or headers.get("X-Remote-Addr") or "unknown").strip()[:64]


def _audit(ip: str, action: str, detail: str = "") -> None:
    try:
        AUDIT.parent.mkdir(parents=True, exist_ok=True)
        rec = {"ts": time.strftime("%Y-%m-%d %H:%M:%S"),
               "ip": ip, "action": action, "detail": detail[:200]}
        with open(AUDIT, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        pass


def check(ip: str, ua: str, content_length: int, nonce: str = "", *,
          method: str = "POST") -> tuple[int, str]:
    """返回 (HTTP 状态码, 原因)；200 表示通过。"""
    now = time.time()
    with _LOCK:
        # 封禁检查
        until = _BANS.get(ip, 0)
        if until > now:
            _audit(ip, "blocked", f"封禁剩余 {int(until-now)}s")
            return 429, "请求过于频繁，请稍后再试"
        if until and until <= now:
            _BANS.pop(ip, None)
            _BAD[ip] = 0

        # UA
        if EXPECTED_UA not in (ua or ""):
            _BAD[ip] += 1
            _audit(ip, "bad_ua", ua[:80])
            if _BAD[ip] >= BAD_LIMIT:
                _BANS[ip] = now + BAN_SECONDS
            return 403, "客户端不被允许"

        # 体长：GET/HEAD 没有 body 属正常；只有 POST 才要求非空
        if content_length > MAX_BODY or (method == "POST" and content_length < 1):
            _BAD[ip] += 1
            _audit(ip, "bad_size", str(content_length))
            return 413, "请求体过大" if content_length > MAX_BODY else "请求体为空"

        # 速率（滑动窗口）
        q = _HITS[ip]
        while q and q[0] < now - RATE_WINDOW:
            q.popleft()
        if len(q) >= RATE_LIMIT:
            _audit(ip, "rate_limit", f"窗口内 {len(q)} 次")
            return 429, "申请太频繁，请 1 分钟后再试"
        q.append(now)

        # nonce 去重
        if nonce:
            t = _SEEN.get(nonce, 0)
            if t and now - t < 3600:
                _audit(ip, "duplicate", nonce[:16])
                return 409, "该申请码已处理过，请勿重复提交"
            # 清理过期
            for k in [k for k, v in _SEEN.items() if now - v > 3600][:200]:
                _SEEN.pop(k, None)
            _SEEN[nonce] = now

    return 200, "ok"


def mark_bad(ip: str, detail: str = "") -> None:
    with _LOCK:
        _BAD[ip] += 1
        if _BAD[ip] >= BAD_LIMIT:
            _BANS[ip] = time.time() + BAN_SECONDS
    _audit(ip, "bad_request", detail)


def mark_ok(ip: str, detail: str = "") -> None:
    with _LOCK:
        _BAD[ip] = 0
    _audit(ip, "ok", detail)


def stats() -> dict:
    with _LOCK:
        now = time.time()
        return {
            "banned_ips": sum(1 for v in _BANS.values() if v > now),
            "tracked_ips": len(_HITS),
            "seen_nonces": len(_SEEN),
            "audit_file": str(AUDIT),
        }
