#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 tools/gate_server.py · 作者端授权校验服务器（只在你这台电脑跑）
============================================================================

【用法】
    python tools/gate_server.py --init          # 首次：生成 RSA-4096 密钥对
    python tools/gate_server.py --seal          # 发布前：把三个能力模块封成密文
    python tools/gate_server.py --port 8787     # 启动校验服务（配隧道）

【审阅流程】
    使用者发来的申请会在终端打印：能力、机器指纹、用途声明（中文）、时间。
    你人工判断后：
      y  批准 → 签发短期回签（默认 7 天）→ 回复给使用者 → 记入 logs/gate_decisions.jsonl
      n  拒绝 → 回复拒绝原因 → 同样记入日志（这是"拒绝记录留痕"的证据）
    **没有任何自动批准路径**。必须人在终端按键。

【安全】
    · 只监听 127.0.0.1，公网入口由你的 cloudflared 隧道提供
    · 私钥 gate_private.pem 只在这台机器，绝不随发布包分发
    · 每条决定写审计日志（含申请码、决定、理由、时间），用于证明逐例审阅
============================================================================
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from rf.secure import gate                                          # noqa: E402
from rf.secure import gate_shield                                    # noqa: E402
from rf import config                                               # noqa: E402

LOG_DIR = ROOT / "logs"
DECISION_LOG = LOG_DIR / "gate_decisions.jsonl"
MOD_SRC = ROOT / "tools" / "gated_src"
MOD_OUT = ROOT / "rf" / "secure" / gate.MOD_DIR_NAME


def log_decision(entry: dict) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    entry["ts"] = datetime.now().isoformat(timespec="seconds")
    with open(DECISION_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def seal_modules(fp: str) -> list[str]:
    """发布前：把源码模块封成多层密文（绑定目标机器的指纹）。"""
    MOD_OUT.mkdir(parents=True, exist_ok=True)
    out = []
    for cap in gate.CAPABILITIES:
        src = MOD_SRC / f"{cap.lower()}.py"
        if not src.is_file():
            out.append(f"{cap}: 跳过（无源码 {src.name}）")
            continue
        sealed = gate.author_seal(cap, src.read_bytes(), fp)
        dst = MOD_OUT / f"{cap}.enc.json"
        dst.write_text(json.dumps(sealed, ensure_ascii=False), encoding="utf-8")
        out.append(f"{cap}: 已封 → {dst.name} ({dst.stat().st_size} B)")
    return out


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):                              # noqa: A002
        sys.stderr.write("[%s] %s\n" % (time.strftime("%H:%M:%S"), fmt % args))

    def _send(self, code: int, obj: dict) -> None:
        raw = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _shield(self) -> tuple[int, str]:
        """统一防护；返回 (状态码, 原因)，200 表示放行。"""
        ip = gate_shield.client_ip(dict(self.headers), self.client_address[0] if self.client_address else "")
        ua = self.headers.get("User-Agent") or ""
        n = int(self.headers.get("Content-Length") or 0)
        code, why = gate_shield.check(ip, ua, n, method=self.command)
        self._shield_ip = ip
        return code, why

    def _deny(self, code: int, why: str) -> None:
        self._send(code, {"ok": False, "reason": why})

    def do_GET(self):                                               # noqa: N802
        code, why = self._shield()
        if code != 200:
            return self._deny(code, why)
        # ping 只回最简信息，不给攻击者探版本
        if self.path == "/gate/ping":
            return self._send(200, {"ok": True})
        return self._send(404, {"ok": False, "error": "not found"})

    def do_POST(self):                                              # noqa: N802
        code, why = self._shield()
        if code != 200:
            return self._deny(code, why)
        if self.path != "/gate/authorize":
            return self._send(404, {"ok": False, "error": "not found"})
        n = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(n).decode("utf-8"))
            req = body.get("request") or ""
            d = gate.parse_request(req)
        except Exception as e:
            gate_shield.mark_bad(getattr(self, "_shield_ip", "?"), str(e)[:80])
            return self._send(400, {"ok": False, "reason": f"申请码无效：{e}"})
        # nonce 去重在 shield 里已按申请码整串做；这里再按 nonce 记一次
        gate_shield.mark_ok(getattr(self, "_shield_ip", "?"), d["cap"])

        cap = d["cap"]
        info = gate.CAPABILITIES[cap]
        # ---- 人工审阅：终端打印，必须按键 ----
        print("\n" + "=" * 64)
        print("【授权申请】收到时间：", datetime.now().isoformat(timespec="seconds"))
        print("  能力      :", cap, "—", info["name"])
        print("  法律依据  :", info["law"])
        print("  机器指纹  :", d.get("fp"))
        print("  客户端版本:", d.get("app"))
        print("  用途声明  :")
        print("    " + (d.get("purpose") or "(未填写)").replace("\n", "\n    "))
        print("  申请码    :", req[:80] + "…")
        print("=" * 64)
        try:
            import threading as _th
            box: dict = {}
            def _ask():
                try:
                    box["ans"] = input("批准？[y/N] ").strip().lower()
                except Exception:
                    box["ans"] = ""
            t = _th.Thread(target=_ask, daemon=True)
            t.start()
            t.join(25)                       # 25 秒不答 = 拒绝
            ans = box.get("ans", "")
            if not t.is_alive() is False and not ans:
                ans = ""
        except Exception:
            ans = ""
        if not ans:
            log_decision({"cap": cap, "fp": d.get("fp"),
                          "purpose": d.get("purpose"), "decision": "timeout",
                          "reason": "25 秒未审阅，自动拒绝"})
            return self._send(200, {"ok": False, "reason": "作者未在 25 秒内审阅，已自动拒绝"})
        if ans != "y":
            reason = input("拒绝理由（中文，可留空）: ").strip() or "未通过人工审阅"
            log_decision({"cap": cap, "fp": d.get("fp"),
                          "purpose": d.get("purpose"), "decision": "deny",
                          "reason": reason, "request": req})
            return self._send(200, {"ok": False, "reason": reason})

        days_raw = input("有效期天数（默认 7，最多 30）: ").strip()
        try:
            days = max(1, min(int(days_raw or 7), 30))
        except ValueError:
            days = 7
        try:
            ack = gate.author_sign_request(req, days=days)
        except Exception as e:
            return self._send(500, {"ok": False, "reason": f"签发失败：{e}"})
        log_decision({"cap": cap, "fp": d.get("fp"),
                      "purpose": d.get("purpose"), "decision": "allow",
                      "days": days, "request": req})
        print(f"✓ 已批准，有效期 {days} 天，回签已发送。")
        return self._send(200, {"ok": True, "ack": ack, "days": days})


def main() -> int:
    ap = argparse.ArgumentParser(description="ReverseForge 作者端授权服务器")
    ap.add_argument("--init", action="store_true", help="生成 RSA-4096 密钥对")
    ap.add_argument("--force", action="store_true", help="覆盖已有私钥（危险）")
    ap.add_argument("--seal", action="store_true", help="把能力模块封成多层密文")
    ap.add_argument("--fp", default="", help="--seal 时指定目标机器指纹")
    ap.add_argument("--port", type=int, default=8787, help="监听端口（默认 8787）")
    ap.add_argument("--show-pub", action="store_true", help="打印公钥路径")
    a = ap.parse_args()

    if a.init:
        r = gate.author_init(force=a.force)
        print("密钥对已生成：")
        print("  私钥（绝不外传）:", r["private"])
        print("  公钥（随包分发）:", r["public"])
        print("  位数:", r["bits"])
        return 0
    if a.show_pub:
        print(gate.public_key_path())
        print("存在" if gate.public_key_path().is_file() else "缺失")
        return 0
    if a.seal:
        fp = a.fp.strip() or gate.machine_fingerprint()
        print("目标机器指纹:", fp)
        for line in seal_modules(fp):
            print(" ", line)
        return 0

    if not gate.private_key_path().is_file():
        print("缺少作者私钥，请先运行：python tools/gate_server.py --init")
        return 2
    url = f"http://127.0.0.1:{a.port}"
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), Handler)
    print("=" * 64)
    print(f"作者端授权校验已启动：{url}")
    print("公网入口请用 cloudflared 隧道指向本机该端口，例如：")
    print(f"  cloudflared tunnel --url {url}")
    print("客户端设置：rf.gate_server('<隧道 https 地址>')")
    print("决策日志：", DECISION_LOG)
    print("=" * 64)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
