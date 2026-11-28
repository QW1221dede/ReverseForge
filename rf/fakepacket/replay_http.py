# -*- coding: utf-8 -*-
"""
============================================================================
 rf.fakepacket.replay_http · 通用 HTTP 重放（2026-11-28）
============================================================================

【用途】
    proxy 抓到真交互后，如果服务器因为卡密无效而拒绝，
    就把请求里的字段逐个改掉重发，看哪个能让它改口。
    这是「骗服务器发真实数据」的实际手段：不是编响应，是让它真的认。

【输入】
    rf_capture.log（rf_hook.so 录的）

【三种改写】
    field=value   改请求体里的字段（urlencoded 或 JSON 都认）
    header=X:Y    改/加请求头
    raw           整条请求体替换

【安全】
    默认只重放第 1 条请求，且 --dry-run 能看到改完的报文再决定发不发。
    属于对外生效能力，调用方须先过 gate.require("NET_SEND")。
============================================================================
"""
from __future__ import annotations

import json
import re
import socket
import time
from pathlib import Path


def parse_requests(cap_log: str | Path) -> list[dict]:
    """从抓包提取请求：[(ip, port, raw_http), ...]"""
    p = Path(cap_log)
    if not p.is_file():
        return []
    text = p.read_text(encoding="utf-8", errors="replace")
    blocks = [b for b in text.split("\n----\n") if b.strip()]

    out: list[dict] = []
    host = ""
    for b in blocks:
        if b.startswith("[== 连真实服务器 "):
            m = re.search(r"\[== 连真实服务器 ([^\]]+)\]", b)
            if m:
                host = m.group(1).strip()
            continue
        if not b.startswith("[>> 发给服务器]"):
            continue
        raw = b[len("[>> 发给服务器]"):].lstrip()
        if not raw.upper().startswith(("GET ", "POST ", "PUT ", "HEAD ")):
            continue
        ip, port = "", 80
        if host:
            if ":" in host:
                a, _, b2 = host.rpartition(":")
                ip, port = a, int(b2) if b2.isdigit() else 80
            else:
                ip, port = host, 80
        out.append({"ip": ip, "port": port, "raw": raw, "host": host})
    return out


def _rewrite_body(raw: str, rules: dict[str, str]) -> str:
    """改写请求体字段，urlencoded / JSON 都支持。"""
    if not rules:
        return raw
    if "\r\n\r\n" in raw:
        head, body = raw.split("\r\n\r\n", 1)
    else:
        head, body = raw, ""

    changed = dict(rules)
    # JSON 体
    stripped = body.strip()
    if stripped.startswith("{") and stripped.endswith("}"):
        try:
            obj = json.loads(stripped)
            for k, v in rules.items():
                if k in obj:
                    obj[k] = v
                    changed.pop(k, None)
            body = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
        except Exception:
            pass
    # urlencoded 体
    for k, v in list(changed.items()):
        pat = re.compile(r"(^|&)" + re.escape(k) + r"=[^&]*")
        if pat.search(body):
            body = pat.sub(lambda m: m.group(1) + k + "=" + str(v), body)
            changed.pop(k, None)
    # 剩下的当新字段追加
    if changed:
        add = "&".join("%s=%s" % (k, v) for k, v in changed.items())
        body = (body + "&" + add) if body else add

    # 重算 Content-Length
    head = re.sub(r"(?im)^Content-Length:\s*\d+\s*$",
                  "Content-Length: %d" % len(body.encode("utf-8")), head)
    return head + "\r\n\r\n" + body


def _rewrite_header(raw: str, headers: dict[str, str]) -> str:
    if not headers or "\r\n\r\n" not in raw:
        return raw
    head, body = raw.split("\r\n\r\n", 1)
    for k, v in headers.items():
        pat = re.compile(r"(?im)^" + re.escape(k) + r":\s*.*$")
        if pat.search(head):
            head = pat.sub("%s: %s" % (k, v), head)
        else:
            head += "\r\n%s: %s" % (k, v)
    return head + "\r\n\r\n" + body


def build(req: dict, fields: dict[str, str] | None = None,
          headers: dict[str, str] | None = None,
          raw_body: str | None = None) -> str:
    raw = req["raw"]
    if raw_body is not None:
        head = raw.split("\r\n\r\n", 1)[0]
        raw = head + "\r\n\r\n" + raw_body
        raw = re.sub(r"(?im)^Content-Length:\s*\d+\s*$",
                     "Content-Length: %d" % len(raw_body.encode("utf-8")), raw)
    raw = _rewrite_body(raw, fields or {})
    raw = _rewrite_header(raw, headers or {})
    return raw


def send(req: dict, raw: str, timeout: float = 10.0,
         read_limit: int = 65536) -> dict:
    """发一条请求，返回响应原文。"""
    r = {"ok": False, "sent": raw, "resp": "", "error": ""}
    if not req.get("ip"):
        r["error"] = "抓包里没有目标地址"
        return r
    try:
        s = socket.create_connection((req["ip"], int(req["port"])), timeout=timeout)
        s.sendall(raw.encode("utf-8", "replace"))
        buf = bytearray()
        s.settimeout(timeout)
        while len(buf) < read_limit:
            try:
                k = s.recv(8192)
            except socket.timeout:
                break
            if not k:
                break
            buf += k
            if b"\r\n\r\n" in buf:
                # 简单判断：拿到完整响应体就收
                head, _, body = bytes(buf).partition(b"\r\n\r\n")
                m = re.search(rb"(?i)content-length:\s*(\d+)", head)
                if m and len(body) >= int(m.group(1)):
                    break
                if b"chunked" in head.lower() and body.endswith(b"0\r\n\r\n"):
                    break
        s.close()
        r["resp"] = bytes(buf).decode("utf-8", "replace")
        r["ok"] = bool(r["resp"])
    except Exception as e:
        r["error"] = "%r" % (e,)
    return r


def judge(resp: str) -> dict:
    """从响应里猜成功与否（不保证准，给个人眼看的信号）。"""
    verdict = {"success": None, "code": "", "hint": ""}
    m = re.search(r'"code"\s*:\s*(\d+)', resp)
    if m:
        verdict["code"] = m.group(1)
        verdict["success"] = m.group(1) in ("20000", "200", "0", "1")
    for key in ("checktrue", "success", "ok"):
        m2 = re.search(r'"%s"\s*:\s*("?)([^",}]+)\1' % key, resp)
        if m2:
            v = m2.group(2).strip().lower()
            verdict["success"] = v in ("1", "true", "yes", "ok")
            verdict["hint"] = "%s=%s" % (key, v)
            break
    if not verdict["hint"]:
        if re.search(r"HTTP/1\.[01] 200", resp):
            verdict["hint"] = "HTTP 200"
    return verdict


def replay(cap_log: str | Path, *, fields: dict[str, str] | None = None,
           headers: dict[str, str] | None = None,
           raw_body: str | None = None, index: int = 0,
           dry_run: bool = False, gap: float = 1.0) -> dict:
    """重放一条请求。dry_run 只返回改完的报文，不发出去。"""
    reqs = parse_requests(cap_log)
    if not reqs:
        return {"ok": False, "error": "抓包里没有可重放的请求", "steps": []}
    if index >= len(reqs):
        index = 0
    req = reqs[index]
    raw = build(req, fields, headers, raw_body)

    out = {"ok": False, "target": req["host"], "index": index,
           "request": raw, "steps": [], "error": ""}
    if dry_run:
        out["ok"] = True
        out["note"] = "DRY-RUN，没发出去"
        return out

    time.sleep(max(0.0, gap))
    r = send(req, raw)
    v = judge(r["resp"])
    out["resp"] = r["resp"]
    out["verdict"] = v
    out["ok"] = r["ok"]
    out["error"] = r["error"]

    # 再发一次原始请求做对照
    if r["ok"]:
        time.sleep(max(0.0, gap))
        base = send(req, req["raw"])
        out["baseline"] = {"resp": base["resp"], "verdict": judge(base["resp"])}
        b_succ = out["baseline"]["verdict"].get("success")
        c_succ = v.get("success")
        if b_succ is False and c_succ is True:
            out["note"] = "★ 改写后服务器改口了：原请求被拒，改后通过"
        elif c_succ is True:
            out["note"] = "改后仍为通过"
        elif b_succ is True:
            out["note"] = "原请求本来就通过（不需要改）"
        else:
            out["note"] = "原请求与改后都未通过，换字段继续试"
    return out


def _cli(argv: list[str]) -> int:
    args = [a for a in argv if not a.startswith("--")]
    flags = {a for a in argv if a.startswith("--")}
    if not args:
        print(__doc__)
        return 1

    fields: dict[str, str] = {}
    headers: dict[str, str] = {}
    for a in args[1:]:
        if a.startswith("h:") and "=" in a:
            k, v = a[2:].split("=", 1)
            headers[k] = v
        elif "=" in a:
            k, v = a.split("=", 1)
            fields[k] = v

    # 对外生效，先过授权
    try:
        import sys as _s
        _s.path.insert(0, str(Path(__file__).resolve().parents[2]))
        from rf.secure import gate
        gate.require("NET_SEND")
    except Exception as e:
        print("需要授权：" + str(e).splitlines()[0])
        return 3

    r = replay(args[0], fields=fields, headers=headers or None,
               dry_run=("--dry-run" in flags))
    if r.get("error") and not r.get("resp"):
        print("失败：" + r["error"])
        return 2
    if "--dry-run" in flags:
        print("【DRY-RUN】改完的请求：\n")
        print(r["request"])
        return 0

    print("目标：%s" % r.get("target"))
    print("结论：%s" % r.get("note", ""))
    if r.get("verdict"):
        print("改后：", r["verdict"])
    if r.get("baseline"):
        print("原样：", r["baseline"]["verdict"])
    print("\n--- 响应 ---")
    print((r.get("resp") or "")[:1500])
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_cli(sys.argv[1:]))
