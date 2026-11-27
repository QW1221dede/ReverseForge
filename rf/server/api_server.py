#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 rf.server.api_server · 本地 HTTP API（给 AI / 外部脚本调用）
============================================================================

【为什么要这个】
    界面是给人用的，AI 用的是 API。
    有了它，任何能发 HTTP 的 agent（Claude、GPT、本地模型、你自己的脚本）
    都能直接指挥这个工具：识别 → 分段 → 解密 → 找校验 → 打补丁。

【安全设计（重要）】
    · 只绑 127.0.0.1，不接受外网连接
    · 每个请求要带 token（`X-RF-Token` 头或 `?token=`）
      token 首次启动随机生成，存在 %LOCALAPPDATA%\\ReverseForge\\api_token.txt
    · 默认**只开放只读能力**；写操作（打补丁/重建/改脚本）必须显式
      allow_write=true 启动，避免 AI 一上来就把文件改了
    · 所有调用都限制在本机已有路径上，不做任意 URL 抓取

【接口】
    GET  /health              存活与版本
    GET  /tools               工具清单（机器可读，直接喂给 LLM 做 function calling）
    POST /call                {"tool": "file_type", "args": {"path": "..."}}
    POST /analyze             {"paths": [...], "task": "自然语言任务"}
    GET  /                    浏览器里看接口说明

【为什么不用 Flask】
    多一个依赖就多一个"装不上"的理由。标准库 http.server 足够，
    打包体积也小。并发用 ThreadingHTTPServer，几个请求同时来不会排队。
============================================================================
"""

from __future__ import annotations

import json
import secrets
import threading
import time
from dataclasses import is_dataclass, asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from .. import config

# ---------------------------------------------------------------------------
# 可调用工具（给 LLM 看的清单）
#   只读工具默认开放；写操作要 allow_write
# ---------------------------------------------------------------------------

TOOLS: list[dict[str, Any]] = [
    {
        "name": "file_type",
        "desc": "识别单个文件的真实类型（PE/ELF/脚本/压缩包/密文…），返回类型、熵、建议的下一步",
        "params": {"path": "文件绝对路径"},
        "write": False,
    },
    {
        "name": "scan_any",
        "desc": "扫描目录，按类型分类统计（脚本/本地程序/压缩包/疑似加密）",
        "params": {"target": "目录或文件路径"},
        "write": False,
    },
    {
        "name": "segments",
        "desc": "文件分段：找出「明文头 + 密文」的分界点，并尝试从头部提取 key/iv",
        "params": {"target": "文件路径"},
        "write": False,
    },
    {
        "name": "garble",
        "desc": "判断文本为什么看不懂：菱形问号(非法UTF-8) / 方块(字体加密) / 一片乱码(编码错位，可修)",
        "params": {"target": "文件路径或一段文本"},
        "write": False,
    },
    {
        "name": "decrypt_auto",
        "desc": "自动试解：编码/压缩/XOR/RC4/AES/TEA/XXTEA/OpenSSL，返回按可信度排序的候选明文",
        "params": {"target": "文件路径", "keys": "可选，已知密码列表"},
        "write": False,
    },
    {
        "name": "keys_any",
        "desc": "从文件或目录里翻候选密钥（明文头、源码常量、配置、长 hex、弱口令）",
        "params": {"target": "文件或目录路径"},
        "write": False,
    },
    {
        "name": "auth_scan",
        "desc": "找密码/卡密/授权校验点：脚本源码按行、PE/ELF 按偏移、class 常量池、smali",
        "params": {"target": "文件或目录路径", "min_confidence": "整数，默认 45"},
        "write": False,
    },
    {
        "name": "patch_scan",
        "desc": "APK 解包目录的启动前校验扫描（smali 布尔闸门 + 调用图）",
        "params": {"target": "apktool 解包目录"},
        "write": False,
    },
    {
        "name": "strings",
        "desc": "提取可打印字符串（带分类：URL/路径/密钥/错误提示）",
        "params": {"path": "文件路径", "min_len": "最短长度，默认 5"},
        "write": False,
    },
    {
        "name": "identify",
        "desc": "识别加密/压缩容器类型与强度（熵、已知头、ZIP 加密项）",
        "params": {"path": "文件路径"},
        "write": False,
    },
    {
        "name": "annotate",
        "desc": "给反编译源码加中文注释（词法级翻译 + 块级语句）",
        "params": {"src": "源码目录或文件", "out": "输出目录，可选"},
        "write": False,
    },
    {
        "name": "auth_apply",
        "desc": "把脚本里的校验改成恒真（自动备份、原子写、可回滚）",
        "params": {"target": "脚本路径", "ids": "可选，只改这些编号", "dry_run": "布尔"},
        "write": True,
    },
    {
        "name": "patch_apply",
        "desc": "应用 smali 补丁（事务化：备份→核对→写入→语法校验→失败回滚）",
        "params": {"target": "解包目录", "ids": "补丁编号列表", "dry_run": "布尔"},
        "write": True,
    },
]


def tool_schema() -> list[dict[str, Any]]:
    """给 LLM 的 function-calling 清单（OpenAI / Claude 都能用）。"""
    out = []
    for t in TOOLS:
        props = {k: {"type": "string", "description": v}
                 for k, v in t["params"].items()}
        out.append({
            "name": t["name"],
            "description": t["desc"],
            "parameters": {
                "type": "object",
                "properties": props,
                "required": [k for k in t["params"]
                             if not k in ("keys", "out", "ids", "dry_run",
                                          "min_confidence", "min_len")],
            },
        })
    return out


# ---------------------------------------------------------------------------
# 结果序列化
# ---------------------------------------------------------------------------

def _plain(obj: Any, depth: int = 0) -> Any:
    """把 dataclass / Path / bytes 转成 JSON 能吃的形状。"""
    if depth > 4:
        return str(obj)
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, (bytes, bytearray)):
        return f"<{len(obj)} bytes>"
    if isinstance(obj, (list, tuple)):
        return [_plain(x, depth + 1) for x in obj[:200]]
    if isinstance(obj, dict):
        return {str(k): _plain(v, depth + 1) for k, v in list(obj.items())[:200]}
    if is_dataclass(obj):
        try:
            return {k: _plain(v, depth + 1) for k, v in asdict(obj).items()}
        except Exception:                            # noqa: BLE001
            return str(obj)
    for attr in ("to_dict", "text", "brief"):
        fn = getattr(obj, attr, None)
        if callable(fn):
            try:
                return _plain(fn(), depth + 1)
            except Exception:                        # noqa: BLE001
                pass
    return str(obj)


# ---------------------------------------------------------------------------
# 服务
# ---------------------------------------------------------------------------

class ApiServer:
    """
    本地 API 服务。
        srv = ApiServer(allow_write=False).start()
        print(srv.url)          # http://127.0.0.1:8765/?token=...
        srv.stop()
    """

    def __init__(self, api=None, host: str = "127.0.0.1", port: int = 8765,
                 token: str = "", allow_write: bool = False):
        self.host = host
        self.port = port
        self.token = token or secrets.token_urlsafe(18)
        self.allow_write = allow_write
        self._api = api
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.started_at = 0.0
        self.calls = 0

    # ---- 生命周期 ----
    @property
    def api(self):
        if self._api is None:
            from ..api import make_api
            self._api = make_api()
        return self._api

    @property
    def running(self) -> bool:
        return self._httpd is not None

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}/?token={self.token}"

    def start(self, port_walk: int = 12) -> "ApiServer":
        if self.running:
            return self
        handler = _make_handler(self)
        last_err: Exception | None = None
        for i in range(port_walk):
            try:
                self.port = self.port + i if i else self.port
                self._httpd = ThreadingHTTPServer((self.host, self.port), handler)
                break
            except OSError as e:
                last_err = e
                continue
        if self._httpd is None:
            raise RuntimeError(f"端口被占用（{self.port} 起试了 {port_walk} 个）：{last_err}")
        self._httpd.daemon_threads = True
        self._thread = threading.Thread(target=self._httpd.serve_forever,
                                        daemon=True)
        self._thread.start()
        self.started_at = time.time()
        try:
            p = config.USER_ROOT / "api_token.txt"
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(f"# ReverseForge 本地 API token\n{self.token}\n"
                         f"# {self.url}\n", encoding="utf-8")
        except OSError:
            pass
        return self

    def stop(self) -> None:
        if self._httpd:
            try:
                self._httpd.shutdown()
                self._httpd.server_close()
            except Exception:                        # noqa: BLE001
                pass
        self._httpd = None
        self._thread = None


# ---------------------------------------------------------------------------
# 请求处理
# ---------------------------------------------------------------------------

def _make_handler(srv: ApiServer):
    class Handler(BaseHTTPRequestHandler):
        server_version = "ReverseForgeAPI/1.0"

        # 关掉默认的 stderr 日志刷屏
        def log_message(self, fmt, *args):            # noqa: A003
            pass

        # ---- 工具函数 ----
        def _send(self, code: int, body: Any, ctype: str = "application/json"):
            raw = body if isinstance(body, bytes) else \
                json.dumps(body, ensure_ascii=False, indent=2).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype + "; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Access-Control-Allow-Origin", "http://127.0.0.1")
            self.send_header("X-RF-Token-Hint", "send X-RF-Token header")
            self.end_headers()
            self.wfile.write(raw)

        def _auth_ok(self, query: dict) -> bool:
            tok = self.headers.get("X-RF-Token") or \
                (query.get("token", [""])[0] if query else "")
            return bool(tok) and tok == srv.token

        def _body(self) -> dict:
            n = int(self.headers.get("Content-Length") or 0)
            if n <= 0:
                return {}
            try:
                return json.loads(self.rfile.read(n).decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                return {}

        # ---- 路由 ----
        def do_GET(self):                            # noqa: N802
            u = urlparse(self.path)
            q = parse_qs(u.query)
            if u.path in ("/", "/index.html"):
                self._send(200, _HELP_HTML.encode("utf-8"), "text/html")
                return
            if u.path == "/health":
                self._send(200, {
                    "ok": True,
                    "app": config.APP_NAME,
                    "version": config.APP_VERSION,
                    "uptime_s": round(time.time() - srv.started_at, 1),
                    "calls": srv.calls,
                    "allow_write": srv.allow_write,
                    "auth_required": True,
                    "tools": len(TOOLS),
                })
                return
            if not self._auth_ok(q):
                self._send(401, {"ok": False, "error": "缺少或错误的 token（X-RF-Token）"})
                return
            if u.path == "/tools":
                self._send(200, {"ok": True, "tools": TOOLS,
                                 "openai_functions": tool_schema(),
                                 "allow_write": srv.allow_write})
                return
            self._send(404, {"ok": False, "error": f"没有这个路径：{u.path}"})

        def do_POST(self):                           # noqa: N802
            u = urlparse(self.path)
            q = parse_qs(u.query)
            if not self._auth_ok(q):
                self._send(401, {"ok": False, "error": "缺少或错误的 token（X-RF-Token）"})
                return
            body = self._body()
            if u.path == "/call":
                self._do_call(body)
            elif u.path == "/analyze":
                self._do_analyze(body)
            else:
                self._send(404, {"ok": False, "error": f"没有这个路径：{u.path}"})

        # ---- /call ----
        def _do_call(self, body: dict) -> None:
            name = str(body.get("tool") or "").strip()
            args = body.get("args") or {}
            if not isinstance(args, dict):
                self._send(400, {"ok": False, "error": "args 必须是对象"})
                return
            spec = next((t for t in TOOLS if t["name"] == name), None)
            if not spec:
                self._send(404, {"ok": False,
                                 "error": f"没有这个工具：{name}",
                                 "available": [t["name"] for t in TOOLS]})
                return
            if spec["write"] and not srv.allow_write:
                self._send(403, {"ok": False,
                                 "error": "写操作被禁用。启动时加 allow_write=True 才开放",
                                 "tool": name})
                return
            t0 = time.time()
            try:
                fn = getattr(srv.api, name, None)
                if fn is None:
                    self._send(500, {"ok": False, "error": f"API 未实现：{name}"})
                    return
                res = fn(**args)
                srv.calls += 1
                self._send(200, {
                    "ok": True,
                    "tool": name,
                    "elapsed_ms": int((time.time() - t0) * 1000),
                    "result": _plain(res),
                })
            except TypeError as e:
                self._send(400, {"ok": False, "error": f"参数不对：{e}",
                                 "expect": spec["params"]})
            except Exception as e:                   # noqa: BLE001
                self._send(500, {"ok": False,
                                 "error": f"{type(e).__name__}: {e}"})

        # ---- /analyze ----
        def _do_analyze(self, body: dict) -> None:
            paths = body.get("paths") or []
            task = str(body.get("task") or "").strip()
            if not paths:
                self._send(400, {"ok": False, "error": "paths 不能为空"})
                return
            t0 = time.time()
            try:
                from ..agent import orchestrator
                plan = orchestrator.plan(task, paths)
                out = orchestrator.run(plan, paths)
                self._send(200, {
                    "ok": True,
                    "elapsed_ms": int((time.time() - t0) * 1000),
                    "intent": plan.intent,
                    "steps": [s.name for s in plan.steps],
                    "report": out.text,
                    "results": _plain(out.items),
                })
            except Exception as e:                   # noqa: BLE001
                self._send(500, {"ok": False,
                                 "error": f"{type(e).__name__}: {e}"})

    return Handler


_HELP_HTML = """<!doctype html><html lang="zh-CN"><meta charset="utf-8">
<title>ReverseForge 本地 API</title>
<style>
body{background:#0e1014;color:#d6dbe6;font:14px/1.7 "Microsoft YaHei UI",sans-serif;
     max-width:860px;margin:40px auto;padding:0 20px}
h1{font-size:20px} code{background:#1b202b;padding:2px 6px;border-radius:4px;
     color:#ff8a3d;font-family:Consolas,monospace}
pre{background:#151821;border:1px solid #262c39;padding:12px;border-radius:6px;
     overflow:auto;font-family:Consolas,monospace;font-size:13px}
.k{color:#3ddc84} .m{color:#79839a}
</style>
<h1>ReverseForge 本地 API</h1>
<p class="m">只监听 127.0.0.1，需要 token。token 在
<code>%LOCALAPPDATA%\\ReverseForge\\api_token.txt</code></p>
<pre><span class="k">GET</span>  /health                     存活与版本（无需 token）
<span class="k">GET</span>  /tools                      工具清单 + OpenAI function 定义
<span class="k">POST</span> /call    {"tool":"file_type","args":{"path":"D:\\\\a.bin"}}
<span class="k">POST</span> /analyze {"paths":["D:\\\\a.bin"],"task":"这是什么，能解密吗"}</pre>
<p>请求头带 <code>X-RF-Token: &lt;token&gt;</code>，或 URL 加 <code>?token=</code>。</p>
<pre>curl -H "X-RF-Token: 你的token" ^
     -H "Content-Type: application/json" ^
     -d "{\\"tool\\":\\"file_type\\",\\"args\\":{\\"path\\":\\"D:/test.bin\\"}}" ^
     http://127.0.0.1:8765/call</pre>
<p class="m">写操作（打补丁 / 重建 / 改脚本）默认关闭，需要启动时显式允许。</p>
</html>
"""
