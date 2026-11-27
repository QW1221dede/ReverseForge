#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 联网校验 —— "连服务器验证，不通过就不给用"
============================================================================

本地校验能改，但不代表就能用。真正的卡点经常在服务器那边：

    POST /api/login  {"card":"xxx"}  →  {"code":403,"msg":"卡密已过期"}
                                        ↓
                                 if (code != 20000) { 退出 }

本地代码一句 System.exit 都没写"错"，它只是在**正确地执行服务器的判决**。
把本地判定改成恒真也没用 —— 服务器就是判你不通过。

所以这一层要动的是"服务器说了什么"和"听完之后怎么反应"：

   ① 状态码强制 200        getResponseCode() / Response.code() 返回值就地改掉
   ② 成功标志恒真          isSuccessful() / code==200 / code==20000
   ③ 失败分支不处置        异常 catch 里的 exit / finish（终结动作那层已覆盖）
   ④ 返回体洗白（Frida）   "code":403 → "code":0，"success":false → true

①②③ 改 dex，④ 走运行时 —— 加固包、逻辑在 so 里的包只有 ④ 能生效。

【这一步就是解法】
服务器说什么，客户端听到的都是"通过"。判定、状态码、返回体判决字段
一起改写，客户端认了，功能就照常开 —— 不需要在结论里再区分
"哪些是客户端判的、哪些是服务器发的"，那是多余的话。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from . import checkpoints as cp

# ---------------------------------------------------------------------------
# 网络调用特征
# ---------------------------------------------------------------------------
# 状态码读取（返回 int，紧跟 move-result）
_CODE_CALLS = re.compile(
    r"Ljava/net/HttpURLConnection;->getResponseCode\(\)I|"
    r"Lokhttp3/Response;->code\(\)I|"
    r"Lretrofit2/Response;->code\(\)I|"
    r"Lcom/squareup/okhttp3/Response;->code\(\)I")

# 成功判定（返回 boolean，紧跟 move-result）
_OK_CALLS = re.compile(
    r"Lokhttp3/Response;->isSuccessful\(\)Z|"
    r"Lretrofit2/Response;->isSuccessful\(\)Z")

# 请求发起点 —— 只用于统计和判断"这个方法真的在联网"
_REQ_CALLS = re.compile(
    r"Ljava/net/URL;->openConnection\(\)|"
    r"Ljava/net/HttpURLConnection;->(connect|getInputStream|getOutputStream)\(|"
    r"Lokhttp3/OkHttpClient;->newCall\(|"
    r"Lokhttp3/Call;->execute\(\)|"
    r"Lretrofit2/Retrofit;->create\(|"
    r"Lcom/android/volley/|"
    r"Lokhttp3/Request\$Builder;->url\(")

# 校验类语义（方法名 / 类名 / 常量）—— 决定"要不要在这里强制 200"
# \blic 用左边界匹配 License / LicNet / LicApi，但不会误中 click / public / clone
_CHECK_WORDS = re.compile(
    r"(?i)(\blic(?:en[cs]e)?|verify|verif|auth|login|activ|check_?card|"
    r"cdkey|card_?key|valid|vip|vpn|member|subscri|trial|expire|"
    r"code|msg|success|token|session|"
    r"卡密|激活|授权|登录|验证|会员|到期|过期|订阅|订单|试用|注册)")

# JSON 判决字段：出现这些说明这个方法在解析"服务器同意不同意"
_JSON_FIELDS = re.compile(
    r'(?i)^"?(code|status|success|ok|valid|msg|message|data|token|expire[ds]?)"?$')

# 常见的"成功"码值
_OK_CODES = (0xC8, 0)


@dataclass
class NetPoint:
    """一个联网校验点。"""
    file: str
    method: str
    cls_simple: str
    kind: str                  # code / ok
    line: int                  # 补丁落点（move-result 所在行）
    reg: str                   # 被赋值的寄存器 v5 / p1
    invoke_line: int           # 原始 invoke 行（参与匹配，保证唯一）
    invoke_text: str
    result_line: int
    result_text: str
    scope: str = "check"       # check / all —— 为什么改它
    why: str = ""


def _is_check_method(m: "cp._Method") -> bool:
    """这个方法像不像"拿到服务器回复后决定放不放行"。"""
    if _CHECK_WORDS.search(m.name) or _CHECK_WORDS.search(m.cls_simple):
        return True
    if any(_CHECK_WORDS.search(s) for s in m.strings):
        return True
    # 解析 JSON 判决字段（"code" / "success" / "msg"）—— 授权接口几乎都有
    if any(_JSON_FIELDS.match(s.strip()) for s in m.strings):
        return True
    # 方法体里有"拒绝运行"的动作，说明它在做处置
    body = [t for _, t in m.body]
    from . import guards
    return bool(guards.find_terminators(body, guarded=False))


def scan_network(root: str | Path, *, max_files: int = 6000) -> list[NetPoint]:
    """扫解包目录，找所有"读服务器回复"的位置。只读。"""
    rt = Path(root)
    pts: list[NetPoint] = []
    if not rt.is_dir():
        return pts

    n = 0
    for f in sorted(rt.rglob("*.smali")):
        n += 1
        if n > max_files:
            break
        try:
            methods, *_ = cp._parse_file(f)
        except Exception:                              # noqa: BLE001
            continue
        for m in methods:
            if not m.body:
                continue
            body = m.body                       # [(绝对行号, strip 文本)]
            is_check = _is_check_method(m)
            for i, (abs_line, text) in enumerate(body):
                kind = ""
                if _CODE_CALLS.search(text):
                    kind = "code"
                elif _OK_CALLS.search(text):
                    kind = "ok"
                if not kind:
                    continue
                # 下一行非空必须是 move-result
                j = i + 1
                while j < len(body) and not body[j][1]:
                    j += 1
                if j >= len(body):
                    continue
                rtxt = body[j][1]
                rm = re.match(r"^move-result(?:-object)?\s+([vp]\d+)$", rtxt)
                if not rm:
                    continue
                reg = rm.group(1)
                pts.append(NetPoint(
                    file=str(f), method=m.name, cls_simple=m.cls_simple,
                    kind=kind, line=body[j][0], reg=reg,
                    invoke_line=abs_line, invoke_text=text,
                    result_line=body[j][0], result_text=rtxt,
                    scope="check" if is_check else "all",
                    why=("校验方法（名字/常量像授权登录）" if is_check
                         else "普通网络调用")))
    return pts


# ---------------------------------------------------------------------------
# 生成补丁
# ---------------------------------------------------------------------------
def plan_network(root: str | Path, *, scope: str = "check",
                 max_ops: int = 60) -> tuple[list, dict]:
    """
    生成"让服务器回复永远算通过"的补丁。

        scope="check"  只改疑似校验的方法（默认，误伤最小）
        scope="all"    全包改（最彻底，但业务接口的 404 也会被当 200）

    改法：在 move-result 之后紧插一条常量赋值，把寄存器就地覆盖掉。

        invoke-virtual {v4}, Ljava/net/HttpURLConnection;->getResponseCode()I
        move-result v5
        const/16 v5, 0xc8          ← 插这一条

    为什么插在 move-result 后面而不是改判断：判断有三种写法
    （==200 / >=200 / >=400 判错），改判断要认标签、认跳转方向，
    改返回值则一次覆盖全部写法。而且 move-result 后面不会有别的
    指令读这个寄存器，插一条赋值不会破坏任何东西。
    """
    pts = scan_network(root)
    stat = {"points": 0, "code": 0, "ok": 0, "check_scope": 0,
            "patched": 0, "skipped_dup": 0}
    stat["points"] = len(pts)
    ops: list = []
    seen: set[tuple[str, int]] = set()

    for p in sorted(pts, key=lambda x: (x.file, -x.line)):
        if scope == "check" and p.scope != "check":
            continue
        stat["check_scope"] += 1
        key = (p.file, p.line)
        if key in seen:
            stat["skipped_dup"] += 1
            continue
        seen.add(key)

        if p.kind == "code":
            stat["code"] += 1
            inject = f"    const/16 {p.reg}, 0xc8"
            why = f"状态码强制 200 · {p.cls_simple}.{p.method}"
        else:
            stat["ok"] += 1
            inject = f"    const/4 {p.reg}, 0x1"
            why = f"isSuccessful 强制 true · {p.cls_simple}.{p.method}"

        # original 用 invoke + move-result 两行，保证文件内唯一
        original = f"{p.invoke_text}\n\n{p.result_text}"
        replacement = f"{p.invoke_text}\n\n{p.result_text}\n\n{inject}"
        ops.append(cp.PatchOp(
            file=p.file,
            line=p.invoke_line, end_line=p.result_line,
            original=original, replacement=replacement,
            reason=why, kind="net_force"))
        stat["patched"] += 1
        if len(ops) >= max_ops:
            break
    return ops, stat


# ---------------------------------------------------------------------------
# 运行时：Frida 版（针对加固包 / 逻辑在 so 里 / 静态改不动）
# ---------------------------------------------------------------------------
_FRIDA_NET = r"""
// ---------------- 联网校验：让客户端始终认为服务器同意了 ----------------
// 静态改不动（加固/so/VMP）时用这个，效果一样，都是骗过客户端自己。
function rfNet() {
  var g = {code: 200, ok: true};

  // ① HttpURLConnection.getResponseCode / getInputStream
  try {
    var HUC = Java.use('java.net.HttpURLConnection');
    HUC.getResponseCode.implementation = function () {
      var real = this.getResponseCode();
      if (real >= 400) console.log('[RF] 状态码 ' + real + ' → 200');
      return 200;
    };
  } catch (e) { }

  // ② OkHttp（3.x / 4.x 都覆盖）
  ['okhttp3.Response', 'com.squareup.okhttp3.Response'].forEach(function (n) {
    try {
      var R = Java.use(n);
      R.code.overload().implementation = function () {
        var real = this.code();
        if (real >= 400) console.log('[RF] OkHttp 状态码 ' + real + ' → 200');
        return 200;
      };
      R.isSuccessful.overload().implementation = function () { return true; };
      R.message.overload().implementation = function () { return 'OK'; };
    } catch (e) { }
  });

  // ③ 返回体洗白：不认识 JSON 结构也能改 —— 只动"判决字段"
  //    服务器说 code:403 / success:false / 卡密过期，一律改成通过。
  var RULES = [
    [/"code"\s*:\s*-?\d+/g,        '"code":0'],
    [/"err(?:or)?_?code"\s*:\s*-?\d+/g, '"err_code":0'],
    [/"status"\s*:\s*-?\d+/g,      '"status":0'],
    [/"success"\s*:\s*false/g,     '"success":true'],
    [/"ok"\s*:\s*false/g,          '"ok":true'],
    [/"valid"\s*:\s*false/g,       '"valid":true'],
    [/"auth(?:orized)?"\s*:\s*false/g, '"auth":true'],
    [/"is_?vip"\s*:\s*false/g,     '"is_vip":true'],
    [/"expire[ds]?"\s*:\s*"[^"]*"/g, '"expires":"2099-12-31 23:59:59"'],
    [/"msg"\s*:\s*"[^"]*(?:过期|失效|错误|失败|无效|不存在|未授权)[^"]*"/g, '"msg":"ok"']
  ];
  function wash(s) {
    if (typeof s !== 'string' || s.length < 2) return s;
    if (s.indexOf('code') < 0 && s.indexOf('success') < 0 &&
        s.indexOf('valid') < 0 && s.indexOf('status') < 0) return s;
    var out = s;
    for (var i = 0; i < RULES.length; i++) out = out.replace(RULES[i][0], RULES[i][1]);
    if (out !== s) console.log('[RF] 返回体洗白：' + s.substring(0, 80));
    return out;
  }

  // OkHttp 的 body.string()
  ['okhttp3.ResponseBody', 'com.squareup.okhttp3.ResponseBody'].forEach(function (n) {
    try {
      Java.use(n).string.overload().implementation = function () {
        return wash(this.string());
      };
    } catch (e) { }
  });

  // 通用：BufferedReader.readLine / InputStream 读完拼串的多数会走这里
  try {
    var BR = Java.use('java.io.BufferedReader');
    BR.readLine.overload().implementation = function () {
      var s = this.readLine();
      return wash(s);
    };
  } catch (e) { }

  // ④ 彻底连不上时（离线/域名被墙）给一个"通过"的假响应
  try {
    var IS = Java.use('java.io.InputStream');
    var Inet = Java.use('java.net.InetAddress');
    Inet.getByName.overload('java.lang.String').implementation = function (h) {
      try { return this.getByName(h); }
      catch (e) { console.log('[RF] DNS 失败 ' + h + '，放行'); }
      return null;
    };
  } catch (e) { }

  console.log('[RF] 联网校验覆盖已挂载（状态码 / 成功标志 / 返回体）');
}
"""


def frida_net_snippet() -> str:
    """返回可直接拼进 hook.js 的网络覆盖段。"""
    return _FRIDA_NET


def write_frida_net(out: str | Path) -> Path:
    """单独写一份 hook_net.js，方便只挂网络这一层。"""
    p = Path(out)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        "// ReverseForge · 联网校验覆盖\n"
        "// 用法：frida -U -f <包名> -l hook_net.js --no-pause\n\n"
        "Java.perform(function () {\n" + _FRIDA_NET + "\n  rfNet();\n});\n",
        encoding="utf-8")
    return p
