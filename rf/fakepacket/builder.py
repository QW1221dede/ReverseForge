#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""假包构造：按判定出的协议，造「请求包 / 响应包 / 发包时序」三种产物。"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .clues import ClueChain
    from .protocol import Proto


@dataclass
class Packet:
    kind: str          # request / response / timing / local
    name: str
    content: str
    note: str = ""
    score: int = 0

    @property
    def size(self) -> int:
        return len(self.content.encode("utf-8"))

    def row(self) -> str:
        return f"{self.kind:<9} {self.name:<34} {self.size:>7}B  {self.note[:46]}"


# 响应判决字段只出现在假响应包里，不该发上去 ——
# 把 statecode=200 发给服务器，等于告诉它「我这边验证通过了」，直接被识破。
_RESPONSE_FIELDS = {"statecode", "state_code", "code", "status", "success", "msg"}


def _json_body(proto: "Proto") -> str:
    body: dict[str, object] = {}
    for k, v in proto.fields.items():
        if k in _RESPONSE_FIELDS:
            continue
        elif k in ("sign", "signature", "timestampsign", "nonce", "token",
                   "secret", "appkey", "app_key", "plaintext_sha256"):
            body[k] = "<伪造签名：按样本算法填>"
        elif k in ("machine", "device", "deviceid", "device_id", "imei", "uuid",
                   "machine_code", "fingerprint"):
            body[k] = "<设备指纹：从样本抓一个真值>"
        elif k in ("kami", "card", "cardkey", "card_key", "cdkey", "license"):
            body[k] = "<假卡密：按格式造，如 DFM-CARD-2-XXXX>"
        else:
            body[k] = "<按样本填>"
    return json.dumps(body, ensure_ascii=False, indent=2)


def _request(proto: "Proto", chain: "ClueChain") -> Packet | None:
    if not proto.endpoint or proto.endpoint.startswith("（"):
        return None
    body = _json_body(proto)
    lines = [
        f"# 假请求包 · {proto.name}",
        f"# 生成时间：{time.strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        f"{proto.method} {proto.endpoint} HTTP/1.1",
        "Host: " + proto.endpoint.split("//")[-1].split("/")[0],
        "Content-Type: application/json; charset=utf-8",
        "User-Agent: <照抄样本里的 UA，没有就用 Termux 默认>",
        f"Content-Length: {len(body.encode('utf-8'))}",
        "",
        body,
        "",
        "# 说明：",
        f"#   {proto.note}",
        f"#   成功判定：{proto.success_rule}",
    ]
    return Packet("request", "假请求包.http", "\n".join(lines),
                  f"骗 {proto.endpoint[:34]}", proto.score)


def _response(proto: "Proto", chain: "ClueChain") -> Packet:
    succ = _first_success(chain)
    fields = proto.fields
    # 判决字段要按协议选：T3 平台就是 statecode，别拿通用 code 糊弄 ——
    # 字段顺序里 code 常在 statecode 前面，next() 会选错，服务器不认。
    preferred = ("statecode", "state_code") if "T3" in proto.name else (
        "code", "statecode", "status", "success")
    code_key = next((k for k in preferred if k in fields),
                    next((k for k in fields
                          if k in ("code", "statecode", "status", "success")),
                         "statecode"))
    body = {
        code_key: 200,
        "msg": succ or "验证成功",
        "session": "<伪造会话 ID>",
        "vip": True,
        "exp": 4102444800,
    }
    # 字段用样本里真实出现的名字，别用通用名糊弄
    if "kami" in fields:
        body["kami"] = "<回显假卡密>"
    txt = json.dumps(body, ensure_ascii=False, indent=2)
    return Packet(
        "response", "假响应包.json", txt,
        f"骗客户端：{code_key}=200 / {succ or '验证成功'}", proto.score)


def _first_success(chain: "ClueChain") -> str:
    cs = chain.of("success")
    return cs[0].text[:60] if cs else ""


def _timing(proto: "Proto", chain: "ClueChain") -> Packet:
    hb = chain.of("heartbeat")
    period = ""
    for c in hb:
        if any(w in c.text.lower() for w in ("30", "60", "120", "分钟", "minute")):
            period = c.text[:80]
            break
    return Packet(
        "timing", "发包时序.md",
        "\n".join([
            "# 什么时候发假包",
            "",
            f"协议：{proto.name}",
            f"时序：{proto.timing}",
            "",
            "## 三个时机",
            "",
            "1. **启动验证**：程序打印「正在验证卡密」时立刻发第一个假包，"
            "必须在它读本地缓存之前。",
            "2. **心跳维持**：" + (f"样本里抓到心跳线索「{period}」——"
                                "按这个周期重发，否则会被服务器踢下线。" if period else
                                "没抓到明确周期，先按 60 秒发一次，观察掉线时间再调。"),
            "3. **失败重试**：服务器返回失败时别立刻重发（容易触发风控），"
            "等下一个心跳周期。",
            "",
            "## 签名怎么来（最容易被卡死的一步）",
            "",
            "样本里有 timestampsign / signature / 设备证书（tecop-device-key、PEM）线索，"
            "说明服务器要验签，光编个 JSON 发过去会被直接拒。两条路：",
            "",
            "1. **拿真的**：在手机上正常登录一次，用抓包把这个请求原样抓下来，"
            "把 kami 换成假卡密重放 —— 签名对设备+时间戳有效，短期内能过。",
            "2. **本地绕**：不改请求，改客户端收到的响应（假响应包），"
            "这条路不碰服务器签名，成功率最高，优先试。",
            "",
            "## 顺序（关键）",
            "",
            "先发请求假包探服务器 → 看它回什么 → 再用假响应包把客户端的判决改掉。"
            "顺序反了会被服务器端的会话状态识破。",
        ]),
        "启动 / 心跳 / 重试", proto.score)


def _local(proto: "Proto", chain: "ClueChain") -> Packet | None:
    path = proto.fields.get("卡密文件") or _first_card_path(chain)
    if not path:
        return None
    return Packet(
        "local", "本地缓存假包.txt",
        "\n".join([
            f"# 本地卡密缓存：{path}",
            "",
            "1. 在手机上先正常跑一次，让程序生成缓存文件。",
            "2. 把那个文件拷出来，用工具箱的「解密」页试解"
            "（这类常是 AES-GCM + 设备指纹派生密钥）。",
            "3. 解出卡密明文后，按假请求包里的格式改掉再写回去。",
            "4. 若解不开，走响应假包：让读缓存后的验证分支恒真。",
        ]),
        path, proto.score)


def _first_card_path(chain: "ClueChain") -> str:
    """卡密路径优先带 card/key/license 的，别拿 netns 这种系统路径糊弄。"""
    for c in chain.of("card_path"):
        if any(w in c.text.lower() for w in ("card", "key", "license", "cdkey")):
            return c.text
    cs = chain.of("card_path")
    return cs[0].text if cs else ""


def build(chain: "ClueChain", protocols: list["Proto"]) -> list[Packet]:
    """按最优协议造包，同时给次优协议留备选响应包。"""
    if not protocols:
        return []
    best = protocols[0]
    out: list[Packet] = []
    r = _request(best, chain)
    if r:
        out.append(r)
    out.append(_response(best, chain))
    out.append(_timing(best, chain))
    lp = _local(best, chain)
    if lp:
        out.append(lp)
    # 次优协议只给响应包，避免包太多把人绕晕
    for alt in protocols[1:2]:
        ap = _response(alt, chain)
        ap.name = f"备选_{alt.name[:12]}.json"
        ap.note = f"备选方案：{alt.name}"
        out.append(ap)
    return out


def render_script(proto: "Proto", packets: list[Packet]) -> str:
    """把假包串成可直接改的发包脚本（Python，标准库，手机/PC 都能跑）。"""
    req = next((p for p in packets if p.kind == "request"), None)
    resp = next((p for p in packets if p.kind == "response"), None)
    return "\n".join([
        "#!/usr/bin/env python3",
        "# -*- coding: utf-8 -*-",
        f'"""假包发包脚本 · {proto.name}',
        "",
        "用法：",
        "  1. 先把 假响应包.json 里的字段按服务器真实响应调好",
        "  2. DRY=1 只打印不发送，确认无误后去掉 DRY",
        "  3. 心跳周期见 发包时序.md，别发太频繁",
        '"""',
        "",
        "import json, os, sys, urllib.request",
        "",
        "DRY = os.environ.get('DRY', '1') == '1'",
        f"URL = {json.dumps(proto.endpoint, ensure_ascii=False)}",
        "",
        "# 请求体：跟假请求包同一份，响应字段不能混进请求",
        "BODY = " + json.dumps(json.loads(_json_body(proto)),
                              ensure_ascii=False, indent=4),
        "",
        "def send():",
        "    data = json.dumps(BODY, ensure_ascii=False).encode()",
        "    req = urllib.request.Request(",
        "        URL, data=data,",
        "        headers={'Content-Type': 'application/json; charset=utf-8'},",
        "        method='POST')",
        "    if DRY:",
        "        print('[DRY] POST', URL, json.dumps(BODY, ensure_ascii=False))",
        "        return",
        "    with urllib.request.urlopen(req, timeout=15) as r:",
        "        print('状态', r.status, '响应', r.read().decode('utf-8', 'replace')[:300])",
        "",
        "if __name__ == '__main__':",
        "    send()",
        "",
        f"# 成功判定：{proto.success_rule}",
        f"# {proto.note if resp else ''}",
    ])
