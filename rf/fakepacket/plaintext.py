#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""明文线索图：把解出来的 ELF/二进制里的可读片段按来源展示。

用户口径「后面还有一大串加密，也没有使用明文展现」—— 这一段专门解决它。
不声称解密，只把本来就是明文、藏在二进制里的字符串抽出来排好：
中文文案 / URL / 协议字段 / 卡密路径 / 成功失败标志，带来源和偏移。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from ..analysis import strings as strmod


@dataclass
class PlaintextMap:
    source: str = ""
    groups: dict[str, list[str]] = None  # type: ignore[assignment]
    total: int = 0

    def __post_init__(self) -> None:
        if self.groups is None:
            self.groups = {}

    def add(self, kind: str, text: str) -> None:
        arr = self.groups.setdefault(kind, [])
        if text not in arr:
            arr.append(text)
            self.total += 1

    def save(self, out_dir: str | Path) -> Path:
        """完整清单落盘：报告只展示前 40 条，这里存全部，想翻随时翻。"""
        od = Path(out_dir)
        od.mkdir(parents=True, exist_ok=True)
        p = od / "明文线索完整清单.txt"
        lines: list[str] = [f"来源：{self.source}", f"共 {self.total} 条", ""]
        for kind, arr in self.groups.items():
            lines += [f"===== {kind}（{len(arr)} 条） =====", ""]
            lines += arr
            lines.append("")
        p.write_text("\n".join(lines), encoding="utf-8")
        return p

    def markdown(self, limit: int = 40) -> str:
        if not self.total:
            return "（没有抽出可读片段，可能整段是真加密）"
        L = [f"来源：`{self.source}`　共 {self.total} 条", ""]
        for kind, arr in self.groups.items():
            L += [f"### {kind}（{len(arr)} 条）", ""]
            for s in arr[:limit]:
                t = s if len(s) <= 110 else s[:107] + "..."
                L.append(f"- `{t}`")
            if len(arr) > limit:
                L.append(f"- ……另有 {len(arr) - limit} 条，见完整清单")
            L.append("")
        return "\n".join(L)


_RE_URL = re.compile(r"https?://[A-Za-z0-9.\-_:]{4,120}/?")
_RE_PATH = re.compile(r"(?:/data/local/tmp/|/sdcard/|/storage/)[A-Za-z0-9_./\-]{3,80}")
_RE_FIELD = re.compile(
    r"(?<![A-Za-z0-9_])(kami|statecode|timestampsign|signature|nonce|"
    r"device_id|device|fingerprint|token|secret|recharge|amount|expire|"
    r"card|license|vip|session|heartbeat|lease)(?![A-Za-z0-9_])",
    re.I)


def build(path: str | Path, *, max_bytes: int = 64 << 20) -> PlaintextMap:
    """从单个文件抽明文片段。大文件按 max_bytes 截断。"""
    p = Path(path)
    pm = PlaintextMap(source=str(p))
    try:
        if p.stat().st_size > max_bytes:
            with p.open("rb") as fh:
                data = fh.read(max_bytes)
        else:
            data = p.read_bytes()
    except OSError:
        return pm

    for s in strmod.extract_cjk(data, min_len=3):
        t = s.strip()
        # 判决/协议类文案优先单列，其它中文（游戏物品、地图名…）归到「内嵌数据」，
        # 避免两万多条把报告撑爆又看不出重点。
        if any(w in t for w in ("卡密", "验证", "授权", "过期", "失效", "设备",
                                "心跳", "登录", "欢迎使用", "未授权", "权限")):
            pm.add("判决提示", t)
        else:
            pm.add("内嵌数据", t)

    # ASCII 里只挑协议相关的，避免 37MB 的 OpenSSL 符号把报告撑爆
    asciis = strmod.extract_ascii(data, min_len=4)
    for s in asciis:
        if len(s) > 160:
            continue
        if _RE_URL.search(s):
            for u in _RE_URL.findall(s):
                if not any(x in u for x in ("googlesource", "github.com", "upx.sf.net")):
                    pm.add("服务器地址", u)
        if _RE_PATH.search(s):
            for x in _RE_PATH.findall(s):
                pm.add("本地路径", x)
        if _RE_FIELD.search(s):
            for f in _RE_FIELD.findall(s):
                pm.add("协议字段", f.lower())

    return pm
