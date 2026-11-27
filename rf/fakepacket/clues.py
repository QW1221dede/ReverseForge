#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""线索提取：从任意文件/目录里捞出「能推出发包方式」的明文片段。

每条线索带来源偏移和证据，跟解密层 Hit 的玩法一致 —— 不靠猜，靠证据打分。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

# 线索种类 → 权重（越能决定发包方式，权重越高）
WEIGHT = {
    "endpoint": 10,      # 服务器地址
    "card_field": 9,     # 卡密字段名
    "status_field": 9,   # 响应判决字段
    "sign_field": 8,     # 签名字段
    "card_path": 8,      # 本地卡密存储路径
    "success": 8,        # 成功标志串
    "failure": 6,        # 失败标志串
    "heartbeat": 7,      # 心跳/定时
    "device": 6,         # 设备指纹/证书
    "secret": 9,         # 密钥/凭据字段名
    "param": 4,          # 其它协议参数
    "vendor": 5,         # 厂商/产品标识
}


@dataclass
class Clue:
    kind: str
    text: str
    source: str = ""
    offset: int = -1
    note: str = ""

    @property
    def weight(self) -> int:
        return WEIGHT.get(self.kind, 2)

    def row(self) -> str:
        loc = f"@0x{self.offset:x}" if self.offset >= 0 else ""
        t = self.text if len(self.text) <= 54 else self.text[:51] + "..."
        return f"{self.kind:<13} {self.weight:>2}  {t:<56} {self.source}{loc}"


@dataclass
class ClueChain:
    source: str = ""
    clues: list[Clue] = field(default_factory=list)
    files_scanned: int = 0
    bytes_scanned: int = 0
    notes: list[str] = field(default_factory=list)

    def add(self, kind: str, text: str, source: str = "",
            offset: int = -1, note: str = "") -> None:
        if any(c.kind == kind and c.text == text for c in self.clues):
            return
        self.clues.append(Clue(kind, text, source, offset, note))

    def of(self, kind: str) -> list[Clue]:
        return [c for c in self.clues if c.kind == kind]

    def has(self, kind: str) -> bool:
        return any(c.kind == kind for c in self.clues)

    @property
    def score(self) -> int:
        return sum(c.weight for c in self.clues)

    def table(self, limit: int = 60) -> str:
        if not self.clues:
            return "（没有找到协议线索）"
        head = f"{'类型':<13} {'权':>2}  {'片段':<56} 来源"
        return "\n".join([head] + [c.row() for c in self.clues[:limit]])

    def summary(self) -> str:
        kinds = {}
        for c in self.clues:
            kinds[c.kind] = kinds.get(c.kind, 0) + 1
        return "；".join(f"{k}×{v}" for k, v in sorted(kinds.items())) or "无线索"


# ---------------------------------------------------------------------------
# 识别规则：都是「证据」，不是「猜」。命中就带偏移落库。
# ---------------------------------------------------------------------------

_RE_URL = re.compile(rb"https?://[A-Za-z0-9.\-_:]{4,120}/?")
_RE_CARD_PATH = re.compile(rb"(?:/data/local/tmp/|/sdcard/|/storage/)[A-Za-z0-9_./\-]{3,80}")
_RE_KV = re.compile(rb"[a-z_]{2,24}")

# 字段名 → 线索类别。这些名字来自真实卡密 SDK（T3 / 易验证 / 自建），
# 命中任何一个都能直接决定假包里要带什么字段。
_FIELD_KIND = {
    "kami": "card_field", "card": "card_field", "cardkey": "card_field",
    "card_key": "card_field", "cdkey": "card_field", "license": "card_field",
    "statecode": "status_field", "state_code": "status_field",
    "status": "status_field", "code": "status_field", "success": "status_field",
    "timestampsign": "sign_field", "timestamp_sign": "sign_field",
    "sign": "sign_field", "signature": "sign_field", "nonce": "sign_field",
    "tecop-device-key": "secret", "device-key": "secret", "pem": "secret",
    "machine": "device", "device": "device", "deviceid": "device",
    "device_id": "device", "imei": "device", "uuid": "device",
    "fingerprint": "device", "machine_code": "device",
    "secret": "secret", "appkey": "secret", "app_key": "secret",
    "token": "secret", "plaintext_sha256": "secret",
    "heartbeat": "heartbeat", "lease": "heartbeat", "session": "heartbeat",
    "recharge": "param", "amount": "param", "msg": "param",
    "exp": "param", "expire": "param", "vip": "param",
}

# 成功/失败文案（中英）。这些直接给出「怎么判断假包生效」。
_SUCCESS_WORDS = (
    "验证成功", "验证通过", "卡密有效", "欢迎使用", "已授权", "认证成功",
    "success", "verified", "authorized", "license ok", "activation ok",
)
_FAILURE_WORDS = (
    "验证失败", "卡密失效", "卡密错误", "设备不匹配", "时间窗口过期",
    "时间过期", "请先登录", "未授权", "无权限", "已过期",
    "invalid license", "verify failed", "unauthorized", "expired",
)
_VENDOR_WORDS = (
    "t3yanzheng", "t3data", "t3卡密", "t3验证", "arrogance", "dfm.card",
)


def _scan_bytes(data: bytes, src: str, chain: ClueChain) -> None:
    # URL
    for m in _RE_URL.finditer(data):
        u = m.group().decode("latin1")
        if any(x in u for x in ("googlesource", "github.com", "upx.sf.net",
                                "source.android.com")):
            continue
        chain.add("endpoint", u, src, m.start(), "服务器地址")

    # 本地卡密/凭据路径
    for m in _RE_CARD_PATH.finditer(data):
        chain.add("card_path", m.group().decode("latin1"), src, m.start(),
                  "本地缓存，可直接造")

    # 可读短串（按 NUL 切，ELF/Rust/Go 的字符串表都这样存）
    for chunk in data.split(b"\x00"):
        if len(chunk) < 3 or len(chunk) > 160:
            continue
        try:
            s = chunk.decode("utf-8")
        except UnicodeDecodeError:
            continue
        low = s.lower().strip()
        if not low:
            continue
        # 整串就是字段名（精确，不做子串匹配）
        bare = low.strip("\"':=,{}[]() ")
        if bare in _FIELD_KIND and len(bare) <= 24:
            chain.add(_FIELD_KIND[bare], s, src, note="协议字段")
        # 长串里只在明确的「键=值 / "键":值 / 键 值」上下文抓字段，
        # 否则 37MB 二进制里的 decode/encode/discard/sdcard 会淹没真字段。
        if len(low) > len(bare):
            for m in re.finditer(
                    r'(?<![A-Za-z0-9_])([a-z_]{2,20})(?="?\s*[:=])([^\s,;]{0,40})',
                    s):
                key = m.group(1).lower()
                if key in _FIELD_KIND:
                    chain.add(_FIELD_KIND[key], m.group(0)[:70], src,
                              note=f"键值上下文 {key}")
                    break
        # 成功/失败标志
        for w in _SUCCESS_WORDS:
            if w in low:
                chain.add("success", s[:80], src, note=f"命中「{w}」")
                break
        for w in _FAILURE_WORDS:
            if w in low:
                chain.add("failure", s[:80], src, note=f"命中「{w}」")
                break
        for w in _VENDOR_WORDS:
            if w in low:
                chain.add("vendor", s[:80], src, note=f"命中「{w}」")
                break


def extract(target: str | Path, *, max_bytes: int = 128 << 20) -> ClueChain:
    """从文件或目录提取线索链。大文件只读前 max_bytes，够用。"""
    p = Path(target)
    chain = ClueChain(source=str(p))
    files: list[Path] = []
    if p.is_dir():
        files = [f for f in sorted(p.rglob("*"))
                 if f.is_file() and not f.name.startswith(".")
                 and not any(x in f.parts for x in ("备份", "__pycache__"))][:600]
    elif p.exists():
        files = [p]
    else:
        chain.notes.append(f"路径不存在：{p}")
        return chain

    for f in files:
        try:
            if f.stat().st_size > max_bytes:
                with f.open("rb") as fh:
                    data = fh.read(max_bytes)
                chain.notes.append(f"{f.name} 超过上限，只读前 {max_bytes}B")
            else:
                data = f.read_bytes()
        except OSError as e:
            chain.notes.append(f"读 {f.name} 失败：{e}")
            continue
        chain.files_scanned += 1
        chain.bytes_scanned += len(data)
        _scan_bytes(data, f.name, chain)

    # 同类型线索按权重和证据长度排，短的排前面（短串更像真字段）
    order = {k: i for i, k in enumerate(WEIGHT)}
    chain.clues.sort(key=lambda c: (-c.weight, order.get(c.kind, 99), len(c.text)))
    # 每类限流：一个 37MB 的 ELF 里几百个 OpenSSL 符号都带 code/sign，
    # 不限流的话线索表几千行，假包字段几百个，全是噪音。
    cap = {"endpoint": 10, "card_field": 12, "status_field": 12,
           "sign_field": 10, "device": 8, "secret": 8, "param": 8,
           "card_path": 8, "success": 8, "failure": 8,
           "heartbeat": 6, "vendor": 6}
    per: dict[str, int] = {}
    kept: list[Clue] = []
    for c in chain.clues:
        n = per.get(c.kind, 0)
        if n >= cap.get(c.kind, 8):
            continue
        per[c.kind] = n + 1
        kept.append(c)
    chain.clues = kept
    return chain
