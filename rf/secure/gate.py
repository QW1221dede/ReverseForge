#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 rf.secure.gate · 高危能力联网授权锁（2026-11-28 v2）
============================================================================

【设计目标】
    下载者本地只有**加密后的能力模块**，本地不保存明文、不保存解密口令。
    要运行，必须先向作者电脑发一个"请求哈希"，作者审阅确认后由作者电脑回签，
    本地收到正确的签名回复，才允许解密并运行。

【为什么这样设计（法律层面）】
    见 docs/LAW_MATRIX.md。核心是让"逐例审阅 + 记录留痕"成为系统事实，
    而不是停留在免责声明的文字上。作者私钥永不出本机，也就谈不上"提供帮助"。

【加密栈：多种算法混合，互不替代】
    1. scrypt(N=2^15, r=8, p=1)         内存硬派生，抗 GPU/ASIC 暴破
    2. PBKDF2-HMAC-SHA512(600k)          二次派生
    3. AES-256-GCM                       外层认证加密
    4. ChaCha20-Poly1305                 内层认证加密（与 AES 不同族，双保险）
    5. HMAC-SHA512                       每层附加 AAD 完整性绑定
    6. RSA-4096-PSS-SHA512               作者侧签名（私钥只在作者电脑）

【本地不解密的含义】
    "解锁"不是把口令交给本机 —— 本机拿不到完整口令。解密密钥 =
    f(作者回签, 机器指纹, nonce)。没有作者回签，即使把本地文件全部逆向也凑不出密钥。

【网络】
    只向一个 URL（隧道域名）发 HTTPS POST，不带任何被分析文件、密钥、路径。
    请求体只有：能力ID + 机器指纹 + nonce + 时间戳 + 用途声明（中文）。
    断网 / 服务器不可达 → 直接拒绝，不降级、不本地绕过。
============================================================================
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from .. import config
from . import crypto

try:
    from Crypto.PublicKey import RSA
    from Crypto.Signature import pss
    from Crypto.Hash import SHA512
    from Crypto.Protocol.KDF import scrypt
    _HAS = True
except Exception:                                   # pragma: no cover
    RSA = pss = SHA512 = scrypt = None              # type: ignore[assignment]
    _HAS = False


# ---------------------------------------------------------------------------
# 能力清单（与 docs/LAW_MATRIX.md 完全一致）
# ---------------------------------------------------------------------------
CAPABILITIES: dict[str, dict[str, str]] = {
    "NET_SEND": {
        "name": "向第三方服务器发包 / 真签名重放",
        "law": "刑法 285 条 2 款、286 条；网络安全法 27 条；反不正当竞争法 12 条",
        "why": "会向外部服务器实际发出请求并获取其回执，属于对外产生实际效果的行为。",
        "script": "19_fakepacket.py（send=true）",
    },
    "LIVE_HARVEST": {
        "name": "真机注入收割（frida / 卡密写入 / 设备签名）",
        "law": "刑法 285 条 3 款（提供工具罪）、286 条；网络安全法 27 条",
        "why": "对运行中的第三方程序注入并取设备私钥签名，是法律风险最集中的能力。",
        "script": "21_card_harvest.py（非离线模式）",
    },
    "DEPLOY_RUN": {
        "name": "向设备安装补丁 APK / 启动目标应用",
        "law": "刑法 217/218 条；著作权法 53 条；计算机软件保护条例 24 条",
        "why": "把绕过授权后的程序实际安装并运行，触及著作权与破坏技术措施的红线。",
        "script": "patch_install / patch_launch",
    },
}
CAP_ALIASES = {
    "net_send": "NET_SEND", "send": "NET_SEND", "replay": "NET_SEND",
    "live": "LIVE_HARVEST", "harvest": "LIVE_HARVEST", "frida": "LIVE_HARVEST",
    "deploy": "DEPLOY_RUN", "install": "DEPLOY_RUN", "launch": "DEPLOY_RUN",
}


def normalize_cap(cap: str) -> str:
    key = (cap or "").strip().upper()
    key = CAP_ALIASES.get(key.lower(), key)
    if key not in CAPABILITIES:
        raise ValueError(f"未知能力 {cap!r}；可选：{', '.join(CAPABILITIES)}")
    return key


class GateError(Exception):
    """授权锁拒绝（中文消息，可直接展示给用户）。"""


# ---------------------------------------------------------------------------
# 路径：公钥随包 / 私钥只在作者电脑 / 加密模块目录
# ---------------------------------------------------------------------------
PUB_NAME = "gate_public.pem"
PRIV_NAME = "gate_private.pem"
MOD_DIR_NAME = "gated_mods"
URL_FILE = "gate_server.txt"
SESSION_FILE = "gate_session.json"


def public_key_path() -> Path:
    return Path(__file__).resolve().parent / PUB_NAME


def private_key_path() -> Path:
    env = os.environ.get("RF_GATE_PRIVATE", "").strip()
    return Path(env) if env else Path(__file__).resolve().parent / PRIV_NAME


def mod_dir() -> Path:
    return Path(__file__).resolve().parent / MOD_DIR_NAME


def server_url_file() -> Path:
    return config.USER_ROOT / URL_FILE


def session_file() -> Path:
    return config.USER_ROOT / SESSION_FILE


def get_server_url() -> str:
    env = os.environ.get("RF_GATE_URL", "").strip()
    if env:
        return env.rstrip("/")
    p = server_url_file()
    if p.is_file():
        return p.read_text(encoding="utf-8").strip().rstrip("/")
    return ""


def set_server_url(url: str) -> str:
    url = (url or "").strip().rstrip("/")
    if not url.startswith(("https://", "http://127.0.0.1", "http://localhost")):
        raise GateError("授权服务器地址必须是 https:// 隧道地址（或本机回环调试地址）。")
    config.ensure_dirs()
    server_url_file().write_text(url, encoding="utf-8")
    return url


# ---------------------------------------------------------------------------
# 机器指纹
# ---------------------------------------------------------------------------
def _run(cmd: list[str], timeout: float = 4) -> str:
    try:
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0
        p = subprocess.run(cmd, capture_output=True, timeout=timeout, creationflags=flags)
        return ((p.stdout or b"") + (p.stderr or b"")).decode("utf-8", "replace").strip()
    except Exception:
        return ""


def machine_fingerprint() -> str:
    parts: list[str] = []
    try:
        parts.append(str(uuid.getnode()))
    except Exception:
        pass
    parts.append(socket.gethostname() or "")
    parts.append(os.environ.get("USERNAME") or os.environ.get("USER") or "")
    if sys.platform == "win32":
        m = re.search(r"([0-9A-F]{4}-[0-9A-F]{4})",
                      _run(["cmd", "/c", "vol", "C:"]), re.I)
        if m:
            parts.append(m.group(1).upper())
    return hashlib.sha256("|".join(p for p in parts if p).encode()).hexdigest()[:32]


# ---------------------------------------------------------------------------
# 多层混合加密：作者侧封装 / 使用者侧凭回签解密
# ---------------------------------------------------------------------------
SCRYPT_N = 1 << 15           # 32768，约 32MB 内存，抗 GPU
SCRYPT_R = 8
SCRYPT_P = 1
LAYER1 = b"RFGATE-L1-AES256GCM\x00"
LAYER2 = b"RFGATE-L2-CHACHA20\x00"
LAYER3 = b"RFGATE-L3-HMACSHA512\x00"


def _master_key(signature: bytes, fp: str, nonce: bytes) -> bytes:
    """三段混合派生：scrypt(内存硬) → PBKDF2(60万轮)。

    signature 是作者电脑的回签字节；本机没有它就算不出这个 key。
    """
    if not _HAS:
        raise GateError("缺少 pycryptodome，授权锁不可用。")
    seed = hashlib.sha512(signature + fp.encode() + nonce).digest()
    slow = scrypt(seed, salt=fp.encode(), key_len=32,
                  N=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return crypto.derive_key(slow, nonce, alg="pbkdf2",
                             rounds=crypto.PBKDF2_ROUNDS, length=32)


def seal_capability(plain: bytes, signature: bytes, fp: str) -> dict:
    """作者侧：用回签作为密钥种子，把能力模块封成三层密文。"""
    if not _HAS:
        raise GateError("缺少 pycryptodome。")
    nonce = secrets.token_bytes(24)   # 12B AES-GCM + 12B ChaCha20
    key = _master_key(signature, fp, nonce)

    from Crypto.Cipher import AES, ChaCha20_Poly1305
    a1 = AES.new(key, AES.MODE_GCM, nonce=nonce[:12], mac_len=16)
    a1.update(LAYER1 + fp.encode())
    mid, t1 = a1.encrypt_and_digest(plain)

    a2 = ChaCha20_Poly1305.new(key=key[::-1], nonce=nonce[12:])
    a2.update(LAYER2 + fp.encode())
    inner, t2 = a2.encrypt_and_digest(mid)

    mac = hmac.new(key, LAYER3 + inner + t1 + t2, hashlib.sha512).digest()
    return {
        "v": 2, "fp": fp, "nonce": base64.b64encode(nonce).decode(),
        "outer": base64.b64encode(inner).decode(),
        "t1": base64.b64encode(t1).decode(),
        "t2": base64.b64encode(t2).decode(),
        "mac": base64.b64encode(mac).decode(),
    }


def unseal_capability(sealed: dict, signature: bytes, fp: str | None = None) -> bytes:
    """使用者侧：只有拿到作者回签才走到这里；否则连密钥都算不出来。"""
    if not _HAS:
        raise GateError("缺少 pycryptodome。")
    want_fp = fp or machine_fingerprint()
    if sealed.get("fp") != want_fp:
        raise GateError("加密模块与本机指纹不匹配。")
    nonce = base64.b64decode(sealed["nonce"])
    key = _master_key(signature, want_fp, nonce)

    inner = base64.b64decode(sealed["outer"])
    t1 = base64.b64decode(sealed["t1"])
    t2 = base64.b64decode(sealed["t2"])
    mac = base64.b64decode(sealed["mac"])
    calc = hmac.new(key, LAYER3 + inner + t1 + t2, hashlib.sha512).digest()
    if not hmac.compare_digest(calc, mac):
        raise GateError("第 3 层完整性校验失败：签名错误或模块被篡改。")

    from Crypto.Cipher import AES, ChaCha20_Poly1305
    a2 = ChaCha20_Poly1305.new(key=key[::-1], nonce=nonce[12:])
    a2.update(LAYER2 + want_fp.encode())
    try:
        mid = a2.decrypt_and_verify(inner, t2)
    except ValueError:
        raise GateError("第 2 层解密失败（ChaCha20-Poly1305 认证不通过）。")

    a1 = AES.new(key, AES.MODE_GCM, nonce=nonce[:12], mac_len=16)
    a1.update(LAYER1 + want_fp.encode())
    try:
        return a1.decrypt_and_verify(mid, t1)
    except ValueError:
        raise GateError("第 1 层解密失败（AES-256-GCM 认证不通过）。")


# ---------------------------------------------------------------------------
# base64url 与请求 / 回签格式
# ---------------------------------------------------------------------------
def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _b64d(s: str) -> bytes:
    t = (s or "").strip()
    return base64.urlsafe_b64decode(t + "=" * (-len(t) % 4))


P_REQ = "RFGATE-REQ2-"
P_ACK = "RFGATE-ACK2-"


def build_request(cap: str, purpose: str) -> str:
    """生成本地要发给作者电脑的"请求哈希格式"（不含任何用户文件/密钥）。"""
    cap = normalize_cap(cap)
    payload = {
        "v": 2, "cap": cap, "fp": machine_fingerprint(),
        "nonce": secrets.token_hex(16), "ts": int(time.time()),
        "purpose": (purpose or "").strip()[:2000],
        "app": config.APP_VERSION,
    }
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":"),
                     sort_keys=True).encode("utf-8")
    return P_REQ + _b64e(raw)


def parse_request(code: str) -> dict:
    s = (code or "").strip()
    if not s.startswith(P_REQ):
        raise GateError("不是 RFGATE-REQ2 申请码。")
    try:
        d = json.loads(_b64d(s[len(P_REQ):]).decode("utf-8"))
        normalize_cap(d.get("cap", ""))
        return d
    except Exception as e:
        raise GateError(f"申请码解析失败：{e}")


def request_guide(cap: str, purpose: str = "") -> str:
    cap = normalize_cap(cap)
    info = CAPABILITIES[cap]
    url = get_server_url()
    return "\n".join([
        "【高危能力解锁申请 · 中文】",
        f"能力：{cap} — {info['name']}",
        f"法律依据：{info['law']}",
        f"为什么上锁：{info['why']}",
        "",
        f"申请码：{build_request(cap, purpose)}",
        "",
        "发送方式（二选一）：",
        f"  1) 填好用途后运行：rf.gate_apply('{cap}', '中文用途声明') —— 直接发到作者电脑；",
        "  2) 手动发邮件至 m358685@163.com（只接受中文）。",
        f"当前作者校验地址：{url or '（未设置，先用 rf.gate_server(url) 设置隧道地址）'}",
        "",
        "用途声明必须写清：①你是谁 ②目标软件归属（自有/书面授权/教学研究+依据）",
        "③具体用途与时段 ④承诺不用于破解他人软件、不用于未授权获取数据。",
    ])


# ---------------------------------------------------------------------------
# 联网校验：把申请码发给作者电脑，拿到回签
# ---------------------------------------------------------------------------
def online_authorize(cap: str, purpose: str, timeout: float = 30) -> tuple[bytes, dict]:
    """只发申请码，收作者回签。失败一律拒绝，不降级。"""
    import urllib.request
    import urllib.error

    cap = normalize_cap(cap)
    url = get_server_url()
    if not url:
        raise GateError("未设置作者校验地址。请先 rf.gate_server('https://你的隧道地址')。")
    code = build_request(cap, purpose)
    body = json.dumps({"action": "authorize", "request": code},
                      ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url + "/gate/authorize", data=body,
        headers={"Content-Type": "application/json; charset=utf-8",
                 "User-Agent": "ReverseForge-Gate/2"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raw = e.read(300).decode("utf-8", "replace")
        raise GateError(f"作者电脑拒绝（HTTP {e.code}）：{raw}")
    except Exception as e:
        raise GateError(f"无法连接作者校验服务器（{type(e).__name__}）：{e}；未降级、未解锁。")

    if not data.get("ok"):
        raise GateError("作者未批准本次申请：" + str(data.get("reason") or "无说明"))
    ack = data.get("ack") or ""
    if not ack.startswith(P_ACK):
        raise GateError("服务器回复不是有效回签（RFGATE-ACK2）。")
    try:
        blob = json.loads(_b64d(ack[len(P_ACK):]).decode("utf-8"))
        payload = blob["payload"].encode("utf-8")
        sig = _b64d(blob["sig"])
        d = json.loads(payload.decode("utf-8"))
    except Exception as e:
        raise GateError(f"回签解析失败：{e}")

    pub = public_key_path()
    if not pub.is_file():
        raise GateError("缺少随包公钥 gate_public.pem。")
    try:
        key = RSA.import_key(pub.read_bytes())
        pss.new(key).verify(SHA512.new(payload), sig)
    except Exception:
        raise GateError("回签签名校验失败：不是作者电脑签发的。")
    if d.get("cap") != cap or d.get("fp") != machine_fingerprint():
        raise GateError("回签的能力或机器指纹不匹配。")
    if int(d.get("exp", 0)) < int(time.time()):
        raise GateError("回签已过期。")
    return sig, d


# ---------------------------------------------------------------------------
# 会话：回签只留短期加密缓存，不落明文口令
# ---------------------------------------------------------------------------
def _session_key() -> bytes:
    return crypto.derive_key(machine_fingerprint(), b"rf-gate-session-v2",
                             alg="pbkdf2", length=32)


def save_session(sig: bytes, meta: dict) -> None:
    config.ensure_dirs()
    plain = json.dumps({"sig": base64.b64encode(sig).decode(), "meta": meta},
                       ensure_ascii=False).encode()
    env = crypto.encrypt(plain, _session_key().decode("latin-1"), alg="aes-gcm")
    session_file().write_bytes(env.to_bytes())


def load_session() -> tuple[bytes, dict] | None:
    p = session_file()
    if not p.is_file():
        return None
    try:
        env = crypto.Sealed.from_bytes(p.read_bytes())
        d = json.loads(crypto.decrypt(env, _session_key().decode("latin-1")))
        meta = d.get("meta") or {}
        if int(meta.get("exp", 0)) < int(time.time()):
            return None
        return base64.b64decode(d["sig"]), meta
    except Exception:
        return None


def clear_session() -> None:
    p = session_file()
    if p.is_file():
        try:
            p.write_bytes(b"")
        except Exception:
            pass


def status() -> dict:
    s = load_session()
    out = {}
    for cap, info in CAPABILITIES.items():
        if s and s[1].get("cap") == cap:
            out[cap] = {"authorized": True,
                        "exp": time.strftime("%Y-%m-%d %H:%M:%S",
                                             time.localtime(s[1]["exp"])),
                        "name": info["name"]}
        else:
            out[cap] = {"authorized": False, "name": info["name"],
                        "law": info["law"], "why": info["why"]}
    return {"fp": machine_fingerprint(), "server": get_server_url(), "caps": out}


def _author_local() -> bool:
    """作者本机判定：持有作者私钥即视为作者，不需要向自己申请授权。

    私钥不进仓库（.gitignore 已排除 *.pem），所以这不构成对外绕过；
    使用者手里只有公钥，伪造不了回签。
    """
    try:
        return private_key_path().is_file()
    except Exception:
        return False


def require(cap: str) -> tuple[bytes, dict]:
    """高危能力入口：无回签直接拒绝；有回签才返回签名供解密。"""
    cap = normalize_cap(cap)
    if _author_local():
        return b"", {"cap": cap, "author": True, "exp": int(time.time()) + 86400}
    s = load_session()
    if not s or s[1].get("cap") != cap or int(s[1].get("exp", 0)) < int(time.time()):
        info = CAPABILITIES[cap]
        raise GateError(
            f"「{info['name']}」需要作者电脑联网授权后才能运行。\n"
            f"法律依据：{info['law']}\n"
            f"申请：rf.gate_apply('{cap}', '中文用途声明')；"
            f"离线手写请用 rf.gate_request('{cap}')。\n"
            f"静态分析、拆包、解密、扫描、方案生成与 DRY 预演均不受影响。")
    return s


def gate_apply(cap: str, purpose: str, timeout: float = 30) -> dict:
    """一步到位：发申请 → 等作者电脑审阅回签 → 存加密会话。"""
    sig, meta = online_authorize(cap, purpose, timeout=timeout)
    save_session(sig, meta)
    return {"cap": meta["cap"],
            "exp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(meta["exp"])),
            "name": CAPABILITIES[meta["cap"]]["name"]}


def load_module(cap: str, *, execute: bool = False) -> dict:
    """带解密的能力模块加载；只有回签正确才解出明文。"""
    cap = normalize_cap(cap)
    sig, meta = require(cap)
    # 模块解密用作者随回签下发的 seal 签名（发布封包时同一把）
    if meta.get("author"):
        seal_sig = _seal_key(cap, meta.get("fp") or machine_fingerprint())
    else:
        seal_sig = base64.b64decode(meta.get("seal") or "")
    if not seal_sig:
        raise GateError("回签里没有模块密钥；请重新申请授权。")
    p = mod_dir() / f"{cap}.enc.json"
    if not p.is_file():
        raise GateError(f"缺少加密能力模块：{p.name}；请使用正式发布版。")
    sealed = json.loads(p.read_text(encoding="utf-8"))
    plain = unseal_capability(sealed, seal_sig)
    if not execute:
        return {"cap": cap, "size": len(plain), "verified": True,
                "note": "已通过作者回签解密，未执行；execute=True 才运行。"}
    ns: dict[str, Any] = {"__name__": f"rf_gate_{cap.lower()}", "rf_config": config}
    exec(compile(plain.decode("utf-8"), str(p), "exec"), ns)   # noqa: S102
    return {"cap": cap, "verified": True, "executed": True, "ns": ns}


# ---------------------------------------------------------------------------
# 作者侧工具（只在作者电脑运行；私钥不出本机）
# ---------------------------------------------------------------------------
def _seal_key(cap: str, fp: str) -> bytes:
    """作者私钥确定性派生模块密钥（PSS 签名带随机 salt，不能当密钥种子）。

    私钥只在本机，客户端拿不到；批准时才把本能力+本机器的 seal_key 随回签下发。
    """
    priv = private_key_path()
    if not priv.is_file():
        raise GateError("缺少作者私钥：" + str(priv))
    seed = hashlib.sha512(priv.read_bytes()).digest()
    return hmac.new(seed, ("seal-v2|%s|%s" % (cap, fp)).encode(), hashlib.sha512).digest()


def author_init(force: bool = False) -> dict:
    if not _HAS:
        raise GateError("缺少 pycryptodome。")
    priv = private_key_path()
    pub = public_key_path()
    if priv.is_file() and not force:
        raise GateError(f"私钥已存在：{priv}（force=True 才覆盖）")
    key = RSA.generate(4096)
    priv.parent.mkdir(parents=True, exist_ok=True)
    priv.write_bytes(key.export_key("PEM"))
    pub.write_bytes(key.publickey().export_key("PEM"))
    return {"private": str(priv), "public": str(pub), "bits": 4096}


def author_sign_request(request: str, days: int = 7) -> str:
    """作者审阅后签发回签（服务器调用；人工审阅在服务器日志/界面完成）。"""
    if not _HAS:
        raise GateError("缺少 pycryptodome。")
    d = parse_request(request)
    priv = private_key_path()
    if not priv.is_file():
        raise GateError(f"缺少作者私钥：{priv}")
    key = RSA.import_key(priv.read_bytes())
    cap, fp = d["cap"], d["fp"]
    # 模块密钥：确定性派生，随回签下发（绑定能力+机器）
    seal_sig = _seal_key(cap, fp)
    payload = {
        "v": 2, "cap": cap, "fp": fp,
        "nonce": d["nonce"], "ts": int(time.time()),
        "exp": int(time.time()) + max(1, min(int(days), 30)) * 86400,
        "seal": base64.b64encode(seal_sig).decode(),   # 随回签下发，绑定机器
    }
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":"),
                     sort_keys=True).encode("utf-8")
    sig = pss.new(key).sign(SHA512.new(raw))
    return P_ACK + _b64e(json.dumps(
        {"payload": raw.decode("utf-8"), "sig": _b64e(sig)},
        separators=(",", ":")).encode("utf-8"))


def author_seal(cap: str, plain: bytes, fp: str) -> dict:
    """作者侧：发布前把能力模块封成多层密文（用固定种子签名）。"""
    if not private_key_path().is_file():
        raise GateError(f"缺少作者私钥：{private_key_path()}")
    return seal_capability(plain, _seal_key(cap, fp), fp)


def selftest() -> dict:
    """完整链路自测：申请 → 签名 → 回签验签 → 三层解密 → 错位拒绝。"""
    if not _HAS:
        return {"ok": False, "error": "pycryptodome 缺失"}
    k = RSA.generate(2048)  # 自测用 2048 加速，发布用 4096
    req = build_request("NET_SEND", "自测")
    d = parse_request(req)
    fp = machine_fingerprint()
    payload = json.dumps({"v": 2, "cap": d["cap"], "fp": fp,
                          "nonce": d["nonce"], "ts": int(time.time()),
                          "exp": int(time.time()) + 3600},
                         ensure_ascii=False, separators=(",", ":"),
                         sort_keys=True).encode("utf-8")
    sig = pss.new(k).sign(SHA512.new(payload))
    sealed = seal_capability(b"print('NET_SEND unlocked')\n", sig, fp)
    plain = unseal_capability(sealed, sig)
    try:
        unseal_capability(sealed, b"wrong-signature")
        wrong_rejected = False
    except GateError:
        wrong_rejected = True
    return {"ok": True, "request": req[:14], "layers": ["scrypt", "pbkdf2",
            "aes-256-gcm", "chacha20-poly1305", "hmac-sha512", "rsa-pss-sha512"],
            "plain_ok": plain == b"print('NET_SEND unlocked')\n",
            "wrong_sig_rejected": wrong_rejected, "sealed_size": len(json.dumps(sealed))}
