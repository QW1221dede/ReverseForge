#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""真机收割：内卡密 → 让程序自己跑起来发包 → 把设备现算的真签名收回来。

为什么必须有这一层
------------------
T3 的签名 = 设备私钥对明文 SHA256 的签名，私钥在手机的 keystore/TEE 里，
样本里根本不存在。静态造包只能造出「结构对、签名假」的包，服务器一律回
「错误的调用」。唯一实路是让**能通过验证的程序自己发一次**，我们把它发出的
请求（含真签名）整段收下来，或者让它替我们签任意明文。

用户口径：
    「依靠破解版内卡密，运行时候肯定会发包，然后你绕过的这个经过更改的包
      自动拿到内部签名不就解决了」

三条收割通道（按可靠性排序）
----------------------------
1. frida hook（首选）：拦 HttpURLConnection / OkHttp 的请求，拿到 URL、头、体、
   响应；同时拦 java.security.Signature.initSign / sign 和 Mac.doFinal，
   记下 (明文 → 签名) 对，并通过 rpc 暴露 sign(bytes) 让程序替我们签任意明文。
2. logcat：程序自己打印的 url/token/sign 也行，弱但零依赖。
3. 离线抓包：用户用 mitmproxy/Charles/VPN 抓下来的文本直接喂进来解析
   （无真机、无 root 也能用，这条是纯本地的）。

纪律
----
- 没有设备 / 没有 frida / 没有 root，一律如实写「未执行」，不冒充成功。
- 写卡密走 /data/local/tmp（shell 可写），要写应用私有目录才需要 su。
- 抓到的签名带来源（header / body / runtime-sign），回填时不混。
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from .replay import Harvest, _extract_signatures, _norm

# --------------------------------------------------------------------------
# 一、内卡密：从破解版/样本里挖出可用的卡密字面量
# --------------------------------------------------------------------------

# 卡密常见形态：32 hex / UUID / 20~24 位混合字符 / 带分隔符的长串
_RE_CARD_LITERAL = re.compile(
    r"""(?<![A-Za-z0-9])
        ([A-Za-z0-9]{16,40}(?:-[A-Za-z0-9]{4,20}){0,4})
        (?![A-Za-z0-9])""", re.X)
_RE_CARD_KV = re.compile(
    r"""(?i)(?:kami|card[_-]?key|cardkey|card|licen[cs]e|activation|auth[_-]?code
         |激活码|卡密|授权码)\s*["']?\s*[:=]\s*["']?
        ([A-Za-z0-9\-_]{8,64})""", re.X)
_RE_CARD_FILE = re.compile(r"(?i)(?:\.card$|card\.txt$|kami.*\.txt$|license.*\.txt$)")
# 明显不是卡密的东西（符号前缀、纯版本号）；哈希单独整串判断，不能前缀命中
_RE_NOT_CARD = re.compile(r"(?i)^(?:com\.|android\.|java\.|javax\.|okhttp|http|www\."
                          r"|[0-9]+(?:\.[0-9]+)+$)")
_RE_HASH = re.compile(r"(?i)^[0-9a-f]{32,64}$")


@dataclass
class CardKey:
    """一条候选卡密。"""
    value: str
    source: str = ""          # 文件名:偏移 / 字段名
    score: int = 0
    note: str = ""

    def row(self) -> str:
        return f"[{self.score:>3}] {self.value[:48]:<48} {self.source[:54]}"


def _card_score(value: str, hooked: bool) -> int:
    """卡密打分：越像「人发的卡密」分越高。"""
    s = 0
    has_digit = any(c.isdigit() for c in value)
    has_alpha = any(c.isalpha() for c in value)
    has_upper = any(c.isupper() for c in value)
    if 20 <= len(value) <= 32:
        s += 20
    elif 16 <= len(value) < 20 or 32 < len(value) <= 40:
        s += 12
    if has_digit and has_alpha:
        s += 15
    if has_upper and any(c.islower() for c in value):
        s += 10
    if "-" in value:
        s += 6
    if hooked:
        s += 25                                  # 键名就是 kami/card/key
    if _RE_HASH.match(value):
        s -= 8                                   # 纯 md5/sha 大概率是摘要
    if _RE_NOT_CARD.match(value):
        s -= 40
    return s


def _scan_text(text: str, src: str, out: list[CardKey]) -> None:
    seen = {c.value for c in out}
    for m in _RE_CARD_KV.finditer(text):
        v = m.group(1)
        if v not in seen:
            out.append(CardKey(v, f"{src}@{m.start()}", _card_score(v, True),
                               f"键名 {m.group(0)[:24]!r}"))
            seen.add(v)
    for m in _RE_CARD_LITERAL.finditer(text):
        v = m.group(1)
        if v in seen:
            continue
        sc = _card_score(v, False)
        if sc >= 25:
            out.append(CardKey(v, f"{src}@{m.start()}", sc, "裸字面量"))
            seen.add(v)


def find_cards(target: str | Path, *, limit: int = 12,
               max_bytes: int = 96 << 20) -> list[CardKey]:
    """从文件 / 解包目录里挖候选内卡密（破解版通常把能用的卡密内嵌或缓存在内）。"""
    p = Path(target)
    out: list[CardKey] = []
    files: list[Path] = []
    if p.is_dir():
        for f in p.rglob("*"):
            if f.is_file() and f.stat().st_size <= (4 << 20):
                files.append(f)
            if len(files) >= 400:
                break
    elif p.is_file():
        files = [p]
    for f in files:
        try:
            if f.stat().st_size > max_bytes:
                continue
            blob = f.read_bytes()
        except OSError:
            continue
        # 卡密缓存文件：整个文件就是一个卡密
        if _RE_CARD_FILE.search(f.name):
            txt = blob.decode("utf-8", "replace").strip().splitlines()
            for i, line in enumerate(txt[:5]):
                v = line.strip()
                if 8 <= len(v) <= 64 and " " not in v:
                    out.append(CardKey(v, f"{f.name}:{i + 1}",
                                       _card_score(v, True) + 20, "卡密缓存文件"))
        _scan_text(blob.decode("utf-8", "replace"), f.name, out)
    out.sort(key=lambda c: c.score, reverse=True)
    # 去重后取前 limit 条
    uniq: list[CardKey] = []
    seen: set[str] = set()
    for c in out:
        if c.value not in seen:
            uniq.append(c)
            seen.add(c.value)
        if len(uniq) >= limit:
            break
    return uniq


def pick_card(cards: list[CardKey]) -> CardKey | None:
    return cards[0] if cards else None


def guess_package(target: str | Path) -> str:
    """猜包名：优先 aapt，其次在样本/解包目录里正则找 com.xxx.yyy。"""
    p = Path(target)
    aapt = shutil.which("aapt") or shutil.which("aapt.exe")
    if aapt and p.is_file() and p.suffix.lower() == ".apk":
        try:
            r = subprocess.run([aapt, "dump", "badging", str(p)],
                               capture_output=True, timeout=60)
            m = re.search(rb"package: name='([^']+)'", r.stdout or b"")
            if m:
                return m.group(1).decode("utf-8", "replace")
        except (OSError, subprocess.SubprocessError):
            pass
    pat = re.compile(r"\b((?:com|cn|net|org|io)\.[a-z0-9_]+(?:\.[a-z0-9_]+){1,4})\b")
    hits: dict[str, int] = {}
    files = ([p] if p.is_file() else
             [f for f in p.rglob("*") if f.is_file()
              and f.suffix.lower() in (".xml", ".json", ".txt", ".smali", ".sh")
              and f.stat().st_size < (2 << 20)][:300])
    for f in files:
        try:
            txt = f.read_bytes().decode("utf-8", "replace")
        except OSError:
            continue
        for m in pat.finditer(txt):
            hits[m.group(1)] = hits.get(m.group(1), 0) + 1
    if not hits:
        return ""
    return max(hits.items(), key=lambda kv: kv[1])[0]


# --------------------------------------------------------------------------
# 二、frida 脚本：抓请求 + 抓签名 + 让程序替我们签
# --------------------------------------------------------------------------

_HOOK_JS = r"""
// ReverseForge 真机收割 hook（由 rf.fakepacket.live 生成）
// 输出协议：每行以 RF_ 开头，Python 侧 parse_log 直接认。
var TAG = "RF_";
function log(s) { try { console.log(s); } catch (e) {} }
function hex(b) {
  if (b === null) return "";
  var a = [], u = new Uint8Array(b);
  for (var i = 0; i < u.length; i++) a.push(("0" + (u[i] & 255).toString(16)).slice(-2));
  return a.join("");
}
function unhex(s) {
  var a = [];
  for (var i = 0; i + 1 < s.length; i += 2) {
    a.push(parseInt(s.substr(i, 2), 16) << 24 >> 24);
  }
  return Java.array('byte', a);
}

Java.perform(function () {
  // ---------- 1) OkHttp：拦 RealInterceptorChain.proceed ----------
  try {
    var Chain = Java.use("okhttp3.internal.http.RealInterceptorChain");
    Chain.proceed.overload("okhttp3.Request").implementation = function (req) {
      try {
        var u = req.url().toString();
        var m = req.method();
        log(TAG + "REQ " + m + " " + u);
        var hs = req.headers();
        for (var i = 0; i < hs.size(); i++) {
          var h = hs.name(i);
          log(TAG + "HDR " + h + ": " + hs.value(i));
        }
        var body = req.body();
        if (body !== null) {
          try {
            var buf = Java.use("okio.Buffer").$new();
            body.writeTo(buf);
            log(TAG + "BODY " + buf.readUtf8());
          } catch (e2) {}
        }
      } catch (e) { log(TAG + "ERR okhttp " + e); }
      var resp = this.proceed(req);
      try {
        var rb = resp.body();
        if (rb !== null) {
          var peek = rb.peekBody(8192);
          log(TAG + "RESP " + resp.code() + " " + peek.string());
        }
      } catch (e3) {}
      return resp;
    };
    log(TAG + "OK okhttp");
  } catch (e) { log(TAG + "MISS okhttp " + e); }

  // ---------- 2) HttpURLConnection：兜底 ----------
  try {
    var HUC = Java.use("java.net.HttpURLConnection");
    HUC.connect.implementation = function () {
      try { log(TAG + "REQ " + this.getRequestMethod() + " " + this.getURL().toString()); } catch (e) {}
      return this.connect();
    };
    log(TAG + "OK httpurlconnection");
  } catch (e) { log(TAG + "MISS httpurlconnection " + e); }

  // ---------- 3) 签名：拿到私钥就替我们签 ----------
  var KEY = {};                       // alg -> PrivateKey
  try {
    var Sig = Java.use("java.security.Signature");
    Sig.initSign.overload("java.security.PrivateKey").implementation = function (k) {
      try {
        KEY[this.getAlgorithm()] = k;
        log(TAG + "SIGKEY " + this.getAlgorithm());
      } catch (e) {}
      return this.initSign(k);
    };
    Sig.sign.overload().implementation = function () {
      var out = this.sign();
      try { log(TAG + "SIG " + this.getAlgorithm() + " => " + hex(out)); } catch (e) {}
      return out;
    };
    Sig.update.overload("[B").implementation = function (b) {
      try { log(TAG + "SIGIN " + hex(b)); } catch (e) {}
      return this.update(b);
    };
    log(TAG + "OK signature");
  } catch (e) { log(TAG + "MISS signature " + e); }

  // HMAC / 摘要型签名（很多小平台用 Mac.doFinal 当签名）
  try {
    var Mac = Java.use("javax.crypto.Mac");
    Mac.doFinal.overload("[B").implementation = function (b) {
      var out = this.doFinal(b);
      try {
        log(TAG + "SIG hmac-" + this.getAlgorithm() + " => " + hex(out));
        log(TAG + "SIGIN " + hex(b));
      } catch (e) {}
      return out;
    };
    log(TAG + "OK mac");
  } catch (e) { log(TAG + "MISS mac " + e); }

  // ---------- 4) RPC：让程序替任意明文签名 ----------
  rpc.exports = {
    sign: function (alg, hexdata) {
      try {
        if (!KEY[alg]) return "";
        var Sig2 = Java.use("java.security.Signature");
        var s = Sig2.getInstance(alg);
        s.initSign(KEY[alg]);
        s.update(unhex(hexdata));
        return hex(s.sign());
      } catch (e) { log(TAG + "ERR sign " + e); return ""; }
    },
    algs: function () { return Object.keys(KEY); }
  };
  log(TAG + "READY");
});
"""


def hook_js() -> str:
    """返回可直接喂给 frida 的 hook 脚本。"""
    return _HOOK_JS.strip() + "\n"


# --------------------------------------------------------------------------
# 三、抓包解析（离线也能跑：没有设备时用户喂日志/har 进来）
# --------------------------------------------------------------------------

@dataclass
class LiveRequest:
    method: str = ""
    url: str = ""
    headers: dict = field(default_factory=dict)
    body: str = ""
    response: str = ""
    status: int = 0


@dataclass
class SigPair:
    """设备现算的一次签名：明文（hex 或文本）→ 签名值。"""
    alg: str = ""
    plain: str = ""
    signature: str = ""
    mode: str = "sign"        # sign / hmac

    def row(self) -> str:
        return (f"{self.mode:<5}{self.alg[:22]:<22} "
                f"{self.signature[:40]}")


@dataclass
class LiveCapture:
    requests: list[LiveRequest] = field(default_factory=list)
    sigs: list[SigPair] = field(default_factory=list)
    lines: int = 0
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return bool(self.requests or self.sigs)

    def table(self) -> str:
        L = [f"抓包行数：{self.lines}｜请求 {len(self.requests)} 个｜"
             f"签名 {len(self.sigs)} 个"]
        for r in self.requests[:6]:
            L.append(f"  {r.method:<5} {r.url[:96]}")
            if r.status:
                L.append(f"        ← HTTP {r.status} {r.response[:60]!r}")
            if r.body:
                L.append(f"        body {r.body[:80]}")
        for s in self.sigs[:6]:
            L.append("  " + s.row())
        for n in self.notes:
            L.append("  ! " + n)
        return "\n".join(L)


def parse_log(text: str) -> LiveCapture:
    """解析 frida 输出 / logcat / 抓包文本。

    同时兼容三种输入：
      - 本模块 hook 的 RF_ 行（信息最全）
      - 普通 logcat / 抓包文本（只捞 URL、头和签名字段）
      - har / 纯 JSON（走 replay.capture_signatures 的兜底）
    """
    cap = LiveCapture()
    cur: LiveRequest | None = None
    last_plain = ""
    for raw in (text or "").splitlines():
        cap.lines += 1
        line = raw.strip()
        if not line:
            continue
        if "RF_REQ " in line:
            rest = line.split("RF_REQ ", 1)[1].split()
            cur = LiveRequest(method=rest[0] if rest else "",
                              url=rest[1] if len(rest) > 1 else "")
            cap.requests.append(cur)
        elif "RF_HDR " in line and cur is not None:
            kv = line.split("RF_HDR ", 1)[1]
            if ":" in kv:
                k, v = kv.split(":", 1)
                cur.headers[k.strip()] = v.strip()
        elif "RF_BODY " in line and cur is not None:
            body = line.split("RF_BODY ", 1)[1]
            cur.body = (cur.body + body) if cur.body else body
        elif "RF_RESP " in line and cur is not None:
            rest = line.split("RF_RESP ", 1)[1].split(None, 1)
            try:
                cur.status = int(rest[0])
            except (ValueError, IndexError):
                cur.status = 0
            cur.response = rest[1] if len(rest) > 1 else ""
        elif "RF_SIGIN " in line:
            last_plain = line.split("RF_SIGIN ", 1)[1].strip()
        elif "RF_SIG " in line:
            rest = line.split("RF_SIG ", 1)[1]
            if " => " in rest:
                head, sig = rest.split(" => ", 1)
                cap.sigs.append(SigPair(alg=head.strip(), plain=last_plain,
                                        signature=sig.strip(), mode="sign"))
        elif re.search(r"(https?://[^\s\"']+)", line):
            m = re.search(r"(https?://[^\s\"']+)", line)
            if m and (cur is None or m.group(1) != cur.url):
                cap.requests.append(LiveRequest(url=m.group(1)))
                cur = cap.requests[-1]
    # 兜底：普通文本里的 token/sign
    if not cap.sigs:
        for h in _extract_signatures(text):
            cap.sigs.append(SigPair(alg=h.field, signature=h.value, mode="text"))
        if cap.sigs:
            cap.notes.append("签名来自文本字段匹配（非 hook）")
    return cap


def harvest(capture: LiveCapture, body: dict | None = None) -> list[Harvest]:
    """把抓到的真签名转成可回填的 Harvest 列表。

    优先级：设备现算的签名（runtime-sign，12）> 程序自己发的头（runtime-header，10）
    > 响应里的 token（json，8）> 文本匹配（log，6）。
    """
    out: list[Harvest] = []
    seen: set[str] = set()

    def add(fld: str, val: str, src: str, score: int) -> None:
        if not val or fld in seen:
            return
        out.append(Harvest(fld, val, src, score))
        seen.add(fld)

    # 1) 设备现算签名：签名值 + 对应摘要
    for s in capture.sigs:
        if s.mode == "sign" and s.signature:
            add("signature", s.signature, "runtime-sign", 12)
            if s.plain and re.fullmatch(r"[0-9a-fA-F]{64}", s.plain):
                add("plaintext_sha256", s.plain.lower(), "runtime-sign", 12)
            break

    # 2) 程序自己发出去的请求里带的签名头/字段（最真）
    for r in capture.requests:
        for k, v in (r.headers or {}).items():
            nk = _norm(k)
            if (nk.endswith("sign") or nk.endswith("signature")
                    or nk.endswith("token") or nk in
                    ("authorization", "timestampsign", "nonce", "sessionid")):
                add(k, v, "runtime-header", 10)
        if r.body:
            try:
                obj = json.loads(r.body)
            except ValueError:
                obj = None
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if _norm(k) in ("timestampsign", "sign", "signature", "token",
                                    "plaintextsha256", "nonce", "statecode",
                                    "kami", "card"):
                        add(k, str(v), "runtime-body", 9)

    # 3) 响应里的会话/令牌
    for r in capture.requests:
        if r.response:
            for h in _extract_signatures(r.response):
                add(h.field, h.value, "runtime-response", 8)

    # 4) 文本兜底
    if not out:
        for s in capture.sigs:
            add(s.alg or "signature", s.signature, "runtime-text", 6)
    return out


def merge_into_body(body: dict, sigs: list[Harvest]) -> tuple[dict, dict]:
    """签名按来源分流：头类进 headers，其余进 body。"""
    b = dict(body or {})
    h: dict[str, str] = {}
    for s in sigs:
        low = s.field.lower()
        if s.source in ("runtime-header", "header", "capture-header") or \
                low.startswith("x-") or low in ("authorization", "cookie"):
            h[s.field] = s.value
        else:
            b[s.field] = s.value
    return b, h


# --------------------------------------------------------------------------
# 四、设备侧编排（adb / frida）
# --------------------------------------------------------------------------

def _adb() -> str | None:
    try:
        from ..tools.registry import registry
        t = registry().get("adb")
        if t and getattr(t, "available", False):
            return t.path
    except Exception:                                    # noqa: BLE001
        pass
    return shutil.which("adb") or shutil.which("adb.exe")


def devices() -> list[str]:
    adb = _adb()
    if not adb:
        return []
    try:
        r = subprocess.run([adb, "devices"], capture_output=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return []
    out = []
    for line in r.stdout.decode("utf-8", "replace").splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            out.append(parts[0])
    return out


def _shell(serial: str, cmd: str, timeout: int = 25) -> tuple[int, str]:
    adb = _adb()
    if not adb:
        return -1, "adb 不可用"
    pre = [adb] + (["-s", serial] if serial else []) + ["shell"]
    try:
        r = subprocess.run(pre + [cmd], capture_output=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as e:
        return -1, f"{type(e).__name__}: {e}"
    txt = (r.stdout or b"").decode("utf-8", "replace") + \
          (r.stderr or b"").decode("utf-8", "replace")
    return r.returncode, txt.strip()


def install_card(serial: str, card: str,
                 path: str = "/data/local/tmp/dfm.card") -> tuple[bool, str]:
    """把卡密写到设备缓存位置。先试普通 shell，不行再试 su。"""
    if not card:
        return False, "没给卡密"
    safe = card.replace("'", "").replace('"', "")
    cmd = f"printf '%s' '{safe}' > {path}"
    rc, out = _shell(serial, cmd)
    if rc == 0:
        rc2, chk = _shell(serial, f"cat {path}")
        if chk.strip() == safe:
            return True, f"{path}（{len(safe)} 字节，回读一致）"
        return False, f"写入后回读不一致：{chk[:60]!r}"
    rc3, out3 = _shell(serial, f"su -c \"{cmd}\"")
    if rc3 == 0:
        return True, f"{path}（经 su 写入）"
    return False, f"写卡密失败：{out[:80] or out3[:80]}"


def launch(serial: str, package: str) -> tuple[bool, str]:
    """启动应用（monkey 优先，失败退回 am start）。"""
    if not package:
        return False, "没给包名"
    rc, out = _shell(serial,
                     f"monkey -p {package} -c android.intent.category.LAUNCHER 1")
    if rc == 0 and "No activities found" not in out:
        return True, "monkey 启动"
    rc2, out2 = _shell(serial,
                       f"am start -n {package}/$(cmd package resolve-activity "
                       f"--brief {package} | tail -n 1 | cut -d/ -f2)")
    if rc2 == 0 and "Error" not in out2:
        return True, "am start 启动"
    return False, (out or out2)[:120]


def frida_available() -> tuple[bool, str]:
    """frida 可用性：先看 CLI，再看 python 模块。"""
    cli = shutil.which("frida") or shutil.which("frida.exe")
    if cli:
        return True, cli
    try:
        import frida  # noqa: F401
        return True, "python-frida"
    except Exception:                                    # noqa: BLE001
        return False, ""


@dataclass
class LiveReport:
    ok: bool = False
    mode: str = ""                     # frida / logcat / offline
    steps: list[tuple[str, bool, str]] = field(default_factory=list)
    capture: LiveCapture = field(default_factory=LiveCapture)
    harvested: list[Harvest] = field(default_factory=list)
    note: str = ""
    log_path: str = ""

    def step(self, name: str, ok: bool, detail: str = "") -> None:
        self.steps.append((name, ok, detail))

    def table(self) -> str:
        L = [f"模式：{self.mode or '未执行'}"]
        for name, ok, detail in self.steps:
            L.append(f"  {'✓' if ok else '×'} {name}" + (f" —— {detail}" if detail else ""))
        L.append("")
        L.append(self.capture.table() if self.capture.lines else "（无抓包内容）")
        L.append("")
        L.append("收割到的真签名：" if self.harvested else "没有收割到签名")
        for h in self.harvested:
            L.append("  " + h.row())
        if self.note:
            L += ["", f"结论：{self.note}"]
        return "\n".join(L)


def run_live(serial: str = "", package: str = "", card: str = "",
             seconds: int = 25,
             card_path: str = "/data/local/tmp/dfm.card",
             log_file: str | Path | None = None) -> LiveReport:
    """真机跑一轮：写卡密 → 起 frida → 启动应用 → 收日志 → 解析。

    没有设备或没有 frida 时不会假装成功，steps 里逐条写清原因。
    """
    rep = LiveReport()

    # 0) 离线模式：给了日志就直接解析，不需要设备
    if log_file:
        p = Path(log_file)
        if not p.exists():
            rep.note = f"日志不存在：{p}"
            return rep
        rep.mode = "offline"
        rep.capture = parse_log(p.read_text("utf-8", "replace"))
        rep.harvested = harvest(rep.capture)
        rep.ok = bool(rep.harvested)
        rep.note = ("离线解析完成" if rep.ok else "日志里没找到签名")
        rep.step("读取抓包/日志", True, str(p))
        return rep

    devs = devices()
    if not devs:
        rep.mode = ""
        rep.note = "没有连接的 Android 设备（adb devices 为空）——未执行"
        rep.step("检测设备", False, "adb devices 无设备")
        return rep
    serial = serial or devs[0]
    rep.step("检测设备", True, serial)

    if card:
        ok, detail = install_card(serial, card, card_path)
        rep.step("写入内卡密", ok, detail)
        if not ok:
            rep.note = "卡密没写进去，程序仍会判定未授权"
            return rep
    else:
        rep.step("写入内卡密", True, "跳过（未提供，用设备已有授权）")

    okf, frida = frida_available()
    if not okf:
        rep.mode = "logcat"
        rep.step("frida", False, "未安装（pip install frida-tools）——退回 logcat")
        _shell(serial, "logcat -c")
        if package:
            lok, ldetail = launch(serial, package)
            rep.step("启动应用", lok, ldetail)
        time.sleep(max(3, min(seconds, 60)))
        rc, txt = _shell(serial, "logcat -d -t 4000")
        rep.capture = parse_log(txt)
        rep.harvested = harvest(rep.capture)
        rep.ok = bool(rep.harvested)
        rep.note = ("logcat 里收到了签名字段" if rep.ok else
                    "logcat 里没有签名 —— 装 frida 才能拦到请求体和签名")
        return rep

    rep.mode = "frida"
    js = Path(log_file).parent / "rf_hook.js" if log_file else \
        Path.cwd() / "rf_hook.js"
    try:
        js.write_text(hook_js(), encoding="utf-8")
    except OSError:
        js = Path("rf_hook.js")
        js.write_text(hook_js(), encoding="utf-8")
    out = js.with_suffix(".log")
    if not package:
        rep.step("启动应用", False, "没给包名，frida 无法 attach 新进程")
        rep.note = "缺包名"
        return rep
    cmd = [frida, "-U", "-f", package, "-l", str(js), "-o", str(out), "-q"]
    if serial:
        cmd = [frida, "-D", serial, "-f", package, "-l", str(js),
               "-o", str(out), "-q"]
    rep.step("frida 注入", True, " ".join(cmd[:4]))
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
        time.sleep(max(5, min(seconds, 180)))
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
    except (OSError, subprocess.SubprocessError) as e:
        rep.step("frida 注入", False, f"{type(e).__name__}: {e}")
        rep.note = "frida 启动失败"
        return rep
    text = out.read_text("utf-8", "replace") if out.exists() else ""
    rep.log_path = str(out)
    rep.capture = parse_log(text)
    rep.harvested = harvest(rep.capture)
    rep.ok = bool(rep.harvested)
    rep.step("解析日志", rep.capture.lines > 0, f"{rep.capture.lines} 行")
    rep.note = ("收割成功" if rep.ok else
                "hook 没抓到签名：确认应用是 Java/OkHttp 实现、frida-server 已起、"
                "并且跑到了验证那一步")
    return rep


def render_live_script(target: str, package: str = "", card: str = "",
                       serial: str = "") -> str:
    """生成可独立运行的真机收割脚本（默认不跑，改参数后自己执行）。"""
    return "\n".join([
        "#!/usr/bin/env python3",
        "# -*- coding: utf-8 # -*-",
        '"""真机内卡密收割（ReverseForge 生成）',
        "",
        "用法：",
        "  1. 手机连上、开 USB 调试，frida-server 已起（推荐）",
        "  2. 填好下面的 SERIAL / PACKAGE / CARD",
        "  3. python 真机收割.py",
        "产物：已签名请求包.json / 已签名请求头.json / 真机收割报告.md",
        '"""',
        "import json, sys, os",
        "sys.path.insert(0, " + json.dumps(str(Path(__file__).resolve().parents[2])) + ")",
        "from rf.fakepacket.live import run_live, merge_into_body",
        "",
        "SERIAL = " + json.dumps(serial, ensure_ascii=False),
        "PACKAGE = " + json.dumps(package, ensure_ascii=False),
        "CARD = " + json.dumps(card, ensure_ascii=False),
        "TARGET = " + json.dumps(target, ensure_ascii=False),
        "",
        "rep = run_live(SERIAL, PACKAGE, CARD, seconds=30)",
        "print(rep.table())",
        "body, headers = merge_into_body({}, rep.harvested)",
        "with open('已签名请求包.json', 'w', encoding='utf-8') as f:",
        "    json.dump(body, f, ensure_ascii=False, indent=2)",
        "with open('已签名请求头.json', 'w', encoding='utf-8') as f:",
        "    json.dump(headers, f, ensure_ascii=False, indent=2)",
        "print('OK' if rep.ok else '未收割到签名')",
    ])
