#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 rf.decrypt.auto · 自动试解（把"这几样加密"一次全撞一遍）
============================================================================

【干什么】
    给它一个文件，它把常见加密全试一遍，把像人话的结果排好队吐出来。
    不保证一定成功——AES-256 没有密钥就是解不开，这是数学，不是努力问题。
    但只要密钥在文件里/在明文中/是弱口令，这里基本都能撞出来。

【试的顺序（便宜的先来）】
    1. 编码层      Base64 / Base32 / Base85 / Hex / zlib / gzip / bz2
                   —— 很多"加密"其实只是编码或压缩，一解就开
    2. 单字节 XOR  256 种全试（外挂和脚本最爱）
    3. 循环 XOR    先猜密钥长度（汉明距离），再按列频率分析求密钥
    4. 密钥 XOR    用候选密钥字符串直接当 key
    5. RC4         用候选密钥试（含 drop=768 变体）
    6. TEA/XXTEA   用 16 字节密钥试（存档、配置常见）
    7. AES         ECB/CBC/CFB/OFB/CTR × 候选密钥 × 候选 IV
                   外加"IV 前置在密文头部"这种常见布局
    8. OpenSSL     Salted__ 头 + 口令（EVP_BytesToKey）
    9. 偏移扫描    前 64 字节逐个当起点（RC4/AES 对起点敏感）

【怎么判断"解对了"】
    两把尺子叠加：
      · 命中标准文件头（ZIP/MZ/ELF/JSON/XML…）→ 直接加 40-45 分
      · 文本可读性（garble.readability）→ 中文常用字、英文词、分词边界
    造假很容易被识破：错误密钥解出来的东西熵接近 8、可读性接近 0。
    所以宁可漏报，不谎报。

【性能】
    打分只看前 64KB，命中之后再对全文重解一次。
    有总时间预算（默认 15 秒，deep=True 时 60 秒），超了就带着已有结果返回。
============================================================================
"""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..analysis import garble, segments
from ..analysis import selfextract as SE
from . import ciphers as C
from . import crib as CR
from . import keys as K

# ---------------------------------------------------------------------------
# 结果
# ---------------------------------------------------------------------------

@dataclass
class Hit:
    method: str = ""
    offset: int = 0
    score: int = 0
    out: bytes = b""
    preview: str = ""
    key: str = ""
    note: str = ""

    @property
    def size(self) -> int:
        return len(self.out)

    def row(self) -> str:
        m = self.method if len(self.method) <= 42 else self.method[:39] + "..."
        return (f"{self.score:>3}  {m:<44} 偏移{self.offset:<5} "
                f"{self.size:>8}B  {self.preview[:40]!r}")

    def save(self, out_dir: str | Path) -> Path:
        od = Path(out_dir)
        od.mkdir(parents=True, exist_ok=True)
        safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in self.method)[:50]
        f = od / f"hit_{self.score:03d}_{safe}_off{self.offset}.bin"
        f.write_bytes(self.out)
        return f


@dataclass
class SalvageReport:
    path: str = ""
    size: int = 0
    tried: int = 0
    hits: list[Hit] = field(default_factory=list)
    elapsed: float = 0.0
    split: segments.Split = field(default_factory=segments.Split)
    keys_used: int = 0
    offsets: list[int] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    stopped_early: bool = False

    @property
    def best(self) -> Hit | None:
        return self.hits[0] if self.hits else None

    @property
    def ok(self) -> bool:
        return bool(self.hits) and self.hits[0].score >= 62

    def summary(self) -> str:
        if not self.hits:
            # 早退分支（完整容器 / 文件太小 / 读不了）已有明确诊断，
            # 不能被"密钥不在这台机器上"这句套话盖掉。
            if self.notes:
                return "；".join(self.notes)
            return (f"没解出来（试了 {self.tried} 次，{self.elapsed:.1f}s）。"
                    f"这通常意味着密钥不在这台机器上，或者用了自定义算法")
        b = self.hits[0]
        s = (f"最可能：{b.method}（得分 {b.score}，偏移 {b.offset}，{b.size}B），"
             f"试了 {self.tried} 次 / {self.elapsed:.1f}s")
        if len(self.hits) > 1:
            s += f"；另有 {len(self.hits) - 1} 个候选"
        return s

    def table(self, limit: int = 12) -> str:
        if not self.hits:
            return "（无结果）"
        out = [f"{'分':>3}  {'方法':<44} {'偏移':<8} {'大小':>9}  预览"]
        out += [h.row() for h in self.hits[:limit]]
        return "\n".join(out)


# ---------------------------------------------------------------------------
# 打分
# ---------------------------------------------------------------------------

def score_output(out: bytes) -> int:
    """
    0..100。带标准文件头的直接判成功，纯乱码归零。

    注意区分强弱魔数：
      ZIP/MZ/ELF 这种多字节签名撞上的概率极低，见到即可信；
      而 `{`、`[`、`<` 只有一个字节，随机数据里到处都是，
      必须**文本本身先可读**才给这份加分，否则会把垃圾报成 JSON。
    """
    if not out or len(out) < 4:
        return 0
    # 先剥掉尾部填充（TEA/DES 的 \x00 或 PKCS7），否则合法 JSON 会被
    # padding 判定为"结构损坏"，差 1 分卡在 45 阈值下。
    probe = out
    if probe and probe[:1] in (b"{", b"["):
        trimmed = probe.rstrip(b"\x00 \t\r\n")
        if len(trimmed) >= 4:
            probe = trimmed
    bonus, magic_name = C.magic_bonus(probe)
    v = garble.view(probe[:16384])
    s = max(v.score, 0)

    if bonus >= C.STRONG_MAGIC:
        # 强魔数假阳性：crib 攻击主动尝试 PK\x03\x04 当已知明文，
        # 解出来必然带这个头，光凭头就判满分是循环论证。
        # ZIP 必须能找到 EOCD（PK\x05\x06）才算真容器。
        if magic_name == "ZIP" and b"PK\x05\x06" not in out[-65557:]:
            return min(s, 42)
        return min(100, 55 + bonus)

    if v.report and v.report.kind in (garble.G_REPLACEMENT, garble.G_CONTROL):
        return min(s, 15)

    ent = C.shannon(out[:8192])
    if ent > 7.7:
        return min(s, 20)                 # 还是密文，别报

    # —— 结构化文本的一致性校验（关键：错误密钥解出 "us$!b}" 也会得高分）——
    # 弱魔数 { 只有 1 字节，garble 看到 "{" 开头 + 一些字母就判 clean，
    # 错误 XOR 密钥解出的半截 JSON 能拿 100 分，把正确答案挤出榜首。
    # 这里用结构证据二次确认：JSON 能解析 = 铁证；引号不成对 = 降分。
    sample_text = probe[:16384]
    head_char = sample_text[:1]
    if head_char in (b"{", b"["):
        import json as _json
        try:
            txt = sample_text.decode("utf-8")
            _json.loads(txt)
            return 100                    # 完整合法 JSON，满分
        except (UnicodeDecodeError, ValueError):
            pass
        # 不能解析：JSON 正文应主要是字母/数字/空白/标点；
        # $!~^`|\\< 这些是 XOR 错位后的"半截可读"噪音。
        # 直接 return，避免后面弱魔数 bonus 再把低分抬上去。
        try:
            t = sample_text.decode("utf-8", "ignore")
            clean_chars = set(' \t\r\n":{},.-_/[]')
            chunk = t[:2048]
            good = sum(1 for c in chunk if c.isalnum() or c in clean_chars)
            weird = sum(1 for c in chunk if c in '$!~^`|\\<>' or ord(c) < 32)
            if t.count('"') % 2 == 1 or good < len(chunk) * 0.92 or weird > len(chunk) * 0.04:
                return min(44, s)
        except Exception:                                    # noqa: BLE001
            pass

    # 弱魔数只有在文本本身像话时才算证据
    if bonus and s >= 40:
        s += bonus
    if ent < 5.0 and C.printable(out[:2048]) > 0.95:
        s = max(s, 55)                    # 干净的结构化文本
    return min(100, s)


def _preview(out: bytes, n: int = 60) -> str:
    try:
        t = out[:n * 3].decode("utf-8", "replace")
    except Exception:                                # noqa: BLE001
        t = out[:n].decode("latin1", "replace")
    t = " ".join(t.split())
    return t[:n]


# 判断"解出来像不像真文本"用的常用词表（英文 + 代码关键字）。
# 只收高频、几乎不会在位移乱码里凑巧出现的词。
_WORDS = frozenset("""
the and for you not with this that from have will are was were been into only
such some more most other about after before again against because while where
when what which who whom whose there their them then than how all any both each
few many nor off own same too very can just should now
if then else elif fi do done case esac echo exit return local export function
print printf true false none null void int char long float double class public
private static final import package android http https json error failed
success license key token user pass password file path data name value type
build test start stop load save read write open close main init begin end
""".split())


def _plausible_text(b: bytes) -> bool:
    """
    "全是可打印字符"根本不等于"解对了" —— 把一段明文 shell 头做凯撒位移，
    结果还是全可打印，打分能拿 80，目录里就多出一堆 1.7KB 的垃圾。

    这里对**看起来像纯文本**的结果再审一道：必须真的出现常用词
    （英文/代码关键字/中文）。二进制、结构化容器（ZIP/ELF/JSON 开头）
    不归它管，直接放行。
    """
    if not b:
        return False
    head = b[:4096]
    if head[:1] in (b"{", b"[", b"PK", b"\x7f"):
        return True                                  # 结构化，交给魔数/JSON 判据
    try:
        if C.printable(head) < 0.92:
            return True                              # 不像纯文本，不拦
    except Exception:                                # noqa: BLE001
        return True
    try:
        t = head.decode("utf-8")
    except UnicodeDecodeError:
        t = head.decode("latin1", "ignore")
    cjk = sum(1 for ch in t if "\u4e00" <= ch <= "\u9fff")
    if cjk >= 4:
        return True
    toks = re.findall(r"[A-Za-z]{2,24}", t)
    if len(toks) < 8:
        return True                                  # 太短，证据不足，不拦
    hit = sum(1 for w in toks if w.lower() in _WORDS)
    return hit / len(toks) >= 0.06


def _worth_unwrap(out: bytes) -> bool:
    """剥掉一层之后，值不值得继续往下剥（避免对纯随机数据反复解）。"""
    if not out or len(out) < 4:
        return False
    bonus, _ = C.magic_bonus(out)
    if bonus:
        return True
    if C.printable(out[:1024]) > 0.85:
        return True
    v = garble.view(out[:4096])
    return (v.score or 0) >= 35


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

def salvage(target: str | Path | bytes, key_cands: list[K.KeyCand] | None = None,
            offsets: list[int] | None = None, top: int = 12,
            deep: bool = False, budget: float | None = None,
            max_bytes: int = 32 * 1024 * 1024,
            scan_offsets: bool = True, _depth: int = 0) -> SalvageReport:
    """
    自动试解。target 可以是文件路径或 bytes。
    返回 SalvageReport，按得分降序。
    """
    t0 = time.time()
    rep = SalvageReport()
    budget = budget if budget is not None else (60.0 if deep else 15.0)
    deadline = t0 + budget

    if isinstance(target, (bytes, bytearray)):
        data = bytes(target)[:max_bytes]
        rep.path = "<bytes>"
    else:
        p = Path(target)
        rep.path = str(p)
        try:
            # 只读前 max_bytes —— read_bytes() 会先把整文件塞进内存再切片，
            # 对几 GB 的镜像等于直接把内存吃光。
            with p.open("rb") as f:
                data = f.read(max_bytes)
        except OSError as e:
            rep.notes.append(f"读不了：{e}")
            return rep

    rep.size = len(data)
    if len(data) < 8:
        rep.notes.append("文件太小，无法试解")
        return rep

    # ---- 完整容器不是待解密的裸密文 ----
    # 例如改了后缀的 APK（*.apk.1）：它的 ZIP 条目本身是压缩数据，熵接近 8，
    # 拿去撞 96 次解密必然全失败，还让人误以为"密钥不在这台机器上"。
    # 这里早退并给出正确下一步，省掉几十秒无效穷举。
    _mb, _mname = C.magic_bonus(data)
    if _mb >= C.STRONG_MAGIC:
        rep.notes.append(
            f"文件头是完整 {_mname} 容器，不是待解密的裸密文；"
            "请先解包（unpack_any / apktool），再对内部被加密的单个文件试解"
        )
        return rep

    # ---- 分段：如果是"明文头 + 密文"，只解密文部分 ----
    seg = segments.analyze(data)
    rep.split = seg.split
    body_offsets = _candidate_offsets(data, seg, offsets, scan_offsets)
    rep.offsets = body_offsets

    # ---- 候选密钥 ----
    cands = list(key_cands or [])
    if seg.split.head_keys:
        cands += K.from_bytes(
            ("\n".join(f"key={k}" for k in seg.split.head_keys)).encode(),
            source="明文头")
    if not cands:
        cands = K.from_bytes(data[:512 * 1024], source="文件内容")
    # 短文件/脚本里，全文搜一遍更靠谱
    if len(data) <= 2 * 1024 * 1024:
        cands = K.merge(cands, K.from_bytes(data, source="全文"))
    rep.keys_used = len(cands)

    ordered = K.ordered_keys(cands, with_common=True, limit=80)

    hits: list[Hit] = []
    near: list[Hit] = []          # 35-44 分的"差一点"片段：整体没救时至少留个抓手
    seen: set[str] = set()
    solved: bool = False          # 已拿到强魔数满分解（gzip→ELF/ZIP 这类），后续算法可跳过

    def add(method: str, out: bytes, offset: int, key: str = "", note: str = "",
            force_score: int = 0) -> None:
        nonlocal hits, near, solved
        rep.tried += 1
        if not out or len(out) < 4:
            return
        # force_score：递归/外部已验证过的分数，直接采用。
        # 混合文件（明文头+解密body）整体打分会被明文头稀释，
        # 但 body 单独验证是 100 分 —— 不能被混合打分过滤掉。
        sc = force_score or score_output(out)
        # force_score 来自子结果，但 crib 伪解在 body 里也可能拿满分
        # （"{" 开头 + garble 判 clean）。对完整 JSON 做铁证校验：
        # 能 json.loads 的排最前，不能解析但 { 开头的降一档。
        if force_score and sc >= 95:
            tail = out[offset:] if 0 <= offset < len(out) else out
            if tail[:1] in (b"{", b"["):
                import json as _j
                try:
                    _j.loads(tail.rstrip(b"\x00 \t\r\n").decode("utf-8"))
                    sc = 100                       # 铁证
                except Exception:                                # noqa: BLE001
                    sc = min(sc, 94)               # 格式不对，降档
        if sc < 45:
            if sc >= 35:
                h = hashlib.sha256(out[:8192]).hexdigest()[:16]
                if h not in seen:
                    seen.add(h)
                    near.append(Hit(method=method + "（低分片段）", offset=offset,
                                    score=sc, out=out, preview=_preview(out),
                                    key=key, note=note or "接近可读但没过线"))
            return
        h = hashlib.sha256(out[:8192]).hexdigest()[:16]
        if h in seen:
            return
        seen.add(h)
        if sc >= 95:
            solved = True
        hits.append(Hit(method=method, offset=offset, score=sc, out=out,
                        preview=_preview(out), key=key, note=note))

    # ---- 0) 自解压 / 多层封装快速通道 ----
    #   *.sh（makeself：skip=N + tail | gzip -cd）、拼接压缩包、UPX 壳、
    #   多个 ELF 拼在一个文件里……这些都不是加密，照着容器协议拆就行。
    #   必须在昂贵试解前处理，否则几十秒白跑，最后还给出"解不出来"的错误结论。
    _body0 = data[seg.split.head_end:] if (seg.split.found and seg.split.head_end > 0) else data
    _magic = _body0[:4]
    _compress_magic = (_magic.startswith(b"\x1f\x8b") or _magic.startswith(b"PK\x03\x04")
                       or _magic.startswith(b"7z\xbc") or _magic.startswith(b"Rar!")
                       or _magic.startswith(b"BZh") or _magic.startswith(b"\xfd7z"))
    _makeself = SE.parse_makeself(data[:65536]) is not None
    if _compress_magic or _makeself:
        try:
            _target = data if _makeself else _body0
            _unp = SE.deep_unpack(_target, Path(str(target)).stem or "payload")
            for a in _unp.artifacts:
                if a.kind in ("makeself",):
                    sc = 60
                elif a.kind == "gzip":
                    sc = 72
                elif a.kind == "upx":
                    sc = 100
                else:
                    sc = 98
                label = {"makeself": "自解压脚本负载", "gzip": "压缩流解包",
                         "upx": "UPX 脱壳", "elf": "ELF 提取"}.get(a.kind, a.kind)
                add(f"{label} · {a.note[:46]}" if a.note else label, a.data, 0,
                    force_score=sc, note=a.note)
            rep.notes.extend(_unp.notes)
            if _unp.artifacts:
                hits.sort(key=lambda h: (h.score, len(h.out)), reverse=True)
                rep.hits = hits[:top]
                rep.elapsed = time.time() - t0
                return rep            # 容器已拆开，不必再撞 96 种算法
        except Exception as e:                                  # noqa: BLE001
            rep.notes.append(f"多层封装拆解失败：{e}")

    # 打分只看样本，命中后全文重解
    sample = data[:256 * 1024]

    # ---- 1) 编码 / 压缩（最多剥三层：base64→base64→zlib 这种套娃很常见）----
    _ENCODERS = (("Base64", C.b64_decode_any), ("Base32", C.b32_decode_any),
                 ("Base85", C.b85_decode_any), ("十六进制", C.hex_decode_any))
    layer: list[tuple[str, bytes, int]] = [("", data, 0)]
    for _ in range(3):
        nxt: list[tuple[str, bytes, int]] = []
        for label, blob, off in layer[:6]:
            for name, fn in _ENCODERS:
                out, how = fn(blob[:1024 * 1024])
                if not out or out == blob or len(out) < 4:
                    continue
                if not _worth_unwrap(out):
                    continue
                tag = f"{label} → {how}" if label else (how or name)
                add(tag, out, off, note="编码层")
                nxt.append((tag, out, off))
            out, how = C.decompress_auto(blob)
            if out and _worth_unwrap(out):
                tag = f"{label} → {how}" if label else how
                add(tag, out, off, note="压缩层")
                nxt.append((tag, out, off))
        layer = nxt[:6]
        if not layer:
            break
    # 剥出来的层往往就是配置/源码（json/yaml/xml），里面藏着真密钥 ——
    # 不回头捞一遍，后面 80 个候选全是白撞
    for label, blob, _off in layer[:6]:
        extra = K.from_bytes(blob[:512 * 1024], source=f"解码层·{label}")
        if extra:
            cands = K.merge(cands, extra, limit=200)
    ordered = K.ordered_keys(cands, with_common=True, limit=80)
    rep.keys_used = len(cands)
    # 跳过明文头再解压缩。分段给出的 head_end 是最可信的真实起点，
    # 必须第一个试——自解压脚本（tail +skip | gzip -cd）的 payload 就在那里。
    # 不能像旧版那样只扫 body_offsets[:8]：数值小的对齐偏移会把它挤出前列，
    # 结果 gzip 数据被拿去撞几十次加密算法，一次都不解压缩。
    _comp_offs = [o for o in body_offsets if o > 0]
    if seg.split.found and seg.split.head_end > 0 and seg.split.head_end in _comp_offs:
        _comp_offs.remove(seg.split.head_end)
        _comp_offs.insert(0, seg.split.head_end)
    for off in _comp_offs[:24]:
        out, how = C.decompress_auto(data[off:])
        if not out:
            continue
        # 带强魔数的解压结果（ELF/ZIP/DEX...）是铁证，直接按满分收，
        # 不走 add() 的 garble 可读性打分——二进制 ELF 本来就不"可读"。
        _mb, _mn = C.magic_bonus(out)
        if _mb >= C.STRONG_MAGIC:
            _h = hashlib.sha256(out[:8192]).hexdigest()[:16]
            if _h not in seen:
                seen.add(_h)
                solved = True
                hits.append(Hit(method=f"{how}（{_mn}）", offset=off, score=100,
                                out=out, preview=f"{_mn} 容器 {len(out)}B",
                                note="压缩层·强魔数"))
            continue
        if _worth_unwrap(out):
            add(how, out, off, note="压缩层（跳过头部）")

    # ---- 1.5) 密文体独立递归试解（最关键的一步）----
    #   大段明文头会把打分彻底淹没：body 只有 116B 解对了，
    #   但 add() 拼上 1108B 明文头后 score_output 看的是整个 file，
    #   频率/熵判据全被明文头主导，解对的结果反而低分被丢。
    #   做法：把 body 当独立目标递归跑一遍（depth 限 1），
    #   命中的结果再拼回明文头。文本形态密文（base64/hex）先解码再递归。
    if seg.split.found and seg.split.head_end >= 8 and _depth < 1:
        body = data[seg.split.head_end:]
        bodies: list[tuple[bytes, str]] = [(body, "密文体")]
        for dec, chow, _ in _text_cipher_bodies(data, seg):
            bodies.append((dec, chow))
        for bi, (bbody, bhow) in enumerate(bodies):
            if len(bbody) < 8 or time.time() > deadline:
                continue
            try:
                sub = salvage(bbody, key_cands=key_cands, offsets=[0], top=6,
                              deep=deep, budget=min(budget, 8.0),
                              _depth=_depth + 1)
            except TypeError:                        # 老签名兜底
                continue
            for h in sub.hits:
                if not h.out or score_output(h.out) < 45:
                    continue
                if not _plausible_text(h.out):
                    continue
                full = data[:seg.split.head_end] + h.out
                add(f"{bhow}·独立试解→{h.method}", full, seg.split.head_end,
                    key=h.key, note=f"{bhow}单独跑（避免明文头稀释打分）",
                    force_score=h.score)

    # ---- 1.6) ROT13 / Caesar / Atbash（经典弱加密，库里有但一直没接进来）----
    for off in ({0, seg.split.head_end} if seg.split.found else {0}):
        if off >= len(data) - 8:
            continue
        chunk = data[off:off + 64 * 1024]
        for name, dec in (("ROT13", C.rot(chunk, 13)), ("Atbash", C.atbash(chunk))):
            if score_output(dec) >= 55 and _plausible_text(dec):
                add(f"{name}·偏移{off}", data[:off] + dec, off, note=name)
        for shift, dec in C.caesar_all(chunk, top=3):
            if score_output(dec) >= 55 and _plausible_text(dec):
                add(f"Caesar+{shift}·偏移{off}", data[:off] + dec, off, note="凯撒位移")

    # ---- 2) 单字节 XOR ----
    for off in body_offsets[:3]:
        chunk = data[off:off + 256 * 1024] if off else sample
        for k, sc, dec in C.xor_single_bruteforce(chunk, top=4):
            if k == 0:                      # XOR 0x00 等于没解，纯噪音
                continue
            add(f"单字节 XOR 0x{k:02X}", dec, off, key=f"0x{k:02X}")

    # ---- 2.5) 已知明文攻击（确定性，比频率分析可靠）----
    #   XOR 类的密钥流是重复的，只要明文格式已知就能直接反推密钥。
    #   这一步放在频率分析之前：能确定就别猜。
    crib_offs = [0]
    if seg.split.found and seg.split.head_end > 0:
        crib_offs.append(seg.split.head_end)
    # 从明文头抠出的字符串是"补充"已知明文，不能"替换"通用 crib ——
    # 明文头是注释/代码，密文解出来是 JSON 时，两者的格式毫无交集；
    # 旧版 cribs=head_cribs or None 会把 {\" 这类通用 crib 全部屏蔽，
    # 这正是"大段明文头+弱加密"100% 撞不开的直接原因。
    head_cribs: list[bytes] = []
    if seg.split.found and 0 < seg.split.head_end <= 8192:
        head = data[:seg.split.head_end]
        for m in re.finditer(rb"[\x20-\x7e]{16,}", head):
            head_cribs.append(m.group()[:64])
            if len(head_cribs) >= 6:
                break
    all_cribs = list(dict.fromkeys(head_cribs + CR.DEFAULT_CRIBS))
    # 密文体也必须单独试：crib 必须打在密文的起始位置，
    # 不能让明文头把偏移 0 占掉（crib_attack 只在给定 off 上试）。
    crib_target = data[seg.split.head_end:] if seg.split.found else data
    crib_offs_body = [0]
    try:
        for ch in CR.crib_attack(crib_target, cribs=all_cribs,
                                 offsets=crib_offs_body, scorer=score_output):
            if not ch.plain:
                continue
            sc = ch.score or score_output(ch.plain)
            if sc < 45:
                continue
            off_global = (seg.split.head_end if seg.split.found else 0) + ch.offset
            full = (data[:off_global] + ch.plain) if seg.split.found else ch.plain
            add(f"已知明文攻击（{_ks(ch.crib.decode('latin1', 'ignore'))} · "
                f"密钥 {ch.key.hex()} · 周期 {ch.period}）",
                full, off_global, key=ch.key.hex(), note=ch.note)
    except Exception as e:                           # noqa: BLE001
        rep.notes.append(f"已知明文攻击跳过：{e}")

    # ---- 3) 循环 XOR ----
    ks = C.xor_keysize_hamming(sample, max_key=40)[:8]
    # 汉明距离对"真实长度的整数倍"同样敏感（5 的倍数都会低分），
    # 所以把候选长度的所有因子也一并试，避免拿到 20 字节的伪密钥。
    lens: list[int] = []
    for klen, dist in ks:
        for d in range(1, klen + 1):
            if klen % d == 0 and d not in lens:
                lens.append(d)
    for klen in lens[:14]:
        if time.time() > deadline:          # 全文异或是纯 Python，必须能被打断
            rep.stopped_early = True
            break
        dec, key = C.xor_break_repeating(sample, klen)
        if not dec or not key:
            continue
        for cand in dict.fromkeys((key, C.xor_reduce_key(key))):
            full = C.xor_bytes(data, cand)
            add(f"循环 XOR（{len(cand)} 字节密钥 {cand.hex()}）",
                full, 0, key=cand.hex(), note="频率分析")

    # ---- 4) 密钥 XOR / 5) RC4 / 6) TEA 系 ----
    tried_keys = 0
    for val, src, sc in ordered:
        if time.time() > deadline:
            rep.stopped_early = True
            break
        if len(val) < 2:
            continue
        tried_keys += 1
        raw = val.encode("utf-8", "ignore")

        dec = C.xor_bytes(sample, raw)
        if dec:
            full = C.xor_bytes(data, raw)
            add(f"密钥 XOR（{_ks(val)}）", full, 0, key=val, note=src)
            # 相位自适应：密钥流在密文里是从中间某处开始循环的，
            # 相位差一位就全盘皆输 —— 样本接近可读但没过线时，把所有相位都试一遍
            sc0 = score_output(dec)
            if 28 <= sc0 < 45 and 2 <= len(raw) <= 64:
                best_ph, best_out = -1, b""
                for ph in range(1, len(raw)):
                    rot = raw[ph:] + raw[:ph]
                    d = C.xor_bytes(sample, rot)
                    if score_output(d) > max(sc0, 0) + 8:
                        best_ph, best_out = ph, d
                if best_ph >= 0:
                    add(f"密钥 XOR（{_ks(val)} · 相位+{best_ph}）",
                        C.xor_bytes(data, raw[best_ph:] + raw[:best_ph]), 0,
                        key=val, note=f"{src}·相位对齐")

        if len(raw) >= 4 and tried_keys <= 40:
            rc = C.rc4(data, raw)
            add(f"RC4（{_ks(val)}）", rc, 0, key=val, note=src)
            # drop 变体：很多实现会先空转 768 轮（OpenSSL/WiFi WEP 常见），
            # 不对齐的话前 768 字节全是乱的，整段打分永远过不了线。
            for drop in (768, 3072):
                rcd = C.rc4(sample, raw, drop=drop)
                if score_output(rcd) >= 45:
                    add(f"RC4-drop{drop}（{_ks(val)}）",
                        C.rc4(data, raw, drop=drop), 0, key=val,
                        note=f"{src}·空转{drop}轮")

        if tried_keys <= 20 or sc >= 70 or src.startswith(("用户", "明文头")):
            for kb, how in K.KeyCand(value=val, source=src).variants((16,)):
                if len(kb) == 16:
                    add(f"XXTEA（{_ks(val)} · {how}）",
                        C.xxtea_decrypt(data, kb), 0, key=val, note=src)
                    add(f"XTEA（{_ks(val)} · {how}）",
                        C.xtea_decrypt(data, kb), 0, key=val, note=src)
                    add(f"TEA（{_ks(val)} · {how}）",
                        C.tea_decrypt(data, kb), 0, key=val, note=src)

    # ---- 7) AES ----
    if C.HAVE_CRYPTO and len(data) >= 32:
        aes_keys = 0
        # IV 候选：全 0 / 密钥前 16 / 明文头里的 hex
        head_ivs: list[tuple[bytes, str]] = []
        for i, hk in enumerate((seg.split.head_keys or [])[:4]):
            hb, _ = C.hex_decode_any(hk)
            if len(hb) >= 16:
                head_ivs.append((hb[:16], f"IV=头{i}"))

        # 起点候选：0 和明文头之后（密文往往紧跟明文头，这是最常踩的坑）
        aes_offs: list[int] = [0]
        if seg.split.found and 0 < seg.split.head_end < len(data) - 32:
            aes_offs.append(seg.split.head_end)

        for val, src, sc in ordered:
            if time.time() > deadline:
                rep.stopped_early = True
                break
            if aes_keys >= 45:
                break
            aes_keys += 1
            for kb, how in K.KeyCand(value=val, source=src).variants((16, 32)):
                for off in aes_offs:
                    body = data[off:]
                    if len(body) < 32:
                        continue
                    ivs = [(b"\x00" * 16, "IV=0"), (kb[:16], "IV=key前16")] + head_ivs
                    for mode in ("ECB", "CBC"):
                        pairs = ivs if mode == "CBC" else [(None, "")]
                        for iv, ivname in pairs:
                            dec, note = C.aes_decrypt(body[:128 * 1024], kb, mode, iv)
                            if not dec or score_output(dec[:16384]) < 45:
                                continue
                            full, _ = C.aes_decrypt(body, kb, mode, iv)
                            add(f"AES-{len(kb) * 8}-{mode}（{_ks(val)} · {how} · "
                                f"{ivname} · 起点{off}）", full or dec, off, key=val, note=src)
                    # IV 前置布局：前 16 字节当 IV
                    if len(body) > 32:
                        dec, _ = C.aes_decrypt(body[16:], kb, "CBC", body[:16])
                        if dec and score_output(dec[:16384]) >= 45:
                            add(f"AES-{len(kb) * 8}-CBC（{_ks(val)} · {how} · IV=密文前16）",
                                dec, off + 16, key=val, note="IV 前置")

    # ---- 8) OpenSSL Salted ----
    if C.HAVE_CRYPTO and data.startswith(b"Salted__"):
        for val, src, sc in ordered[:40]:
            out, note = C.openssl_decrypt(data, val)
            if out:
                add(f"OpenSSL {note}（口令 {_ks(val)}）", out, 16, key=val, note=src)

    # ---- 9) 偏移扫描（RC4 / AES 对起点敏感）----
    if scan_offsets and len(data) <= 8 * 1024 * 1024:
        best_sc = max((h.score for h in hits), default=0)
        if best_sc < 62:
            for off in range(1, min(64, len(data) - 16)):
                if time.time() > deadline:
                    rep.stopped_early = True
                    break
                chunk = data[off:off + 16384]
                # 便宜的先扫：单字节 XOR 的偏移等价于换 key，跳过；
                # RC4 用前 4 个候选密钥扫
                for val, src, sc in ordered[:4]:
                    raw = val.encode("utf-8", "ignore")
                    if len(raw) < 4:
                        continue
                    dec = C.rc4(chunk, raw)
                    if score_output(dec) >= 60:
                        add(f"RC4（{_ks(val)}）· 偏移 {off}",
                            C.rc4(data[off:], raw), off, key=val, note=src)
                # 压缩：有时前面垫了几个字节
                out, how = C.decompress_auto(chunk)
                if out:
                    out2, how2 = C.decompress_auto(data[off:])
                    add(f"{how} · 偏移 {off}", out2 or out, off)
                if off > 32 and not hits:
                    pass

    # ---- 10) 片段自动拼接：整体撞不开 ≠ 没救 ----
    #   混合加密（前半 XOR、后半 RC4 / 分段不同密钥 / 中间垫了明文段）时，
    #   整文件任何单一算法都过不了线。做法：切成块，每块独立把
    #   「单字节 XOR / 循环 XOR / 候选密钥 XOR」全试一遍，各块取最高分，
    #   高分块用解密结果、低分块保留原文，拼成一份完整明文。
    best_sc = max((h.score for h in hits), default=0)
    if best_sc < 62 and len(data) >= 4096 and time.time() < deadline:
        try:
            WIN = 8192
            body = data[seg.split.head_end:] if seg.split.found else data
            head_len = len(data) - len(body)
            blocks: list[bytes] = []
            for i in range(0, len(body) - 1023, WIN):
                blocks.append(body[i:i + WIN])
            if len(blocks) >= 2 and len(blocks) <= 4096:
                # 每块的候选密钥：全局候选 + 该块自己的循环XOR破解
                cand_keys: list[bytes] = []
                for val, _src, _sc in ordered[:24]:
                    kb = val.encode("utf-8", "ignore")
                    if len(kb) >= 2:
                        cand_keys.append(kb)
                stitched: list[bytes] = []
                good = 0
                for bi, blk in enumerate(blocks):
                    if time.time() > deadline:
                        stitched.append(blk)
                        continue
                    best_blk = (0, blk)
                    # 单字节 XOR
                    for k, _sc, dec in C.xor_single_bruteforce(blk[:16384], top=2):
                        if k and dec:
                            s = score_output(dec)
                            if s > best_blk[0]:
                                best_blk = (s, dec)
                    # 循环 XOR（块内破解）
                    ksizes = C.xor_keysize_hamming(blk[:16384], max_key=32)[:3]
                    for klen, _d in ksizes:
                        dec, rkey = C.xor_break_repeating(blk, klen)
                        if dec and rkey:
                            s = score_output(dec)
                            if s > best_blk[0]:
                                best_blk = (s, dec)
                    # 候选密钥 XOR
                    for kb in cand_keys[:16]:
                        dec = C.xor_bytes(blk, kb)
                        s = score_output(dec)
                        if s > best_blk[0]:
                            best_blk = (s, dec)
                    if best_blk[0] >= 40:
                        good += 1
                    stitched.append(best_blk[1])
                if good >= max(2, len(blocks) // 2):
                    merged = (data[:head_len] + b"".join(stitched))
                    sc_all = score_output(merged[:65536])
                    if sc_all >= 45:
                        add(f"片段拼接（{good}/{len(blocks)} 块解出）",
                            merged, 0, note="分块独立破解后自动拼接")
                        rep.notes.append(
                            f"拼接：{len(blocks)} 块里 {good} 块独立解出并拼合")
        except Exception as e:                              # noqa: BLE001
            rep.notes.append(f"拼接跳过：{e}")

    # ---- 收尾：排序、全文重解校验 ----
    hits.sort(key=lambda h: -h.score)
    # 只对前几个做全文重解，避免在大文件上浪费时间
    rep.hits = hits[:top]
    rep.elapsed = time.time() - t0
    if rep.stopped_early:
        rep.notes.append(f"到时间预算（{budget:.0f}s）就停了，结果可能不全；"
                         f"用 deep=True 跑更久")
    if not rep.hits:
        if near:
            near.sort(key=lambda h: -h.score)
            rep.hits = near[:top]
            rep.notes.append("没有完整命中，只有低分片段（已列出最接近的）："
                             "可能是偏移不对/加密模式变体 —— 试着把片段里的"
                             "可读部分当 crib 再跑，或提供已知密钥")
        else:
            rep.notes.append("常见算法全试过没命中。下一步：从程序里找解密函数"
                             "（rf.patch_scan / rf.auth_scan），或 hook 拿明文")
    return rep


def _text_cipher_bodies(data: bytes, seg: segments.SegmentMap) -> list[tuple[bytes, str, int]]:
    """
    从"明文头 + 文本形态密文"里抠出可解码的密文体。
    返回 [(解码后的密文字节, 说明, 全局偏移)]。

    真实外挂常见形态：一大段中文注释/代码头，末尾一行
      ENCRYPTED_DATA = "HbFh..."  或  DATA = '6a2f...'
    整文件送进 b64_decode_any 会因为前面的中文/换行失败，
    必须先按段切开，再只解码密文那一段。
    """
    if not seg.split.found or seg.split.head_end <= 0:
        return []
    body = data[seg.split.head_end:]
    base = seg.split.head_end
    out: list[tuple[bytes, str, int]] = []

    # 整段直接解（纯 base64/hex 密文块）
    for fn, label in ((C.b64_decode_any, "Base64"), (C.hex_decode_any, "Hex")):
        dec, how = fn(body)
        if dec and len(dec) >= 8:
            out.append((dec, f"{label}→{how}", base))

    # 逐行解（密文藏在一行里，行首有 DATA= / ENCRYPTED_DATA= 等标记）
    for line in body.split(b"\n"):
        s = line.strip()
        if len(s) < 16:
            continue
        # 跳过赋值前缀，只留引号内或 = 后的串
        m = re.search(rb"[\"']([A-Za-z0-9+/=_\-]{16,})[\"']", s)
        if m:
            s = m.group(1)
        elif b"=" in s and not s.startswith(b"="):
            s = s.split(b"=", 1)[1].strip().strip(b"\"'")
        for fn, label in ((C.b64_decode_any, "Base64"), (C.hex_decode_any, "Hex")):
            dec, how = fn(s)
            if dec and len(dec) >= 8 and dec not in (d for d, _, _ in out):
                out.append((dec, f"{label}行→{how}", base))
    return out[:12]


def _ks(val: str, n: int = 20) -> str:
    v = val if len(val) <= n else val[:n] + "…"
    return repr(v)


def _candidate_offsets(data: bytes, seg: segments.SegmentMap,
                       user: list[int] | None, scan: bool) -> list[int]:
    """候选起点：0 / 明文头之后 / 常见对齐值。"""
    offs: set[int] = {0}
    if user:
        offs.update(o for o in user if 0 <= o < len(data))
    if seg.split.found and seg.split.head_end > 0:
        offs.add(seg.split.head_end)
    for a in (4, 8, 12, 16, 20, 24, 32, 48, 64, 128, 256, 512, 1024):
        if a < len(data):
            offs.add(a)
    return sorted(o for o in offs if o < len(data))


# ---------------------------------------------------------------------------
# 快速版（只跑最便宜的三样，给文件识别流程用）
# ---------------------------------------------------------------------------

def quick(target: str | Path | bytes) -> SalvageReport:
    """只试编码/压缩/单字节 XOR/循环 XOR，几百毫秒出结果。"""
    return salvage(target, budget=4.0, top=5, scan_offsets=False)


# ---------------------------------------------------------------------------
# 报告
# ---------------------------------------------------------------------------

def report_md(rep: SalvageReport, title: str = "自动试解") -> str:
    L = [f"## {title}", "",
         f"- 文件：`{rep.path}`（{rep.size} 字节）",
         f"- 试解次数：{rep.tried}，用时 {rep.elapsed:.1f}s",
         f"- 候选密钥：{rep.keys_used} 条"]
    if rep.split.found:
        L.append(f"- 分段：明文头 {rep.split.head_len}B + 密文 {rep.split.tail_len}B "
                 f"（可信 {rep.split.confidence}%）")
    L.append("")
    if not rep.hits:
        L += ["**没有解出来。**", ""]
        L += [f"- {n}" for n in rep.notes]
        return "\n".join(L)

    L += [f"**最可能：{rep.hits[0].method}**（得分 {rep.hits[0].score}）", "",
          "| 分 | 方法 | 偏移 | 大小 | 预览 |", "|---|---|---|---|---|"]
    for h in rep.hits:
        L.append(f"| {h.score} | {h.method} | {h.offset} | {h.size} | "
                 f"`{h.preview[:40]}` |")
    if rep.notes:
        L += ["", "### 备注", ""] + [f"- {n}" for n in rep.notes]
    return "\n".join(L)


def save_hits(rep: SalvageReport, out_dir: str | Path, limit: int = 5) -> list[Path]:
    """把前几个结果落盘，方便直接打开看。"""
    return [h.save(out_dir) for h in rep.hits[:limit]]
