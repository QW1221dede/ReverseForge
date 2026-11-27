#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 rf.analysis.garble · 乱码判定与自动修复
============================================================================

【三种"看不懂"是完全不同的病，得分开治】

  1) 方块里一个问号  □?   ← 缺字形（tofu）
     字符码位是合法的，但当前字体里没有对应字形，编辑器就画个方框。
     * 私有区（U+E000–U+F8FF）大量出现 → 字体加密。
       典型场景：小说站、PDF 阅读器把常用字重映射到私有区码位，
       复制出来全是方块，必须拿字体文件反查字模才能还原。
     * 这里能做的事：精确判定"这是字体混淆，不是加密"，
       并把出现频率最高的私有区码位列出来（做字模比对时就是索引表）。

  2) 菱形问号  �   ← U+FFFD 替换字符
     解码器说"这串字节按声明的编码解不出来"，于是每个坏字节换成 �。
     * 比例很高（>15%）→ 这段根本不是文本：要么还是密文，要么是二进制。
     * 比例很低（个别几个）→ 大概率是编码猜错，换个编码重解就能救。

  3) 一片乱码 锟斤拷 / 烫烫烫 / é–æ–‡  ← 编码链错位（mojibake）
     * 「锟斤拷」= UTF-8 里的 U+FFFD 又被 GBK 编码了一次的产物
     * 「烫烫烫」= 0xCC 填充字节被当 GBK 解（VC 调试版未初始化栈）
     * 「屯屯屯」= 0xCD 填充字节被当 GBK 解
     * 「é–æ–‡」= UTF-8 字节被当成 Latin-1 / CP1252 解
     这一类是**可逆**的：拿当前字符串按错误编码 encode 回去，
     再按正确编码 decode，就还原了。本模块自动试全部常见组合。

【给解密器用的评分】
    readability(text) → 0..100，越高越像人话。
    自动试解时按这个排序，就不用靠肉眼挑了。
    评分只看"像不像自然语言"，不做语义理解。

【诚实边界】
    字体加密（私有区重映射）没有字体文件就无法还原，这里只判定不猜。
    它和"真加密"要分开报告——很多人把字体混淆当成 AES，白折腾半天。
============================================================================
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# 判定结果
# ---------------------------------------------------------------------------

# 病症代码
G_CLEAN = "clean"            # 正常
G_REPLACEMENT = "replacement"  # 大量 U+FFFD，像二进制/密文
G_CONTROL = "control"        # 控制字符占多数
G_MOJIBAKE = "mojibake"      # 编码链错位（可修）
G_PUA = "pua"                # 私有区 → 字体加密
G_MIXED = "mixed"            # 上面几种混着
G_SHORT = "short"            # 样本太短，不下结论

G_CN = {
    G_CLEAN: "正常文本",
    G_REPLACEMENT: "替换字符（疑似密文/二进制）",
    G_CONTROL: "控制字符（疑似二进制）",
    G_MOJIBAKE: "编码错位乱码（可修）",
    G_PUA: "私有区字符（字体加密）",
    G_MIXED: "混合异常",
    G_SHORT: "样本过短",
}

# 已知 mojibake 签名：出现这些片段基本可以确诊
_MOJIBAKE_SIGNS = [
    "锟斤拷", "烫烫烫", "屯屯屯", "锘", "鈥", "銆", "銆傘", "锛",
    "ï»¿", "â€", "Ã©", "Ã¨", "Ã¼", "Ã¤", "Â ", "Ð°", "Ñ€",
    "æ–‡", "çš„", "ä¸", "å¤", "è¿", "é«",
]

# 常见中文字（用于快速判断"这段像不像中文"，比统计字频简单可靠）
_COMMON_CN = set(
    "的一是在不了有和人这中大为上个国我以要他时来用们生到作地于出就分对成会可主发年动同工也能下"
    "过子说产种面而方后多定行学法所民得经十三之进着等部度家电力里如水化高自二理起小物现实加量"
    "都两体制机当使点从业本去把性好应开它合还因由其些然前外天政四日那社义事平形相全表间样与关"
    "各重新线内数正心反你明看原又么利比或但质气第向道命此变条只没结解问意建月公无系军很情者最"
    "立代想已通并提直题党程展五果料象员革位入常文总次品式活设及管特件长求老头基资边流路级少图"
    "山统接知较将组见计别她手角期根论运农指几九区强放决西被干做必战先回则任取据处理世车价"
    "密码卡注册验证登录授权激活成功失败错误请输入确认取消使用说明版本试用到期"
)

_CJK = re.compile(r"[\u4e00-\u9fff]")
_PUA = re.compile(r"[\ue000-\uf8ff\U000f0000-\U000ffffd]")
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


@dataclass
class GarbleReport:
    """一段文本的"可读性诊断书"。"""
    length: int = 0
    kind: str = G_CLEAN
    score: int = 0                  # 可读性 0-100
    cjk_ratio: float = 0.0
    ascii_ratio: float = 0.0
    replacement_ratio: float = 0.0
    control_ratio: float = 0.0
    pua_ratio: float = 0.0
    signs: list[str] = field(default_factory=list)       # 命中的 mojibake 片段
    pua_codes: list[str] = field(default_factory=list)   # 高频私有区码位
    fixed: str = ""                 # 修好后的文本（没修则空）
    fixed_by: str = ""              # 用了哪条修复链
    note: str = ""

    @property
    def readable(self) -> bool:
        return self.kind == G_CLEAN and self.score >= 55

    def brief(self) -> str:
        s = f"{G_CN.get(self.kind, self.kind)}  可读性 {self.score}"
        if self.replacement_ratio > 0.02:
            s += f"  替换符 {self.replacement_ratio:.0%}"
        if self.pua_ratio > 0.02:
            s += f"  私有区 {self.pua_ratio:.0%}"
        if self.fixed_by:
            s += f"  → 已修（{self.fixed_by}）"
        return s


# ---------------------------------------------------------------------------
# 可读性评分
# ---------------------------------------------------------------------------

# 英文常见双字母组合。自然语言里这一项占比很高（约 30%-35%），
# 而"看似可打印的乱码"里极低（10% 上下）——这是区分人话和垃圾最有效的尺子。
_BIGRAMS = frozenset((
    "th he in er an re on at en nd ti es or te of ed is it al ar st to nt ng se "
    "ha as ou io le ve co me de hi ri ro ic ne ea ra ce li ch ll be ma si om ur "
    "ca el ta la ns ge il us ss da po pe tr ac ct im no wa ee ly un qu lo ad fa "
    "we wh ey so pr pl ay ke ow su id os ui"
).split())

_VOWELS = frozenset("aeiouAEIOU")


def _bigram_rate(text: str) -> float:
    """相邻字母对里，命中常见双字母组合的比例。"""
    low = text.lower()
    hits = pairs = 0
    for i in range(len(low) - 1):
        a, b = low[i], low[i + 1]
        if ("a" <= a <= "z") and ("a" <= b <= "z"):
            pairs += 1
            if low[i:i + 2] in _BIGRAMS:
                hits += 1
    return hits / pairs if pairs else 0.0


def readability(text: str) -> int:
    """
    0..100。只看"像不像人能读的东西"，不做语义判断。

    打分结构（不是拍脑袋给基底分，全部按比例算）：
      中文文本：常用字比例（最关键）+ 中文占比 + 标点/空白结构
      西文文本：常见双字母组合比例（最关键）+ 元音比例 + 字母占比 + 空格结构
      两者都没有：接近 0

    为什么不能用"可打印率"当主指标：
      随机字节里 37% 落在可打印 ASCII 区间，XOR 之后更是接近 90% 可打印，
      但那些东西一个词都拼不出来。可打印率只当辅助，不当主证据。
    """
    if not text:
        return 0
    n = len(text)
    if n < 8:
        return 0

    rep = text.count("\ufffd")
    ctrl = len(_CTRL.findall(text))
    pua = len(_PUA.findall(text))
    cjk = len(_CJK.findall(text))
    common = sum(1 for ch in text if ch in _COMMON_CN)
    letters = sum(1 for ch in text if ("a" <= ch.lower() <= "z"))
    vowels = sum(1 for ch in text if ch in _VOWELS)
    spaces = text.count(" ") + text.count("\n") + text.count("\t")
    cjk_ratio = cjk / n
    sp_ratio = spaces / n

    score = 0.0

    if cjk_ratio >= 0.20:
        # ---- 中文 ----
        common_ratio = common / max(1, cjk)
        score += 55.0 * min(1.0, common_ratio / 0.30)
        score += 20.0 * min(1.0, cjk_ratio / 0.75)
        if 0.01 <= sp_ratio <= 0.30:
            score += 10.0
        if re.search(r"[，。！？：；、（）“”《》]", text):
            score += 8.0
        # 混进来的西文垃圾（XOR 产物常见）扣分
        if cjk_ratio < 0.55 and letters / n > 0.15:
            score -= 12.0
    else:
        # ---- 西文 / 代码 / JSON ----
        alpha_ratio = letters / n
        vow = vowels / max(1, letters)
        big = _bigram_rate(text)
        score += 40.0 * min(1.0, max(0.0, big - 0.10) / 0.20)
        score += 22.0 * min(1.0, max(0.0, vow - 0.15) / 0.22)
        score += 18.0 * min(1.0, alpha_ratio / 0.50)
        if 0.02 <= sp_ratio <= 0.30:
            score += 12.0
        # 完全没有字母也没有中文（纯符号/数字/控制）
        if alpha_ratio < 0.08:
            score = min(score, 12.0)

    # ---- 三种病灶：重罚 ----
    score -= min(60.0, rep / n * 300)
    score -= min(50.0, ctrl / n * 200)
    score -= min(50.0, pua / n * 180)

    return max(0, min(100, int(round(score))))


# ---------------------------------------------------------------------------
# 诊断
# ---------------------------------------------------------------------------

def _ratio(text: str, n: int) -> float:
    return (n / len(text)) if text else 0.0


def diagnose(text: str, sample: int = 4000) -> GarbleReport:
    """诊断一段文本到底哪里不对，并尽可能修好。"""
    rep = GarbleReport()
    if text is None:
        rep.kind = G_SHORT
        return rep
    s = text[:sample]
    rep.length = len(text)
    if len(s) < 8:
        rep.kind = G_SHORT
        rep.score = readability(text)
        rep.note = "样本不足 8 字符，不下结论"
        return rep

    rep.cjk_ratio = _ratio(s, len(_CJK.findall(s)))
    rep.ascii_ratio = _ratio(s, sum(1 for c in s if 32 <= ord(c) < 127))
    rep.replacement_ratio = _ratio(s, s.count("\ufffd"))
    rep.control_ratio = _ratio(s, len(_CTRL.findall(s)))
    rep.pua_ratio = _ratio(s, len(_PUA.findall(s)))
    rep.score = readability(s)

    # 命中已知乱码片段
    for sign in _MOJIBAKE_SIGNS:
        if sign in s:
            rep.signs.append(sign)

    # 私有区高频码位（做字模映射时的索引）
    if rep.pua_ratio > 0.01:
        from collections import Counter
        cnt = Counter(ch for ch in s if _PUA.match(ch))
        rep.pua_codes = [f"U+{ord(c):04X}" for c, _ in cnt.most_common(12)]

    # ---- 判定优先级 ----
    # 先排除字体加密：它看着最像"加密"，但其实和加密无关，误判会白折腾
    if rep.pua_ratio > 0.06:
        rep.kind = G_PUA
        rep.note = ("私有区字符占 {:.0%} → 字体加密（字符码位被重映射到 U+E000+）。"
                    "这不是 AES 那类加密，拿字体文件做字模比对才能还原；"
                    "纯文本层面无法还原。".format(rep.pua_ratio))
        return rep

    # 再试修复：必须在"判成二进制"之前试。
    # 原因：UTF-8 字节被 Latin-1 解出来，0x80–0x9F 那一批会变成 C1 控制字符，
    # 控制字符占比很高，先判就永远到不了修复这一步（这个坑踩过）。
    fixed, how = repair(s)
    if fixed and readability(fixed) > rep.score + 12:
        rep.fixed, rep.fixed_by = fixed, how
        rep.kind = G_MOJIBAKE
        rep.note = f"编码链错位，用 {how} 还原成功（可读性 {rep.score} → {readability(fixed)}）"
        rep.score = readability(fixed)
        return rep

    # 修不动，且替换符/控制符占大头 → 认定这不是文本
    if rep.replacement_ratio > 0.15 or rep.control_ratio > 0.10:
        rep.kind = G_REPLACEMENT if rep.replacement_ratio > rep.control_ratio else G_CONTROL
        rep.note = ("解出来仍然有超过 15% 的替换字符 → 这段不是文本，"
                    "多半还是密文或二进制；说明解密没成")
        return rep

    if rep.signs:
        rep.kind = G_MOJIBAKE
        rep.note = "命中已知乱码片段：" + "、".join(rep.signs[:4]) + "，但自动修复未成功"
        return rep

    if rep.cjk_ratio > 0.55 or rep.ascii_ratio > 0.80:
        rep.kind = G_CLEAN
        return rep

    rep.kind = G_MIXED
    rep.note = ("字符分布杂乱（中文 {:.0%} / ASCII {:.0%}），既不像正常文本也不像纯密文，"
                "可能压缩过或部分加密".format(rep.cjk_ratio, rep.ascii_ratio))
    return rep


# ---------------------------------------------------------------------------
# 修复：编码链反向
# ---------------------------------------------------------------------------

# (用哪个编码把当前字符串 encode 回去, 再用哪个编码 decode)
# 顺序按命中率排：UTF-8 被当 Latin-1 解的情况最多
_REPAIR_CHAINS: list[tuple[str, str, str]] = [
    ("latin1", "utf-8", "Latin-1→UTF-8"),
    ("cp1252", "utf-8", "CP1252→UTF-8"),
    ("gb18030", "utf-8", "GB18030→UTF-8"),
    ("gbk", "utf-8", "GBK→UTF-8"),
    ("latin1", "gb18030", "Latin-1→GB18030"),
    ("cp1252", "gb18030", "CP1252→GB18030"),
    ("utf-8", "gb18030", "UTF-8→GB18030"),
    ("latin1", "big5", "Latin-1→Big5"),
    ("latin1", "shift_jis", "Latin-1→Shift-JIS"),
]


def repair(text: str) -> tuple[str, str]:
    """
    尝试把乱码还原。返回 (修好的文本, 用了哪条链)；修不动返回 ("", "")。

    原理：字符串是「字节 + 错误编码」的产物。
    按错误编码 encode 回去，就还原出原始字节；再按正确编码 decode，就得到原文。
    难点是事先不知道哪个编码是错的，所以全部常见组合都试一遍，用可读性选最优。
    """
    if not text or len(text) > 2_000_000:
        return "", ""
    base = readability(text)
    best, best_score, best_how = "", base, ""
    for enc_from, enc_to, how in _REPAIR_CHAINS:
        try:
            raw = text.encode(enc_from)
        except (UnicodeEncodeError, LookupError):
            continue
        if b"\xef\xbf\xbd" in raw:
            # 原文已经含替换字符，encode 回去只会带着毒，先剔掉
            raw = raw.replace(b"\xef\xbf\xbd", b"")
        try:
            cand = raw.decode(enc_to)
        except (UnicodeDecodeError, LookupError):
            continue
        if not cand or cand == text:
            continue
        sc = readability(cand)
        if sc > best_score + 8 and sc >= 45:
            best, best_score, best_how = cand, sc, how
    return best, best_how


def repair_all(text: str, max_rounds: int = 3) -> tuple[str, list[str]]:
    """多轮修复（有的乱码被编错了两次，比如 UTF-8 → GBK → latin1）。"""
    used: list[str] = []
    cur = text
    for _ in range(max_rounds):
        nxt, how = repair(cur)
        if not nxt:
            break
        used.append(how)
        cur = nxt
    return cur, used


# ---------------------------------------------------------------------------
# 字节级入口（给解密器用）
# ---------------------------------------------------------------------------

@dataclass
class BytesView:
    """一段字节"看起来"像什么。"""
    decodable: bool = False
    encoding: str = ""
    text: str = ""
    report: GarbleReport | None = None
    score: int = 0


def view(data: bytes, sample: int = 4000) -> BytesView:
    """
    把字节当文本看，给出最佳解码 + 诊断 + 评分。
    解密器拿它判断"这次试解出来了人话没有"。
    """
    v = BytesView()
    if not data:
        return v
    blob = data[:sample]
    best_enc, best_text, best_sc = "", "", -1
    for enc in ("utf-8", "gb18030", "big5", "shift_jis", "utf-16-le"):
        try:
            t = blob.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
        sc = readability(t)
        if sc > best_sc:
            best_enc, best_text, best_sc = enc, t, sc
    if not best_text:
        # 一种编码都解不通 → 用替换模式强行解一份，只为拿到诊断（内容是垃圾，但能定性）
        junk = blob.decode("utf-8", "replace")
        v.report = diagnose(junk)
        v.score = v.report.score
        v.text = ""
        return v
    v.decodable = True
    v.encoding = best_enc
    v.text = best_text[:2000]
    v.report = diagnose(best_text)
    v.score = max(best_sc, v.report.score)
    return v


def looks_encrypted(path: str | Path, sample: int = 65536) -> tuple[bool, GarbleReport | None, str]:
    """
    文件级判断：打开就一片看不懂的东西，到底是什么毛病。
    返回 (是否值得当密文处理, 诊断, 说明)。
    """
    try:
        data = Path(path).read_bytes()[:sample]
    except OSError as e:
        return False, None, f"读不了：{e}"
    if not data:
        return False, None, "空文件"

    v = view(data)
    if v.decodable and v.report and v.report.kind == G_CLEAN and v.score >= 60:
        return False, v.report, f"读出正常{v.report and '文本'}（{v.encoding}），不是密文"

    rep = v.report or GarbleReport()
    if rep.kind == G_MOJIBAKE and rep.fixed:
        return False, rep, f"只是编码错位，已还原：{rep.fixed[:60]}"
    if rep.kind == G_PUA:
        return False, rep, "字体加密（私有区），不是 AES 类加密"
    if rep.kind in (G_REPLACEMENT, G_CONTROL) or not v.decodable:
        return True, rep, "无有效文本结构 → 按密文处理"
    if rep.kind == G_MIXED:
        return True, rep, "部分可读、部分杂乱 → 可能前明文后密文，跑 segments"
    return False, rep, "判定不出，建议直接用 decrypt_auto 试"


# ---------------------------------------------------------------------------
# 报告
# ---------------------------------------------------------------------------

def report_md(rep: GarbleReport, title: str = "文本诊断") -> str:
    L = [f"## {title}", "",
         f"- 长度：{rep.length}",
         f"- 结论：**{G_CN.get(rep.kind, rep.kind)}**",
         f"- 可读性：{rep.score}/100",
         f"- 中文占比：{rep.cjk_ratio:.1%}　可见 ASCII：{rep.ascii_ratio:.1%}",
         f"- 替换字符：{rep.replacement_ratio:.1%}　控制字符：{rep.control_ratio:.1%}　"
         f"私有区：{rep.pua_ratio:.1%}"]
    if rep.signs:
        L.append(f"- 命中乱码片段：{'、'.join(rep.signs)}")
    if rep.pua_codes:
        L.append(f"- 高频私有区码位：{' '.join(rep.pua_codes)}")
    if rep.note:
        L += ["", f"> {rep.note}"]
    if rep.fixed:
        L += ["", f"**已用 {rep.fixed_by} 修复**，前 200 字：", "",
              "```text", rep.fixed[:200].replace("\n", " "), "```"]
    return "\n".join(L)
