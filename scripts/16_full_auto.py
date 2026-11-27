#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @name 全自动化·一键拆解密改打包
# @desc 拆包 → 解密 → 删前置验证(卡密/密码/服务器复核) → 按原类型重建 → 丢桌面，全程记「进什么出什么」
# @param target 文件或文件夹（从投放区取） [file]
# @param stage 执行到哪一步 [choice:all,unpack,decrypt,patch,pack:all]
# @param to_desktop 成品自动复制到桌面 [bool:true]
# @param min_conf 只应用置信度不低于此值的补丁（0=跟「一键绕过」完全同款，不过滤） [int:0]

"""
全自动化页的引擎：每一步都能单独跑，也能一口气跑完。

    unpack   ① 一键拆包      apktool 全解包；非 APK 走通用拆解
    decrypt  ② 一键解密      assets/ raw 里的加密文件、明文头+密文体，全算法撞一遍
    patch    ③ 一键删前置验证 六类"安全"补丁（APK）；脚本类做源码文本替换
    pack     ④ 按原类型重建   ← 关键：进去什么，出来就是什么
    desktop  ⑤ 成品丢桌面    后缀跟成品真实类型走（.sh 就落 .sh）

【④ 为什么必须按原类型重建】
    之前是「一律打成 zip」，结果 .sh 样本出来一个 zip，
    用户改成 .sh 名去跑 → 手机 mksh 读第 1 行就是 gzip 字节：
        syntax error: unexpected 'M0K...'
    现在：
      · makeself 自解压 .sh → 保留原头 978B / skip=N，只重写数据段，出来还是 .sh
      · zip/rar/7z/tar 归档  → 解包目录重新压成同族压缩包
      · 单文件程序/脚本       → 原后缀单文件
      · APK                  → 原生 .apk（重建+签名+验签）

【进什么出什么】
    每一步都记进台账，收尾写两份机器/人可读清单：
        产物清单.md / manifest.json
    报告开头就是「进去的是什么 / 出来的是什么」两张表。

【带服务器的怎么保证能跑】
    打了 ③ 的补丁后：本地校验全部放行、网络校验结果伪造、
    运行中复核与失效处理被清空 —— 服务器说什么都不影响 App 继续跑。
    服务端真正的权益（远程停卡、在线规则推送）在服务器上，本地补丁不碰。

产物在「全自动化」目录，原文件不动，改动有备份可回滚。
"""

import hashlib
import json
import re
import shutil
import time
import zipfile
from pathlib import Path

from rf.tools.desktop import base_stem, split_ext


target = Path(target)
if not target.exists():
    raise RuntimeError("目标不存在。先把 APK / 文件拖到左上投放区。")

stage = str(stage or "all").strip().lower()
out = rf.sub("全自动化")
out.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# 台账：进去什么、出来什么
# ---------------------------------------------------------------------------
class Ledger:
    def __init__(self) -> None:
        self.inputs: list[dict] = []
        self.outputs: list[dict] = []

    def inp(self, p: Path, kind=None, note: str = "") -> None:
        self.inputs.append({
            "path": str(p), "name": p.name, "size": _size(p),
            "type": getattr(kind, "label", "") if kind else "",
            "real": getattr(kind, "real", "") if kind else "",
            "sha256": _sha(p), "note": note})

    def outp(self, step: str, p: Path | None, note: str = "",
             kind: str = "", real: str = "") -> None:
        if p is None:
            return
        self.outputs.append({
            "step": step, "path": str(p), "name": p.name,
            "size": _size(p), "type": kind or _guess_type(p),
            "real": real or (p.suffix.lower().lstrip(".")),
            "sha256": _sha(p), "note": note})


def _size(p: Path) -> int:
    try:
        return p.stat().st_size
    except OSError:
        return 0


def _sha(p: Path, limit: int = 512 << 20) -> str:
    try:
        if p.stat().st_size > limit:
            return f"（超过 {limit >> 20}MB，未计算）"
        h = hashlib.sha256()
        with p.open("rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


def _human(n: int) -> str:
    x = float(n)
    for u in ("B", "KB", "MB", "GB"):
        if x < 1024 or u == "GB":
            return f"{int(x)} B" if u == "B" else f"{x:.1f} {u}"
        x /= 1024


def _guess_type(p: Path) -> str:
    try:
        from rf.analysis import filetype as _ft
        return _ft.sniff(p).label
    except Exception:                                       # noqa: BLE001
        return p.suffix or "未知"


LED = Ledger()
body: list[str] = []
lines_last: list[str] = []          # 兼容旧的全局名，收尾用它拼报告


def put(s: str = "") -> None:
    body.append(str(s))
    rf.log(str(s))


# ---------------------------------------------------------------------------
# 输入登记
# ---------------------------------------------------------------------------
_kind = None
if target.is_file():
    try:
        _kind = rf.file_type(target)
    except Exception as e:                                  # noqa: BLE001
        put(f"- 类型识别失败（不影响后续）：{e}")
LED.inp(target, _kind, "原始样本（只读，全程不修改）")

gate = {"结构": "未做", "签名": "未做", "回读": "未做",
        "运行": "未验证（无设备/非 APK）"}
desktop_apk = None
final_apk = None
_unpack_result = None
_nonapk = False
_dec_files: list[Path] = []


# ---------------------------------------------------------------------------
# ① 一键拆包
# ---------------------------------------------------------------------------
def do_unpack() -> Path:
    if target.is_dir():
        put("- 已是解包目录，跳过拆包")
        return target
    rf.step("① 一键拆包", 8)
    # 非 APK 容器（zip/rar/iso/文档/加密脚本/固件…）自动切通用拆解，
    # 后续解密/删验证/重建照样跑
    kind = _kind or rf.file_type(target)
    if kind.real != "apk":
        put(f"- 识别为 {kind.label}，不是 APK → 通用拆解 + 通用解密/删验证链路")
        r = rf.unpack_any(target, out=out / "unpack")
        put(f"- ✓ {r['method']}（{r['files']} 个文件）")
        for n in r["notes"][:3]:
            put(f"    · {n}")
        global _unpack_result, _nonapk
        _unpack_result = r
        _nonapk = True
        rep_md = out / "unpack" / "拆解报告.md"
        if rep_md.exists():
            LED.outp("① 拆解", rep_md, f"{r['method']}，{r['files']} 个文件",
                     "拆解报告")
        return out / "unpack"
    un = rf.apk_unpack(target, out=out / "unpack", apktool=True, jadx=False)
    if not un.apktool_dir:
        raise RuntimeError("拆包失败：" + "；".join(un.errors[:3]))
    put(f"- ✓ 解包完成：`{un.apktool_dir}`")
    LED.outp("① 拆包", Path(un.apktool_dir), "apktool 全解包", "smali 工程目录")
    return Path(un.apktool_dir)


# ---------------------------------------------------------------------------
# ①b 通用链路（非 APK 全类型适用）
# ---------------------------------------------------------------------------
def _iter_targets(root: Path, limit: int = 80, max_mb: float = 64) -> list[Path]:
    """挑出要试解/扫描的候选文件：解包目录里的 + 原文件本身（单文件直拖场景）。"""
    files: list[Path] = []
    if target.is_file():
        files.append(target)
    try:
        files.extend(p for p in sorted(root.rglob("*"))
                     if p.is_file() and not p.name.startswith("."))
    except OSError:
        pass
    out_l: list[Path] = []
    for p in files:
        try:
            if p.stat().st_size <= max_mb * (1 << 20):
                out_l.append(p)
        except OSError:
            pass
        if len(out_l) >= limit:
            break
    return out_l


def _own_output(p: Path) -> bool:
    """是不是本工具自己产出的报告 —— 别拿自己的报告去跑解密，
    会解出一堆 1.7KB 的凯撒垃圾把 已解密/ 塞满。"""
    if p.name in ("拆解报告.md", "产物清单.md", "全自动化报告.md", "manifest.json"):
        return True
    if p.suffix.lower() in (".md", ".json") and p.stat().st_size < 256 * 1024:
        try:
            head = p.read_bytes()[:64]
        except OSError:
            return True
        if head.startswith((b"# ", b"{\n", b"{\"", b"#\xe6")):
            return True
    return False


def do_decrypt_any(root: Path) -> int:
    """② 通用解密：解包产物里每个文件全算法撞一遍，命中的落盘。"""
    rf.step("② 一键解密（通用）", 30)
    cands = [p for p in _iter_targets(root) if not _own_output(p)]
    keys = rf.keys_any(root, limit=80)
    put(f"- 候选文件 {len(cands)} 个，候选密钥 {len(keys)} 条")
    saved = 0
    dec_dir = out / "已解密"
    for i, f in enumerate(cands, 1):
        # 只跳过"铁定是明文/容器"的文件；注意**不能**跳过 # 开头的脚本 ——
        # 「大段中文注释头 + 尾部加密块」正是最常见的外挂形态。
        try:
            with f.open("rb") as fh:
                head = fh.read(512)
        except OSError:
            continue
        if head.lstrip()[:1] in (b"{", b"[") or head.startswith(
                (b"PK", b"\x7fELF", b"\x89PNG", b"\xff\xd8")):
            continue
        # 低熵 = 本来就是明文，硬解只会解出一堆假阳性（已知明文攻击对
        # 一段普通文本永远"成功"）。真密文/压缩流熵都在 7 以上。
        try:
            from rf.analysis import crypto as _c
            with f.open("rb") as fh:
                probe = fh.read(64 * 1024)
            if len(probe) < 64 or _c.shannon(probe) < 4.8:
                continue
        except Exception:                                   # noqa: BLE001
            pass
        rf.step(f"试解 {f.name}", int(30 + 20 * i / max(1, len(cands))))
        try:
            rep = rf.decrypt_auto(f, keys=keys, deep=False, budget=20, top=6)
            if rep.hits:
                files = rf.decrypt_save(rep, dec_dir, limit=3, min_score=55)
                saved += len(files)
                for fp in files:
                    _dec_files.append(Path(fp))
                    LED.outp("② 解密", Path(fp), f"从 {f.name} 解出")
        except Exception as e:                              # noqa: BLE001
            put(f"    ! {f.name}：{e}")
    put(f"- ✓ 解密命中落盘 {saved} 份 → 已解密/" if saved
        else "- 解密未命中（可能不是常规算法加密，或本身是明文）")
    return saved


def do_auth_any(root: Path) -> int:
    """③ 通用删验证：脚本源码文本替换（带备份可回滚），PE/ELF 给定位清单。"""
    rf.step("③ 一键删前置验证（通用）", 55)
    changed = 0
    for scan_t in ([target] if target.is_file() else []) + [root]:
        try:
            rep = rf.auth_scan(scan_t, min_confidence=int(min_conf))
        except Exception as e:                              # noqa: BLE001
            put(f"    ! 扫描 {scan_t} 失败：{e}")
            continue
        if not rep.points:
            continue
        put(f"- {len(rep.points)} 个校验点（{scan_t.name or '解包目录'}），"
            "自动应用恒真改法，先备份可回滚")
        try:
            res = rf.auth_apply(rep, dry_run=False, backup_dir=out / "备份")
            changed += len(res.changed or [])
        except Exception as e:                              # noqa: BLE001
            put(f"    ! 应用失败：{e}")
    if changed:
        put(f"- ✓ 已改 {changed} 处（备份在 备份/，可回滚）")
    else:
        put("- 没有能自动改的校验点；PE/ELF 类的偏移定位见上方清单，"
            "用 Ghidra 改跳转")
    return changed


# ---------------------------------------------------------------------------
# ③b 按原类型重建（核心修复）
# ---------------------------------------------------------------------------
_ARCH_ZIP = {"zip", "jar", "whl", "egg", "apk", "ipa", "aab", "apks", "xapk",
             "war", "ear", "epub", "docx", "xlsx", "pptx", "odt", "ods",
             "odp", "msix", "appx", "nupkg", "crx", "xpi", "aar", "sketch"}
_ARCH_TAR = {"tar", "tgz", "gzip", "bzip2", "xz"}
_ARCH_OTHER = {"7z", "rar", "iso", "dmg", "msi", "cab", "wim", "squashfs",
               "ar", "rpm", "zst", "lz4"}


def _sig_files(d: Path, min_size: int = 1024) -> list[Path]:
    if not d.is_dir():
        return []
    res = []
    for p in sorted(d.rglob("*")):
        if not p.is_file() or p.name.startswith(".") or "备份" in p.parts:
            continue
        try:
            if p.stat().st_size >= min_size:
                res.append(p)
        except OSError:
            pass
    return res


def _zip_dir(zpath: Path, src: Path, exclude: set[Path]) -> None:
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(src.rglob("*")):
            if not p.is_file() or p in exclude or "备份" in p.parts:
                continue
            try:
                z.write(p, p.relative_to(src))
            except OSError:
                pass


def do_pack_any(root: Path) -> Path:
    """④ 按原类型重建：进去 .sh 出来就是能跑的 .sh，进去 zip 出来还是 zip。"""
    rf.step("④ 按原类型重建成品", 78)
    stem = base_stem(target.name)
    ext = split_ext(target.name)[1]
    real = (_kind.real if _kind else "") or target.suffix.lower().lstrip(".")

    # --- A) 单文件输入：保真重建，绝不改后缀 ---
    if target.is_file() and real not in (_ARCH_ZIP | _ARCH_TAR | _ARCH_OTHER):
        dst = out / f"{stem}_已处理{ext}"
        r = rf.repack_any(target, dst)
        put(f"- ✓ 成品（{r['kind']}）：`{dst.name}`　{_human(_size(dst))}")
        put(f"    · {r['method']}")
        for n in str(r.get("note", "")).split("；"):
            if n.strip():
                put(f"    · {n}")
        LED.outp("④ 重建", dst, r["method"], r["kind"], real)
        if "直通" in str(r["method"]):
            put("    · 本轮**只做了结构恢复**：payload 字节没动，"
                "所以行为跟原件一致（卡密照旧拦）。")
            put("    · 要真正绕过，得对 payload 里的 ELF 打补丁 —— "
                "偏移清单见上面 ③ 的校验点，确认后单独跑改跳转。")
        gate["结构"] = "已重建为原类型" + ("（自检通过）" if r.get("ok") else "")
        gate["签名"] = "非 APK，不适用"
        gate["回读"] = "非 APK，不适用"
        return dst

    # --- B) 归档输入：解包目录重新压成同族压缩包 ---
    if real in _ARCH_TAR:
        import tarfile
        dst = out / f"{stem}_已处理.tar.gz"
        with tarfile.open(dst, "w:gz") as tf:
            for p in sorted(out.rglob("*")):
                if p.is_file() and p != dst and "备份" not in p.parts:
                    tf.add(p, p.relative_to(out))
        how = "tar.gz 重打（与原类型同族）"
    else:
        dst = out / f"{stem}_已处理.zip"
        _zip_dir(dst, out, {dst})
        how = f"{real or '容器'} → zip 重打（同族可解）"
    put(f"- ✓ 成品归档：`{dst.name}`（{_human(_size(dst))}）　{how}")
    LED.outp("④ 重打包", dst, how, "zip 归档", "zip")
    gate["结构"] = "已重新打包"
    gate["签名"] = "非 APK，不适用"
    gate["回读"] = "非 APK，不适用"
    return dst


def do_dec_bundle(stem: str) -> Path | None:
    """解密产物单独打一份包，方便直接拿走（单文件样本靠这个把成果带出去）。"""
    files = _sig_files(out / "已解密", min_size=1)
    if not files:
        return None
    dst = out / f"{stem}_解密产物.zip"
    _zip_dir(dst, out / "已解密", {dst})
    put(f"- ✓ 解密产物包：`{dst.name}`（{len(files)} 份，{_human(_size(dst))}）")
    LED.outp("④b 解密打包", dst, f"{len(files)} 份解密结果", "zip 归档", "zip")
    return dst


# ---------------------------------------------------------------------------
# ② 一键解密（APK 分支）
# ---------------------------------------------------------------------------
_SKIP_DIRS = {"res", "smali", "smali_classes2", "smali_classes3", "smali_classes4",
              "smali_classes5", "smali_classes6", "original", "build", "dist",
              "unknown", "Backup", "备份"}


def do_decrypt(root: Path) -> int:
    rf.step("② 一键解密", 30)
    cands: list[Path] = []
    for sub in ("assets",):
        d = root / sub
        if d.is_dir():
            cands.extend(p for p in d.rglob("*") if p.is_file())
    raw = root / "res" / "raw"
    if raw.is_dir():
        cands.extend(p for p in raw.rglob("*") if p.is_file())
    seen = set()
    picks: list[Path] = []
    for p in cands:
        if p in seen or p.stat().st_size == 0 or p.stat().st_size > 32 * 1024 * 1024:
            continue
        seen.add(p)
        try:
            head = p.read_bytes()[:16]
        except OSError:
            continue
        known = (head.startswith((b"PK", b"\x89PNG", b"\xff\xd8", b"GIF8",
                                  b"{", b"[", b"<?", b"\xca\xfe\xba\xbe"))
                 or head.lstrip()[:1] in (b"{", b"["))
        if not known:
            picks.append(p)
    if not picks:
        put("- 没有发现疑似加密文件（assets/raw 里的都是明文格式）")
        return 0
    put(f"- 疑似加密文件 {len(picks)} 个，逐个试解：")
    keys = rf.keys_any(root, limit=80)
    saved = 0
    dec_dir = out / "已解密"
    for p in picks[:16]:
        try:
            rep = rf.decrypt_auto(p, keys=[k.value for k in keys
                                           if getattr(k, "value", None)],
                                  deep=False, budget=20, top=3)
            if rep and getattr(rep, "hits", None):
                files = rf.decrypt_save(rep, dec_dir, limit=3, min_score=55)
                saved += len(files)
                for fp in files:
                    _dec_files.append(Path(fp))
                    LED.outp("② 解密", Path(fp), f"从 {p.relative_to(root)} 解出")
                put(f"  · ✓ {p.relative_to(root)} → {len(files)} 份解密结果")
        except Exception as e:                              # noqa: BLE001
            put(f"  · ✗ {p.name}：{e}")
    if not saved:
        put("- 没撞出可解的（算法是自定义的）；不影响 ③ —— "
            "加密的多是规则/配置数据，卡密闸门在 dex 里，已经单独处理")
    else:
        put(f"- ✓ 解密产物 {saved} 份 → `{dec_dir}`")
    return saved


# ---------------------------------------------------------------------------
# ③ 一键删除前置验证（APK 分支）
# ---------------------------------------------------------------------------
def _runtime_kill_switches(rep, chosen: list) -> list:
    """运行中的服务器复核 / 失效处理 —— 只收「清空方法体」这一类。

    为什么这么挑：这类方法名叫 onLicenseInvalid / recheckLicense，
    服务器判卡密失效就调它停功能。清空之后服务器说什么都不影响运行；
    而且它们是 void，清空不会破坏调用方的栈平衡，App 不会崩。
    别的运行时方法（matchIp / domainHit 之类通用判定）一律不碰 ——
    碰了就会出现"包能装、一开就闪退/功能残废"。
    """
    have = {(getattr(o, "file", ""), getattr(o, "line", -1)) for o in chosen}
    pre = {p.cid for p in rep.pre_run}
    out = []
    for p in rep.points:
        if p.cid in pre or not p.best:
            continue
        if p.best.kind != "void_noop":
            continue
        if p.category not in ("授权校验", "完整性校验", "服务端校验"):
            continue
        if p.confidence < 30:
            continue
        op = p.best.op
        if (op.file, op.line) in have:
            continue
        op.reason = (f"[{p.cid}] 运行时短路 · {p.cls_simple}.{p.method}："
                     f"{p.best.label}｜服务器判失效也不停功能")
        out.append(op)
        have.add((op.file, op.line))
    return out


def do_patch(root: Path) -> list:
    rf.step("③ 扫描前置验证点", 45)
    # 判据跟「一键绕过」完全一致（同一套 patch_scan / patch_plan 默认值）。
    # 之前这里多加了 safe_only=True + min_confidence=40，把真正卡住启动的
    # 那几个点滤掉了 —— 结果「一键绕过」能生效、全自动化打出来却还要卡密。
    rep = rf.patch_scan(root)
    if not rep.points:
        put("- 扫描不到校验点。两种可能：")
        put("    · 这个包之前已经打过补丁（校验点被改掉，再扫自然扫不出来）")
        put("    · 逻辑在 so / 加固壳里，dex 侧没有可改的地方")
        put("- 不中断流程：按现有 smali 继续重建，成品照样出（不会被这一步卡死）。")
        gate["结构"] = "无校验点可改（可能已处理过），按现状重建"
        return []

    pre = len(rep.pre_run)
    put(f"- 校验点 {len(rep.points)} 个（启动路径 {pre} 个）")

    rf.step("③ 生成补丁方案（与一键绕过同一套判据）", 52)
    #
    # 第一步：与「一键绕过」**完全同一套** —— 启动路径上的点，不过滤安全、
    #        不设置信度门槛、上限 20 条。之前这里多加了 safe_only=True +
    #        min_confidence=40，20 条被砍到 10 条（MainActivity / LicNet /
    #        LicenseApi / Dh 全被滤掉），所以「绕过」能生效、自动化却还要卡密。
    ops = rf.patch_plan(rep, only_pre=True, max_ops=20,
                        min_confidence=int(min_conf or 0))
    #
    # 第二步：全自动化**唯一多出来的那一步** —— 把运行中的服务器复核 /
    #        失效处理也删掉。只认「清空方法体」这一类（void_noop）：
    #        服务器判卡密失效后调的方法，清空后照样跑，且 void 方法清空
    #        不会破坏调用方的栈平衡，不会让 App 崩（不是无脑全量加补丁）。
    extra = _runtime_kill_switches(rep, ops)
    if extra:
        put(f"- 额外删除运行中服务器校验 {len(extra)} 处（这一步是自动化独有的）：")
        for op in extra:
            put(f"  · {op.reason[:90]}")
        ops.extend(extra)
    if not ops:
        put("- 识别到校验点，但没有可自动应用的改法（缺 best 建议）。"
            "不中断：按现状重建，卡密可能仍需手动处理。")
        gate["结构"] = "有校验点但无自动改法，按现状重建"
        return []
    put(f"- 补丁 {len(ops)} 条（含运行中复核/失效处理）：")
    for op in ops:
        put(f"  · {op.reason[:90]}")

    rf.step("③ 预演（不写盘）", 56)
    dry = rf.patch_apply(root, ops, dry_run=True, backup=out / "备份")
    if not dry.ok:
        raise RuntimeError("预演没过，停止。原文件没动。")

    rf.step("③ 应用补丁（删前置验证）", 60)
    res = rf.patch_apply(root, ops, dry_run=False, backup=out / "备份")
    put(f"- 应用：{res.text().splitlines()[0]}")
    if not res.ok:
        raise RuntimeError("补丁失败，已自动回滚。")
    gate["结构"] = "通过（补丁已写入 smali，预演+应用双校验）"
    return ops


# ---------------------------------------------------------------------------
# ④ 一键打包（仅 APP） + ⑤ 桌面
# ---------------------------------------------------------------------------
def do_pack(root: Path, ops: list) -> Path:
    global final_apk
    rf.step("④ 一键打包（重建+签名+验签）", 72)
    stem = base_stem(target.name)
    apk_out = out / f"{stem}_已绕过.apk"
    rb = rf.patch_rebuild(root, out=apk_out, ops=ops or None, sign=True)
    if not rb.ok and target.is_file():
        put("- 完整重建失败（资源编译问题），启用退路：只换 dex，原资源保留")
        rf.step("④b 只换 dex 重建", 76)
        rb = rf.patch_rebuild_dex(target, root, out=apk_out, ops=ops or None,
                                  sign=True)
    gate["签名"] = "通过" if rb.verified else "未通过"
    gate["回读"] = "确认" if rb.roundtrip else "未确认"
    if not rb.ok:
        raise RuntimeError("打包失败，备份在「备份」目录。")
    if not rb.roundtrip:
        put("- ⚠ 回读未确认：新包里没读到补丁痕迹，装上去很可能还要卡密。"
            "（回读是唯一能证明补丁真的进了 dex 的证据，不确认就别说生效）")
    put(f"- ✓ 成品：`{rb.apk}`")
    final_apk = Path(rb.apk)
    LED.outp("④ 重打包", final_apk, "apktool 重建 + 签名 + 验签", "APK", "apk")
    return final_apk


def do_desktop(prod: Path, tag: str = "已绕过") -> None:
    """成品丢桌面：后缀永远跟成品真实类型走（.sh 落 .sh）。"""
    if not bool(to_desktop):
        put("- 已关闭自动放桌面，成品在产物目录")
        return
    rf.step("⑤ 成品丢桌面", 95)
    try:
        from rf.tools.desktop import drop_to_desktop
        global desktop_apk
        stem = base_stem(target.name)
        dp, msg = drop_to_desktop(prod, name=stem, tag=tag)
        desktop_apk = dp
        put(f"- ✓ {msg}")
        LED.outp("⑤ 桌面", dp, "复制到桌面（后缀=真实类型）", "桌面副本")
    except Exception as e:                                  # noqa: BLE001
        put(f"- 放桌面失败（成品仍在产物目录）：{e}")


# ---------------------------------------------------------------------------
# 清单 + 报告
# ---------------------------------------------------------------------------
def _io_tables() -> list[str]:
    L = ["## 一、进去的是什么（输入）", "",
         "| 文件 | 识别类型 | 大小 | SHA256（前 16 位） |",
         "|---|---|---|---|"]
    for r in LED.inputs:
        L.append(f"| `{r['name']}` | {r['type'] or '—'} | {_human(r['size'])} | "
                 f"`{(r['sha256'] or '')[:16]}` |")
    L += ["", f"完整路径：`{LED.inputs[0]['path'] if LED.inputs else ''}`"
              "（只读，未改动）", "",
          "## 二、出来的是什么（产物，按生成顺序）", "",
          "| # | 环节 | 产物 | 实际类型 | 大小 | 说明 |",
          "|---|---|---|---|---|---|"]
    for i, r in enumerate(LED.outputs, 1):
        L.append(f"| {i} | {r['step']} | `{r['name']}` | {r['type']} | "
                 f"{_human(r['size'])} | {r['note']} |")
    if not LED.outputs:
        L.append("| — | — | （本次没有落盘产物） | — | — | — |")
    if desktop_apk:
        L += ["", f"**桌面成品**：`{desktop_apk}`"]
    return L


def _write_manifest() -> tuple[Path, Path]:
    md = out / "产物清单.md"
    js = out / "manifest.json"
    head = ["# 产物清单（进 → 出）", "",
            f"- 生成时间：{time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"- 原始文件：`{target}`",
            f"- 执行范围：{stage}", ""]
    md.write_text("\n".join(head + _io_tables()), encoding="utf-8")
    js.write_text(json.dumps({
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "target": str(target), "stage": stage,
        "inputs": LED.inputs, "outputs": LED.outputs,
        "desktop": str(desktop_apk) if desktop_apk else ""},
        ensure_ascii=False, indent=2), encoding="utf-8")
    return md, js


def _append_into_zip(zpath: Path, files: list[Path]) -> None:
    """把清单/报告塞进成品 zip 里一份，解压就能看到进→出。"""
    if not zpath.suffix.lower() == ".zip" or not zpath.exists():
        return
    try:
        with zipfile.ZipFile(zpath, "a", zipfile.ZIP_DEFLATED) as z:
            for f in files:
                if f.exists():
                    z.write(f, f.relative_to(out))
    except Exception as e:                                  # noqa: BLE001
        rf.log(f"  （清单塞进 zip 失败，不影响成品）：{e}")


# ---------------------------------------------------------------------------
# 分派执行
# ---------------------------------------------------------------------------
main_product: Path | None = None
root = do_unpack()
if _nonapk:
    if stage == "unpack":
        put("- 按要求只执行到拆包")
    else:
        do_decrypt_any(root)
        if stage not in ("decrypt",):
            do_auth_any(root)
            if stage != "patch":
                main_product = do_pack_any(root)
                stem = base_stem(target.name)
                bundle = do_dec_bundle(stem)
                if main_product is not None:
                    do_desktop(main_product, tag="已处理")
                if bundle is not None and bool(to_desktop):
                    try:
                        from rf.tools.desktop import drop_to_desktop
                        dp, msg = drop_to_desktop(bundle, name=stem,
                                                  tag="解密产物")
                        put(f"- ✓ {msg}")
                        LED.outp("⑤ 桌面", dp, "解密成果单独打包")
                    except Exception as e:                  # noqa: BLE001
                        put(f"- 解密包放桌面失败：{e}")
            else:
                put("- 按要求只执行到删验证（没打包）")
        else:
            put("- 按要求只执行到解密")
elif stage == "unpack":
    put("- 按要求只执行到拆包")
else:
    do_decrypt(root)
    if stage not in ("decrypt",):
        ops = do_patch(root)
        if stage != "patch":
            main_product = do_pack(root, ops)
            do_desktop(main_product, tag="已绕过")
        else:
            put("- 按要求只执行到打补丁（没重新打包）")

# ---- 结果段 ----
put("")
put("## 三、结果")
for k, v in gate.items():
    put(f"- {k}关：{v}")
if _nonapk:
    put("- 非 APK 通用链路：拆解 → 解密 → 删验证 → **按原类型重建**"
        "（进去什么类型，出来还是什么类型）")

md, js = _write_manifest()

# 报告 = 头 + 进→出表 + 过程 + 结果
head = ["# 全自动化报告", "",
        f"- 目标：`{target}`",
        f"- 识别类型：{getattr(_kind, 'label', '目录') if _kind else '目录'}",
        f"- 执行范围：{stage}",
        f"- 产物目录：`{out}`", ""]
final_md = out / "全自动化报告.md"
final_md.write_text("\n".join(head + _io_tables() + [""] + body),
                    encoding="utf-8")

# 成品是归档就把清单/报告塞进去
if main_product is not None and main_product.suffix.lower() == ".zip":
    _append_into_zip(main_product, [md, js, final_md])

rf.log(f"✓ 报告：{final_md}")
rf.log(f"✓ 清单：{md}")
if LED.outputs:
    rf.log("── 进 → 出 ──")
    rf.log(f"  进：{target.name}（{getattr(_kind, 'label', '目录')}）")
    for r in LED.outputs:
        rf.log(f"  出：{r['name']}　{r['type']}　{_human(r['size'])}")
