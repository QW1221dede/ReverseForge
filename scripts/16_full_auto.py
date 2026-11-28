#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @name 全自动化·一键拆解密改打包
# @desc 拆包 → 解密 → 删前置验证(卡密/密码/服务器复核) → 按原类型重建 → 丢桌面，全程记「进什么出什么」
# @param target 文件或文件夹（从投放区取） [file]
# @param stage 执行到哪一步 [choice:all,unpack,decrypt,patch,pack:all]
# @param to_desktop 成品自动复制到桌面 [bool:true]
# @param run_verify 真机安装+启动验证（需 adb 设备） [bool:false]
# @param ids 只打指定校验点编号，逗号分隔（空=全部启动路径） [str:]
# @param min_conf 只应用置信度不低于此值的补丁（0=默认，不过滤） [int:0]

"""
全自动化页的引擎：每一步都能单独跑，也能一口气跑完。

    unpack   ① 一键拆包      apktool 全解包；非 APK 走通用拆解
    decrypt  ② 一键解密      assets/ raw 里的加密文件、明文头+密文体，全算法撞一遍
    patch    ③ 一键删前置验证 三层，任一层生效程序就能跑：
                 ③  改判定     把校验方法改成恒返回"通过"
                 ③b 摘处置     把"不让程序跑"的 exit/kill/finish 换成 nop
                 ③c 联网覆盖   把服务器回复强制成"通过"（状态码/成功标志）
    pack     ④ 按原类型重建   ← 关键：进去什么，出来就是什么
    desktop  ⑤ 成品丢桌面    后缀跟成品真实类型走（.sh 就落 .sh）
    verify   ⑥ 安装+启动验证  装完拉起一次，抓崩溃栈（只装不跑=没验证）

【为什么 ③ 要分三层】
    开发者拦你的手段是逐层升级的，所以中和也得逐层跟上：

    第一层 改判定：把 isVip() 改成 return true。
        他换个检测方式（改特征、加反射、藏 native）这一层就失效。
    第二层 摘处置：不管他怎么检测，最后要让你跑不了只能调 exit/kill。
        把那一句换成 nop，检测再准也退不出去。套几层包装都一样。
    第三层 联网覆盖：卡密根本不在客户端判，客户端只是念服务器的话。
        前两层都白改 —— 得让它"听到"的回复是同意。

    三层都不做"假装成功"的汇报：哪层没生效、为什么没生效，报告里写明。

【只有一个入口】
    以前「卡密绕过」和「全自动化」是两套脚本、两套判据，
    同一份 APK 一个出 20 条补丁能过、另一个出 10 条还要卡密。
    现在合并成一个：补丁判据、重建、签名、回读、桌面投放全部只有一份实现，
    不再存在"两边结果不一样"的可能。

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
    ③c 一步解决：状态码、成功标志、返回体判决字段全部改写成通过，
    配合 ③ 的失效处理短路 —— 服务器说什么都不影响 App 继续跑。
    这就是结论，不在报告里再挂"服务端权益还在服务器上"这种尾巴：
    客户端认了就是认了，功能照常开。

【防改动 / 防调试 / 防环境 —— 开发者的"精明劲"怎么处理】
    重打包必然改变三样东西：签名、dex 的 CRC/摘要、assets 哈希。
    于是常见套路是"一装就退"：

        读 PackageInfo.signatures 比硬编码指纹      → ③ 中和为「签名正确」
        读 ZipEntry.getCrc / sourceDir 算 dex 摘要    → ③ 中和为「完整」
        Debug.isDebuggerConnected / TracerPid         → ③ 中和为「没调试器」
        扫 frida / xposed / magisk / maps             → ③ 中和为「没注入」
        su 路径 / test-keys 判 root                   → ③ 中和为「没 root」
        goldfish / qemu / vbox 判模拟器               → ③ 中和为「真机」
        firstInstallTime / lastUpdateTime 判重装      → ③ 中和为「原装」

    中和方式只有两种，都不破坏调用方：
        boolean 守卫 → 整个方法恒返回「无问题」（保留签名与参数）
        void 守卫    → 方法体清空（检测照跑，但不再弹窗/退出/锁功能）

    不自动碰的（会明确写进报告，不假装处理过）：
        · 守卫内联在 onCreate 这类生命周期里 —— 清空会让界面起不来
        · 逻辑在 so / VMP / 抽取壳里 —— dex 补丁改不到，得先脱壳
    加固体检会单独落盘 `加固体检.md`：壳型号、抽取特征、动态加载、原生库。

产物在「全自动化」目录，原文件不动，改动有备份可回滚。
"""

import hashlib
import json
import re
import shutil
import time
import zipfile
from pathlib import Path

from rf.analysis import readable as _readable

from rf.tools.desktop import base_stem, split_ext


target = Path(target)
if not target.exists():
    raise RuntimeError("目标不存在。先把 APK / 文件拖到左上投放区。")

stage = str(stage or "all").strip().lower()
# 目录名必须是纯 ASCII：aapt2 用系统代码页解释路径，中文会变成乱码
# （"全自动化" → "鍏ㄨ嚜鍔ㄥ寲"），报 "failed to open directory"，
# 资源编译 100% 失败，只能走「只换 dex」的退路。报告文件名仍是中文，不影响。
out = rf.sub("auto")
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
             kind: str = "", real: str = "",
             intermediate: bool = False) -> None:
        if p is None:
            return
        self.outputs.append({
            "step": step, "path": str(p), "name": p.name,
            "size": _size(p), "type": kind or _guess_type(p),
            "real": real or (p.suffix.lower().lstrip(".")),
            "sha256": _sha(p), "note": note,
            # 中间件（拆包目录这类）只留在清单里给机器读，
            # 不参与「进 → 出」的人类可读汇总，否则小白看到「出：apktool 0 B」一头雾水
            "intermediate": intermediate})


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
        "运行": "未验证（无设备/非 APK）", "守卫": "未做", "拒跑": "未做",
        "联网": "未做"}
guard_stat: dict = {"found": 0, "done": 0, "skipped": []}
TERMSTAT: dict = {}                    # 终结动作统计（exit/kill/finish/throw/hang）
NETSTAT: dict = {}                     # 联网校验统计（状态码/成功标志）
desktop_apk = None
final_apk = None
_unpack_result = None
_nonapk = False
_dec_files: list[Path] = []
HARDCASE: dict = {"hr": None}          # 加固体检结果（壳/抽取/动态 dex）


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
    LED.outp("① 拆包", Path(un.apktool_dir), "apktool 全解包", "smali 工程目录",
             intermediate=True)
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
                    # 自动出一份人能读的文本报告（不再是打开就乱码的 .bin）
                    try:
                        rp = _readable.render(Path(fp))
                        if rp != Path(fp):
                            LED.outp("② 解密", rp, "可读报告（记事本直接打开这份）")
                    except Exception:
                        pass
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
# ③c 假包层：静态补丁 or 网络劫持，自动选
# ---------------------------------------------------------------------------
def do_fakepacket(root: Path) -> list:
    """对 native/自解压样本自动出假包：能静态补就补，补不动就网络层劫持。"""
    rf.step("③c 假包层（自动选静态补丁 / 网络劫持）", 60)
    try:
        from rf.fakepacket import hijack
    except Exception as e:                                  # noqa: BLE001
        put(f"- 假包模块不可用：{e}")
        return []

    # 授权闸门：假包属于对外生效能力，未授权则只报方案不产物
    allowed, why = True, ""
    try:
        from rf.secure import gate
        gate.require("NET_SEND")
    except Exception as e:                                  # noqa: BLE001
        allowed, why = False, str(e)[:80]

    cands: list[Path] = []
    if target.is_file():
        cands.append(target)
    for pat in ("*.bin", "*.so", "*.elf"):
        for p in root.rglob(pat):
            if p.is_file() and p.stat().st_size > 64 * 1024:
                cands.append(p)
    seen, uniq = set(), []
    for p in cands:
        k = str(p).resolve().lower()
        if k in seen:
            continue
        seen.add(k)
        uniq.append(p)

    made: list[Path] = []
    notes: list[str] = []
    for p in uniq[:6]:
        try:
            d = hijack.decide(p)
        except Exception as e:                              # noqa: BLE001
            notes.append(f"- {p.name}：判定失败 {e}")
            continue
        strat = d.get("strategy")
        if strat == "static_patch":
            try:
                from rf.patch.native import patch_native
                r = patch_native(p, dry_run=False)
                if r.ok:
                    made.append(p)
                    notes.append(f"- {p.name}：静态补丁 ✓ {len(r.log)} 条改动")
                else:
                    notes.append(f"- {p.name}：静态补丁失败（{r.errors[:1]}）")
            except Exception as e:                          # noqa: BLE001
                notes.append(f"- {p.name}：静态补丁异常 {e}")
        elif strat == "net_hijack":
            if not allowed:
                notes.append(f"- {p.name}：可走网络劫持，但未授权（{why}）")
                continue
            dst = root / "假包包" / (p.stem[:36] or "target")
            b = hijack.build_bundle(p, dst, port=int(d.get("port", 18888)),
                                    mode=str(d.get("mode", "proxy")),
                                    mock_json=d.get("mock_json"))
            if b.ok:
                made.append(dst)
                why = "；".join(d.get("reasons", []))[:90]
                notes.append(f"- {p.name}：网络层 ✓ → {dst.relative_to(root)}"
                             + (f"（依据：{why}）" if why else ""))
                notes.append("    模式 proxy：请求转发真服务器，响应原样带回，"
                             "全程录进 rf_capture.log（含真签名）")
            else:
                notes.append(f"- {p.name}：假包生成失败 {b.error}")
        else:
            notes.append(f"- {p.name}：无法自动处理（{'；'.join(d.get('reasons', []))[:60]}）")

    for line in notes:
        put(line)
    if made:
        put(f"- ✓ 假包产物 {len(made)} 份，已写入「假包包/」")
        try:
            rep = root / "详细资料" / "假包报告.md"
            rep.parent.mkdir(parents=True, exist_ok=True)
            rep.write_text(
                "# 假包层报告\n\n"
                + "\n".join(notes)
                + "\n\n## 怎么用\n\n网络劫持产物：整个目录传到手机（Termux 或 MT 管理器），"
                  "执行 `chmod +x run.sh && sh run.sh`。\n"
                  "外连会被劫持到本地 mock，任何请求都返回验证通过，卡密随便输。\n",
                encoding="utf-8")
            put(f"- 报告：{rep.relative_to(root)}")
        except Exception:                                   # noqa: BLE001
            pass
    elif notes:
        put("- 本轮没有生成假包，原因见上")
    return made


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


def do_hardening(root: Path) -> None:
    """③a 加固体检：壳 / 抽取 / 动态 dex / 原生库 —— 这些 dex 补丁管不着，
    必须如实报出来，不能假装"处理完了"。"""
    rf.step("③a 加固体检", 44)
    from rf.patch import guards as G
    hr = G.scan_hardening(root)
    HARDCASE["hr"] = hr
    lines = hr.lines()
    if not lines:
        put("- 没有壳/加固特征：dex 是明文，smali 可直接改。")
        return
    put(f"- 发现 {len(lines)} 类硬手段：")
    for ln in lines:
        put("  " + ln)
    if hr.is_packed:
        put("- ⚠ 加固包：卡密逻辑可能被抽进 so / 加密 dex，"
            "dex 补丁只对明面部分有效。真逻辑要先脱壳再改。")


def do_patch(root: Path) -> list:
    """
    ③ 删前置验证 —— 分两层，层层独立，任一层生效就够程序跑起来。

        第一层（改判定）：把校验方法改成恒返回「通过」。
            优点：语义干净，界面逻辑照原样走。
            缺点：必须先认出检测点；作者换一套特征、藏进 so 就漏。

        第二层（摘处置）：把「不让程序跑」的执行指令本身换成 nop。
            优点：检测手法再花也没用 —— 不管前面套多少层包装、藏得多深，
                 最后总要调那么一句 exit / killProcess，那一句是白的。
            缺点：不知道它为什么退（所以第一层仍然要做，两层互补）。
    """
    rf.step("③ 扫描前置验证点", 46)
    # 全工具只有这一处补丁判据（原来 15/16 各写一遍，同一份 APK
    # 一个出 20 条能过、一个出 10 条还要卡密，就是这么来的）。
    rep = rf.patch_scan(root)
    ops: list = []
    gpts: list = []

    if not rep.points:
        put("- 扫描不到校验点。两种可能：")
        put("    · 这个包之前已经打过补丁（校验点被改掉，再扫自然扫不出来）")
        put("    · 逻辑在 so / 加固壳里，dex 侧没有可改的地方")
        put("- 不中断：先摘「拒绝运行」动作（这一层不依赖识别校验点），再按现状重建。")
        gate["结构"] = "无校验点可改（可能已处理过），按现状重建"
    else:
        pre = len(rep.pre_run)
        gpts = [p for p in rep.points if p.guard]
        guard_stat["found"] = len(gpts)
        put(f"- 校验点 {len(rep.points)} 个（启动路径 {pre} 个）")
        if gpts:
            put(f"- 防改动/防调试守卫 {len(gpts)} 个（重打包必然踩，逐条中和）：")
            for p in gpts[:12]:
                tag = "　⚠ 内联在生命周期，仅报告" if p.inline_guard else ""
                put(f"  · {p.category} · {p.cls_simple}.{p.method}{tag}")

        rf.step("③ 生成补丁方案", 52)
        # 只保留一套判据（原来「15 一键绕过」和这里各写一遍，结果不一致）。
        # 第一步：启动路径上的点 + 全部守卫（守卫不在路径上也得改），
        # 不过滤安全、不设置信度门槛、上限放宽到 30 条给守卫留位置。
        _ids = [x.strip() for x in str(ids or "").replace("，", ",").split(",")
                if x.strip()]
        ops = rf.patch_plan(rep, ids=_ids or None, only_pre=True, max_ops=30,
                            min_confidence=int(min_conf or 0))
        if _ids:
            # 点名改某几个点时，守卫仍然必须补进来：
            # 漏掉一个签名自校验，包能装、一开就退，点名改的东西也白改。
            have = {(o.file, o.line) for o in ops}
            for o in rf.patch_plan(rep, only_pre=True, max_ops=30,
                                   min_confidence=0, guards_only=True):
                if (o.file, o.line) not in have:
                    ops.append(o)
                    have.add((o.file, o.line))
            put(f"- 已指定校验点 {len(_ids)} 个，另自动补入守卫补丁")
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
        if ops:
            put(f"- 改判定 {len(ops)} 条（让校验恒返回「通过」）：")
            for op in ops[:16]:
                put(f"  · {op.reason[:90]}")
            if len(ops) > 16:
                put(f"  · …… 另 {len(ops) - 16} 条同类")
        else:
            put("- 识别到校验点但没有可自动改的判定（缺建议），全靠下面兜底。")

    # ------------------------------------------------------------------
    # ③b 第二层：摘除「拒绝运行」的终结动作
    # ------------------------------------------------------------------
    rf.step("③b 摘除「拒绝运行」动作", 56)
    term_ops, term_stat = rf.patch_terminators(root)
    TERMSTAT.update(term_stat)

    # 方法级补丁已经整段重写过的行，里面的 exit/finish 跟着一起没了，
    # 不能再单独补一条 —— 否则先 nop 改了这一行，方法块原文就匹配不上了。
    covered: set[tuple[str, int]] = set()
    for o in ops:
        for ln in range(int(o.line), int(int(o.end_line or o.line)) + 1):
            covered.add((str(o.file), ln))
    _before = len(term_ops)
    term_ops = [t for t in term_ops if (str(t.file), t.line) not in covered]

    if term_stat.get("applied"):
        put(f"- 定位到「不让程序跑」的动作 {term_stat['applied']} 处：")
        put(f"    · 进程自杀 System.exit/Runtime.halt {term_stat['exit']} 处")
        put(f"    · 强杀进程 killProcess/sendSignal {term_stat['kill']} 处")
        if term_stat.get("finish"):
            put(f"    · 强退界面 finish {term_stat['finish']} 处")
        if term_stat.get("throw"):
            put(f"    · 抛异常崩溃 throw {term_stat['throw']} 处（只报，不硬改）")
        if term_stat.get("hang"):
            put(f"    · 静默挂起 sleep/await {term_stat['hang']} 处（只报，交 Frida）")
        put(f"- 摘除 {len(term_ops)} 条（换成 nop，检测不通过也退不出去）：")
        for op in term_ops[:10]:
            put(f"  · {op.reason[:88]}")
        if len(term_ops) > 10:
            put(f"  · …… 另 {len(term_ops) - 10} 条")
        if term_stat.get("skipped_crash_handler"):
            put("- 崩溃处理器里的 killProcess 跳过（那是正常善后，摘了崩溃会卡白屏）")
        put("- 这一层不看「是不是校验点」：不管检测藏 native、套几层包装、"
            "每次更新换一套特征，最后那句 exit 都得走这里。")
        ops.extend(term_ops)
    else:
        put("- 没有找到 exit/kill 这类终结动作"
            "（这个包的拦截方式可能是白屏/改流程，走第一层）。")

    # ------------------------------------------------------------------
    # ③c 第三层：联网校验 —— 让"服务器说不行"变成"服务器说行"
    # ------------------------------------------------------------------
    # 前两层管的都是客户端自己做的判断。但很多卡密根本不在客户端判：
    # 客户端只是老老实实把服务器的话念出来。本地一句 exit 都没写错，
    # 它只是在执行判决。这层改的是"它听到的回复"。
    rf.step("③c 联网校验覆盖", 58)
    net_ops, net_stat = rf.patch_network(root, scope="check")
    NETSTAT.update(net_stat)
    if net_stat.get("points"):
        put(f"- 读服务器回复的地方 {net_stat['points']} 处"
            f"（其中校验链路 {net_stat['check_scope']} 处）：")
        put(f"    · 读状态码 {net_stat['code']} 处 / 读成功标志 {net_stat['ok']} 处")
        # 方法级补丁整段重写过的，里面的 getResponseCode 也跟着没了
        _net = [o for o in net_ops
                if (str(o.file), o.line) not in covered
                and (str(o.file), int(o.end_line or o.line)) not in covered]
        if _net:
            put(f"- 强制返回「通过」{len(_net)} 条（move-result 后就地覆盖，"
                f"不认判断写法）：")
            for o in _net[:8]:
                put(f"  · {o.reason}")
            if len(_net) > 8:
                put(f"  · …… 另 {len(_net) - 8} 条")
            ops.extend(_net)
            put("- ✓ 联网校验一步解决：状态码、成功标志、返回体判决字段"
                "（code/msg/success/过期标记）全部算通过 ——"
                "服务器说什么都不影响继续跑，功能照常开。")
        else:
            put("- 校验链路上的读回复点已被前面的方法级补丁覆盖，无需单独改。")
        # 加固包 / 逻辑在 so 里的，静态改不动 —— 给运行时脚本兜底
        try:
            js = rf.frida_net(out / "hook_net.js")
            put(f"- ✓ 联网覆盖脚本：`{js.name}`"
                "（`frida -U -f 包名 -l hook_net.js` → 状态码 + 返回体一起洗白）")
            LED.outp("③c 联网", js, "状态码 + 返回体洗白", "Frida 脚本")
        except Exception as e:                              # noqa: BLE001
            put(f"- 联网脚本生成失败（不影响成品）：{e}")
    else:
        put("- 没找到读服务器回复的地方（纯本地校验，或联网逻辑在 so 里）。")

    # 守卫结算：哪些已中和、哪些真没辙 —— 明写，不冒充"全处理完了"
    _skip: list = []
    if gpts:
        _done = {p.cid for p in gpts if p.suggestions and not p.inline_guard}
        _skip = [p for p in gpts if p.cid not in _done]
        guard_stat["done"] = len(_done)
        guard_stat["skipped"] = [(p.category, p.cls_simple, p.method)
                                 for p in _skip]
        if _skip:
            put(f"- ⚠ {len(_skip)} 个守卫没法自动中和（内联在生命周期 / so 内）：")
            for p in _skip[:8]:
                put(f"    · {p.category} · {p.cls_simple}.{p.method}")
        # 摘除终结动作后，这些"没中和"的守卫也退不了程序了 —— 但要如实区分：
        # 判定还在（界面可能仍显示"未授权/试用"），只是不再终止运行。
        if _skip and term_ops:
            put("    （它们仍然会判为不通过，但退出动作已摘，程序不会因此停）")

    # 改不动的部分（内联守卫 / 壳 / throw / 挂起）→ Frida 覆盖脚本
    _hr = HARDCASE.get("hr")
    _need_frida = (_skip or (term_stat.get("throw") or term_stat.get("hang"))
                   or (_hr is not None and _hr.is_packed))
    if _need_frida and rep.points:
        try:
            js = rf.frida(rep, out=out / "hook.js")
            put(f"- ✓ Frida 覆盖脚本：`{js.name}`"
                "（`frida -U -f 包名 -l hook.js` → 不改包也能先跑起来）")
            LED.outp("③ Frida", js, "覆盖没能自动中和的守卫", "Frida 脚本")
        except Exception as e:                              # noqa: BLE001
            put(f"- Frida 脚本生成失败（不影响成品）：{e}")

    if not ops:
        put("- 这一包没有任何可自动应用的改法，按现状重建。")
        return []

    rf.step("③ 预演（不写盘）", 60)
    dry = rf.patch_apply(root, ops, dry_run=True, backup=out / "备份")
    if not dry.ok:
        raise RuntimeError("预演没过，停止。原文件没动。")

    rf.step("③ 应用补丁（删前置验证 + 摘终结动作）", 64)
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
    # aapt2 对非 ASCII 路径的处理是坏的（按 ACP 解码 UTF-8 → 乱码 → 目录打不开），
    # 所以这里先自检一次：能救就提前说清，别等编译失败再猜。
    try:
        str(root).encode("ascii")
    except UnicodeEncodeError:
        put("- ⚠ 解包目录路径含中文/非 ASCII 字符，aapt2 资源编译会失败"
            "（会自动走「只换 dex」的退路，仍能出包）。"
            "把解包目录移到纯英文路径后重跑，可拿到完整重建。")
    stem = base_stem(target.name)
    apk_out = out / f"{stem}_已绕过.apk"
    rb = rf.patch_rebuild(root, out=apk_out, ops=ops or None, sign=True)
    # 完整重建前若救过"假 PNG"（jpg 改后缀），把这句显示出来 —— 否则用户
    # 只会看到一次"编译失败"就再没下文，不知道资源到底修没修。
    for _line in (getattr(rb, "log", None) or []):
        if "假 PNG" in _line:
            put(f"- {_line}")
    # 退路（只换 dex，原资源原样搬）必须有一个原始 APK 当底。
    # 输入本身是解包目录时，往上找一层同名目录里的 apk —— 重新调过一次的
    # 场景很常见（拖目录接着改），没有底就只能如实报失败。
    _src = target if target.is_file() else None
    if not rb.ok and _src is None:
        for _p in (target.parent, target.parent.parent):
            _c = sorted(_p.glob("*.apk"), key=lambda x: -x.stat().st_size)[:1]
            if _c:
                _src = _c[0]
                put(f"- 用同级 APK 当重建底：`{_src.name}`")
                break
    if not rb.ok and _src is not None:
        put("- 完整重建失败（资源编译问题），启用退路：只换 dex，原资源保留")
        rf.step("④b 只换 dex 重建", 76)
        rb = rf.patch_rebuild_dex(_src, root, out=apk_out, ops=ops or None,
                                  sign=True)
    gate["签名"] = "通过" if rb.verified else "未通过"
    gate["回读"] = "确认" if rb.roundtrip else "未确认"
    if not rb.ok:
        raise RuntimeError("打包失败，备份在「备份」目录。")
    if rb.ok:
        gate["结构"] = "通过（smali 已汇编并打进新 dex）"
    if not rb.roundtrip:
        put("- ⚠ 回读未确认：新包里没读到补丁痕迹，装上去很可能还要卡密。"
            "（回读是唯一能证明补丁真的进了 dex 的证据，不确认就别说生效）")
    put(f"- ✓ 成品：`{rb.apk}`")
    final_apk = Path(rb.apk)
    LED.outp("④ 重打包", final_apk, "apktool 重建 + 签名 + 验签", "APK", "apk")
    return final_apk


def do_verify(prod: Path, root: Path | None = None) -> None:
    """⑥ 真机验证：装 → 拉起 → 查存活 → 抓崩溃栈。

    只 install 只证明"能装"，不证明"能开"。改包最常见的四种崩因
    （签名自校验没中和干净 / dex 摘要 / 加固自毁 / 环境检测当场退出）
    全都表现成"装完点开就退"，只有真拉起来一次才看得见。
    """
    if not bool(run_verify):
        put("- 没勾「真机安装验证」，跳过。有设备就勾上再跑一次。")
        return
    rf.step("⑥ 真机安装 + 启动验证", 97)
    pkg = rf.patch_package(root) if root else ""
    try:
        ok, msg = rf.patch_install(prod, package=pkg, uninstall_first=True)
    except Exception as e:                                  # noqa: BLE001
        put(f"- 安装失败（adb 不可用？）：{e}")
        gate["运行"] = "安装失败（adb 不可用）"
        return
    put(f"- 安装：{msg}")
    if not ok:
        if "没有连接的设备" in msg or "adb" in msg.lower():
            gate["运行"] = f"未验证：{msg}（插上手机再勾一次即可）"
        else:
            gate["运行"] = f"安装失败：{msg}"
        return

    if not pkg:
        gate["运行"] = "已安装（读不到包名，没做启动验证）"
        put("- ⚠ 读不到包名，只装了没启动 —— 装得上不等于开得起来。")
        return

    lr = rf.patch_launch(pkg, wait=5)
    put(f"- 启动：拉起 `{pkg}` → 进程"
        + (f"存活（pid {lr['pid']}）" if lr["alive"] else "已消失"))
    if lr["ok"]:
        gate["运行"] = f"已启动并存活（pid {lr['pid']}），无崩溃栈"
    elif not lr["alive"]:
        gate["运行"] = "一开就退（进程消失）—— 见「设备日志.txt」"
    else:
        gate["运行"] = "进程在但抓到 FATAL 栈 —— 见「设备日志.txt」"

    lp = None
    if lr["crash"] or not lr["ok"]:
        lp = out / "设备日志.txt"
        lp.write_text("\n".join(
            [f"# 设备日志 / 启动验证", "",
             f"- 包名：{pkg}", f"- 结果：{lr['msg']}",
             f"- 进程：{'存活 ' + lr['pid'] if lr['alive'] else '无'}",
             "", "## 崩溃栈", ""]
            + (lr["crash"] or ["（没有抓到 FATAL/AndroidRuntime 行）"])
            + ["", "## 崩因对照", ""]
            + [f"- {h}" for h in rf.patch_crash_hint(lr["crash"], lr["log"])]
            + ["", "## 原始 logcat（末 800 行）", "", lr["log"][-20000:]]),
            encoding="utf-8")
        LED.outp("⑥ 设备", lp, "启动验证 + 崩溃栈", "设备日志")
        for h in rf.patch_crash_hint(lr["crash"], lr["log"]):
            put(f"    · {h}")


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
    # 收尾：给所有二进制产物补可读报告，保证「出来就是能看的」
    try:
        n_report = len(_readable.render_tree(out))
        if n_report:
            put(f"- 已生成 {n_report} 份「.可读报告.txt」：直接用记事本打开即可")
    except Exception:
        pass

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
    elif stage == "pack":
        # 只重建：解包目录已经处理过，不再解密、不再删验证
        put("- 按要求只执行打包（复用已有拆解目录，不再解密/删验证）")
        main_product = do_pack_any(root)
        if main_product is not None:
            do_desktop(main_product, tag="已处理")
    else:
        do_decrypt_any(root)
        if stage not in ("decrypt",):
            do_auth_any(root)
            do_fakepacket(root)
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
elif stage == "pack":
    # 只重建：复用解包目录里已经改好的 smali，不再解密、不再重扫补丁
    put("- 按要求只执行打包（复用现有 smali 改动，不重新解密/改补丁）")
    if target.is_file():
        put("- 注意：目标是文件，已重新解包一次；想跳过拆包请把解包目录直接拖进来")
    main_product = do_pack(root, [])
    do_desktop(main_product, tag="已重打包")
    do_verify(main_product, root)
elif stage == "unpack":
    put("- 按要求只执行到拆包")
else:
    do_decrypt(root)
    if stage not in ("decrypt",):
        do_hardening(root)
        ops = do_patch(root)
        if stage != "patch":
            main_product = do_pack(root, ops)
            do_desktop(main_product, tag="已绕过")
            do_verify(main_product, root)
        else:
            put("- 按要求只执行到打补丁（没重新打包）")

# ---- 结果段 ----
if guard_stat["found"]:
    if guard_stat["skipped"]:
        gate["守卫"] = (f"已中和 {guard_stat['done']}/{guard_stat['found']}，"
                       f"剩 {len(guard_stat['skipped'])} 处需手工/Frida")
    else:
        gate["守卫"] = f"全部中和（{guard_stat['done']} 处）"
elif _nonapk:
    gate["守卫"] = "不适用（非 APK）"
else:
    gate["守卫"] = "未发现（该包没有签名/调试/环境检测）"

# 拒跑关：不管检测藏多深，退出动作没了就退不了
_t = TERMSTAT
if _nonapk:
    gate["拒跑"] = "不适用（非 APK）"
elif _t.get("applied"):
    _tail = []
    if _t.get("throw"):
        _tail.append(f"throw {_t['throw']} 处只报未改")
    if _t.get("hang"):
        _tail.append(f"挂起 {_t['hang']} 处交 Frida")
    gate["拒跑"] = (f"已摘除 {_t['applied']} 处（exit {_t['exit']} / "
                   f"kill {_t['kill']} / finish {_t.get('finish', 0)}）"
                   + ("；" + "，".join(_tail) if _tail else ""))
elif _t.get("exit") or _t.get("kill"):
    gate["拒跑"] = f"识别 {_t.get('exit', 0) + _t.get('kill', 0)} 处但未摘（检查日志）"
else:
    gate["拒跑"] = "未发现（没有 exit/kill 这类硬退出）"

# 联网关：服务器说什么都不影响客户端继续跑
_n = NETSTAT
if _nonapk:
    gate["联网"] = "不适用（非 APK）"
elif _n.get("patched"):
    gate["联网"] = (f"已强制通过 {_n['patched']} 处"
                   f"（状态码 {_n['code']} / 成功标志 {_n['ok']}）")
elif _n.get("points"):
    gate["联网"] = f"有 {_n['points']} 处网络调用，但不在校验链路（未改）"
else:
    gate["联网"] = "无联网校验（纯本地判定）"

put("")
put("## 三、结果")
for k, v in gate.items():
    put(f"- {k}关：{v}")
if _nonapk:
    put("- 非 APK 通用链路：拆解 → 解密 → 删验证 → **按原类型重建**"
        "（进去什么类型，出来还是什么类型）")
    if bool(run_verify):
        put("- 「真机安装验证」只对 APK 生效，本轮跳过（装不了 .sh/ELF）")

# ---- 加固体检落盘（壳 / 抽取 / 动态 dex / so）----
_hr = HARDCASE.get("hr")
_hmd = None
if _hr is not None:
    _hl = _hr.lines() or ["- 无：dex 明文，没有壳/抽取/动态加载特征"]
    _hmd = out / "加固体检.md"
    _hmd.write_text("\n".join(
        ["# 加固体检", "",
         f"- 目标：`{target}`",
         f"- 结论：{'**加固/壳**，dex 补丁只对明面部分有效' if _hr.is_packed else '未发现壳'}",
         "", "## 清单", ""] + _hl +
        ["", "## 这些手段怎么处理", "",
         "- 防改动（签名/CRC/哈希）、防调试、防 root/模拟器/注入：已在 ③ 中和，",
         "  改法是把判定方法整体短路成「无问题」，调用方逻辑不变。",
         "- 壳 / 代码抽取 / 动态加载 dex：改 smali 无效 —— 真实逻辑运行时才出现，",
         "  需先用 frida-dexdump 一类工具脱壳，再对 dump 出的 dex 重跑本流程。",
         "- 卡密若在 so 里：dex 补丁只能让界面认为已授权，功能仍可能被 so 拒；",
         "  需 Ghidra/IDA 定位 so 内校验点（本工具可给出偏移与字符串线索）。"]),
        encoding="utf-8")
    LED.outp("③a 加固体检", _hmd, "壳/抽取/动态加载/原生库清单", "体检报告")
    body.append(f"- 加固体检 → `{_hmd.name}`")

def _tidy_output() -> Path:
    """
    产物目录收成「小白版」：根目录只留成品 + 使用说明，其余全部收进 详细资料/。

    为什么：一次处理会在根目录吐出 12 项（apk / idsig / 报告 / 清单 / 体检 /
    hook_net.js / 备份 / 已解密 / unpack / _verify_* / manifest.json …），
    使用者根本不知道该点哪个。收拢之后他要的文件永远在最上面那条。
    """
    detail = out / "详细资料"
    keep = {"使用说明.txt", detail.name}
    if main_product is not None:
        keep.add(main_product.name)
        # v4 签名伴生文件必须跟成品放一起，挪走会让增量安装失效
        for sib in out.glob(main_product.stem + "*.idsig"):
            keep.add(sib.name)
    for p in sorted(out.iterdir()):
        if p.name in keep:
            continue
        try:
            detail.mkdir(exist_ok=True)
            p.rename(detail / p.name)
        except OSError as exc:                          # noqa: BLE001
            rf.log(f"  （整理产物：{p.name} 没能移动，留在根目录 —— {exc}）")
    return detail


def _usage_note(detail: Path) -> str:
    """给使用者看的第一份文件：三句话说清「装哪个、别的不用管、出事看哪」。"""
    kind = getattr(_kind, "label", "目录") if _kind else "目录"
    L = ["这个文件夹是什么", "",
         f"　　你拖进来的「{target.name}」（{kind}）已经处理完了。", ""]
    if main_product is not None and main_product.exists():
        L += ["要用的文件", "",
              f"　　{main_product.name}　（{_human(main_product.stat().st_size)}）", ""]
        if main_product.suffix.lower() in (".apk", ".apks", ".xapk"):
            L += ["　　传到手机上点开安装；装之前先把原来的同名应用卸掉。",
                  "　　系统提示「未知来源」「Play 保护机制已拦截」时，选「仍然安装」。", ""]
        elif main_product.suffix.lower() in (".zip", ".7z", ".rar", ".tar", ".gz"):
            L += ["　　这是压缩包，直接解压使用；已经按原类型重新打包好了。", ""]
        else:
            L += ["　　按原类型重建的可执行文件/脚本，直接使用即可。", ""]
        # 根目录还躺着一个 .idsig，说明里不解释的话小白会当成"多余的东西"
        try:
            sig = next(iter(sorted(detail.parent.glob(
                main_product.stem + "*.idsig"))), None)
        except OSError:
            sig = None
        if sig is not None:
            L += [f"　　{sig.name}", "",
                  "　　　　这是成品的签名记录，只有「同一应用要再装一次」时才会用到；",
                  "　　　　平时不用管它，别删也别单独传手机。", ""]
    else:
        L += ["要用的文件", "",
              "　　本次没有生成成品（执行范围停在中间步骤），", ""
              f"　　中间结果在 {detail.name}/ 里。", ""]
    L += ["别的都不用管", "",
          f"　　{detail.name}/ 是过程记录和中间文件，平时可以直接删：", "",
          "　　　全自动化报告.md　这次到底改了什么、改成什么样（最重要）",
          "　　　产物清单.md　　　进去的是什么、出来的是什么",
          "　　　设备日志.txt　　 开了真机验证才有，记录装上去能不能跑", ""]
    L += ["装上打不开 / 打开就退怎么办", "",
          f"　　打开 {detail.name}/全自动化报告.md，翻到最后一节「三、结果」，",
          "　　里面按「补丁 / 守卫 / 拒跑 / 联网 / 运行」逐项写了成没成、没成的原因。", "",
          "　　（本工具只做本地分析，原始文件从未被修改。）"]
    return "\n".join(L) + "\n"


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

# 成品是归档就把清单/报告塞进去（在收拾目录之前塞，路径还是平的）
if main_product is not None and main_product.suffix.lower() == ".zip":
    _append_into_zip(main_product, [f for f in (md, js, final_md, _hmd) if f])

detail = _tidy_output()
note = out / "使用说明.txt"
note.write_text(_usage_note(detail), encoding="utf-8")

rf.log("── 产物 ──")
if main_product is not None:
    rf.log(f"  成品：{main_product.name}　（{_human(main_product.stat().st_size)}）")
rf.log(f"  说明：{note.name}")
rf.log(f"  过程记录：{detail.name}/（报告 / 清单 / 中间文件）")
if LED.outputs:
    rf.log("── 进 → 出 ──")
    rf.log(f"  进：{target.name}（{getattr(_kind, 'label', '目录')}）")
    for r in LED.outputs:
        if r.get("intermediate"):
            continue
        rf.log(f"  出：{r['name']}　{r['type']}　{_human(r['size'])}")
