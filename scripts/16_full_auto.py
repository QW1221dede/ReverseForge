#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @name 全自动化·一键拆解密改打包
# @desc 拆包 → 解密 → 删前置验证(卡密/密码/服务器复核) → 打包 → 丢桌面，全程无人值守
# @param target 文件或文件夹（从投放区取） [file]
# @param stage 执行到哪一步 [choice:all,unpack,decrypt,patch,pack:all]
# @param to_desktop 成品 APK 自动复制到桌面 [bool:true]
# @param min_conf 只应用置信度不低于此值的"安全"补丁 [int:40]

"""
全自动化页的引擎：每一步都能单独跑，也能一口气跑完。

    unpack   ① 一键拆包      apktool 全解包（资源 + 全部 dex → smali）
    decrypt  ② 一键解密      assets/ raw 里的加密文件全撞一遍
                             （XOR/RC4/AES/TEA/XXTEA/OpenSSL Salted）
    patch    ③ 一键删前置验证 六类"安全"补丁，含带服务器的三件套：
                               · 字符串闸门   Cfg.license 空默认值 → 非空
                               · 路由改道     启动直接进主界面，不进卡密页
                               · 布尔闸门     isActivated / Result.ok → true
                               · 结果伪造     verifySync 直接返回已授权
                               · 失效短路     onLicenseInvalid / recheck 清空
                               · 签名校验     certOk → true（改包后不被杀）
    pack     ④ 一键打包      重建 → 对齐 → 签名 → 验签 → 回读核对
    desktop  ⑤ 成品丢桌面    "原名_已绕过.apk"，同名自动加 _2

【带服务器的怎么保证能跑】
    打了 ③ 的补丁后：
      - 本地校验全部放行，启动直达主界面；
      - 网络校验函数被"结果伪造"替换，服务器拒了也当成功；
      - 运行中定时复核（recheck）和失效处理（onLicenseInvalid）被清空，
        服务器判定卡密失效也不会停拦截/停功能；
      - 规则包若是内嵌加密文件（如 assets/dfjl_rules.dat），
        ② 会把解密结果落盘 —— 内置规则照常加载，功能照常跑。
    服务端真正的权益（远程停卡、在线规则推送）在服务器上，
    本地补丁保证的是"服务器说什么都不影响 App 继续运行"。

产物在「全自动化」目录，原文件不动，smali 改动有备份可回滚。
"""

from pathlib import Path

target = Path(target)
if not target.exists():
    raise RuntimeError("目标不存在。先把 APK 拖到左上投放区。")

stage = str(stage or "all").strip().lower()
out = rf.sub("全自动化")
out.mkdir(parents=True, exist_ok=True)
lines = ["# 全自动化报告", "",
         f"- 目标：`{target}`",
         f"- 执行范围：{stage}",
         f"- 产物目录：`{out}`", ""]
gate = {"结构": "未做", "签名": "未做", "回读": "未做", "运行": "未验证（无设备/非 APK）"}
desktop_apk = None
final_apk = None


def put(s=""):
    lines.append(str(s))
    rf.log(str(s))


# ---------------------------------------------------------------------------
# ① 一键拆包
# ---------------------------------------------------------------------------
def do_unpack() -> Path:
    if target.is_dir():
        put("- 已是解包目录，跳过拆包")
        return target
    rf.step("① 一键拆包", 8)
    # 非 APK 容器（zip/rar/iso/文档…）自动切通用拆解
    kind = rf.file_type(target)
    if kind.real != "apk":
        put(f"- 识别为 {kind.label}，不是 APK → 走通用拆解")
        r = rf.unpack_any(target, out=out / "unpack")
        put(f"- ✓ {r['method']}（{r['files']} 个文件）")
        for n in r["notes"][:3]:
            put(f"    · {n}")
        if stage == "unpack":
            return target          # 非 APK 没有后续补丁/打包流程
        raise RuntimeError("该文件不是 APK，无法走「删验证 + 打包」流程；"
                           "用「通用拆解（任何文件）」脚本或单独跑拆包即可")
    un = rf.apk_unpack(target, out=out / "unpack", apktool=True, jadx=False)
    if not un.apktool_dir:
        raise RuntimeError("拆包失败：" + "；".join(un.errors[:3]))
    put(f"- ✓ 解包完成：`{un.apktool_dir}`")
    return Path(un.apktool_dir)


# ---------------------------------------------------------------------------
# ② 一键解密
# ---------------------------------------------------------------------------
_DEX_EXT = (".dex", ".so")
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
                files = rf.decrypt_save(rep, dec_dir, limit=2)
                saved += len(files)
                put(f"  · ✓ {p.relative_to(root)} → {len(files)} 份解密结果")
        except Exception as e:                          # noqa: BLE001
            put(f"  · ✗ {p.name}：{e}")
    if not saved:
        put("- 没撞出可解的（算法是自定义的）；不影响 ③ —— "
            "加密的多是规则/配置数据，卡密闸门在 dex 里，已经单独处理")
    else:
        put(f"- ✓ 解密产物 {saved} 份 → `{dec_dir}`")
    return saved


# ---------------------------------------------------------------------------
# ③ 一键删除前置验证
# ---------------------------------------------------------------------------
def do_patch(root: Path) -> list:
    rf.step("③ 扫描前置验证点", 45)
    rep = rf.patch_scan(root, min_confidence=35)
    if not rep.points:
        raise RuntimeError("没有识别到校验点。这包可能加固了（逻辑在 so 里），"
                           "把日志发对话页进一步分析。")
    pre = len(rep.pre_run)
    put(f"- 校验点 {len(rep.points)} 个（启动路径 {pre} 个）")

    rf.step("③ 生成安全补丁方案", 52)
    ops = rf.patch_plan(rep, only_pre=True, safe_only=True,
                        include_running=True, max_ops=24,
                        min_confidence=int(min_conf or 40))
    if not ops:
        raise RuntimeError("识别到了校验点，但没有敢自动应用的改法。"
                           "打开「补丁」页人工挑，或在对话页让 AI 分析。")
    put(f"- 安全补丁 {len(ops)} 条（只收确定性改法，不含误伤类）：")
    for op in ops:
        put(f"  · {op.reason[:80]}")

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
    rb = rf.patch_rebuild(root, out=out / "bypass.apk", ops=ops, sign=True)
    if not rb.ok and target.is_file():
        put("- 完整重建失败（资源编译问题），启用退路：只换 dex，原资源保留")
        rf.step("④b 只换 dex 重建", 76)
        rb = rf.patch_rebuild_dex(target, root, out=out / "bypass.apk",
                                  ops=ops, sign=True)
    gate["签名"] = "通过" if rb.verified else "未通过"
    gate["回读"] = "确认" if rb.roundtrip else "未确认"
    if not rb.ok:
        raise RuntimeError("打包失败，备份在「备份」目录。")
    put(f"- ✓ 成品：`{rb.apk}`")
    final_apk = rb.apk
    return rb.apk


def do_desktop(apk: Path) -> None:
    if not bool(to_desktop):
        put("- 已关闭自动放桌面，成品在产物目录")
        return
    rf.step("⑤ 成品丢桌面", 95)
    try:
        from rf.tools.desktop import drop_to_desktop
        global desktop_apk
        desktop_apk, msg = drop_to_desktop(apk, name=target.stem, tag="已绕过")
        put(f"- ✓ {msg}")
    except Exception as e:                              # noqa: BLE001
        put(f"- 放桌面失败（成品仍在产物目录）：{e}")


# ---------------------------------------------------------------------------
# 分派执行
# ---------------------------------------------------------------------------
root = do_unpack()
if stage == "unpack":
    put("- 按要求只执行到拆包")
else:
    do_decrypt(root)
    if stage not in ("decrypt",):
        ops = do_patch(root)
        if stage != "patch":
            apk = do_pack(root, ops)
            do_desktop(apk)
        else:
            put("- 按要求只执行到打补丁（没重新打包）")

put("")
put("## 结果")
for k, v in gate.items():
    put(f"- {k}关：{v}")
if desktop_apk:
    put(f"- 桌面成品：`{desktop_apk}`　← 直接传手机安装")
if final_apk:
    put(f"- 产物成品：`{final_apk}`")
put(f"- smali 备份：`{out / '备份'}`（改坏了可回滚）")
put("- 带服务器说明：本地补丁让「服务器拒绝/复核失效」不再影响运行；"
    "规则包内嵌加密文件已尝试解密落盘（见「已解密」目录）。")

md = out / "全自动化报告.md"
md.write_text("\n".join(lines), encoding="utf-8")
rf.log(f"✓ 报告：{md}")
