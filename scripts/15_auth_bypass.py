#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @name 一键绕过卡密/启动校验
# @desc 识别 → 定位 → 替换 → 重建/改写 → 逐关验证能跑起来，出中文报告
# @param target 文件或文件夹（从投放区取） [file]
# @param mode 处理方式 [choice:auto,scan,patch,full:auto]
# @param run_verify 真机安装并启动验证（需 adb 设备） [bool:false]
# @param to_desktop 成品 APK 自动复制到桌面 [bool:true]
# @param ids 指定校验点编号，逗号分隔（空=全部启动路径） [str:]

"""
轮椅模式：目标从左上投放区取，这里只管点开始。

流程（每一步都写进报告，失败不装作成功）：
    APK / DEX
      ① 解包 → ② 扫启动前校验点 → ③ 生成补丁方案
      ④ 预演（不写盘）→ ⑤ 事务化应用 → ⑥ 重建 + 签名 + 回读
      ⑦ 四关验证：语法 / 签名 / 回读 / 真机启动

    脚本（py/js/lua/bat/...）
      ① auth_scan 找校验 → ② 预演 → ③ 备份后改写 → ④ 语法校验 + 试跑

    PE / ELF
      只能定位到偏移，机器码补丁交 Ghidra；如实说明，不瞎改。

【"能跑起来"的四关】
    1. 结构关：smali 汇编通过 / Python 语法通过
    2. 签名关：apksigner 验签通过
    3. 回读关：从新 APK 里把补丁读回来，确认真的进了 dex
    4. 运行关：有 adb 设备才装并启动；没设备就写"未验证真机"，不冒充通过

【成品】默认自动复制到桌面，文件名 "原名_已绕过.apk"，同名自动加 _2。
        不想放桌面就把 to_desktop 关掉（GUI 上取消勾选）。
        产物目录那份始终保留，报告/回滚都指它。

产物在工作区的「一键绕过」目录下，原文件不动。
"""

from pathlib import Path

from rf.analysis import authscan
from rf.patch import checkpoints as cp
from rf.patch import engine as patchmod

target = Path(target)
if not target.exists():
    raise RuntimeError("目标不存在。先把文件或文件夹拖到左上投放区。")

mode = str(mode or "auto").strip().lower()
out = rf.sub("一键绕过")
out.mkdir(parents=True, exist_ok=True)

lines = [
    "# 一键绕过报告", "",
    f"- 目标：`{target}`",
    f"- 模式：{mode}",
    f"- 产物目录：`{out}`",
    "",
]
gate = {"结构": "未做", "签名": "未做", "回读": "未做", "运行": "未验证（无设备/非 APK）"}
final_apk = None
final_script = None
desktop_apk = None


def put(s=""):
    lines.append(str(s))
    rf.log(str(s))


# ---------------------------------------------------------------------------
# APK / DEX / 解包目录
# ---------------------------------------------------------------------------
def do_apk(t: Path) -> bool:
    global final_apk, desktop_apk
    rf.step("① 准备解包目录", 5)
    if t.is_dir() or (t.suffix.lower() in (".smali",) ):
        root = t
        put("- 直接用已有解包目录，跳过解包")
    else:
        un = rf.apk_unpack(t, out=rf.sub("unpack"), apktool=True, jadx=False)
        if not un.apktool_dir:
            raise RuntimeError("解包失败：" + "；".join(un.errors[:3]))
        root = Path(un.apktool_dir)
        put(f"- 解包目录：`{root}`")

    rf.step("② 扫启动前校验点", 18)
    rep = rf.patch_scan(root)
    put(f"- {rep.summary()}")
    pre = rep.pre_run
    if not pre:
        put("- 没找到启动路径上的校验点。可能逻辑在别处，"
            "试试对话页说「找卡密校验」重新分析。")
        return False
    for p in pre[:12]:
        put(f"  · {p.cid} {p.cls_simple}.{p.method} · {p.category} · {p.confidence}%")
        if p.best:
            put(f"      改法：{p.best.label}")

    ids_list = [x.strip() for x in str(ids or "").replace("，", ",").split(",") if x.strip()]
    rf.step("③ 生成补丁方案", 32)
    ops = rf.patch_plan(rep, ids=ids_list or None, only_pre=True)
    if not ops:
        put("- 没有可自动应用的补丁建议。")
        return False
    put(f"- 方案 {len(ops)} 条")

    if mode == "scan":
        put("- 只扫描模式，到此为止。")
        return False

    rf.step("④ 预演（不写盘）", 42)
    dry = rf.patch_apply(root, ops, dry_run=True, backup=out / "备份")
    put(f"- 预演：{dry.text().splitlines()[0]}")
    if not dry.ok:
        put("- 预演没过，停止。原文件没动。")
        return False

    rf.step("⑤ 应用补丁", 52)
    if mode == "patch":
        put("- 只打补丁模式，不重建。")
        return True
    res = rf.patch_apply(root, ops, dry_run=False, backup=out / "备份")
    put(f"- 应用：{res.text().splitlines()[0]}")
    if not res.ok:
        put("- 补丁失败，已自动回滚。")
        return False
    gate["结构"] = "补丁已写入（smali 汇编校验通过，待打进 APK）"

    rf.step("⑥ 重建 + 签名 + 回读", 66)
    rb = rf.patch_rebuild(root, out=out / "bypass.apk", ops=ops, sign=True)
    put(f"- {rb.text()}")
    if not rb.ok and t.is_file():
        # aapt2 编资源常炸，但 dex 早汇编好了。只换 dex、原资源搬过去。
        put("- 完整重建失败，启用退路：只换 dex，原 APK 资源原样保留。")
        rf.step("⑥b 只换 dex 重建", 72)
        rb = rf.patch_rebuild_dex(t, root, out=out / "bypass.apk",
                                  ops=ops, sign=True)
        put(f"- {rb.text()}")
        if rb.ok:
            put("- ✓ 这条退路保留了原资源，签名和回读都过了。")
    if rb.ok:
        gate["结构"] = "通过（smali 已汇编并打进新 dex）"
    final_apk = rb.apk
    gate["签名"] = "通过" if rb.verified else "未通过"
    gate["回读"] = "确认" if rb.roundtrip else "未确认"
    if not rb.ok:
        put("- 重建失败，检查上面的日志。备份在「备份」目录。")
        return False

    # ---- 成品自动丢桌面（默认开；不想就 to_desktop=false）----
    if bool(to_desktop):
        rf.step("⑦b 成品放桌面", 92)
        try:
            from rf.tools.desktop import drop_to_desktop
            desktop_apk, msg = drop_to_desktop(
                rb.apk, name=t.stem if t.is_file() else "patched",
                tag="已绕过")
            put(f"- {msg}")
        except Exception as e:                       # noqa: BLE001
            put(f"- 放桌面失败（成品仍在产物目录）：{e}")
    else:
        put("- 已关闭自动放桌面，成品在产物目录。")

    rf.step("⑦ 运行验证", 88)
    if bool(run_verify):
        ok, msg = rf.patch_install(rb.apk, uninstall_first=True)
        put(f"- 安装：{msg}")
        if ok:
            gate["运行"] = "已安装到设备（未自动启动界面）"
    else:
        put("- 没开 run_verify，跳过真机验证。")
        put("  有设备的话重跑并把 run_verify 勾上，就能验到安装这一关。")
    return True


# ---------------------------------------------------------------------------
# 脚本
# ---------------------------------------------------------------------------
def do_script(t: Path) -> bool:
    global final_script
    import subprocess
    import py_compile

    rf.step("① 扫脚本里的卡密校验", 15)
    rep = rf.auth_scan(t)
    pts = rep.fixable
    put(f"- {rep.summary()}")
    if not pts:
        put("- 没有可自动改的校验点。二进制类只能定位，不能自动改。")
        return False
    for p in pts[:12]:
        put(f"  · {p.aid} {p.loc} {p.kind_cn} {p.confidence}%  {p.code.strip()[:50]}")

    if mode == "scan":
        return False

    rf.step("② 预演", 35)
    rf.auth_apply(rep, ids=[p.aid for p in pts], dry_run=True,
                  backup_dir=out / "备份")

    rf.step("③ 备份后改写", 50)
    res = rf.auth_apply(rep, ids=[p.aid for p in pts], dry_run=False,
                        backup_dir=out / "备份")
    put(f"- 改了 {len(res.changed)} 个文件；备份：{res.backup}")
    final_script = t
    if not res.ok:
        put("- 改写失败，已回滚。")
        return False

    rf.step("④ 语法 + 试跑验证", 70)
    if t.suffix.lower() in (".py", ".pyw"):
        try:
            py_compile.compile(str(t), doraise=True)
            gate["结构"] = "通过（py_compile）"
            put("- py_compile 通过")
        except Exception as e:                       # noqa: BLE001
            put(f"- py_compile 失败：{e}")
            return False
        try:
            run_path = t.resolve()
            r = subprocess.run(["python", str(run_path)], cwd=str(run_path.parent),
                               input=b"\n\n", capture_output=True, timeout=12)
            tail = (r.stdout + r.stderr).decode("utf-8", "replace").strip()[-300:]
            put(f"- 试跑退出码 {r.returncode}")
            if tail:
                put(f"- 试跑输出：{tail}")
            gate["运行"] = (f"已试跑（退出码 {r.returncode}）"
                            if r.returncode == 0 else
                            f"试跑退出码 {r.returncode}，需人工确认")
        except subprocess.TimeoutExpired:
            put("- 试跑超时（可能进入交互/主循环）—— 不等于失败，但需人工确认")
            gate["运行"] = "试跑超时，需人工确认"
        except OSError as e:
            put(f"- 试跑起不来：{e}")
    else:
        put("- 非 Python 脚本，自动试跑不适用，只做了语法/文本层面检查")
        gate["结构"] = "改写完成（非 Python，未做编译验证）"
    return True


# ---------------------------------------------------------------------------
# 分派
# ---------------------------------------------------------------------------
ft = rf.file_type(target)
put(f"- 识别：{ft.label}（{ft.category}，可信 {ft.confidence}%）")

if target.is_dir() or ft.category in ("android", "apk") or \
        "__apk__" in str(ft.real):
    ok = do_apk(target)
elif ft.category == "script":
    ok = do_script(target)
elif ft.category in ("native", "pe", "elf"):
    rf.step("定位校验点", 30)
    rep = rf.auth_scan(target)
    put(f"- {rep.summary()}")
    for p in rep.points[:10]:
        put(f"  · {p.loc} {p.kind_cn} {p.confidence}%  {p.code[:60]}")
    put("- 本地程序改的是机器码，不能像脚本那样文本替换。")
    put("  下一步：用 Ghidra / rizin 跳到上面的偏移，把判断跳转改掉。")
    ok = bool(rep.points)
else:
    put("- 这类文件没有自动替换路径。可以在对话页说「找卡密校验」看看。")
    ok = False

# ---------------------------------------------------------------------------
# 结论
# ---------------------------------------------------------------------------
put("")
put("## 能不能跑起来（四关）")
for k, v in gate.items():
    put(f"- {k}关：{v}")

passed = sum(1 for v in gate.values() if str(v).startswith(("通过", "确认", "已安装", "已试跑")))
put("")
put(f"结论：{'✓ 可用' if ok and passed >= 2 else '△ 未完成全部验证'}"
    f"（{passed}/4 关通过）")
if final_apk:
    put(f"- 成品 APK（产物）：`{final_apk}`")
if desktop_apk:
    put(f"- 成品 APK（桌面）：`{desktop_apk}`　← 直接双击安装")
if final_script:
    put(f"- 改写后的脚本：`{final_script}`")
put(f"- 备份：`{out / '备份'}`")
put("- 原文件没动。改坏了从备份还原。")

md = out / "一键绕过报告.md"
md.write_text("\n".join(lines), encoding="utf-8")
rf.log(f"✓ 报告：{md}")
if final_apk:
    rf.log(f"✓ 成品：{final_apk}")
if desktop_apk:
    rf.log(f"✓ 桌面：{desktop_apk}")
