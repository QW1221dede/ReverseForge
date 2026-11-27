#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 rf.snippets.builtin · 内置积木
============================================================================

【怎么读这块文件】
    每一块都是"能直接粘进脚本运行"的完整片段，不是伪代码。
    顺序按难度：入门 → 侦察 → 校验 → 补丁 → 解密 → 运行期 → 报告 → 工程。

【为什么积木要这么多、这么碎】
    逆向的每一步都可能单独失败。把"解包"和"注释"和"补丁"和"重建"拆开，
    用户就能只跑其中一步、只改其中一块，而不是被一个 500 行的全家桶绑死。
============================================================================
"""

from __future__ import annotations

import textwrap

from .model import Snippet


def _s(sid: str, title: str, category: str, level: int, purpose: str,
       code: str, *, when: str = "", needs: list[str] | None = None,
       gives: list[str] | None = None, tags: list[str] | None = None,
       depends: list[str] | None = None, risk: str = "无") -> Snippet:
    return Snippet(
        sid=sid, title=title, category=category, level=level, purpose=purpose,
        code=textwrap.dedent(code).strip("\n"), when=when,
        needs=needs or [], gives=gives or [], tags=tags or [],
        depends=depends or [], risk=risk,
    ).check()


BUILTIN: list[Snippet] = [

    # ------------------------------------------------------------------
    # 入门
    # ------------------------------------------------------------------
    _s("intro.log", "日志与进度", "入门", 1,
       "在终端里打出分节标题和进度，让你知道脚本跑到哪一步了。",
       """
       goal = args.get("apk") or args.get("smali_dir") or "未指定目标"
       rf.note("开始处理", f"目标：{goal}")
       rf.step("读取文件", 5)
       rf.log("这一步只写日志，不改任何文件")
       rf.step("分析", 40)
       rf.log("进度条会跟着 step 的数字走")
       rf.step("完成", 100)
       """,
       when="任何脚本的第一段。先能看见过程，再谈分析。",
       gives=["终端输出"], tags=["日志", "进度"]),

    _s("intro.guard", "目标检查（防手滑）", "入门", 1,
       "确认目标文件存在、大小正常，避免后面所有步骤对着空气跑。",
       """
       from pathlib import Path

       target = Path(apk)
       if not target.exists():
           raise RuntimeError(f"目标不存在：{target}")
       if target.stat().st_size == 0:
           raise RuntimeError("目标文件是空的")
       rf.log(f"目标 {target.name} / {target.stat().st_size / 1048576:.2f} MB")
       """,
       when="脚本开头。尤其是批量脚本，一个坏路径会让整批白跑。",
       needs=["apk"], gives=["target"], tags=["校验", "健壮性"]),

    _s("intro.timer", "给任意步骤计时", "入门", 1,
       "量出每一步到底花了多久，避免「感觉卡住了」却不知道卡在哪。",
       """
       import time

       t0 = time.time()
       rf.step("开始", 0)

       # ↓ 把要计时的代码放这里

       rf.log(f"本段耗时 {time.time() - t0:.2f}s")
       rf.step("完成", 100)
       """,
       when="Ghidra 反编译、批量扫描这类「可能很慢」的步骤。",
       gives=["耗时"], tags=["计时"]),

    _s("intro.safe", "单步失败不拖垮全流程", "入门", 1,
       "某一步失败时记下原因继续跑，最后统一看哪些没做成。",
       """
       problems = []
       info = None
       try:
           info = rf.apk_info(apk)
       except Exception as e:
           problems.append(f"画像失败：{e}")
           rf.log(f"⚠ 画像失败，继续：{e}")

       if info:
           rf.log(f"包名：{info.package or '未知'}")

       if problems:
           rf.log("本次有未完成项：" + "；".join(problems))
       """,
       when="批量处理多个 APK；单个坏包不该让整批中断。",
       needs=["apk"], gives=["info", "problems"], tags=["异常", "批量"]),

    _s("intro.files", "列出产物文件", "入门", 1,
       "把工作区里的产物按大小列出来，方便确认到底生成了什么。",
       """
       for p in rf.list(rf.out_dir, "**/*.txt"):
           rel = p.relative_to(rf.out_dir)
           rf.log(f"{rel}  {rf.size(p)} 字节")
       """,
       when="脚本结尾。产物太多时先看清单，再决定打开哪个。",
       gives=["文件清单"], tags=["产物", "遍历"]),

    # ------------------------------------------------------------------
    # 侦察
    # ------------------------------------------------------------------
    _s("recon.apk", "APK 画像（包名/权限/加固）", "侦察", 1,
       "不拆包，先看这个 APK 是谁、要什么权限、有没有加壳。",
       """
       info = rf.apk_info(apk)
       rf.log(f"包名：{info.package}")
       rf.log(f"版本：{info.version_name} ({info.version_code})")
       rf.log(f"大小：{info.size / 1048576:.1f} MB")
       rf.log(f"权限 {len(info.permissions)} 项")
       if info.packers:
           rf.log("⚠ 疑似加固：" + "、".join(info.packers))
       """,
       when="拿到任何 APK 的第一分钟。加固包后面很多静态分析会失效。",
       needs=["apk"], gives=["info"], tags=["APK", "画像"],
       risk="只读"),

    _s("recon.unpack", "解包 + 反编译 + 中文注释", "侦察", 2,
       "把 APK 拆成资源和 smali，再反编译成 Java 并逐类加中文注释。",
       """
       rf.step("解包中", 10)
       res = rf.apk_unpack(apk, annotate=True)
       smali_dir = res.apktool_dir
       sources_dir = res.sources_dir
       rf.log(f"资源目录：{smali_dir or '（失败）'}")
       rf.log(f"源码目录：{sources_dir or '（失败）'}")
       if sources_dir:
           rf.log("下一步可跑 07_core_deps.py 看核心依赖")
       """,
       when="需要读代码、找校验逻辑时。大包可能要几分钟。",
       needs=["apk"], gives=["smali_dir", "sources_dir"],
       tags=["APK", "jadx", "注释"], risk="只读，产物在workspace"),

    _s("recon.strings", "字符串提取与分类", "侦察", 2,
       "把 URL、路径、密钥、类名从二进制里捞出来并分类，先找线索。",
       """
       r = rf.strings(apk, min_len=6)
       rf.log(r.summary())
       for label, items in r.by_kind.items():
           if not items:
               continue
           rf.log(f"[{label}] {len(items)} 条")
           for s in items[:5]:
               rf.log(f"  {s[:100]}")
       """,
       when="面对加固包、或者不知道从哪下手时。字符串往往比代码先招供。",
       needs=["apk"], gives=["字符串分类"], tags=["字符串", "线索"]),

    _s("recon.keys", "找硬编码密钥/口令", "侦察", 2,
       "扫源码和二进制里的 AK/SK、token、password、私钥块。",
       """
       hits = rf.keys(apk)
       if not hits:
           rf.log("没有发现明显的硬编码密钥")
       for label, frag in hits[:15]:
           rf.log(f"{label}: {frag[:80]}")
       """,
       when="怀疑配置里写死了服务端密钥；或要复现签名算法。",
       needs=["apk"], gives=["hits"], tags=["密钥", "硬编码"]),

    _s("recon.elf", "so 库风险导入", "侦察", 2,
       "看 so 调了哪些敏感函数（ptrace/反调试/加解密/socket）。",
       """
       import pathlib
       sos = list(pathlib.Path(rf.out_dir).rglob("*.so"))
       if not sos and smali_dir:
           sos = list(pathlib.Path(smali_dir).parent.rglob("*.so"))
       for so in sos[:10]:
           info = rf.elf(so)
           rf.log(f"{so.name}: {info.machine} / {len(info.imports)} 个导入")
       """,
       when="怀疑核心校验在 native 层；先看导入再决定要不要上 Ghidra。",
       needs=["smali_dir"], gives=["so 列表"], tags=["ELF", "native"]),

    _s("recon.dex", "DEX 结构速览", "侦察", 2,
       "不反编译，直接读 DEX 头：方法数、类数、字符串数。",
       """
       import pathlib
       for dex in pathlib.Path(apk).parent.glob("classes*.dex"):
           d = rf.dex(dex)
           rf.log(f"{dex.name}: {d.method_count} 方法 / {d.class_count} 类")
       """,
       when="判断是不是多 dex、有没有被拆分/加固。",
       needs=["apk"], gives=["dex 统计"], tags=["DEX"]),

    _s("recon.hashes", "产物哈希清单", "侦察", 2,
       "给关键文件算 SHA-256，便于事后证明「我改的是这个版本」。",
       """
       import hashlib
       from pathlib import Path

       rows = []
       for p in rf.list(out_dir, "**/*"):
           if not p.is_file() or p.stat().st_size > 200 * 1048576:
               continue
           h = hashlib.sha256(p.read_bytes()).hexdigest()
           rows.append((p.relative_to(out_dir).as_posix(), h))
       rf.write_text(Path(out_dir) / "hashes.txt",
                     "".join(f"{h}  {n}\\n" for n, h in rows))
       rf.log(f"已记录 {len(rows)} 个文件哈希")
       """,
       when="交付前、对比两个版本前。",
       gives=["hashes.txt"], tags=["哈希", "留证"]),

    # ------------------------------------------------------------------
    # 校验
    # ------------------------------------------------------------------
    _s("verify.deps", "依赖图：谁被最多人调用", "校验", 2,
       "建跨文件调用图，按入度找核心类，顺带标出校验特征。",
       """
       g = rf.deps(smali_dir)
       rf.log(g.summary())
       for n in g.hubs(10):
           rf.log(f"入度 {n.fan_in:>3}  {n.name}  {'⚑ 校验' if n.is_verify else ''}")
       """,
       when="想在几十个类里挑出「改这里最有效」的那几个。",
       needs=["smali_dir"], gives=["DepGraph"], tags=["依赖", "核心"],
       depends=["intro.log"]),

    _s("verify.scan", "精确扫描启动前校验", "校验", 2,
       "沿启动调用链找卡密/授权/签名/环境判定，给出证据、置信度和补丁建议。",
       """
       rep = rf.patch_scan(smali_dir)
       rf.log(rep.summary())
       rf.log(rep.table(only_pre=True, limit=15))
       for p in rep.pre_run[:5]:
           rf.log(f"⚑ {p.cid} {p.cls_simple}.{p.method} · {p.category} · {p.confidence}")
           if p.best:
               rf.log(f"   建议：{p.best.label}（风险 {p.best.risk}）")
       """,
       when="拿到 APK 后想知道「它启动时到底查了什么」。",
       needs=["smali_dir"], gives=["rep"], tags=["校验", "启动", "精确"],
       depends=["intro.log"]),

    _s("verify.report", "校验点中文报告", "校验", 2,
       "把扫描结果写成 Markdown：证据、调用链、建议改法、边界说明。",
       """
       from rf.patch import checkpoints as cp

       rep = globals().get("rep") or rf.patch_scan(smali_dir)
       path = rf.out_dir / "report" / "校验点.md"
       path.parent.mkdir(parents=True, exist_ok=True)
       path.write_text(cp.report_md(rep), encoding="utf-8")
       rf.log(f"报告：{path}")
       """,
       when="要把结论交给别人看，或者自己隔几天再回来看。",
       needs=["smali_dir"], gives=["校验点.md"], tags=["报告", "校验"],
       depends=["verify.scan"]),

    _s("verify.export", "导出补丁配方 JSON", "校验", 2,
       "把校验点、证据、建议操作导成 JSON，供别的脚本或人工复核。",
       """
       import json

       rep = globals().get("rep") or rf.patch_scan(smali_dir)
       data = [p.to_dict() for p in rep.points]
       path = rf.out_dir / "patch_recipe.json"
       path.write_text(json.dumps(data, ensure_ascii=False, indent=2),
                       encoding="utf-8")
       rf.log(f"已导出 {len(data)} 条 → {path}")
       """,
       when="想先审一遍再动手；或做批量处理时喂给下游。",
       needs=["smali_dir"], gives=["patch_recipe.json"], tags=["导出", "配方"],
       depends=["verify.scan"]),

    # ------------------------------------------------------------------
    # 补丁
    # ------------------------------------------------------------------
    _s("patch.plan", "生成补丁方案并预演", "补丁", 2,
       "只选启动路径上的校验点，先预演：原指令对不对得上、改完语法过不过。",
       """
       rep = globals().get("rep") or rf.patch_scan(smali_dir)
       ops = globals().get("ops") or rf.patch_plan(rep, only_pre=True)
       rf.log(f"方案 {len(ops)} 条")
       for op in ops[:8]:
           rf.log(f"{op.reason}  @ {op.line}")

       dry = rf.patch_apply(smali_dir, ops, dry_run=True)
       rf.log(dry.text())
       """,
       when="真正改文件之前。预演不写盘，失败也不会有损失。",
       needs=["smali_dir"], gives=["ops", "dry"], tags=["补丁", "预演"],
       depends=["verify.scan"],
       risk="只读（dry_run）"),

    _s("patch.apply", "应用补丁（自动备份/回滚）", "补丁", 3,
       "把方案写进 smali；任何一条失败就整批还原，不会留下半成品。",
       """
       # 前面有 verify.scan / patch.plan 就复用，避免重复扫描和重复改
       rep = globals().get("rep") or rf.patch_scan(smali_dir)
       ops = globals().get("ops") or rf.patch_plan(rep, only_pre=True)
       res = rf.patch_apply(smali_dir, ops)
       rf.log(res.text())
       if not res.ok:
           raise RuntimeError("补丁未通过校验，已回滚：" + "；".join(res.errors[:2]))
       rf.log(f"备份目录：{res.backup_dir}")
       """,
       when="确认方案没问题之后。改的是解包目录，不动原 APK。",
       needs=["smali_dir"], gives=["res"], tags=["补丁", "事务", "回滚"],
       depends=["patch.plan"],
       risk="会改 smali 文件（自动备份）"),

    _s("patch.rebuild", "重建 APK + 签名 + 验签", "补丁", 3,
       "把改过的目录编回 APK，用本地调试证书签名，并回读确认补丁进包。",
       """
       rep = globals().get("rep") or rf.patch_scan(smali_dir)
       ops = globals().get("ops") or rf.patch_plan(rep, only_pre=True)
       out = rf.out_dir / "patched.apk"
       rb = rf.patch_rebuild(smali_dir, out, ops=ops)
       rf.log(rb.text())
       if not rb.ok:
           raise RuntimeError("重建失败：" + "；".join(rb.errors[:2]))
       """,
       when="改完 smali 之后。没签名的包装不上。",
       needs=["smali_dir"], gives=["patched.apk"], tags=["重建", "签名", "apksigner"],
       depends=["patch.apply"],
       risk="会生成新 APK（不动原包）"),

    _s("patch.rollback", "回滚到补丁前", "补丁", 2,
       "用备份目录把 smali 整体还原，回到动手之前的状态。",
       """
       backup = args.get("backup") or ""
       if not backup:
           raise RuntimeError("请把备份目录填到参数 backup")
       files = rf.patch_rollback(smali_dir, backup)
       rf.log(f"已还原 {len(files)} 个文件")
       """,
       when="补丁后程序起不来，先回到干净状态再排查。",
       needs=["smali_dir", "backup"], gives=["还原文件"], tags=["回滚", "备份"]),

    _s("patch.const_replace", "替换写死的卡密/口令", "补丁", 2,
       "把 smali 里的字符串常量换成指定值；改的是字面量，不是比对算法。",
       """
       old_text = args.get("old_text") or "旧值"
       new_text = args.get("new_text") or "新值"
       res = rf.replace_strings(smali_dir, old_text, new_text, dry_run=True)
       rf.log(res.text())
       if not res.ok:
           raise RuntimeError("预演未通过，未改任何文件")
       if args.get("commit"):
           res = rf.replace_strings(smali_dir, old_text, new_text)
           rf.log(res.text())
       """,
       when="卡密/默认口令/测试密钥写死在代码里；或想把服务地址换掉。",
       needs=["smali_dir"], gives=["res"], tags=["字符串", "卡密", "替换"],
       depends=["intro.log"],
       risk="会改 smali（自动备份）；默认只预演，commit=true 才落盘"),

    _s("patch.method_true", "手写一条：指定方法恒返回 true", "补丁", 3,
       "已知类名/方法名时，直接用代码构造一条方法级补丁，不依赖自动扫描。",
       """
       from rf.patch.checkpoints import PatchOp
       from rf.patch import smali as sm

       path = rf.out_dir / "unpack" / "smali" / "com" / "x" / "License.smali"
       lines = sm.read_lines(path)
       # 找到方法体范围（这里假设已确认方法在 120-160 行）
       op = PatchOp(file=str(path), line=120, end_line=160,
                    original="\\n".join(lines[119:160]),
                    replacement="    .locals 1\\n\\n    const/4 v0, 0x1\\n\\n    return v0",
                    reason="手动指定：License.check 恒真", kind="method")
       res = rf.patch_apply(path.parents[3], [op], dry_run=True)
       rf.log(res.text())
       """,
       when="自动扫描没覆盖到，或你要改的是自己确认过的方法。",
       gives=["op"], tags=["补丁", "手动", "smali"],
       risk="示例路径需替换；先 dry_run"),

    _s("patch.branch", "手写一条：分支取反", "补丁", 3,
       "把 if-eqz 改成 if-nez（或反向），用于双重否定/反调试场景。",
       """
       from rf.patch.checkpoints import PatchOp

       # 先用扫描拿到候选，再挑一条 invert 建议
       rep = rf.patch_scan(smali_dir)
       cand = [p for p in rep.points if p.best and p.best.kind == "invert"]
       if not cand:
           raise RuntimeError("没有可反转的分支")
       op = cand[0].best.op
       rf.log(f"将修改 {op.file}:{op.line}")
       rf.log(f"{op.original}  →  {op.replacement}")
       res = rf.patch_apply(smali_dir, [op], dry_run=True)
       rf.log(res.text())
       """,
       when="确认某条分支就是「通过/不通过」的开关。",
       needs=["smali_dir"], gives=["op"], tags=["分支", "反转"],
       risk="方向搞反会让程序更坏，先 dry_run"),

    # ------------------------------------------------------------------
    # 解密
    # ------------------------------------------------------------------
    _s("crypto.identify", "识别加密/压缩并尝试解开", "解密", 2,
       "先判断是 zip/7z/xor/AES 哪一类，再按类型尝试（弱口令、单字节 XOR）。",
       """
       r = rf.identify(blob)
       rf.log(r.brief())

       if r.kind in ("zip", "7z"):
           out = rf.zip_password(blob)
           rf.log(out.note)
       elif r.kind == "xor":
           x = rf.xor(blob)
           rf.log(x.note)
       """,
       when="assets 里有看不懂的 .bin/.dat；配置被加密。",
       needs=["blob"], gives=["识别结果"], tags=["加密", "识别"]),

    _s("crypto.aes", "AES-256-GCM 加密保存结果", "解密", 2,
       "用本机强加密把补丁配方/密钥清单加密落盘，避免明文躺着。",
       """
       from rf.secure import crypto as C

       payload = {"包名": "com.example", "校验点": ["License.verify"]}
       path = C.seal_json(payload, "换成你的口令", rf.out_dir / "recipe.sealed")
       rf.log(f"已加密：{path}（{rf.size(path)} 字节）")

       back = C.open_json(path, "换成你的口令")
       rf.log(f"回读成功：{back['包名']}")
       """,
       when="结果里有卡密、密钥、绕过后门这类敏感信息。",
       gives=["*.sealed"], tags=["AES", "GCM", "加密"], risk="口令丢了无法恢复"),

    _s("crypto.verify", "HMAC 校验配置没被改", "解密", 2,
       "给配置文件算 HMAC-SHA256，运行前比对，防止被手改成半截。",
       """
       from rf.secure import crypto as C

       cfg = rf.read_text(config_path)
       tag = C.hmac_sign(cfg, "shared-secret")
       rf.log(f"HMAC = {tag[:32]}…")
       ok = C.hmac_verify(cfg, "shared-secret", tag)
       rf.log("校验通过" if ok else "✗ 内容被改过")
       """,
       when="自己写的工具要防止配置被误改；或复现别人的签名校验。",
       needs=["config_path"], gives=["tag", "ok"], tags=["HMAC", "完整性"]),

    # ------------------------------------------------------------------
    # 运行期
    # ------------------------------------------------------------------
    _s("runtime.frida", "生成 Frida 覆盖脚本", "运行期", 3,
       "对识别出的布尔校验生成运行时 hook，不改包先验证「改这里有没有用」。",
       """
       from rf.patch import checkpoints as cp

       rep = globals().get("rep") or rf.patch_scan(smali_dir)
       js = cp.to_frida(rep)
       path = rf.out_dir / "hook.js"
       path.write_text(js, encoding="utf-8")
       rf.log(f"已生成 {path}，覆盖 {len(rep.pre_run)} 个启动校验")
       rf.log("用法：frida -U -f <包名> -l hook.js --no-pause")
       """,
       when="有壳改不动 smali；或想先确认校验点再决定要不要改包。",
       needs=["smali_dir"], gives=["hook.js"], tags=["Frida", "hook", "运行期"],
       depends=["verify.scan"],
       risk="需要目标进程可调试；加固应用可能检测 frida"),

    _s("runtime.install", "装到设备并抓启动日志", "运行期", 3,
       "有设备时安装重建包，抓一段 logcat，确认是起来了还是崩了。",
       """
       ok, msg = rf.patch_install(apk, uninstall_first=True)
       rf.log(msg)
       if ok:
           log = rf.adb_logcat(lines=200)
           rf.log(log[-3000:])
       """,
       when="重建完成，手边正好有测试机。",
       needs=["apk"], gives=["安装结果", "logcat"], tags=["adb", "安装", "logcat"],
       risk="会卸载设备上的同包名应用"),

    _s("runtime.compare", "改前改后行为对比", "运行期", 2,
       "同一段检测代码，分别对原包和补丁包跑一次，比较输出差异。",
       """
       rf.note("基线", "原包")
       base = rf.run([rf.tool("adb").prefix[0], "shell", "dumpsys", "package", package])
       rf.log(base.out[:1500])

       rf.log("补丁包安装后重复同一条命令，对比差异即可")
       """,
       when="需要向别人证明「补丁确实改变了行为」。",
       needs=["package"], gives=["对比依据"], tags=["对比", "验证"],
       risk="只读命令"),

    # ------------------------------------------------------------------
    # 报告
    # ------------------------------------------------------------------
    _s("report.md", "一分钟生成中文报告", "报告", 1,
       "把任意字典渲染成带表格的 Markdown，落在 workspace/report 下。",
       """
       info = rf.apk_info(apk)
       rf.report("APK 速览", {
           "基本信息": {
               "包名": info.package,
               "版本": info.version_name,
               "大小MB": round(info.size / 1048576, 2),
               "加固": "、".join(info.packers) or "未发现",
           },
           "结论": ["先跑校验扫描，再决定改哪里"],
       })
       """,
       when="任何任务的收尾。报告是给未来的自己看的。",
       needs=["apk"], gives=["report.md"], tags=["报告", "Markdown"]),

    _s("report.json", "结构化结果落盘", "报告", 1,
       "把关键数据写成 JSON，方便后面做批量统计或二次处理。",
       """
       import json

       data = {
           "apk": str(apk),
           "包名": info.package if "info" in globals() else "",
           "校验点": [p.to_dict() for p in rep.points] if "rep" in globals() else [],
       }
       path = rf.out_dir / "result.json"
       path.write_text(json.dumps(data, ensure_ascii=False, indent=2),
                       encoding="utf-8")
       rf.log(f"已写入 {path}")
       """,
       when="批量跑完要汇总；或要把结果喂给别的工具。",
       gives=["result.json"], tags=["JSON", "落盘"]),

    # ------------------------------------------------------------------
    # 工程
    # ------------------------------------------------------------------
    _s("eng.tools", "看一眼工具链", "工程", 1,
       "列出 17 个工具的可用状态与版本，缺什么一目了然。",
       """
       rf.log(rf.tools_table())
       miss = [t["name"] for t in rf.status() if not t["available"]]
       if miss:
           rf.log("⚠ 缺失：" + "、".join(miss))
       """,
       when="脚本报「工具不可用」时，先跑这个。",
       gives=["工具表"], tags=["工具链", "自检"]),

    _s("eng.selftest", "加密与语法自检", "工程", 1,
       "真跑一遍 AES/HMAC/PBKDF2 往返，再验一块积木的语法。",
       """
       from rf.secure import crypto as C

       rep = C.selftest(payload_kb=16)
       for case in rep["cases"]:
           rf.log(str(case))
       rf.log("加密自检：" + ("通过" if rep["ok"] else "失败"))

       v = rf.validate("def f():\\n    return 1\\n", kind="python")
       rf.log(f"语法校验器：{v.brief()}")
       """,
       when="换机器、换 Python 版本后，先确认加密没退化成「假加密」。",
       gives=["自检结果"], tags=["自检", "加密", "语法"]),

    _s("eng.compose", "把多块积木拼成一个脚本", "工程", 2,
       "按 ID 取积木、自动排序、拼成一份可运行脚本并落盘。",
       """
       ids = ["intro.log", "recon.apk", "verify.scan", "verify.report"]
       code = rf.compose(ids, out=rf.out_dir / "composed.py")
       rf.log(f"已拼装 {len(ids)} 块 → {rf.out_dir / 'composed.py'}")
       rf.log(code.splitlines()[0] if code else "（空）")
       """,
       when="想把自己的常用流程固化下来，下次一键跑。",
       gives=["composed.py"], tags=["积木", "组合", "模板"]),

    # ------------------------------------------------------------------
    # 任意文件 / 解密（不限 APK）
    # ------------------------------------------------------------------
    _s("any.identify", "识别任意文件（不限 APK）", "侦察", 1,
       "魔数 + 容器结构 + 扩展名 + 熵兜底，判断一个文件到底是什么，并给下一步建议。",
       """
       target = args.get("path") or args.get("apk") or "."
       res = rf.scan_any(target, quiet=False) if __import__("os").path.isdir(target) \\
             else None
       if res is None:
           k = rf.file_type(target)
           rf.log(f"{k.label} · {k.cat_cn} · 熵 {k.entropy:.2f} · 可信 {k.confidence}%")
           rf.log("建议：" + " → ".join(k.route))
           for n in k.notes:
               rf.log("  · " + n)
       """,
       when="拿到一个不知道是什么的东西时，第一件事就是这个。",
       needs=["path"], gives=["类型结论"], tags=["识别", "魔数", "熵"]),

    _s("any.split", "找「明文头 + 密文」的分界", "侦察", 2,
       "量出前段明文到哪结束、密文从哪开始，顺手把头部里的 key/iv 捞出来。",
       """
       from rf.analysis import segments as SG

       target = args.get("path") or "secret.bin"
       sm = rf.segments(target)
       rf.log(sm.table(10))
       if sm.split.found:
           rf.log(sm.split.brief())
           if sm.split.head_keys:
               rf.log("头部密钥：" + "、".join(sm.split.head_keys))
           # 直接取出密文部分，喂给解密器
           body = SG.carve_tail(target, sm)
           rf.log(f"密文部分 {len(body)} 字节，偏移 {sm.split.head_end}")
       """,
       when="文件打开是「前几行正常、后面一片乱码」——这就是典型的部分加密。",
       needs=["path"], gives=["sm", "body"], tags=["分段", "熵", "偏移"]),

    _s("dec.auto", "自动试解（常见加密全撞）", "解密", 2,
       "编码/压缩/XOR/RC4/AES/TEA/XXTEA/OpenSSL 一次全试，按可读性排序。",
       """
       target = args.get("path") or "secret.bin"
       keys = [k for k in str(args.get("keys", "")).split(",") if k.strip()]

       rep = rf.decrypt_auto(target, keys=keys, deep=False)
       if rep.hits:
           rf.decrypt_save(rep, limit=3)
       else:
           rf.log("没解出来：先跑 any.split 看有没有明文头，把里面的 key 填进 keys")
       """,
       when="确认过是密文、也知道大概不是什么强加密时。",
       needs=["path"], gives=["rep", "明文"], tags=["解密", "XOR", "AES", "RC4"],
       risk="会对文件做几十万次试解，大文件上耗时；默认有 15 秒预算"),

    _s("dec.keys", "把密钥翻出来", "解密", 2,
       "从明文头、源码常量、配置、长 hex 里找候选密钥，给自动试解当输入。",
       """
       from rf.decrypt import keys as K

       target = args.get("path") or "."
       cands = rf.keys_any(target)
       if cands:
           rf.log(K.report_table(cands, 20))
           # 转成实际字节密钥（原文补齐 / MD5 / SHA256 / hex / base64）
           for kb, how in cands[0].variants((16, 32)):
               rf.log(f"  试 {how}: {kb.hex()}")
       """,
       when="自动试解没命中，但你相信密钥就在这台机器上。",
       needs=["path"], gives=["cands"], tags=["密钥", "硬编码", "配置"]),

    _s("verify.any", "任何类型的校验点（脚本/EXE/class）", "校验", 2,
       "找密码、卡密、授权校验，精确到行/偏移，能改的直接给 old→new。",
       """
       from rf.analysis import authscan

       target = args.get("path") or "."
       rep = rf.auth_scan(target, min_confidence=45)

       for p in rep.pre_run[:6]:
           rf.log(f"{p.aid} {p.loc} {p.kind_cn} {p.confidence}%")
           if p.fix_old:
               rf.log("  改：" + p.fix_old.strip())
               rf.log("  → " + p.fix_new.strip())
       """,
       when="程序/脚本启动要先输密码、卡密、注册码。",
       needs=["path"], gives=["rep"], tags=["校验", "密码", "卡密", "脚本"],
       depends=["any.identify"]),

    _s("verify.fix", "把脚本里的校验改掉", "补丁", 3,
       "把 if 条件改成恒真，写前备份、改后校验语法，出事自动回滚。",
       """
       target = args.get("path") or "tool.py"
       rep = rf.auth_scan(target)
       pts = rep.fixable
       if not pts:
           rf.log("没有可自动改的点（二进制类只能打机器码补丁）")
       else:
           # 先预演，看清楚要改哪几行
           rf.auth_apply(rep, ids=[p.aid for p in pts], dry_run=True)
           # 确认无误再真改
           rf.auth_apply(rep, ids=[p.aid for p in pts], dry_run=False,
                         backup_dir=rf.out_dir / "备份")
       """,
       when="脚本类型的卡密校验，改一行就能过。",
       needs=["path"], gives=["改后的脚本"], tags=["补丁", "脚本", "校验"],
       depends=["verify.any"],
       risk="会改源文件。已强制备份；二进制类型不会被改"),

    _s("term.run", "在常驻终端里跑代码", "工程", 1,
       "拿一个变量跨次保留的 Python 终端，边调边看，调通就能存成积木。",
       """
       term = rf.terminal(timeout=30)
       try:
           term.run("x = 21")
           r = term.run("print(x * 2)")
           rf.log(r.out.strip() or "（无输出）")
           r2 = term.run("import os; print(os.getcwd())")
           rf.log(r2.out.strip())
       finally:
           term.stop()
       """,
       when="想交互式试 API，而不是每次重跑整个脚本。",
       gives=["终端输出"], tags=["终端", "调试", "REPL"]),
]


# 清理未使用的参数（level_note 只是给 _s 的可读性占位）
for _sn in BUILTIN:
    _sn.code = _sn.code.strip("\n")
