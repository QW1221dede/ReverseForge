#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @name 自动解密
# @desc 把常见加密全撞一遍：编码/压缩/XOR/RC4/AES/TEA/XXTEA/OpenSSL，含偏移
# @param target 密文文件或目录 [file]
# @param keys 已知密码/密钥，多个用逗号分隔 [str:]
# @param deep 跑更久（60 秒预算） [bool:false]
# @param save 把命中的明文落盘 [bool:true]

"""
用法：
    选一个"看起来是密文"的文件（或者先跑 12_any_file.py 确认过）。

    试的顺序（便宜的在前）：
      Base64/32/85/Hex → zlib/gzip/bz2 → 单字节 XOR → 循环密钥 XOR
      → 密钥 XOR → RC4 → TEA/XXTEA → AES(ECB/CBC/CFB/OFB/CTR)
      → OpenSSL Salted → 前 64 字节偏移扫描

    判断"解对了"用的是两把尺子：命中标准文件头 + 文本可读性（中文常用字/英文词）。
    解不出来就老实说解不出来——AES-256 没有密钥就是数学上不可能。

    产出：解密/**（命中的明文）、解密报告.md
"""

from pathlib import Path

from rf.decrypt import auto as decauto, keys as deckeys

target = Path(target)
if not target.exists():
    raise RuntimeError(f"路径不存在：{target}")

key_list = [k.strip() for k in str(keys or "").split(",") if k.strip()]

rf.step("准备", 8)
prof = rf.cipher_profile()
if not prof["pycryptodome"]:
    rf.log("  ! 没有 pycryptodome，AES/DES/ChaCha20 不可用（其余算法照常）")

files: list[Path]
if target.is_dir():
    scan = rf.scan_any(target, quiet=True)
    files = [Path(k.path) for k in scan.encrypted][: 30 if not deep else 200]
    if not files:
        files = [Path(k.path) for k in scan.kinds if k.size > 64][:20]
    rf.log(f"  目录里挑出 {len(files)} 个待试文件")
else:
    files = [target]

out = rf.sub("report")
out.mkdir(parents=True, exist_ok=True)
dec_dir = rf.out_dir / "解密"
lines = ["# 自动解密报告", "", f"- 目标：`{target}`", f"- 已知密钥：{key_list or '（无）'}", ""]
ok_count = 0

for i, f in enumerate(files):
    pct = 10 + int(80 * i / max(1, len(files)))
    rf.step(f"试解 {f.name}", pct)
    try:
        rep = rf.decrypt_auto(f, keys=key_list, deep=bool(deep))
    except Exception as e:                       # noqa: BLE001
        lines.append(f"## {f.name}\n\n- 出错：{e}\n")
        continue

    lines.append(f"## {f.name}")
    lines.append("")
    lines.append(f"- {rep.summary()}")
    if rep.split.found:
        lines.append(f"- 分段：明文头 {rep.split.head_len}B + 密文 {rep.split.tail_len}B")
    if rep.hits:
        ok_count += 1
        lines.append("")
        lines.append("| 分 | 方法 | 偏移 | 大小 | 预览 |")
        lines.append("|---|---|---|---|---|")
        for h in rep.hits[:6]:
            lines.append(f"| {h.score} | {h.method} | {h.offset} | {h.size} | "
                         f"`{h.preview[:40]}` |")
        if save:
            for p in decauto.save_hits(rep, dec_dir, limit=3):
                lines.append(f"- 已存：`{p.name}`")
    else:
        lines.append("")
        lines.append("没解出来。下一步：")
        lines.append("- 先跑 12_any_file.py 看是不是「明文头+密文」，"
                     "把明文头里的 key/iv 填到本脚本的 keys 参数")
        lines.append("- 从程序里找解密函数：`rf.auth_scan(程序目录)` "
                     "或 `rf.patch_scan(解包目录)`")
    lines.append("")

md = out / "解密报告.md"
md.write_text("\n".join(lines), encoding="utf-8")

rf.step("完成", 100)
rf.log(f"✓ 报告：{md}")
rf.log(f"✓ {ok_count}/{len(files)} 个文件解出了东西"
       + (f"，明文在 {dec_dir}" if ok_count and save else ""))
