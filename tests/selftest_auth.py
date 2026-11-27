#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 tests/selftest_auth.py · 跨类型校验点标注自测
============================================================================

    造一批真实形态的样本（脚本 + 伪二进制 + 目录混合），
    看能不能精确指出"哪一行、什么类型、怎么改"，并且改完真的能跑。

    [1] Python 脚本：明文口令 + sys.exit
    [2] JavaScript：=== 比较 + 失败退出
    [3] 批处理：if "%1"=="x"
    [4] Lua：if pwd == "x" then
    [5] 二进制：字符串 + strcmp 导入特征
    [6] 目录混合：一次扫全
    [7] 自动改：改完语法仍然合法、原文件已备份
    [8] 反例：注释里的示例不该被当成校验
============================================================================
"""

from __future__ import annotations

import py_compile
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rf.analysis import authscan as A

ROOT = Path(__file__).resolve().parent.parent / "_test_out" / "auth"
if ROOT.exists():
    shutil.rmtree(ROOT, ignore_errors=True)
ROOT.mkdir(parents=True, exist_ok=True)

FAILED: list[str] = []


def check(name: str, cond: bool, extra: str = "") -> None:
    mark = "✓" if cond else "✗"
    print(f"  {mark} {name}" + (f"  [{extra}]" if extra else ""))
    if not cond:
        FAILED.append(name)


def section(n: str, t: str) -> None:
    print(f"[{n}] {t}")


# ---------------------------------------------------------------------------
section("1", "Python 脚本")
py = ROOT / "tool.py"
py.write_text('''# 演示脚本
import sys, hashlib

CARD_DB = {"admin": "123456"}

def login(user, password):
    if password == "abc123":
        return True
    print("密码错误")
    sys.exit(1)

def main():
    u = input("账号: ")
    p = input("密码: ")
    if not login(u, p):
        sys.exit(2)
    print("进入主程序")

if __name__ == "__main__":
    main()
''', encoding="utf-8")
rep = A.scan(py)
print("  ·", rep.summary())
print(rep.table(8))
check("找到口令校验", any(p.kind == A.K_PASSWORD for p in rep.points), str(rep.by_kind))
hit = [p for p in rep.points if p.fix_old]
check("给出可执行改法", bool(hit), hit[0].fix_new if hit else "无")
if hit:
    print(f"    原文: {hit[0].fix_old.strip()}")
    print(f"    改法: {hit[0].fix_new.strip()}")
check("改法是 if True", any("True" in p.fix_new for p in hit))

# ---------------------------------------------------------------------------
section("2", "JavaScript")
js = ROOT / "app.js"
js.write_text('''const pwd = prompt("请输入密码");
if (pwd === "xyz789") {
  start();
} else {
  alert("密码错误");
  process.exit(1);
}
''', encoding="utf-8")
rep2 = A.scan(js)
check("JS 找到校验", bool(rep2.points), str(rep2.by_kind))
jhit = [p for p in rep2.points if p.fix_old]
check("JS 改法为 (true)", bool(jhit) and "(true)" in jhit[0].fix_new,
      jhit[0].fix_new.strip() if jhit else "无")

# ---------------------------------------------------------------------------
section("3", "批处理")
bat = ROOT / "run.bat"
bat.write_text('@echo off\r\nset /p pwd=请输入卡密: \r\nif "%pwd%"=="CARD-9999" (\r\n  echo ok\r\n) else (\r\n  echo 卡密错误\r\n  exit /b 1\r\n)\r\n',
               encoding="utf-8")
rep3 = A.scan(bat)
check("BAT 找到校验", bool(rep3.points), str(rep3.by_kind))
bhit = [p for p in rep3.points if p.fix_old]
check("BAT 改法为 1==1", bool(bhit) and "1==1" in bhit[0].fix_new,
      bhit[0].fix_new.strip() if bhit else "无")

# ---------------------------------------------------------------------------
section("4", "Lua")
lua = ROOT / "main.lua"
lua.write_text('''local pwd = io.read()
if pwd == "lua-pass" then
  print("ok")
else
  os.exit(1)
end
''', encoding="utf-8")
rep4 = A.scan(lua)
check("Lua 找到校验", bool(rep4.points), str(rep4.by_kind))
lhit = [p for p in rep4.points if p.fix_old]
check("Lua 改法为 true", bool(lhit) and " true" in lhit[0].fix_new,
      lhit[0].fix_new.strip() if lhit else "无")

# ---------------------------------------------------------------------------
section("5", "二进制（字符串 + strcmp 特征）")
# 造一个带 PE 头和真实字符串的伪可执行文件
fake = ROOT / "crackme.exe"
body = (b"MZ" + b"\x00" * 58 + b"PE\x00\x00" + b"\x00" * 200)
body += b"\x00Please enter your card key: \x00"
body += b"InvalidKey\x00"
body += b"strcmp\x00lstrcmpA\x00"
body += b"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\x00"
body += b"\x00" * 64 + b"license expired, please activate\x00"
fake.write_bytes(body)
rep5 = A.scan(fake)
print("  ·", rep5.summary())
print(rep5.table(8))
check("二进制找到卡密/授权线索", len(rep5.points) >= 2, str(rep5.by_kind))
check("定位到文件偏移", all(p.offset > 0 for p in rep5.points))
check("识别出 SHA-256 形态线索",
      any(p.kind == A.K_HASH and len(p.code) == 64 for p in rep5.points))

# ---------------------------------------------------------------------------
section("6", "目录混合扫描")
rep6 = A.scan(ROOT)
print("  ·", rep6.summary())
check("目录扫描覆盖多语言", len(rep6.by_lang) >= 3, str(rep6.by_lang))
check("总数不少于单文件之和", len(rep6.points) >= 5, str(len(rep6.points)))

# ---------------------------------------------------------------------------
section("7", "自动改：改完还能跑 + 有备份")
target = ROOT / "patchme.py"
target.write_text('''import sys
pwd = input("密码: ")
if pwd == "secret2024":
    print("OK-ENTER")
else:
    print("NO")
    sys.exit(1)
''', encoding="utf-8")
rep7 = A.scan(target)
pts = [p for p in rep7.points if p.fix_old]
check("可改点存在", bool(pts))
res = A.apply_points(rep7, [pts[0].aid], backup_dir=ROOT / "_bak", dry_run=True)
check("预演不写盘", "预演" in "".join(res.changed) and
      "secret2024" in target.read_text(encoding="utf-8"))
res = A.apply_points(rep7, [pts[0].aid], backup_dir=ROOT / "_bak")
print("    ", res.changed, res.skipped)
check("实际改写成功", res.ok, res.note or "")
new_src = target.read_text(encoding="utf-8")
check("原文已被短路", "if True" in new_src and "pwd == \"secret2024\"" not in new_src)
try:
    py_compile.compile(str(target), doraise=True)
    ok_syntax = True
except py_compile.PyCompileError as e:
    ok_syntax = False
    print("    语法错误:", e)
check("改后语法合法", ok_syntax)
check("备份文件存在", Path(res.backup).exists() and
      any(Path(res.backup).iterdir()), res.backup)

# ---------------------------------------------------------------------------
section("8", "反例：注释与示例不该误报")
noise = ROOT / "noise.py"
noise.write_text('''# 用法示例：if password == "example":
# 请不要把密码写死在代码里
def render():
    label = "请输入密码"
    return label
''', encoding="utf-8")
rep8 = A.scan(noise)
check("注释里的示例不报", len(rep8.points) == 0,
      f"{len(rep8.points)} 条：{[p.code for p in rep8.points][:2]}")

# ---------------------------------------------------------------------------
section("9", "APK / DEX / Electron asar（真实外挂形态）")
import json
import struct
import zipfile

# 9a) 改了后缀的 APK（.apk.1）+ DEX 里的中文卡密串
apk = ROOT / "cheat.apk.1"
dex = (
    b"dex\n035\x00" + b"\x00" * 40
    + ("\x02卡密\x00\x0f卡密无效，请检查后重试\x00"
       "\x02卡密\x00\x0c请输入卡密\x00"
       "\x04机器码\x00\x0a机器码已绑定\x00").encode("utf-8")
)
with zipfile.ZipFile(apk, "w") as z:
    z.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00")
    z.writestr("classes.dex", dex)
rep9 = A.scan(apk, min_confidence=45)
check("改后缀 APK 仍识别为卡密校验", any(
    p.kind == A.K_CARD for p in rep9.points), str(rep9.by_kind))
check("命中 DEX 偏移", any("classes.dex" in p.file and p.offset > 0
                      for p in rep9.points))

# 9b) Electron asar：JSON 文件表 + JS 里的卡密判断
js = """function check(cardKey) {
  if (cardKey === "CARD-2026") { localStorage.setItem('vip','1'); return true; }
  alert("卡密无效"); return false;
}
"""
header_obj = {"files": {"dist": {"files": {"main.js": {
    "offset": "0", "size": str(len(js.encode()))}}}}}
hdr = json.dumps(header_obj).encode()
body = (struct.pack("<III", 4, len(hdr) + 16, len(hdr) + 8)
        + struct.pack("<I", len(hdr)) + hdr)
asar = ROOT / "app.asar"
asar.write_bytes(body + js.encode())
rep9b = A.scan(asar, min_confidence=45)
check("asar 内 JS 卡密校验被标出", any(
    p.kind == A.K_CARD and "main.js" in p.file for p in rep9b.points),
    str(rep9b.by_kind))
check("asar 不误报 node_modules 的 license", len(rep9b.points) <= 3,
      str(len(rep9b.points)))

# 9c) 默认"全面分析"必须包含 auth_scan，不能只走解密
from rf.agent import orchestrator as ag

p9 = ag.make_plan("全面分析这些文件：找卡密校验并尝试还原明文", ["x"])
check("全面分析包含 auth_scan", "auth_scan" in [s.tool for s in p9.steps],
      str([s.tool for s in p9.steps]))

# ---------------------------------------------------------------------------
print()
if FAILED:
    print(f"失败 {len(FAILED)} 项：")
    for f in FAILED:
        print("  ✗", f)
    sys.exit(1)
print("全部通过")
