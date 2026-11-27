#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 release.py · 打发布包（开源分发用）
============================================================================

 做什么
   1. 调 build.py 重新打包 exe（可 --skip-build 跳过）
   2. 把 exe 目录 + vendor（若已安装）+ 文档 + 安装脚本 打成一个 zip
   3. 生成 SHA256SUMS.txt（下载方核对完整性用）
   4. 生成「先读我.txt」——第一次打开就能看到杀软提示与免责声明

 用法
   python release.py                  # 完整流程
   python release.py --skip-build     # 只打包（已 build 过）
   python release.py --no-vendor      # 不带 vendor（让用户自己跑安装脚本）

 产物
   release/ReverseForge_v<版本>_win64.zip
   release/ReverseForge_v<版本>_win64.zip.sha256
   release/SHA256SUMS.txt
============================================================================
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DIST = ROOT / "dist" / "ReverseForge"
OUT = ROOT / "release"

# 一起打包的文档与脚本
DOCS = ["README.md", "DISCLAIMER.md", "SECURITY.md", "LICENSE",
        "install.bat", "install.ps1"]

FIRST_READ = """\
============================================================
 ReverseForge · 先读我（30 秒）
============================================================

【一、这不是病毒，但会被杀软拦】
  本工具是逆向分析平台。它做的每件事（读进程、改文件、hook）
  都是逆向必须做的，和恶意软件的区别只在"你是否获得授权"。
  杀软看不懂授权，只看行为，所以会误报。

  第一次运行前，请先把它加入白名单：
    设置 → 隐私和安全性 → Windows 安全中心 → 病毒和威胁防护
    → 管理设置 → 排除项 → 添加排除项 → 文件夹
    添加这两个：
      %LOCALAPPDATA%\\ReverseForge
      <你解压本程序的目录>

  详细步骤与第三方杀软（360/火绒/卡巴）见 SECURITY.md

【二、首次使用：装环境】
  双击 install.bat（需要管理员，会弹 UAC）。
  它会装好 JDK17 / apktool / aapt2 / apksigner / zipalign / adb / 7zr，
  装到 %LOCALAPPDATA%\\ReverseForge\\vendor。
  装完程序就能开箱用，不需要你自己再装 Java 或 Android SDK。

  没网？见 install.ps1 文件末尾的离线安装说明。

【三、验证文件完整】
  核对随包附带的 SHA256SUMS.txt：
    Get-FileHash .\\ReverseForge_v*.zip -Algorithm SHA256
  不一致就别运行。

【四、它能干什么】
  拖文件进左侧投放区 → 自动识别类型 / 找明文头 / 试解密 /
  找密码卡密校验 / 中文注释 / 打补丁 / 重打包。
  具体见 README.md。

【五、合法使用】
  仅限分析你自己拥有或已获书面授权的目标。
  完整条款见 DISCLAIMER.md —— 下载即视为同意。

============================================================
"""


def _log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def version() -> str:
    sys.path.insert(0, str(ROOT))
    try:
        from rf import config
        return config.APP_VERSION
    except Exception:                                # noqa: BLE001
        return "0.0.0"


def build() -> bool:
    _log("打包 exe …")
    r = subprocess.run([sys.executable, str(ROOT / "build.py")], cwd=str(ROOT))
    return r.returncode == 0


def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _skip(p: Path) -> bool:
    """打包时跳过缓存与临时文件。"""
    parts = {x.lower() for x in p.parts}
    if "__pycache__" in parts:
        return True
    if p.suffix.lower() in (".pyc", ".pyo", ".tmp"):
        return True
    if p.name.endswith(".rf.tmp"):
        return True
    return False


def make_zip(tag: str, with_vendor: bool) -> Path:
    OUT.mkdir(exist_ok=True)
    zpath = OUT / f"ReverseForge_{tag}.zip"
    if zpath.exists():
        zpath.unlink()

    n = 0
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        # 1) 程序本体
        for p in sorted(DIST.rglob("*")):
            if p.is_dir() or _skip(p):
                continue
            z.write(p, f"ReverseForge/{p.relative_to(DIST)}")
            n += 1
        # 2) 文档与安装脚本
        for name in DOCS:
            f = ROOT / name
            if f.exists():
                z.write(f, f"ReverseForge/{name}")
                n += 1
        # 3) vendor（可选）
        if with_vendor:
            for v in (ROOT / "vendor", Path(os.environ.get("LOCALAPPDATA", "")) /
                      "ReverseForge" / "vendor"):
                if v.is_dir() and any(v.iterdir()):
                    _log(f"打入 vendor：{v}")
                    for p in sorted(v.rglob("*")):
                        if p.is_dir() or _skip(p):
                            continue
                        z.write(p, f"ReverseForge/vendor/{p.relative_to(v)}")
                        n += 1
                    break
        # 4) 先读我
        z.writestr("ReverseForge/先读我.txt", FIRST_READ)
        n += 1

    _log(f"zip 完成：{zpath.name}（{n} 个文件，"
         f"{zpath.stat().st_size / 1024 / 1024:.1f}MB）")
    return zpath


def main() -> int:
    argv = sys.argv[1:]
    skip_build = "--skip-build" in argv
    with_vendor = "--no-vendor" not in argv

    if not DIST.exists() and not skip_build:
        pass
    if not skip_build:
        if not build():
            _log("打包失败")
            return 1
    if not DIST.exists():
        _log(f"找不到产物目录：{DIST}（先跑 build.py）")
        return 1

    ver = version()
    tag = f"v{ver}_win64"
    _log(f"版本 {ver}")

    zp = make_zip(tag, with_vendor)
    digest = _sha256(zp)

    side = zp.with_suffix(zp.suffix + ".sha256")
    side.write_text(f"{digest}  {zp.name}\n", encoding="utf-8")

    sums = OUT / "SHA256SUMS.txt"
    line = f"{digest}  {zp.name}\n"
    if sums.exists():
        txt = sums.read_text(encoding="utf-8")
        txt = "\n".join(l for l in txt.splitlines() if zp.name not in l)
        sums.write_text((txt + "\n" if txt.strip() else "") + line, encoding="utf-8")
    else:
        sums.write_text(line, encoding="utf-8")

    _log("—" * 54)
    _log(f"发布包：{zp}")
    _log(f"SHA256：{digest}")
    _log(f"清单　：{sums}")
    _log("—" * 54)
    _log("开源发放前自检：")
    _log("  □ README 顶部有免责声明与杀软提示")
    _log("  □ LICENSE / DISCLAIMER.md / SECURITY.md 已随包")
    _log("  □ 发布页写明 SHA256，提醒用户核对")
    _log("  □ 说明「需要管理员运行 install.bat」")
    return 0


if __name__ == "__main__":
    sys.exit(main())
