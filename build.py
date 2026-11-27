#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 打包脚本 · 生成 Windows 桌面程序
============================================================================

    python build.py            生成 dist/ReverseForge/ReverseForge.exe（目录版）
    python build.py --onefile  单文件版（启动慢 5-10 秒，但只有一个 exe）

为什么默认用「目录版」：
    单文件版每次启动都要把几百 MB 解压到临时目录，tkinter 应用启动会慢
    到让人以为卡死；目录版双击即开，且脚本目录是可见的（用户能自己加脚本）。
============================================================================
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DIST = ROOT / "dist"
BUILD = ROOT / "build"
ICON = BUILD / "app.ico"

PY = r"E:\Tools\Python312\python.exe"
if not Path(PY).exists():
    PY = sys.executable


def make_icon() -> bool:
    """用 Pillow 画一个图标：橙框 + A 形箭头 + 绿点。"""
    try:
        from PIL import Image, ImageDraw
    except ImportError:
        print("! 没装 Pillow，跳过图标")
        return False

    ICON.parent.mkdir(parents=True, exist_ok=True)
    S = 256
    img = Image.new("RGBA", (S, S), (14, 16, 20, 255))
    d = ImageDraw.Draw(img)

    # 外框（圆角）
    d.rounded_rectangle([20, 20, 236, 236], radius=40,
                        outline=(255, 138, 61, 255), width=13)
    # A 形折线
    d.line([(76, 190), (128, 70), (180, 190)], fill=(255, 138, 61, 255),
           width=15, joint="curve")
    # A 的横杠
    d.line([(104, 150), (152, 150)], fill=(255, 138, 61, 255), width=13)
    # 状态点
    d.ellipse([170, 176, 200, 206], fill=(61, 220, 132, 255))

    img.save(ICON, sizes=[(16, 16), (24, 24), (32, 32), (48, 48),
                          (64, 64), (128, 128), (256, 256)])
    print(f"✓ 图标 {ICON}")
    return True


def run_build(onefile: bool = False) -> int:
    if BUILD.exists():
        shutil.rmtree(BUILD, ignore_errors=True)
    BUILD.mkdir(parents=True, exist_ok=True)
    has_icon = make_icon()

    cmd = [
        PY, "-m", "PyInstaller",
        "--noconfirm", "--clean",
        "--windowed" if onefile else "--windowed",
        "--onefile" if onefile else "--onedir",
        "--name", "ReverseForge",
        "--distpath", str(DIST),
        "--workpath", str(BUILD / "pyi"),
        "--specpath", str(BUILD),
        "--add-data", f"{ROOT / 'scripts'};scripts",
        # 拖拽靠 tkdnd 的原生二进制，必须一起收进去，否则 exe 里拖不了
        "--collect-data", "tkinterdnd2",
        "--hidden-import", "tkinterdnd2",
        "--collect-submodules", "rf",
        "--hidden-import", "Crypto.Cipher.AES",
        "--hidden-import", "Crypto.Cipher.ChaCha20_Poly1305",
        "--hidden-import", "Crypto.Protocol.KDF",
        # 资源里 jpg 改后缀冒充 .png 时用它转码（可选能力，缺了只是少一条修复路径）
        "--hidden-import", "PIL.Image",
        "--exclude-module", "numpy",
        "--exclude-module", "matplotlib",
        "--exclude-module", "pandas",
        "--exclude-module", "scipy",
    ]
    if has_icon:
        cmd += ["--icon", str(ICON)]
    cmd.append(str(ROOT / "run.py"))

    print("$", " ".join(cmd))
    r = subprocess.run(cmd, cwd=str(ROOT))
    if r.returncode != 0:
        print("✗ 打包失败")
        return r.returncode

    exe = (DIST / "ReverseForge.exe") if onefile else (DIST / "ReverseForge" / "ReverseForge.exe")
    if exe.exists():
        size = exe.stat().st_size / 1048576
        total = sum(f.stat().st_size for f in exe.parent.rglob("*") if f.is_file()) / 1048576
        print(f"\n✓ 产物：{exe}")
        print(f"  exe {size:.1f} MB，" + ("" if onefile else f"整目录 {total:.1f} MB"))
    else:
        print("✗ 没找到 exe，检查 PyInstaller 输出")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(run_build("--onefile" in sys.argv))
