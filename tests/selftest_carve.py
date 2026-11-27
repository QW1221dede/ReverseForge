#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
 tests/selftest_carve.py · 内嵌对象雕刻自测
 构造含内嵌 dex / zip / gzip / vdex 的样本，验证雕刻与 unpack_any 链路。
"""
from __future__ import annotations

import gzip
import io
import struct
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from rf.analysis import carve as carvemod     # noqa: E402
from rf.api import Ctx, make_api              # noqa: E402

FAILS: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    print(("  ✓ " if cond else "  ✗ ") + name + (f"  [{detail}]" if detail else ""))
    if not cond:
        FAILS.append(name)


def fake_dex(payload: bytes = b"hello-dex-body") -> bytes:
    """最小伪 dex：头字段合法即可通过 _looks_dex 校验。"""
    d = bytearray(b"dex\n035\x00" + b"\x00" * 0x60)
    struct.pack_into("<I", d, 0x20, len(d) + len(payload))   # file_size
    struct.pack_into("<I", d, 0x38, 16)                      # string_ids_size
    return bytes(d) + payload


def build_samples(tmp: Path) -> dict[str, Path]:
    out: dict[str, Path] = {}
    dex = fake_dex()

    # vdex：头 + 两个内嵌 dex（模拟 ART 产物）
    vdex = b"vdex" + struct.pack("<I", 15) + b"\x00" * 40 + dex + b"\x01" * 16 + dex
    p = tmp / "base.vdex"
    p.write_bytes(vdex)
    out["vdex"] = p

    # 固件风格：前缀垃圾 + 内嵌 zip + gzip 段
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("classes.dex", dex)
        z.writestr("assets/config.json", '{"mode":1}')
    blob = b"\xff" * 300 + b"FIRMWARE-HEADER" + buf.getvalue() + gzip.compress(b"kernel-image-data")
    p = tmp / "fw.img"
    p.write_bytes(blob)
    out["firmware"] = p

    # 加壳 so 风格：ELF 头 + 内嵌 dex（加固残留）
    p = tmp / "libshell.so"
    p.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 100 + dex)
    out["so"] = p

    # 加密 zip（zip_password 链路用）
    p = tmp / "plain.zip"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("readme.txt", "normal zip")
    out["zip"] = p
    return out


def main() -> int:
    print("[1] carve 模块")
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        s = build_samples(tmp)

        cr = carvemod.carve(s["vdex"].read_bytes())
        ndex = sum(1 for o in cr.objects if o.kind in ("dex", "cdex"))
        check("vdex 雕出 dex ≥2", ndex >= 2, f"实际 {len(cr.objects)} 个")

        cr = carvemod.carve(s["firmware"].read_bytes())
        kinds = {o.kind for o in cr.objects}
        check("固件雕出 zip", "zip" in kinds, str(kinds))
        check("固件雕出 gzip", "gzip" in kinds, str(kinds))
        zobj = next((o for o in cr.objects if o.kind == "zip"), None)
        if zobj and zobj.data:
            with zipfile.ZipFile(io.BytesIO(zobj.data)) as z:
                names = z.namelist()
            check("重建 zip 可打开且含 classes.dex",
                  "classes.dex" in names, str(names))

        cr = carvemod.carve(s["so"].read_bytes())
        check("so 雕出内嵌 dex",
              any(o.kind == "dex" for o in cr.objects), cr.brief())

        print("[2] carve_file 落盘")
        dst = tmp / "vdex_out"
        cr = carvemod.carve_file(s["vdex"], dst)
        files = list(dst.rglob("*.dex"))
        check("落盘 .dex 文件", len(files) >= 2, str([f.name for f in files]))

        print("[3] unpack_any 链路（vdex / so / 固件）")
        api = make_api(Ctx(on_log=print, quiet=False))
        r = api.unpack_any(s["vdex"])
        check("vdex 走雕刻方法", "雕刻" in r["method"], r["method"])
        r = api.unpack_any(s["so"])
        check("so 兜底含雕刻", "carved" in str(r["notes"]) or "雕刻" in r["method"],
              r["method"] + " / " + " | ".join(r["notes"][-2:]))
        r = api.unpack_any(s["firmware"])
        check("固件兜底含雕刻", "carved" in str(r["notes"]) or "雕刻" in r["method"],
              r["method"])
        r = api.carve(s["firmware"])
        check("api.carve 返回对象", r["found"] and len(r["objects"]) >= 2)

    print()
    if FAILS:
        print(f"失败 {len(FAILS)} 项：{FAILS}")
        return 1
    print("全部通过")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
