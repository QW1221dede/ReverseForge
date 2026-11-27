#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 tests/selftest_core.py · 加密 / 语法校验 / 积木库自测
============================================================================

    python tests/selftest_core.py
============================================================================
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from rf.analysis import validator as V          # noqa: E402
from rf.secure import crypto as C               # noqa: E402
from rf.snippets import get_library             # noqa: E402

FAILS: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    print(("  ✓ " if cond else "  ✗ ") + name + (f"  [{detail}]" if detail else ""))
    if not cond:
        FAILS.append(name)


def test_crypto() -> None:
    print("[1] 加密")
    prof = C.profile()
    check("AES 可用", prof["aes_gcm"], prof["source"])
    data = b"card-key: 123456 / license: valid"
    env = C.encrypt(data, "pw-测试")
    check("加密后非明文", data not in env.to_bytes())
    check("往返一致", C.decrypt(env, "pw-测试") == data)
    try:
        C.decrypt(env, "wrong")
        check("错误口令被拒绝", False)
    except C.CryptoError:
        check("错误口令被拒绝", True)

    env2 = C.encrypt(data, "pw-测试")
    env2.ciphertext = bytes([env2.ciphertext[0] ^ 1]) + env2.ciphertext[1:]
    try:
        C.decrypt(env2, "pw-测试")
        check("篡改被拒绝", False)
    except C.CryptoError:
        check("篡改被拒绝", True)

    tag = C.hmac_sign("payload", "k")
    check("HMAC 正确通过", C.hmac_verify("payload", "k", tag))
    check("HMAC 改一字节失败", not C.hmac_verify("payloaD", "k", tag))
    check("HMAC 常数时间比较", C.hmac_verify("payload", "k", tag.upper()))

    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "x.sealed"
        C.seal_json({"a": [1, 2, 3], "中文": "值"}, "pw", p)
        check("加密文件不带明文", "中文".encode() not in p.read_bytes()
              and b'"a"' not in p.read_bytes())
        back = C.open_json(p, "pw")
        check("加密 JSON 回读一致", back["a"] == [1, 2, 3] and back["中文"] == "值")

    rep = C.selftest(payload_kb=8)
    check("自检整体通过", rep["ok"])
    check("自检含篡改用例",
          any(c.get("算法") == "篡改检测" and "通过" in str(c.get("结果"))
              for c in rep["cases"]))


def test_validator() -> None:
    print("[2] 语法校验")
    check("Python 正常通过", V.validate("def f():\n    return 1\n", "python").ok)
    r = V.validate("def f()\n    return 1\n", "python")
    check("Python 缺冒号报错", not r.ok and r.errors[0].line == 1)
    check("错误带中文提示", "冒号" in r.errors[0].hint, r.errors[0].hint)
    r = V.validate("x = 1\ny = （2）\n", "python")
    check("中文括号被识别", not r.ok and "中文" in r.errors[0].msg)

    smali_ok = (".class public Lcom/a/B;\n.super Ljava/lang/Object;\n"
                ".method public static c()Z\n    .locals 1\n"
                "    const/4 v0, 0x0\n    if-eqz v0, :ok\n    return v0\n"
                "    :ok\n    const/4 v0, 0x1\n    return v0\n.end method\n")
    check("smali 正常通过", V.validate(smali_ok, "smali").ok)
    r = V.validate(smali_ok.replace("    :ok\n", "    :other\n"), "smali")
    check("smali 标签缺失报错", not r.ok and "没有定义" in r.errors[0].msg)
    r = V.validate(smali_ok.replace(".end method", ""), "smali")
    check("smali 缺 .end method 报错", not r.ok)

    java_bad = "class A { void f() { if (x) { } "
    check("Java 括号不配对", not V.validate(java_bad, "java").ok)
    check("JSON 合法", V.validate('{"a":1}', "json").ok)
    check("JSON 尾逗号报错", not V.validate('{"a":1,}', "json").ok)
    check("XML 未闭合报错", not V.validate("<a><b></a>", "xml").ok)


def test_snippets() -> None:
    print("[3] 积木库")
    lib = get_library(reload=True)
    st = lib.stats()
    check("积木数量 ≥ 30", st["total"] >= 30, str(st["total"]))
    check("全部语法通过", st["invalid"] == 0, str(st["invalid"]))
    cats = {c["name"] for c in lib.categories()}
    for name in ("入门", "侦察", "校验", "补丁", "解密", "运行期", "报告", "工程"):
        check(f"分类存在：{name}", name in cats)
    check("入门级 ≥ 5 块", len(lib.all(level=1)) >= 5,
          str(len(lib.all(level=1))))
    check("每块都有作用说明", all(len(s.purpose) >= 6 for s in lib.all()))
    check("每块都标了风险", all(s.risk for s in lib.all()))

    code = lib.compose(["patch.rebuild"])
    check("拼装语法通过", V.validate(code, "python").ok)
    order = [code.index(x) for x in ("intro.log", "verify.scan", "patch.plan",
                                     "patch.apply", "patch.rebuild")]
    check("依赖链自动排在前", order == sorted(order))
    check("拼装带来源注释", "作用：" in code and "ReverseForge" in code)

    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "my.py"
        f.write_text("# @id my.test\n# @title 我的积木\n# @category 工程\n"
                     "# @level 1\n# @purpose 测试用户积木\n\nrf.log('hi')\n",
                     encoding="utf-8")
        from rf.snippets.model import parse_user_snippet
        sn = parse_user_snippet(f)
        check("用户积木可解析", bool(sn and sn.sid == "my.test" and sn.valid))

    bad = V.validate("def broken(:\n  pass\n", "python")
    check("坏积木能被识别", not bad.ok)


def main() -> int:
    test_crypto()
    test_validator()
    test_snippets()
    print()
    if FAILS:
        print(f"失败 {len(FAILS)} 项：" + "、".join(FAILS))
        return 1
    print("全部通过")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
