#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
联网校验自测 —— "连服务器验证，不通过就不给用"。

服务器说不行，本地代码只是**忠实地执行判决**。改本地判断没用，
得让客户端"听到的回复"变成同意。

覆盖三种真实写法（都从外挂样本里抄的）：

    [1] LoginCheck   getResponseCode → if-eq 200 才成功     ← == 200
    [2] RangeCheck   getResponseCode → if-lt 200 才成功     ← >= 200
    [3] ErrCheck     getResponseCode → if-lt 400 判错       ← >= 400
    [4] OkHttpCheck  Response.code() + isSuccessful()       ← OkHttp 系
    [5] BusinessApi  getWeather（正常业务接口）              ← 不许误改

验收：
    · 4 个校验点全部识别，1 个业务点不被当校验
    · 补丁全部落在 move-result 之后，强制 200 / true
    · 应用后语法通过（apktool 能汇编）
    · scope="all" 时才动业务接口

用法：python tests/selftest_netcheck.py
"""

import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rf.patch import checkpoints as cp          # noqa: E402
from rf.patch import netcheck as nc            # noqa: E402
from rf.patch.engine import apply as patch_apply   # noqa: E402

_ok = _fail = 0


def check(cond, msg: str) -> None:
    global _ok, _fail
    if cond:
        _ok += 1
        print(f"  ✓ {msg}")
    else:
        _fail += 1
        print(f"  ✗ {msg}")


SAMPLES: dict[str, str] = {}

# [1] 卡密登录：码值必须等于 200
SAMPLES["LoginCheck"] = """\
.class public Lcom/test/LoginCheck;
.super Ljava/lang/Object;

.method public static verifyCard(Ljava/lang/String;)Z
    .locals 5
    new-instance v0, Ljava/net/URL;
    const-string v1, "http://wig.example.top/api/login"
    invoke-direct {v0, v1}, Ljava/net/URL;-><init>(Ljava/lang/String;)V
    invoke-virtual {v0}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;
    move-result-object v0
    check-cast v0, Ljava/net/HttpURLConnection;
    const/4 v1, 0x1
    invoke-virtual {v0, v1}, Ljava/net/HttpURLConnection;->setDoOutput(Z)V
    invoke-virtual {v0}, Ljava/net/HttpURLConnection;->connect()V
    invoke-virtual {v0}, Ljava/net/HttpURLConnection;->getResponseCode()I
    move-result v3
    const/16 v4, 0xc8
    if-eq v3, v4, :fail
    const/4 v0, 0x1
    return v0
    :fail
    const/4 v0, 0x0
    return v0
.end method
"""

# [2] >= 200 视为成功
SAMPLES["RangeCheck"] = """\
.class public Lcom/test/RangeCheck;
.super Ljava/lang/Object;

.method public static checkLicense(Ljava/lang/String;)V
    .locals 4
    new-instance v0, Ljava/net/URL;
    invoke-direct {v0, p0}, Ljava/net/URL;-><init>(Ljava/lang/String;)V
    invoke-virtual {v0}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;
    move-result-object v0
    check-cast v0, Ljava/net/HttpURLConnection;
    invoke-virtual {v0}, Ljava/net/HttpURLConnection;->getResponseCode()I
    move-result v1
    const/16 v2, 0xc8
    if-lt v1, v2, :cond_0
    invoke-virtual {v0}, Ljava/net/HttpURLConnection;->getInputStream()Ljava/io/InputStream;
    move-result-object v1
    return-void
    :cond_0
    const-string v1, "卡密校验失败"
    const/4 v2, 0x0
    invoke-static {v2}, Ljava/lang/System;->exit(I)V
    return-void
.end method
"""

# [3] >= 400 判错（错误分支在前）
SAMPLES["ErrCheck"] = """\
.class public Lcom/test/ErrCheck;
.super Ljava/lang/Object;

.method public static verify(Ljava/lang/String;)Ljava/lang/String;
    .locals 3
    new-instance v0, Ljava/net/URL;
    invoke-direct {v0, p0}, Ljava/net/URL;-><init>(Ljava/lang/String;)V
    invoke-virtual {v0}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;
    move-result-object v0
    check-cast v0, Ljava/net/HttpURLConnection;
    invoke-virtual {v0}, Ljava/net/HttpURLConnection;->getResponseCode()I
    move-result v1
    const/16 v2, 0x190
    if-lt v1, v2, :err
    const-string v1, "{\\"code\\":0,\\"msg\\":\\"ok\\"}"
    return-object v1
    :err
    const-string v1, "{\\"code\\":403,\\"msg\\":\\"卡密已过期\\"}"
    return-object v1
.end method
"""

# [4] OkHttp：code() + isSuccessful()
SAMPLES["OkHttpCheck"] = """\
.class public Lcom/test/OkHttpCheck;
.super Ljava/lang/Object;

.method public static login(Ljava/lang/String;)Z
    .locals 3
    new-instance v0, Lokhttp3/OkHttpClient;
    invoke-direct {v0}, Lokhttp3/OkHttpClient;-><init>()V
    const-string v1, "https://api.example.top/v1/activate"
    invoke-static {v1}, Lokhttp3/Request;->create(Ljava/lang/String;)Lokhttp3/Request;
    move-result-object v1
    invoke-virtual {v0, v1}, Lokhttp3/OkHttpClient;->newCall(Lokhttp3/Request;)Lokhttp3/Call;
    move-result-object v0
    invoke-interface {v0}, Lokhttp3/Call;->execute()Lokhttp3/Response;
    move-result-object v0
    invoke-virtual {v0}, Lokhttp3/Response;->code()I
    move-result v1
    const/16 v2, 0xc8
    if-eq v1, v2, :bad
    invoke-virtual {v0}, Lokhttp3/Response;->isSuccessful()Z
    move-result v1
    return v1
    :bad
    const/4 v1, 0x0
    return v1
.end method
"""

# [5] 正常业务接口：不该被当校验
SAMPLES["BusinessApi"] = """\
.class public Lcom/test/BusinessApi;
.super Ljava/lang/Object;

.method public static getTemperature(Ljava/lang/String;)Ljava/lang/String;
    .locals 3
    new-instance v0, Ljava/net/URL;
    invoke-direct {v0, p0}, Ljava/net/URL;-><init>(Ljava/lang/String;)V
    invoke-virtual {v0}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;
    move-result-object v0
    check-cast v0, Ljava/net/HttpURLConnection;
    invoke-virtual {v0}, Ljava/net/HttpURLConnection;->getResponseCode()I
    move-result v1
    const/16 v2, 0xc8
    if-ne v1, v2, :skip
    const-string v1, "n/a"
    return-object v1
    :skip
    const-string v1, "25C"
    return-object v1
.end method
"""


def _write(root: Path) -> None:
    d = root / "com" / "test"
    d.mkdir(parents=True, exist_ok=True)
    for name, code in SAMPLES.items():
        (d / f"{name}.smali").write_text(code, encoding="utf-8")


def main() -> int:
    td = Path(tempfile.mkdtemp(prefix="rfnet_"))
    try:
        root = td / "smali"
        _write(root)

        print("[1] 网络点识别")
        pts = nc.scan_network(root)
        names = {p.cls_simple for p in pts}
        print("    点位：", sorted((p.cls_simple, p.kind, p.scope) for p in pts))
        check("LoginCheck" in names, "HttpURLConnection ==200 写法被认出")
        check("RangeCheck" in names, ">=200 写法被认出")
        check("ErrCheck" in names, ">=400 判错写法被认出")
        check("OkHttpCheck" in names, "OkHttp code()/isSuccessful() 被认出")
        check("BusinessApi" in names, "业务接口的 getResponseCode 也被扫到（只是不进校验范围）")
        biz = [p for p in pts if p.cls_simple == "BusinessApi"]
        check(biz and all(p.scope == "all" for p in biz),
              "业务接口标为 all（默认不改）")
        okp = [p for p in pts if p.cls_simple == "OkHttpCheck" and p.kind == "ok"]
        check(bool(okp), "isSuccessful() 单独识别为 ok 类型")

        print("\n[2] 生成补丁（默认只改校验方法）")
        ops, stat = nc.plan_network(root)
        print("    统计：", stat)
        files = {Path(o.file).stem for o in ops}
        check("LoginCheck" in files and "RangeCheck" in files, "校验方法都进补丁")
        check("ErrCheck" in files, "判错写法也进补丁")
        check("OkHttpCheck" in files, "OkHttp 进补丁")
        check("BusinessApi" not in files, "业务接口默认不动（不误伤）")
        check(stat["code"] >= 4, f"识别状态码点 {stat['code']} 处")
        check(stat["ok"] >= 1, f"识别成功标志 {stat['ok']} 处")

        print("\n[3] 应用 + 语法校验")
        res = patch_apply(root, ops, backup_dir=td / "bak")
        check(res.ok, f"应用：{res.text().splitlines()[0] if res.text() else ''}")
        if not res.ok:
            for e in res.errors[:5]:
                print("      !", e)

        for stem, want in (("LoginCheck", "const/16 v3, 0xc8"),
                           ("RangeCheck", "const/16 v1, 0xc8"),
                           ("ErrCheck", "const/16 v1, 0xc8")):
            txt = (root / "com" / "test" / f"{stem}.smali").read_text(encoding="utf-8")
            check(want in txt, f"{stem} 已强制 {want}")

        okx = (root / "com" / "test" / "OkHttpCheck.smali").read_text(encoding="utf-8")
        check("const/16 v1, 0xc8" in okx, "OkHttp code() 已强制 200")
        check("const/4 v1, 0x1" in okx, "isSuccessful() 已强制 true")

        biztxt = (root / "com" / "test" / "BusinessApi.smali").read_text(encoding="utf-8")
        check(biztxt.count("0xc8") == 1, "业务接口只保留原判断，没被加塞")

        print("\n[4] scope=all 才动业务接口")
        _write(root)
        ops2, stat2 = nc.plan_network(root, scope="all")
        files2 = {Path(o.file).stem for o in ops2}
        check("BusinessApi" in files2, "scope=all 时业务接口也改")
        check(len(ops2) > len(ops), f"all 比 check 多 {len(ops2) - len(ops)} 条")

        print("\n[5] Frida 网络覆盖脚本")
        js = nc.write_frida_net(td / "hook_net.js")
        t = js.read_text(encoding="utf-8")
        check("getResponseCode" in t, "脚本 hook 了 getResponseCode")
        check("isSuccessful" in t, "脚本 hook 了 isSuccessful")
        check("洗白" in t or "wash" in t, "脚本含返回体洗白逻辑")
        check("rfNet();" in t, "脚本有入口调用")
        check(js.stat().st_size > 1500, f"脚本 {js.stat().st_size} 字节")

        print(f"\n{'=' * 56}")
        print(f"通过 {_ok}｜失败 {_fail}")
        return 0 if _fail == 0 else 1
    finally:
        shutil.rmtree(td, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
