# -*- coding: utf-8 -*-
"""
============================================================================
 rf.fakepacket.hijack · 网络层拦截：mock / 透明代理 双模（2026-11-28）
============================================================================

【两种模式，根本区别】

  mode=mock   拦住请求，自己回假的"成功"
              → 本地程序以为过了，但服务器压根没搭理你
              → 拿不到真签名、拿不到真数据，验证通过也是空壳

  mode=proxy  把请求**原样**送到真服务器，把真响应原样带回来
              → 服务器真的处理了这次请求，签名/数据都是真的
              → 全程录进 rf_capture.log，可离线分析、可重放

  默认走 proxy。连不上真服务器（无网/DNS 挂）时自动退回 mock，
  保证程序至少能启动，不会直接报错退出。

【proxy 怎么知道原来要连哪】
  getaddrinfo 做**真实解析**，把真 IP 交给程序；
  connect 被 hook 后重定向到本地，同时把真目标以
  "RFORIGIN 1.2.3.4:80\\n" 的协议头告诉本地服务端；
  服务端用 real_connect 连真服务器，双向 relay，边转发边记录。
  real_connect 是 dlsym 拿的原始指针，不会二次触发 hook（死循环防护）。

【拿到的东西】
  rf_capture.log 里是全量明文：
    [>> 发给服务器]  POST /api/login ... code=xxx&imei=xxx
    [<< 服务器返回]  HTTP/1.1 200 ... {"code":20000,"checktrue":"1","sign":"..."}
  用 rf.fakepacket.capture 解析，自动提取签名、卡密、真数据。
============================================================================
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import struct
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

_NDK_ROOTS = [
    r"D:\android_tools\sdk\ndk",
    r"C:\Users\SRIB\AppData\Local\Android\Sdk\ndk",
]

DEFAULT_PORT = 18888
DEFAULT_CAP = "/data/local/tmp/rf_capture.log"

DEFAULT_JSON = {
    "code": 20000, "status": 20000, "errcode": 0, "ret": 20000,
    "msg": "ok", "message": "ok", "success": True,
    "checktrue": "1", "check_true": "1", "checkTrue": "1",
    "valid": 1, "ok": 1,
    "expires": "2030-12-31 23:59:59",
    "expire": "2030-12-31 23:59:59",
    "expire_time": "2030-12-31 23:59:59",
    "new_code2": "1",
    "data": {"code": 20000, "checktrue": "1", "msg": "ok"},
}


# --------------------------------------------------------------------------
# C 源码模板（占位符用 @@XXX@@，避免 % 转义地狱）
# --------------------------------------------------------------------------
C_TEMPLATE = r"""
/* rf_hook.so —— 由 ReverseForge 自动生成，勿手改 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <pthread.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/select.h>
#include <errno.h>

#define MODE_MOCK  0
#define MODE_PROXY 1

static int  g_port = @@PORT@@;
static int  g_mode = @@MODE@@;
static int  g_rewrite = @@REWRITE@@;
static char g_json[8192] = @@JSON@@;
static char g_cap_path[512] = "@@CAP@@";

static int (*real_connect)(int, const struct sockaddr *, socklen_t);
static int (*real_getaddrinfo)(const char *, const char *,
                               const struct addrinfo *, struct addrinfo **);
static struct hostent *(*real_ghbn)(const char *);

static int g_cap_fd = -1;
static pthread_mutex_t g_cap_lock = PTHREAD_MUTEX_INITIALIZER;

static void cap_raw(const char *tag, const char *buf, int n) {
    if (g_cap_fd < 0) return;
    pthread_mutex_lock(&g_cap_lock);
    if (tag && *tag) write(g_cap_fd, tag, strlen(tag));
    if (buf && n > 0) write(g_cap_fd, buf, (size_t)n);
    write(g_cap_fd, "\n----\n", 6);
    pthread_mutex_unlock(&g_cap_lock);
}

static void load_conf(void) {
    const char *p = getenv("RF_HIJACK_CONF");
    FILE *f = NULL;
    if (p) f = fopen(p, "r");
    if (!f) f = fopen("./rf_hook.conf", "r");
    if (!f) return;
    char line[8192];
    while (fgets(line, sizeof line, f)) {
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = 0;
        char *v = eq + 1;
        char *nl = strpbrk(v, "\r\n");
        if (nl) *nl = 0;
        if (!strcmp(line, "port")) g_port = atoi(v);
        else if (!strcmp(line, "json")) {
            strncpy(g_json, v, sizeof(g_json) - 1);
            g_json[sizeof(g_json) - 1] = 0;
        }
        else if (!strcmp(line, "mode")) g_mode = strcmp(v, "mock") ? MODE_PROXY : MODE_MOCK;
        else if (!strcmp(line, "rewrite")) g_rewrite = atoi(v);
        else if (!strcmp(line, "cap")) {
            strncpy(g_cap_path, v, sizeof(g_cap_path) - 1);
            g_cap_path[sizeof(g_cap_path) - 1] = 0;
        }
    }
    fclose(f);
}

/* 把 JSON 里的失败标志原地改成通过。全部等长替换，Content-Length 不用动。 */
static int rewrite_body(char *body, size_t blen) {
    int n = 0;
    static const char *num_keys[] = { "code", "status", "errcode", "ret", NULL };
    static const char *bool_keys[] = {
        "checktrue", "check_true", "checkTrue", "success", "valid", "ok",
        "result", "isok", "pass", NULL
    };
    int i;
    for (i = 0; bool_keys[i]; i++) {
        char pat[64];
        snprintf(pat, sizeof pat, "\"%s\"", bool_keys[i]);
        char *p = body;
        while ((p = strstr(p, pat)) != NULL && (size_t)(p - body) < blen) {
            char *q = p + strlen(pat);
            while (*q == ' ') q++;
            if (*q != ':') { p++; continue; }
            q++;
            while (*q == ' ') q++;
            if (*q == '"') {
                char *v = q + 1;
                char *e = strchr(v, '"');
                if (!e) { p++; continue; }
                if (e - v == 1 && v[0] == '0') { v[0] = '1'; n++; }
                p = e;
            } else if (strncmp(q, "false", 5) == 0) {
                memcpy(q, "true ", 5); n++; p = q + 5;
            } else if (*q == '0' && (q[1] == ',' || q[1] == '}' || q[1] == ']' || q[1] == ' ')) {
                *q = '1'; n++; p = q + 1;
            } else {
                p = q;
            }
        }
    }
    for (i = 0; num_keys[i]; i++) {
        char pat[64];
        snprintf(pat, sizeof pat, "\"%s\"", num_keys[i]);
        char *p = body;
        while ((p = strstr(p, pat)) != NULL && (size_t)(p - body) < blen) {
            char *q = p + strlen(pat);
            while (*q == ' ') q++;
            if (*q != ':') { p++; continue; }
            q++;
            while (*q == ' ') q++;
            if (*q == '"') {
                char *v = q + 1;
                char *e = strchr(v, '"');
                if (!e) { p++; continue; }
                size_t vl = (size_t)(e - v), k;
                int dig = vl == 5;
                for (k = 0; dig && k < vl; k++) if (v[k] < '0' || v[k] > '9') dig = 0;
                if (dig && memcmp(v, "20000", 5) != 0) { memcpy(v, "20000", 5); n++; }
                p = e;
            } else if (*q >= '0' && *q <= '9') {
                char *e = q;
                while (*e >= '0' && *e <= '9') e++;
                if (e - q == 5 && memcmp(q, "20000", 5) != 0) { memcpy(q, "20000", 5); n++; }
                p = e;
            } else {
                p = q;
            }
        }
    }
    (void)blen;
    return n;
}

/* 读一条完整消息（按 Content-Length 判断结束） */
static char *read_msg(int fd, size_t *out_len, size_t cap0) {
    size_t cap = cap0, len = 0, need = 0;
    char *buf = (char *)malloc(cap);
    int hdr = 0;
    if (!buf) return NULL;
    for (;;) {
        if (len + 8192 >= cap) {
            char *nb = (char *)realloc(buf, cap * 2);
            if (!nb) break;
            buf = nb;
            cap *= 2;
        }
        ssize_t k = recv(fd, buf + len, cap - len - 1, 0);
        if (k <= 0) break;
        len += (size_t)k;
        buf[len] = 0;
        if (!hdr) {
            char *p = strstr(buf, "\r\n\r\n");
            if (p) {
                hdr = 1;
                char *cl = strcasestr(buf, "content-length:");
                if (cl) need = (size_t)atoi(cl + 15);
                else need = 0;
                if (need == 0) break;
            }
        }
        if (hdr) {
            char *p = strstr(buf, "\r\n\r\n");
            if (p && len - (size_t)(p + 4 - buf) >= need) break;
        }
    }
    *out_len = len;
    return buf;
}

/* 转发 + 改写：请求原样发，响应改完再给客户端，两边都录像 */
static void pump(int cli, int up) {
    char buf[8192];
    size_t rlen = 0, slen = 0;
    char *req = read_msg(cli, &rlen, 65536);
    if (!req || rlen == 0) { free(req); return; }
    cap_raw("[>> 发给服务器] ", req, (int)rlen);
    send(up, req, rlen, 0);
    free(req);

    char *res = read_msg(up, &slen, 131072);
    if (!res) return;
    /* 先录原始响应——真签名、真数据都在这里 */
    cap_raw("[<< 服务器返回] ", res, (int)slen);

    if (g_rewrite && slen > 0) {
        char *body = strstr(res, "\r\n\r\n");
        if (body) {
            int ch = rewrite_body(body + 4, slen - (size_t)(body + 4 - res));
            if (ch) {
                char note[96];
                snprintf(note, sizeof note, "[~~ 已把 %d 处失败标志改为通过]", ch);
                cap_raw(note, "", 0);
            }
        }
    }
    send(cli, res, slen, 0);
    free(res);

    /* 后续 keep-alive 流量纯透传 */
    for (;;) {
        struct timeval tv;
        fd_set r;
        FD_ZERO(&r);
        FD_SET(cli, &r);
        FD_SET(up, &r);
        tv.tv_sec = 8;
        tv.tv_usec = 0;
        int n = select((cli > up ? cli : up) + 1, &r, NULL, NULL, &tv);
        if (n <= 0) break;
        int fin = 0;
        if (FD_ISSET(cli, &r)) {
            ssize_t k = recv(cli, buf, sizeof buf, 0);
            if (k <= 0) fin = 1;
            else { send(up, buf, (size_t)k, 0); cap_raw("[>> 发给服务器] ", buf, (int)k); }
        }
        if (!fin && FD_ISSET(up, &r)) {
            ssize_t k = recv(up, buf, sizeof buf, 0);
            if (k <= 0) fin = 1;
            else { send(cli, buf, (size_t)k, 0); cap_raw("[<< 服务器返回] ", buf, (int)k); }
        }
        if (fin) break;
    }
}

static void send_mock(int c) {
    char hdr[512];
    int hl = snprintf(hdr, sizeof hdr,
        "HTTP/1.1 200 OK\r\n"
        "Server: nginx\r\n"
        "Content-Type: application/json; charset=utf-8\r\n"
        "Content-Length: %u\r\n"
        "Connection: close\r\n\r\n",
        (unsigned)strlen(g_json));
    send(c, hdr, (size_t)hl, 0);
    send(c, g_json, strlen(g_json), 0);
}

static void *serve_thread(void *arg) {
    (void)arg;
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) return NULL;
    int one = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons((unsigned short)g_port);
    if (bind(lfd, (struct sockaddr *)&a, sizeof a) < 0) { close(lfd); return NULL; }
    listen(lfd, 64);

    for (;;) {
        int c = accept(lfd, NULL, NULL);
        if (c < 0) continue;

        /* 先读一行，看是不是 RFORIGIN 协议头 */
        char line[192];
        int n = 0;
        while (n < (int)sizeof(line) - 1) {
            char ch;
            ssize_t k = recv(c, &ch, 1, 0);
            if (k <= 0) break;
            if (ch == '\n') break;
            line[n++] = ch;
        }
        line[n] = 0;

        struct sockaddr_in orig;
        int is_px = 0;
        if (g_mode == MODE_PROXY && strncmp(line, "RFORIGIN ", 9) == 0) {
            unsigned x1, x2, x3, x4;
            int p = 0;
            if (sscanf(line + 9, "%u.%u.%u.%u:%d", &x1, &x2, &x3, &x4, &p) == 5
                    && x1 < 256 && x2 < 256 && x3 < 256 && x4 < 256
                    && p > 0 && p < 65536) {
                memset(&orig, 0, sizeof orig);
                orig.sin_family = AF_INET;
                orig.sin_addr.s_addr = htonl((x1 << 24) | (x2 << 16) | (x3 << 8) | x4);
                orig.sin_port = htons((unsigned short)p);
                is_px = 1;
            }
        }

        int up = -1;
        if (is_px) {
            up = socket(AF_INET, SOCK_STREAM, 0);
            if (up >= 0 && real_connect
                    && real_connect(up, (struct sockaddr *)&orig, sizeof orig) != 0) {
                close(up);
                up = -1;
            }
        }

        if (up >= 0) {
            char note[256];
            snprintf(note, sizeof note, "[== 连真实服务器 %s] ", line + 9);
            cap_raw(note, "", 0);
            pump(c, up);
            close(up);
        } else {
            /* 真服务器连不上：退回 mock，保证程序能走完 */
            char tmp[4096];
            int k = (int)recv(c, tmp, sizeof tmp, 0);
            if (k <= 0 && n > 0) { memcpy(tmp, line, (size_t)n); }
            cap_raw("[! 真服务器不通，已回落 mock] ", line, n);
            send_mock(c);
        }

        shutdown(c, SHUT_WR);
        close(c);
    }
    return NULL;
}

static pthread_once_t g_once = PTHREAD_ONCE_INIT;
static void boot(void) {
    signal(SIGPIPE, SIG_IGN);
    real_connect     = dlsym(RTLD_NEXT, "connect");
    real_getaddrinfo = dlsym(RTLD_NEXT, "getaddrinfo");
    real_ghbn        = dlsym(RTLD_NEXT, "gethostbyname");
    load_conf();
    g_cap_fd = open(g_cap_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (g_cap_fd < 0) g_cap_fd = open("./rf_capture.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    pthread_t t;
    if (pthread_create(&t, NULL, serve_thread, NULL) == 0)
        pthread_detach(t);
    usleep(150000);
}

/* ---------------- hooks ---------------- */
int connect(int fd, const struct sockaddr *addr, socklen_t len) {
    pthread_once(&g_once, boot);
    if (addr && addr->sa_family == AF_INET) {
        const struct sockaddr_in *in = (const struct sockaddr_in *)addr;
        unsigned int ip = ntohl(in->sin_addr.s_addr);
        unsigned short port = ntohs(in->sin_port);
        int hijack = 0;
        if (ip != INADDR_LOOPBACK && ip != 0) hijack = 1;
        else if (ip == INADDR_LOOPBACK && (port == 80 || port == 443)) hijack = 1;

        if (hijack) {
            struct sockaddr_in na = *in;
            na.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            na.sin_port = htons((unsigned short)g_port);
            int rc = real_connect(fd, (struct sockaddr *)&na, sizeof(na));
            if (rc == 0) {
                char hdr[96];
                int hn = snprintf(hdr, sizeof hdr, "RFORIGIN %u.%u.%u.%u:%u\n",
                    (ip >> 24) & 255, (ip >> 16) & 255, (ip >> 8) & 255, ip & 255,
                    (unsigned)port);
                send(fd, hdr, (size_t)hn, MSG_NOSIGNAL);
            }
            return rc;
        }
    }
    return real_connect(fd, addr, len);
}

int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints, struct addrinfo **res) {
    pthread_once(&g_once, boot);
    /* 真实解析：拿到真 IP，交给 connect 去劫持并回报 */
    int rc = real_getaddrinfo(node, service, hints, res);
    if (rc == 0) return rc;
    /* 解析不了（无网/被墙）：指向本地，走 mock 兜底 */
    char ps[16];
    snprintf(ps, sizeof ps, "%d", g_port);
    return real_getaddrinfo("127.0.0.1", ps, hints, res);
}

__attribute__((visibility("default"), used))
struct hostent *gethostbyname(const char *name) {
    pthread_once(&g_once, boot);
    struct hostent *h = real_ghbn ? real_ghbn(name) : NULL;
    if (h) return h;
    static struct in_addr addr;
    static char *aliases[] = { NULL };
    static char *addrs[2];
    static struct hostent fake;
    addr.s_addr = htonl(INADDR_LOOPBACK);
    addrs[0] = (char *)&addr;
    addrs[1] = NULL;
    fake.h_name = (char *)name;
    fake.h_aliases = aliases;
    fake.h_addrtype = AF_INET;
    fake.h_length = 4;
    fake.h_addr_list = addrs;
    return &fake;
}
"""


# --------------------------------------------------------------------------
# 工具链
# --------------------------------------------------------------------------
def find_ndk() -> tuple[Path, Path] | None:
    for root in _NDK_ROOTS:
        p = Path(root)
        if not p.is_dir():
            continue
        for d in sorted([x for x in p.iterdir() if x.is_dir()], reverse=True):
            base = d / "toolchains/llvm/prebuilt/windows-x86_64"
            clang = base / "bin/clang.exe"
            sysroot = base / "sysroot"
            if clang.is_file() and sysroot.is_dir():
                return clang, sysroot
    return None


def compile_hook(c_src: Path, out_so: Path,
                 tool: tuple[Path, Path] | None = None) -> tuple[bool, str]:
    tool = tool or find_ndk()
    if not tool:
        return False, "找不到 NDK（clang.exe / sysroot）"
    clang, sysroot = tool
    cmd = [str(clang), "--target=aarch64-linux-android21",
           "--sysroot=" + str(sysroot),
           "-shared", "-fPIC", "-O2", "-s",
           "-o", str(out_so), str(c_src)]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=180)
    except Exception as e:
        return False, "编译异常：%r" % (e,)
    if r.returncode != 0 or not out_so.is_file():
        msg = (r.stderr or b"").decode("utf-8", "replace")[-800:]
        return False, "编译失败：" + msg
    head = out_so.read_bytes()[:20]
    if head[:4] != b"\x7fELF" or struct.unpack_from("<H", head, 18)[0] != 0xB7:
        return False, "产物不是 AArch64 ELF"
    return True, "%d B" % out_so.stat().st_size


# --------------------------------------------------------------------------
# 目标分析
# --------------------------------------------------------------------------
DOMAIN_RE = re.compile(rb"(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+"
                       rb"(?:com|net|org|top|cn|xyz|io|cc|me|vip|club|site|shop|app|dev|info|biz)")
SUCCESS_CODE_RE = re.compile(rb"(?:code|status)[\"']?\s*[:=]\s*(\d{3,5})", re.I)

_DOMAIN_NOISE = (
    "upx.sf.net", "sf.net", "unpkg.com", "googlesource.com", "googleapis.com",
    "github.com", "githubusercontent.com", "schemas.android.com", "w3.org",
    "python.org", "nodejs.org", "mozilla.org", "openssl.org", "zlib.net",
    "android.com", "termux.dev", "gnu.org", "kernel.org", "busybox.net",
)


def _shell_of(data: bytes) -> str:
    if b"UPX!" in data or b"UPX 4." in data or b"$Id: UPX" in data:
        return "upx"
    if b".vmp" in data or b"VMProtect" in data:
        return "vmp"
    if data[:4] == b"\x7fELF":
        return "plain"
    return "unknown"


def _find_domains(data: bytes, limit: int = 12) -> list[str]:
    out, seen = [], set()
    for m in DOMAIN_RE.finditer(data):
        d = m.group().decode("ascii", "ignore")
        if len(d) < 6 or d in seen:
            continue
        if any(d == n or d.endswith("." + n) for n in _DOMAIN_NOISE):
            continue
        if d.endswith((".so", ".zip", ".png", ".html")) or d.startswith(("www.", "schemas.")):
            continue
        seen.add(d)
        out.append(d)
        if len(out) >= limit:
            break
    return out


def analyze(target: str | Path) -> dict:
    p = Path(target)
    info: dict = {"target": str(p), "ok": False, "notes": []}
    if not p.is_file():
        info["notes"].append("目标不存在")
        return info

    raw = p.read_bytes()
    if raw[:4] != b"\x7fELF":
        i = raw.find(b"\x1f\x8b\x08")
        if i > 0:
            import gzip
            try:
                raw = gzip.decompress(raw[i:])
                info["notes"].append("makeself 包，已解出载荷")
            except Exception as e:
                info["notes"].append("解压失败：%r" % (e,))
                return info
    info["size"] = len(raw)
    info["shell"] = _shell_of(raw)
    info["sha256"] = hashlib.sha256(raw).hexdigest()

    feats = []
    for kw in (b"checktrue", b"api/login", b"HTTP/1.1", b"POST /", b"Host:",
               b"x-www-form-urlencoded", b"card", b"activate", b"expires"):
        if kw in raw:
            feats.append(kw.decode("ascii", "ignore"))
    info["features"] = feats
    info["domains"] = _find_domains(raw)

    codes = sorted({int(m.group(1)) for m in SUCCESS_CODE_RE.finditer(raw)
                    if 100 <= int(m.group(1)) <= 99999})
    if b"\x20\x4e\x00" in raw or b"20000" in raw:
        codes = sorted(set(codes) | {20000})
    info["success_codes"] = codes[:6]

    net = any(f in feats for f in ("HTTP/1.1", "POST /", "Host:"))
    info["net_client"] = net
    info["hijackable"] = bool(net and (info["domains"] or info["shell"] in ("upx", "vmp", "plain")))
    if not net:
        info["notes"].append("未发现自实现 HTTP 客户端，劫持可能无效")
    if info["shell"] in ("upx", "vmp"):
        info["notes"].append("样本有壳（%s），静态补丁不可行，走网络层" % info["shell"])
    info["ok"] = True
    return info


def decide(target: str | Path) -> dict:
    p = Path(target)
    d: dict = {"target": str(p), "strategy": "manual", "reasons": [], "detail": {}}

    info = analyze(p)
    d["detail"]["analyze"] = info
    if not info.get("ok"):
        d["reasons"].append("目标不可读")
        return d

    static_ok, static_note = False, ""
    if info.get("shell") == "plain":
        try:
            import sys
            sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
            from rf.patch.native import patch_native
            r = patch_native(p, dry_run=True)
            static_ok = r.ok and any("0x" in x for x in r.log)
            static_note = r.text()
        except Exception as e:
            static_note = "静态补丁探测异常：%r" % (e,)
    elif info.get("shell") in ("upx", "vmp"):
        static_note = "样本 %s 加壳，静态补丁不做" % info["shell"]
    d["detail"]["static"] = {"ok": static_ok, "note": static_note}

    if static_ok:
        d["strategy"] = "static_patch"
        d["reasons"].append("明文代码里有可拦截的失败分支，静态补丁优先")
    elif info.get("hijackable"):
        d["strategy"] = "net_hijack"
        d["reasons"].append("有自实现 HTTP 客户端"
                            + ("，且样本加壳" if info.get("shell") in ("upx", "vmp") else "")
                            + " → 网络层（proxy 模式，转发真服务器并录像）")
        if info.get("domains"):
            d["reasons"].append("疑似业务域名（参考）：" + ", ".join(info["domains"][:3]))
    else:
        d["reasons"].append("既无可补分支、也无 HTTP 客户端，需人工判断")

    d["port"] = DEFAULT_PORT
    d["mode"] = "proxy"
    d["mock_json"] = dict(DEFAULT_JSON)
    return d


# --------------------------------------------------------------------------
# 抓包解析
# --------------------------------------------------------------------------
_SIG_KEYS = ("sign", "signature", "sig", "token", "access_token", "auth",
             "checksign", "md5", "hash", "key")


def parse_capture(path: str | Path) -> dict:
    """解析 rf_capture.log：请求、响应、签名、卡密、真数据。"""
    p = Path(path)
    out = {"file": str(p), "ok": False, "requests": [], "responses": [],
           "signatures": [], "cards": [], "hosts": [], "error": ""}
    if not p.is_file():
        out["error"] = "文件不存在"
        return out
    text = p.read_text(encoding="utf-8", errors="replace")
    blocks = [b for b in text.split("\n----\n") if b.strip()]

    hosts: set[str] = set()
    for b in blocks:
        if b.startswith("[== 连真实服务器 "):
            m = re.search(r"\[== 连真实服务器 ([^\]]+)\]", b)
            if m:
                hosts.add(m.group(1).strip())
        elif b.startswith("[>> 发给服务器]"):
            out["requests"].append(b[len("[>> 发给服务器]"):].lstrip())
        elif b.startswith("[<< 服务器返回]"):
            out["responses"].append(b[len("[<< 服务器返回]"):].lstrip())

    sig_seen = set()
    for r in out["responses"]:
        for m in re.finditer(
                r'"([A-Za-z_][A-Za-z0-9_]{0,30})"\s*:\s*"([^"]{6,200})"', r):
            k, v = m.group(1), m.group(2)
            if k.lower() in _SIG_KEYS and v not in sig_seen:
                sig_seen.add(v)
                out["signatures"].append({"field": k, "value": v})
        # 响应体里的纯文本签名（无引号场景）
        for m in re.finditer(r"(?:sign|sig|token)[=:]\s*([A-Fa-f0-9]{16,64})", r, re.I):
            v = m.group(1)
            if v not in sig_seen:
                sig_seen.add(v)
                out["signatures"].append({"field": "raw", "value": v})

    card_seen = set()
    for req in out["requests"]:
        body = req.split("\r\n\r\n", 1)[-1] if "\r\n\r\n" in req else req
        for k in ("code", "card", "card_key", "kami", "key", "激活码", "卡密"):
            for m in re.finditer(r"(?:^|&)" + re.escape(k) + r"=([^&\s]{1,64})", body):
                v = m.group(1)
                if v and v not in card_seen:
                    card_seen.add(v)
                    out["cards"].append({"field": k, "value": v})
        # JSON body
        for m in re.finditer(r'"' + k + r'"\s*:\s*"([^"]{1,64})"', body):
            v = m.group(1)
            if v and v not in card_seen:
                card_seen.add(v)
                out["cards"].append({"field": k, "value": v})

    out["hosts"] = sorted(hosts)
    out["ok"] = bool(out["requests"] or out["responses"])
    if not out["ok"]:
        out["error"] = "抓包文件里没有流量记录"
    return out


def render_capture(rep: dict) -> str:
    if not rep.get("ok"):
        return "抓包解析失败：" + rep.get("error", "")
    L = ["抓包结果", "=" * 46,
         "来源：%s" % rep["file"],
         "真实服务器：%s" % (", ".join(rep["hosts"]) or "（未记录到）"),
         "请求 %d 条 ｜ 响应 %d 条 ｜ 签名 %d 个 ｜ 卡密字段 %d 个"
         % (len(rep["requests"]), len(rep["responses"]),
            len(rep["signatures"]), len(rep["cards"])), ""]
    if rep["signatures"]:
        L.append("【真签名】")
        for s in rep["signatures"][:20]:
            L.append("  %-14s %s" % (s["field"], s["value"]))
        L.append("")
    if rep["cards"]:
        L.append("【请求里的卡密/凭证字段】")
        for c in rep["cards"][:20]:
            L.append("  %-14s %s" % (c["field"], c["value"]))
        L.append("")
    if rep["requests"]:
        L.append("【请求样本】")
        L.append(rep["requests"][0][:800])
        L.append("")
    if rep["responses"]:
        L.append("【响应样本】")
        L.append(rep["responses"][-1][:800])
    return "\n".join(L)


# --------------------------------------------------------------------------
# 运行包
# --------------------------------------------------------------------------
@dataclass
class Bundle:
    ok: bool = False
    dir: str = ""
    files: list[str] = field(default_factory=list)
    error: str = ""
    note: str = ""

    def text(self) -> str:
        if not self.ok:
            return "✗ 假包包生成失败：" + self.error
        return "✓ 假包包已生成（%d 个文件）\n" % len(self.files) + \
               "\n".join("  " + f for f in self.files) + "\n  " + self.note


def build_bundle(target: str | Path, out_dir: str | Path, *,
                 port: int = DEFAULT_PORT,
                 mode: str = "proxy",
                 mock_json: dict | None = None,
                 cap_path: str = DEFAULT_CAP,
                 launch: str = "") -> Bundle:
    B = Bundle()
    src = Path(target)
    out = Path(out_dir)
    if not src.is_file():
        B.error = "目标不存在"
        return B
    out.mkdir(parents=True, exist_ok=True)

    js = json.dumps(mock_json or DEFAULT_JSON, ensure_ascii=False, separators=(",", ":"))
    c_text = (C_TEMPLATE
              .replace("@@PORT@@", str(port))
              .replace("@@MODE@@", "1" if mode == "proxy" else "0")
              .replace("@@REWRITE@@", "1" if mode == "proxy" else "0")
              .replace("@@JSON@@", json.dumps(js))
              .replace("@@CAP@@", cap_path))

    c_path = out / "rf_hook.c"
    c_path.write_text(c_text, encoding="utf-8")
    B.files.append(c_path.name)

    so_path = out / "rf_hook.so"
    ok, msg = compile_hook(c_path, so_path)
    if not ok:
        B.error = msg
        return B
    B.files.append("%s (%s)" % (so_path.name, msg))

    conf = out / "rf_hook.conf"
    conf.write_text("port=%d\nmode=%s\nrewrite=%d\ncap=%s\njson=%s\n"
                    % (port, mode, 1 if mode == "proxy" else 0, cap_path, js),
                    encoding="utf-8")
    B.files.append(conf.name)

    tgt = out / src.name
    if not tgt.exists():
        shutil.copy2(src, tgt)
    B.files.append(tgt.name)

    run = out / "run.sh"
    run.write_text(
        "#!/system/bin/sh\n"
        "# %s\n"
        'DIR="$(cd "$(dirname "$0")" && pwd)"\n'
        'export LD_PRELOAD="$DIR/rf_hook.so"\n'
        'export RF_HIJACK_CONF="$DIR/rf_hook.conf"\n'
        'CAP="%s"\n'
        'echo "[rf] 模式=%s 端口=%d"\n'
        'echo "[rf] 抓包文件：$CAP"\n'
        'cd "$DIR"\n'
        '%s\n'
        'echo ""\n'
        'echo "[rf] 已退出。抓包在：$CAP"\n'
        % ("透明代理：请求转发真服务器，全程录像" if mode == "proxy"
           else "本地 mock：不外连，直接回成功",
           cap_path, mode, port,
           launch or ('sh "./%s" "$@"' % src.name)),
        encoding="utf-8", newline="\n")
    B.files.append(run.name)

    readme = out / "使用说明.txt"
    readme.write_text(
        "ReverseForge 网络层运行包\n"
        "==============================\n\n"
        "模式：%s\n"
        "端口：%d\n"
        "抓包：%s\n\n"
        "%s\n\n"
        "手机端：\n"
        "  chmod +x run.sh\n"
        "  sh run.sh\n\n"
        "跑完后把抓包文件拿回来，用这条命令解析：\n"
        "  python -m rf.fakepacket.capture <抓包文件>\n"
        "能直接看到：真实服务器地址、请求原文、响应原文、签名、卡密字段。\n\n"
        "改返回内容：编辑 rf_hook.conf 的 json= 行（仅 mock 模式或回落时生效）\n"
        "改成纯本地不联网：把 rf_hook.conf 的 mode 改成 mock\n"
        % ("透明代理（转发真服务器，录真签名真数据）" if mode == "proxy"
           else "本地 mock（不外连）",
           port, cap_path,
           "proxy 模式：请求原样发给真服务器，响应原样带回，"
           "中间不篡改；真服务器连不上时自动回落 mock，保证程序能跑完。"
           if mode == "proxy" else
           "mock 模式：所有外连被拦在本地，任何请求都返回成功 JSON。"),
        encoding="utf-8")
    B.files.append(readme.name)

    B.ok = True
    B.dir = str(out)
    B.note = ("拷到手机后：chmod +x run.sh && sh run.sh；"
              + ("跑完取回抓包看真签名" if mode == "proxy" else "本地过验证"))
    return B


# --------------------------------------------------------------------------
# 自检
# --------------------------------------------------------------------------
def selftest() -> dict:
    import tempfile
    r = {"ndk": "", "compile": False, "so_arch": "", "symbols": [], "error": ""}
    tool = find_ndk()
    if not tool:
        r["error"] = "未找到 NDK"
        return r
    r["ndk"] = str(tool[0])
    tmp = Path(tempfile.mkdtemp(prefix="rf_hijack_"))
    c = tmp / "t.c"
    c.write_text((C_TEMPLATE
                  .replace("@@PORT@@", str(DEFAULT_PORT))
                  .replace("@@MODE@@", "1")
                  .replace("@@REWRITE@@", "1")
                  .replace("@@JSON@@", json.dumps(json.dumps(DEFAULT_JSON)))
                  .replace("@@CAP@@", DEFAULT_CAP)), encoding="utf-8")
    so = tmp / "t.so"
    ok, msg = compile_hook(c, so, tool)
    r["compile"] = ok
    if ok:
        r["so_arch"] = "AArch64 / %d B" % so.stat().st_size
        try:
            from elftools.elf.elffile import ELFFile
            with so.open("rb") as f:
                e = ELFFile(f)
                syms = set()
                for s in e.iter_sections():
                    if s["sh_type"] == "SHT_DYNSYM":
                        for x in s.iter_symbols():
                            if x.name and x["st_info"]["type"] == "STT_FUNC":
                                syms.add(x.name)
            r["symbols"] = sorted(x for x in syms
                                  if x in ("connect", "getaddrinfo", "gethostbyname"))
        except Exception as e:
            r["error"] = "符号读取失败：%r" % (e,)
    else:
        r["error"] = msg
    try:
        shutil.rmtree(tmp, ignore_errors=True)
    except Exception:
        pass
    return r


if __name__ == "__main__":
    print(json.dumps(selftest(), ensure_ascii=False, indent=2))
