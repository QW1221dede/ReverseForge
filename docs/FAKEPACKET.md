# 网络层拦截 · mock / 透明代理

> 卡密闸门在壳里（UPX / VMProtect）时，静态补丁没有切入点。
> 但这类客户端通常自己拼 HTTP 报文，只认服务器回执——
> 那就从网络层入手。**关键是别自欺：本地回个假成功，服务器根本没参与，签名和数据都是空的。**

---

## 一、两种模式，本质区别

| | `mode=mock` | `mode=proxy`（默认） |
|---|---|---|
| 请求 | 拦在本地，不发出去 | **原样转发给真服务器** |
| 响应 | 自己编一个"成功" | **真服务器回什么就带什么** |
| 服务器知道吗 | 完全不知道 | 真的处理了这次请求 |
| 拿得到真签名 | ✗ | ✓（响应里就是真的） |
| 拿得到真数据 | ✗ | ✓（服务器真下发的） |
| 适用 | 只要能启动/跳过验证 | **要真签名、真数据** |

`proxy` 是默认。真服务器连不上（无网 / DNS 挂）时**自动回落 mock**，保证程序不会因为连不上而报错退出。

---

## 二、proxy 怎么知道原来要连哪

难点：`connect()` 被 hook 后，原始目标就丢了。解法是一条自定义协议头：

```
① getaddrinfo 做真实解析 → 把真 IP 交给程序（不劫持解析）
② 程序 connect(真IP:80) → hook 拦下，改连 127.0.0.1:18888
③ 连上后立刻发一行：  RFORIGIN 45.12.34.56:80\n
④ 本地服务端读到这行，用 real_connect 连真服务器
⑤ 双向 relay：客户端的字节往上游送，上游的字节往客户端送
⑥ 每个方向的字节都写进 rf_capture.log
```

`real_connect` 是 `dlsym(RTLD_NEXT, "connect")` 拿的原始指针，
**不会二次触发 hook**，不会死循环。

DNS 解析失败时（无网），`getaddrinfo` 返回 `127.0.0.1:18888`，
`connect` 看到是回环地址就不加 `RFORIGIN`，服务端读不到协议头 → 走 mock 分支。

---

## 三、录下来的就是全部真相

`rf_capture.log` 格式（纯文本，直接能看）：

```
[== 连真实服务器 45.12.34.56:80]
----
[>> 发给服务器] POST /api/login HTTP/1.1
Host: wig.xiaoman.top
Content-Type: application/x-www-form-urlencoded

imei=865123456789012&code=123&api_time=1795811000
----
[<< 服务器返回] HTTP/1.1 200 OK

{"code":20000,"msg":"ok","checktrue":"1","sign":"a1b2c3d4...","expires":"2027-01-01"}
----
```

解析：

```bash
python -m rf.fakepacket.capture rf_capture.log
python -m rf.fakepacket.capture rf_capture.log --json -o 结果.json
```

输出：

```
真实服务器：45.12.34.56:80
请求 1 条 ｜ 响应 1 条 ｜ 签名 1 个 ｜ 卡密字段 1 个

【真签名】
  sign   a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6

【请求里的卡密/凭证字段】
  code   123
```

签名提取覆盖两种写法：JSON 字段（`sign` / `signature` / `token` / `hash` / `md5` …）
和裸文本（`sign=abc123...` 形式）。

---

## 三·五、响应改写：让本地程序也过（关键一环）

只转发还不够。服务器回「卡密无效」，程序接到这个响应照样自己 exit——
**所以代理必须在回给程序之前把失败标志改掉。**

改写是**原地等长替换**，因此 `Content-Length` 完全不用动，不会破坏报文：

| 原样 | 改成 | 说明 |
|---|---|---|
| `"checktrue":"0"` | `"checktrue":"1"` | 等长 1 字节 |
| `"success":false` | `"success":true ` | 5 字节持平，尾随空格 JSON 合法 |
| `"code":40001` | `"code":20000` | 5 位数字 |
| `"checktrue":0` | `"checktrue":1` | 数字形式 |

覆盖的字段：

- 布尔类：`checktrue` / `check_true` / `checkTrue` / `success` / `valid` / `ok` / `result` / `isok` / `pass`
- 数字类：`code` / `status` / `errcode` / `ret`（5 位数字且不是 20000 的一律改成 20000）

**顺序很重要**：先把服务器原始响应整段录进抓包（真签名、真数据都在里面），
**然后**才改写发给程序。所以：

```
抓包文件 = 服务器真实说了什么（真数据、真签名）
程序收到的 = 改写后的通过响应（所以它不会退出）
```

两件事不冲突，各拿各的。

关闭改写：`rf_hook.conf` 里 `rewrite=0`，就变成纯透明转发。

---

## 四、能不能真的骗过服务器

分三种情况，别混：

**① 程序本身带了有效凭证**（内置卡密、改过的设备指纹）
→ proxy 直接就能拿到真数据和真签名，什么都不用改。

**② 服务器因为卡密无效拒绝**
→ 你拿到的是拒绝响应，但这恰恰有价值：里面有服务器的判定字段（`code` / `checktrue` / `msg`），
  据此能看出它到底校验什么。下一步是把请求字段逐个改掉重发，看哪个能让它改口。

**③ 服务器校验严格（签名 + 时间戳 + 设备绑定）**
→ 光改字段没用，签名对不上就拒。这时候要看客户端怎么算签名，
  用 `live.py` 的通道（frida 让程序自己发一次，把 `(明文, 签名)` 配对抓下来）
  或者从壳里把签名算法挖出来。

**这三种的界线是数据决定的，不是猜的**——抓一次就有了。

---

## 五、hook 的三个点

| 符号 | 作用 | 备注 |
|---|---|---|
| `connect()` | 拦外连，转发真目标 | 回环的 80/443 也拦（DNS 失败兜底）；程序自己的本地服务（高端口）放行 |
| `getaddrinfo()` | 真实解析，保留真 IP | 解析失败才退回本地 |
| `gethostbyname()` | 老式解析，真实解析 | bionic 里标 deprecated，需 `visibility(default)+used` 才导出 |

`SIGPIPE` 已忽略（转发时对端先关不会杀进程）；`select` 60 秒超时兜底。

---

## 六、用起来

### 工具箱里（推荐）

「网络层劫持」页 / 脚本 `22_proxy_pack.py`，参数三项就够：

```
target  目标文件（ELF / makeself .sh）
mode    proxy（默认，转发真服务器并改写） / mock（不外连）
port    本地监听端口，默认 18888
```

跑完自动出 `假包包/`，日志里直接告诉你下一步怎么做。

API 对应四个方法（`rf.api`）：

```python
api.hijack_analyze(target)                  # 判断该走静态补丁还是网络层
api.hijack_pack(target, out, mode="proxy")  # 生成运行包（需 NET_SEND 授权）
api.hijack_capture("rf_capture.log")        # 解析抓包，提真签名
api.hijack_replay(log, {"code": "88888888"}, dry_run=True)   # 试改字段
```

### 手机端

```bash
chmod +x run.sh
sh run.sh
```

跑完把抓包取回来：

```bash
adb pull /data/local/tmp/rf_capture.log      # 有 adb
# 或者用 MT 管理器直接拷
```

改模式：`rf_hook.conf` 里 `mode=proxy` / `mode=mock`。
改本地回落响应：同一文件 `json=` 行。
改端口、抓包路径：`port=` / `cap=`。

---

## 七、授权与限制

**授权**：对外生效，纳入 `NET_SEND`。使用者无回签时 `do_fakepacket` 只报方案不产物；
作者本机持 `gate_private.pem` 自动放行。

**限制**：

| 项 | 说明 |
|---|---|
| 明文 HTTP | 走 TLS 的客户端，relay 虽能转发但录到的是密文；要抓明文需另配证书 |
| 静态链接 ELF | `LD_PRELOAD` 无效（本样本动态链 `libc.so`/`libdl.so`，没问题） |
| 自实现 DNS（UDP 53） | `getaddrinfo` hook 不生效，但 `connect` 仍能拦到最终 IP |
| 并发连接 | 串行 accept，单连接处理完再下一个；HTTP 短连接够用 |

---

## 八、工具链

```bash
clang.exe --target=aarch64-linux-android21 --sysroot=<ndk>/sysroot \
          -shared -fPIC -O2 -s -o rf_hook.so rf_hook.c
```

NDK：`D:\android_tools\sdk\ndk\28.2.13676358`
自检：`python -m rf.fakepacket.hijack`（编译 + 符号校验）
