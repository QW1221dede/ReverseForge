# 高危能力联网授权 · 部署说明（2026-11-28）

## 一、已完成什么

按 `docs/LAW_MATRIX.md` 的法条分级，只锁了三类"对外产生实际效果"的能力：

| 能力 ID | 锁什么 | 法律依据 |
|---|---|---|
| `NET_SEND` | 真发包 / 真签名重放（`send=true`） | 刑法 285 条 2 款、286 条；网安法 27 条 |
| `LIVE_HARVEST` | 真机 frida 注入 / 卡密写入 / 设备签名收割 | 刑法 285 条 3 款；网安法 27 条 |
| `DEPLOY_RUN` | 安装补丁 APK / 启动目标应用 / 实施绕过补丁 | 刑法 217/218 条；软保条例 24 条 |

**静态分析、拆包、反编译、解密、扫描、假包方案生成、DRY 预演、离线抓包解析全部照常可用** —— 这是绝大多数功能。

## 二、加密栈（六层混合）

```
scrypt(N=32768, r=8, p=1)      内存硬派生，抗 GPU/ASIC
  → PBKDF2-HMAC-SHA512(60万轮) 二次派生
  → AES-256-GCM                外层认证加密
  → ChaCha20-Poly1305          内层认证加密（不同算法族）
  → HMAC-SHA512                完整性绑定（AAD 含机器指纹）
  → RSA-4096-PSS-SHA512        作者签名（私钥不出你的电脑）
```

关键点：**本地加密模块的解密密钥 = f(作者回签, 机器指纹, nonce)**。
没有作者回签，把本地文件全部逆向也凑不出密钥。PSS 签名带随机 salt 不能当密钥种子，
所以模块密钥改为**从作者私钥确定性派生**，批准时随回签下发（绑定能力+机器）。

## 三、端到端验证结果（已实跑）

```
申请码生成        RFGATE-REQ2-…  268 B（只含能力/指纹/nonce/用途/时间）
HTTP POST         → 作者电脑 127.0.0.1:8811
人工批准 y         → 回签 RFGATE-ACK2-…  1300 B（含模块密钥）
客户端验签         ✓ RSA-4096 PSS-SHA512
会话落盘           ✓ AES-256-GCM 加密，无明文口令
三层解密模块       ✓ NET_SEND 已解密并执行
未授权能力         ✓ LIVE_HARVEST 被拒
错误签名           ✓ 第 3 层 HMAC 校验失败，拒绝
```

## 四、部署步骤（你这边）

### 1. 生成正式密钥（**只做一次，私钥绝不外传**）
```bash
cd E:\ReverseForge
python tools/gate_server.py --init
```
- 私钥：`E:\ReverseForge\rf\secure\gate_private.pem` —— **不要放进发布包、不要提交 git**
- 公钥：`E:\ReverseForge\rf\secure\gate_public.pem` —— 随包分发

> 目前 `rf\secure\gate_public.pem` 是端到端测试的 4096-bit 公钥，配套的测试私钥在
> `tools\_e2e_priv.pem`。**正式发布前请用 `--init --force` 重新生成，再重新封包**。

### 2. 建隧道（你的第三方云，443）
```
cloudflared tunnel --url http://127.0.0.1:8787
```
拿到 `https://xxx.trycloudflare.com` 后测一下：
```
curl https://xxx.trycloudflare.com/gate/ping     # 应返回 {"ok":true,...}
```

### 3. 封包（发布前）
```bash
python tools/gate_server.py --seal --fp <使用者机器指纹>
```
每个使用者机器指纹不同 → **需要按申请者的指纹单独封包后发给他**。
（这是最严格模式；若要通用发布，可改为运行时下发 seal_key 由客户端封包。）

### 4. 启动校验服务
```bash
python tools/gate_server.py --port 8787
```
收到申请时终端会打印中文用途声明，你输入 `y` 批准 / 其它键拒绝，
每条决定写入 `logs\gate_decisions.jsonl`（这是"逐例审阅"的证据留痕）。

### 5. 使用者侧
```python
rf.gate_server('https://你的隧道地址')          # 设置一次
rf.gate_request('NET_SEND')                     # 看中文申请模板
rf.gate_apply('NET_SEND', '中文用途声明')        # 发申请，等批准
rf.gate_status()                                # 查看授权状态
```

## 五、需要你决定的两点

1. **封包模式**：现在最严格（按机器指纹单独封包分发）。若群友多，要不要改成"通用封包 + 运行时下发密钥"？后者方便但要调整架构。
2. **服务端常驻**：要不要把 `gate_server.py` 也挂进开机自启（像机器人那套 silent_boot）？

## 六、改动文件

- 新增 `rf/secure/gate.py`（联网授权核心）
- 新增 `tools/gate_server.py`（作者端服务器）
- 新增 `tools/gated_src/*.py`（三个能力模块明文，发布时不分发）
- 新增 `rf/secure/gated_mods/*.enc.json`（三层加密后的模块）
- 新增 `docs/LAW_MATRIX.md`（法条深度对照）
- 修改 `rf/api.py`（4 个高危入口上锁 + 6 个 gate_* 门面方法）
