# ReverseForge · 逆锻台

> ## ⚠️ 先读两条
>
> **1. 会被杀软拦，这是预期内的。**
> 本工具用 PyInstaller 打包、内含 hook/注入/跨进程读取等逆向必备能力，与注入类木马的行为特征重合。
> 第一次运行前请把 `%LOCALAPPDATA%\ReverseForge` 和解压目录加入白名单，详见 [SECURITY.md](SECURITY.md)。
>
> **2. 仅限自有或已授权目标。**
> 破解、盗版、未授权获取他人数据、制作外挂或恶意软件 —— 一律禁止。
> 完整条款见 [DISCLAIMER.md](DISCLAIMER.md)，下载即视为同意。

---

## English / 英文简介

**ReverseForge** is a local-first reverse engineering & security analysis workbench for Windows.
It wraps scattered CLI tools (jadx / apktool / rizin / Ghidra / 7-Zip / adb) into one GUI driven
by **scripts** — one line like `rf.apk_unpack(path)` runs unpack + decompile, with annotated output.

- **Auth-checkpoint scanning** along the Application/Activity startup chain: license keys, activation, signature & environment checks — with evidence, confidence, and "patch this line" suggestions.
- **Rollbackable patching**: edit smali -> validate -> rebuild -> sign -> roundtrip verify; any failure reverts the whole batch.
- **Not just APK**: EXE/DLL, native .so, scripts and data files can be identified, segmented and auto-decrypted (XOR/RC4/AES/TEA/XXTEA/OpenSSL Salted, known-plaintext attack).
- **Full-auto pipeline** tab: unpack -> decrypt -> remove pre-run license checks -> rebuild & sign -> drop result to Desktop.
- **42 code blocks + resident terminal + local HTTP API** for AI orchestration.

> **English notice**: AV engines may flag it (PyInstaller + injection-style capabilities) — whitelist `%LOCALAPPDATA%\ReverseForge` first, see [SECURITY.md](SECURITY.md). Use **only** on software you own or are explicitly authorized to test; cracking, piracy and malware-making are strictly forbidden — see [DISCLAIMER.md](DISCLAIMER.md).

**License: GNU AGPL-3.0 with additional terms — commercial use is prohibited.** Any derivative (including running it as a network service) must remain AGPL-3.0 open-source with these terms preserved.

---

桌面端逆向工作台。把散落的一堆命令行工具（jadx / apktool / rizin / Ghidra / 7-Zip / adb）
收进一个界面，并用**脚本**驱动全部流程 —— 脚本里一行 `rf.apk_unpack(path)` 就能跑完
解包 + 反编译，输出带中文注释的源码。

在此之上又加了几层：

* **启动前校验识别** —— 沿 Application/Activity 启动链找出卡密、授权、签名、环境判定，
  给证据、置信度和"改哪一行"的建议；
* **可回滚补丁** —— 改 smali → 语法校验 → 重建 → 签名 → 回读确认，任何一步失败整批还原；
* **不限 APK** —— EXE/DLL、.so、脚本、数据文件都能拖进来识别、分段、试解密；
* **42 块代码积木** —— 按难度分类，每块标作用/输入/产出/风险，可单跑、可拼装、自动语法校验；
* **代码终端** —— 常驻进程，变量跨次保留，积木送进去改完可存回。

```
┌──────────────────────────────────────────────────────────────┐
│ ReverseForge 逆锻台            工具 17/17  [工作区] [工具链] │
├───────────────┬──────────────────────────────────────────────┤
│ 脚本库        │  终端 │ 产物 │ 报告                            │
│  拆解 APK     │  ── [ 40%] 源码反编译 · jadx -d              │
│  分析 so      │  ✓ 源码反编译完成：75 个 .java                │
│  加密解密     │  ✓ 注释 75 类 / 633 方法                     │
│  批量画像     │  [====进度====] 100%                         │
│  Manifest 审计│                                              │
│ ─────────     │                                              │
│ 参数          │                                              │
│  目标 [....]  │                                              │
│  [ 开 始 ]    │                                              │
└───────────────┴──────────────────────────────────────────────┘
```

---

## 零、三种用法（先看这个）

### 1. 拖进去（最省事）

界面左上是**投放区**：把文件或整个文件夹拖进那个方块（也可以点一下选），
它会自动识别类型、大小并排队。然后：

* 点 **分析** → 直接出画像（类型 / 明文头 / 密文 / 可解性）
* 去 **对话** 页说人话："这几个文件是什么，能解密吗"
* 或者选个脚本点 **开始** —— **所有路径参数都从这里取**

**路径输入只有一个入口。** 以前脚本参数区里有 `apk` / `target` / `path` /
`smali_dir` 好几个路径框，名字乱、经常空着，脚本直接跑不起来。
现在它们全部合并成一行「目标 → 投放区 → xxx」，不再让你填任何路径：

| 脚本参数原来叫 | 现在的值 |
|---|---|
| `apk` / `target` / `path` / `src` | 投放区第 1 个文件 |
| `smali_dir` / 目录类参数 | 投放区文件所在目录（多文件同目录时取共同父目录） |
| 全部投放文件 | 自动注入 `args["files"]`，脚本可用 `args.get("files")` 拿全量 |

投放区空着点「开始」会明确提示"先把文件或文件夹拖到左上角投放区"，
不会让你对着一个空框猜该填什么。

拖拽不可用时（没装 `tkinterdnd2`）方块会明说"拖拽需要 tkinterdnd2"，
并且照样可以点开文件选择框 —— 不会出现"看起来能拖但没反应"。

### 2. 说一句话（AI 编排）

「对话」页输入：

```
这几个文件是什么，能解密就把明文解出来
把脚本里的卡密/授权校验找出来
给这个 APK 的启动校验打个补丁（先预演）
```

工具会把这句话翻成**步骤序列**再真跑，过程逐行打在对话里：

```
【意图】解密与分段（关键词：解密、是什么）
【规划】规则引擎 · 3 个步骤
  1. file_type      先认类型：决定后面用哪套分析器
  2. segments       分段：找明文头/密文分界，顺手捞密钥
  3. decrypt_auto   自动试解（编码/压缩/XOR/RC4/AES/TEA/OpenSSL）
── 1/1 mixed.bin
   类型：明文头 + 密文（混合文件） · 熵 7.74 · 可信 75%
   明暗分界：明文 48B + 密文 700B（可信 96%）
   头部密钥：pass1234
   解密：RC4（'pass1234'）· 偏移 48（得分 100）
```

默认是**规则引擎**：离线、零延迟、结果可复现。只有当你在
`%LOCALAPPDATA%\ReverseForge\settings.json` 里配了 OpenAI 兼容端点，
才会改走 LLM 规划；失败自动退回规则，并在结果里写明用的是哪个引擎。

```json
{"llm": {"base_url": "https://api.xxx.com/v1",
         "api_key": "sk-...", "model": "gpt-4o-mini"}}
```

### 3. 让 AI 直接调（HTTP API）

「对话」页右上角点 **本地 API**，或命令行：

```bash
python run.py --api               # 只读
python run.py --api --api-write   # 开放写操作（打补丁/重建）
```

只监听 `127.0.0.1`，必须带 token（启动时打印并复制到剪贴板，
同时写到 `%LOCALAPPDATA%\ReverseForge\api_token.txt`）。

| 接口 | 用途 |
|---|---|
| `GET /health` | 存活与版本（无需 token） |
| `GET /tools` | 13 个工具的机器可读清单 + OpenAI function-calling 定义 |
| `POST /call` | `{"tool":"file_type","args":{"path":"D:/a.bin"}}` |
| `POST /analyze` | `{"paths":[...],"task":"能解密吗"}` → 计划 + 完整报告 |

```bash
curl -H "X-RF-Token: <token>" -H "Content-Type: application/json" \
     -d '{"tool":"decrypt_auto","args":{"target":"D:/secret.bin"}}' \
     http://127.0.0.1:8765/call
```

**写操作默认关闭**（`patch_apply` / `auth_apply` 返回 403），
要显式用 `--api-write` 或 `ApiServer(allow_write=True)` 才开放 ——
避免 AI 一上来就把文件改了。

---

## 一、启动

### 第一种：开箱即用（推荐，给不想折腾环境的人）

```
1) 解压 zip 到任意目录（路径别带奇怪的符号）
2) 双击 install.bat        ← 会自动弹 UAC 要管理员权限
3) 等它跑完（首次约 3-8 分钟，取决于网速）
4) 双击桌面上的「ReverseForge 逆锻台」快捷方式
```

安装脚本会自动在桌面建快捷方式（图标指向 exe，工作目录设为 exe 所在目录）。
如果你已经装过了、想补一个：程序菜单「工具 → 创建桌面快捷方式」，
或者 `python -c "from rf.tools.shortcut import create_desktop_shortcut; print(create_desktop_shortcut())"`。

`install.bat` 做的事（全部自动，装到 `%LOCALAPPDATA%\ReverseForge\vendor`）：

| 组件 | 用途 | 大小 |
|---|---|---|
| Temurin JDK 17 | apktool / apksigner 依赖 JVM | ~180MB |
| apktool 2.9.3 | APK 解包 / 重打包 | 15MB |
| Android cmdline-tools → build-tools + platform-tools | aapt2 / apksigner / zipalign / adb | ~100MB |
| 7zr | 压缩包 / 固件镜像 | 0.6MB |
| jadx（加 `-WithJadx` 才装） | DEX → Java 源码 | 30MB |

**装完之后不需要系统里再装 Java、Android SDK、Python。** 程序优先用 vendor 里的工具，
系统里有没有都不影响。整个目录连同 vendor 拷到别的机器，直接能用（绿色版）。

其他安装方式：

```powershell
.\install.ps1 -DryRun          # 只检查不下载，看清会装什么
.\install.ps1 -WithJadx        # 顺带装 jadx
.\install.ps1 -Proxy http://127.0.0.1:7890   # 走代理
.\install.ps1                  # 默认（已装的会跳过，可重复运行）
```

断网/内网：把官网的 zip/jar 下到本地目录，用 `-Offline D:\pkgs`，脚本会从本地装（说明在 `install.ps1` 末尾）。
Ghidra 不在默认列表（解压 1.5GB+），需要的人自己下，程序探测到就用。

### 第二种：从源码跑（给开发者和想审计代码的人）

```bash
python run.py                 # 图形界面
python run.py --tools         # 只打印工具链状态（排障）
python run.py --script scripts/01_apk_full.py apk=D:\x.apk   # 命令行跑脚本
python run.py --selfcheck     # 环境自检
```

要求：Python 3.9+（本机用 3.12），Windows 自带 tkinter 即可，**无第三方 GUI 依赖**。

打包成 exe / 打发布包：

```bash
python build.py              # → dist/ReverseForge/ReverseForge.exe
python release.py            # → release/ReverseForge_v0.1.0_win64.zip + SHA256
```

---

## 二、它集成了什么

工具不写死路径，启动时自动探测；探测不到的可以在「工具链」窗口里手动指定。

| 分类 | 工具 | 用途 |
|---|---|---|
| Android | **jadx** 1.5.6 | DEX → Java 源码，支持去混淆 |
| Android | **Apktool** 3.0.3 | 解资源、Manifest 反编译、smali |
| Android | aapt2 / apksigner / adb | 包信息、签名校验、设备拉包 |
| Native | **rizin** 0.9.1 | 反汇编、函数识别、交叉引用 |
| Native | **Ghidra** 12.2 | 反编译出 C 伪代码（需 JDK21） |
| Archive | 7-Zip 26.04 | 通用解包、加密包结构 |
| 自研 | DEX/ELF/PE 解析器 | 纯 Python，毫秒级，不依赖外部工具 |
| 自研 | 加密识别 / 字符串提取 / 哈希熵 | 判断"到底是不是加密" |
| 自研 | **中文注释器** | 给反编译源码插方法级中文注释 + 风险标注 |

工具版本探测结果会缓存，第二次启动不重复拉起 JVM。

---

## 三、十四个内置脚本

| 脚本 | 干什么 | 典型耗时 |
|---|---|---|
| `01_apk_full.py` | 画像 → 解包 → 反编译 → 中文注释 → 密钥扫描 → 报告 | 5.4MB 包约 35 秒 |
| `02_native.py` | 一批 so/dll：结构、加壳判定、危险导入、字符串分类 | 秒级 |
| `03_crypto.py` | 加密文件识别 → 熵判定 → ZIP 弱口令 → 单字节 XOR | 秒级 |
| `04_batch_apk.py` | 一批 APK 只画像不拆包，出汇总清单 | 每包 0.2 秒 |
| `05_manifest_audit.py` | Manifest 审计：可调试、允许备份、明文流量、导出组件 | 秒级 |
| `06_ghidra.py` | Ghidra 完整分析，每函数导出一个 .c | 分钟到小时 |
| `07_core_deps.py` | **建跨文件调用图 → 找校验点 → 回溯入口链路**（可选顺带全量注释） | 75 个类约 3 秒 |
| `08_patch_scan.py` | 启动校验扫描：证据 + 置信度 + 补丁建议 + Frida 脚本 | 151 个 smali 约 0.5 秒 |
| `09_patch_apply.py` | 预演 → 应用 → 重建 → 签名 → 验签 → 回读（全程可回滚） | 小包约 8 秒 |
| `10_snippet_build.py` | 从积木库挑一组拼成可运行脚本（自动排序 + 校验） | 秒级 |
| `11_crypto_test.py` | 本机强加密实测：AES-GCM / ChaCha20 / HMAC / PBKDF2 | 约 4 秒 |
| `12_any_file.py` | **任意文件**画像：类型 → 分段（明文头/密文）→ 乱码诊断 → 校验点 | 秒级 |
| `13_decrypt_auto.py` | **自动解密**：编码/压缩/XOR/RC4/AES/TEA/XXTEA/OpenSSL 全撞 | 默认 15 秒预算 |
| `14_auth_any.py` | **任意类型校验点**：脚本/EXE/DLL/class/smali，给行号与改法 | 秒级 |
| `15_auth_bypass.py` | **一键绕过卡密**：识别→替换→重建→四关验证，出可运行成品 | APK 约 15 秒 |

---

## 四、不止 APK：任意文件

真实目标里校验逻辑不全在 APK 里。Windows 上多半是 `EXE/DLL`，客户端是 `.so`，
小工具干脆就是 `.py/.js/.lua/.bat`，数据文件则往往本身就是加密的。

`rf.file_type(path)` / `rf.scan_any(dir)` 按四步判定：

1. **魔数**（最硬）——PE/ELF/Mach-O/class/DEX/APK/ZIP/7z/PDF/PNG…
2. **容器结构** —— PE 的 `e_lfanew` 指针、ELF 的 `e_type`、ZIP 中央目录里的特征文件名
3. **扩展名 + 内容特征** —— 只用于脚本（扩展名谁都能改）
4. **熵 + 可打印率** —— 前三条都不中时的兜底，>7.5 判疑似加密

能分出来的类型：

| 类别 | 识别内容 |
|---|---|
| 本地程序 | PE（EXE/DLL/.NET）、ELF（可执行/.so/PIE）、Mach-O、WASM |
| 安卓 | APK/AAB、DEX/CompactDEX、boot 镜像、sparse |
| Java | class（带版本号）、JAR |
| 脚本 | Python/JS/Lua/Shell/BAT/PowerShell/VBS/AutoIt/AHK/PHP/Ruby/Perl + pyc/luac |
| 容器 | ZIP/7z/RAR/gzip/bzip2/xz/zstd/LZMA |
| 密文 | 裸密文、OpenSSL `Salted__`、**明文头+密文混合** |

PE 还额外判 .NET（读 CLR 数据目录）和常见壳（`UPX0`/`.vmp0`/`.themida` 等节名）；
ELF 报架构与类型。判不出来的老实写"未知二进制"，不硬塞一个类型。

**混合文件**是最常遇到的一类：前几行配置，后面整段密文。
`rf.segments(path)` 从文件开头按字节量明文前缀，再验证后面全是高熵，
把分界精确到字节（80B / 48B 这种小头也能抓到，不会因为比熵窗口小就漏掉）。
顺手把头部里的 `key=` / `iv=` / 长 hex 捞出来当候选密钥。

---

## 五、自动解密：能撞的全撞

`rf.decrypt_auto(path)` 按"便宜的先来"排序，全试一遍：

| 顺序 | 算法 | 说明 |
|---|---|---|
| 1 | Base64/32/85/Hex、zlib/gzip/bz2/xz | 大量"加密"其实只是编码或压缩，最多剥三层 |
| 2 | 单字节 XOR | 256 种全试，用英文字频打分 |
| 3 | 循环密钥 XOR | 汉明距离猜密钥长度（含所有因子），逐列频率分析求密钥 |
| 4 | 密钥 XOR | 候选密钥字符串直接当 key |
| 5 | RC4 | 含 `drop=768` 变体 |
| 6 | TEA / XTEA / XXTEA | 16 字节密钥，XXTEA 自动剥长度头 |
| 7 | AES | ECB/CBC/CFB/OFB/CTR × 候选密钥 × 候选 IV，含"IV 前置在密文头部"布局 |
| 8 | OpenSSL | `Salted__` 头 + 口令（EVP_BytesToKey/MD5），真实文件里最常见 |
| 9 | 偏移扫描 | 前 64 字节逐个当起点（RC4/AES 对起点极敏感） |

候选密钥来自：明文头、文件里的 `key="..."` 常量、配置、独立长 hex/base64、弱口令表。
每段密钥还会派生出「原文补齐 / MD5 / SHA256 截断 / hex 解码 / base64 解码」多种形态。

**已知明文攻击（确定性，不靠猜）**

暴力试解有随机性：猜密钥长度、按列做频率分析，都可能差几位。但真实文件有个确定的弱点——
**明文格式是已知的**：JSON 一定以 `{` 开头，ZIP 一定以 `PK\x03\x04` 开头。于是：

```
cipher[i] = plain[i] ^ key[i mod p]
⇒ key[i mod p] = cipher[i] ^ plain[i]
```

拿到密钥流片段，找最小周期，密钥就到手了，不需要猜。实现要点（都踩过）：

* **验证必须剔掉 crib 覆盖的那一段**。用 crib 反推的密钥，当然能让 crib 出现在那个位置——
  拿它当验证等于循环论证，第一版所有结果都是 100 分。
  现在的判据是"**crib 之外**的部分也得像人话"。
* 片段 ≤4 字节时不推断周期，只当作完整密钥试一把；否则随便一个 4 字节都能自洽。

实测边界（如实写在自测里）：

| 情况 | 结果 |
|---|---|
| 2 / 5 字节密钥，靠 3–7 字节 crib | 直接攻破 |
| 12 字节密钥，只有默认短 crib | **不谎报**（0 个候选） |
| 12 字节密钥，用户给出 20 字节已知明文 | 攻破，密钥完整还原 |
| 同一密钥流加密两段明文 | `c1^c2` 上 crib-drag 能读出对方片段 |

AES/RC4 这类真加密不受影响：它们的密钥流不重复，crib 只能验证猜没猜对，
不能反推密钥。这一点是数学限制，不是实现偷懒。

**怎么判"解对了"**——两把尺子叠加，不靠感觉：

* 命中标准文件头：ZIP/MZ/ELF/PDF/PNG 这类多字节签名 → 直接判成功
* 文本可读性：中文常用字比例、英文双字母组合频率、元音比例、分词边界

`{` `[` `<` 这类单字节"弱魔数"必须先确认文本可读才加分，
否则随机垃圾首字节撞上 `{` 就会被报成 JSON（这个坑踩过，自测里专门有一条守着）。

实测（`tests/selftest_decrypt.py`，12 组真加密样本）：

| 场景 | 结果 |
|---|---|
| Base64 / 双层 Base64 / Hex / zlib | 全部解出 |
| 单字节 XOR | 解出（得分 100） |
| 循环密钥 XOR（5 字节，密钥未提示） | 解出（先猜 20 字节伪密钥，缩到 5 字节才对） |
| 明文头里写 key 的 XOR / RC4 | 解出 |
| AES-256-CBC（IV=0 / IV 前置 / 头里写 key+iv） | 全部解出 |
| AES-256-ECB | 解出 |
| OpenSSL Salted（口令 123456） | 解出 |
| 明文头 + RC4 密文（混合文件） | 分界 48B 精确命中，解出 |
| XXTEA | 解出 |
| **无密钥的 AES / 真随机密文** | **如实报"解不出来"，不谎报** |

诚实边界：AES-256 没有密钥就是解不开，这是数学不是努力问题。
这时正确的下一步是"从程序里找解密函数"，而不是继续加大暴力。

---

## 六、三种"看不懂"，不是一回事

打开一个文件看到的东西，基本就三种，病因完全不同：

| 看到的样子 | 真实原因 | 处理 |
|---|---|---|
| **菱形问号 `�`** | U+FFFD 替换字符 —— 那段字节不是合法 UTF-8 | 换编码重解；换不出来就说明还是密文 |
| **方块里一个问号 `□?`** | 字体里没有这个字形。大量出现=**私有区字符（U+E000+）= 字体加密** | 不是 AES；要拿字体文件做字模比对，纯文本层面无法还原 |
| **一片乱码**（锟斤拷 / 烫烫烫 / é–æ–‡） | 编码链错位：GBK 当 UTF-8 解、UTF-8 当 Latin-1 解 | **可逆**，自动试反向链并修复 |

`rf.garble(path)` 输出诊断书：中文占比、替换字符率、控制字符率、私有区率、
命中的乱码片段、高频私有区码位，以及修好之后的正文。

修复顺序上有个细节：**必须先试修复，再判"二进制"**。
UTF-8 字节被 Latin-1 解出来时，`0x80–0x9F` 会变成 C1 控制字符，
控制字符占比很高——要是先判二进制，就永远走不到修复那一步（这个坑自测抓过一次）。

评分器也重写过一版：最初给"全部可打印"的乱码打了 73 分，
现在主指标换成英文双字母组合频率和中文常用字比例，
随机垃圾稳定落在 20 分以下，正常中英文/JSON 稳定 90+。

---

## 七、自己写脚本

脚本就是 `scripts/` 下的 `.py`。运行时自动注入 `rf`（工具门面）和参数变量。

```python
# @name  我自己的流程
# @desc  一句话说明
# @param apk 目标 APK [file]

rf.note("开始")
info = rf.apk_info(apk)
res  = rf.apk_unpack(apk)
if res.sources_dir:
    rf.annotate(res.sources_dir)          # 中文注释
    rf.keys(res.apktool_path or res.sources_dir)
rf.report("我的报告", {"包名": info.package})
```

**可用 API**（详见程序内「帮助 → 脚本写法」）：

```
rf.log / rf.note / rf.step          日志与进度
rf.apk_info / rf.apk_unpack         APK 画像与拆解
rf.dex / rf.elf / rf.pe             DEX / ELF / PE 解析
rf.disasm / rf.functions            rizin 反汇编
rf.ghidra_decompile                 Ghidra 伪代码
rf.identify / rf.zip_password / rf.xor / rf.keys   加密相关
rf.strings / rf.annotate            字符串与注释
rf.patch_scan / rf.patch_plan       启动校验识别 → 补丁方案
rf.patch_apply / rf.patch_rebuild   事务化应用 → 重建签名验签
rf.replace_strings                  替换写死的卡密/口令常量
rf.patch_rollback / rf.frida        回滚 / 运行时覆盖
rf.validate / rf.validate_tree      语法校验（py/smali/java/json/xml）
rf.snippets / rf.snippet / rf.compose   代码积木与拼装
rf.file_type / rf.scan_any          任意文件识别与目录分类
rf.segments / rf.garble             明暗分段 / 乱码判定与修复
rf.decrypt_auto / rf.decrypt_save   自动试解与结果落盘
rf.keys_any / rf.cipher_profile     候选密钥翻找 / 算法可用性
rf.auth_scan / rf.auth_apply        跨类型校验点 → 改写脚本校验
rf.terminal                         常驻 Python 终端（变量跨次保留）
rf.crypto / rf.crypto_test          本机强加密与实测
rf.run / rf.tool / rf.shell         直接调命令与工具
rf.report / rf.sub / rf.out_dir     报告与产物目录
```

头部 `@param` 会变成界面上的参数表单，支持 `[file] [dir] [bool:true] [int:4] [choice:a,b]`。

---

## 八、启动前校验：怎么做到"精确"

关键词扫一遍谁都会，难的是**不误报**。这里用四路证据交叉，再用调用图确认"是不是启动时就会走到"。

### 覆盖哪些形态（外挂常见的都算）

| 形态 | 怎么扫 | 实测 |
|---|---|---|
| smali（APK 解包目录） | checkpoints：布尔闸门 + 调用图 BFS | 151 个 smali 命中 35 点 |
| **APK / DEX（含被改名成 `.apk.1`）** | 按魔数认，扫 classes*.dex 的 MUTF-8 中文串 | ACE 外挂命中 **11 个卡密点** |
| **Electron（app.asar）** | 解析 asar 文件表，只扫应用自己的 JS，跳过 node_modules 的 license 注释 | 造的 asar 样本命中 |
| PE / ELF（EXE/DLL/.so） | ASCII 串 + **UTF-16LE 中文串**（.NET/WinForms）+ strcmp 导入佐证 | 伪 PE 样本命中 |
| class / JAR | 常量池字符串 | — |
| 脚本（11 种语言） | 逐行比较运算 + 退出路径 | py/js/bat/lua 全过 |

DEX 那一条是补的坑：**中文在 DEX 里是 3 字节 MUTF-8**，
原来只抽 ASCII 的扫描器对它完全瞎 —— 实测 ACE 外挂的 `classes.dex` 里
「卡密」出现 22 次，工具却一个都报不出来。现在按 UTF-8 字节范围抠串，
再用"卡密无效 / 卡密有效期 / 请输入卡密"这类**动作短语**加权，
光一个"授权"（常在免责声明里）不会误报。

同理，Windows 外挂的中文提示常是 UTF-16LE，也单独抽了一遍。

投放区点「分析」走的是**全流程**意图（`file_type → segments → decrypt_auto → auth_scan`）。
之前默认那句提示里有"能解密的解出来"，意图识别把整件事判成只解密，
直接跳过卡密扫描 —— 也修了：多强意图并存时走全流程，而且扫描目标传**那个文件本身**，
不是它所在的目录（扫桌面会撞上损坏 ZIP 报 BadZipFile）。

### 轮椅入口：一个按钮，改完还要证明能跑

「卡密绕过」页是**独立的一键入口**：拖文件 → 点「一键识别 → 替换 → 验证」。
脚本 `15_auth_bypass.py` 做同样的事，也能在命令行或 API 里调。

它不只改，改完还要过四关，报告逐关写结论：

| 关卡 | 怎么验 |
|---|---|
| 结构 | APK：smali 汇编通过、dex 可反编译；脚本：`py_compile` |
| 签名 | `apksigner verify` 通过 |
| 回读 | **重新解包新 APK**，逐条确认补丁 smali 真在 dex 里（不是拿文本去二进制里 find，那样永远"未确认"） |
| 运行 | Python：真起进程试跑看退出码；APK：插了 adb 设备才装并启动 |
| 没设备 | 明写"未验证真机"，**不冒充通过** |

实测 ACE 外挂：`3/4 关通过`（结构 / 签名 / 回读 1/1，运行关未验证——没插手机），产出 `bypass.apk`；
实测带卡密的 Python 脚本：`py_compile` 通过 + 试跑退出码 0，真进主流程打印了 `OK-ENTER-MAIN`。

**资源重建失败的退路**：apktool 3.0.3 用 aapt2 编资源，有些 APK 的 `res` 会让它崩。
但这时 `build/apk/classes*.dex` 已经汇编好了 —— 工具自动改用
**只换 dex、原 APK 资源原样搬过去**，再 zipalign + 签名 + 验签 + 回读。
资源 100% 保持原样，不会因为 aapt2 的脾气把包搞坏。

改之前一律先 `dry_run` 预演；失败整批回滚；备份留在产物目录；原文件不动。

**成品自动放桌面（默认开）**：改完直接复制一份到桌面，命名 `原名_已绕过.apk`，
同名自动加 `_2` / `_3`，绝不覆盖你已有文件；产物目录那份始终保留。
小白不用学 apktool 打包，双击桌面文件就能装。
懂的人把 `to_desktop=false`（GUI 上取消勾选「成品自动放桌面」）即可关掉。

| 证据 | 看什么 | 权重 |
|---|---|---|
| 命名 | 类名/方法名命中 license、card、verify、isVip、isRooted… | 高 |
| 结构 | 方法体是否同时返回 0/1（布尔闸门）、失败分支是否有 finish/exit/throw | 高 |
| 常量 | 代码型字面量：URL、key、`sha256=`、卡密提示（中文 UI 文案会被过滤） | 中 |
| 接口 | MessageDigest / Cipher / getPackageInfo / HTTP / SharedPreferences | 中 |
| 可达 | 从 Application/Activity/Service 的 onCreate/attachBaseContext 出发 BFS ≤4 层 | 加分 |

每条结论都带证据和链路，不是黑盒分数：

```
P001 ✓ 85 授权校验  LicenseManager.verify
  ev: 命名 → 方法名是校验动词；结构 → 同时返回 0/1；常量 → 「8d969eef…」
      可达 → 启动路径上会被调用；可达 → 返回值参与启动阻断
  链: onCreate → verify
  建议: 整个方法强制返回 true（风险 低）

P002 ✓ 77 有效期    LicenseManager.isExpired
  建议: 整个方法强制返回 false（让 isExpired 永远判否）
```

**方向会单独判断**：`isExpired` / `isRooted` / `isDebug` 这类"为真即坏事"的负面闸门，
补丁方向是返回 `false`；`verify` / `isVip` 这类正面闸门才返回 `true`。方向搞反会把程序改得更坏。

**实测**（本机，真实 5.4MB 包，151 个 smali / 1002 个方法）：
0.5 秒扫完，命中 35 个判定点，其中 14 个在启动路径上。
该包是 root 工具、没有卡密逻辑，命中的多是 `canRun` / `selinuxEnforcing` / `accepted`
这类能力判定 —— 报告会把它们标成「通用判定」并注明"可能是功能开关，改前先确认"。

**局限**：加固壳把逻辑放进 so 时看不到；服务端校验改本地只骗过界面；
反射/动态代理会让静态调用图断链。这三种情况报告里都会写明，并可改用 Frida 先验证。

---

## 九、补丁：四种改法 + 事务 + 重建验证

自动生成的建议只有四种，都是"最小改动"：

| 类型 | 做什么 | 适用 |
|---|---|---|
| `method_true` / `method_false` | 保留方法签名，方法体只留 `const/4 v0, 0x1|0x0` + `return v0` | 布尔闸门，最稳 |
| `branch_goto` | 把条件跳转换成 `goto :label` | 强制走某条分支 |
| `invert` | `if-eqz ↔ if-nez`、`if-eq ↔ if-ne` | 双重否定 / 反调试 |
| `const_flag` | 只改返回前的 `const/4 0x0 ↔ 0x1` | 多返回点、想影响面最小 |
| 字符串替换 | 把 `const-string "旧卡密"` 换成新值 | 卡密/默认口令/服务地址写死 |

流程（`rf.patch_apply` 一条命令内部完成）：

```
备份（保留相对路径）
  → 逐条核对原指令（行号漂移时全文件找唯一匹配，多处命中就拒绝）
  → 原子写（.tmp + os.replace）
  → 改后 smali 语法校验（标签/.method 配对/寄存器/指令表）
  → 任一条失败：整批还原，一个字节不留
  → 全通过：写 patch_log.json（改了什么、为什么、前后哈希）
```

方法体短路会保留原来的 `.locals` / `.registers` 声明，寄存器不够时才加一 ——
直接把 `.registers` 改成 2 会让带参方法汇编失败，这是实测踩过的坑。

重建链（`rf.patch_rebuild`）：

```
apktool b → zipalign -p 4 → apksigner sign（本地调试证书）
          → apksigner verify --print-certs
          → 重新解包新 APK，逐条确认补丁文本真的进了 dex
```

样本实测：应用 2 条 → 重建 12KB APK → 验签通过 → 回读 2/2，约 7 秒。

真实包实测（`X-提权者-1.57`，5.4MB / 151 smali）：未打补丁直接重建 → 5.39MB，
`apktool b` + 对齐 + 签名 + 验签共 7.3 秒；`aapt2 dump badging` 仍能读出
`package df.root / versionCode 75 / minSdk 26` 与全部权限 —— 说明资源与 Manifest 没被破坏。

**"保证能跑"到底保证到什么程度**（不吹）：

| 已验证 | 未验证 |
|---|---|
| smali 能汇编回 dex（apktool b 成功） | 真机启动不闪退（本机 `adb devices` 为空） |
| APK zip 结构完整、Manifest 可解析 | 加固包重打包后壳的自校验 |
| 签名有效（apksigner verify 通过） | 服务端权益是否仍然有效 |
| 重新解包能读到补丁（回读 2/2） | 多 dex / split APK 的全部路径 |

有设备时 `09_patch_apply.py` 勾选 `install=true` 会自动装并抓 logcat；
`snippets/runtime.install` 也是同一套。签名变了必须先卸载原版。

---

## 十、代码积木：42 块内置 + 你自己的任意代码块

**先说清楚"积木"是什么**：不是只能选那 42 块预设模板。
积木就是**一段 Python 代码**，内置的 42 块只是 Examples。
你写的代码、终端里调通的代码、从别处复制来的代码，存进去就是一块。

### 新代码块

积木页点 **＋新代码块** → 填编号/名称/分类/难度/作用 → 粘贴任意 Python 代码 →
「校验语法」→「保存到积木库」。它立刻出现在左边的树里，和内置块一样可用。
选中的是内置块时点「编辑」会问你要不要复制一份自己的（内置只读，不会被改坏）。

终端里调通的代码也可以按「存回积木」，一步变成可复用块。

### 拼装工作台（真正的"拼成一串能跑的代码"）

选中多块 → 点 **拼装选中**，打开工作台：

```
┌ 已选块（↑↓ 调顺序）      ┃ 拼装结果（完整可运行代码） ┐
│ ① user.block.one        ┃ # 拼装脚本                  │
│ ② user.block.two   ↓    ┃ try: args                   │
│ ─────────────────        ┃ except NameError: args={…}  │
│ 加入其它块 [Combobox]    ┃ # ── [块一] ──             │
│ 运行参数 k=v, k2=123     ┃ ...                        │
│ [刷新][保存为脚本]       ┃ [送终端并运行]              │
└──────────────────────────┴─────────────────────────────┘
```

* **顺序你自己定**：↑↓ 移动，不是只按依赖自动排（依赖排序作为默认，可改）
* **实时预览**：拼完立刻看到完整代码，`ast.parse` 不过会当场报错，不让你存半截脚本
* **参数兜底**：生成 `try: args / except NameError: args = {...}`。
  在脚本运行器里不会覆盖真参数；直接丢进终端跑也有默认值 —— 这是"拼完就能跑"的关键
* **两条出口**：「保存为脚本」落盘到 scripts/ 并刷新脚本列表；
  「送终端并运行」直接把代码送进代码终端并按 F5

所以它的闭环是：**写块 → 排序 → 拼成一串 → 立刻跑 → 调通 → 存回积木**。

按难度分三级，按用途分八类。每块都写明**作用 / 需要什么 / 产出什么 / 风险**，
加载时自动跑 `ast.parse`，写错了会在界面上标出来，不会静默消失。

| 分类 | 块数 | 内容 |
|---|---|---|
| 入门 | 5 | 日志进度、目标检查、计时、异常保护、产物遍历 |
| 侦察 | 9 | APK 画像、解包+注释、字符串、密钥、so 导入、DEX、哈希清单、**任意文件识别**、**明暗分段** |
| 校验 | 5 | 依赖图、精确扫描、中文报告、配方导出、**任意类型校验点** |
| 补丁 | 8 | 方案预演、应用、重建、回滚、字符串替换、手写恒真、分支反转、**改脚本校验** |
| 解密 | 5 | 识别+XOR/ZIP、AES-GCM 落盘、HMAC 校验、**自动试解**、**密钥翻找** |
| 运行期 | 3 | Frida 覆盖、安装+logcat、改前改后对比 |
| 报告 | 2 | Markdown、JSON |
| 工程 | 5 | 工具链自检、加密自检、积木拼装、**常驻终端** |

拼装按 `depends` 自动排序，缺依赖只提醒、不报错；拼完整体再校验一次，不过就拒绝落盘。

```python
# 只要一块
ops = rf.patch_plan(rf.patch_scan(smali_dir))

# 拼一整条链（自动带上 verify.scan / patch.plan / patch.apply）
rf.compose(["patch.rebuild"], out="scripts/my_patch.py")
```

界面上「积木」页：左树分类 → 右侧看作用/风险/代码 → 校验语法 → 保存为脚本 → 多选拼装。
「补丁」页：①选目录 ②扫描 ③预演 ④应用 ⑤重建，支持多选校验点、回滚、打开产物。

---

## 十一、代码终端：边调边改

「积木」右边多了个 **送终端**，补丁页有 **改法送终端**，代码直接落到「代码终端」页。

它不是一个 `exec()` 包装，而是**常驻子进程**：

* 变量跨次保留 —— 上一块算出来的 `rep` / `ops` / `smali_dir`，下一块接着用，不用重扫 APK
* 最后一行是表达式就打印它的值（和真 REPL 一样）
* `rf` 已注入，写法和脚本完全一致
* `rf.log` / `rf.step` 在终端里改成打到 stdout，积木代码原样丢进来就能看到输出
* 出错显示完整堆栈，界面不崩；超时会杀掉重建（丢状态也不让界面卡住）

调通之后按 **存回积木**，代码直接变成一块用户积木（写到用户目录，不污染内置的），
立刻出现在「积木」页里，下次可以拼进任何脚本。

两种执行方式，按运行形态自动选：

| 运行形态 | 方式 | 差别 |
|---|---|---|
| 源码运行（`python run.py`） | 真子进程 | 变量隔离、超时能强杀、崩了自动重启 |
| 打包 exe | 本进程内持久命名空间 | `rf` 门面完整可用；**死循环不能强杀**，只能关窗口 |

为什么 exe 不用子进程：`sys.executable` 指向 exe 自己（再跑就是又开一个主窗口），
而 exe 目录里没有 `rf` 源码树，子进程里 `from rf.api import make_api` 会失败，
终端就只剩个空壳。两害相权，选了「API 完整」而不是「能强杀」。

```
积木页选一块 → 送终端 → 改 → F5 → 存回积木 → 出现在积木页
补丁页选补丁点 → 改法送终端 → 预演 → 确认改法 → 落盘
```

自测（`tests/gui_repl_test.py`）覆盖：送终端、运行、变量保留（21×2=42）、
出错不崩、存回积木、补丁改法代码可编译。
一个坑记一下：tkinter 的 `after()` 在主循环没跑的时候会抛
`RuntimeError: main thread is not in main loop`，所以这类测试必须 `mainloop()` + `after` 串起来，
用 `while + update()` 是测不出来的。

---

## 十二、本机强加密（真跑，不是占位）

| 算法 | 用途 | 本机实测 |
|---|---|---|
| AES-256-GCM | 默认对称加密 + 认证 | 4MB 纯加密 4.3ms ≈ **925 MB/s**（AES-NI） |
| ChaCha20-Poly1305 | 无 AES 硬件时的等价选择 | 通过 |
| HMAC-SHA256 | 完整性 / 签名比对 | 0.7ms 级 |
| PBKDF2-HMAC-SHA512 | 口令派生（60 万轮） | 约 420ms/次 |
| scrypt | 内存硬派生 | n=2^14 约 200ms |
| SHA-256 | 文件摘要 | 流式，无大小限制 |

每个信封自带算法、KDF 参数、随机 salt/nonce，口令错或密文被改都会因认证标签不匹配而拒绝。
`rf.crypto.seal_json` 用来加密落盘补丁配方、密钥清单；`rf.crypto_test()` 会真跑一遍往返并计时。

---

## 十三、中文注释器怎么工作

**先说它原来差在哪**

第一版是"词对词翻译"：`如果 授权 等于 空 或 不是 授权.是否有效()`。
单看一行还行，连着读就是电报体——因为那是**词的堆叠**，不是句子。
代码本来就是一堆符号拼起来的，逐词替换不会自动变成自然语言。

**现在的做法：先给一句总述，再给证据**

```
// 【verify】 校验
//   总述：这个方法先检查参数是否为空或长度是否合法，再从本地读配置或卡密，
//         然后做摘要或加解密计算，接着取当前时间做时间判定，最后判断是否过期；
//         两条出口分别返回 true/false，是典型的放行与拦截结构。
//   签名：static boolean verify(Context ctx)
//   出口：true / false 两条出口（典型放行/拦截结构）
//   被调用：MainActivity.onCreate、App.attachBaseContext
//   步骤：①length ②readCard ③sha256 ④isExpired
```

总述不是模板套话，是按**方法里真实发生过的调用**（`recv_calls` / `calls` /
`local_types` / 返回表达式）按阶段拼的：判空 → 读存储 → 读文件 → 摘要计算 →
取时间 → 判过期 → 环境检测 → 网络 → 写回 → 日志。
连接词按顺序轮换（先/再/然后/接着/最后），不是一连串顿号。
拼不出来就老实说"没有明显副作用"，不硬编。

下面这几行是**证据链**，用来核对那句总述对不对——毕竟推断可能错，
但签名、出口、调用者是硬的。

**三层信息，从硬到软**：

1. **结构事实**（100% 确定）：类名、父类、接口、字段类型、方法签名、参数、`return` 有几个出口
2. **跨文件依赖**（可靠）：谁调用了谁、被几个类依赖、从入口到这里的调用链
3. **API 与命名推断**（参考）：`Cipher.getInstance` → 加解密；`Runtime.exec` → 执行命令；
   `downloadAndInstall` → 下载并安装；混淆名 `a/b/c` 标「混淆名，无语义」

**注释长什么样**（真实产物，来自 5.4MB 样本）：

```java
// 【类】MainActivity  主活动页
//   包 df.root ｜ 方法 161 ｜ 字段 34 ｜ 2703 行
//   角色：界面页（有生命周期，UI 逻辑）
//   被依赖：12 个类（BootReceiver、WizardActivity…）
//   ⚑ 核心依赖（入度 10）—— 改动波及多处，逆向时优先读这里
//   ⚑ 校验点：环境检测
//       · 字面量「X-Root」→ Root/模拟器/调试器检测
//   校验链：BootReceiver.onReceive() → ExploitRunner.run()

// 【gkiLevel】 gki级别
//   签名：static int gkiLevel()
//   出口：2 条出口：0、Integer.parseInt(...)
//   被调用：DeviceProfile.hasGkiToken、DeviceProfile.report
//   步骤：①截取子串 ②转整数
public static int gkiLevel() {
    int iIndexOf = strKernelRelease.indexOf("android");
    // · 如果 iIndexOf 小于 0 则进入下列分支
    if (iIndexOf < 0) {
        // · 返回 0
        return 0;
    }
    // · 当 i2 小于 字符串内核发布.长度() 且 Character.是否数字(...) 时反复执行
    while (...) { ... }
}
```

**「核心依赖」是怎么判的** —— 两路独立证据，都写进注释：

| 证据 | 含义 | 阈值 |
|---|---|---|
| 校验特征分 | 命名/字面量/API 命中授权、签名、完整性、环境检测、鉴权、有效期 | ≥ 30 判核心 |
| 入度 | 被多少个不同的类依赖 | ≥ 6 判核心 |
| 入口可达 | 从 Activity/Service 能否走到 | 只作标注，不单独判核心 |

**语句级翻译**是这一层最麻烦的部分：`if (mLicense == null || !mLicense.isValid())`
要变成「如果 授权 等于 空 或 不是 授权.是否有效()」。做法是先按运算符优先级拆（`||`→`&&`→比较→算术），
原子部分查词典，查不到就原样保留 —— 保留 `a0` 比编一个中文名更有用。

密度可切：`density="full"` 连 `if/for/try` 都翻；`"lite"` 只加类头与方法头（大工程速览）。

输出是在**原代码行之前插入注释**，一行源码都不改，改完还能编译、能对照。

---

## 十四、能力边界（重要，别指望它做不到的事）

| 你以为 | 实际 |
|---|---|
| "翻译出源码" | jadx 还原的是**等价 Java 源码**。变量名、注释、原始类名在编译时就丢了，混淆过的名字永远回不来，只能推断语义 |
| "拆加密的 APK" | 加固包（梆梆/乐固/爱加密…）的 dex 已被壳加密，直接反编译只看到壳入口。**需要先脱壳**（内存 dump + 修复），这属于另一条流水线 |
| "解密加密文件" | 容器加密（ZIP/RAR/7z）可试弱口令；**整文件 AES 无密钥不可能爆破**，只能从代码里找密钥或动态 hook |
| "Ghidra 出源码" | 出的是 C **伪代码**，类型和变量名都是推断的，逻辑顺序可信、类型可能不准 |
| "中文注释读起来像人写的" | 方法头有一句按真实调用拼出的**总述**（不再是纯词对词），但方法体内部的逐行注释仍是词法级翻译。它解决"这个方法是干嘛的"，不保证每行都通顺 |
| "标了核心就是核心" | 核心判定靠命名+字面量+入度。R8 混淆后名字变 `a/b/c`，命名信号归零，只剩 API 特征，**会漏判**。命中的点要用动态调试复核 |
| 病毒扫描 | 不是杀软。它告诉你「这包能干什么」，不告诉你「它是不是恶意」 |
| "改完一定能跑" | 能证明：smali 汇编通过、签名有效、补丁确实进了 dex。**不能**代替真机启动；没设备时不会假装跑过 |
| "服务端校验也能绕" | 只能改本地判定。权益在服务端，改本地最多骗过界面 |
| "积木拼起来一定能跑" | 语法一定过（不过就拒绝落盘）；变量是否齐备取决于你选了哪几块，拼装头部会列出需要的变量 |
| "解密工具什么都能解" | 只覆盖"作者图省事"的那几样：XOR/RC4/AES/TEA/XXTEA/编码/压缩/OpenSSL。自定义算法、改过 S-box 的 AES、白盒加密，撞不出来就是撞不出来 |
| "字体加密能还原" | 私有区字符只能**判定**（这是字体加密，不是 AES），没有字体文件做字模比对就还原不了，工具不会假装能 |
| "任意文件都能自动改" | 脚本类能给可执行改法并落盘（带备份和语法校验）；**PE/ELF 只能定位到偏移**，改机器码要走补丁引擎或 Ghidra，工具不瞎猜 |
| "终端里跑通就等于修好了" | 终端只是省掉反复起进程的麻烦。它验证的是"这段代码逻辑对"，不是"目标程序能跑" |

---

## 十五、目录

```
reverseforge/
├─ run.py                 入口（GUI / 命令行 / 自检 / --api）
├─ build.py               PyInstaller 打包
├─ release.py             打发布包（zip + SHA256 + 先读我）
├─ install.bat / .ps1     一键安装（管理员，装 JDK/apktool/Android 工具）
├─ DISCLAIMER.md          免责声明
├─ SECURITY.md            杀软误报与白名单
├─ LICENSE                AGPL-3.0 + 禁止商用附加条款
├─ rf/
│  ├─ config.py           路径探测、JDK 选择、用户配置
│  ├─ api.py              脚本门面（脚本里的 rf）
│  ├─ tools/
│  │  ├─ registry.py      工具注册表（17 项，含版本缓存）
│  │  └─ runner.py        统一执行器（流式输出、超时、可终止）
│  ├─ engine/
│  │  ├─ script_runtime.py 脚本执行（元信息、事件、异常翻译）
│  │  └─ repl.py          常驻 Python 终端（变量跨次保留）
│  ├─ server/api_server.py 本地 HTTP API（13 工具，token 鉴权）
│  ├─ agent/orchestrator.py 指令 → 计划 → 调工具（规则优先，可选 LLM）
│  ├─ analysis/
│  │  ├─ apk.py           APK 六步流水线
│  │  ├─ validator.py     语法校验（Python/Smali/Java/JSON/XML）
│  │  ├─ dex.py           DEX 解析 + 加固特征
│  │  ├─ native.py        ELF / PE 解析 + 加壳判定
│  │  ├─ crypto.py        加密识别 / 弱口令 / XOR
│  │  ├─ strings.py       字符串提取与分类
│  │  ├─ filetype.py      任意文件识别与路由（PE/ELF/脚本/密文）
│  │  ├─ segments.py      明暗分段：明文头/密文分界、偏移、头部密钥
│  │  ├─ garble.py        乱码三类判定与编码链修复
│  │  ├─ authscan.py      跨类型校验点（脚本/PE/ELF/class/smali）
│  │  └─ annotate.py      中文注释器
│  ├─ patch/              校验点识别 + 补丁引擎
│  │  ├─ checkpoints.py   启动链 BFS / 四路证据 / 置信度 / Frida
│  │  ├─ smali.py         指令级改写（行号校正 / 原子写）
│  │  └─ engine.py        事务、备份、回滚、重建、签名、回读
│  ├─ decrypt/            解密层
│  │  ├─ ciphers.py       XOR/RC4/AES/DES/ChaCha20/TEA/XXTEA/编码/压缩
│  │  ├─ keys.py          候选密钥提取（头/常量/配置/弱口令）
│  │  ├─ crib.py          已知明文攻击 / 密钥流复用
│  │  └─ auto.py          自动试解编排（打分排序 + 时间预算）
│  ├─ snippets/           42 块代码积木（模型 / 内置 / 拼装）
│  ├─ secure/crypto.py    AES-GCM / ChaCha20 / HMAC / PBKDF2 / scrypt
│  └─ ui/                 界面（theme / app / dropzone，含「卡密绕过」页）
│     └─ dropzone.py      左栏投放区（拖拽 + 队列 + 类型识别）
├─ scripts/               内置脚本 + ghidra/DecompileToFile.py
└─ tests/                 自检与截图
   ├─ build_sample_apk.py 造带卡密校验的样本 APK（aapt2/javac/d8）
   ├─ selftest_patch.py   识别→预演→反向测试→应用→重建→回滚
   ├─ selftest_core.py    加密/语法/积木库
   ├─ selftest_decrypt.py 12 组真加密样本 → 自动试解（含"必须解不出"的反例）
   ├─ selftest_auth.py    脚本/伪 PE 校验点识别 → 自动改 → 语法复查
   ├─ gui_repl_test.py    代码终端：送码/运行/变量保留/出错/存回积木
   └─ gui_patch_test.py   界面扫描与预演联动
```

运行期数据在 `%LOCALAPPDATA%\ReverseForge\`：`workspace/`（每次任务一个目录）、
`logs/`（逐次命令日志）、`scripts/`（自己的脚本）、`tool_versions.json`（版本缓存）。


## 反馈与意见渠道

- **邮箱**：m358685@163.com
- **Gitee**：https://gitee.com/tw-dm/reverse-forge/issues
- **GitHub**：https://github.com/QW1221dede/ReverseForge/issues

> ⚠️ **请用中文交流。本项目的反馈、Issue、邮件一律只接受中文，不接受英文。**
> 用英文提交的 Issue 与邮件可能不会得到回复。
>
> (Feedback in Chinese only — English issues/emails may not be answered.)

## 打赏（可选项，非使用前提）

如果这个工具帮到了你、想支持一下后续更新，欢迎**邮件联系作者**（m358685@163.com）
沟通打赏方式。

> 打赏纯属自愿，**不影响任何功能**，也没有"打赏解锁"一说——本项目全部功能
> 永久免费开源（AGPL-3.0 + 禁止商用附加条款）。请用中文交流。


## 开源协议

本项目采用 **GNU AGPL-3.0** + 附加条款发布：

- **传染性最强**：任何修改、衍生版本（包括作为网络服务运行）都必须以 AGPL-3.0 开源并保留本附加条款；
- **禁止商用**：详见 LICENSE 文末「附加条款」——禁止销售、收费分发、SaaS 收费、嵌入商业产品等任何营利用途；内部安全审计、教学、学术研究等非营利用途不受限；
- 使用本项目即视为你声明用途合法且已获目标授权，详见 [DISCLAIMER.md](DISCLAIMER.md)。
