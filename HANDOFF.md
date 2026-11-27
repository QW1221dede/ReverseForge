# ReverseForge 深度交接文档

> 最后更新：2026-11-27 17:30 · 版本 v0.2.0 · 双平台同步提交 `fbb4013`
> 接手人先读这份，30 分钟内可完整接管项目。

---

## 一、项目是什么

**ReverseForge** 是 Windows 桌面端（Python + tkinter）的逆向工具箱，
面向"拿到一个游戏/App/程序，想看懂它、解开它、改掉它的前置验证"的完整链路：

```
投放任意文件 → 自动识别类型 → 拆包/雕刻 → 解密 → 删前置验证(卡密/签名/复核)
→ 打包重签 → 成品丢桌面
```

- **协议**：AGPL-3.0 + §7 附加条款（禁止商用、传染开源、保留声明）
- **免责**：DISCLAIMER.md 含中文法条（刑法285/286/217/218、著作权法24/53、
  网安法27、反不正当竞争法12、软件保护条例24）+ 主观故意排除声明 + English Summary
- **反馈**：邮箱 m358685@163.com + Gitee/GitHub Issues，**只接受中文**
- **打赏**：仅邮件沟通（开源平台禁止二维码类内容，写了会下架）

### 双平台地址
| 平台 | 地址 | 默认分支 |
|---|---|---|
| Gitee | https://gitee.com/tw-dm/reverse-forge.git | master |
| GitHub | https://github.com/QW1221dede/ReverseForge.git | master（main 同步） |

---

## 二、目录结构（关键部分）

```
reverseforge/
├── run.py                  # 桌面程序入口
├── build.py                # PyInstaller 打包（默认 --onedir，产物 dist/ReverseForge/）
├── release.py              # 打发布 zip + SHA256SUMS（--skip-build 跳过编译）
├── rf/                     # 核心库
│   ├── api.py              # ★ 门面：所有 rf.xxx 能力的实现（约1300行）
│   ├── config.py           # APP_VERSION / USER_ROOT / WORKSPACE_ROOT
│   ├── analysis/
│   │   ├── filetype.py     # ★ 类型识别：MAGIC 表 +40 种、加固检测、_post_fallback
│   │   ├── carve.py        # ★ v12新增：内嵌对象雕刻（zip重建/dex/ELF/压缩流…）
│   │   ├── apk.py / dex.py / native.py       # APK/DEX/PE·ELF 画像
│   │   ├── segments.py     # 明文头/密文体分界 + 头部密钥提取（解密前置）
│   │   ├── authscan.py     # 跨类型校验点扫描（脚本/PE字符串/smali）
│   │   └── ...
│   ├── decrypt/
│   │   ├── auto.py         # ★ salvage()：九大算法自动试解 + v0.2.0 四项深度优化
│   │   ├── keys.py         # 密钥候选挖掘（key=正则/XML/hex/base64）
│   │   ├── crib.py         # 已知明文攻击（XOR 密钥流反推）
│   │   └── ciphers.py      # 算法底座（XOR/RC4/AES/TEA系/编码/压缩/OpenSSL）
│   ├── engine/             # 脚本运行器（@param 注入、SystemExit=正常退出）
│   ├── tools/runner.py / desktop.py     # 子进程 / 丢桌面
│   └── ui/                 # tkinter 界面（9 标签页，含全自动化页）
├── scripts/                # 一键脚本（GUI 各页面实际执行的积木）
│   ├── 01_apk_full.py      # 拆解 APK 全家桶（非 APK 自动转通用拆解）
│   ├── 13_decrypt_auto.py  # 一键解密（任意文件）
│   ├── 15_auth_bypass.py   # 删验证（APK/脚本/PE 分流）
│   ├── 16_full_auto.py     # ★ 全自动化：所有类型通吃（见 §四）
│   ├── 17_unpack_any.py    # 通用拆解（任何文件）
│   └── 18_carve_embedded.py# 内嵌对象雕刻（v12 新增）
├── tests/                  # selftest_core/decrypt/auth/apk/patch/carve + gui_* 
├── release/                # 成品 zip（.gitignore 排除，本地构建）
├── secrets.github.token    # GitHub 令牌（.gitignore 排除，勿提交勿外传）
└── github_ip.txt           # 当前可用的 GitHub 直连 IP
```

运行期数据：`%LOCALAPPDATA%\ReverseForge\`（workspace/、logs/、scripts/）。

---

## 三、构建与发布（三条命令）

```bash
python tests/selftest_core.py && python tests/selftest_decrypt.py   # 回归
python build.py                     # PyInstaller → dist/ReverseForge/（约50秒）
python release.py --skip-build      # → release/ReverseForge_v<版本>_win64.zip + SHA256
```

- **改了 rf/ 或 scripts/ 后必须重跑 build.py**——GUI exe 里打的是构建时刻的副本，
  这就是上次"代码推了但本地成品还是旧的"事故的原因。
- 版本号改 `rf/config.py: APP_VERSION`，随功能变更一起提交。
- 发布 zip 不进 git（.gitignore 排除 release/ dist/ build/）。

---

## 四、v11 → v0.2.0 的功能演进（本次会话重点）

### 1. 通用拆解 v11（b737342）
`rf.unpack_any()` 按识别类型自动选拆法：
- APK → apktool+jadx 全流程；APKS/XAPK/AAB → 解容器再走内层
- ZIP 家族（jar/docx/ipa/crx/epub…）→ Python 原生解压 + 中文文件名 cp437→gbk 修复
- tar 家族 → tarfile（零外部依赖）；RAR/7z/ISO/MSI/CHM/OLE → 7-Zip 完整版
- PE → 7-Zip 抽资源 + 字符串清单；其它 → 分段+熵+画像

### 2. 内嵌对象雕刻 v12（a00e997）
`rf/analysis/carve.py` + `rf.carve()` + 脚本18。核心思想：**"通用拆解"≠"专属提取"**——
vdex/oat 里能反编译的是内嵌 dex、加固 APK 原始 dex 藏在 lib/*.so、固件里埋 zip 段，
这些都要在字节流里扫特征整块抠出（不依赖文件头在偏移 0）：
- 支持：zip（解析 EOCD 重建为可打开压缩包）/ dex / cdex / ELF / gzip / xz / bzip2 /
  7z / rar / png / jpg / pdf / sqlite / zstd
- `unpack_any` 四处接入：ART 产物专属雕 dex；加固 APK 从 so 雕残留 dex；
  加密 zip 失败自动接弱口令；兜底路径画像+雕刻
- 自测：`tests/selftest_carve.py`

### 3. 全自动化链路通吃所有类型（ce77fb2）
`scripts/16_full_auto.py` 重构分派（这是用户实测报过"该文件不是 APK"崩溃的页面）：
```
do_unpack():
    APK  → apk_unpack（原链路：解密→smali补丁→重建→签名→丢桌面）
    非APK → unpack_any → 返回解包目录，_nonapk=True
_do 分派:
    _nonapk → do_decrypt_any(root)   # 解包产物逐文件 decrypt_auto，命中落盘 已解密/
            → do_auth_any(root)      # auth_scan + auth_apply（文本类可自动改，有备份）
            → do_pack_any(root)      # 全部成果打成 <原名>_已处理.zip，可选丢桌面
```
同批：01/15 对非 APK 友好分流（不再糊红字）；XOR 0x00 假命中过滤（等于没解）。

### 4. 解密深度优化（fbb4013）
`rf/decrypt/auto.py::salvage()` 四项升级（用户反馈"撞90多次没用、不找片段、不拼接"）：
1. **解码层回头捞密钥**：base64/压缩剥出的层往往是配置，藏着真密钥——
   每剥一层就 `K.from_bytes` 回捞并重排候选（`ordered` 在此处重算）
2. **密钥 XOR 相位自适应**：样本 28-44 分时把密钥所有相位轮转试一遍
3. **片段自动拼接**：整体没过线时切 8KB 块，每块独立试
   单字节XOR/循环XOR破解/候选密钥，高分块用解密结果拼成完整明文（"片段拼接"）
4. **低分片段兜底**：35-44 分不再丢弃，整体没救时展示最接近的片段 + 下一步指引

**边界（要如实告诉用户）**：标准 AES/RC4 且密钥不在文件内时，静态撞库无解——
用 keys 参数喂已知密钥，或 hook 运行时拿明文。这是算法边界。

---

## 五、双平台推送（重要：国内网络坑）

GitHub 直连大部分 IP 被重置，流程已固化：

```bash
# 1. 探活找可用 IP（curl 200 才算通；IP 经常失效，失效就换）
for ip in 20.27.177.113 140.82.112.34 20.205.243.166; do
  curl -s -m 6 --resolve github.com:443:$ip -o /dev/null -w "$ip->%{http_code}\n" https://github.com
done

# 2. 推送（token 放 URL + 禁用凭据管理器 + 固定 IP + 失败立即重试）
cd reverseforge
TOKEN=$(cat secrets.github.token | tr -d '\r\n ')
git push origin HEAD                                    # Gitee，通常一次过
git -c credential.helper= -c http.curloptResolve="github.com:443:<可用IP>" \
  push "https://QW1221dede:${TOKEN}@github.com/QW1221dede/ReverseForge.git" "HEAD:refs/heads/master"
# main 同理
```

踩过的坑（都是真实发生过的事故）：
- **curl 200 但 git 连不上** → 网络抖动，同 IP 立即重试通常第 2-8 次成功；
  `if git push | tail` 判断成功是错的（tail 恒真），要用 `echo "$o" | grep -q "refs/heads/master"`
- **credential.helper 残留旧令牌覆盖 URL 里的 token** → 必须 `-c credential.helper=`
- **IP 会失效**：57.155.223.240 → 20.27.177.113（当前可用，已记 github_ip.txt）
- GitHub master 和 main 两个分支都要推，默认分支是 master

---

## 六、测试与验证方式

| 自测 | 覆盖 |
|---|---|
| `tests/selftest_core.py` | 加密底座/语法校验/积木库 |
| `tests/selftest_decrypt.py` | 九大算法试解/crib/密钥流复用 |
| `tests/selftest_carve.py` | vdex 雕 dex/固件雕 zip+gzip/重建 zip 可打开/unpack_any 链路 |
| `tests/selftest_auth.py` / `selftest_apk.py` / `selftest_patch.py` | 校验点/拆包/补丁 |
| `tests/gui_*_test.py` | 界面/脚本运行器 |

端到端复现用户场景的方法：构造样本（如高熵 .sh 内埋 zip）→
`python -c "from rf.engine.script_runtime import run_cli; run_cli('scripts/16_full_auto.py', ['target=...', 'stage=all', 'to_desktop=false'])"`，
看 RC=0 且产物落盘。

---

## 七、已知问题与下一步

1. **GitHub 推送始终靠运气**——网络层问题无法根治，只能按 §五 流程重试；
   换 SSH/代理由用户决定（涉及账号配置，AI 不动）。
2. **score_output 对高重复文本有假高分**（TEA/XTEA 对周期性数据误报）——
   现象是垃圾密钥解出 60+ 分。改进方向：打分时加重复字节占比惩罚。
3. **build_sample 后 GUI 未做像素级回归**——本次只跑了 gui_deps 等脚本级测试，
   下次改 UI 后应截图检查（tests/shot_gui.py 已有基础）。
4. **ex5/OAT 等更深的脱壳**（内存 dump、unpack 壳）是用户后续可能提的方向：
   当前 carve 只做静态特征雕刻，真脱壳需要运行时（frida 页已有基础）。
5. **release zip 未上传到 GitHub Releases 页**（只有仓库源码）——如需发版页，
   用 gh CLI 或网页上传 release/*.zip，并贴 SHA256。

---

## 八、沟通与合规红线（必须遵守）

- 用户明确要求：**反馈/Issue/邮件只接受中文**（README 已声明）。
- 不在开源平台放二维码/收款码类内容（会被判下架）；打赏走邮件。
- 工具用途合规声明都在 README 顶部 + DISCLAIMER.md，**改文档时别删法条章节**。
- secrets.github.token 绝不入库（.gitignore 已排除；泄露需用户自行吊销换新）。
