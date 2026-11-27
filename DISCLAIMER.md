# 免责声明 / DISCLAIMER

**ReverseForge · 逆锻台**（下称"本工具"）

最后更新：2026-11-26

---

## 一、用途限定

本工具是**逆向工程与安全分析的学习、研究与授权测试平台**，仅可用于：

1. 分析**你自己拥有**的软件、数据与文件；
2. 分析你已获得**明确书面授权**的目标（渗透测试、代码审计、应急响应、取证）；
3. 教学、学术研究、CTF 等合法场景；
4. 安全产品研发过程中的样本分析。

**严禁**用于：

- 破解、盗版、去除商业软件的授权与付费限制；
- 未经授权获取他人账号、密码、数据、通信内容；
- 制作、传播恶意软件、外挂、木马、勒索软件；
- 侵犯他人知识产权、商业秘密、个人信息权益；
- 任何违反中华人民共和国法律法规及你所在司法辖区法律的行为。

## 二、责任自负

1. 使用者应自行确认其对目标拥有合法权利或授权。**因使用本工具产生的一切法律责任、经济损失、数据损坏、设备故障、第三方索赔，均由使用者自行承担**，作者与贡献者不承担任何责任。
2. 本工具会**修改文件**（打补丁、改写脚本、重打包 APK）。修改前工具会自动备份，但**不保证备份一定成功、不保证修改后程序仍可正常运行**。请自行保留原始文件。
3. 本工具会**尝试解密**。解密失败、解出错误内容、或对错误数据执行操作造成的后果，由使用者承担。
4. 本工具**不是杀毒软件**，不对任何样本的合法性、安全性作出判断。报告中出现"校验点""可疑"等字样仅为技术描述，**不构成对软件性质的认定**。

## 三、无担保

本工具按"现状"（AS IS）提供，不附带任何明示或默示的担保，包括但不限于适销性、特定用途适用性、无侵权担保。作者不保证工具无缺陷、不中断、结果准确。

## 四、第三方组件

本工具在运行时可调用第三方开源软件（apktool、jadx、rizin、Ghidra、Android SDK 工具、7-Zip 等）。这些组件遵循各自许可证，其版权归各自作者所有。一键安装脚本仅从**官方地址**下载这些公开软件，不修改其二进制。

使用第三方组件时，你同时受其许可证约束。

## 五、数据与隐私

1. 本工具**完全本地运行**，不上传任何被分析文件、密钥、路径或分析结果。
2. 唯一的联网行为是：你主动执行的"一键安装"从官方地址下载工具；以及你自己配置的 AI 接口（若启用）。
3. 日志与产物保存在本机 `%LOCALAPPDATA%\ReverseForge\` 下，由你自行管理。

## 六、开源许可

本工具以 **MIT License** 发布（见 `LICENSE`）。你可以自由使用、修改、分发，但须保留版权声明与许可声明。

**分发者请注意**：若你二次分发本工具，必须同时保留本免责声明，并确保接收者知晓上述用途限定。

## 七、接受条款

下载、安装、运行本工具，即表示你已阅读、理解并同意本免责声明全部内容。若不同意，请立即停止使用并删除本工具。

---

## English Summary

ReverseForge is a reverse-engineering and security-analysis platform intended **only** for software you own or are explicitly authorized to test. Any use for cracking, piracy, unauthorized access, malware development, or violation of applicable law is strictly prohibited. The software is provided "AS IS" without warranty of any kind. **You are solely responsible** for any consequences arising from its use. The authors and contributors accept no liability. Licensed under MIT; redistribution must retain this disclaimer.

---

> 一句话：**这是把刀，给你自己家的东西开箱用的。拿它去撬别人家门，与作者无关。**

## 五、主要相关法律条款（中华人民共和国）

以下条款为使用者自行判断合规性的主要参考，本声明对其仅为提示性引用，
不构成法律意见：

- **《中华人民共和国刑法》第 285 条**（非法侵入计算机信息系统罪；
  非法获取计算机信息系统数据、非法控制计算机信息系统罪；提供侵入、
  非法控制计算机信息系统程序、工具罪）：未经授权侵入他人计算机系统、
  获取其数据或对其非法控制，以及为此提供程序工具，均属犯罪。
- **《中华人民共和国刑法》第 286 条**（破坏计算机信息系统罪）：
  对计算机信息系统功能、数据、应用程序进行删除、修改、干扰，造成
  系统不能正常运行或数据丢失的，构成犯罪。
- **《中华人民共和国刑法》第 217、218 条**（侵犯著作权罪、销售侵权
  复制品罪）：以营利为目的未经许可复制发行他人软件，属犯罪。
- **《中华人民共和国著作权法》**：计算机软件受著作权保护；第 24 条
  合理使用情形不含破解授权控制。规避技术保护措施（第 53 条）需承担
  民事乃至行政责任。
- **《中华人民共和国网络安全法》第 27 条**：任何个人和组织不得从事
  非法侵入他人网络、干扰他人网络正常功能、窃取网络数据等危害网络
  安全的活动，不得为其提供技术支持、广告推广、支付结算等帮助。
- **《反不正当竞争法》第 12 条**（互联网专条）：利用技术手段破坏
  其他经营者合法提供的网络产品或服务的正常运行，属不正当竞争。
- **《计算机软件保护条例》第 24 条**：故意避开或者破坏著作权人为其
  软件采取的技术措施，属侵权行为。
- **《数据安全法》《个人信息保护法》**：非法获取、加工、传输他人
  数据与个人信息需承担法律责任。

**本工具能力的法律边界**：工具具备的"校验点识别""补丁""解密"等功能
是逆向工程领域的通用分析技术，其本身中立；但**对他人软件实施这些操作
以规避其授权验证或付费机制，在上述法律框架下构成侵权乃至犯罪**。
使用者必须在授权范围内（自有资产 / 书面授权 / 教学研究豁免）使用。

## 六、主观故意的排除声明

作者开发、分发本工具的目的是：

1. 帮助软件开发者理解逆向分析技术，从而**更好地加固自己的产品**；
2. 为授权范围内的安全测试、教学与研究提供效率工具；
3. 推动开源安全分析技术（apktool、rizin 等同类项目的思路）的可及性。

作者**不具有**协助他人实施违法行为的故意，本工具不针对任何特定商业
软件作专门适配，不内置任何特定软件的破解方案；使用者若将其用于违法
用途，属超出作者明示许可范围的自主决定，与作者无涉。依据《刑法》第
285 条第 3 款及司法解释，提供程序工具类犯罪要求行为人明知他人实施
危害活动而专门提供帮助——本工具的通用性质与上述声明即为对该主观
要件的否定。

## 七、商标与归属

"ReverseForge · 逆锻台"名称及标识归作者所有，未经许可不得用于
暗示背书的商业宣传。

本声明以中文为准。有疑问请在Issue中提出，勿以违法方式"实测"。

---
最后更新：2026-11-27（v10，AGPL-3.0 + 禁商用附加条款）


---

## English Summary / 英文摘要

**What this tool is for**: ReverseForge is an educational & authorized-testing platform for
reverse engineering and security analysis. It may only be used on software/files you own, or
targets you are **explicitly authorized in writing** to test (pentest, code audit, forensics,
CTF, academic research).

**Strictly prohibited**: cracking or removing license/payment controls of commercial software,
unauthorized access to accounts/data/communications, creating or spreading cheats/malware,
infringing IP, trade secrets or personal information.

**No warranty; you bear all liability.** The authors provide this tool AS IS, do not endorse any
illegal use, and are not liable for any consequences of your use. Before use you must review the
applicable laws of your jurisdiction — for the PRC these include Criminal Law Arts. 285/286/217/218,
Copyright Law Arts. 24/53, Cybersecurity Law Art. 27, Anti-Unfair Competition Law Art. 12, and the
Software Protection Regulations Art. 24 (see Section 5 above, authoritative Chinese text).

**License**: GNU AGPL-3.0 **plus additional terms prohibiting any commercial use** (see LICENSE).
By downloading or using this tool you declare your use is lawful and authorized.


## 联系方式 / Contact

- **邮箱 / Email**：m358685@163.com
- **Gitee Issues**：https://gitee.com/tw-dm/reverse-forge/issues
- **GitHub Issues**：https://github.com/QW1221dede/ReverseForge/issues

**请用中文交流，不接受英文。** 用英文提交的反馈、Issue 与邮件可能不会得到回复。
(Chinese only — English submissions may not be answered.)
