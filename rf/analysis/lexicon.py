#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 rf.analysis.lexicon · 词典与命名翻译
============================================================================

【为什么单独一个模块】
    命名翻译（英文标识符 → 中文短语）是注释器最底层的原料：
      · annotate 用它给类名/方法名/字段名配中文
      · cnlang   用它把 if/for 里的表达式翻成中文伪代码
    两边都要用，放在任一方的模块里都会形成循环导入，所以独立出来。

【翻译能力边界（必须诚实）】
    这是**词级映射 + 整词优先**，不是机器翻译：
      downloadAndInstall → 下载并安装（整词表命中）
      verifyLicense      → 校验授权（逐词拼接）
      a / x0 / y1        → 空串（R8 混淆后名字本身不携带任何语义，翻不出来）
    逐词拼接的语序按英文顺序保留，中文读起来是"电报体"——
    它解决的是"看不懂这串英文"，不是"生成通顺的中文句子"。
============================================================================
"""

from __future__ import annotations

import re

WORD_CN: dict[str, str] = {
    # 动作
    "get": "获取", "set": "设置", "is": "是否", "has": "是否有", "can": "能否",
    "add": "添加", "remove": "移除", "delete": "删除", "clear": "清空",
    "create": "创建", "build": "构建", "make": "生成", "new": "新建",
    "init": "初始化", "initialize": "初始化", "setup": "装配", "prepare": "准备",
    "start": "启动", "stop": "停止", "pause": "暂停", "resume": "恢复",
    "open": "打开", "close": "关闭", "release": "释放", "destroy": "销毁",
    "load": "加载", "unload": "卸载", "save": "保存", "store": "存储",
    "read": "读取", "write": "写入", "parse": "解析", "format": "格式化",
    "encode": "编码", "decode": "解码", "encrypt": "加密", "decrypt": "解密",
    "compress": "压缩", "uncompress": "解压", "zip": "打包", "unzip": "解包",
    "download": "下载", "upload": "上传", "send": "发送", "receive": "接收",
    "push": "推送", "pull": "拉取", "fetch": "拉取", "request": "请求",
    "response": "响应", "connect": "连接", "disconnect": "断开",
    "install": "安装", "uninstall": "卸载", "update": "更新", "upgrade": "升级",
    "check": "检查", "verify": "校验", "validate": "验证", "confirm": "确认",
    "compare": "比较", "match": "匹配", "search": "搜索", "find": "查找",
    "filter": "筛选", "sort": "排序", "merge": "合并", "split": "分割",
    "copy": "复制", "move": "移动", "rename": "重命名", "backup": "备份",
    "restore": "还原", "reset": "重置", "reload": "重载", "refresh": "刷新",
    "register": "注册", "unregister": "注销", "bind": "绑定", "unbind": "解绑",
    "login": "登录", "logout": "登出", "auth": "认证", "authorize": "授权",
    "permission": "权限", "grant": "授予", "revoke": "撤销",
    "exec": "执行", "execute": "执行", "run": "运行", "invoke": "调用",
    "call": "调用", "apply": "应用", "handle": "处理", "process": "处理",
    "dispatch": "分发", "notify": "通知", "broadcast": "广播", "emit": "发出",
    "listen": "监听", "observe": "观察", "watch": "监视", "monitor": "监控",
    "hook": "钩取", "inject": "注入", "patch": "打补丁", "bypass": "绕过",
    "detect": "检测", "scan": "扫描", "probe": "探测", "dump": "转储",
    "extract": "提取", "collect": "收集", "capture": "捕获", "record": "录制",
    "play": "播放", "show": "显示", "hide": "隐藏", "enable": "启用",
    "disable": "禁用", "toggle": "切换", "switch": "切换", "select": "选择",
    "click": "点击", "touch": "触摸", "scroll": "滚动", "input": "输入",
    "output": "输出", "render": "渲染", "draw": "绘制", "paint": "绘制",
    "measure": "测量", "layout": "布局", "inflate": "填充布局",
    # 名词
    "user": "用户", "account": "账号", "password": "密码", "token": "令牌",
    "session": "会话", "cookie": "Cookie", "key": "密钥", "secret": "密文",
    "sign": "签名", "signature": "签名", "hash": "哈希", "salt": "盐值",
    "cert": "证书", "certificate": "证书", "ssl": "SSL", "tls": "TLS",
    "http": "HTTP", "https": "HTTPS", "url": "链接", "uri": "资源标识",
    "host": "主机", "port": "端口", "socket": "套接字", "proxy": "代理",
    "header": "请求头", "body": "报文体", "param": "参数", "params": "参数",
    "args": "参数", "config": "配置", "option": "选项", "setting": "设置",
    "preference": "偏好设置", "property": "属性", "attr": "属性",
    "field": "字段", "method": "方法", "class": "类", "object": "对象",
    "instance": "实例", "instanceof": "", "type": "类型", "name": "名称",
    "value": "值", "data": "数据", "info": "信息", "detail": "详情",
    "list": "列表", "array": "数组", "map": "映射", "set_": "集合",
    "queue": "队列", "stack": "栈", "node": "节点", "tree": "树",
    "item": "条目", "entry": "条目", "element": "元素", "index": "索引",
    "count": "数量", "size": "大小", "length": "长度", "num": "数量",
    "total": "总计", "max": "最大", "min": "最小", "sum": "求和",
    "file": "文件", "path": "路径", "dir": "目录", "folder": "文件夹",
    "stream": "流", "buffer": "缓冲区", "channel": "通道", "pipe": "管道",
    "thread": "线程", "task": "任务", "job": "作业", "worker": "工作线程",
    "pool": "池", "async": "异步", "sync": "同步", "callback": "回调",
    "listener": "监听器", "handler": "处理器", "manager": "管理器",
    "service": "服务", "receiver": "接收器", "provider": "提供者",
    "activity": "活动页", "fragment": "碎片页", "adapter": "适配器",
    "view": "视图", "widget": "控件", "button": "按钮", "dialog": "对话框",
    "toast": "提示条", "menu": "菜单", "tab": "标签页", "page": "页面",
    "screen": "屏幕", "window": "窗口", "context": "上下文",
    "application": "应用", "app": "应用", "package": "包", "pkg": "包",
    "module": "模块", "plugin": "插件", "component": "组件",
    "resource": "资源", "asset": "资产", "raw": "原始资源",
    "image": "图片", "bitmap": "位图", "icon": "图标", "color": "颜色",
    "text": "文本", "string": "字符串", "char": "字符", "byte": "字节",
    "bytes": "字节串", "int": "整数", "long": "长整型", "float": "浮点",
    "double": "双精度", "bool": "布尔", "boolean": "布尔",
    "null": "空", "empty": "空", "valid": "有效", "invalid": "无效",
    "success": "成功", "fail": "失败", "failure": "失败", "warning": "警告",
    "info": "信息", "debug": "调试", "fatal": "致命错误", "crash": "崩溃",
    "advice": "建议", "suggest": "建议", "reason": "原因", "cause_": "原因",
    "problem": "问题", "issue": "问题", "warn": "警告", "notice": "提示", "error": "错误", "exception": "异常",
    "result": "结果", "status": "状态", "state": "状态", "mode": "模式",
    "flag": "标志", "level": "级别", "step": "步骤", "stage": "阶段",
    "time": "时间", "date": "日期", "timestamp": "时间戳", "delay": "延迟",
    "timeout": "超时", "interval": "间隔", "duration": "时长",
    "device": "设备", "phone": "手机", "sim": "SIM 卡", "imei": "IMEI",
    "imsi": "IMSI", "mac": "MAC 地址", "ip": "IP 地址", "wifi": "WiFi",
    "network": "网络", "mobile": "移动网络", "location": "定位",
    "gps": "GPS", "camera": "相机", "mic": "麦克风", "audio": "音频",
    "video": "视频", "media": "媒体", "sms": "短信", "phone_call": "通话",
    "contact": "联系人", "calendar": "日历", "clipboard": "剪贴板",
    "notification": "通知", "alarm": "闹钟", "battery": "电池",
    "storage": "存储", "memory": "内存", "cpu": "CPU", "disk": "磁盘",
    "root": "Root 权限", "su": "su 提权", "shell": "Shell 命令",
    "superuser": "超级用户", "admin": "管理员", "system": "系统",
    "kernel": "内核", "driver": "驱动", "firmware": "固件",
    "dex": "DEX", "apk": "APK", "jar": "JAR", "so": "动态库",
    "native": "原生层", "jni": "JNI 桥", "reflection": "反射",
    "reflect": "反射", "loader": "加载器", "classloader": "类加载器",
    "clone": "克隆", "proxy_": "代理", "stub": "桩", "wrapper": "包装",
    "lambda": "Lambda 合成体", "synthetic": "编译器合成",
}

# ---------------------------------------------------------------------------
# 通用缩写/后缀 —— 缺了它们，注释里会频繁漏出 "设备id""剩余days""结果code"
# ---------------------------------------------------------------------------
WORD_CN.update({
    "id": "标识", "ids": "标识列表", "uuid_": "唯一标识",
    "of": "", "the": "", "and": "和", "or": "或", "to": "到", "by": "按",
    "for": "用于", "in": "在", "on": "于", "at": "在", "is": "是否",
    "code": "码", "codes": "码值", "no": "编号", "num_": "编号", "seq": "序号",
    "days": "天数", "day": "天", "hours": "小时", "hour": "小时",
    "mins": "分钟", "minute": "分钟", "secs": "秒", "seconds": "秒",
    "ms": "毫秒", "millis": "毫秒",
    "str": "字符串", "strs": "字符串", "buf": "缓冲区", "byteArr": "字节数组",
    "idx": "下标", "pos": "位置", "len": "长度", "cnt": "计数",
    "msg": "消息", "err": "错误", "ret": "返回", "res": "结果", "resp": "响应",
    "req": "请求", "tmp": "临时", "cur": "当前", "curr": "当前",
    "ctx": "上下文", "app_": "应用", "ui": "界面", "db": "数据库",
    "util": "工具", "utils": "工具", "helper": "辅助类", "common": "公共",
    "base": "基础", "core": "核心", "main": "主", "default": "默认",
    "custom": "自定义", "global": "全局", "local": "本地", "remote": "远端",
    "inner": "内部", "outer": "外部", "real": "真实", "fake": "伪造",
    "origin": "原始", "raw_": "原始", "pure": "纯", "quick": "快速",
    "simple": "简单", "full": "完整", "part": "部分", "rest": "剩余",
    "first": "首个", "last": "最后", "next_": "下一个", "prev": "上一个",
    "left": "左", "right": "右", "top": "上", "bottom": "下",
    "width": "宽度", "height": "高度", "x": "", "y": "",
    "enable_": "启用", "enabled": "已启用", "disabled": "已禁用",
    "ok": "成功", "done": "完成", "ready": "就绪", "busy": "忙碌",
    "wait": "等待", "waiting": "等待中", "loading": "加载中",
    "hint": "提示", "tip": "提示", "title": "标题", "desc": "描述",
    "content": "内容", "body_": "正文", "label": "标签", "tag_": "标签",
    "note": "备注", "comment": "注释", "author": "作者", "version": "版本",
    "ver": "版本", "build_": "构建", "release": "发布", "debug_": "调试",
    "test_": "测试", "prod": "生产", "dev": "开发", "env": "环境",
})

#   上层词典是通用词，遇到 license / activate / entitlement 会原样漏成英文，
#   注释就会变成"校验license"这种半土半洋的东西。这批词专治这个。
# ---------------------------------------------------------------------------
WORD_CN.update({
    # 授权 / 付费
    "license": "授权", "licence": "授权", "lic": "授权", "licensing": "授权",
    "activate": "激活", "activation": "激活", "deactivate": "反激活",
    "serial": "序列号", "cdkey": "卡密", "keygen": "注册机",
    "purchase": "购买", "subscribe": "订阅", "subscription": "订阅",
    "entitlement": "权益", "quota": "配额", "credit": "额度", "balance": "余额",
    "vip": "会员", "premium": "高级版", "pro": "专业版", "trial": "试用",
    "expire": "过期", "expiry": "到期", "expired": "已过期", "validity": "有效期",
    "renew": "续期", "refund": "退款", "order": "订单", "sku": "商品编号",
    "pay": "支付", "payment": "支付", "billing": "计费", "invoice": "发票",
    "unlock": "解锁", "unlocked": "已解锁", "locked": "已锁定", "lock": "锁定",
    "feature": "功能", "limit": "限制", "limited": "受限", "remain": "剩余",
    "remainder": "剩余", "used": "已用", "usage": "用量",
    # 签名 / 完整性
    "integrity": "完整性", "tamper": "篡改", "tampered": "被篡改",
    "checksum": "校验和", "digest": "摘要", "fingerprint": "指纹",
    "md5": "MD5", "sha": "SHA", "sha1": "SHA1", "sha256": "SHA256",
    "crc": "CRC", "hmac": "HMAC", "nonce": "随机数", "salt_": "盐值",
    "keystore": "密钥库", "pkcs": "PKCS", "rsa": "RSA", "aes": "AES",
    "publickey": "公钥", "privatekey": "私钥", "pubkey": "公钥",
    "encryptdata": "加密数据", "decryptdata": "解密数据",
    # 环境 / 反调试
    "emulator": "模拟器", "virtual": "虚拟环境", "virtualapp": "分身/多开",
    "debugger": "调试器", "debuggable": "可调试", "ptrace": "进程跟踪",
    "xposed": "Xposed", "magisk": "Magisk", "frida": "Frida",
    "substrate": "Substrate", "detect": "检测", "detected": "已检测到",
    "ban": "封禁", "banned": "已封禁", "blacklist": "黑名单", "whitelist": "白名单",
    # 网络校验
    "server": "服务端", "client": "客户端", "api": "接口", "endpoint": "接口地址",
    "verify": "校验", "verification": "校验", "validate": "验证",
    "auth": "鉴权", "authenticate": "鉴权", "authorization": "授权头",
    "oauth": "OAuth", "jwt": "JWT", "bearer": "Bearer 令牌",
    "refresh": "刷新", "expires_in": "有效期秒数", "scope": "权限范围",
    "sign_": "签名", "signature_": "签名", "appsign": "应用签名",
    "channel": "渠道", "device": "设备", "deviceid": "设备标识",
    "uuid": "唯一标识", "androidid": "Android ID", "oaid": "OAID",
    "imei_": "IMEI", "macaddr": "MAC 地址",
    # 结果 / 分支
    "granted": "已授予", "denied": "被拒绝", "allowed": "允许",
    "forbidden": "禁止", "unauthorized": "未授权", "expired_": "已过期",
    "retry": "重试", "attempt": "尝试", "attempts": "尝试次数",
    "threshold": "阈值", "tolerance": "容差", "grace": "宽限期",
})


# 整词优先（比逐词拼接自然）
PHRASE_CN: dict[str, str] = {
    "getinstance": "获取单例",
    "getapplicationcontext": "获取应用上下文",
    "getsystemservice": "获取系统服务",
    "oncreate": "创建时回调",
    "onstart": "启动时回调",
    "onresume": "恢复前台时回调",
    "onpause": "退到后台时回调",
    "onstop": "停止时回调",
    "ondestroy": "销毁时回调",
    "onreceive": "收到广播时回调",
    "onclick": "点击时回调",
    "onbind": "绑定时回调",
    "onstartcommand": "服务启动时回调",
    "getsharedpreferences": "获取偏好设置存储",
    "startactivity": "启动页面",
    "startservice": "启动服务",
    "sendbroadcast": "发送广播",
    "setcontentview": "设置界面布局",
    "findviewbyid": "按 ID 查找控件",
    "setonclicklistener": "设置点击监听",
    "runonuithread": "切到主线程执行",
    "postdelayed": "延迟投递任务",
    "getpackagemanager": "获取包管理器",
    "getinstalledpackages": "获取已安装应用列表",
    "getinstalledapplications": "获取已安装应用列表",
    "checkpermission": "检查权限",
    "requestpermissions": "申请权限",
    "getexternalstoragedirectory": "获取外部存储目录",
    "getfilesdir": "获取应用私有目录",
    "openfileoutput": "打开文件输出流",
    "openfileinput": "打开文件输入流",
    "readallbytes": "读取全部字节",
    "writebytes": "写入字节",
    "closequietly": "静默关闭",
    "printstacktrace": "打印异常堆栈",
    "getmessage": "获取消息内容",
    "tostring": "转字符串",
    "equalsignorecase": "忽略大小写比较",
    "startswith": "以…开头",
    "endswith": "以…结尾",
    "contains": "包含",
    "isempty": "是否为空",
    "size_": "元素个数",
    "downloadandinstall": "下载并安装",
    "installapk": "安装 APK",
    "silentinstall": "静默安装",
    "execshell": "执行 Shell",
    "runcmd": "执行命令",
    "getdevicestate": "获取设备状态",
    "getlastknownlocation": "获取最后已知定位",
    "requeslocationupdates": "请求定位更新",
    "getsimoperator": "获取运营商",
    "getdeviceid": "获取设备标识",
    "getsubscriberid": "获取用户标识",
}

# 校验域整词优先（逐词拼会得到"校验授权是否有效"这种长串，整词更利落）
PHRASE_CN.update({
    "checklicense": "校验授权",
    "verifylicense": "校验授权",
    "checklicence": "校验授权",
    "islicensesvalid": "授权是否有效",
    "islicensevalid": "授权是否有效",
    "islicensed": "是否已授权",
    "isactivated": "是否已激活",
    "isvip": "是否会员",
    "ispremium": "是否高级版",
    "istrial": "是否试用",
    "isexpired": "是否已过期",
    "getexpiretime": "获取到期时间",
    "getexpirydate": "获取到期日期",
    "getremaindays": "获取剩余天数",
    "remainingdays": "剩余天数",
    "checksignature": "校验签名",
    "verifysignature": "校验签名",
    "verifyappsig": "校验应用签名",
    "getsignature": "获取签名",
    "getappsignature": "获取应用签名",
    "getpackageinfo": "获取包信息",
    "checkintegrity": "校验完整性",
    "verifyintegrity": "校验完整性",
    "checktamper": "检测篡改",
    "isrooted": "是否已 Root",
    "checkroot": "检测 Root",
    "isdeviceemulator": "是否模拟器",
    "checkemulator": "检测模拟器",
    "isdebuggerconnected": "是否有调试器连接",
    "checkdebug": "检测调试",
    "checkxposed": "检测 Xposed",
    "checkfrida": "检测 Frida",
    "getdeviceid_": "获取设备标识",
    "isnetworkavailable": "网络是否可用",
    "verifyreceipt": "校验购买凭证",
    "checkpurchase": "校验购买记录",
    "reportlicense": "上报授权状态",
    "uploadlicense": "上传授权信息",
    "onlicensechecked": "授权校验回调",
    "onverifyresult": "校验结果回调",
    "showsuccess": "显示成功",
    "showfail": "显示失败",
    "showpaywall": "弹出付费墙",
    "showdialog": "弹出对话框",
    "lockfeature": "锁定功能",
    "unlockfeature": "解锁功能",
})


def split_words(name: str) -> list[str]:
    """downloadAndInstall / download_and_install / a0 → ['download','and','install']"""
    if not name:
        return []
    s = name.replace("-", "_")
    parts = re.split(r"[_\s]+", s)
    out: list[str] = []
    for p in parts:
        # 数字与字母交界处切开：base64 -> base,64
        p = re.sub(r"(?<=[a-zA-Z])(?=\d)", " ", p)
        p = re.sub(r"(?<=\d)(?=[a-zA-Z])", " ", p)
        for chunk in p.split():
            # camelCase / PascalCase
            for w in re.findall(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+", chunk):
                if w:
                    out.append(w.lower())
    return out


# 三字母视图前缀（btnOk / imgBanner / txtTitle），不是词、不该出现在中文里
_VIEW_PREFIX = frozenset({
    "btn", "img", "txt", "edt", "rv", "wv", "ll", "fl", "sv", "pb", "tb", "fab",
    "act", "frag", "dlg", "adp", "vm", "repo", "svc", "mgr", "utils_", "impl",
})


# 变量名里的类型前缀（strAdvice / objResult），翻成"字符串建议"会让人对不上代码
_TYPE_PREFIX = frozenset({"str", "sb", "obj", "arr", "buf", "tmp", "lst", "itm"})


def translate_name(name: str) -> str:
    """
    把标识符翻成中文短语。整词命中优先，否则逐词拼。

    返回值可能是空串（纯混淆名），调用方自行处理。

    【为什么要剥前缀】
        Android 代码里满是匈牙利式前缀：mLicense / sInstance / tvTitle / btnOk。
        不剥的话会翻成"m授权""s实例""tv标题"，读起来像乱码。
        规则：首段是 1~2 个字母、且后面还有实词 → 判定为前缀，丢掉。
    """
    if not name:
        return ""
    low = name.lower().replace("_", "")
    if low in PHRASE_CN:
        return PHRASE_CN[low]
    words = split_words(name)
    if not words:
        return ""
    if len(words) > 1 and len(words[0]) <= 2 and words[0] not in WORD_CN:
        words = words[1:]
        # 双前缀很常见：mTvTitle / sIvIcon
        if len(words) > 1 and len(words[0]) <= 2 and words[0] not in WORD_CN:
            words = words[1:]
    # 三字母控件前缀：btnOk / imgBanner / txtTitle
    if len(words) > 1 and words[0] in _VIEW_PREFIX:
        words = words[1:]
    # 类型前缀：strAdvice / sbBuilder —— 首段只是类型代号，不是语义
    if len(words) > 1 and words[0] in _TYPE_PREFIX:
        words = words[1:]
    cn = []
    hits = 0
    for w in words:
        if w in WORD_CN:
            c = WORD_CN[w]
            if c:
                cn.append(c)
                hits += 1
        elif w.isdigit():
            continue
        else:
            # 未收录的词保留原样，让读者知道略过了什么
            cn.append(w)
    # 一个词都没翻出来 → 返回空串，由调用方保留原始大小写
    # （否则 Integer 会被当成已翻译，漏成小写 integer）
    if hits == 0:
        return ""
    text = "".join(cn)
    return text if text and text != name else ""


def cn_literal(s: str, limit: int = 40) -> str:
    """把代码里的字符串字面量压缩成一行，便于注释展示。"""
    s = s.replace("\\n", " ").replace("\\t", " ").replace('\\"', '"')
    s = re.sub(r"\s+", " ", s).strip()
    if len(s) > limit:
        s = s[:limit] + "…"
    return s


# ---------------------------------------------------------------------------
# 源码扫描
# ---------------------------------------------------------------------------
