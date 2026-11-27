<#
============================================================================
 ReverseForge · 一键安装脚本（Windows / PowerShell 5.1+）
============================================================================

 干什么
   把程序需要的运行环境一次性装好，装到：
       %LOCALAPPDATA%\ReverseForge\vendor
   程序启动时优先用这里的工具，**不依赖系统里装过什么**。
   装完把整个 exe 目录拷到别的机器，配合这个 vendor 目录就能跑（绿色版）。

 为什么需要管理员
   · 写入 %LOCALAPPDATA% 之外的目录、给 Defender 加排除项要管理员
   · 部分杀软会把"下载可执行文件"直接拦掉，管理员权限下才能正常落盘
   脚本会自己检查，不是管理员就直接退出并提示怎么提权。

 用法
   install.bat                      双击（会自动弹 UAC 提权）
   powershell -ExecutionPolicy Bypass -File install.ps1
   install.ps1 -DryRun              只检查不断下载，看清会装什么
   install.ps1 -Offline D:\pkgs     断网/内网：从本地目录装（见文件尾说明）
   install.ps1 -WithJadx            顺带装 jadx（反编译 DEX 用）
   install.ps1 -NoDefender          不碰 Windows Defender 排除项
   install.ps1 -Proxy http://127.0.0.1:7890     走代理下载

 装了什么（都能单独跳过）
   1. Temurin JDK 17      apktool / apksigner 依赖 JVM
   2. apktool 2.9.3       APK 解包 / 重打包
   3. Android cmdline-tools → build-tools + platform-tools
                          aapt2 / apksigner / zipalign / adb
   4. 7zr                 压缩包与固件镜像
   5. jadx（可选）        DEX → Java 源码
   Ghidra 不在默认列表里：解压后 1.5GB+，需要的人自己下，程序探测到就用。

 免责
   本脚本只从官方地址下载公开软件，不修改它们的二进制。
   使用本工具链请遵守当地法律与目标授权，详见 DISCLAIMER.md。
============================================================================
#>

[CmdletBinding()]
param(
    [switch]$Silent,
    [switch]$DryRun,
    [string]$Offline = "",
    [switch]$WithJadx,
    [switch]$NoDefender,
    [string]$Proxy = ""
)

$ErrorActionPreference = "Stop"
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------
$AppName    = "ReverseForge"
$Root       = Join-Path $env:LOCALAPPDATA $AppName
$Vendor     = Join-Path $Root "vendor"
$Tmp        = Join-Path $Root "_install_tmp"
$LogFile    = Join-Path $Root "install.log"

$UrlJdk      = "https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.13%2B11/OpenJDK17U-jdk_x64_windows_hotspot_17.0.13_11.zip"
$UrlApktool  = "https://github.com/iBotPeaches/Apktool/releases/download/v2.9.3/apktool_2.9.3.jar"
$UrlCmdline  = "https://dl.google.com/android/repository/commandlinetools-win-11076708_latest.zip"
$UrlJadx     = "https://github.com/skylot/jadx/releases/download/v1.5.1/jadx-1.5.1.zip"
$Url7zr      = "https://www.7-zip.org/a/7zr.exe"

$BT_VERSION  = "35.0.0"

# ---------------------------------------------------------------------------
# 输出
# ---------------------------------------------------------------------------
function Say($msg, $color = "Gray") {
    # 用拼接而不是 -f：日志里出现花括号时 -f 会当成占位符炸掉
    if ([string]::IsNullOrEmpty($msg)) { Write-Host ""; return }
    $line = "[" + (Get-Date -Format "HH:mm:ss") + "] " + $msg
    Write-Host $line -ForegroundColor $color
    try { Add-Content -Path $LogFile -Value $line -Encoding UTF8 } catch {}
}
function Step($n, $t) { Say ""; Say "== $n. $t ==" "Cyan" }
function Ok($m)   { Say "  [OK]   $m" "Green" }
function Warn($m) { Say "  [注意] $m" "Yellow" }
function Fail($m) { Say "  [失败] $m" "Red" }

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Confirm-Continue($prompt) {
    if ($Silent) { return $true }
    $a = Read-Host "$prompt [Y/n]"
    return ($a -eq "" -or $a -match "^[Yy]")
}

# ---------------------------------------------------------------------------
# 下载（带重试 + 断点）
# ---------------------------------------------------------------------------
function Get-File($url, $dest, $what) {
    if (Test-Path $dest) {
        $sz = (Get-Item $dest).Length
        if ($sz -gt 1024) { Ok "$what 已存在（$([math]::Round($sz/1MB,1))MB），跳过下载"; return $true }
    }
    if ($DryRun) { Warn "$what 需要下载：$url"; return $false }

    New-Item -ItemType Directory -Force -Path (Split-Path $dest) | Out-Null
    $iwr = @{ Uri = $url; OutFile = $dest; UseBasicParsing = $true; TimeoutSec = 300 }
    if ($Proxy) { $iwr["Proxy"] = $Proxy }

    for ($i = 1; $i -le 3; $i++) {
        try {
            Say "  下载 $what …（第 $i 次）"
            Invoke-WebRequest @iwr
            if ((Get-Item $dest).Length -gt 1024) { Ok "$what 下载完成"; return $true }
        } catch {
            Warn "第 $i 次失败：$($_.Exception.Message)"
            Start-Sleep -Seconds (2 * $i)
        }
    }
    Fail "$what 下载失败。手动下载后放到：$dest"
    Say "       地址：$url" "DarkGray"
    return $false
}

function Expand-Zip($zip, $dest) {
    if ($DryRun) { return }
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    Expand-Archive -Path $zip -DestinationPath $dest -Force
}

# ---------------------------------------------------------------------------
# 0. 环境检查
# ---------------------------------------------------------------------------
Step 0 "环境检查"
Say "  目标目录：$Vendor"

$skipAdmin = ($env:RF_SKIP_ADMIN -eq "1") -and $DryRun
if (-not (Test-Admin) -and -not $skipAdmin) {
    Fail "需要管理员权限"
    Say ""
    Say "  右键 install.bat → 以管理员身份运行" "Yellow"
    Say "  或者在这个 PowerShell 里执行：" "Yellow"
    Say "    Start-Process powershell -Verb RunAs -ArgumentList '-ExecutionPolicy Bypass -File `"$PSCommandPath`"'" "Yellow"
    exit 1
}
if (Test-Admin) { Ok "管理员权限" } else { Warn "跳过管理员检查（仅预演）" }

New-Item -ItemType Directory -Force -Path $Vendor, $Tmp | Out-Null
$os = [Environment]::OSVersion.Version
Say "  系统：Windows $($os.Major).$($os.Minor)  PowerShell $($PSVersionTable.PSVersion)"
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Fail "PowerShell 版本过低（需要 5.1+）"; exit 1
}
Ok "PowerShell 版本可用"

if ($DryRun) {
    Warn "预演模式：只检查不下载、不写盘"
}

# ---------------------------------------------------------------------------
# 1. JDK 17
# ---------------------------------------------------------------------------
Step 1 "JDK 17（apktool / apksigner 依赖）"
$jdkDir = Join-Path $Vendor "jdk"
$javaExe = Join-Path $jdkDir "bin\java.exe"
if (Test-Path $javaExe) {
    Ok "已安装：$(& $javaExe -version 2>&1 | Select-Object -First 1)"
} else {
    $zip = Join-Path $Tmp "jdk17.zip"
    if (Get-File $UrlJdk $zip "JDK 17") {
        Say "  解压 …"
        $stage = Join-Path $Tmp "jdk_stage"
        if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
        Expand-Zip $zip $stage
        $inner = Get-ChildItem $stage -Directory | Select-Object -First 1
        if ($inner) {
            if (Test-Path $jdkDir) { Remove-Item $jdkDir -Recurse -Force }
            Move-Item $inner.FullName $jdkDir
            Ok "JDK 已就位：$jdkDir"
        } else { Fail "JDK 解压后没找到目录" }
        Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
    }
}
$env:JAVA_HOME = $jdkDir
$env:PATH = "$jdkDir\bin;$env:PATH"

# ---------------------------------------------------------------------------
# 2. apktool
# ---------------------------------------------------------------------------
Step 2 "apktool（APK 解包 / 重打包）"
$jar = Join-Path $Vendor "apktool.jar"
if (Test-Path $jar) {
    Ok "已存在 apktool.jar（$([math]::Round((Get-Item $jar).Length/1MB,1))MB）"
} else {
    Get-File $UrlApktool $jar "apktool.jar" | Out-Null
}
# 写一个 bat 包装，方便命令行直接用
$bat = Join-Path $Vendor "apktool.bat"
if (-not (Test-Path $bat) -and -not $DryRun) {
    @"
@echo off
"%JAVA_HOME%\bin\java.exe" -jar "%~dp0apktool.jar" %*
"@ | Set-Content -Path $bat -Encoding ASCII
    Ok "已生成 apktool.bat"
}

# ---------------------------------------------------------------------------
# 3. Android 命令行工具 → build-tools / platform-tools
# ---------------------------------------------------------------------------
Step 3 "Android 工具（aapt2 / apksigner / zipalign / adb）"
$sdkRoot = Join-Path $Vendor "android-sdk"
$sdkmanager = Join-Path $sdkRoot "cmdline-tools\latest\bin\sdkmanager.bat"

if (Test-Path $sdkmanager) {
    Ok "sdkmanager 已存在"
} else {
    $zip = Join-Path $Tmp "cmdline-tools.zip"
    if (Get-File $UrlCmdline $zip "Android cmdline-tools") {
        $stage = Join-Path $Tmp "cmd_stage"
        if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
        Expand-Zip $zip $stage
        $lat = Join-Path $sdkRoot "cmdline-tools\latest"
        New-Item -ItemType Directory -Force -Path (Split-Path $lat) | Out-Null
        $inner = Get-ChildItem $stage -Directory | Select-Object -First 1
        if ($inner) {
            if (Test-Path $lat) { Remove-Item $lat -Recurse -Force }
            New-Item -ItemType Directory -Force -Path (Split-Path $lat) | Out-Null
            Move-Item $inner.FullName $lat
            Ok "cmdline-tools 已就位"
        } else { Fail "cmdline-tools 解压异常" }
        Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if ((Test-Path $sdkmanager) -and -not $DryRun) {
    Say "  安装 build-tools;$BT_VERSION 与 platform-tools（首次约 100MB）…"
    try {
        $yes = ("y`n" * 40)
        $yes | & $sdkmanager --sdk_root="$sdkRoot" --licenses 2>&1 | Out-Null
        $yes | & $sdkmanager --sdk_root="$sdkRoot" "platform-tools" "build-tools;$BT_VERSION" 2>&1 | Out-Null
        Ok "Android 组件安装完成"
    } catch {
        Warn "sdkmanager 执行失败：$($_.Exception.Message)"
        Say "  可稍后手动执行：" "DarkGray"
        Say "    `"$sdkmanager`" --sdk_root=`"$sdkRoot`" `"platform-tools`" `"build-tools;$BT_VERSION`"" "DarkGray"
    }
}

# 统一成程序认识的布局：vendor\build-tools\<ver>\ 、vendor\platform-tools\
$btSrc = Join-Path $sdkRoot "build-tools\$BT_VERSION"
if (Test-Path $btSrc) {
    $btDst = Join-Path $Vendor "build-tools\$BT_VERSION"
    if (-not (Test-Path $btDst)) {
        New-Item -ItemType Directory -Force -Path (Split-Path $btDst) | Out-Null
        Copy-Item $btSrc $btDst -Recurse -Force
        Ok "build-tools 已复制到 vendor"
    } else { Ok "build-tools 已存在" }
}
$ptSrc = Join-Path $sdkRoot "platform-tools"
if (Test-Path $ptSrc) {
    $ptDst = Join-Path $Vendor "platform-tools"
    if (-not (Test-Path $ptDst)) {
        Copy-Item $ptSrc $ptDst -Recurse -Force
        Ok "platform-tools 已复制到 vendor"
    } else { Ok "platform-tools 已存在" }
}

# ---------------------------------------------------------------------------
# 4. 7zr
# ---------------------------------------------------------------------------
Step 4 "7zr（压缩包 / 固件镜像）"
$sevenZ = Join-Path $Vendor "7zr.exe"
if (Test-Path $sevenZ) { Ok "已存在" }
else { Get-File $Url7zr $sevenZ "7zr.exe" | Out-Null }

# ---------------------------------------------------------------------------
# 5. jadx（可选）
# ---------------------------------------------------------------------------
if ($WithJadx) {
    Step 5 "jadx（DEX → Java 源码）"
    $jdir = Join-Path $Vendor "jadx"
    if (Test-Path (Join-Path $jdir "bin\jadx.bat")) {
        Ok "已存在"
    } else {
        $zip = Join-Path $Tmp "jadx.zip"
        if (Get-File $UrlJadx $zip "jadx") {
            $stage = Join-Path $Tmp "jadx_stage"
            if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
            Expand-Zip $zip $stage
            if (Test-Path $jdir) { Remove-Item $jdir -Recurse -Force }
            Move-Item $stage $jdir
            Ok "jadx 已就位"
        }
    }
} else {
    Step 5 "jadx（跳过）"
    Say "  需要 DEX 反编译时加 -WithJadx 重跑"
}

# ---------------------------------------------------------------------------
# 6. Defender 排除项
# ---------------------------------------------------------------------------
Step 6 "Windows Defender 排除项"
if ($NoDefender) {
    Warn "按参数跳过"
} else {
    try {
        Add-MpPreference -ExclusionPath $Root -ErrorAction Stop
        Add-MpPreference -ExclusionProcess "ReverseForge.exe" -ErrorAction SilentlyContinue
        Ok "已把 $Root 加入 Defender 排除项"
    } catch {
        Warn "加排除项失败（可能被组策略/第三方杀软接管）：$($_.Exception.Message)"
        Say "  请手动把下面两个路径加入白名单：" "Yellow"
        Say "    $Root" "Yellow"
        Say "    <程序目录>\ReverseForge.exe" "Yellow"
    }
}

# ---------------------------------------------------------------------------
# 7. 校验
# ---------------------------------------------------------------------------
Step 7 "逐项校验"

function Check-Tool($name, $path, $argList) {
    if (-not (Test-Path $path)) { Fail "$name 缺失：$path"; return $false }
    if ($DryRun) { Ok "$name（预演，未执行）"; return $true }
    try {
        $out = & $path @argList 2>&1 | Select-Object -First 1
        Ok "$name  $out"
        return $true
    } catch {
        Fail "$name 无法运行：$($_.Exception.Message)"
        return $false
    }
}

$okCount = 0; $total = 0
$checks = @(
    @{ n = "java";      p = (Join-Path $Vendor "jdk\bin\java.exe"); a = @("-version") },
    @{ n = "aapt2";     p = (Join-Path $Vendor "build-tools\$BT_VERSION\aapt2.exe"); a = @("version") },
    @{ n = "zipalign";  p = (Join-Path $Vendor "build-tools\$BT_VERSION\zipalign.exe"); a = @() },
    @{ n = "apksigner"; p = (Join-Path $Vendor "build-tools\$BT_VERSION\apksigner.bat"); a = @("--version") },
    @{ n = "adb";       p = (Join-Path $Vendor "platform-tools\adb.exe"); a = @("version") },
    @{ n = "7zr";       p = (Join-Path $Vendor "7zr.exe"); a = @() }
)
foreach ($c in $checks) {
    $total++
    if (Check-Tool $c.n $c.p $c.a) { $okCount++ }
}

# apktool 单独校验（走 java -jar）
$total++
if (Test-Path (Join-Path $Vendor "apktool.jar")) {
    if ($DryRun) { Ok "apktool（预演）"; $okCount++ }
    else {
        try {
            $v = & (Join-Path $Vendor "jdk\bin\java.exe") -jar (Join-Path $Vendor "apktool.jar") --version 2>&1 | Select-Object -First 1
            Ok "apktool  $v"; $okCount++
        } catch { Fail "apktool 无法运行" }
    }
} else { Fail "apktool.jar 缺失" }

# ---------------------------------------------------------------------------
# 8. 写清单
# ---------------------------------------------------------------------------
Step 8 "写安装清单"
if (-not $DryRun) {
    $manifest = [ordered]@{
        app          = $AppName
        installed_at = (Get-Date).ToString("s")
        vendor       = $Vendor
        jdk          = "17"
        apktool      = "2.9.3"
        build_tools  = $BT_VERSION
        jadx         = [bool]$WithJadx
        proxy        = $Proxy
        verified     = "$okCount/$total"
    }
    $manifest | ConvertTo-Json -Depth 4 | Set-Content -Path (Join-Path $Vendor "manifest.json") -Encoding UTF8
    Ok "manifest.json 已写入"
} else {
    Say "  （预演，不写清单）"
}

# ---------------------------------------------------------------------------
# 9. 桌面快捷方式
# ---------------------------------------------------------------------------
Step 9 "桌面快捷方式"
$exe = Join-Path $PSScriptRoot "ReverseForge.exe"
if (-not (Test-Path $exe)) { $exe = Join-Path $PSScriptRoot "dist\ReverseForge\ReverseForge.exe" }
if (Test-Path $exe) {
    if ($DryRun) {
        Warn "预演：将创建桌面快捷方式 → $exe"
    } else {
        try {
            $desktop = [Environment]::GetFolderPath("Desktop")
            $lnk = Join-Path $desktop "ReverseForge 逆锻台.lnk"
            $ws = New-Object -ComObject WScript.Shell
            $sc = $ws.CreateShortcut($lnk)
            $sc.TargetPath = $exe
            $sc.WorkingDirectory = (Split-Path $exe)
            $sc.Description = "ReverseForge 逆锻台"
            $sc.IconLocation = "$exe,0"
            $sc.Save()
            Ok "已创建：$lnk"
        } catch {
            Warn "快捷方式创建失败：$($_.Exception.Message)"
            Warn "可在程序里点「工具 → 创建桌面快捷方式」重试"
        }
    }
} else {
    Warn "没找到 exe，跳过快捷方式：$exe"
}

# ---------------------------------------------------------------------------
# 完成
# ---------------------------------------------------------------------------
Say ""
Say "============================================================" "Cyan"
Say " 安装结果：$okCount/$total 项可用" $(if ($okCount -eq $total) { "Green" } else { "Yellow" })
Say " 目录：$Vendor" "Cyan"
Say " 日志：$LogFile" "DarkGray"
Say "============================================================" "Cyan"
Say ""
Say " 下一步：" "White"
Say "   1) 如果杀软仍然拦截 ReverseForge.exe，把程序目录加入白名单" "Yellow"
Say "      （Defender：设置 → 病毒和威胁防护 → 排除项 → 添加文件夹）" "DarkGray"
Say "   2) 启动 ReverseForge.exe，左侧「投放文件」区拖入目标即可" "White"
Say "   3) 工具状态看界面右上角「工具」按钮" "White"
Say ""
if ($okCount -lt $total) {
    Say " 未全部成功不代表不能用：缺什么就在界面「工具」里看哪项标红，" "Yellow"
    Say " 按上面日志里的地址手动下载后放进 $Vendor 同一个位置即可。" "Yellow"
}

if (-not $Silent) {
    Read-Host "按回车关闭"
}
