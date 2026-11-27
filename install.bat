@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion
cd /d "%~dp0"
title ReverseForge 一键安装

echo ============================================================
echo   ReverseForge  一键安装
echo ============================================================
echo.
echo   安装位置：%LOCALAPPDATA%\ReverseForge\vendor
echo   需要管理员权限，会弹出一次 UAC 确认。
echo.
echo   【先说清楚，避免装到一半被拦】
echo   本工具是逆向分析平台，打包后会被部分杀软误报
echo   （PyInstaller 壳 + 程序里带 hook/注入相关字符串）。
echo.
echo   如果装完被杀软删了文件，请先把下面两个路径加入白名单：
echo     1) %LOCALAPPDATA%\ReverseForge
echo     2) 本程序的安装目录
echo   Defender：设置 ^> 病毒和威胁防护 ^> 排除项 ^> 添加文件夹
echo.
echo   仅可用于你拥有授权的目标。详见 DISCLAIMER.md。
echo.
pause

rem ---- 是否已是管理员 ----
net session >nul 2>&1
if %errorlevel% equ 0 goto :run

echo 正在申请管理员权限……
powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs -ArgumentList '%*'"
if %errorlevel% neq 0 (
  echo.
  echo 提权失败或被取消。请右键本文件 ^> 以管理员身份运行。
  pause
)
exit /b

:run
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" %*
set RC=%errorlevel%
echo.
if %RC% neq 0 (
  echo 安装结束，但有步骤未成功（退出码 %RC%），请查看上面的日志。
) else (
  echo 安装完成。
)
pause
exit /b %RC%
