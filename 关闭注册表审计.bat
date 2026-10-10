@echo off
chcp 65001 >nul
cd /d "%~dp0"
title NetSentinel - 关闭注册表审计

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] 需要管理员权限。请右键本文件 -^> "以管理员身份运行"
    echo.
    pause
    exit /b 1
)

echo 正在关闭注册表审计（Registry）...
auditpol /set /subcategory:"Registry" /success:disable /failure:disable

echo.
echo 已复原。此后 NetSentinel 将不再能直接从安全日志指认修改进程。
echo.
pause
