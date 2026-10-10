@echo off
chcp 65001 >nul
cd /d "%~dp0"
title NetSentinel - 开启注册表审计

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] 需要管理员权限。
    echo     请右键本文件 -^> "以管理员身份运行"
    echo.
    pause
    exit /b 1
)

echo 正在开启注册表审计（Registry）...
auditpol /set /subcategory:"Registry" /success:enable /failure:enable

echo.
echo ============================================================
echo  已开启。此后 Windows 会记录"哪个进程访问/修改了哪条注册表"。
echo  NetSentinel 会自动读取事件 4663，在报告中直接指认执行者。
echo.
echo  注意：审计日志增长较快，排查完成后请运行"关闭注册表审计.bat"。
echo ============================================================
echo.
pause
