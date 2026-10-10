@echo off
chcp 65001 >nul
cd /d "%~dp0"
title NetSentinel - 生成报告

where python >nul 2>nul
if %errorlevel%==0 (
    python run.py report
) else (
    py -3 run.py report
)

echo.
echo 正在打开报告...
start "" "data\report.html"
echo.
pause
