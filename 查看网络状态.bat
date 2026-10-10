@echo off
chcp 65001 >nul
cd /d "%~dp0"
title NetSentinel - 当前网络状态

where python >nul 2>nul
if %errorlevel%==0 (
    python run.py status
) else (
    py -3 run.py status
)

echo.
pause
