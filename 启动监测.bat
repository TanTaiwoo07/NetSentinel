@echo off
chcp 65001 >nul
cd /d "%~dp0"
title NetSentinel - 网络配置变更监测

echo ============================================================
echo   NetSentinel  网络配置变更监测与溯源
echo   持续监测中，检测到变化会自动记录并分析原因/源头
echo   按 Ctrl+C 停止
echo ============================================================
echo.

where python >nul 2>nul
if %errorlevel%==0 (
    python run.py watch -i 5
) else (
    py -3 run.py watch -i 5
)

echo.
echo 监测已结束。正在生成可视化报告...
where python >nul 2>nul
if %errorlevel%==0 (
    python run.py report
) else (
    py -3 run.py report
)

echo.
pause
