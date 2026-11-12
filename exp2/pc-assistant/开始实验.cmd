@echo off
chcp 65001 >nul
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0启动助手.ps1" %*
if errorlevel 1 (
    echo.
    echo 启动未完成。请保留上面的报错，或双击“检查启动.cmd”。
    pause
)
