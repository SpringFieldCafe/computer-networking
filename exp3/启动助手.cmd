@echo off
setlocal
cd /d "%~dp0.."
python -X utf8 "%~dp0scripts\launch_assistant.py"
if errorlevel 1 pause
endlocal
