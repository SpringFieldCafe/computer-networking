@echo off
setlocal
cd /d "%~dp0.."
python -X utf8 "%~dp0scripts\assistant.py" menu
if errorlevel 1 pause
endlocal
