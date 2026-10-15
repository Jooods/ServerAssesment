@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
echo First run Start_Windows.bat to set up the app.
pause
exit /b 1
)
set /p "REPORT=Enter full path to assessment.json (without surrounding quotes): "
.venv\Scripts\python.exe report_renderer.py "%REPORT%"
pause
