@echo off
setlocal
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" goto install
where py >nul 2>nul
if errorlevel 1 goto pythonfallback
py -3 -m venv .venv
if errorlevel 1 goto fail
goto install
:pythonfallback
python -m venv .venv
if errorlevel 1 goto fail
:install
.venv\Scripts\python.exe -m pip install -r requirements.txt
if errorlevel 1 goto fail
.venv\Scripts\python.exe cloud_assessor.py
if errorlevel 1 goto fail
exit /b 0
:fail
echo Setup or launch failed. Install Python 3.10+ with Tkinter, then try again.
echo Check the error above. No administrator bypass is attempted.
pause
exit /b 1
