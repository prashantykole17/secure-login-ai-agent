@echo off
setlocal

where python >nul 2>nul
if %errorlevel%==0 goto :makeenv

where py >nul 2>nul
if %errorlevel%==0 goto :makeenvpy

echo Python was not found. Install Python 3.10+ first.
exit /b 1

:makeenv
python -m venv "%~dp0.venv"
"%~dp0.venv\Scripts\python.exe" -m pip install --upgrade pip
"%~dp0.venv\Scripts\python.exe" -m pip install -r "%~dp0requirements.txt"
exit /b %errorlevel%

:makeenvpy
py -3 -m venv "%~dp0.venv"
"%~dp0.venv\Scripts\python.exe" -m pip install --upgrade pip
"%~dp0.venv\Scripts\python.exe" -m pip install -r "%~dp0requirements.txt"
exit /b %errorlevel%
