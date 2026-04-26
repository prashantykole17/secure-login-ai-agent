@echo off
setlocal

if exist "%~dp0.venv\Scripts\python.exe" (
  "%~dp0.venv\Scripts\python.exe" "%~dp0app.py"
  exit /b %errorlevel%
)

python "%~dp0app.py"
if %errorlevel%==0 exit /b 0

py -3 "%~dp0app.py"
if %errorlevel%==0 exit /b 0

py "%~dp0app.py"
if %errorlevel%==0 exit /b 0

echo Python or the project virtual environment was not found. Run setup.bat first.
exit /b 1
