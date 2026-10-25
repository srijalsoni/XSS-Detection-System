@echo off
setlocal
title Cross-Site Scripting (XSS) Attack Detection System

echo ======================================================================
echo  CROSS-SITE SCRIPTING (XSS) ATTACK DETECTION APPLICATION STARTUP
echo ======================================================================

:: 1. Navigate to script directory (canonical repo)
cd /d "%~dp0"
echo [*] Working Directory: %CD%

:: 2. Check for virtual environment
if not exist ".venv\Scripts\python.exe" (
    echo [-] ERROR: Virtual environment not found at .venv\Scripts\python.exe
    echo     Please create it using: python -m venv .venv
    echo     And install dependencies using: .venv\Scripts\pip install -r requirements.txt
    pause
    exit /b 1
)

:: 3. Set local environment variables
set "FLASK_ENV=development"
set "PYTHONPATH=%CD%"

echo [+] Virtual environment verified.
echo [*] Launching application on http://127.0.0.1:5000 ...
echo [*] Press CTRL+C to terminate the server.
echo ======================================================================

".venv\Scripts\python.exe" app.py

endlocal
