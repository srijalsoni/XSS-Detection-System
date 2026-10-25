# PowerShell Startup Script for Cross-Site Scripting (XSS) Attack Detection Defensive Web Application
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -Path $ScriptDir

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host " CROSS-SITE SCRIPTING (XSS) ATTACK DETECTION STARTUP (POWERSHELL)" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "[*] Canonical Directory: $ScriptDir"

$PythonExe = Join-Path $ScriptDir ".venv\Scripts\python.exe"

if (-not (Test-Path $PythonExe)) {
    Write-Host "[-] ERROR: Virtual environment not detected at $PythonExe" -ForegroundColor Red
    Write-Host "    Create virtual environment: python -m venv .venv"
    Write-Host "    Install dependencies: .venv\Scripts\pip install -r requirements.txt"
    exit 1
}

$env:FLASK_ENV = "development"
$env:PYTHONPATH = $ScriptDir

Write-Host "[+] Virtual environment verified." -ForegroundColor Green
Write-Host "[*] Starting Flask application on http://127.0.0.1:5000 ..." -ForegroundColor Yellow
Write-Host "[*] Press CTRL+C to stop the application."
Write-Host "======================================================================" -ForegroundColor Cyan

& $PythonExe "app.py"
