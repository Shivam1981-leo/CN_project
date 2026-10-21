# ====================================================================
# Automated Setup Script for Windows PowerShell
# Encrypted Client-Server Communication Framework (ECCP)
# ====================================================================

Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host "  ECCP Setup Script (PowerShell)" -ForegroundColor Cyan
Write-Host "  Encrypted Client-Server Communication Framework" -ForegroundColor Cyan
Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host ""

# Check Python
Write-Host "[*] Checking Python installation..." -ForegroundColor Blue
try {
    $pythonVersion = python --version
    Write-Host "[OK] $pythonVersion found." -ForegroundColor Green
} catch {
    Write-Host "[X] Python is not installed or not in PATH." -ForegroundColor Red
    exit 1
}

# Directories
Write-Host "[*] Creating directories..." -ForegroundColor Blue
@("logs", "data", "config", "received_files") | ForEach-Object {
    if (-not (Test-Path $_)) {
        New-Item -ItemType Directory -Path $_ | Out-Null
    }
}
Write-Host "[OK] Directories verified." -ForegroundColor Green

# Dependencies
Write-Host "[*] Installing Python dependencies..." -ForegroundColor Blue
pip install -r requirements.txt
Write-Host "[OK] Dependencies checked." -ForegroundColor Green

# Check Certificates
Write-Host "[*] Checking SSL certificates..." -ForegroundColor Blue
if (-not (Test-Path "certs\server.crt") -or -not (Test-Path "certs\server.key")) {
    Write-Host "[!] Certificates missing in certs\ folder. Generating automatically..." -ForegroundColor Yellow
    python certs\generate_certs.py certs
}
if (Test-Path "certs\server.crt" -and Test-Path "certs\server.key") {
    Write-Host "[OK] Certificates verified in certs\" -ForegroundColor Green
} else {
    Write-Host "[X] Certificate generation failed." -ForegroundColor Red
}

# Run tests
Write-Host "`n[*] Running full test suite..." -ForegroundColor Blue
python tests\run_all_tests.py

Write-Host "`n====================================================================" -ForegroundColor Cyan
Write-Host "  Setup Complete!" -ForegroundColor Cyan
Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host "`nStart server:         python src/server/server.py" -ForegroundColor Green
Write-Host "Start CLI client:     python src/client/client.py" -ForegroundColor Green
Write-Host "Start GUI client:     python src/client/client_gui.py`n" -ForegroundColor Green
