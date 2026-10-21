@echo off
REM ====================================================================
REM Automated Setup Script for Windows (Command Prompt)
REM Encrypted Client-Server Communication Framework (ECCP)
REM ====================================================================

echo ====================================================================
echo   ECCP Setup Script (Windows CMD)
echo   Encrypted Client-Server Communication Framework
echo ====================================================================
echo.

REM Check Python
echo [*] Checking Python installation...
python --version >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [X] Python is not installed or not in PATH. Please install Python 3.8+.
    exit /b 1
)
python --version
echo [OK] Python found.
echo.

REM Create directories
echo [*] Creating directories...
if not exist "logs" mkdir logs
if not exist "data" mkdir data
if not exist "config" mkdir config
if not exist "received_files" mkdir received_files
echo [OK] Directories verified.
echo.

REM Install dependencies
echo [*] Installing dependencies from requirements.txt...
pip install -r requirements.txt
if %ERRORLEVEL% neq 0 (
    echo [!] Pip install had warnings or errors. Continuing...
)
echo.

REM Verify certificates
echo [*] Checking SSL certificates...
if not exist "certs\server.crt" (
    echo [!] Server certificate not found in certs\
    echo [*] Generating TLS certificates automatically using Python...
    python certs\generate_certs.py certs
)
if exist "certs\server.crt" (
    echo [OK] Certificates ready.
) else (
    echo [X] Could not generate certificates.
)
echo.

REM Run all unit test suites
echo [*] Running full test suite...
python tests\run_all_tests.py
echo.

echo ====================================================================
echo   Setup Complete!
echo ====================================================================
echo.
echo To run the server:
echo   python src\server\server.py
echo.
echo To run the terminal client:
echo   python src\client\client.py
echo.
echo To run the GUI client:
echo   python src\client\client_gui.py
echo.
pause
