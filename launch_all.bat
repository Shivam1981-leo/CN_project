@echo off
title ECCP Full Demo Launcher
echo ====================================================================
echo   Launching ECCP Full Chat System + Live Wireshark Simulation
echo ====================================================================
echo.
echo [*] Starting ECCP Server on port 5000...
start "ECCP Server [Port 5000]" cmd /k "python src\server\server.py"

echo [*] Waiting 2 seconds for server to initialize...
timeout /t 2 >nul

echo [*] Starting Interactive Live Packet Flow Simulator (Browser)...
start "ECCP Live Visualizer" cmd /k "python src\tools\run_simulator.py"

echo [*] Waiting 1 second...
timeout /t 1 >nul

echo [*] Launching Client 1 (e.g. Alice)...
start "ECCP Client 1" cmd /k "python src\client\client_gui.py"

echo [*] Launching Client 2 (e.g. Bob)...
start "ECCP Client 2" cmd /k "python src\client\client_gui.py"

echo.
echo ====================================================================
echo   All Components Launched!
echo   - 1 Server Window (port 5000)
echo   - 1 Web Visualizer (http://localhost:8080)
echo   - 2 Client GUI Windows (Register/Login as Alice and Bob)
echo ====================================================================
