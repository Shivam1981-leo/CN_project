# ECCP Full Demo Launcher for Windows PowerShell
Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host "  Launching ECCP Full Chat System + Live Wireshark Simulation" -ForegroundColor Green
Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[*] Starting ECCP Server on port 5050..." -ForegroundColor Yellow
Start-Process cmd -ArgumentList "/k python src\server\server.py"

Start-Sleep -Seconds 2

Write-Host "[*] Starting Interactive Live Packet Flow Simulator (Browser)..." -ForegroundColor Yellow
Start-Process cmd -ArgumentList "/k python src\tools\run_simulator.py"

Start-Sleep -Seconds 1

Write-Host "[*] Launching Client 1 (e.g. Alice)..." -ForegroundColor Yellow
Start-Process cmd -ArgumentList "/k python src\client\client_gui.py"

Write-Host "[*] Launching Client 2 (e.g. Bob)..." -ForegroundColor Yellow
Start-Process cmd -ArgumentList "/k python src\client\client_gui.py"

Write-Host ""
Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host "  All Components Launched!" -ForegroundColor Green
Write-Host "  - 1 Server Window (port 5050)"
Write-Host "  - 1 Web Visualizer (http://localhost:8080)"
Write-Host "  - 2 Client GUI Windows (Register/Login as Alice and Bob)"
Write-Host "====================================================================" -ForegroundColor Cyan
