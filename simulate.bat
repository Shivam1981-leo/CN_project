@echo off
REM ====================================================================
REM ECCP Packet Flow Simulator & Wireshark Tracer Launcher
REM ====================================================================
echo ====================================================================
echo   ECCP Packet Flow Simulator & Wireshark Tracer
echo ====================================================================
echo.
echo Launching interactive simulation server...
python src\tools\run_simulator.py
pause
