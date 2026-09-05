@echo off
echo ========================================
echo   ThreatNexus - AI Email Threat Detection
echo   Detect - Trace - Investigate
echo ========================================
echo.

echo [1/2] Starting backend on http://localhost:8000 ...
start "ThreatNexus Backend" cmd /k "cd /d %~dp0backend && .venv\Scripts\activate.bat && python -m uvicorn main:app --reload --port 8000"

echo [2/2] Starting frontend on http://localhost:3000 ...
start "ThreatNexus Frontend" cmd /k "cd /d %~dp0frontend && npm run dev"

echo.
echo Backend:  http://localhost:8000
echo API Docs: http://localhost:8000/docs
echo Frontend: http://localhost:3000
echo.
echo Both servers started in separate windows.
echo Press any key to close this window (servers keep running)...
pause >nul
