@echo off
echo Starting ThreatNexus Frontend...
cd /d "%~dp0frontend"
if not exist "node_modules" (
    echo Installing dependencies...
    call npm install
)
call npm run dev
