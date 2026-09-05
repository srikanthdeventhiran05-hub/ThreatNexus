@echo off
echo Stopping any existing ThreatNexus servers...
taskkill /F /IM python.exe /FI "WINDOWTITLE eq ThreatNexus*" >nul 2>&1
echo Done.
