@echo off
echo Starting ThreatNexus Backend...
cd /d "%~dp0backend"
if not exist ".venv" (
    echo Creating virtual environment...
    python -m venv .venv
    call .venv\Scripts\activate.bat
    pip install -r requirements.txt
    call .venv\Scripts\deactivate.bat
)
call .venv\Scripts\activate.bat
python -m uvicorn main:app --reload --port 8000
