# ThreatNexus - AI-Powered Email Threat Detection Platform

## Quick Start (Without Docker)

### Backend
```bash
cd backend
pip install -r requirements.txt
python -m uvicorn main:app --reload --port 8000
```

### Frontend
```bash
cd frontend
npm install
npm run dev
```

Backend: http://localhost:8000
Frontend: http://localhost:3000
API Docs: http://localhost:8000/docs

## Quick Start (With Docker)

```bash
docker-compose up --build
```

All services start automatically.

## Features

- AI-powered email threat detection
- SPF / DKIM / DMARC authentication checks
- IP, domain and URL reputation analysis
- Geolocation and trace path visualization
- Forensic evidence and reporting
- Interactive dashboard with charts

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/analyze | Full email analysis |
| POST | /api/quick-scan | Quick threat scan |
| POST | /api/check-domain | Domain reputation check |
| POST | /api/check-ip | IP reputation check |
| GET | /api/stats | Dashboard statistics |
| GET | /api/analyses/recent | Recent analyses |
| POST | /api/auth/register | Register user |
| POST | /api/auth/login | Login |

## Environment Variables

Copy `.env.example` to `.env` and set:
- `SECRET_KEY` - JWT secret
- `VIRUSTOTAL_API_KEY` - VirusTotal API key (optional)
- `ABUSEIPDB_API_KEY` - AbuseIPDB API key (optional)
