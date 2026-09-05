# ThreatNexus

**AI-Powered Email Threat Detection, Geolocation and Forensic Intelligence Platform**

ThreatNexus helps security teams investigate suspicious emails. It analyses email content, headers, and metadata to identify phishing, spoofing, impersonation, malicious links, and suspicious sender infrastructure. The platform combines AI-assisted threat analysis with email authentication checks, reputation intelligence, and forensic reporting.

> **Important:** IP geolocation and email-header tracing provide an evidence-based estimate of an email's likely origin or relay path. They cannot reliably identify a sender behind forged headers, VPNs, Tor, proxies, or compromised infrastructure.

## Problem Statement

Email-based attacks often contain more than one indicator of compromise: suspicious language, forged sender details, failed authentication, malicious URLs, risky IP addresses, and unusual mail-routing patterns. Investigators need these signals in one place, with evidence that supports a quick and defensible response.

ThreatNexus supports the full investigation flow:

```text
Detect → Analyze → Trace → Correlate → Report
```

## Features

- AI-assisted analysis of email content and metadata
- Detection support for phishing, spoofing, impersonation, suspicious links, attachments, and fraud indicators
- SPF, DKIM, and DMARC authentication checks
- IP, domain, and URL reputation analysis
- DNS, WHOIS/RDAP, and mail-infrastructure intelligence
- Geolocation and email relay-path visualization
- Risk scores with supporting forensic evidence
- Dashboard statistics and recent-analysis history
- User registration and login

## Technology Stack

| Layer | Technology |
| --- | --- |
| Frontend | React-based npm application |
| Backend API | Python and FastAPI |
| AI analysis | AI/ML and NLP components |
| Primary database | PostgreSQL |
| Search and analytics | Elasticsearch |
| Cache / supporting service | Redis |
| External intelligence | VirusTotal, AbuseIPDB, IP/DNS/WHOIS APIs |
| Local container environment | Docker and Docker Compose |

## Architecture

```text
Email, headers, and metadata
            │
            ▼
      FastAPI backend
            │
   ┌────────┼───────────┐
   ▼        ▼           ▼
AI/NLP   Auth checks  Intelligence checks
         SPF/DKIM/     IP, URL, domain,
         DMARC         DNS and WHOIS/RDAP
   └────────┴───────────┘
            │
            ▼
Risk score, evidence, trace path, and forensic report
            │
            ▼
      React dashboard
```

## Project Services

The Docker Compose configuration starts the following services:

| Service | Default local port | Purpose |
| --- | ---: | --- |
| Frontend | 3000 | Web interface |
| Backend | 8000 | FastAPI API and analysis services |
| PostgreSQL | 5432 | Application data |
| Elasticsearch | 9200 | Search and analytical data |
| Redis | 6379 | Cache and supporting data |

## Getting Started

### Prerequisites

- Python and `pip`
- Node.js and npm
- Docker Desktop, optional but recommended for the complete local stack

### Run without Docker

Start the backend:

```bash
cd backend
pip install -r requirements.txt
python -m uvicorn main:app --reload --port 8000
```

Start the frontend in a separate terminal:

```bash
cd frontend
npm install
npm run dev
```

Local URLs:

- Frontend: `http://localhost:3000`
- Backend: `http://localhost:8000`
- API documentation: `http://localhost:8000/docs`

### Run with Docker Compose

From the project root:

```bash
docker-compose up --build
```

Docker Compose provisions the frontend, backend, PostgreSQL, Elasticsearch, and Redis services together. Use this setup for local development and self-hosted environments.

## Environment Variables

Create a local `.env` file from the project example, or define the following values in your deployment platform. Never commit `.env` files or real credentials.

```env
# Required: use a long, random value in every non-local environment
SECRET_KEY=replace-with-a-long-random-secret

# Required for a production deployment
DATABASE_URL=postgresql://USER:PASSWORD@HOST:5432/DATABASE
ELASTICSEARCH_URL=https://ELASTICSEARCH_HOST
REDIS_URL=rediss://REDIS_HOST:PORT

# Optional reputation integrations
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
```

| Variable | Required | Description |
| --- | --- | --- |
| `SECRET_KEY` | Yes | Secret used for JWT signing. Generate a unique production value. |
| `DATABASE_URL` | Yes | PostgreSQL connection URL. |
| `ELASTICSEARCH_URL` | Yes when search/analytics are enabled | Elasticsearch connection URL. |
| `REDIS_URL` | Yes when Redis-backed features are enabled | Redis connection URL. |
| `VIRUSTOTAL_API_KEY` | Optional | Enables VirusTotal reputation lookups. |
| `ABUSEIPDB_API_KEY` | Optional | Enables AbuseIPDB IP-reputation lookups. |

## API Endpoints

| Method | Endpoint | Description |
| --- | --- | --- |
| `POST` | `/api/analyze` | Run a full email analysis. |
| `POST` | `/api/quick-scan` | Run a quick threat scan. |
| `POST` | `/api/check-domain` | Check domain reputation. |
| `POST` | `/api/check-ip` | Check IP reputation. |
| `GET` | `/api/stats` | Get dashboard statistics. |
| `GET` | `/api/analyses/recent` | Get recent analyses. |
| `POST` | `/api/auth/register` | Register a user. |
| `POST` | `/api/auth/login` | Sign in a user. |

Interactive API documentation is available locally at `/docs` when the FastAPI backend is running.

## Deployment

### Recommended production topology

Deploy the frontend on Vercel and deploy the backend as a Docker service on a platform that supports persistent services. Use managed versions of PostgreSQL, Redis, and Elasticsearch.

```text
Vercel frontend
      │ HTTPS API requests
      ▼
FastAPI Docker backend
      ├── Managed PostgreSQL
      ├── Managed Redis
      └── Managed Elasticsearch
```

### Vercel frontend

1. Push the repository to GitHub without `.env`.
2. Import the repository into Vercel.
3. Set the Vercel project root directory to `frontend`.
4. Configure the frontend API base URL to point to the public FastAPI backend. Check the frontend source for the exact variable name used by the application.
5. Deploy and add the resulting Vercel domain to the backend CORS allowlist.

### Backend and data services

Host the `backend` Dockerfile on a container-capable platform such as Railway, Render, or Fly.io. Configure the environment variables above through the host's secure environment-variable settings. Provision external PostgreSQL, Redis, and Elasticsearch services, then use their production connection URLs.

Do not use the development database password or the Compose defaults in production. Restrict CORS to the public frontend domain and use HTTPS for the frontend, API, and managed service connections.

## Security and Privacy

- Treat uploaded emails, headers, attachments, IP addresses, and investigation reports as sensitive data.
- Keep API keys, database credentials, and `SECRET_KEY` outside source control.
- Use least-privilege database accounts and encrypted service connections in production.
- Apply access control and audit logging to investigation records.
- Mask sensitive content in reports where possible and retain evidence according to the applicable policy.
- Use threat scores as investigation support. Review high-impact decisions with a qualified analyst.

## Limitations

- Email authentication failures and reputation signals are indicators, not proof of malicious activity.
- Attackers can forge headers or hide their infrastructure using proxies, VPNs, Tor, or compromised systems.
- External threat-intelligence results depend on provider availability, coverage, rate limits, and API credentials.

## References

- SPF, DKIM, and DMARC email-authentication standards
- NIST cybersecurity guidance
- MITRE ATT&CK knowledge base
- VirusTotal and AbuseIPDB threat-intelligence services

## License

Add a license file before publishing the repository publicly.
