# TrustShield AI

TrustShield AI is an explainable website-risk intelligence system. It combines technical URL, DNS, SSL, domain, brand, lexical, ML, explainability and reputation evidence into a clearly labeled TrustShield score.

## Features

- Website scan and TrustShield score
- Technical, domain, brand, typosquatting and lexical analysis
- ML phishing probability and top explainability factors
- VirusTotal, Google Safe Browsing, URLhaus and Gemini integrations
- AI summary and Ask TrustShield with deterministic fallback
- Scan history, community reports and scam-network relationships
- Downloadable PDF security report and safe Copy Summary action

## Architecture and tech stack

See [SYSTEM_ARCHITECTURE.md](docs/SYSTEM_ARCHITECTURE.md), [TECH_STACK.md](docs/TECH_STACK.md) and [API_REFERENCE.md](docs/API_REFERENCE.md).

## Setup

### Backend

```powershell
cd backend
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
uvicorn app.main:app --reload
```

Backend: `http://127.0.0.1:8000` · Swagger: `/docs`

### Frontend

```powershell
cd frontend
npm install
npm run dev
```

Frontend: `http://127.0.0.1:5173`. Set `VITE_API_BASE_URL` for a deployed backend; localhost is only the development fallback.

## Environment variables

Provider keys belong only in `backend/.env`. Use `backend/.env.production.example` as a placeholder template. Never commit real keys.

## Tests and ML

```powershell
cd backend
.\.venv\Scripts\Activate.ps1
pytest
```

The trained model is loaded from `backend/app/ml`. Training utilities are under `ml-training/scripts`.

## Security notes and limitations

The backend validates URLs, blocks private-network targets, keeps provider keys server-side, avoids returning reporter contact details, and uses an environment-driven CORS allow-list. SQLite is appropriate for a mini-project/demo; PostgreSQL is recommended for high-concurrency production. External provider results depend on availability, configuration and rate limits.

## Demo

Use `google.com`, `github.com` or `microsoft.com` for safe live scans. Use synthetic suspicious domains only in offline/demo mode; do not browse them live. See [DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md).
