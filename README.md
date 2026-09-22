# TrustShield AI

## Project Title

TrustShield AI: An Explainable AI-Based Website Trust Scoring and Scam Risk Detection System

## Purpose

TrustShield AI will help users understand website trust and scam risk. Phase 1A now includes the initial real-time technical URL analysis engine and a simple testing page.

## Current Tech Stack

- Backend: Python 3.13, FastAPI, Uvicorn
- Frontend: React, Vite, JavaScript
- Supporting packages: SQLAlchemy, scikit-learn, pandas, NumPy, and HTTP utilities
- Analysis endpoint: `POST /api/scan`
- Phase 1B: brand impersonation and lexical domain intelligence

## Folder Structure

See `PROJECT_STRUCTURE.md` for the initial layout.

Phase 1B details are documented in `docs/PHASE_1B.md`.

## Start the Backend

```powershell
cd backend
.\.venv\Scripts\Activate.ps1
uvicorn app.main:app --reload
```

Backend: http://127.0.0.1:8000  
Swagger: http://127.0.0.1:8000/docs

To run the backend tests:

```powershell
cd backend
.\.venv\Scripts\Activate.ps1
pytest
```

## Start the Frontend

```powershell
cd frontend
npm run dev
```

Frontend: http://127.0.0.1:5173
