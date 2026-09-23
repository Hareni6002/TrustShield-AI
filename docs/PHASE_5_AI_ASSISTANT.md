# Phase 5: AI Explanation and Ask TrustShield

Phase 5 adds an optional language-model explanation layer. The existing technical analysis, ML prediction, SHAP contributions, reputation results, and TrustShield Score remain authoritative; the AI layer only explains them.

## Provider configuration

Set these backend-only variables in `backend/.env`:

- `AI_PROVIDER=openai` or `gemini`
- `AI_API_KEY=...`
- `AI_MODEL=...`

The provider is selected through an abstraction in `backend/app/services/ai/provider.py`. OpenAI and Gemini adapters are supported without exposing credentials to the frontend or scan response. If the provider or key is absent, scans continue normally with deterministic fallback text.

## Context and safety

`context_builder.py` sends a compact, structured subset of the completed backend scan: URL/domain, TrustShield and component scores, technical evidence, brand/lexical signals, ML probabilities, SHAP factors, reputation provider statuses, and conflicts. It does not send API keys, cookies, authorization headers, passwords, raw HTML, or environment values.

Website-derived text is treated as untrusted data. The system prompt explicitly rejects instructions inside scanned content, prevents fabricated facts, prohibits 100% safe claims, and keeps SSL, ML, SHAP, and reputation evidence distinct.

## Endpoints

- `POST /api/ai/summary` with `{ "scan_id": "..." }` returns an AI-generated summary or deterministic fallback.
- `POST /api/ai/ask` with `{ "scan_id": "...", "question": "..." }` answers a short question using only that stored scan snapshot.

Each scan receives a backend-generated `scan_id` and is retained in memory for one hour. This prevents the frontend from supplying arbitrary scan evidence and keeps questions tied to the current domain. Summary responses are cached for 30 minutes.

## Fallback behavior

Provider absence, invalid keys, quota/rate limits, timeouts, malformed responses, and provider downtime return `fallback_used: true`. Deterministic templates provide a cautious summary and practical advice. Credential, payment, OTP, CVV, and UPI questions never receive permission to share secrets with an unverified site.

## Frontend

The `AI INSIGHT` tab shows the interpretation, main concerns, positive evidence, recommended action, and source labels. `ASK TRUSTSHIELD` provides a compact question-and-answer panel with suggested questions and a current-domain context banner. The scan result remains usable while an AI summary is loading.

## Boundaries

ML prediction is a statistical estimate from URL features. SHAP explains the ML model's feature contributions. LLM output is a human-friendly interpretation of fixed backend evidence. The LLM never creates or changes a TrustShield Score, probability, reputation result, or technical fact. It is not a replacement for independent verification or professional security review.
