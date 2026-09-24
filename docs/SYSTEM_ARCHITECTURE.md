# TrustShield AI — System Architecture

```mermaid
flowchart TD
  U[User] --> F[React Frontend]
  F --> API[FastAPI]
  API --> E[Analysis Engines]
  E --> ML[ML Prediction]
  ML --> SHAP[Explainability]
  E --> REP[Reputation APIs]
  E --> SCORE[Trust Fusion]
  SCORE --> AI[AI Explanation / Fallback]
  API --> DB[(SQLite)]
  DB --> PDF[Stored Scan PDF]
  API --> F
```

The scan endpoint validates before network access, combines independent evidence into the existing TrustShield score, stores the completed payload for history/report export, and returns the structured result needed by the frontend.
