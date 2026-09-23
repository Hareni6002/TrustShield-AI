# Phase 3: Explainable AI

TrustShield AI now explains the phishing model's prediction with SHAP feature contributions.

## What SHAP does

SHAP (SHapley Additive exPlanations) assigns each input feature a contribution relative to the model's baseline. Positive values increase the phishing prediction and negative values reduce it.

## Model and explainer

The trained model is a `CalibratedClassifierCV` containing Random Forest estimators. The API keeps the calibrated classifier for the reported phishing probability. Explanations use `shap.TreeExplainer` on each underlying Random Forest and average their class-1 contributions. This keeps the feature order identical to `ML_FEATURE_NAMES` while making the calibration distinction explicit.

## API output

`POST /api/scan` now includes `explainability` with `available`, `method`, up to five `top_risk_factors`, up to five `top_trust_factors`, deterministic `summary` text, and approximate `explanation_time_ms`. A SHAP failure returns `available: false` without failing the scan.

Each factor includes the canonical feature name, a readable display name, raw feature value, numeric impact, and a deterministic human-friendly explanation. Examples include `Digits in Domain`, `Suspicious URL Terms`, and `Possible Typosquatting`.

## Frontend

The `AI EXPLANATION` tab displays the model probability, risk-increasing and trust-supporting factors, animated zero-centered bars, and the generated summary. Technical evidence remains in the Technical, Domain, Brand, Lexical, and Website Content tabs.

## Limitations

SHAP explains the ML model only. It is not a live reputation check and does not replace SSL, DNS, WHOIS, HTTP, or content evidence. The calibrated probability and tree-model explanation are related but not numerically identical because the explanation intentionally targets the underlying Random Forest estimators.
