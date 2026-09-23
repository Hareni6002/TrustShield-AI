# Phase 2: Machine-Learning Phishing Detection

## Dataset

Training uses the public balanced `ESDAUNG/PhishDataset` workbook, described as URLs collected from PhishTank and legitimate URLs derived from IP2Location. The source artifact is stored locally at `ml-training/datasets/source_phishdataset_balanced.xlsx`. The source documents `0` as legitimate and `1` as phishing.

The preparation pipeline produced `ml-training/datasets/cleaned_urls.csv` with 19,729 unique valid URLs: 9,960 legitimate and 9,769 phishing. It removed 46 duplicate rows and 225 malformed rows.

## Offline Features

The first model uses only reproducible URL-derived features. It does not use WHOIS, SSL, DNS, HTTP status, reputation services, or live page content. The canonical 28-feature order is defined in `backend/app/ml/features.py` and is shared by training and runtime prediction.

Features include URL lengths and symbols, subdomain and HTTPS/IP flags, suspicious terms, domain digit/entropy/randomness measures, suspicious path count, brand similarity and impersonation flags, shortener detection, and cautionary TLD indicator.

## Models and Metrics

The training script compares Logistic Regression, Random Forest, and Gradient Boosting using an 80/20 stratified split with `random_state=42`. Actual metrics are saved in `ml-training/reports/model_comparison.csv`.

The selected model is Random Forest based on the combined F1, recall, and ROC-AUC comparison. Its held-out metrics are recorded in `ml-training/models/phishing_model_metadata.json`. The selected decision threshold is loaded from that metadata at runtime; it is not duplicated in the API code.

Generated visual artifacts include a confusion matrix, ROC curve, and feature-importance plot in `ml-training/reports/`.

## API Integration

`POST /api/scan` now returns an `ml_analysis` object containing model availability, cautious prediction label, phishing probability, legitimate probability, model version, and any non-fatal model error.

`GET /api/model-info` returns model name/version, feature count, held-out metrics, dataset size, and decision threshold.

The ML result remains separate from `technical_trust_score` and `lexical_risk_score`. No final combined TrustShield score is presented yet. Official-brand evidence is shown alongside ML output rather than overriding it.

## Limitations

- The dataset is historical and its labels and collection assumptions may not represent current web behavior.
- URL-only models can miss page content, infrastructure, reputation, and newly emerging attack patterns.
- Exact duplicate removal does not eliminate every near-duplicate or domain-family leakage risk.
- Metrics are held-out results from this dataset, not a guarantee of production accuracy.
- SHAP explainability, LLM explanations, reputation APIs, and Safe Browsing are intentionally deferred.
