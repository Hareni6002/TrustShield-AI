# Phase 2B — ML Debugging, False-Positive Reduction and Calibration

## Outcome

- Selected model: calibrated random forest (`2.0-calibrated`).
- Decision threshold: `0.55`, selected on the grouped validation set.
- Calibration: sigmoid calibration with 3-fold cross-validation.
- Held-out test FPR: `4.15%` (`62` false positives / `1,495` legitimate test URLs).
- Held-out test FNR: `7.28%` (`94` false negatives / `1,291` phishing test URLs).
- Held-out accuracy / precision / recall / F1 / ROC-AUC: `94.40% / 95.08% / 92.72% / 93.88% / 98.15%`.

## Root cause of false positives

The original model used a URL-level random split, allowing repeated domains and near-duplicate domain families to leak between train and evaluation. The source dataset also contains very few clean exact official-domain anchors. As a result, the forest relied heavily on URL-shape shortcuts such as subdomain count, digit count, HTTPS presence, hostname length, and URL length. Exact official domains could therefore receive high phishing scores even when the technical and brand signals were clean.

The feature audit found `38` legitimate versus `426` phishing rows with a perfect brand similarity score of `100`. That value was ambiguous: an exact official domain and a highly similar suspicious domain could both look like a strong model signal. The feature representation now encodes exact official matches separately and sets the similarity score to `0` for that safe case.

## Dataset and training changes

- Source: `ESDAUNG/PhishDataset`, cleaned to `19,729` rows (`9,960` legitimate and `9,769` phishing).
- Duplicate URL audit: no exact duplicate URLs; repeated registered domains remain, so evaluation is grouped by registered domain.
- Unique registered domains: `14,325`; `16` domains appeared with both labels.
- Split: `70%` train / `15%` validation / `15%` test, grouped by registered domain with random state `42`.
- Added `official_brand_domain_match` to the 29-feature schema.
- Added 30 repetitions of 10 curated exact official HTTPS domains to the training partitions only. Validation and test metrics remain source-only.
- Technical URL/domain/SSL/DNS/HTTP analysis and Phase 1 brand/lexical logic were not changed.

## Before and after

The previous URL-level random-split random forest reported accuracy `95.03%`, precision `95.40%`, recall `94.52%`, F1 `94.96%`, and ROC-AUC `98.56%`. Its saved model produced high false-positive probabilities for official domains such as Google (`0.777`), GitHub (`0.748`), Microsoft (`0.705`), and Amazon India (`0.765`).

The new grouped-split calibrated model reports slightly more conservative held-out metrics but is better aligned with production behavior: FPR is `4.15%`, the threshold is explicit, and the official-domain benchmark is no longer classified as phishing-like.

## Benchmark results

Legitimate benchmark (`ml-training/reports/legitimate_benchmark.csv`): all 10 URLs are `LEGITIMATE-LIKE`, with phishing probabilities from `0.219` to `0.309`.

Synthetic phishing benchmark (`ml-training/reports/synthetic_benchmark.csv`): all 5 URLs are `PHISHING-LIKE`, with phishing probabilities from `0.943` to `0.963`.

These synthetic URLs are offline test inputs, not live reputation lookups.

## Artifacts and verification

- Saved model: `backend/app/ml/phishing_model.joblib`
- Saved metadata: `backend/app/ml/model_metadata.json`
- Training copy: `ml-training/models/phishing_model.joblib`
- Metrics: `ml-training/reports/model_comparison.csv`
- Feature importance: `ml-training/reports/feature_importance.csv`
- Benchmarks: `ml-training/reports/legitimate_benchmark.csv` and `ml-training/reports/synthetic_benchmark.csv`
- Tests: `21 passed` in the backend suite; frontend lint and production build pass.

The API now exposes `signal_conflict` and `conflict_message` in ML analysis. The frontend only consumes that backend flag for the existing conflict panel; no visual redesign was made in Phase 2B.
