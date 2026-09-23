from __future__ import annotations

import sys
from pathlib import Path

import joblib
import matplotlib
import numpy as np
import pandas as pd

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import shap

PROJECT_ROOT = Path(__file__).resolve().parents[2]
BACKEND_ROOT = PROJECT_ROOT / "backend"
sys.path.insert(0, str(BACKEND_ROOT))

from app.ml.features import ML_FEATURE_NAMES, extract_feature_vector


MODEL_PATH = BACKEND_ROOT / "app" / "ml" / "phishing_model.joblib"
DATASET_PATH = PROJECT_ROOT / "ml-training" / "datasets" / "cleaned_urls.csv"
REPORT_DIR = PROJECT_ROOT / "ml-training" / "reports"


def main() -> None:
    model = joblib.load(MODEL_PATH)
    dataset = pd.read_csv(DATASET_PATH)
    dataset = dataset.sample(n=min(5, len(dataset)), random_state=42)
    matrix = np.asarray([extract_feature_vector(value) for value in dataset["url"]], dtype=float)
    explainers = [shap.TreeExplainer(item.estimator) for item in model.calibrated_classifiers_]
    contributions = []
    for explainer in explainers:
        values = np.asarray(explainer.shap_values(matrix))
        contributions.append(values[:, :, 1] if values.ndim == 3 else values)
    importance = np.mean(np.abs(np.mean(np.asarray(contributions), axis=0)), axis=0)
    report = pd.DataFrame({"feature": ML_FEATURE_NAMES, "mean_abs_shap": importance}).sort_values("mean_abs_shap", ascending=False)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    report.to_csv(REPORT_DIR / "shap_feature_importance.csv", index=False)
    top = report.head(15).sort_values("mean_abs_shap")
    plt.figure(figsize=(9, 6))
    plt.barh(top["feature"], top["mean_abs_shap"], color="#e42b37")
    plt.xlabel("Mean absolute SHAP value")
    plt.title("Global SHAP feature importance")
    plt.tight_layout()
    plt.savefig(REPORT_DIR / "shap_feature_importance.png", dpi=160)
    plt.close()


if __name__ == "__main__":
    main()
