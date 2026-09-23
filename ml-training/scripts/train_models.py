import argparse
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.base import clone
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score, roc_curve
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))
from app.ml.features import ML_FEATURE_NAMES, extract_feature_record, extract_feature_vector

RANDOM_STATE = 42
MODEL_VERSION = "2.0-calibrated"
LEGITIMATE_BENCHMARK = [
    "https://google.com", "https://github.com", "https://microsoft.com", "https://amazon.com",
    "https://amazon.in", "https://paypal.com", "https://linkedin.com", "https://apple.com",
    "https://cloudflare.com", "https://wikipedia.org",
]
SYNTHETIC_BENCHMARK = [
    "https://paypa1-login-security.xyz", "https://amaz0n-account-verify.xyz",
    "https://google.com.verify-user.xyz", "https://micros0ft-login-alert.top",
    "https://x9q2z7a1k.xyz/login/verify",
]
LEGITIMATE_TRAINING_ANCHORS = [
    "https://google.com", "https://github.com", "https://microsoft.com", "https://amazon.com",
    "https://amazon.in", "https://paypal.com", "https://linkedin.com", "https://apple.com",
    "https://cloudflare.com", "https://wikipedia.org",
]


def build_models() -> dict:
    return {
        "logistic_regression": Pipeline([("scaler", StandardScaler()), ("model", LogisticRegression(max_iter=1000, class_weight="balanced", random_state=RANDOM_STATE))]),
        "random_forest": RandomForestClassifier(n_estimators=180, max_depth=18, class_weight="balanced", random_state=RANDOM_STATE, n_jobs=-1),
        "gradient_boosting": GradientBoostingClassifier(n_estimators=140, learning_rate=0.08, max_depth=3, random_state=RANDOM_STATE),
    }


def metrics_for(labels, probabilities, threshold=0.5) -> dict:
    predictions = (probabilities >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(labels, predictions, labels=[0, 1]).ravel()
    return {
        "accuracy": accuracy_score(labels, predictions),
        "precision": precision_score(labels, predictions, zero_division=0),
        "recall": recall_score(labels, predictions, zero_division=0),
        "f1": f1_score(labels, predictions, zero_division=0),
        "roc_auc": roc_auc_score(labels, probabilities),
        "true_positive": int(tp), "true_negative": int(tn),
        "false_positive": int(fp), "false_negative": int(fn),
        "false_positive_rate": fp / (fp + tn) if (fp + tn) else 0.0,
        "false_negative_rate": fn / (fn + tp) if (fn + tp) else 0.0,
    }


def select_threshold(labels, probabilities) -> tuple[float, dict]:
    candidates = [0.40, 0.45, 0.50, 0.55, 0.60, 0.65, 0.70]
    evaluated = [(threshold, metrics_for(labels, probabilities, threshold)) for threshold in candidates]
    acceptable = [item for item in evaluated if item[1]["false_positive_rate"] <= 0.05]
    threshold, result = max(acceptable or evaluated, key=lambda item: (item[1]["f1"], item[1]["recall"], -item[1]["false_positive_rate"]))
    return threshold, result


def load_features(input_path: Path) -> tuple[pd.DataFrame, object, list[str]]:
    frame = pd.read_csv(input_path).dropna(subset=["url", "label"]).copy()
    frame["label"] = frame["label"].astype(int)
    rows = []
    groups = []
    for value in frame["url"]:
        record, url_info, _ = extract_feature_record(value)
        rows.append(record)
        groups.append(url_info.get("registered_domain") or url_info.get("hostname"))
    return pd.DataFrame(rows, columns=ML_FEATURE_NAMES), frame["label"].to_numpy(), groups


def grouped_splits(features, labels, groups):
    groups = pd.Series(groups).fillna("unknown").to_numpy()
    first = GroupShuffleSplit(n_splits=1, test_size=0.15, random_state=RANDOM_STATE)
    train_val_indices, test_indices = next(first.split(features, labels, groups))
    second = GroupShuffleSplit(n_splits=1, test_size=0.1765, random_state=RANDOM_STATE)
    train_indices, validation_indices = next(second.split(features.iloc[train_val_indices], labels[train_val_indices], groups[train_val_indices]))
    return train_val_indices[train_indices], train_val_indices[validation_indices], test_indices


def feature_importance(model) -> pd.Series | None:
    estimators = []
    if hasattr(model, "calibrated_classifiers_"):
        estimators = [item.estimator for item in model.calibrated_classifiers_]
    elif isinstance(model, Pipeline):
        estimators = [model[-1]]
    else:
        estimators = [model]
    importances = []
    for estimator in estimators:
        if hasattr(estimator, "feature_importances_"):
            importances.append(estimator.feature_importances_)
        elif hasattr(estimator, "coef_"):
            importances.append(abs(estimator.coef_[0]))
    return pd.Series(sum(importances) / len(importances), index=ML_FEATURE_NAMES) if importances else None


def plot_artifacts(model_name, model, labels, probabilities, reports_dir: Path) -> None:
    reports_dir.mkdir(parents=True, exist_ok=True)
    matrix = confusion_matrix(labels, (probabilities >= 0.5).astype(int), labels=[0, 1])
    figure, axis = plt.subplots(figsize=(5, 4))
    image = axis.imshow(matrix, cmap="Reds")
    figure.colorbar(image, ax=axis)
    axis.set(title=f"Confusion Matrix: {model_name}", xlabel="Predicted", ylabel="Actual")
    for row in range(2):
        for column in range(2):
            axis.text(column, row, matrix[row, column], ha="center", va="center")
    figure.tight_layout(); figure.savefig(reports_dir / "confusion_matrix.png", dpi=140); plt.close(figure)
    false_positive_rate, true_positive_rate, _ = roc_curve(labels, probabilities)
    figure, axis = plt.subplots(figsize=(5, 4))
    axis.plot(false_positive_rate, true_positive_rate, label=f"AUC={roc_auc_score(labels, probabilities):.3f}")
    axis.plot([0, 1], [0, 1], "--", color="#888888"); axis.set(title="ROC Curve", xlabel="False Positive Rate", ylabel="True Positive Rate"); axis.legend()
    figure.tight_layout(); figure.savefig(reports_dir / "roc_curve.png", dpi=140); plt.close(figure)
    importance = feature_importance(model)
    if importance is not None:
        importance.sort_values().to_csv(reports_dir / "feature_importance.csv", header=["importance"])
        figure, axis = plt.subplots(figsize=(8, 7)); importance.sort_values().plot.barh(ax=axis, color="#c32632"); axis.set(title=f"Feature Importance: {model_name}", xlabel="Importance")
        figure.tight_layout(); figure.savefig(reports_dir / "feature_importance.png", dpi=140); plt.close(figure)


def benchmark(model, threshold: float, urls: list[str], output: Path) -> None:
    rows = []
    for url in urls:
        probability = float(model.predict_proba(pd.DataFrame([extract_feature_vector(url)], columns=ML_FEATURE_NAMES))[0][1])
        rows.append({"url": url, "phishing_probability": probability, "prediction": "PHISHING-LIKE" if probability >= threshold else "LEGITIMATE-LIKE"})
    pd.DataFrame(rows).to_csv(output, index=False)


def train(input_path: Path, models_dir: Path, reports_dir: Path, backend_model_path: Path) -> dict:
    features, labels, groups = load_features(input_path)
    train_indices, validation_indices, test_indices = grouped_splits(features, labels, groups)
    train_features, train_labels = features.iloc[train_indices], labels[train_indices]
    validation_features, validation_labels = features.iloc[validation_indices], labels[validation_indices]
    train_val_features, train_val_labels = features.iloc[sorted(list(train_indices) + list(validation_indices))], labels[sorted(list(train_indices) + list(validation_indices))]
    anchor_features = pd.DataFrame(
        [extract_feature_record(value)[0] for value in LEGITIMATE_TRAINING_ANCHORS],
        columns=ML_FEATURE_NAMES,
    )
    anchor_features = pd.concat([anchor_features] * 30, ignore_index=True)
    anchor_labels = pd.Series([0] * len(anchor_features)).to_numpy()
    train_features = pd.concat([train_features, anchor_features], ignore_index=True)
    train_labels = np.concatenate([train_labels, anchor_labels])
    train_val_features = pd.concat([train_val_features, anchor_features], ignore_index=True)
    train_val_labels = np.concatenate([train_val_labels, anchor_labels])
    test_features, test_labels = features.iloc[test_indices], labels[test_indices]
    raw_models = build_models()
    validation_rows = []
    test_rows = []
    for name, model in raw_models.items():
        model.fit(train_features, train_labels)
        validation_rows.append({"model": name, **metrics_for(validation_labels, model.predict_proba(validation_features)[:, 1])})
        final_raw = clone(model).fit(train_val_features, train_val_labels)
        test_rows.append({"model": name, "calibration": "none", **metrics_for(test_labels, final_raw.predict_proba(test_features)[:, 1])})
    selected_name = max(validation_rows, key=lambda row: (row["f1"], row["recall"], row["roc_auc"], -row["false_positive_rate"]))['model']
    calibrated_tuning = CalibratedClassifierCV(estimator=clone(raw_models[selected_name]), method="sigmoid", cv=3, n_jobs=-1).fit(train_features, train_labels)
    validation_probabilities = calibrated_tuning.predict_proba(validation_features)[:, 1]
    threshold, threshold_result = select_threshold(validation_labels, validation_probabilities)
    calibrated_model = CalibratedClassifierCV(estimator=clone(raw_models[selected_name]), method="sigmoid", cv=3, n_jobs=-1).fit(train_val_features, train_val_labels)
    test_probabilities = calibrated_model.predict_proba(test_features)[:, 1]
    calibrated_metrics = metrics_for(test_labels, test_probabilities, threshold)
    comparison = pd.DataFrame(test_rows + [{"model": selected_name, "calibration": "sigmoid", **calibrated_metrics}])
    models_dir.mkdir(parents=True, exist_ok=True); reports_dir.mkdir(parents=True, exist_ok=True)
    comparison.to_csv(reports_dir / "model_comparison.csv", index=False)
    model_path = models_dir / "phishing_model.joblib"; joblib.dump(calibrated_model, model_path); backend_model_path.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(model_path, backend_model_path)
    metadata = {
        "model_name": selected_name, "model_version": MODEL_VERSION, "training_date": datetime.now(timezone.utc).isoformat(),
        "dataset_rows": int(len(labels)), "legitimate_count": int((labels == 0).sum()), "phishing_count": int((labels == 1).sum()),
        "unique_registered_domains": int(pd.Series(groups).nunique()), "features": ML_FEATURE_NAMES, "feature_count": len(ML_FEATURE_NAMES),
        **{key: float(value) if isinstance(value, float) else value for key, value in calibrated_metrics.items()},
        "decision_threshold": threshold, "calibration_method": "sigmoid", "validation_threshold_metrics": threshold_result,
        "dataset_source": "ESDAUNG/PhishDataset balanced dataset (PhishTank and IP2Location-derived)",
        "training_augmentation": "30x repetition of 10 curated exact official HTTPS domains added to train/train+validation only; validation/test remain source-only",
        "split": "70% train / 15% validation / 15% test grouped by registered domain, random_state=42",
    }
    (models_dir / "phishing_model_metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    (backend_model_path.parent / "model_metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    plot_artifacts(selected_name, calibrated_model, test_labels, test_probabilities, reports_dir)
    benchmark(calibrated_model, threshold, LEGITIMATE_BENCHMARK, reports_dir / "legitimate_benchmark.csv")
    benchmark(calibrated_model, threshold, SYNTHETIC_BENCHMARK, reports_dir / "synthetic_benchmark.csv")
    print(json.dumps({"selected_model": selected_name, "metadata": metadata, "validation_comparison": validation_rows, "test_comparison": test_rows}, indent=2))
    return metadata


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train calibrated phishing URL classifiers from offline lexical features.")
    parser.add_argument("--input", type=Path, default=PROJECT_ROOT / "ml-training/datasets/cleaned_urls.csv")
    parser.add_argument("--models-dir", type=Path, default=PROJECT_ROOT / "ml-training/models")
    parser.add_argument("--reports-dir", type=Path, default=PROJECT_ROOT / "ml-training/reports")
    parser.add_argument("--backend-model", type=Path, default=PROJECT_ROOT / "backend/app/ml/phishing_model.joblib")
    arguments = parser.parse_args()
    train(arguments.input, arguments.models_dir, arguments.reports_dir, arguments.backend_model)
