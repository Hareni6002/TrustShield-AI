import json
from functools import lru_cache
from pathlib import Path

import joblib
import pandas as pd

from app.ml.features import ML_FEATURE_NAMES, extract_feature_vector


MODEL_PATH = Path(__file__).with_name("phishing_model.joblib")
METADATA_PATH = Path(__file__).with_name("model_metadata.json")


@lru_cache(maxsize=1)
def _load_artifacts() -> tuple[object | None, dict | None, str | None]:
    if not MODEL_PATH.exists() or not METADATA_PATH.exists():
        return None, None, "The phishing model is not available."
    try:
        metadata = json.loads(METADATA_PATH.read_text(encoding="utf-8"))
        if metadata.get("features") != ML_FEATURE_NAMES:
            return None, None, "The model feature schema does not match the runtime schema."
        model = joblib.load(MODEL_PATH)
        if getattr(model, "n_features_in_", len(ML_FEATURE_NAMES)) != len(ML_FEATURE_NAMES):
            return None, None, "The model feature count does not match the runtime schema."
        return model, metadata, None
    except Exception as error:
        return None, None, str(error)


def predict_url(url: str, vector: list[float] | None = None) -> dict:
    model, metadata, error = _load_artifacts()
    if model is None or metadata is None:
        return {
            "model_available": False,
            "prediction": "MODEL-UNAVAILABLE",
            "phishing_probability": None,
            "legitimate_probability": None,
            "model_version": None,
            "error": error,
        }
    try:
        feature_vector = vector or extract_feature_vector(url)
        feature_frame = pd.DataFrame([feature_vector], columns=ML_FEATURE_NAMES)
        probabilities = model.predict_proba(feature_frame)[0]
        phishing_probability = float(probabilities[1])
        legitimate_probability = float(probabilities[0])
        threshold = float(metadata.get("decision_threshold", 0.5))
        return {
            "model_available": True,
            "prediction": "PHISHING-LIKE" if phishing_probability >= threshold else "LEGITIMATE-LIKE",
            "phishing_probability": phishing_probability,
            "legitimate_probability": legitimate_probability,
            "model_version": metadata.get("model_version"),
            "error": None,
        }
    except Exception as error:
        return {
            "model_available": False,
            "prediction": "MODEL-UNAVAILABLE",
            "phishing_probability": None,
            "legitimate_probability": None,
            "model_version": metadata.get("model_version"),
            "error": str(error),
        }


def model_info() -> dict:
    _, metadata, error = _load_artifacts()
    if metadata is None:
        return {
            "model_available": False,
            "error": error,
        }
    return {
        "model_available": True,
        "model_name": metadata.get("model_name"),
        "model_version": metadata.get("model_version"),
        "feature_count": metadata.get("feature_count"),
        "accuracy": metadata.get("accuracy"),
        "precision": metadata.get("precision"),
        "recall": metadata.get("recall"),
        "f1": metadata.get("f1"),
        "roc_auc": metadata.get("roc_auc"),
        "training_dataset_size": metadata.get("dataset_rows"),
        "decision_threshold": metadata.get("decision_threshold"),
        "explainability_available": True,
        "explainability_method": "SHAP TreeExplainer",
    }
