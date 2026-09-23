from __future__ import annotations

from functools import lru_cache
from time import perf_counter
from typing import Any

import numpy as np

from app.ml.features import ML_FEATURE_NAMES, extract_feature_record, extract_feature_vector
from app.ml.predictor import _load_artifacts


FEATURE_DISPLAY_NAMES = {
    "url_length": "URL Length",
    "hostname_length": "Hostname Length",
    "path_length": "Path Length",
    "query_length": "Query Length",
    "dot_count": "Dot Count",
    "hyphen_count": "Hyphen Count",
    "underscore_count": "Underscore Count",
    "digit_count": "Digits in URL",
    "special_character_count": "Special Characters",
    "subdomain_count": "Subdomain Count",
    "has_https": "HTTPS Enabled",
    "has_ip_address": "IP Address Used",
    "has_at_symbol": "@ Symbol in URL",
    "has_double_slash_path": "Double-Slash Path",
    "has_punycode": "Punycode Domain",
    "suspicious_keyword_count": "Suspicious URL Terms",
    "domain_digit_count": "Digits in Domain",
    "domain_digit_ratio": "Domain Digit Ratio",
    "domain_hyphen_count": "Domain Hyphens",
    "domain_entropy": "Domain Entropy",
    "domain_randomness_score": "Domain Randomness",
    "suspicious_path_keyword_count": "Suspicious Path Terms",
    "brand_similarity_score": "Brand Similarity",
    "official_brand_domain_match": "Official Brand Match",
    "possible_brand_impersonation": "Possible Brand Impersonation",
    "possible_typosquatting": "Possible Typosquatting",
    "misleading_subdomain_detected": "Misleading Subdomain",
    "url_shortener_detected": "URL Shortener Detected",
    "tld_caution_indicator": "Cautionary TLD",
}


def _value_for_display(value: float) -> int | float:
    return int(value) if float(value).is_integer() else round(float(value), 4)


def _explanation_for(feature: str, value: float, impact: float) -> str:
    active = value > 0
    if feature == "possible_brand_impersonation" and active:
        return "Possible brand impersonation increased the phishing risk."
    if feature == "possible_typosquatting" and active:
        return "The domain resembles a known brand with possible typosquatting."
    if feature == "misleading_subdomain_detected" and active:
        return "A brand-like subdomain points toward a different registered domain."
    if feature in {"suspicious_keyword_count", "suspicious_path_keyword_count"} and active:
        return "The URL contains multiple suspicious login or verification terms."
    if feature == "domain_randomness_score" and active:
        return "The domain structure is unusually random."
    if feature == "domain_entropy" and value >= 3.5:
        return "The domain has a high character-entropy pattern."
    if feature == "has_https" and active and impact < 0:
        return "HTTPS reduced the model's risk estimate slightly."
    if feature == "official_brand_domain_match" and active and impact < 0:
        return "An official brand-domain match reduced the model's risk estimate."
    if feature == "tld_caution_indicator" and active:
        return "The top-level domain is associated with additional caution."
    if feature == "has_ip_address" and active:
        return "The URL uses an IP address instead of a conventional domain."
    if feature == "url_length" and value >= 80:
        return "The URL is unusually long and structurally complex."
    if feature == "subdomain_count" and value >= 2:
        return "The URL contains multiple subdomain levels."
    if impact > 0:
        return f"{FEATURE_DISPLAY_NAMES.get(feature, feature)} increased the phishing risk."
    return f"{FEATURE_DISPLAY_NAMES.get(feature, feature)} reduced the model's risk estimate."


def _factor(feature: str, value: float, impact: float) -> dict[str, Any]:
    return {
        "feature": feature,
        "display_name": FEATURE_DISPLAY_NAMES.get(feature, feature),
        "value": _value_for_display(value),
        "impact": round(float(impact), 6),
        "explanation": _explanation_for(feature, value, impact),
    }


def _summary(risk_factors: list[dict[str, Any]], trust_factors: list[dict[str, Any]]) -> list[str]:
    parts = []
    if risk_factors:
        names = ", ".join(item["display_name"].lower() for item in risk_factors[:3])
        parts.append(f"Most of the model's phishing risk came from {names}.")
    if trust_factors:
        names = ", ".join(item["display_name"].lower() for item in trust_factors[:3])
        parts.append(f"The strongest trust signals were {names}.")
    return parts or ["The model did not identify a strong feature contribution."]


@lru_cache(maxsize=1)
def _load_explainers() -> tuple[list[Any], str | None]:
    try:
        import shap

        model, metadata, error = _load_artifacts()
        if model is None or metadata is None:
            return [], error or "The phishing model is not available."
        estimators = []
        calibrated = getattr(model, "calibrated_classifiers_", None)
        if calibrated:
            estimators = [item.estimator for item in calibrated]
        elif hasattr(model, "estimators_"):
            estimators = [model]
        if not estimators:
            return [], "The underlying tree estimator is not available."
        return [shap.TreeExplainer(estimator) for estimator in estimators], None
    except Exception as error:
        return [], str(error)


def explain_url(url: str, vector: list[float] | None = None) -> dict[str, Any]:
    started_at = perf_counter()
    try:
        import shap

        explainers, error = _load_explainers()
        if error or not explainers:
            return {"available": False, "message": error or "Model explanation is currently unavailable."}
        values = vector or extract_feature_vector(url)
        row = np.asarray([values], dtype=float)
        contributions = []
        for explainer in explainers:
            shap_values = np.asarray(explainer.shap_values(row))
            if shap_values.ndim == 3:
                shap_values = shap_values[:, :, 1]
            contributions.append(shap_values[0])
        mean_contributions = np.mean(np.asarray(contributions), axis=0)
        factors = [
            (feature, float(value), float(impact))
            for feature, value, impact in zip(ML_FEATURE_NAMES, values, mean_contributions)
            if abs(impact) > 1e-7
        ]
        risk_factors = [_factor(*item) for item in sorted(factors, key=lambda item: item[2], reverse=True) if item[2] > 0][:5]
        trust_factors = [_factor(*item) for item in sorted(factors, key=lambda item: abs(item[2]), reverse=True) if item[2] < 0][:5]
        return {
            "available": True,
            "method": "SHAP TreeExplainer",
            "top_risk_factors": risk_factors,
            "top_trust_factors": trust_factors,
            "summary": _summary(risk_factors, trust_factors),
            "explanation_time_ms": round((perf_counter() - started_at) * 1000, 2),
        }
    except Exception:
        return {"available": False, "message": "Model explanation is currently unavailable."}


def explain_features(features: dict[str, float]) -> dict[str, Any]:
    values = [float(features[name]) for name in ML_FEATURE_NAMES]
    return explain_url("", values)


def feature_record_for_url(url: str) -> dict[str, float]:
    record, _, _ = extract_feature_record(url)
    return {name: float(record[name]) for name in ML_FEATURE_NAMES}
