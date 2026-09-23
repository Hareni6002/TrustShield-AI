import pytest

from app.ml import explainer
from app.ml.features import ML_FEATURE_NAMES, extract_feature_vector


@pytest.mark.parametrize("url", [
    "https://google.com",
    "https://github.com",
    "https://paypa1-login-security.xyz/login/verify",
])
def test_explanation_output_structure(url):
    result = explainer.explain_url(url)
    assert result["available"] is True
    assert result["method"] == "SHAP TreeExplainer"
    assert len(result["top_risk_factors"]) <= 5
    assert len(result["top_trust_factors"]) <= 5
    for factor in result["top_risk_factors"] + result["top_trust_factors"]:
        assert factor["feature"] in ML_FEATURE_NAMES
        assert isinstance(factor["impact"], float)
        assert "display_name" in factor
        assert "explanation" in factor


def test_official_domain_does_not_report_brand_impersonation():
    result = explainer.explain_url("https://google.com")
    features = {item["feature"] for item in result["top_risk_factors"]}
    assert "possible_brand_impersonation" not in features


def test_suspicious_url_exposes_lexical_factors():
    result = explainer.explain_url("https://amaz0n-account-verify.xyz")
    features = {item["feature"] for item in result["top_risk_factors"]}
    assert features.intersection({"suspicious_keyword_count", "tld_caution_indicator", "brand_similarity_score"})


def test_explanation_uses_canonical_feature_order(monkeypatch):
    vector = extract_feature_vector("https://example.com")
    captured = []

    class DummyExplainer:
        def shap_values(self, row):
            captured.append(row[0].tolist())
            return [[[0.0, 0.0] for _ in ML_FEATURE_NAMES]]

    monkeypatch.setattr(explainer, "_load_explainers", lambda: ([DummyExplainer()], None))
    result = explainer.explain_url("https://example.com", vector)
    assert result["available"] is True
    assert captured == [vector]


def test_explanation_failure_is_non_fatal(monkeypatch):
    monkeypatch.setattr(explainer, "_load_explainers", lambda: ([], "broken"))
    result = explainer.explain_url("https://example.com")
    assert result == {"available": False, "message": "broken"}
