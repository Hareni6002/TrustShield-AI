from __future__ import annotations

from typing import Any


def _provider_context(provider: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": provider.get("status"),
        "message": provider.get("message"),
        "malicious": provider.get("malicious"),
        "suspicious": provider.get("suspicious"),
        "harmless": provider.get("harmless"),
        "threat_detected": provider.get("threat_detected"),
        "url_status": provider.get("url_status"),
        "threat": provider.get("threat"),
        "tags": provider.get("tags", [])[:10],
    }


def build_context(scan: dict[str, Any]) -> dict[str, Any]:
    url = scan.get("url_analysis", {})
    domain = scan.get("domain_analysis", {})
    ssl = scan.get("ssl_analysis", {})
    dns = scan.get("dns_analysis", {})
    http = scan.get("http_analysis", {})
    brand = scan.get("brand_analysis", {})
    lexical = scan.get("lexical_analysis", {})
    ml = scan.get("ml_analysis", {})
    explanation = scan.get("explainability", {})
    reputation = scan.get("reputation_analysis", {})
    providers = reputation.get("providers", {})
    return {
        "url": scan.get("normalized_url"),
        "registered_domain": domain.get("domain_name"),
        "trustshield_score": scan.get("trustshield_score"),
        "trustshield_risk_level": scan.get("trustshield_risk_level"),
        "technical": {"trust_score": scan.get("technical_trust_score"), "risk_level": scan.get("risk_level"), "ssl_valid": ssl.get("ssl_valid"), "ssl_available": ssl.get("ssl_available"), "dns_resolves": dns.get("dns_resolves"), "domain_age_days": domain.get("domain_age_days"), "redirect_count": http.get("redirect_count"), "http_status": http.get("http_status")},
        "brand": {"detected_brand": brand.get("detected_brand"), "possible_impersonation": brand.get("possible_brand_impersonation"), "possible_typosquatting": brand.get("possible_typosquatting"), "misleading_subdomain": brand.get("misleading_subdomain_detected")},
        "lexical": {"risk_score": lexical.get("lexical_risk_score"), "risk_level": lexical.get("lexical_risk_level"), "suspicious_path_keywords": lexical.get("suspicious_path_keywords", [])[:10], "entropy": lexical.get("domain_entropy"), "randomness": lexical.get("domain_randomness_score")},
        "ml": {"prediction": ml.get("prediction"), "phishing_probability": ml.get("phishing_probability"), "legitimate_probability": ml.get("legitimate_probability")},
        "shap": {"top_risk_factors": [{"display_name": item.get("display_name"), "impact": item.get("impact")} for item in explanation.get("top_risk_factors", [])[:5]], "top_trust_factors": [{"display_name": item.get("display_name"), "impact": item.get("impact")} for item in explanation.get("top_trust_factors", [])[:5]]},
        "reputation": {"risk_score": reputation.get("reputation_risk_score"), "level": reputation.get("reputation_level"), "evidence_count": reputation.get("external_threat_evidence_count"), "confidence": reputation.get("reputation_confidence"), "providers": {name: _provider_context(value) for name, value in providers.items()}},
        "signal_conflict": {"detected": scan.get("signal_conflict", False), "message": scan.get("conflict_message")},
    }
