from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from math import prod
from typing import Any

from app.services.reputation.google_safe_browsing import lookup as google_lookup
from app.services.reputation.urlhaus import lookup as urlhaus_lookup
from app.services.reputation.virustotal import lookup as virustotal_lookup


def _provider_risk(name: str, provider: dict[str, Any]) -> int:
    if provider.get("status") == "threat_found":
        if name == "google_safe_browsing":
            return 95
        if name == "urlhaus":
            return 90
        malicious = int(provider.get("malicious", 0))
        suspicious = int(provider.get("suspicious", 0))
        return min(95, 45 + malicious * 8 + suspicious * 4) if malicious else min(45, suspicious * 6)
    return 0


def _reputation_level(score: int) -> str:
    if score >= 70:
        return "HIGH"
    if score >= 35:
        return "CAUTION"
    return "LOW"


def _confidence(providers: dict[str, dict[str, Any]], threat_sources: int) -> str:
    available = sum(bool(provider.get("available")) for provider in providers.values())
    if available >= 3 and (threat_sources >= 2 or threat_sources == 0):
        return "HIGH"
    if available >= 2:
        return "MEDIUM"
    return "LOW"


def analyze_reputation(normalized_url: str) -> dict[str, Any]:
    jobs = {
        "virustotal": virustotal_lookup,
        "google_safe_browsing": google_lookup,
        "urlhaus": urlhaus_lookup,
    }
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {name: executor.submit(lookup, normalized_url) for name, lookup in jobs.items()}
        providers = {}
        for name, future in futures.items():
            try:
                providers[name] = future.result(timeout=8)
            except Exception:
                providers[name] = {"available": False, "configured": True, "provider": name, "status": "lookup_failed", "message": "Provider lookup failed."}
    risks = [_provider_risk(name, provider) for name, provider in providers.items()]
    reputation_risk_score = round((1 - prod(1 - risk / 100 for risk in risks)) * 100)
    threat_sources = sum(risk > 0 for risk in risks)
    available = sum(bool(provider.get("available")) for provider in providers.values())
    reputation_trust_score = (
        100 - reputation_risk_score
        if threat_sources
        else 50
        if available
        else None
    )
    return {
        "providers_checked": len(providers),
        "providers_available": available,
        "threat_sources": threat_sources,
        "external_threat_evidence_count": threat_sources,
        "reputation_risk_score": max(0, min(100, reputation_risk_score)),
        "reputation_level": _reputation_level(reputation_risk_score),
        "reputation_confidence": _confidence(providers, threat_sources),
        "reputation_trust_score": reputation_trust_score,
        "providers": providers,
    }


def fuse_trustshield_score(
    technical_trust_score: int,
    lexical_risk_score: int,
    phishing_probability: float | None,
    reputation_analysis: dict[str, Any],
) -> dict[str, Any]:
    components = [("technical", float(technical_trust_score), 0.25), ("lexical", 100 - float(lexical_risk_score), 0.20)]
    if phishing_probability is not None:
        components.append(("machine_learning", 100 - phishing_probability * 100, 0.25))
    if reputation_analysis.get("reputation_trust_score") is not None:
        components.append(("reputation", float(reputation_analysis["reputation_trust_score"]), 0.30))
    total_weight = sum(weight for _, _, weight in components)
    score = round(sum(value * weight for _, value, weight in components) / total_weight)
    if score >= 80:
        risk_level = "LOW OBSERVED RISK"
    elif score >= 60:
        risk_level = "CAUTION"
    elif score >= 40:
        risk_level = "ELEVATED RISK"
    elif score >= 20:
        risk_level = "SUSPICIOUS"
    else:
        risk_level = "HIGH RISK"
    reputation_risk = reputation_analysis["reputation_risk_score"]
    ml_conflict = phishing_probability is not None and phishing_probability >= 0.65 and reputation_risk < 20 and reputation_analysis.get("providers_available", 0) > 0
    reputation_conflict = reputation_risk >= 45 and technical_trust_score >= 80
    signal_conflict = ml_conflict or reputation_conflict
    if reputation_conflict:
        conflict_message = "Technical signals appear normal, but external reputation sources report threat indicators."
    elif ml_conflict:
        conflict_message = "The machine-learning model reports elevated risk while available reputation sources show no matching threat record."
    else:
        conflict_message = None
    return {
        "trustshield_score": max(0, min(100, score)),
        "trustshield_risk_level": risk_level,
        "signal_conflict": signal_conflict,
        "conflict_message": conflict_message,
        "score_components": {name: round(value, 2) for name, value, _ in components},
    }
