from __future__ import annotations

from typing import Any


def deterministic_summary(context: dict[str, Any]) -> dict[str, Any]:
    risk_level = context.get("trustshield_risk_level", "UNKNOWN")
    technical = context.get("technical", {})
    ml = context.get("ml", {})
    brand = context.get("brand", {})
    lexical = context.get("lexical", {})
    reputation = context.get("reputation", {})
    concerns: list[str] = []
    positives: list[str] = []
    sources = ["Technical Evidence", "ML Evidence", "External Reputation"]
    if brand.get("possible_impersonation"):
        concerns.append("Brand intelligence detected possible impersonation.")
    if brand.get("possible_typosquatting"):
        concerns.append("Brand intelligence detected possible typosquatting.")
    if lexical.get("risk_score", 0) >= 40:
        concerns.append("Lexical analysis found elevated URL or domain-pattern risk.")
    if reputation.get("evidence_count", 0):
        concerns.append("External reputation sources reported threat evidence.")
    if context.get("signal_conflict", {}).get("detected"):
        concerns.append(context.get("signal_conflict", {}).get("message") or "Signals disagree and require additional verification.")
    if technical.get("ssl_valid"):
        positives.append("The connection uses a valid SSL certificate; this supports encryption only.")
    if technical.get("domain_age_days") is not None and technical["domain_age_days"] >= 365:
        positives.append("The domain has been registered for at least one year.")
    if reputation.get("evidence_count", 0) == 0 and reputation.get("confidence") == "HIGH":
        positives.append("Available reputation providers reported no known threat match.")
    if ml.get("phishing_probability") is not None and ml["phishing_probability"] < 0.25:
        positives.append("The ML model reports a low phishing probability.")
    if concerns:
        summary = "The scan found evidence that warrants caution. " + " ".join(concerns[:2])
    else:
        summary = "Technical, ML, and available reputation signals do not show a strong threat pattern. Continue to verify sensitive actions independently."
    if risk_level in {"HIGH RISK", "SUSPICIOUS"}:
        action = "Do not enter passwords, OTPs, payment details, or UPI credentials. Open the official service by typing its known domain manually."
    elif risk_level in {"ELEVATED RISK", "CAUTION"}:
        action = "Avoid entering passwords, OTPs, card details, or UPI credentials until the website is independently verified."
    else:
        action = "Normal browsing appears lower risk based on available evidence, but verify sensitive transactions independently."
    return {"ai_available": False, "available": False, "fallback_used": True, "summary": summary, "main_concerns": concerns[:5], "positive_evidence": positives[:5], "recommended_action": action, "sources": sources}
