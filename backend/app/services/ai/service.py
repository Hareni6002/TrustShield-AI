from __future__ import annotations

import json
from hashlib import sha256
from threading import Lock
from time import monotonic
from typing import Any

from app.services.ai.context_builder import build_context
from app.services.ai.base import AIProviderError
from app.services.ai.prompts import SYSTEM_PROMPT, question_prompt, summary_prompt
from app.services.ai.provider import get_provider
from app.services.ai.safety import deterministic_summary


SUMMARY_CACHE_TTL = 30 * 60
_summary_cache: dict[str, tuple[float, dict[str, Any]]] = {}
_cache_lock = Lock()


def _cache_key(context: dict[str, Any]) -> str:
    return sha256(json.dumps(context, sort_keys=True, default=str).encode()).hexdigest()


def _cached_summary(key: str) -> dict[str, Any] | None:
    with _cache_lock:
        item = _summary_cache.get(key)
        if not item:
            return None
        created_at, summary = item
        if monotonic() - created_at >= SUMMARY_CACHE_TTL:
            _summary_cache.pop(key, None)
            return None
        return summary


def _store_summary(key: str, summary: dict[str, Any]) -> None:
    with _cache_lock:
        _summary_cache[key] = (monotonic(), summary)


def _parse_json(text: str) -> dict[str, Any]:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.split("\n", 1)[1].rsplit("```", 1)[0]
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start < 0 or end <= start:
        raise ValueError("The AI response was not JSON.")
    value = json.loads(cleaned[start:end + 1])
    if not isinstance(value, dict):
        raise ValueError("The AI response was not an object.")
    return value


def generate_summary(scan: dict[str, Any]) -> dict[str, Any]:
    context = build_context(scan)
    fallback = deterministic_summary(context)
    provider = get_provider()
    if provider is None:
        return fallback
    key = _cache_key(context)
    cached = _cached_summary(key)
    if cached is not None:
        return cached
    try:
        generated = _parse_json(provider.generate(SYSTEM_PROMPT, summary_prompt(context), 600))
        result = {
            "ai_available": True,
            "available": True,
            "fallback_used": False,
            "summary": str(generated.get("summary") or fallback["summary"]),
            "main_concerns": [str(item) for item in generated.get("main_concerns", [])][:5],
            "positive_evidence": [str(item) for item in generated.get("positive_evidence", [])][:5],
            "recommended_action": str(generated.get("recommended_action") or fallback["recommended_action"]),
            "sources": [str(item) for item in generated.get("sources", fallback["sources"])][:6],
        }
        _store_summary(key, result)
        return result
    except (AIProviderError, ValueError, TypeError, json.JSONDecodeError):
        return fallback


def _deterministic_answer(question: str, context: dict[str, Any]) -> str:
    question_lower = question.lower()
    risk_level = context.get("trustshield_risk_level", "UNKNOWN")
    reputation = context.get("reputation", {})
    ml = context.get("ml", {})
    technical = context.get("technical", {})
    if any(word in question_lower for word in ["password", "login", "otp", "card", "payment", "pay", "upi"]):
        if risk_level in {"HIGH RISK", "SUSPICIOUS", "ELEVATED RISK", "CAUTION"}:
            return "Do not enter passwords, OTPs, card details, CVV, or UPI PIN on this site until it is independently verified. Use the official service's known domain or app instead."
        return "The available evidence does not prove this site is safe for credentials or payments. Verify the domain independently and use a known official route before entering sensitive information."
    if "ssl" in question_lower or "certificate" in question_lower:
        if technical.get("ssl_valid"):
            return "The scan found a valid SSL certificate. That means the connection is encrypted, but SSL alone does not prove that the website is legitimate."
        return "A valid SSL result was not available for this scan. Treat the connection status as unavailable and verify the official domain before sharing information."
    if "virustotal" in question_lower or "external" in question_lower or "blacklist" in question_lower:
        provider = reputation.get("providers", {}).get("virustotal", {})
        if provider.get("status") in {"not_configured", "lookup_failed", "rate_limited", "invalid_key"}:
            return "VirusTotal data was unavailable for this scan. That is not the same as a clean result; use the other evidence and verify the site independently."
        if provider.get("malicious", 0) or provider.get("suspicious", 0):
            return f"VirusTotal reported {provider.get('malicious', 0)} malicious and {provider.get('suspicious', 0)} suspicious detections in the scan evidence. Avoid credentials and payment information."
        return "VirusTotal did not report malicious or suspicious detections in the available result, but a clean provider result is not proof of safety."
    if "ml" in question_lower or "model" in question_lower:
        probability = ml.get("phishing_probability")
        return f"The ML model reported a phishing probability of {round(probability * 100)}%. This is a model estimate based on URL features, not a confirmed reputation verdict." if probability is not None else "The ML model result was unavailable for this scan."
    if context.get("signal_conflict", {}).get("detected"):
        return context.get("signal_conflict", {}).get("message") or "The scan contains conflicting signals. Technical checks, ML patterns, and external reputation sources evaluate different evidence, so verify the site independently."
    return deterministic_summary(context)["summary"] + " Ask about SSL, the ML model, or external reputation for a more specific explanation."


def answer_question(scan: dict[str, Any], question: str) -> dict[str, Any]:
    context = build_context(scan)
    fallback = {"ai_available": False, "available": False, "fallback_used": True, "answer": _deterministic_answer(question, context), "sources": ["Technical Evidence", "ML Evidence", "External Reputation"]}
    provider = get_provider()
    if provider is None:
        return fallback
    try:
        answer = provider.generate(SYSTEM_PROMPT, question_prompt(context, question), 450)
        if not answer:
            raise AIProviderError("Empty AI response.")
        return {"ai_available": True, "available": True, "fallback_used": False, "answer": answer[:4000], "sources": ["Technical Evidence", "ML Evidence", "External Reputation"]}
    except AIProviderError:
        return fallback
