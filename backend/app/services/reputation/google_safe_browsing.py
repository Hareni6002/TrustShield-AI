from __future__ import annotations

import os
from typing import Any

import httpx

from app.services.reputation.cache import get_cached, set_cached


def lookup(url: str) -> dict[str, Any]:
    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    if not api_key:
        return {
            "available": False,
            "configured": False,
            "provider": "Google Safe Browsing",
            "status": "not_configured",
            "matches": [],
            "threat_detected": False,
            "message": "Google Safe Browsing API key is not configured.",
        }
    cache_key = f"google-safe-browsing:{url}"
    cached = get_cached(cache_key)
    if cached is not None:
        return cached
    body = {
        "client": {"clientId": "trustshield-ai", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        response = httpx.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
            json=body,
            timeout=6,
        )
    except httpx.TimeoutException:
        return {"available": False, "configured": True, "provider": "Google Safe Browsing", "status": "lookup_failed", "matches": [], "threat_detected": False, "message": "Google threat lookup timed out."}
    except httpx.HTTPError:
        return {"available": False, "configured": True, "provider": "Google Safe Browsing", "status": "lookup_failed", "matches": [], "threat_detected": False, "message": "Google Safe Browsing is temporarily unavailable."}
    if response.status_code in {400, 401, 403}:
        return {"available": False, "configured": True, "provider": "Google Safe Browsing", "status": "invalid_key", "matches": [], "threat_detected": False, "message": "Google Safe Browsing credentials were rejected."}
    if response.status_code == 429:
        return {"available": False, "configured": True, "provider": "Google Safe Browsing", "status": "rate_limited", "matches": [], "threat_detected": False, "message": "Google threat lookup is temporarily rate limited."}
    if response.status_code != 200:
        return {"available": False, "configured": True, "provider": "Google Safe Browsing", "status": "lookup_failed", "matches": [], "threat_detected": False, "message": "Google threat lookup could not be completed."}
    try:
        matches = response.json().get("matches", [])
        result = {
            "available": True,
            "configured": True,
            "provider": "Google Safe Browsing",
            "status": "threat_found" if matches else "no_record",
            "matches": matches,
            "threat_detected": bool(matches),
            "message": None if matches else "No known Google Safe Browsing threat match found.",
        }
        return set_cached(cache_key, result)
    except (TypeError, ValueError):
        return {"available": False, "configured": True, "provider": "Google Safe Browsing", "status": "lookup_failed", "matches": [], "threat_detected": False, "message": "Google returned an unexpected response."}
