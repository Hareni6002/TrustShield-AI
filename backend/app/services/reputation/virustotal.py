from __future__ import annotations

import base64
import os
from typing import Any

import httpx

from app.services.reputation.cache import get_cached, set_cached


def _unavailable(status: str, message: str, configured: bool = True) -> dict[str, Any]:
    return {
        "available": False,
        "configured": configured,
        "provider": "VirusTotal",
        "status": status,
        "message": message,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "last_analysis_date": None,
        "permalink": None,
    }


def lookup(url: str) -> dict[str, Any]:
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        return _unavailable("not_configured", "VirusTotal API key is not configured.", False)
    cache_key = f"virustotal:{url}"
    cached = get_cached(cache_key)
    if cached is not None:
        return cached
    encoded_url = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    try:
        response = httpx.get(
            f"https://www.virustotal.com/api/v3/urls/{encoded_url}",
            headers={"x-apikey": api_key},
            timeout=6,
        )
    except httpx.TimeoutException:
        return _unavailable("lookup_failed", "VirusTotal lookup timed out.")
    except httpx.HTTPError:
        return _unavailable("lookup_failed", "VirusTotal is temporarily unavailable.")
    if response.status_code in {401, 403}:
        return _unavailable("invalid_key", "VirusTotal credentials were rejected.")
    if response.status_code == 429:
        return _unavailable("rate_limited", "VirusTotal temporarily unavailable due to API rate limit.")
    if response.status_code == 404:
        return set_cached(cache_key, _unavailable("no_record", "No VirusTotal analysis record found."))
    if response.status_code >= 500:
        return _unavailable("lookup_failed", "VirusTotal is temporarily unavailable.")
    if response.status_code != 200:
        return _unavailable("lookup_failed", "VirusTotal lookup could not be completed.")
    try:
        attributes = response.json()["data"]["attributes"]
        stats = attributes.get("last_analysis_stats", {})
        result = {
            "available": True,
            "configured": True,
            "provider": "VirusTotal",
            "status": "threat_found" if stats.get("malicious", 0) or stats.get("suspicious", 0) else "available",
            "message": None,
            "malicious": int(stats.get("malicious", 0)),
            "suspicious": int(stats.get("suspicious", 0)),
            "harmless": int(stats.get("harmless", 0)),
            "undetected": int(stats.get("undetected", 0)),
            "last_analysis_date": attributes.get("last_analysis_date"),
            "permalink": response.json().get("data", {}).get("links", {}).get("self"),
        }
        return set_cached(cache_key, result)
    except (KeyError, TypeError, ValueError):
        return _unavailable("lookup_failed", "VirusTotal returned an unexpected response.")
