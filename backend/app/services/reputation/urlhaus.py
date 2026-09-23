from __future__ import annotations

import os
from typing import Any

import httpx

from app.services.reputation.cache import get_cached, set_cached


def lookup(url: str) -> dict[str, Any]:
    if os.getenv("URLHAUS_ENABLED", "true").strip().lower() not in {"1", "true", "yes", "on"}:
        return {"available": False, "configured": False, "provider": "URLhaus", "status": "not_configured", "url_status": None, "threat": None, "tags": [], "date_added": None, "message": "URLhaus lookups are disabled."}
    cache_key = f"urlhaus:{url}"
    cached = get_cached(cache_key)
    if cached is not None:
        return cached
    try:
        response = httpx.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url}, timeout=6)
    except httpx.TimeoutException:
        return {"available": False, "configured": True, "provider": "URLhaus", "status": "lookup_failed", "url_status": None, "threat": None, "tags": [], "date_added": None, "message": "URLhaus lookup timed out."}
    except httpx.HTTPError:
        return {"available": False, "configured": True, "provider": "URLhaus", "status": "lookup_failed", "url_status": None, "threat": None, "tags": [], "date_added": None, "message": "URLhaus is temporarily unavailable."}
    if response.status_code != 200:
        return {"available": False, "configured": True, "provider": "URLhaus", "status": "lookup_failed", "url_status": None, "threat": None, "tags": [], "date_added": None, "message": "URLhaus lookup could not be completed."}
    try:
        payload = response.json()
        if payload.get("query_status") == "no_results":
            return set_cached(cache_key, {"available": True, "configured": True, "provider": "URLhaus", "status": "no_record", "url_status": None, "threat": None, "tags": [], "date_added": None, "message": "No URLhaus threat record found."})
        result = {
            "available": True,
            "configured": True,
            "provider": "URLhaus",
            "status": "threat_found",
            "url_status": payload.get("url_status"),
            "threat": payload.get("threat"),
            "tags": payload.get("tags") or [],
            "date_added": payload.get("date_added"),
            "message": "URLhaus has a threat record for this URL.",
        }
        return set_cached(cache_key, result)
    except (TypeError, ValueError):
        return {"available": False, "configured": True, "provider": "URLhaus", "status": "lookup_failed", "url_status": None, "threat": None, "tags": [], "date_added": None, "message": "URLhaus returned an unexpected response."}
