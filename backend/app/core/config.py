from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv


load_dotenv(Path(__file__).resolve().parents[2] / ".env")


def is_configured(name: str) -> bool:
    return bool(os.getenv(name, "").strip())


def is_enabled(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def integration_status() -> dict[str, dict[str, bool | str]]:
    gemini = is_configured("AI_API_KEY") and os.getenv("AI_PROVIDER", "").strip().lower() == "gemini"
    virustotal = is_configured("VIRUSTOTAL_API_KEY")
    google = is_configured("GOOGLE_SAFE_BROWSING_API_KEY")
    urlhaus = is_enabled("URLHAUS_ENABLED", default=True)
    urlhaus_configured = urlhaus and is_configured("URLHAUS_AUTH_KEY")
    return {
        "gemini": {"configured": gemini, "available": gemini, "status": "configured" if gemini else "unavailable"},
        "virustotal": {"configured": virustotal, "available": virustotal, "status": "configured" if virustotal else "unavailable"},
        "google_safe_browsing": {"configured": google, "available": google, "status": "configured" if google else "unavailable"},
        "urlhaus": {"configured": urlhaus_configured, "available": urlhaus_configured, "status": "available" if urlhaus_configured else "not_configured"},
    }
