from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any

import httpx
import whois


def _first(value: Any) -> Any:
    return value[0] if isinstance(value, (list, tuple)) and value else value


def _as_datetime(value: Any) -> datetime | None:
    value = _first(value)
    if not isinstance(value, datetime):
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def _lookup(domain: str) -> Any:
    return whois.whois(domain)


def _rdap_lookup(domain: str) -> dict[str, Any] | None:
    try:
        response = httpx.get(
            f"https://rdap.org/domain/{domain}",
            follow_redirects=True,
            timeout=5,
            headers={"Accept": "application/rdap+json, application/json"},
        )
        response.raise_for_status()
        return response.json()
    except Exception:
        return None


def _rdap_date(record: dict[str, Any], action: str) -> datetime | None:
    for event in record.get("events", []):
        if event.get("eventAction") == action:
            value = event.get("eventDate")
            if isinstance(value, str):
                try:
                    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
                except ValueError:
                    return None
    return None


def analyze_domain(domain: str, timeout_seconds: float = 5) -> dict:
    result = {
        "domain_name": domain,
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "updated_date": None,
        "name_servers": [],
        "domain_age_days": None,
        "registration_remaining_days": None,
        "lookup_status": "unavailable",
    }
    rdap_record = _rdap_lookup(domain)
    if rdap_record:
        creation = _rdap_date(rdap_record, "registration")
        expiration = _rdap_date(rdap_record, "expiration")
        updated = _rdap_date(rdap_record, "last changed")
        now = datetime.now(timezone.utc)
        result.update(
            {
                "creation_date": creation,
                "expiration_date": expiration,
                "updated_date": updated,
                "name_servers": [
                    str(link.get("ldhName"))
                    for link in rdap_record.get("nameservers", [])
                    if link.get("ldhName")
                ],
                "domain_age_days": (now - creation).days if creation else None,
                "registration_remaining_days": (expiration - now).days if expiration else None,
                "lookup_status": "available_rdap",
            }
        )
        return result
    executor = ThreadPoolExecutor(max_workers=1)
    future = executor.submit(_lookup, domain)
    try:
        record = future.result(timeout=timeout_seconds)
    except Exception:
        record = None
    executor.shutdown(wait=False, cancel_futures=True)

    creation = _as_datetime(getattr(record, "creation_date", None)) if record else None
    expiration = _as_datetime(getattr(record, "expiration_date", None)) if record else None
    updated = _as_datetime(getattr(record, "updated_date", None)) if record else None
    rdap_record = None
    if not creation or not expiration:
        rdap_record = _rdap_lookup(domain)
        if rdap_record:
            creation = creation or _rdap_date(rdap_record, "registration")
            expiration = expiration or _rdap_date(rdap_record, "expiration")
            updated = updated or _rdap_date(rdap_record, "last changed")
    if not record and not rdap_record:
        return result
    now = datetime.now(timezone.utc)
    result.update(
        {
            "registrar": _first(getattr(record, "registrar", None)) if record else None,
            "creation_date": creation,
            "expiration_date": expiration,
            "updated_date": updated,
            "name_servers": [str(value) for value in (getattr(record, "name_servers", None) or [])] if record else [
                str(link.get("ldhName")) for link in (rdap_record or {}).get("nameservers", []) if link.get("ldhName")
            ],
            "domain_age_days": (now - creation).days if creation else None,
            "registration_remaining_days": (expiration - now).days if expiration else None,
            "lookup_status": "available_rdap" if rdap_record else "available",
        }
    )
    return result
