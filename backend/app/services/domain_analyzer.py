from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any

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
    executor = ThreadPoolExecutor(max_workers=1)
    future = executor.submit(_lookup, domain)
    try:
        record = future.result(timeout=timeout_seconds)
    except Exception:
        executor.shutdown(wait=False, cancel_futures=True)
        return result
    executor.shutdown(wait=False, cancel_futures=True)

    creation = _as_datetime(getattr(record, "creation_date", None))
    expiration = _as_datetime(getattr(record, "expiration_date", None))
    updated = _as_datetime(getattr(record, "updated_date", None))
    now = datetime.now(timezone.utc)
    result.update(
        {
            "registrar": _first(getattr(record, "registrar", None)),
            "creation_date": creation,
            "expiration_date": expiration,
            "updated_date": updated,
            "name_servers": [str(value) for value in (getattr(record, "name_servers", None) or [])],
            "domain_age_days": (now - creation).days if creation else None,
            "registration_remaining_days": (expiration - now).days if expiration else None,
            "lookup_status": "available",
        }
    )
    return result
