from __future__ import annotations

from threading import Lock
from time import monotonic
from typing import Any


CACHE_TTL_SECONDS = 30 * 60
_cache: dict[str, tuple[float, Any]] = {}
_lock = Lock()


def get_cached(key: str) -> Any | None:
    now = monotonic()
    with _lock:
        entry = _cache.get(key)
        if not entry:
            return None
        created_at, value = entry
        if now - created_at >= CACHE_TTL_SECONDS:
            _cache.pop(key, None)
            return None
        return value


def set_cached(key: str, value: Any) -> Any:
    with _lock:
        _cache[key] = (monotonic(), value)
    return value


def clear_cache() -> None:
    with _lock:
        _cache.clear()
