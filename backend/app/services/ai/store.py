from __future__ import annotations

from threading import Lock
from time import monotonic
from typing import Any


SCAN_TTL_SECONDS = 60 * 60
_scans: dict[str, tuple[float, dict[str, Any]]] = {}
_lock = Lock()


def save_scan(scan_id: str, scan: dict[str, Any]) -> None:
    with _lock:
        _scans[scan_id] = (monotonic(), scan)


def get_scan(scan_id: str) -> dict[str, Any] | None:
    with _lock:
        entry = _scans.get(scan_id)
        if not entry:
            return None
        created_at, scan = entry
        if monotonic() - created_at >= SCAN_TTL_SECONDS:
            _scans.pop(scan_id, None)
            return None
        return scan


def clear_scans() -> None:
    with _lock:
        _scans.clear()
