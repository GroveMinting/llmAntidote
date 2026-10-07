"""Sanitized runtime route metadata observed from Hermes API requests."""

from __future__ import annotations

import threading
from urllib.parse import urlsplit


class RuntimeRoutes:
    def __init__(self) -> None:
        self._latest: dict[str, str] = {}
        self._lock = threading.RLock()

    def observe(self, *, provider: object = "", model: object = "", base_url: object = "") -> None:
        raw_url = str(base_url or "")
        parsed = urlsplit(raw_url)
        endpoint = parsed.hostname or ""
        if parsed.port:
            endpoint = f"{endpoint}:{parsed.port}"
        with self._lock:
            self._latest = {
                "provider": str(provider or ""),
                "model": str(model or ""),
                "endpoint": endpoint,
            }

    def snapshot(self) -> dict[str, str]:
        with self._lock:
            return dict(self._latest)
