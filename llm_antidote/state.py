"""Bounded session risk state containing metadata only.

State tracks two related facts per session alias:

* completed sensitive access (taint categories), and
* in-flight sensitive access that has been permitted but has not yet completed
  (a pending reservation).

Pending reservations close the decision-ordering window in which an
outbound-capable tool could be authorized before a sensitive read's post hook
marks the session tainted. Neither field ever contains arguments, paths, or
result content.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field


@dataclass
class SessionRisk:
    categories: set[str] = field(default_factory=set)
    pending: int = 0
    updated_at: float = 0.0


class SessionRiskStore:
    def __init__(self, ttl_minutes: int = 60, clock: Callable[[], float] = time.monotonic) -> None:
        self._ttl_seconds = max(1, min(int(ttl_minutes), 24 * 60)) * 60
        self._clock = clock
        self._items: dict[str, SessionRisk] = {}
        self._lock = threading.RLock()

    @staticmethod
    def key(session_id: str = "", task_id: str = "") -> str:
        return str(session_id or task_id or "unknown")

    @staticmethod
    def _unique(keys: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(dict.fromkeys(key for key in keys if key)) or ("unknown",)

    def _live(self, key: str) -> SessionRisk | None:
        item = self._items.get(key)
        if item is None:
            return None
        if self._clock() - item.updated_at > self._ttl_seconds:
            self._items.pop(key, None)
            return None
        return item

    def _merge(self, keys: tuple[str, ...]) -> SessionRisk | None:
        existing = [self._items[key] for key in keys if key in self._items]
        if not existing:
            return None
        item = existing[0]
        for other in existing[1:]:
            if other is item:
                continue
            item.categories.update(other.categories)
            item.pending = max(item.pending, other.pending)
            item.updated_at = max(item.updated_at, other.updated_at)
            for alias, value in tuple(self._items.items()):
                if value is other:
                    self._items[alias] = item
        return item

    def mark(self, key: str, categories: tuple[str, ...] | list[str]) -> None:
        self.mark_many((key,), categories)

    def mark_many(self, keys: tuple[str, ...], categories: tuple[str, ...] | list[str]) -> None:
        if not categories:
            return
        now = self._clock()
        unique_keys = self._unique(keys)
        with self._lock:
            item = self._merge(unique_keys)
            if item is None:
                item = SessionRisk()
            item.categories.update(categories)
            item.updated_at = now
            for key in unique_keys:
                self._items[key] = item

    def reserve_pending(self, keys: tuple[str, ...]) -> None:
        """Record that a permitted sensitive access is executing and unresolved."""
        now = self._clock()
        unique_keys = self._unique(keys)
        with self._lock:
            item = self._merge(unique_keys)
            if item is None:
                item = SessionRisk()
            item.pending += 1
            item.updated_at = now
            for key in unique_keys:
                self._items[key] = item

    def release_pending(self, keys: tuple[str, ...]) -> None:
        """Resolve a pending reservation regardless of success or failure."""
        now = self._clock()
        unique_keys = self._unique(keys)
        with self._lock:
            item = self._merge(unique_keys)
            if item is None:
                return
            item.pending = max(0, item.pending - 1)
            item.updated_at = now

    def link(self, keys: tuple[str, ...]) -> None:
        unique_keys = self._unique(keys)
        if len(unique_keys) < 2:
            return
        with self._lock:
            item = self._merge(unique_keys)
            if item is None:
                return
            for key in unique_keys:
                self._items[key] = item

    def categories(self, key: str) -> tuple[str, ...]:
        with self._lock:
            item = self._live(key)
            if item is None:
                return ()
            return tuple(sorted(item.categories))

    def is_tainted(self, key: str) -> bool:
        return bool(self.categories(key))

    def has_pending(self, key: str) -> bool:
        with self._lock:
            item = self._live(key)
            return item is not None and item.pending > 0

    def clear(self, *keys: str) -> None:
        with self._lock:
            for key in keys:
                item = self._items.get(key) if key else None
                if item is not None:
                    for alias, value in tuple(self._items.items()):
                        if value is item:
                            self._items.pop(alias, None)

    def clear_all(self) -> None:
        with self._lock:
            self._items.clear()

    def summary(self) -> dict[str, object]:
        with self._lock:
            for key in tuple(self._items):
                self._live(key)
            unique = {id(item): item for item in self._items.values()}
            categories = sorted(
                {category for item in unique.values() for category in item.categories}
            )
            tainted = sum(1 for item in unique.values() if item.categories)
            pending = sum(1 for item in unique.values() if item.pending > 0)
            return {
                "tainted_sessions": tainted,
                "pending_sessions": pending,
                "categories": categories,
            }
