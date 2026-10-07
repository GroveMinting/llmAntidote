"""Bounded session risk state containing metadata only."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field


@dataclass
class SessionRisk:
    categories: set[str] = field(default_factory=set)
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

    def mark(self, key: str, categories: tuple[str, ...] | list[str]) -> None:
        self.mark_many((key,), categories)

    def mark_many(self, keys: tuple[str, ...], categories: tuple[str, ...] | list[str]) -> None:
        if not categories:
            return
        now = self._clock()
        with self._lock:
            unique_keys = tuple(dict.fromkeys(key for key in keys if key)) or ("unknown",)
            existing = [self._items[key] for key in unique_keys if key in self._items]
            item = existing[0] if existing else SessionRisk()
            for other in existing[1:]:
                if other is item:
                    continue
                item.categories.update(other.categories)
                for alias, value in tuple(self._items.items()):
                    if value is other:
                        self._items[alias] = item
            item.categories.update(categories)
            item.updated_at = now
            for key in unique_keys:
                self._items[key] = item

    def link(self, keys: tuple[str, ...]) -> None:
        unique_keys = tuple(dict.fromkeys(key for key in keys if key))
        with self._lock:
            existing = [self._items[key] for key in unique_keys if key in self._items]
            if not existing:
                return
            item = existing[0]
            for other in existing[1:]:
                if other is item:
                    continue
                item.categories.update(other.categories)
                item.updated_at = max(item.updated_at, other.updated_at)
                for alias, value in tuple(self._items.items()):
                    if value is other:
                        self._items[alias] = item
            for key in unique_keys:
                self._items[key] = item

    def categories(self, key: str) -> tuple[str, ...]:
        now = self._clock()
        with self._lock:
            item = self._items.get(key)
            if item is None:
                return ()
            if now - item.updated_at > self._ttl_seconds:
                self._items.pop(key, None)
                return ()
            return tuple(sorted(item.categories))

    def is_tainted(self, key: str) -> bool:
        return bool(self.categories(key))

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
                self.categories(key)
            unique = {id(item): item for item in self._items.values() if item.categories}
            categories = sorted(
                {category for item in unique.values() for category in item.categories}
            )
            return {"tainted_sessions": len(unique), "categories": categories}
