"""Metadata-only policy event recording."""

from __future__ import annotations

import hashlib
import logging
import threading
from collections import Counter, deque
from dataclasses import asdict, dataclass
from datetime import UTC, datetime

from .capabilities import tool_family

logger = logging.getLogger("llm_antidote.audit")


@dataclass(frozen=True)
class AuditEvent:
    timestamp: str
    action: str
    would_action: str
    tool_family: str
    tool_ref: str
    rule_ids: tuple[str, ...]
    session_ref: str


class MetadataAudit:
    def __init__(self, capacity: int = 200) -> None:
        self._events: deque[AuditEvent] = deque(maxlen=max(10, min(int(capacity), 10_000)))
        self._counts: Counter[str] = Counter()
        self._lock = threading.RLock()

    @staticmethod
    def session_ref(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:12]

    @staticmethod
    def tool_identity(value: str) -> tuple[str, str]:
        return (
            tool_family(value),
            hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:12],
        )

    def record(
        self,
        *,
        action: str,
        would_action: str,
        tool_name: str,
        rule_ids: tuple[str, ...],
        session_key: str,
    ) -> None:
        tool_family, tool_ref = self.tool_identity(tool_name)
        event = AuditEvent(
            timestamp=datetime.now(UTC).isoformat(),
            action=action,
            would_action=would_action,
            tool_family=tool_family,
            tool_ref=tool_ref,
            rule_ids=rule_ids,
            session_ref=self.session_ref(session_key),
        )
        with self._lock:
            self._events.append(event)
            self._counts[action] += 1
        logger.info(
            "decision action=%s would=%s tool_family=%s tool_ref=%s rules=%s session=%s",
            action,
            would_action,
            event.tool_family,
            event.tool_ref,
            ",".join(rule_ids) or "none",
            event.session_ref,
        )

    def summary(self) -> dict[str, object]:
        with self._lock:
            return {
                "retained_events": len(self._events),
                "counts": dict(sorted(self._counts.items())),
            }

    def events(self) -> list[dict[str, object]]:
        with self._lock:
            return [asdict(event) for event in self._events]
