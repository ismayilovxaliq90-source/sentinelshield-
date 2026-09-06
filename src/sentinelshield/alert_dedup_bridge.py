from __future__ import annotations

import hashlib
from dataclasses import dataclass

from sentinelshield.violation_event_bridge import ViolationEvent


@dataclass(frozen=True)
class Alert:
    alert_id: str
    event_type: str
    decision: str
    failures: tuple[str, ...]
    reason: str


class AlertDedupStore:
    """In-memory deduplication store."""

    def __init__(self):
        self._seen: set[str] = set()

    def contains(self, alert_id: str) -> bool:
        return alert_id in self._seen

    def add(self, alert_id: str) -> None:
        self._seen.add(alert_id)


class AlertDispatcher:
    def __init__(self, dedup: AlertDedupStore):
        self.dedup = dedup
        self.alerts: list[Alert] = []

    @staticmethod
    def _alert_id(event: ViolationEvent) -> str:
        raw = "|".join(
            [
                event.event_type,
                event.decision,
                ",".join(event.failures),
                event.reason,
            ]
        )

        return hashlib.sha256(
            raw.encode("utf-8")
        ).hexdigest()

    def dispatch(
        self,
        event: ViolationEvent,
    ) -> Alert | None:
        alert_id = self._alert_id(event)

        if self.dedup.contains(alert_id):
            return None

        alert = Alert(
            alert_id=alert_id,
            event_type=event.event_type,
            decision=event.decision,
            failures=tuple(event.failures),
            reason=event.reason,
        )

        self.dedup.add(alert_id)
        self.alerts.append(alert)

        return alert
