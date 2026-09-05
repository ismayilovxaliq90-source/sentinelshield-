from __future__ import annotations

from sentinelshield.audit_engine import AuditEngine
from sentinelshield.event_engine import SecurityEvent


class EventAuditBridge:
    """
    Persists SecurityEvent objects through AuditEngine.
    """

    def __init__(self, audit: AuditEngine | None = None):
        self.audit = audit or AuditEngine()

    def record(self, event: SecurityEvent) -> dict:
        if not isinstance(event, SecurityEvent):
            raise TypeError("event must be SecurityEvent")

        return self.audit.record(
            event=event.event_type.value,
            action=event.event_type.value,
            decision=event.severity.value,
            reason=event.reason,
            executed=False,
        )

    def record_many(
        self,
        events: list[SecurityEvent],
    ) -> list[dict]:
        if not isinstance(events, list):
            raise TypeError("events must be list")

        return [self.record(event) for event in events]
