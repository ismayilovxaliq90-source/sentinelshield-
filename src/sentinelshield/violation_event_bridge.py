from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sentinelshield.policy_violation_detector import (
    PolicyViolationDetector,
)


@dataclass(frozen=True)
class ViolationEvent:
    event_type: str
    timestamp: str
    decision: str
    failures: tuple[str, ...]
    reason: str


class ViolationEventBridge:
    """Converts policy violations into audit-ready events."""

    def __init__(self, detector: PolicyViolationDetector):
        self.detector = detector

    def create_event(self) -> ViolationEvent | None:
        violation = self.detector.check()

        if not violation.violated:
            return None

        return ViolationEvent(
            event_type="POLICY_VIOLATION",
            timestamp=datetime.now(
                timezone.utc
            ).isoformat(),
            decision=violation.decision,
            failures=tuple(violation.failures),
            reason=violation.reason,
        )


class InMemoryAuditSink:
    """Minimal audit sink used by tests and local integration."""

    def __init__(self):
        self.events: list[ViolationEvent] = []

    def write(self, event: ViolationEvent) -> None:
        self.events.append(event)


class AuditedViolationBridge:
    def __init__(
        self,
        bridge: ViolationEventBridge,
        audit: InMemoryAuditSink,
    ):
        self.bridge = bridge
        self.audit = audit

    def process(self) -> ViolationEvent | None:
        event = self.bridge.create_event()

        if event is not None:
            self.audit.write(event)

        return event
