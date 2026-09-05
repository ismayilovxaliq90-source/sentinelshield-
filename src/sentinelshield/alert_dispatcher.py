from __future__ import annotations

from dataclasses import dataclass

from sentinelshield.event_engine import (
    EventSeverity,
    EventType,
    SecurityEvent,
)


@dataclass(frozen=True)
class Alert:
    event_type: EventType
    severity: EventSeverity
    project: str
    message: str
    reason: str


class AlertDispatcher:
    """
    Converts security events into alerts.

    No external network communication is performed here.
    """

    def create_alert(
        self,
        event: SecurityEvent,
    ) -> Alert | None:
        if not isinstance(event, SecurityEvent):
            raise TypeError("event must be SecurityEvent")

        if event.severity == EventSeverity.INFO:
            return None

        message = (
            f"{event.event_type.value}: "
            f"{event.project} | {event.reason}"
        )

        return Alert(
            event_type=event.event_type,
            severity=event.severity,
            project=event.project,
            message=message,
            reason=event.reason,
        )

    def dispatch(
        self,
        event: SecurityEvent,
    ) -> Alert | None:
        return self.create_alert(event)

    def dispatch_many(
        self,
        events: list[SecurityEvent],
    ) -> tuple[Alert, ...]:
        if not isinstance(events, list):
            raise TypeError("events must be list")

        alerts = []

        for event in events:
            alert = self.create_alert(event)

            if alert is not None:
                alerts.append(alert)

        return tuple(alerts)
