from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum


class EventType(str, Enum):
    RESOURCE_BLOCK = "RESOURCE_BLOCK"
    ACTION_DENIED = "ACTION_DENIED"
    ACTION_EXECUTED = "ACTION_EXECUTED"
    RECOVERY_REQUIRED = "RECOVERY_REQUIRED"
    RECOVERY_SUCCESS = "RECOVERY_SUCCESS"
    RECOVERY_FAILED = "RECOVERY_FAILED"
    PROJECT_HEALTHY = "PROJECT_HEALTHY"


class EventSeverity(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class SecurityEvent:
    event_type: EventType
    severity: EventSeverity
    project: str
    reason: str
    timestamp_utc: str

    def as_dict(self) -> dict:
        data = asdict(self)
        data["event_type"] = self.event_type.value
        data["severity"] = self.severity.value
        return data

    def as_json(self) -> str:
        return json.dumps(
            self.as_dict(),
            ensure_ascii=False,
            sort_keys=True,
        )


class EventEngine:
    def _severity(
        self,
        event_type: EventType,
    ) -> EventSeverity:
        if event_type in (
            EventType.RESOURCE_BLOCK,
            EventType.ACTION_DENIED,
            EventType.RECOVERY_FAILED,
        ):
            return EventSeverity.CRITICAL

        if event_type == EventType.RECOVERY_REQUIRED:
            return EventSeverity.WARNING

        return EventSeverity.INFO

    def create(
        self,
        *,
        event_type: EventType,
        project: str,
        reason: str,
    ) -> SecurityEvent:

        if not isinstance(event_type, EventType):
            raise TypeError("event_type must be EventType")

        if not isinstance(project, str):
            raise TypeError("project must be str")

        if not project.strip():
            raise ValueError("project must not be empty")

        if not isinstance(reason, str):
            raise TypeError("reason must be str")

        if not reason.strip():
            raise ValueError("reason must not be empty")

        timestamp = datetime.now(timezone.utc).isoformat()

        return SecurityEvent(
            event_type=event_type,
            severity=self._severity(event_type),
            project=project.strip(),
            reason=reason.strip(),
            timestamp_utc=timestamp,
        )
