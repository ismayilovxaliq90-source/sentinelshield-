from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass
from typing import Any


class ExecutionAuditError(RuntimeError):
    """Raised when an audit event is invalid."""


@dataclass(frozen=True)
class AuditEvent:
    sequence: int
    timestamp: float
    execution_id: str
    event_type: str
    status: str
    message: str
    command_digest: str | None


class ExecutionAudit:
    """
    Task 37 — Execution Audit.

    Records structured execution events without executing commands.
    Sensitive-looking values are redacted before storage.
    """

    SECRET_PATTERN = re.compile(
        r"(?i)\b("
        r"password|passwd|secret|api[_-]?key|"
        r"access[_-]?token|auth[_-]?token|token"
        r")\s*[:=]\s*[^\s,;]+"
    )

    def __init__(self, clock=None) -> None:
        self._clock = clock or time.time
        self._events: list[AuditEvent] = []
        self._next_sequence = 1

    @staticmethod
    def _validate_text(
        value: str,
        field_name: str,
    ) -> str:
        if not isinstance(value, str):
            raise TypeError(
                f"{field_name} must be a string"
            )

        value = value.strip()

        if not value:
            raise ValueError(
                f"{field_name} cannot be empty"
            )

        return value

    @classmethod
    def redact(cls, message: str) -> str:
        if not isinstance(message, str):
            raise TypeError(
                "message must be a string"
            )

        return cls.SECRET_PATTERN.sub(
            lambda match: (
                match.group(0).split("=", 1)[0] + "=[REDACTED]"
                if "=" in match.group(0)
                else (
                    match.group(0).split(":", 1)[0]
                    + "=[REDACTED]"
                )
            ),
            message,
        )

    @staticmethod
    def command_digest(
        command: Any,
    ) -> str:
        if isinstance(command, (str, bytes)):
            raise TypeError(
                "command must be a sequence of strings"
            )

        try:
            normalized = tuple(command)
        except TypeError as exc:
            raise TypeError(
                "command must be iterable"
            ) from exc

        if not normalized:
            raise ValueError(
                "command cannot be empty"
            )

        if not all(
            isinstance(item, str)
            for item in normalized
        ):
            raise TypeError(
                "all command items must be strings"
            )

        serialized = json.dumps(
            normalized,
            ensure_ascii=False,
            separators=(",", ":"),
        )

        return hashlib.sha256(
            serialized.encode("utf-8")
        ).hexdigest()

    def record(
        self,
        *,
        execution_id: str,
        event_type: str,
        status: str,
        message: str,
        command: Any = None,
    ) -> AuditEvent:

        execution_id = self._validate_text(
            execution_id,
            "execution_id",
        )

        event_type = self._validate_text(
            event_type,
            "event_type",
        )

        status = self._validate_text(
            status,
            "status",
        )

        message = self._validate_text(
            message,
            "message",
        )

        redacted_message = self.redact(message)

        digest = None

        if command is not None:
            digest = self.command_digest(command)

        event = AuditEvent(
            sequence=self._next_sequence,
            timestamp=self._clock(),
            execution_id=execution_id,
            event_type=event_type,
            status=status,
            message=redacted_message,
            command_digest=digest,
        )

        self._events.append(event)
        self._next_sequence += 1

        return event

    def events(self) -> tuple[AuditEvent, ...]:
        return tuple(self._events)

    def last_event(self) -> AuditEvent | None:
        if not self._events:
            return None

        return self._events[-1]

    def count(self) -> int:
        return len(self._events)

    def clear(self) -> None:
        self._events.clear()
        self._next_sequence = 1

    def export_json(self) -> str:
        payload = [
            {
                "sequence": event.sequence,
                "timestamp": event.timestamp,
                "execution_id": event.execution_id,
                "event_type": event.event_type,
                "status": event.status,
                "message": event.message,
                "command_digest": event.command_digest,
            }
            for event in self._events
        ]

        return json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
