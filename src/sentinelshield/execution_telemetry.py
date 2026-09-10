from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable, Mapping, Sequence
import json
import re


class ExecutionTelemetryError(Exception):
    """Raised when execution telemetry is invalid or unsafe."""


_ALLOWED_STATUSES = frozenset(
    {
        "started",
        "completed",
        "failed",
        "timeout",
        "terminated",
    }
)

_SECRET_KEY_PATTERN = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|"
    r"access[_-]?key|private[_-]?key|credential|authorization)",
    re.IGNORECASE,
)

_SECRET_VALUE_PATTERN = re.compile(
    r"(?i)\b("
    r"sk-[a-z0-9_-]{8,}|"
    r"gh[pousr]_[a-z0-9_]{8,}|"
    r"bearer\s+[a-z0-9._~+/=-]{8,}|"
    r"password\s*=\s*[^\s]+|"
    r"token\s*=\s*[^\s]+|"
    r"secret\s*=\s*[^\s]+"
    r")"
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _validate_timestamp(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ExecutionTelemetryError(
            "Timestamp must be a non-empty string"
        )

    try:
        parsed = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise ExecutionTelemetryError(
            f"Invalid timestamp: {value!r}"
        ) from exc

    if parsed.tzinfo is None:
        raise ExecutionTelemetryError(
            "Timestamp must contain timezone information"
        )

    return value


def _sanitize_text(value: str | None, limit: int = 4096) -> str | None:
    if value is None:
        return None

    if not isinstance(value, str):
        raise ExecutionTelemetryError(
            "Telemetry text must be a string"
        )

    sanitized = _SECRET_VALUE_PATTERN.sub(
        "[REDACTED]",
        value,
    )

    if len(sanitized) > limit:
        sanitized = sanitized[:limit] + "[TRUNCATED]"

    return sanitized


def _sanitize_mapping(
    values: Mapping[str, object] | None,
) -> dict[str, object]:
    if values is None:
        return {}

    if not isinstance(values, Mapping):
        raise ExecutionTelemetryError(
            "Telemetry metadata must be a mapping"
        )

    result: dict[str, object] = {}

    for key, value in values.items():
        key_text = str(key)

        if _SECRET_KEY_PATTERN.search(key_text):
            result[key_text] = "[REDACTED]"
            continue

        if isinstance(value, str):
            result[key_text] = _sanitize_text(
                value,
                limit=1024,
            )
        elif isinstance(value, (str, int, float, bool)) or value is None:
            result[key_text] = value
        else:
            result[key_text] = str(value)

    return result


def _sanitize_command(
    command: Sequence[str] | None,
) -> tuple[str, ...]:
    if command is None:
        return ()

    if isinstance(command, (str, bytes)):
        raise ExecutionTelemetryError(
            "Command must be a sequence, not a string"
        )

    result: list[str] = []

    try:
        iterator = iter(command)
    except TypeError as exc:
        raise ExecutionTelemetryError(
            "Command must be iterable"
        ) from exc

    for argument in iterator:
        if not isinstance(argument, str):
            raise ExecutionTelemetryError(
                "Command arguments must be strings"
            )

        if _SECRET_VALUE_PATTERN.search(argument):
            result.append("[REDACTED]")
        else:
            result.append(
                _sanitize_text(argument, limit=1024) or ""
            )

    return tuple(result)


@dataclass(frozen=True)
class ExecutionTelemetry:
    execution_id: str
    status: str
    started_at: str
    completed_at: str | None = None
    duration_seconds: float | None = None
    command: tuple[str, ...] = ()
    return_code: int | None = None
    timed_out: bool = False
    terminated: bool = False
    stdout_bytes: int = 0
    stderr_bytes: int = 0
    stdout_preview: str | None = None
    stderr_preview: str | None = None
    resource_usage: Mapping[str, object] = field(
        default_factory=dict
    )
    metadata: Mapping[str, object] = field(
        default_factory=dict
    )

    def __post_init__(self) -> None:
        if not isinstance(self.execution_id, str):
            raise ExecutionTelemetryError(
                "execution_id must be a string"
            )

        if not self.execution_id.strip():
            raise ExecutionTelemetryError(
                "execution_id cannot be empty"
            )

        if self.status not in _ALLOWED_STATUSES:
            raise ExecutionTelemetryError(
                f"Unsupported status: {self.status!r}"
            )

        _validate_timestamp(self.started_at)

        if self.completed_at is not None:
            _validate_timestamp(self.completed_at)

        if self.duration_seconds is not None:
            if self.duration_seconds < 0:
                raise ExecutionTelemetryError(
                    "duration_seconds cannot be negative"
                )

        if self.return_code is not None:
            if not isinstance(self.return_code, int):
                raise ExecutionTelemetryError(
                    "return_code must be an integer"
                )

        if self.stdout_bytes < 0 or self.stderr_bytes < 0:
            raise ExecutionTelemetryError(
                "Output byte counts cannot be negative"
            )

        if not isinstance(self.timed_out, bool):
            raise ExecutionTelemetryError(
                "timed_out must be boolean"
            )

        if not isinstance(self.terminated, bool):
            raise ExecutionTelemetryError(
                "terminated must be boolean"
            )

        _sanitize_command(self.command)
        _sanitize_mapping(self.resource_usage)
        _sanitize_mapping(self.metadata)

    def to_dict(self) -> dict:
        return {
            "execution_id": self.execution_id,
            "status": self.status,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_seconds": self.duration_seconds,
            "command": list(
                _sanitize_command(self.command)
            ),
            "return_code": self.return_code,
            "timed_out": self.timed_out,
            "terminated": self.terminated,
            "stdout_bytes": self.stdout_bytes,
            "stderr_bytes": self.stderr_bytes,
            "stdout_preview": _sanitize_text(
                self.stdout_preview
            ),
            "stderr_preview": _sanitize_text(
                self.stderr_preview
            ),
            "resource_usage": _sanitize_mapping(
                self.resource_usage
            ),
            "metadata": _sanitize_mapping(
                self.metadata
            ),
        }

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
        )


@dataclass(frozen=True)
class ExecutionTelemetryCollector:
    execution_id: str
    command: tuple[str, ...]
    started_at: str
    metadata: Mapping[str, object] = field(
        default_factory=dict
    )

    def __post_init__(self) -> None:
        if not self.execution_id.strip():
            raise ExecutionTelemetryError(
                "execution_id cannot be empty"
            )

        _validate_timestamp(self.started_at)
        _sanitize_command(self.command)
        _sanitize_mapping(self.metadata)

    @classmethod
    def start(
        cls,
        execution_id: str,
        command: Sequence[str],
        metadata: Mapping[str, object] | None = None,
    ) -> "ExecutionTelemetryCollector":
        return cls(
            execution_id=execution_id,
            command=_sanitize_command(command),
            started_at=_utc_now(),
            metadata=_sanitize_mapping(metadata),
        )

    def finish(
        self,
        *,
        status: str,
        completed_at: str | None = None,
        duration_seconds: float | None = None,
        return_code: int | None = None,
        timed_out: bool = False,
        terminated: bool = False,
        stdout: str | None = None,
        stderr: str | None = None,
        resource_usage: Mapping[str, object] | None = None,
        metadata: Mapping[str, object] | None = None,
    ) -> ExecutionTelemetry:
        if status not in _ALLOWED_STATUSES:
            raise ExecutionTelemetryError(
                f"Unsupported status: {status!r}"
            )

        if completed_at is None:
            completed_at = _utc_now()

        _validate_timestamp(completed_at)

        if duration_seconds is not None:
            if duration_seconds < 0:
                raise ExecutionTelemetryError(
                    "duration_seconds cannot be negative"
                )

        if return_code is not None and not isinstance(
            return_code,
            int,
        ):
            raise ExecutionTelemetryError(
                "return_code must be an integer"
            )

        stdout_text = _sanitize_text(stdout)
        stderr_text = _sanitize_text(stderr)

        merged_metadata = dict(self.metadata)
        merged_metadata.update(
            _sanitize_mapping(metadata)
        )

        return ExecutionTelemetry(
            execution_id=self.execution_id,
            status=status,
            started_at=self.started_at,
            completed_at=completed_at,
            duration_seconds=duration_seconds,
            command=self.command,
            return_code=return_code,
            timed_out=timed_out,
            terminated=terminated,
            stdout_bytes=len(
                stdout.encode("utf-8")
                if isinstance(stdout, str)
                else b""
            ),
            stderr_bytes=len(
                stderr.encode("utf-8")
                if isinstance(stderr, str)
                else b""
            ),
            stdout_preview=stdout_text,
            stderr_preview=stderr_text,
            resource_usage=_sanitize_mapping(
                resource_usage
            ),
            metadata=merged_metadata,
        )


def validate_execution_telemetry(
    telemetry: ExecutionTelemetry,
) -> bool:
    if not isinstance(
        telemetry,
        ExecutionTelemetry,
    ):
        raise ExecutionTelemetryError(
            "Invalid telemetry object"
        )

    if telemetry.duration_seconds is not None:
        if telemetry.duration_seconds < 0:
            return False

    if telemetry.stdout_bytes < 0:
        return False

    if telemetry.stderr_bytes < 0:
        return False

    if telemetry.timed_out and telemetry.status != "timeout":
        return False

    return True


def create_execution_telemetry(
    *,
    execution_id: str,
    command: Sequence[str],
    status: str,
    started_at: str,
    completed_at: str | None = None,
    duration_seconds: float | None = None,
    return_code: int | None = None,
    timed_out: bool = False,
    terminated: bool = False,
    stdout: str | None = None,
    stderr: str | None = None,
    resource_usage: Mapping[str, object] | None = None,
    metadata: Mapping[str, object] | None = None,
) -> ExecutionTelemetry:
    telemetry = ExecutionTelemetry(
        execution_id=execution_id,
        status=status,
        started_at=started_at,
        completed_at=completed_at,
        duration_seconds=duration_seconds,
        command=_sanitize_command(command),
        return_code=return_code,
        timed_out=timed_out,
        terminated=terminated,
        stdout_bytes=len(
            stdout.encode("utf-8")
            if isinstance(stdout, str)
            else b""
        ),
        stderr_bytes=len(
            stderr.encode("utf-8")
            if isinstance(stderr, str)
            else b""
        ),
        stdout_preview=_sanitize_text(stdout),
        stderr_preview=_sanitize_text(stderr),
        resource_usage=_sanitize_mapping(
            resource_usage
        ),
        metadata=_sanitize_mapping(metadata),
    )

    if not validate_execution_telemetry(telemetry):
        raise ExecutionTelemetryError(
            "Telemetry validation failed"
        )

    return telemetry
