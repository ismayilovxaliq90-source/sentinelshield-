from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import re
from typing import Any, Mapping, Sequence


class ExecutionTelemetryError(Exception):
    """Raised when execution telemetry is invalid or unsafe."""


VALID_STATUSES = frozenset(
    {
        "started",
        "completed",
        "failed",
        "timeout",
        "terminated",
    }
)

_SECRET_KEY_RE = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|"
    r"access[_-]?key|private[_-]?key|credential|authorization)",
    re.IGNORECASE,
)

_SECRET_VALUE_RE = re.compile(
    r"(?i)"
    r"(bearer\s+)[A-Za-z0-9._~+/=-]+"
    r"|((?:token|secret|password|passwd|api[_-]?key)"
    r"\s*[=:]\s*)[^\s,;]+"
    r"|((?:sk|gh[pousr])_[A-Za-z0-9_-]{8,})"
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def validate_timestamp(value: str) -> str:
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
            "Timestamp must include timezone information"
        )

    return value


def sanitize_text(
    value: str | None,
    *,
    limit: int = 4096,
) -> str | None:
    if value is None:
        return None

    if not isinstance(value, str):
        raise ExecutionTelemetryError(
            "Telemetry text must be a string"
        )

    value = _SECRET_VALUE_RE.sub(
        lambda match: (
            match.group(1)
            or match.group(2)
            or "[REDACTED]"
        ) + "[REDACTED]"
        if match.group(1) or match.group(2)
        else "[REDACTED]",
        value,
    )

    if len(value) > limit:
        return value[:limit] + "[TRUNCATED]"

    return value


def sanitize_command(
    command: Sequence[str],
) -> tuple[str, ...]:
    if isinstance(command, (str, bytes)):
        raise ExecutionTelemetryError(
            "Command must be a sequence, not a string"
        )

    try:
        values = list(command)
    except TypeError as exc:
        raise ExecutionTelemetryError(
            "Command must be iterable"
        ) from exc

    sanitized: list[str] = []

    for argument in values:
        if not isinstance(argument, str):
            raise ExecutionTelemetryError(
                "Command arguments must be strings"
            )

        if _SECRET_KEY_RE.search(argument):
            sanitized.append("[REDACTED]")
            continue

        sanitized.append(
            sanitize_text(argument, limit=1024) or ""
        )

    return tuple(sanitized)


def sanitize_mapping(
    values: Mapping[str, Any] | None,
) -> dict[str, Any]:
    if values is None:
        return {}

    if not isinstance(values, Mapping):
        raise ExecutionTelemetryError(
            "Telemetry metadata must be a mapping"
        )

    result: dict[str, Any] = {}

    for key, value in values.items():
        key_text = str(key)

        if _SECRET_KEY_RE.search(key_text):
            result[key_text] = "[REDACTED]"
            continue

        if isinstance(value, str):
            result[key_text] = sanitize_text(
                value,
                limit=1024,
            )
        elif value is None or isinstance(
            value,
            (bool, int, float),
        ):
            result[key_text] = value
        elif isinstance(value, (list, tuple)):
            result[key_text] = [
                sanitize_text(str(item), limit=512)
                for item in value
            ]
        else:
            result[key_text] = sanitize_text(
                str(value),
                limit=1024,
            )

    return result


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
    resource_usage: Mapping[str, Any] = field(
        default_factory=dict
    )
    metadata: Mapping[str, Any] = field(
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

        if self.status not in VALID_STATUSES:
            raise ExecutionTelemetryError(
                f"Unsupported execution status: {self.status}"
            )

        validate_timestamp(self.started_at)

        if self.completed_at is not None:
            validate_timestamp(self.completed_at)

        if self.duration_seconds is not None:
            if not isinstance(
                self.duration_seconds,
                (int, float),
            ):
                raise ExecutionTelemetryError(
                    "duration_seconds must be numeric"
                )

            if self.duration_seconds < 0:
                raise ExecutionTelemetryError(
                    "duration_seconds cannot be negative"
                )

        if self.return_code is not None:
            if not isinstance(self.return_code, int):
                raise ExecutionTelemetryError(
                    "return_code must be an integer"
                )

        if not isinstance(self.timed_out, bool):
            raise ExecutionTelemetryError(
                "timed_out must be boolean"
            )

        if not isinstance(self.terminated, bool):
            raise ExecutionTelemetryError(
                "terminated must be boolean"
            )

        if not isinstance(self.stdout_bytes, int):
            raise ExecutionTelemetryError(
                "stdout_bytes must be an integer"
            )

        if not isinstance(self.stderr_bytes, int):
            raise ExecutionTelemetryError(
                "stderr_bytes must be an integer"
            )

        if self.stdout_bytes < 0 or self.stderr_bytes < 0:
            raise ExecutionTelemetryError(
                "Output byte counts cannot be negative"
            )

        sanitize_command(self.command)
        sanitize_mapping(self.resource_usage)
        sanitize_mapping(self.metadata)

        if self.timed_out and self.status != "timeout":
            raise ExecutionTelemetryError(
                "timed_out requires timeout status"
            )

        if self.terminated and self.status != "terminated":
            raise ExecutionTelemetryError(
                "terminated requires terminated status"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "status": self.status,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_seconds": self.duration_seconds,
            "command": list(
                sanitize_command(self.command)
            ),
            "return_code": self.return_code,
            "timed_out": self.timed_out,
            "terminated": self.terminated,
            "stdout_bytes": self.stdout_bytes,
            "stderr_bytes": self.stderr_bytes,
            "stdout_preview": sanitize_text(
                self.stdout_preview
            ),
            "stderr_preview": sanitize_text(
                self.stderr_preview
            ),
            "resource_usage": sanitize_mapping(
                self.resource_usage
            ),
            "metadata": sanitize_mapping(
                self.metadata
            ),
        }

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
        )


@dataclass
class ExecutionTelemetryCollector:
    execution_id: str
    command: tuple[str, ...]
    started_at: str
    metadata: dict[str, Any] = field(
        default_factory=dict
    )

    @classmethod
    def start(
        cls,
        execution_id: str,
        command: Sequence[str],
        metadata: Mapping[str, Any] | None = None,
    ) -> "ExecutionTelemetryCollector":
        if not isinstance(execution_id, str):
            raise ExecutionTelemetryError(
                "execution_id must be a string"
            )

        if not execution_id.strip():
            raise ExecutionTelemetryError(
                "execution_id cannot be empty"
            )

        return cls(
            execution_id=execution_id,
            command=sanitize_command(command),
            started_at=utc_now(),
            metadata=sanitize_mapping(metadata),
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
        resource_usage: Mapping[str, Any] | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> ExecutionTelemetry:
        merged_metadata = dict(self.metadata)
        merged_metadata.update(
            sanitize_mapping(metadata)
        )

        return ExecutionTelemetry(
            execution_id=self.execution_id,
            status=status,
            started_at=self.started_at,
            completed_at=completed_at or utc_now(),
            duration_seconds=duration_seconds,
            command=self.command,
            return_code=return_code,
            timed_out=timed_out,
            terminated=terminated,
            stdout_bytes=(
                len(stdout.encode("utf-8"))
                if stdout is not None
                else 0
            ),
            stderr_bytes=(
                len(stderr.encode("utf-8"))
                if stderr is not None
                else 0
            ),
            stdout_preview=sanitize_text(stdout),
            stderr_preview=sanitize_text(stderr),
            resource_usage=sanitize_mapping(
                resource_usage
            ),
            metadata=merged_metadata,
        )


def create_execution_telemetry(
    *,
    execution_id: str,
    status: str,
    started_at: str,
    command: Sequence[str],
    completed_at: str | None = None,
    duration_seconds: float | None = None,
    return_code: int | None = None,
    timed_out: bool = False,
    terminated: bool = False,
    stdout: str | None = None,
    stderr: str | None = None,
    resource_usage: Mapping[str, Any] | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> ExecutionTelemetry:
    return ExecutionTelemetry(
        execution_id=execution_id,
        status=status,
        started_at=started_at,
        completed_at=completed_at,
        duration_seconds=duration_seconds,
        command=sanitize_command(command),
        return_code=return_code,
        timed_out=timed_out,
        terminated=terminated,
        stdout_bytes=(
            len(stdout.encode("utf-8"))
            if stdout is not None
            else 0
        ),
        stderr_bytes=(
            len(stderr.encode("utf-8"))
            if stderr is not None
            else 0
        ),
        stdout_preview=sanitize_text(stdout),
        stderr_preview=sanitize_text(stderr),
        resource_usage=sanitize_mapping(
            resource_usage
        ),
        metadata=sanitize_mapping(metadata),
    )


def validate_execution_telemetry(
    telemetry: ExecutionTelemetry,
) -> bool:
    if not isinstance(
        telemetry,
        ExecutionTelemetry,
    ):
        return False

    try:
        validate_timestamp(telemetry.started_at)

        if telemetry.completed_at is not None:
            validate_timestamp(
                telemetry.completed_at
            )

        sanitize_command(telemetry.command)
        sanitize_mapping(telemetry.metadata)
        sanitize_mapping(
            telemetry.resource_usage
        )

    except ExecutionTelemetryError:
        return False

    if telemetry.duration_seconds is not None:
        if telemetry.duration_seconds < 0:
            return False

    if telemetry.stdout_bytes < 0:
        return False

    if telemetry.stderr_bytes < 0:
        return False

    if telemetry.timed_out and telemetry.status != "timeout":
        return False

    if telemetry.terminated and telemetry.status != "terminated":
        return False

    return True
