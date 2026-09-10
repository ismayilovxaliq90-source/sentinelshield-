from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any, Sequence


class ExecutionFailureCaptureError(ValueError):
    """Raised when failure-capture input is invalid."""


VALID_FAILURE_CATEGORIES = frozenset(
    {
        "NONE",
        "COMMAND_NOT_FOUND",
        "PERMISSION_ERROR",
        "EXECUTION_ERROR",
        "NON_ZERO_EXIT",
        "TIMEOUT",
        "RESOURCE_LIMIT",
        "TERMINATED",
        "UNEXPECTED_EXCEPTION",
    }
)


_SECRET_PATTERNS = (
    re.compile(
        r"(?i)(password|passwd|pwd|token|secret|api[_-]?key|"
        r"access[_-]?key|private[_-]?key)\s*[:=]\s*[^\s,;]+"
    ),
    re.compile(
        r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+"
    ),
    re.compile(
        r"\bsk-[A-Za-z0-9_-]{8,}\b"
    ),
)


def sanitize_text(value: str, max_length: int = 4096) -> str:
    if not isinstance(value, str):
        raise ExecutionFailureCaptureError(
            "text value must be a string"
        )

    if type(max_length) is not int or max_length <= 0:
        raise ExecutionFailureCaptureError(
            "max_length must be a positive integer"
        )

    sanitized = value

    for pattern in _SECRET_PATTERNS:
        sanitized = pattern.sub(
            lambda match: _redact_match(match.group(0)),
            sanitized,
        )

    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length] + "…"

    return sanitized


def _redact_match(value: str) -> str:
    if "=" in value:
        prefix, _ = value.split("=", 1)
        return prefix + "=[REDACTED]"

    if ":" in value:
        prefix, _ = value.split(":", 1)
        return prefix + ":[REDACTED]"

    if value.lower().startswith("bearer "):
        return "Bearer [REDACTED]"

    return "[REDACTED]"


def sanitize_command(
    command: Sequence[str],
) -> tuple[str, ...]:
    if isinstance(command, (str, bytes)):
        raise ExecutionFailureCaptureError(
            "command must be a sequence"
        )

    if not isinstance(command, Sequence):
        raise ExecutionFailureCaptureError(
            "command must be a sequence"
        )

    normalized = tuple(command)

    if not normalized:
        raise ExecutionFailureCaptureError(
            "command must not be empty"
        )

    result: list[str] = []

    for argument in normalized:
        if not isinstance(argument, str):
            raise ExecutionFailureCaptureError(
                "command arguments must be strings"
            )

        if "\x00" in argument:
            raise ExecutionFailureCaptureError(
                "NULL character is not allowed"
            )

        result.append(sanitize_text(argument, 1024))

    return tuple(result)


def _exception_category(exception: BaseException) -> str:
    if isinstance(exception, FileNotFoundError):
        return "COMMAND_NOT_FOUND"

    if isinstance(exception, PermissionError):
        return "PERMISSION_ERROR"

    if isinstance(exception, OSError):
        return "EXECUTION_ERROR"

    if isinstance(exception, TimeoutError):
        return "TIMEOUT"

    return "UNEXPECTED_EXCEPTION"


@dataclass(frozen=True)
class ExecutionFailure:
    category: str
    message: str
    exception_type: str | None
    return_code: int | None
    timed_out: bool
    resource_limit_exceeded: bool
    terminated: bool

    def __post_init__(self) -> None:
        if self.category not in VALID_FAILURE_CATEGORIES:
            raise ExecutionFailureCaptureError(
                f"invalid failure category: {self.category}"
            )

        if not isinstance(self.message, str):
            raise ExecutionFailureCaptureError(
                "failure message must be a string"
            )

        if self.exception_type is not None:
            if not isinstance(self.exception_type, str):
                raise ExecutionFailureCaptureError(
                    "exception_type must be a string or None"
                )

        if self.return_code is not None:
            if type(self.return_code) is not int:
                raise ExecutionFailureCaptureError(
                    "return_code must be an integer or None"
                )

        if type(self.timed_out) is not bool:
            raise ExecutionFailureCaptureError(
                "timed_out must be boolean"
            )

        if type(self.resource_limit_exceeded) is not bool:
            raise ExecutionFailureCaptureError(
                "resource_limit_exceeded must be boolean"
            )

        if type(self.terminated) is not bool:
            raise ExecutionFailureCaptureError(
                "terminated must be boolean"
            )

    @property
    def failed(self) -> bool:
        return self.category != "NONE"

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "message": sanitize_text(self.message),
            "exception_type": (
                sanitize_text(self.exception_type)
                if self.exception_type is not None
                else None
            ),
            "return_code": self.return_code,
            "timed_out": self.timed_out,
            "resource_limit_exceeded": self.resource_limit_exceeded,
            "terminated": self.terminated,
            "failed": self.failed,
        }


@dataclass(frozen=True)
class ExecutionFailureResult:
    command: tuple[str, ...]
    failure: ExecutionFailure
    stdout: str
    stderr: str

    @property
    def failed(self) -> bool:
        return self.failure.failed

    def to_dict(self) -> dict[str, Any]:
        return {
            "command": list(self.command),
            "failure": self.failure.to_dict(),
            "stdout": sanitize_text(self.stdout),
            "stderr": sanitize_text(self.stderr),
            "failed": self.failed,
        }

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
        )


def capture_execution_failure(
    command: Sequence[str],
    *,
    return_code: int | None = None,
    exception: BaseException | None = None,
    timed_out: bool = False,
    resource_limit_exceeded: bool = False,
    terminated: bool = False,
    stdout: str = "",
    stderr: str = "",
) -> ExecutionFailureResult:
    normalized_command = sanitize_command(command)

    if return_code is not None and type(return_code) is not int:
        raise ExecutionFailureCaptureError(
            "return_code must be an integer or None"
        )

    for name, value in (
        ("timed_out", timed_out),
        ("resource_limit_exceeded", resource_limit_exceeded),
        ("terminated", terminated),
    ):
        if type(value) is not bool:
            raise ExecutionFailureCaptureError(
                f"{name} must be boolean"
            )

    if not isinstance(stdout, str):
        raise ExecutionFailureCaptureError(
            "stdout must be a string"
        )

    if not isinstance(stderr, str):
        raise ExecutionFailureCaptureError(
            "stderr must be a string"
        )

    if timed_out:
        category = "TIMEOUT"
    elif resource_limit_exceeded:
        category = "RESOURCE_LIMIT"
    elif terminated:
        category = "TERMINATED"
    elif exception is not None:
        category = _exception_category(exception)
    elif return_code is not None and return_code != 0:
        category = "NON_ZERO_EXIT"
    else:
        category = "NONE"

    if exception is not None:
        message = str(exception)
        exception_type = type(exception).__name__
    elif category == "TIMEOUT":
        message = "execution timed out"
        exception_type = None
    elif category == "RESOURCE_LIMIT":
        message = "execution exceeded a resource limit"
        exception_type = None
    elif category == "TERMINATED":
        message = "execution was terminated"
        exception_type = None
    elif category == "NON_ZERO_EXIT":
        message = (
            f"execution returned non-zero exit code: "
            f"{return_code}"
        )
        exception_type = None
    else:
        message = ""
        exception_type = None

    failure = ExecutionFailure(
        category=category,
        message=sanitize_text(message),
        exception_type=(
            sanitize_text(exception_type)
            if exception_type is not None
            else None
        ),
        return_code=return_code,
        timed_out=timed_out,
        resource_limit_exceeded=resource_limit_exceeded,
        terminated=terminated,
    )

    return ExecutionFailureResult(
        command=normalized_command,
        failure=failure,
        stdout=sanitize_text(stdout),
        stderr=sanitize_text(stderr),
    )


def capture_exception(
    command: Sequence[str],
    exception: BaseException,
) -> ExecutionFailureResult:
    if not isinstance(exception, BaseException):
        raise ExecutionFailureCaptureError(
            "exception must derive from BaseException"
        )

    return capture_execution_failure(
        command,
        exception=exception,
    )


def capture_execution_result(
    command: Sequence[str],
    *,
    return_code: int,
    stdout: str = "",
    stderr: str = "",
    timed_out: bool = False,
    resource_limit_exceeded: bool = False,
    terminated: bool = False,
) -> ExecutionFailureResult:
    return capture_execution_failure(
        command,
        return_code=return_code,
        stdout=stdout,
        stderr=stderr,
        timed_out=timed_out,
        resource_limit_exceeded=resource_limit_exceeded,
        terminated=terminated,
    )


def validate_execution_failure(
    result: ExecutionFailureResult,
) -> bool:
    if not isinstance(result, ExecutionFailureResult):
        return False

    if not result.command:
        return False

    failure = result.failure

    if failure.category == "NONE":
        if failure.failed:
            return False

        if (
            failure.timed_out
            or failure.resource_limit_exceeded
            or failure.terminated
        ):
            return False

        if failure.return_code not in (None, 0):
            return False

    if failure.category == "TIMEOUT":
        if not failure.timed_out:
            return False

    if failure.category == "RESOURCE_LIMIT":
        if not failure.resource_limit_exceeded:
            return False

    if failure.category == "TERMINATED":
        if not failure.terminated:
            return False

    if failure.category == "NON_ZERO_EXIT":
        if failure.return_code in (None, 0):
            return False

    if failure.exception_type is not None:
        if not failure.exception_type:
            return False

    try:
        json.dumps(result.to_dict(), sort_keys=True)
    except (TypeError, ValueError):
        return False

    return True


__all__ = [
    "ExecutionFailure",
    "ExecutionFailureCaptureError",
    "ExecutionFailureResult",
    "VALID_FAILURE_CATEGORIES",
    "capture_exception",
    "capture_execution_failure",
    "capture_execution_result",
    "sanitize_command",
    "sanitize_text",
    "validate_execution_failure",
]
