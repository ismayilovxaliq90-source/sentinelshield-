from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class FailureType(str, Enum):
    NONE = "NONE"
    PROCESS_EXIT = "PROCESS_EXIT"
    NONZERO_EXIT = "NONZERO_EXIT"
    TIMEOUT = "TIMEOUT"
    RESOURCE = "RESOURCE"
    EXCEPTION = "EXCEPTION"
    VALIDATION = "VALIDATION"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class FailureEvent:
    failed: bool
    failure_type: FailureType
    message: str
    exit_code: int | None = None


class FailureDetection:
    """
    Deterministic failure detection layer.

    This component detects and records failure conditions.
    It does not restart processes or perform recovery.
    """

    def __init__(self) -> None:
        self._last_failure = FailureEvent(
            failed=False,
            failure_type=FailureType.NONE,
            message="",
            exit_code=None,
        )

    @property
    def failed(self) -> bool:
        return self._last_failure.failed

    @property
    def last_failure(self) -> FailureEvent:
        return self._last_failure

    def clear(self) -> FailureEvent:
        self._last_failure = FailureEvent(
            failed=False,
            failure_type=FailureType.NONE,
            message="",
            exit_code=None,
        )
        return self._last_failure

    def record(
        self,
        failure_type: FailureType,
        message: str,
        exit_code: int | None = None,
    ) -> FailureEvent:
        if not isinstance(failure_type, FailureType):
            raise TypeError("failure_type must be a FailureType")

        if failure_type == FailureType.NONE:
            raise ValueError("failure_type cannot be NONE")

        if not isinstance(message, str):
            raise TypeError("message must be a string")

        if exit_code is not None and not isinstance(exit_code, int):
            raise TypeError("exit_code must be an integer or None")

        self._last_failure = FailureEvent(
            failed=True,
            failure_type=failure_type,
            message=message,
            exit_code=exit_code,
        )

        return self._last_failure

    def detect_exit(self, exit_code: int) -> FailureEvent:
        if not isinstance(exit_code, int):
            raise TypeError("exit_code must be an integer")

        if exit_code == 0:
            return self.clear()

        return self.record(
            FailureType.NONZERO_EXIT,
            f"process exited with code {exit_code}",
            exit_code=exit_code,
        )

    def detect_timeout(self, message: str = "execution timeout") -> FailureEvent:
        return self.record(
            FailureType.TIMEOUT,
            message,
        )

    def detect_resource(self, message: str) -> FailureEvent:
        return self.record(
            FailureType.RESOURCE,
            message,
        )

    def detect_exception(self, message: str) -> FailureEvent:
        return self.record(
            FailureType.EXCEPTION,
            message,
        )

    def detect_validation(self, message: str) -> FailureEvent:
        return self.record(
            FailureType.VALIDATION,
            message,
        )

    def detect_process_exit(self, message: str = "process exited") -> FailureEvent:
        return self.record(
            FailureType.PROCESS_EXIT,
            message,
        )

    def detect_unknown(self, message: str = "unknown failure") -> FailureEvent:
        return self.record(
            FailureType.UNKNOWN,
            message,
        )
