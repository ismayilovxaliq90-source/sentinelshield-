from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class FailureClass(str, Enum):
    NONE = "NONE"
    PROCESS = "PROCESS"
    TIMEOUT = "TIMEOUT"
    RESOURCE = "RESOURCE"
    VALIDATION = "VALIDATION"
    EXCEPTION = "EXCEPTION"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class ClassificationResult:
    failure_class: FailureClass
    reason: str


class FailureClassifier:
    """
    Deterministic failure classification.

    Converts known failure signals into a stable failure class.
    Does not perform recovery or process control.
    """

    def classify(
        self,
        *,
        exit_code: int | None = None,
        timed_out: bool = False,
        resource_exceeded: bool = False,
        validation_failed: bool = False,
        exception: bool = False,
        process_failed: bool = False,
        reason: str = "",
    ) -> ClassificationResult:

        if not isinstance(timed_out, bool):
            raise TypeError("timed_out must be bool")

        if not isinstance(resource_exceeded, bool):
            raise TypeError("resource_exceeded must be bool")

        if not isinstance(validation_failed, bool):
            raise TypeError("validation_failed must be bool")

        if not isinstance(exception, bool):
            raise TypeError("exception must be bool")

        if not isinstance(process_failed, bool):
            raise TypeError("process_failed must be bool")

        if exit_code is not None and not isinstance(exit_code, int):
            raise TypeError("exit_code must be int or None")

        if not isinstance(reason, str):
            raise TypeError("reason must be str")

        if timed_out:
            return ClassificationResult(
                FailureClass.TIMEOUT,
                reason or "execution timeout",
            )

        if resource_exceeded:
            return ClassificationResult(
                FailureClass.RESOURCE,
                reason or "resource limit exceeded",
            )

        if validation_failed:
            return ClassificationResult(
                FailureClass.VALIDATION,
                reason or "validation failure",
            )

        if exception:
            return ClassificationResult(
                FailureClass.EXCEPTION,
                reason or "exception detected",
            )

        if process_failed:
            return ClassificationResult(
                FailureClass.PROCESS,
                reason or "process failure",
            )

        if exit_code is not None and exit_code != 0:
            return ClassificationResult(
                FailureClass.PROCESS,
                reason or f"process exited with code {exit_code}",
            )

        return ClassificationResult(
            FailureClass.NONE,
            reason,
        )

    def classify_from_failure_type(
        self,
        failure_type: str,
        reason: str = "",
    ) -> ClassificationResult:

        if not isinstance(failure_type, str):
            raise TypeError("failure_type must be str")

        mapping = {
            "NONE": FailureClass.NONE,
            "PROCESS_EXIT": FailureClass.PROCESS,
            "NONZERO_EXIT": FailureClass.PROCESS,
            "TIMEOUT": FailureClass.TIMEOUT,
            "RESOURCE": FailureClass.RESOURCE,
            "VALIDATION": FailureClass.VALIDATION,
            "EXCEPTION": FailureClass.EXCEPTION,
            "UNKNOWN": FailureClass.UNKNOWN,
        }

        failure_class = mapping.get(
            failure_type,
            FailureClass.UNKNOWN,
        )

        return ClassificationResult(
            failure_class,
            reason or failure_type,
        )
