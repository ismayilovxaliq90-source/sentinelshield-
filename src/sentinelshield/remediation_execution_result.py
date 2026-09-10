from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import json
from typing import Iterable


MAX_PATH_LENGTH = 4096
MAX_ITEMS = 10000
MAX_FAILURE_LENGTH = 4096


class RemediationExecutionResultError(ValueError):
    """Raised when TASK 215 input is invalid."""


class ExecutionResultState(str, Enum):
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"
    TERMINATED = "TERMINATED"
    UNEXPECTED_CHANGE = "UNEXPECTED_CHANGE"


def _normalize_path(value: object) -> str:
    if not isinstance(value, str):
        raise RemediationExecutionResultError(
            "change path must be a string"
        )

    if not value or not value.strip():
        raise RemediationExecutionResultError(
            "change path must not be empty"
        )

    if len(value) > MAX_PATH_LENGTH:
        raise RemediationExecutionResultError(
            "change path is too long"
        )

    normalized = value.replace("\\", "/")

    if normalized.startswith("/"):
        raise RemediationExecutionResultError(
            "absolute paths are not allowed"
        )

    parts = normalized.split("/")

    if any(part == ".." for part in parts):
        raise RemediationExecutionResultError(
            "parent traversal is not allowed"
        )

    if normalized in {".", "./"}:
        raise RemediationExecutionResultError(
            "repository root is not a valid change path"
        )

    return normalized


def _normalize_paths(values: Iterable[str]) -> frozenset[str]:
    if isinstance(values, (str, bytes)):
        raise RemediationExecutionResultError(
            "paths must be an iterable, not a string"
        )

    try:
        iterator = iter(values)
    except TypeError as error:
        raise RemediationExecutionResultError(
            "paths must be iterable"
        ) from error

    result: set[str] = set()

    for value in iterator:
        result.add(_normalize_path(value))

        if len(result) > MAX_ITEMS:
            raise RemediationExecutionResultError(
                "too many change paths"
            )

    return frozenset(result)


def _normalize_failure(value: object) -> str | None:
    if value is None:
        return None

    if not isinstance(value, str):
        raise RemediationExecutionResultError(
            "failure_category must be a string or None"
        )

    if len(value) > MAX_FAILURE_LENGTH:
        raise RemediationExecutionResultError(
            "failure_category is too long"
        )

    return value


@dataclass(frozen=True)
class RemediationExecutionResult:
    """
    Immutable final execution result for TASK 215.

    This object describes an execution outcome.
    It does not execute remediation or rollback operations.
    """

    state: ExecutionResultState
    return_code: int | None
    expected_changes: frozenset[str]
    actual_changes: frozenset[str]
    applied_changes: frozenset[str]
    missing_changes: frozenset[str]
    unexpected_changes: frozenset[str]
    failure_category: str | None = None
    timed_out: bool = False
    resource_limited: bool = False
    terminated: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.state, ExecutionResultState):
            raise RemediationExecutionResultError(
                "invalid execution result state"
            )

        if self.return_code is not None:
            if type(self.return_code) is not int:
                raise RemediationExecutionResultError(
                    "return_code must be an integer or None"
                )

        for name in (
            "timed_out",
            "resource_limited",
            "terminated",
        ):
            value = getattr(self, name)

            if type(value) is not bool:
                raise RemediationExecutionResultError(
                    f"{name} must be a boolean"
                )

        expected = _normalize_paths(self.expected_changes)
        actual = _normalize_paths(self.actual_changes)
        applied = _normalize_paths(self.applied_changes)
        missing = _normalize_paths(self.missing_changes)
        unexpected = _normalize_paths(self.unexpected_changes)

        failure = _normalize_failure(self.failure_category)

        object.__setattr__(
            self,
            "expected_changes",
            expected,
        )
        object.__setattr__(
            self,
            "actual_changes",
            actual,
        )
        object.__setattr__(
            self,
            "applied_changes",
            applied,
        )
        object.__setattr__(
            self,
            "missing_changes",
            missing,
        )
        object.__setattr__(
            self,
            "unexpected_changes",
            unexpected,
        )
        object.__setattr__(
            self,
            "failure_category",
            failure,
        )

        calculated_applied = expected & actual
        calculated_missing = expected - actual
        calculated_unexpected = actual - expected

        if applied != calculated_applied:
            raise RemediationExecutionResultError(
                "applied_changes is inconsistent"
            )

        if missing != calculated_missing:
            raise RemediationExecutionResultError(
                "missing_changes is inconsistent"
            )

        if unexpected != calculated_unexpected:
            raise RemediationExecutionResultError(
                "unexpected_changes is inconsistent"
            )

        if actual != applied | unexpected:
            raise RemediationExecutionResultError(
                "actual_changes is inconsistent"
            )

        if self.timed_out and self.state is not ExecutionResultState.TIMEOUT:
            raise RemediationExecutionResultError(
                "timed_out requires TIMEOUT state"
            )

        if (
            self.resource_limited
            and self.state is not ExecutionResultState.RESOURCE_LIMIT
        ):
            raise RemediationExecutionResultError(
                "resource_limited requires RESOURCE_LIMIT state"
            )

        if self.terminated and self.state is not ExecutionResultState.TERMINATED:
            raise RemediationExecutionResultError(
                "terminated requires TERMINATED state"
            )

        if self.state is ExecutionResultState.SUCCESS:
            if self.return_code != 0:
                raise RemediationExecutionResultError(
                    "SUCCESS requires return_code 0"
                )

            if missing:
                raise RemediationExecutionResultError(
                    "SUCCESS cannot have missing changes"
                )

            if unexpected:
                raise RemediationExecutionResultError(
                    "SUCCESS cannot have unexpected changes"
                )

            if failure is not None:
                raise RemediationExecutionResultError(
                    "SUCCESS cannot contain failure_category"
                )

            if (
                self.timed_out
                or self.resource_limited
                or self.terminated
            ):
                raise RemediationExecutionResultError(
                    "SUCCESS cannot have execution failure flags"
                )

        elif self.state is ExecutionResultState.PARTIAL:
            if not missing:
                raise RemediationExecutionResultError(
                    "PARTIAL requires missing changes"
                )

            if unexpected:
                raise RemediationExecutionResultError(
                    "PARTIAL cannot hide unexpected changes"
                )

            if self.return_code == 0:
                raise RemediationExecutionResultError(
                    "PARTIAL cannot have return_code 0"
                )

        elif self.state is ExecutionResultState.UNEXPECTED_CHANGE:
            if not unexpected:
                raise RemediationExecutionResultError(
                    "UNEXPECTED_CHANGE requires unexpected changes"
                )

            if self.return_code == 0:
                raise RemediationExecutionResultError(
                    "UNEXPECTED_CHANGE cannot have return_code 0"
                )

        elif self.state is ExecutionResultState.TIMEOUT:
            if not self.timed_out:
                raise RemediationExecutionResultError(
                    "TIMEOUT requires timed_out=True"
                )

            if self.return_code == 0:
                raise RemediationExecutionResultError(
                    "TIMEOUT cannot have return_code 0"
                )

        elif self.state is ExecutionResultState.RESOURCE_LIMIT:
            if not self.resource_limited:
                raise RemediationExecutionResultError(
                    "RESOURCE_LIMIT requires resource_limited=True"
                )

            if self.return_code == 0:
                raise RemediationExecutionResultError(
                    "RESOURCE_LIMIT cannot have return_code 0"
                )

        elif self.state is ExecutionResultState.TERMINATED:
            if not self.terminated:
                raise RemediationExecutionResultError(
                    "TERMINATED requires terminated=True"
                )

            if self.return_code == 0:
                raise RemediationExecutionResultError(
                    "TERMINATED cannot have return_code 0"
                )

        elif self.state is ExecutionResultState.FAILED:
            if self.return_code == 0:
                raise RemediationExecutionResultError(
                    "FAILED cannot have return_code 0"
                )

    @property
    def succeeded(self) -> bool:
        return self.state is ExecutionResultState.SUCCESS

    @property
    def failed(self) -> bool:
        return not self.succeeded

    @property
    def is_partial(self) -> bool:
        return self.state is ExecutionResultState.PARTIAL

    @property
    def requires_recovery(self) -> bool:
        return self.failed

    def to_dict(self) -> dict[str, object]:
        return {
            "state": self.state.value,
            "return_code": self.return_code,
            "expected_changes": sorted(self.expected_changes),
            "actual_changes": sorted(self.actual_changes),
            "applied_changes": sorted(self.applied_changes),
            "missing_changes": sorted(self.missing_changes),
            "unexpected_changes": sorted(self.unexpected_changes),
            "failure_category": self.failure_category,
            "timed_out": self.timed_out,
            "resource_limited": self.resource_limited,
            "terminated": self.terminated,
            "succeeded": self.succeeded,
            "failed": self.failed,
            "is_partial": self.is_partial,
            "requires_recovery": self.requires_recovery,
        }

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            ensure_ascii=False,
        )


def create_remediation_execution_result(
    *,
    return_code: int | None,
    expected_changes: Iterable[str],
    actual_changes: Iterable[str],
    failure_category: str | None = None,
    timed_out: bool = False,
    resource_limited: bool = False,
    terminated: bool = False,
) -> RemediationExecutionResult:
    """
    Construct the authoritative TASK 215 execution result.
    """

    expected = _normalize_paths(expected_changes)
    actual = _normalize_paths(actual_changes)

    applied = expected & actual
    missing = expected - actual
    unexpected = actual - expected

    if unexpected:
        state = ExecutionResultState.UNEXPECTED_CHANGE

    elif timed_out:
        state = ExecutionResultState.TIMEOUT

    elif resource_limited:
        state = ExecutionResultState.RESOURCE_LIMIT

    elif terminated:
        state = ExecutionResultState.TERMINATED

    elif missing and return_code != 0:
        state = ExecutionResultState.PARTIAL

    elif missing:
        state = ExecutionResultState.PARTIAL

    elif return_code == 0:
        state = ExecutionResultState.SUCCESS

    else:
        state = ExecutionResultState.FAILED

    return RemediationExecutionResult(
        state=state,
        return_code=return_code,
        expected_changes=expected,
        actual_changes=actual,
        applied_changes=applied,
        missing_changes=missing,
        unexpected_changes=unexpected,
        failure_category=failure_category,
        timed_out=timed_out,
        resource_limited=resource_limited,
        terminated=terminated,
    )


def validate_remediation_execution_result(
    result: object,
) -> bool:
    if not isinstance(result, RemediationExecutionResult):
        return False

    try:
        RemediationExecutionResult(
            state=result.state,
            return_code=result.return_code,
            expected_changes=result.expected_changes,
            actual_changes=result.actual_changes,
            applied_changes=result.applied_changes,
            missing_changes=result.missing_changes,
            unexpected_changes=result.unexpected_changes,
            failure_category=result.failure_category,
            timed_out=result.timed_out,
            resource_limited=result.resource_limited,
            terminated=result.terminated,
        )
    except (
        TypeError,
        ValueError,
        RemediationExecutionResultError,
    ):
        return False

    return True


__all__ = [
    "RemediationExecutionResultError",
    "ExecutionResultState",
    "RemediationExecutionResult",
    "create_remediation_execution_result",
    "validate_remediation_execution_result",
]
