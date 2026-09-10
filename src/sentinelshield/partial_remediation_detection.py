from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import json
from pathlib import PurePosixPath
from typing import Iterable


MAX_PATH_LENGTH = 4096
MAX_ITEMS = 10000


class PartialRemediationDetectionError(ValueError):
    """Raised when TASK 214 input is invalid."""


class RemediationState(str, Enum):
    NO_CHANGE = "NO_CHANGE"
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    UNEXPECTED_CHANGE = "UNEXPECTED_CHANGE"


def _normalize_path(value: object) -> str:
    if not isinstance(value, str):
        raise PartialRemediationDetectionError(
            "change path must be a string"
        )

    if not value or not value.strip():
        raise PartialRemediationDetectionError(
            "change path must not be empty"
        )

    if len(value) > MAX_PATH_LENGTH:
        raise PartialRemediationDetectionError(
            "change path is too long"
        )

    normalized = value.replace("\\", "/")

    path = PurePosixPath(normalized)

    if path.is_absolute():
        raise PartialRemediationDetectionError(
            "absolute paths are not allowed"
        )

    parts = normalized.split("/")

    if any(part == ".." for part in parts):
        raise PartialRemediationDetectionError(
            "parent traversal is not allowed"
        )

    if normalized in {".", "./"}:
        raise PartialRemediationDetectionError(
            "repository root is not a file change"
        )

    return normalized


def _normalize_paths(values: Iterable[str]) -> frozenset[str]:
    if isinstance(values, (str, bytes)):
        raise PartialRemediationDetectionError(
            "paths must be an iterable, not a string"
        )

    try:
        iterator = iter(values)
    except TypeError as error:
        raise PartialRemediationDetectionError(
            "paths must be iterable"
        ) from error

    result: set[str] = set()

    for value in iterator:
        result.add(_normalize_path(value))

        if len(result) > MAX_ITEMS:
            raise PartialRemediationDetectionError(
                "too many change paths"
            )

    return frozenset(result)


@dataclass(frozen=True)
class PartialRemediationResult:
    """
    Immutable result of TASK 214 partial-remediation detection.
    """

    state: RemediationState
    expected_changes: frozenset[str]
    actual_changes: frozenset[str]
    applied_changes: frozenset[str]
    missing_changes: frozenset[str]
    unexpected_changes: frozenset[str]
    failure_category: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.state, RemediationState):
            raise PartialRemediationDetectionError(
                "invalid remediation state"
            )

        expected = _normalize_paths(self.expected_changes)
        actual = _normalize_paths(self.actual_changes)
        applied = _normalize_paths(self.applied_changes)
        missing = _normalize_paths(self.missing_changes)
        unexpected = _normalize_paths(self.unexpected_changes)

        object.__setattr__(self, "expected_changes", expected)
        object.__setattr__(self, "actual_changes", actual)
        object.__setattr__(self, "applied_changes", applied)
        object.__setattr__(self, "missing_changes", missing)
        object.__setattr__(self, "unexpected_changes", unexpected)

        if self.failure_category is not None:
            if not isinstance(self.failure_category, str):
                raise PartialRemediationDetectionError(
                    "failure_category must be a string or None"
                )

            if len(self.failure_category) > 128:
                raise PartialRemediationDetectionError(
                    "failure_category is too long"
                )

        calculated_applied = expected & actual
        calculated_missing = expected - actual
        calculated_unexpected = actual - expected

        if applied != calculated_applied:
            raise PartialRemediationDetectionError(
                "applied_changes is inconsistent"
            )

        if missing != calculated_missing:
            raise PartialRemediationDetectionError(
                "missing_changes is inconsistent"
            )

        if unexpected != calculated_unexpected:
            raise PartialRemediationDetectionError(
                "unexpected_changes is inconsistent"
            )

        if actual != applied | unexpected:
            raise PartialRemediationDetectionError(
                "actual_changes is inconsistent"
            )

        if unexpected:
            expected_state = RemediationState.UNEXPECTED_CHANGE
        elif not expected and not actual:
            expected_state = RemediationState.NO_CHANGE
        elif not missing:
            expected_state = RemediationState.COMPLETE
        else:
            expected_state = RemediationState.PARTIAL

        if self.state is not expected_state:
            raise PartialRemediationDetectionError(
                "remediation state is inconsistent"
            )

    @property
    def is_partial(self) -> bool:
        return self.state is RemediationState.PARTIAL

    @property
    def is_complete(self) -> bool:
        return self.state is RemediationState.COMPLETE

    @property
    def is_safe(self) -> bool:
        return self.state is not RemediationState.UNEXPECTED_CHANGE

    def to_dict(self) -> dict[str, object]:
        return {
            "state": self.state.value,
            "expected_changes": sorted(self.expected_changes),
            "actual_changes": sorted(self.actual_changes),
            "applied_changes": sorted(self.applied_changes),
            "missing_changes": sorted(self.missing_changes),
            "unexpected_changes": sorted(self.unexpected_changes),
            "failure_category": self.failure_category,
            "is_partial": self.is_partial,
            "is_complete": self.is_complete,
            "is_safe": self.is_safe,
        }

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            ensure_ascii=False,
        )


def detect_partial_remediation(
    expected_changes: Iterable[str],
    actual_changes: Iterable[str],
    *,
    failure_category: str | None = None,
) -> PartialRemediationResult:
    """
    Compare expected remediation changes with actual changes.

    This function performs classification only.
    It does not modify files, execute remediation, or rollback changes.
    """

    expected = _normalize_paths(expected_changes)
    actual = _normalize_paths(actual_changes)

    applied = expected & actual
    missing = expected - actual
    unexpected = actual - expected

    if unexpected:
        state = RemediationState.UNEXPECTED_CHANGE
    elif not expected and not actual:
        state = RemediationState.NO_CHANGE
    elif not missing:
        state = RemediationState.COMPLETE
    else:
        state = RemediationState.PARTIAL

    return PartialRemediationResult(
        state=state,
        expected_changes=expected,
        actual_changes=actual,
        applied_changes=applied,
        missing_changes=missing,
        unexpected_changes=unexpected,
        failure_category=failure_category,
    )


def validate_partial_remediation(
    result: object,
) -> bool:
    if not isinstance(result, PartialRemediationResult):
        return False

    try:
        PartialRemediationResult(
            state=result.state,
            expected_changes=result.expected_changes,
            actual_changes=result.actual_changes,
            applied_changes=result.applied_changes,
            missing_changes=result.missing_changes,
            unexpected_changes=result.unexpected_changes,
            failure_category=result.failure_category,
        )
    except (
        TypeError,
        ValueError,
        PartialRemediationDetectionError,
    ):
        return False

    return True


__all__ = [
    "PartialRemediationDetectionError",
    "RemediationState",
    "PartialRemediationResult",
    "detect_partial_remediation",
    "validate_partial_remediation",
]
