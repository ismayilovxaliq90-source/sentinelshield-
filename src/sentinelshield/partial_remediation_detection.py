from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import json
import os
from pathlib import Path
import subprocess
from typing import Iterable, Mapping, Sequence


MAX_PATH_LENGTH = 4096
MAX_ITEMS = 10000


class PartialRemediationDetectionError(ValueError):
    """Raised when partial-remediation input is invalid."""


class RemediationState(str, Enum):
    NO_CHANGE = "NO_CHANGE"
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    UNEXPECTED_CHANGE = "UNEXPECTED_CHANGE"


def _validate_relative_path(value: object) -> str:
    if not isinstance(value, str):
        raise PartialRemediationDetectionError("path must be a string")

    if not value or not value.strip():
        raise PartialRemediationDetectionError("path must not be empty")

    if len(value) > MAX_PATH_LENGTH:
        raise PartialRemediationDetectionError("path is too long")

    path = Path(value)

    if path.is_absolute():
        raise PartialRemediationDetectionError(
            "absolute paths are not allowed"
        )

    normalized = value.replace("\\", "/")

    if normalized.startswith("../") or normalized == "..":
        raise PartialRemediationDetectionError(
            "parent traversal is not allowed"
        )

    parts = [part for part in normalized.split("/") if part]

    if ".." in parts:
        raise PartialRemediationDetectionError(
            "parent traversal is not allowed"
        )

    return normalized


def _normalize_paths(values: Iterable[str]) -> frozenset[str]:
    if isinstance(values, (str, bytes)):
        raise PartialRemediationDetectionError(
            "paths must be an iterable of strings"
        )

    result: set[str] = set()

    for value in values:
        result.add(_validate_relative_path(value))

        if len(result) > MAX_ITEMS:
            raise PartialRemediationDetectionError(
                "too many paths"
            )

    return frozenset(result)


def _normalize_mapping(
    values: Mapping[str, str],
) -> dict[str, str]:
    if not isinstance(values, Mapping):
        raise PartialRemediationDetectionError(
            "expected mapping"
        )

    result: dict[str, str] = {}

    for key, value in values.items():
        normalized_key = _validate_relative_path(key)

        if not isinstance(value, str):
            raise PartialRemediationDetectionError(
                "mapping values must be strings"
            )

        if len(value) > MAX_PATH_LENGTH:
            raise PartialRemediationDetectionError(
                "mapping value is too long"
            )

        result[normalized_key] = value

        if len(result) > MAX_ITEMS:
            raise PartialRemediationDetectionError(
                "too many mapping entries"
            )

    return result


@dataclass(frozen=True)
class PartialRemediationResult:
    state: RemediationState
    expected_changes: frozenset[str]
    actual_changes: frozenset[str]
    applied_changes: frozenset[str]
    missing_changes: frozenset[str]
    unexpected_changes: frozenset[str]
    failure_category: str | None = None

    def __post_init__(self) -> None:
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

        if not isinstance(self.state, RemediationState):
            raise PartialRemediationDetectionError(
                "invalid remediation state"
            )

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

        if unexpected and self.state != RemediationState.UNEXPECTED_CHANGE:
            raise PartialRemediationDetectionError(
                "unexpected changes require UNEXPECTED_CHANGE state"
            )

        if not unexpected:
            if not expected and not actual:
                expected_state = RemediationState.NO_CHANGE
            elif not missing:
                expected_state = RemediationState.COMPLETE
            else:
                expected_state = RemediationState.PARTIAL

            if self.state != expected_state:
                raise PartialRemediationDetectionError(
                    "remediation state is inconsistent"
                )

    @property
    def is_partial(self) -> bool:
        return self.state == RemediationState.PARTIAL

    @property
    def is_complete(self) -> bool:
        return self.state == RemediationState.COMPLETE

    @property
    def is_safe(self) -> bool:
        return self.state != RemediationState.UNEXPECTED_CHANGE

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
    result: PartialRemediationResult,
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
    except (TypeError, ValueError, PartialRemediationDetectionError):
        return False

    return True


def _repository_root(start_path: str | os.PathLike[str]) -> Path:
    root = Path(start_path).expanduser().resolve()

    if not root.exists() or not root.is_dir():
        raise PartialRemediationDetectionError(
            "repository path must be an existing directory"
        )

    completed = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--show-toplevel"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=False,
        timeout=10.0,
        check=False,
    )

    if completed.returncode != 0:
        raise PartialRemediationDetectionError(
            "path is not a Git repository"
        )

    return Path(completed.stdout.strip()).resolve()


def collect_repository_changes(
    start_path: str | os.PathLike[str],
) -> frozenset[str]:
    root = _repository_root(start_path)

    completed = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain=v1", "--untracked-files=all"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=False,
        timeout=10.0,
        check=False,
    )

    if completed.returncode != 0:
        raise PartialRemediationDetectionError(
            "unable to collect Git changes"
        )

    changes: set[str] = set()

    for line in completed.stdout.splitlines():
        if not line.strip():
            continue

        if len(line) < 4:
            raise PartialRemediationDetectionError(
                "invalid Git status entry"
            )

        status_path = line[3:]

        # Rename/copy entries contain "old -> new".
        if " -> " in status_path:
            status_path = status_path.split(" -> ", 1)[1]

        if status_path.startswith('"') and status_path.endswith('"'):
            status_path = status_path[1:-1]

        relative = _validate_relative_path(status_path)

        candidate = (root / relative).resolve()

        try:
            candidate.relative_to(root)
        except ValueError as error:
            raise PartialRemediationDetectionError(
                "Git change escapes repository"
            ) from error

        changes.add(relative)

        if len(changes) > MAX_ITEMS:
            raise PartialRemediationDetectionError(
                "too many Git changes"
            )

    return frozenset(changes)


def detect_repository_partial_remediation(
    start_path: str | os.PathLike[str],
    expected_changes: Iterable[str],
    *,
    failure_category: str | None = None,
) -> PartialRemediationResult:
    actual = collect_repository_changes(start_path)

    return detect_partial_remediation(
        expected_changes,
        actual,
        failure_category=failure_category,
    )


__all__ = [
    "PartialRemediationDetectionError",
    "RemediationState",
    "PartialRemediationResult",
    "detect_partial_remediation",
    "validate_partial_remediation",
    "collect_repository_changes",
    "detect_repository_partial_remediation",
]
