from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping


MAX_NAME_LENGTH = 512
MAX_VERSION_LENGTH = 512


class DependencyVersionDiffError(ValueError):
    """Raised when TASK 219 input is invalid."""


class DependencyVersionDiffState(str, Enum):
    NO_CHANGE = "NO_CHANGE"
    EXPECTED_CHANGE = "EXPECTED_CHANGE"
    UNEXPECTED_CHANGE = "UNEXPECTED_CHANGE"


def _validate_text(value: object, field: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise DependencyVersionDiffError(f"{field} must be a string")

    if not value or not value.strip():
        raise DependencyVersionDiffError(f"{field} must not be empty")

    value = value.strip()

    if len(value) > maximum:
        raise DependencyVersionDiffError(f"{field} is too long")

    if "\\x00" in value:
        raise DependencyVersionDiffError(f"{field} contains NULL")

    return value


def _normalize_dependencies(values: Mapping[object, object]) -> dict[str, str]:
    if not isinstance(values, Mapping):
        raise DependencyVersionDiffError(
            "dependency versions must be a mapping"
        )

    result: dict[str, str] = {}

    for raw_name, raw_version in values.items():
        name = _validate_text(
            raw_name,
            "dependency name",
            MAX_NAME_LENGTH,
        )

        version = _validate_text(
            raw_version,
            f"version for {name}",
            MAX_VERSION_LENGTH,
        )

        result[name] = version

    return result


@dataclass(frozen=True)
class DependencyVersionChange:
    name: str
    before: str | None
    after: str | None
    state: DependencyVersionDiffState


@dataclass(frozen=True)
class DependencyVersionDiffResult:
    state: DependencyVersionDiffState
    changes: tuple[DependencyVersionChange, ...]
    expected_changes: tuple[DependencyVersionChange, ...]
    unexpected_changes: tuple[DependencyVersionChange, ...]

    @property
    def has_changes(self) -> bool:
        return bool(self.changes)

    @property
    def is_valid(self) -> bool:
        return not self.unexpected_changes

    def to_dict(self) -> dict[str, object]:
        return {
            "state": self.state.value,
            "has_changes": self.has_changes,
            "is_valid": self.is_valid,
            "changes": [
                {
                    "name": change.name,
                    "before": change.before,
                    "after": change.after,
                    "state": change.state.value,
                }
                for change in self.changes
            ],
            "expected_changes": [
                {
                    "name": change.name,
                    "before": change.before,
                    "after": change.after,
                    "state": change.state.value,
                }
                for change in self.expected_changes
            ],
            "unexpected_changes": [
                {
                    "name": change.name,
                    "before": change.before,
                    "after": change.after,
                    "state": change.state.value,
                }
                for change in self.unexpected_changes
            ],
        }


def analyze_dependency_version_diff(
    before: Mapping[object, object],
    after: Mapping[object, object],
    expected: Mapping[object, object] | None = None,
) -> DependencyVersionDiffResult:
    """
    TASK 219:
    Compare dependency versions before and after remediation.

    Only version differences are analyzed here.
    This function does not modify files, install packages,
    regenerate lockfiles, or execute remediation.
    """

    old = _normalize_dependencies(before)
    new = _normalize_dependencies(after)
    approved = _normalize_dependencies(expected or {})

    changes: list[DependencyVersionChange] = []
    expected_changes: list[DependencyVersionChange] = []
    unexpected_changes: list[DependencyVersionChange] = []

    for name in sorted(set(old) | set(new)):
        previous = old.get(name)
        current = new.get(name)

        if previous == current:
            continue

        approved_version = approved.get(name)

        if approved_version is not None and current == approved_version:
            state = DependencyVersionDiffState.EXPECTED_CHANGE
        else:
            state = DependencyVersionDiffState.UNEXPECTED_CHANGE

        change = DependencyVersionChange(
            name=name,
            before=previous,
            after=current,
            state=state,
        )

        changes.append(change)

        if state is DependencyVersionDiffState.EXPECTED_CHANGE:
            expected_changes.append(change)
        else:
            unexpected_changes.append(change)

    if unexpected_changes:
        overall = DependencyVersionDiffState.UNEXPECTED_CHANGE
    elif expected_changes:
        overall = DependencyVersionDiffState.EXPECTED_CHANGE
    else:
        overall = DependencyVersionDiffState.NO_CHANGE

    return DependencyVersionDiffResult(
        state=overall,
        changes=tuple(changes),
        expected_changes=tuple(expected_changes),
        unexpected_changes=tuple(unexpected_changes),
    )


__all__ = [
    "DependencyVersionDiffError",
    "DependencyVersionDiffState",
    "DependencyVersionChange",
    "DependencyVersionDiffResult",
    "analyze_dependency_version_diff",
]
