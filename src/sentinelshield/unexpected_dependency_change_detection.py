from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import json
import re


class UnexpectedDependencyChangeError(Exception):
    """Raised when dependency-change input is invalid."""


@dataclass(frozen=True)
class DependencyState:
    name: str
    version: str
    source: str | None = None
    direct: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("dependency name must be non-empty")

        if not isinstance(self.version, str) or not self.version.strip():
            raise ValueError("dependency version must be non-empty")

        if self.source is not None and not isinstance(self.source, str):
            raise TypeError("dependency source must be string or None")

        if not isinstance(self.direct, bool):
            raise TypeError("direct must be bool")

    @property
    def normalized_name(self) -> str:
        return normalize_dependency_name(self.name)

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "version": self.version,
            "source": self.source,
            "direct": self.direct,
        }


@dataclass(frozen=True)
class ApprovedDependencyChange:
    name: str
    old_version: str | None = None
    new_version: str | None = None
    change_type: str = "update"

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("approved dependency name must be non-empty")

        allowed = {"add", "remove", "update"}

        if self.change_type not in allowed:
            raise ValueError(
                f"unsupported change type: {self.change_type}"
            )

        if self.change_type == "add" and self.new_version is None:
            raise ValueError("add requires new_version")

        if self.change_type == "remove" and self.old_version is None:
            raise ValueError("remove requires old_version")

        if self.change_type == "update":
            if self.old_version is None or self.new_version is None:
                raise ValueError(
                    "update requires old_version and new_version"
                )

    @property
    def normalized_name(self) -> str:
        return normalize_dependency_name(self.name)

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "old_version": self.old_version,
            "new_version": self.new_version,
            "change_type": self.change_type,
        }


@dataclass(frozen=True)
class DependencyChange:
    name: str
    change_type: str
    baseline_version: str | None
    current_version: str | None
    approved: bool
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "change_type": self.change_type,
            "baseline_version": self.baseline_version,
            "current_version": self.current_version,
            "approved": self.approved,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class UnexpectedDependencyChangeResult:
    valid: bool
    reason: str
    changes: tuple[DependencyChange, ...] = field(default_factory=tuple)
    unexpected_added: tuple[str, ...] = ()
    unexpected_removed: tuple[str, ...] = ()
    unexpected_updated: tuple[str, ...] = ()
    duplicate_baseline: tuple[str, ...] = ()
    duplicate_current: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "valid": self.valid,
            "reason": self.reason,
            "changes": [
                change.to_dict()
                for change in self.changes
            ],
            "unexpected_added": list(self.unexpected_added),
            "unexpected_removed": list(self.unexpected_removed),
            "unexpected_updated": list(self.unexpected_updated),
            "duplicate_baseline": list(self.duplicate_baseline),
            "duplicate_current": list(self.duplicate_current),
        }

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            indent=2,
            sort_keys=True,
        )


@dataclass(frozen=True)
class UnexpectedDependencyChangeRequest:
    repository_root: Path
    baseline: tuple[DependencyState, ...]
    current: tuple[DependencyState, ...]
    approved_changes: tuple[ApprovedDependencyChange, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.repository_root, Path):
            raise TypeError("repository_root must be pathlib.Path")

        for dependency in self.baseline:
            if not isinstance(dependency, DependencyState):
                raise TypeError(
                    "baseline must contain DependencyState values"
                )

        for dependency in self.current:
            if not isinstance(dependency, DependencyState):
                raise TypeError(
                    "current must contain DependencyState values"
                )

        for change in self.approved_changes:
            if not isinstance(change, ApprovedDependencyChange):
                raise TypeError(
                    "approved_changes must contain "
                    "ApprovedDependencyChange values"
                )


def normalize_dependency_name(name: str) -> str:
    if not isinstance(name, str):
        raise TypeError("dependency name must be string")

    normalized = name.strip().lower()

    if not normalized:
        raise ValueError("dependency name must be non-empty")

    normalized = re.sub(r"\s+", "-", normalized)

    return normalized


def _validate_repository(root: Path) -> Path:
    try:
        resolved = root.expanduser().resolve()
    except OSError as error:
        raise UnexpectedDependencyChangeError(
            "unable to resolve repository root"
        ) from error

    if not resolved.exists():
        raise UnexpectedDependencyChangeError(
            f"repository does not exist: {resolved}"
        )

    if not resolved.is_dir():
        raise UnexpectedDependencyChangeError(
            f"repository is not a directory: {resolved}"
        )

    if not (resolved / ".git").exists():
        raise UnexpectedDependencyChangeError(
            f"not a git repository: {resolved}"
        )

    return resolved


def _duplicates(
    dependencies: tuple[DependencyState, ...],
) -> tuple[str, ...]:
    seen: set[str] = set()
    duplicates: set[str] = set()

    for dependency in dependencies:
        name = dependency.normalized_name

        if name in seen:
            duplicates.add(name)
        else:
            seen.add(name)

    return tuple(sorted(duplicates))


def _map_dependencies(
    dependencies: tuple[DependencyState, ...],
) -> dict[str, DependencyState]:
    return {
        dependency.normalized_name: dependency
        for dependency in dependencies
    }


def _approved_map(
    approved_changes: tuple[ApprovedDependencyChange, ...],
) -> dict[str, ApprovedDependencyChange]:
    result: dict[str, ApprovedDependencyChange] = {}

    for change in approved_changes:
        name = change.normalized_name

        if name in result:
            raise UnexpectedDependencyChangeError(
                f"duplicate approved change: {name}"
            )

        result[name] = change

    return result


def _matches_approval(
    name: str,
    change_type: str,
    baseline_version: str | None,
    current_version: str | None,
    approved: dict[str, ApprovedDependencyChange],
) -> tuple[bool, str]:
    expected = approved.get(name)

    if expected is None:
        return False, "NO_APPROVED_CHANGE"

    if expected.change_type != change_type:
        return False, "APPROVED_CHANGE_TYPE_MISMATCH"

    if change_type == "add":
        if expected.new_version != current_version:
            return False, "APPROVED_NEW_VERSION_MISMATCH"

    elif change_type == "remove":
        if expected.old_version != baseline_version:
            return False, "APPROVED_OLD_VERSION_MISMATCH"

    elif change_type == "update":
        if expected.old_version != baseline_version:
            return False, "APPROVED_OLD_VERSION_MISMATCH"

        if expected.new_version != current_version:
            return False, "APPROVED_NEW_VERSION_MISMATCH"

    return True, "APPROVED"


def detect_unexpected_dependency_changes(
    request: UnexpectedDependencyChangeRequest,
) -> UnexpectedDependencyChangeResult:
    _validate_repository(request.repository_root)

    duplicate_baseline = _duplicates(request.baseline)
    duplicate_current = _duplicates(request.current)

    if duplicate_baseline or duplicate_current:
        return UnexpectedDependencyChangeResult(
            valid=False,
            reason="DUPLICATE_DEPENDENCY",
            duplicate_baseline=duplicate_baseline,
            duplicate_current=duplicate_current,
        )

    baseline = _map_dependencies(request.baseline)
    current = _map_dependencies(request.current)
    approved = _approved_map(request.approved_changes)

    all_names = sorted(set(baseline) | set(current))

    changes: list[DependencyChange] = []
    unexpected_added: list[str] = []
    unexpected_removed: list[str] = []
    unexpected_updated: list[str] = []

    for name in all_names:
        before = baseline.get(name)
        after = current.get(name)

        if before is None and after is not None:
            change_type = "add"
            baseline_version = None
            current_version = after.version

        elif before is not None and after is None:
            change_type = "remove"
            baseline_version = before.version
            current_version = None

        elif before is not None and after is not None:
            if before.version == after.version:
                continue

            change_type = "update"
            baseline_version = before.version
            current_version = after.version

        else:
            continue

        is_approved, reason = _matches_approval(
            name=name,
            change_type=change_type,
            baseline_version=baseline_version,
            current_version=current_version,
            approved=approved,
        )

        changes.append(
            DependencyChange(
                name=name,
                change_type=change_type,
                baseline_version=baseline_version,
                current_version=current_version,
                approved=is_approved,
                reason=reason,
            )
        )

        if not is_approved:
            if change_type == "add":
                unexpected_added.append(name)
            elif change_type == "remove":
                unexpected_removed.append(name)
            elif change_type == "update":
                unexpected_updated.append(name)

    if unexpected_added:
        reason = "UNEXPECTED_DEPENDENCY_ADDED"
    elif unexpected_removed:
        reason = "UNEXPECTED_DEPENDENCY_REMOVED"
    elif unexpected_updated:
        reason = "UNEXPECTED_DEPENDENCY_UPDATED"
    else:
        reason = "DEPENDENCY_CHANGES_EXPECTED"

    return UnexpectedDependencyChangeResult(
        valid=not (
            unexpected_added
            or unexpected_removed
            or unexpected_updated
        ),
        reason=reason,
        changes=tuple(changes),
        unexpected_added=tuple(unexpected_added),
        unexpected_removed=tuple(unexpected_removed),
        unexpected_updated=tuple(unexpected_updated),
    )


def validate_change_result(
    result: UnexpectedDependencyChangeResult,
) -> bool:
    return (
        result.valid
        and not result.unexpected_added
        and not result.unexpected_removed
        and not result.unexpected_updated
        and not result.duplicate_baseline
        and not result.duplicate_current
    )
