from __future__ import annotations

import json
import posixpath
from dataclasses import dataclass
from enum import Enum
from pathlib import PurePosixPath
from typing import Iterable, Mapping


class ManifestDiffAnalysisError(ValueError):
    """Raised when manifest diff input is invalid."""


class ManifestChangeType(str, Enum):
    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"


_MAX_PATH_LENGTH = 4096
_MAX_DEPENDENCY_LENGTH = 1024


def _normalize_path(value: object) -> str:
    if not isinstance(value, str):
        raise ManifestDiffAnalysisError("manifest path must be a string")

    if not value or not value.strip():
        raise ManifestDiffAnalysisError("manifest path must not be empty")

    value = value.strip().replace("\\", "/")

    if len(value) > _MAX_PATH_LENGTH:
        raise ManifestDiffAnalysisError("manifest path is too long")

    if value.startswith("/"):
        raise ManifestDiffAnalysisError("absolute manifest paths are not allowed")

    normalized = posixpath.normpath(value)

    if normalized in ("", "."):
        raise ManifestDiffAnalysisError("invalid manifest path")

    parts = PurePosixPath(normalized).parts
    if ".." in parts:
        raise ManifestDiffAnalysisError(
            "parent traversal is not allowed"
        )

    if any(part == "" for part in parts):
        raise ManifestDiffAnalysisError("invalid manifest path")

    return normalized


def _normalize_paths(values: Iterable[object]) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise ManifestDiffAnalysisError(
            "paths must be an iterable of path values"
        )

    result = []
    seen = set()

    try:
        iterator = iter(values)
    except TypeError as exc:
        raise ManifestDiffAnalysisError("paths must be iterable") from exc

    for value in iterator:
        path = _normalize_path(value)
        if path in seen:
            raise ManifestDiffAnalysisError(
                f"duplicate manifest path: {path}"
            )
        seen.add(path)
        result.append(path)

    return tuple(sorted(result))


def _normalize_dependency(value: object) -> str:
    if not isinstance(value, str):
        raise ManifestDiffAnalysisError(
            "dependency name must be a string"
        )

    value = value.strip()

    if not value:
        raise ManifestDiffAnalysisError(
            "dependency name must not be empty"
        )

    if len(value) > _MAX_DEPENDENCY_LENGTH:
        raise ManifestDiffAnalysisError(
            "dependency name is too long"
        )

    if "\x00" in value:
        raise ManifestDiffAnalysisError(
            "dependency name contains NUL"
        )

    return value


def _normalize_dependency_set(
    values: Iterable[object],
) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise ManifestDiffAnalysisError(
            "dependencies must be iterable"
        )

    result = []
    seen = set()

    try:
        iterator = iter(values)
    except TypeError as exc:
        raise ManifestDiffAnalysisError(
            "dependencies must be iterable"
        ) from exc

    for value in iterator:
        dependency = _normalize_dependency(value)
        if dependency in seen:
            raise ManifestDiffAnalysisError(
                f"duplicate dependency: {dependency}"
            )
        seen.add(dependency)
        result.append(dependency)

    return tuple(sorted(result))


@dataclass(frozen=True)
class ManifestChange:
    path: str
    change_type: ManifestChangeType
    added_dependencies: tuple[str, ...] = ()
    removed_dependencies: tuple[str, ...] = ()
    modified_dependencies: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        path = _normalize_path(self.path)

        if not isinstance(self.change_type, ManifestChangeType):
            try:
                change_type = ManifestChangeType(self.change_type)
            except (TypeError, ValueError) as exc:
                raise ManifestDiffAnalysisError(
                    "invalid manifest change type"
                ) from exc
        else:
            change_type = self.change_type

        added = _normalize_dependency_set(self.added_dependencies)
        removed = _normalize_dependency_set(self.removed_dependencies)
        modified = _normalize_dependency_set(self.modified_dependencies)

        if set(added) & set(removed):
            raise ManifestDiffAnalysisError(
                "dependency cannot be both added and removed"
            )

        if set(added) & set(modified):
            raise ManifestDiffAnalysisError(
                "dependency cannot be both added and modified"
            )

        if set(removed) & set(modified):
            raise ManifestDiffAnalysisError(
                "dependency cannot be both removed and modified"
            )

        object.__setattr__(self, "path", path)
        object.__setattr__(self, "change_type", change_type)
        object.__setattr__(self, "added_dependencies", added)
        object.__setattr__(self, "removed_dependencies", removed)
        object.__setattr__(self, "modified_dependencies", modified)


@dataclass(frozen=True)
class ManifestDiffResult:
    manifest_changes: tuple[ManifestChange, ...]
    expected_manifest_paths: tuple[str, ...]
    expected_added_dependencies: tuple[str, ...]
    expected_removed_dependencies: tuple[str, ...]
    expected_modified_dependencies: tuple[str, ...]
    unexpected_manifest_paths: tuple[str, ...]
    unexpected_added_dependencies: tuple[str, ...]
    unexpected_removed_dependencies: tuple[str, ...]
    unexpected_modified_dependencies: tuple[str, ...]
    passed: bool

    def __post_init__(self) -> None:
        changes = tuple(self.manifest_changes)

        for change in changes:
            if not isinstance(change, ManifestChange):
                raise ManifestDiffAnalysisError(
                    "manifest_changes must contain ManifestChange values"
                )

        expected_paths = _normalize_paths(self.expected_manifest_paths)
        expected_added = _normalize_dependency_set(
            self.expected_added_dependencies
        )
        expected_removed = _normalize_dependency_set(
            self.expected_removed_dependencies
        )
        expected_modified = _normalize_dependency_set(
            self.expected_modified_dependencies
        )

        unexpected_paths = _normalize_paths(self.unexpected_manifest_paths)
        unexpected_added = _normalize_dependency_set(
            self.unexpected_added_dependencies
        )
        unexpected_removed = _normalize_dependency_set(
            self.unexpected_removed_dependencies
        )
        unexpected_modified = _normalize_dependency_set(
            self.unexpected_modified_dependencies
        )

        if type(self.passed) is not bool:
            raise ManifestDiffAnalysisError("passed must be bool")

        object.__setattr__(self, "manifest_changes", changes)
        object.__setattr__(self, "expected_manifest_paths", expected_paths)
        object.__setattr__(
            self,
            "expected_added_dependencies",
            expected_added,
        )
        object.__setattr__(
            self,
            "expected_removed_dependencies",
            expected_removed,
        )
        object.__setattr__(
            self,
            "expected_modified_dependencies",
            expected_modified,
        )
        object.__setattr__(
            self,
            "unexpected_manifest_paths",
            unexpected_paths,
        )
        object.__setattr__(
            self,
            "unexpected_added_dependencies",
            unexpected_added,
        )
        object.__setattr__(
            self,
            "unexpected_removed_dependencies",
            unexpected_removed,
        )
        object.__setattr__(
            self,
            "unexpected_modified_dependencies",
            unexpected_modified,
        )

        calculated = not any(
            (
                unexpected_paths,
                unexpected_added,
                unexpected_removed,
                unexpected_modified,
            )
        )

        if self.passed != calculated:
            raise ManifestDiffAnalysisError(
                "passed flag is inconsistent with diff findings"
            )

    @property
    def is_safe(self) -> bool:
        return self.passed

    @property
    def changed_manifest_count(self) -> int:
        return len(self.manifest_changes)

    def to_dict(self) -> dict:
        return {
            "manifest_changes": [
                {
                    "path": change.path,
                    "change_type": change.change_type.value,
                    "added_dependencies": list(
                        change.added_dependencies
                    ),
                    "removed_dependencies": list(
                        change.removed_dependencies
                    ),
                    "modified_dependencies": list(
                        change.modified_dependencies
                    ),
                }
                for change in self.manifest_changes
            ],
            "expected_manifest_paths": list(
                self.expected_manifest_paths
            ),
            "expected_added_dependencies": list(
                self.expected_added_dependencies
            ),
            "expected_removed_dependencies": list(
                self.expected_removed_dependencies
            ),
            "expected_modified_dependencies": list(
                self.expected_modified_dependencies
            ),
            "unexpected_manifest_paths": list(
                self.unexpected_manifest_paths
            ),
            "unexpected_added_dependencies": list(
                self.unexpected_added_dependencies
            ),
            "unexpected_removed_dependencies": list(
                self.unexpected_removed_dependencies
            ),
            "unexpected_modified_dependencies": list(
                self.unexpected_modified_dependencies
            ),
            "passed": self.passed,
        }

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
        )


def _normalize_changes(
    changes: Iterable[ManifestChange],
) -> tuple[ManifestChange, ...]:
    if isinstance(changes, (str, bytes)):
        raise ManifestDiffAnalysisError(
            "changes must be iterable"
        )

    result = []

    try:
        iterator = iter(changes)
    except TypeError as exc:
        raise ManifestDiffAnalysisError(
            "changes must be iterable"
        ) from exc

    seen = set()

    for change in iterator:
        if not isinstance(change, ManifestChange):
            raise ManifestDiffAnalysisError(
                "changes must contain ManifestChange values"
            )

        if change.path in seen:
            raise ManifestDiffAnalysisError(
                f"duplicate manifest change: {change.path}"
            )

        seen.add(change.path)
        result.append(change)

    return tuple(
        sorted(
            result,
            key=lambda item: item.path,
        )
    )


def analyze_manifest_diff(
    changes: Iterable[ManifestChange],
    *,
    expected_manifest_paths: Iterable[object] = (),
    expected_added_dependencies: Iterable[object] = (),
    expected_removed_dependencies: Iterable[object] = (),
    expected_modified_dependencies: Iterable[object] = (),
) -> ManifestDiffResult:
    normalized_changes = _normalize_changes(changes)

    expected_paths = _normalize_paths(expected_manifest_paths)
    expected_added = _normalize_dependency_set(
        expected_added_dependencies
    )
    expected_removed = _normalize_dependency_set(
        expected_removed_dependencies
    )
    expected_modified = _normalize_dependency_set(
        expected_modified_dependencies
    )

    actual_paths = {
        change.path
        for change in normalized_changes
    }

    actual_added = {
        dependency
        for change in normalized_changes
        for dependency in change.added_dependencies
    }

    actual_removed = {
        dependency
        for change in normalized_changes
        for dependency in change.removed_dependencies
    }

    actual_modified = {
        dependency
        for change in normalized_changes
        for dependency in change.modified_dependencies
    }

    unexpected_paths = tuple(
        sorted(actual_paths - set(expected_paths))
    )
    unexpected_added = tuple(
        sorted(actual_added - set(expected_added))
    )
    unexpected_removed = tuple(
        sorted(actual_removed - set(expected_removed))
    )
    unexpected_modified = tuple(
        sorted(actual_modified - set(expected_modified))
    )

    return ManifestDiffResult(
        manifest_changes=normalized_changes,
        expected_manifest_paths=expected_paths,
        expected_added_dependencies=expected_added,
        expected_removed_dependencies=expected_removed,
        expected_modified_dependencies=expected_modified,
        unexpected_manifest_paths=unexpected_paths,
        unexpected_added_dependencies=unexpected_added,
        unexpected_removed_dependencies=unexpected_removed,
        unexpected_modified_dependencies=unexpected_modified,
        passed=not any(
            (
                unexpected_paths,
                unexpected_added,
                unexpected_removed,
                unexpected_modified,
            )
        ),
    )


def validate_manifest_diff(
    result: ManifestDiffResult,
) -> bool:
    if not isinstance(result, ManifestDiffResult):
        return False

    try:
        ManifestDiffResult(
            manifest_changes=result.manifest_changes,
            expected_manifest_paths=result.expected_manifest_paths,
            expected_added_dependencies=result.expected_added_dependencies,
            expected_removed_dependencies=result.expected_removed_dependencies,
            expected_modified_dependencies=result.expected_modified_dependencies,
            unexpected_manifest_paths=result.unexpected_manifest_paths,
            unexpected_added_dependencies=result.unexpected_added_dependencies,
            unexpected_removed_dependencies=result.unexpected_removed_dependencies,
            unexpected_modified_dependencies=result.unexpected_modified_dependencies,
            passed=result.passed,
        )
    except (ManifestDiffAnalysisError, TypeError, ValueError):
        return False

    return True


def analyze_manifest_mapping(
    manifest_diffs: Mapping[object, Mapping[str, Iterable[object]]],
    *,
    expected_manifest_paths: Iterable[object] = (),
    expected_added_dependencies: Iterable[object] = (),
    expected_removed_dependencies: Iterable[object] = (),
    expected_modified_dependencies: Iterable[object] = (),
) -> ManifestDiffResult:
    if not isinstance(manifest_diffs, Mapping):
        raise ManifestDiffAnalysisError(
            "manifest_diffs must be a mapping"
        )

    changes = []

    for raw_path, raw_diff in manifest_diffs.items():
        path = _normalize_path(raw_path)

        if not isinstance(raw_diff, Mapping):
            raise ManifestDiffAnalysisError(
                "manifest diff entry must be a mapping"
            )

        raw_type = raw_diff.get("change_type", "modified")

        try:
            change_type = ManifestChangeType(raw_type)
        except (TypeError, ValueError) as exc:
            raise ManifestDiffAnalysisError(
                "invalid manifest change type"
            ) from exc

        changes.append(
            ManifestChange(
                path=path,
                change_type=change_type,
                added_dependencies=raw_diff.get(
                    "added_dependencies",
                    (),
                ),
                removed_dependencies=raw_diff.get(
                    "removed_dependencies",
                    (),
                ),
                modified_dependencies=raw_diff.get(
                    "modified_dependencies",
                    (),
                ),
            )
        )

    return analyze_manifest_diff(
        changes,
        expected_manifest_paths=expected_manifest_paths,
        expected_added_dependencies=expected_added_dependencies,
        expected_removed_dependencies=expected_removed_dependencies,
        expected_modified_dependencies=expected_modified_dependencies,
    )


__all__ = [
    "ManifestDiffAnalysisError",
    "ManifestChangeType",
    "ManifestChange",
    "ManifestDiffResult",
    "analyze_manifest_diff",
    "analyze_manifest_mapping",
    "validate_manifest_diff",
]
