from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional


@dataclass(frozen=True)
class Dependency:
    name: str
    version: Optional[str] = None


@dataclass(frozen=True)
class VersionConflict:
    name: str
    versions: tuple[str, ...]


@dataclass(frozen=True)
class VersionConflictDetectionResult:
    conflicts: tuple[VersionConflict, ...]
    detected: bool
    status: str


def detect_version_conflicts(
    dependencies: Iterable[object],
) -> VersionConflictDetectionResult:
    if dependencies is None:
        return VersionConflictDetectionResult(
            (), False, "DEPENDENCIES_IS_NONE"
        )

    if isinstance(dependencies, (str, bytes)):
        return VersionConflictDetectionResult(
            (), False, "UNSUPPORTED_DEPENDENCY_COLLECTION"
        )

    try:
        items = tuple(dependencies)
    except TypeError:
        return VersionConflictDetectionResult(
            (), False, "UNSUPPORTED_DEPENDENCY_COLLECTION"
        )

    versions: dict[str, set[str]] = {}

    for dependency in items:
        if isinstance(dependency, dict):
            name = dependency.get("name")
            version = dependency.get("version")
        else:
            name = getattr(dependency, "name", None)
            version = getattr(dependency, "version", None)

        if not isinstance(name, str) or not name.strip():
            return VersionConflictDetectionResult(
                (), False, "INVALID_DEPENDENCY_NAME"
            )

        if version is not None and not isinstance(version, str):
            return VersionConflictDetectionResult(
                (), False, "INVALID_DEPENDENCY_VERSION"
            )

        if version is None or not version.strip():
            continue

        name = name.strip()
        version = version.strip()

        versions.setdefault(name, set()).add(version)

    conflicts = tuple(
        VersionConflict(
            name=name,
            versions=tuple(sorted(values)),
        )
        for name, values in sorted(versions.items())
        if len(values) > 1
    )

    return VersionConflictDetectionResult(
        conflicts=conflicts,
        detected=bool(conflicts),
        status=(
            "VERSION_CONFLICTS_DETECTED"
            if conflicts
            else "NO_VERSION_CONFLICTS"
        ),
    )
