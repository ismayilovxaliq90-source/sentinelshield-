from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional


@dataclass(frozen=True)
class Dependency:
    name: str
    version: Optional[str] = None


@dataclass(frozen=True)
class MultipleVersion:
    name: str
    versions: tuple[str, ...]


@dataclass(frozen=True)
class MultipleVersionDetectionResult:
    dependencies: tuple[MultipleVersion, ...]
    detected: bool
    status: str


def detect_multiple_versions(
    dependencies: Iterable[object],
) -> MultipleVersionDetectionResult:
    if dependencies is None:
        return MultipleVersionDetectionResult(
            (), False, "DEPENDENCIES_IS_NONE"
        )

    if isinstance(dependencies, (str, bytes)):
        return MultipleVersionDetectionResult(
            (), False, "UNSUPPORTED_DEPENDENCY_COLLECTION"
        )

    try:
        items = tuple(dependencies)
    except TypeError:
        return MultipleVersionDetectionResult(
            (), False, "UNSUPPORTED_DEPENDENCY_COLLECTION"
        )

    versions: dict[str, set[str]] = {}

    for dependency in items:
        name = getattr(dependency, "name", None)
        version = getattr(dependency, "version", None)

        if isinstance(dependency, dict):
            name = dependency.get("name")
            version = dependency.get("version")

        if not isinstance(name, str) or not name.strip():
            return MultipleVersionDetectionResult(
                (), False, "INVALID_DEPENDENCY_NAME"
            )

        if version is not None and not isinstance(version, str):
            return MultipleVersionDetectionResult(
                (), False, "INVALID_DEPENDENCY_VERSION"
            )

        if version is None or not version.strip():
            continue

        normalized_name = name.strip()
        normalized_version = version.strip()

        versions.setdefault(normalized_name, set()).add(
            normalized_version
        )

    result = tuple(
        MultipleVersion(
            name=name,
            versions=tuple(sorted(values)),
        )
        for name, values in sorted(versions.items())
        if len(values) > 1
    )

    return MultipleVersionDetectionResult(
        dependencies=result,
        detected=bool(result),
        status=(
            "MULTIPLE_VERSIONS_DETECTED"
            if result
            else "NO_MULTIPLE_VERSIONS"
        ),
    )
