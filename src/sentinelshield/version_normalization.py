from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Optional


@dataclass(frozen=True)
class NormalizedDependencyVersion:
    name: str
    original_version: Optional[str]
    normalized_version: Optional[str]


@dataclass(frozen=True)
class VersionNormalizationResult:
    dependencies: tuple[NormalizedDependencyVersion, ...]
    normalized: bool
    status: str


def _normalize_version(value: Any) -> tuple[Optional[str], str]:
    if value is None:
        return None, "VALID"

    if not isinstance(value, str):
        return None, "INVALID_DEPENDENCY_VERSION"

    version = value.strip()

    if not version:
        return None, "EMPTY_DEPENDENCY_VERSION"

    # Normalize only representation-level whitespace and
    # an optional leading "v". Do not alter constraints.
    if version[:1].lower() == "v" and len(version) > 1:
        version = version[1:].strip()

    return version, "VALID"


def normalize_dependency_versions(
    dependencies: Iterable[Any],
) -> VersionNormalizationResult:

    if dependencies is None:
        return VersionNormalizationResult(
            dependencies=(),
            normalized=False,
            status="DEPENDENCIES_IS_NONE",
        )

    if isinstance(dependencies, (str, bytes)):
        return VersionNormalizationResult(
            dependencies=(),
            normalized=False,
            status="UNSUPPORTED_DEPENDENCY_COLLECTION",
        )

    try:
        items = tuple(dependencies)
    except TypeError:
        return VersionNormalizationResult(
            dependencies=(),
            normalized=False,
            status="UNSUPPORTED_DEPENDENCY_COLLECTION",
        )

    result: list[NormalizedDependencyVersion] = []

    for dependency in items:
        if not hasattr(dependency, "name"):
            return VersionNormalizationResult(
                dependencies=(),
                normalized=False,
                status="INVALID_DEPENDENCY",
            )

        name = getattr(dependency, "name")

        if not isinstance(name, str) or not name.strip():
            return VersionNormalizationResult(
                dependencies=(),
                normalized=False,
                status="INVALID_DEPENDENCY_NAME",
            )

        original_version = getattr(
            dependency,
            "version",
            None,
        )

        normalized_version, status = _normalize_version(
            original_version
        )

        if status != "VALID":
            return VersionNormalizationResult(
                dependencies=(),
                normalized=False,
                status=status,
            )

        result.append(
            NormalizedDependencyVersion(
                name=name.strip(),
                original_version=original_version,
                normalized_version=normalized_version,
            )
        )

    return VersionNormalizationResult(
        dependencies=tuple(result),
        normalized=True,
        status="NORMALIZED",
    )


def normalize_dependency_version(
    dependency: Any,
) -> VersionNormalizationResult:
    return normalize_dependency_versions([dependency])
