from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional


@dataclass(frozen=True)
class Dependency:
    name: str
    version: Optional[str] = None
    dependency_type: str = "production"
    source: Optional[str] = None


@dataclass(frozen=True)
class ConsolidatedDependency:
    name: str
    versions: tuple[str, ...]
    dependency_types: tuple[str, ...]
    sources: tuple[str, ...]


@dataclass(frozen=True)
class DuplicateDependencyConsolidationResult:
    dependencies: tuple[ConsolidatedDependency, ...]
    consolidated: bool
    duplicates_found: int
    status: str


def _validate(item: object) -> tuple[Optional[Dependency], str]:
    if not hasattr(item, "name"):
        return None, "INVALID_DEPENDENCY"

    name = getattr(item, "name")
    version = getattr(item, "version", None)
    dependency_type = getattr(item, "dependency_type", "production")
    source = getattr(item, "source", None)

    if not isinstance(name, str) or not name.strip():
        return None, "INVALID_DEPENDENCY_NAME"

    if version is not None and not isinstance(version, str):
        return None, "INVALID_DEPENDENCY_VERSION"

    if not isinstance(dependency_type, str):
        return None, "INVALID_DEPENDENCY_TYPE"

    if source is not None and not isinstance(source, str):
        return None, "INVALID_DEPENDENCY_SOURCE"

    return (
        Dependency(
            name=name.strip(),
            version=version,
            dependency_type=dependency_type.strip().lower(),
            source=source,
        ),
        "VALID",
    )


def consolidate_duplicate_dependencies(
    dependencies: Iterable[object],
) -> DuplicateDependencyConsolidationResult:
    if dependencies is None:
        return DuplicateDependencyConsolidationResult(
            dependencies=(),
            consolidated=False,
            duplicates_found=0,
            status="DEPENDENCIES_IS_NONE",
        )

    if isinstance(dependencies, (str, bytes)):
        return DuplicateDependencyConsolidationResult(
            dependencies=(),
            consolidated=False,
            duplicates_found=0,
            status="UNSUPPORTED_DEPENDENCY_COLLECTION",
        )

    try:
        items = tuple(dependencies)
    except TypeError:
        return DuplicateDependencyConsolidationResult(
            dependencies=(),
            consolidated=False,
            duplicates_found=0,
            status="UNSUPPORTED_DEPENDENCY_COLLECTION",
        )

    groups: dict[str, list[Dependency]] = {}

    for item in items:
        dependency, status = _validate(item)

        if dependency is None:
            return DuplicateDependencyConsolidationResult(
                dependencies=(),
                consolidated=False,
                duplicates_found=0,
                status=status,
            )

        key = dependency.name.casefold()
        groups.setdefault(key, []).append(dependency)

    duplicates_found = sum(
        max(0, len(group) - 1)
        for group in groups.values()
    )

    consolidated: list[ConsolidatedDependency] = []

    for group in groups.values():
        names = sorted(
            {dependency.name for dependency in group},
            key=lambda value: (value.casefold(), value),
        )

        versions = sorted(
            {
                dependency.version
                for dependency in group
                if dependency.version is not None
            }
        )

        dependency_types = sorted(
            {
                dependency.dependency_type
                for dependency in group
            }
        )

        sources = sorted(
            {
                dependency.source
                for dependency in group
                if dependency.source is not None
            }
        )

        consolidated.append(
            ConsolidatedDependency(
                name=names[0],
                versions=tuple(versions),
                dependency_types=tuple(dependency_types),
                sources=tuple(sources),
            )
        )

    consolidated.sort(
        key=lambda dependency: (
            dependency.name.casefold(),
            dependency.name,
        )
    )

    return DuplicateDependencyConsolidationResult(
        dependencies=tuple(consolidated),
        consolidated=True,
        duplicates_found=duplicates_found,
        status="CONSOLIDATED",
    )


def consolidate_dependencies(
    dependencies: Iterable[object],
) -> DuplicateDependencyConsolidationResult:
    return consolidate_duplicate_dependencies(dependencies)
