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
class NormalizedDependency:
    name: str
    version: Optional[str]
    dependency_type: str
    source: Optional[str]


@dataclass(frozen=True)
class NormalizedDependencyInventoryResult:
    dependencies: tuple[NormalizedDependency, ...]
    normalized: bool
    status: str


def _normalize(item: object) -> tuple[Optional[NormalizedDependency], str]:
    if not hasattr(item, "name"):
        return None, "INVALID_DEPENDENCY"

    name = getattr(item, "name")

    if not isinstance(name, str) or not name.strip():
        return None, "INVALID_DEPENDENCY_NAME"

    version = getattr(item, "version", None)

    if version is not None and not isinstance(version, str):
        return None, "INVALID_DEPENDENCY_VERSION"

    dependency_type = getattr(
        item,
        "dependency_type",
        "production",
    )

    if not isinstance(dependency_type, str):
        return None, "INVALID_DEPENDENCY_TYPE"

    source = getattr(item, "source", None)

    if source is not None and not isinstance(source, str):
        return None, "INVALID_DEPENDENCY_SOURCE"

    return (
        NormalizedDependency(
            name=name.strip().casefold(),
            version=version.strip() if version else version,
            dependency_type=dependency_type.strip().lower(),
            source=source.strip() if source else source,
        ),
        "VALID",
    )


def build_normalized_dependency_inventory(
    dependencies: Iterable[object],
) -> NormalizedDependencyInventoryResult:

    if dependencies is None:
        return NormalizedDependencyInventoryResult(
            dependencies=(),
            normalized=False,
            status="DEPENDENCIES_IS_NONE",
        )

    if isinstance(dependencies, (str, bytes)):
        return NormalizedDependencyInventoryResult(
            dependencies=(),
            normalized=False,
            status="UNSUPPORTED_DEPENDENCY_COLLECTION",
        )

    try:
        items = tuple(dependencies)
    except TypeError:
        return NormalizedDependencyInventoryResult(
            dependencies=(),
            normalized=False,
            status="UNSUPPORTED_DEPENDENCY_COLLECTION",
        )

    normalized: list[NormalizedDependency] = []

    for item in items:
        dependency, status = _normalize(item)

        if dependency is None:
            return NormalizedDependencyInventoryResult(
                dependencies=(),
                normalized=False,
                status=status,
            )

        normalized.append(dependency)

    normalized.sort(
        key=lambda dependency: (
            dependency.name,
            dependency.version or "",
            dependency.dependency_type,
            dependency.source or "",
        )
    )

    return NormalizedDependencyInventoryResult(
        dependencies=tuple(normalized),
        normalized=True,
        status="NORMALIZED",
    )


def normalize_dependency_inventory(
    dependencies: Iterable[object],
) -> NormalizedDependencyInventoryResult:
    return build_normalized_dependency_inventory(dependencies)
