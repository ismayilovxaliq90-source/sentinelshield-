from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional


@dataclass(frozen=True)
class Dependency:
    name: str
    version: Optional[str] = None
    source: Optional[str] = None
    dependency_type: str = "production"


@dataclass(frozen=True)
class DependencySource:
    name: str
    source: Optional[str]


@dataclass(frozen=True)
class PackageSourceExtractionResult:
    dependencies: tuple[DependencySource, ...]
    extracted: bool
    status: str


def _validate(item: object) -> tuple[Optional[DependencySource], str]:
    if not hasattr(item, "name"):
        return None, "INVALID_DEPENDENCY"

    if not hasattr(item, "source"):
        return None, "INVALID_DEPENDENCY"

    name = getattr(item, "name")
    source = getattr(item, "source")

    if not isinstance(name, str) or not name.strip():
        return None, "INVALID_DEPENDENCY_NAME"

    if source is not None and not isinstance(source, str):
        return None, "INVALID_DEPENDENCY_SOURCE"

    normalized_name = name.strip()

    normalized_source = (
        source.strip()
        if isinstance(source, str)
        else None
    )

    if normalized_source == "":
        normalized_source = None

    return (
        DependencySource(
            name=normalized_name,
            source=normalized_source,
        ),
        "VALID",
    )


def extract_package_sources(
    dependencies: Iterable[object],
) -> PackageSourceExtractionResult:

    if dependencies is None:
        return PackageSourceExtractionResult(
            dependencies=(),
            extracted=False,
            status="DEPENDENCIES_IS_NONE",
        )

    if isinstance(dependencies, (str, bytes)):
        return PackageSourceExtractionResult(
            dependencies=(),
            extracted=False,
            status="UNSUPPORTED_DEPENDENCY_COLLECTION",
        )

    try:
        items = tuple(dependencies)
    except TypeError:
        return PackageSourceExtractionResult(
            dependencies=(),
            extracted=False,
            status="UNSUPPORTED_DEPENDENCY_COLLECTION",
        )

    extracted: list[DependencySource] = []

    for item in items:
        dependency, status = _validate(item)

        if dependency is None:
            return PackageSourceExtractionResult(
                dependencies=(),
                extracted=False,
                status=status,
            )

        extracted.append(dependency)

    return PackageSourceExtractionResult(
        dependencies=tuple(extracted),
        extracted=True,
        status="EXTRACTED",
    )


def extract_dependency_sources(
    dependencies: Iterable[object],
) -> PackageSourceExtractionResult:
    return extract_package_sources(dependencies)
