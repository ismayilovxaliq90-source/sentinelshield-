from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional


@dataclass(frozen=True)
class DependencyMetadata:
    name: str
    version: Optional[str]
    source: Optional[str]
    integrity: Optional[str]
    hash: Optional[str]
    dependency_type: Optional[str]


@dataclass(frozen=True)
class DependencyMetadataExtractionResult:
    dependencies: tuple[DependencyMetadata, ...]
    extracted: bool
    status: str


def _validate(
    dependency: object,
) -> tuple[Optional[DependencyMetadata], str]:
    if not hasattr(dependency, "name"):
        return None, "INVALID_DEPENDENCY"

    name = getattr(dependency, "name")

    if not isinstance(name, str) or not name.strip():
        return None, "INVALID_DEPENDENCY_NAME"

    def optional_string(
        attribute: str,
        error: str,
    ) -> tuple[Optional[str], Optional[str]]:
        if not hasattr(dependency, attribute):
            return None, None

        value = getattr(dependency, attribute)

        if value is not None and not isinstance(value, str):
            return None, error

        if isinstance(value, str):
            value = value.strip()
            if not value:
                return None, None

        return value, None

    version, error = optional_string(
        "version",
        "INVALID_DEPENDENCY_VERSION",
    )
    if error:
        return None, error

    source, error = optional_string(
        "source",
        "INVALID_DEPENDENCY_SOURCE",
    )
    if error:
        return None, error

    integrity, error = optional_string(
        "integrity",
        "INVALID_INTEGRITY",
    )
    if error:
        return None, error

    dependency_hash, error = optional_string(
        "hash",
        "INVALID_HASH",
    )
    if error:
        return None, error

    dependency_type, error = optional_string(
        "dependency_type",
        "INVALID_DEPENDENCY_TYPE",
    )
    if error:
        return None, error

    return (
        DependencyMetadata(
            name=name.strip(),
            version=version,
            source=source,
            integrity=integrity,
            hash=dependency_hash,
            dependency_type=dependency_type,
        ),
        "VALID",
    )


def extract_dependency_metadata(
    dependencies: Iterable[object],
) -> DependencyMetadataExtractionResult:

    if dependencies is None:
        return DependencyMetadataExtractionResult(
            dependencies=(),
            extracted=False,
            status="DEPENDENCIES_IS_NONE",
        )

    if isinstance(dependencies, (str, bytes)):
        return DependencyMetadataExtractionResult(
            dependencies=(),
            extracted=False,
            status="UNSUPPORTED_DEPENDENCY_COLLECTION",
        )

    try:
        items = tuple(dependencies)
    except TypeError:
        return DependencyMetadataExtractionResult(
            dependencies=(),
            extracted=False,
            status="UNSUPPORTED_DEPENDENCY_COLLECTION",
        )

    metadata: list[DependencyMetadata] = []

    for item in items:
        dependency, status = _validate(item)

        if dependency is None:
            return DependencyMetadataExtractionResult(
                dependencies=(),
                extracted=False,
                status=status,
            )

        metadata.append(dependency)

    return DependencyMetadataExtractionResult(
        dependencies=tuple(metadata),
        extracted=True,
        status="EXTRACTED",
    )


def extract_metadata(
    dependencies: Iterable[object],
) -> DependencyMetadataExtractionResult:
    return extract_dependency_metadata(dependencies)
