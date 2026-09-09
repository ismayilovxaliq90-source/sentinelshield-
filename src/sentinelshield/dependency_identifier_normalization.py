from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Optional


@dataclass(frozen=True)
class DependencyIdentifier:
    name: str
    identifier: str
    source: Optional[str] = None


@dataclass(frozen=True)
class DependencyIdentifierNormalizationResult:
    dependencies: tuple[DependencyIdentifier, ...]
    normalized: bool
    status: str


def _normalize_name(value: Any) -> tuple[Optional[str], str]:
    if not isinstance(value, str):
        return None, "INVALID_DEPENDENCY_NAME"

    name = value.strip()

    if not name:
        return None, "INVALID_DEPENDENCY_NAME"

    return name, "VALID"


def _normalize_identifier(value: Any) -> tuple[Optional[str], str]:
    if not isinstance(value, str):
        return None, "INVALID_DEPENDENCY_IDENTIFIER"

    identifier = value.strip()

    if not identifier:
        return None, "INVALID_DEPENDENCY_IDENTIFIER"

    return identifier, "VALID"


def normalize_dependency_identifiers(
    dependencies: Iterable[Any],
) -> DependencyIdentifierNormalizationResult:

    if dependencies is None:
        return DependencyIdentifierNormalizationResult(
            dependencies=(),
            normalized=False,
            status="DEPENDENCIES_IS_NONE",
        )

    if isinstance(dependencies, (str, bytes)):
        return DependencyIdentifierNormalizationResult(
            dependencies=(),
            normalized=False,
            status="UNSUPPORTED_DEPENDENCY_COLLECTION",
        )

    try:
        items = tuple(dependencies)
    except TypeError:
        return DependencyIdentifierNormalizationResult(
            dependencies=(),
            normalized=False,
            status="UNSUPPORTED_DEPENDENCY_COLLECTION",
        )

    result: list[DependencyIdentifier] = []

    for dependency in items:
        if not hasattr(dependency, "name"):
            return DependencyIdentifierNormalizationResult(
                dependencies=(),
                normalized=False,
                status="INVALID_DEPENDENCY",
            )

        if not hasattr(dependency, "identifier"):
            return DependencyIdentifierNormalizationResult(
                dependencies=(),
                normalized=False,
                status="INVALID_DEPENDENCY",
            )

        name, name_status = _normalize_name(
            getattr(dependency, "name")
        )

        if name is None:
            return DependencyIdentifierNormalizationResult(
                dependencies=(),
                normalized=False,
                status=name_status,
            )

        identifier, identifier_status = _normalize_identifier(
            getattr(dependency, "identifier")
        )

        if identifier is None:
            return DependencyIdentifierNormalizationResult(
                dependencies=(),
                normalized=False,
                status=identifier_status,
            )

        source = getattr(dependency, "source", None)

        if source is not None:
            if not isinstance(source, str):
                return DependencyIdentifierNormalizationResult(
                    dependencies=(),
                    normalized=False,
                    status="INVALID_DEPENDENCY_SOURCE",
                )

            source = source.strip() or None

        result.append(
            DependencyIdentifier(
                name=name,
                identifier=identifier,
                source=source,
            )
        )

    return DependencyIdentifierNormalizationResult(
        dependencies=tuple(result),
        normalized=True,
        status="NORMALIZED",
    )


def normalize_dependency_identifier(
    dependency: Any,
) -> DependencyIdentifierNormalizationResult:
    return normalize_dependency_identifiers([dependency])
