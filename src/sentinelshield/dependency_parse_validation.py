from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional


@dataclass(frozen=True)
class ParsedDependency:
    name: str
    version: Optional[str] = None
    dependency_type: str = "production"
    source: Optional[str] = None


@dataclass(frozen=True)
class DependencyParseValidationResult:
    valid: bool
    dependencies: tuple[ParsedDependency, ...]
    status: str


def _validate_dependency(
    dependency: object,
) -> tuple[Optional[ParsedDependency], str]:

    if not hasattr(dependency, "name"):
        return None, "INVALID_DEPENDENCY"

    name = getattr(dependency, "name")

    if not isinstance(name, str) or not name.strip():
        return None, "INVALID_DEPENDENCY_NAME"

    version = getattr(dependency, "version", None)

    if version is not None and not isinstance(version, str):
        return None, "INVALID_DEPENDENCY_VERSION"

    dependency_type = getattr(
        dependency,
        "dependency_type",
        "production",
    )

    if not isinstance(dependency_type, str):
        return None, "INVALID_DEPENDENCY_TYPE"

    source = getattr(dependency, "source", None)

    if source is not None and not isinstance(source, str):
        return None, "INVALID_DEPENDENCY_SOURCE"

    return (
        ParsedDependency(
            name=name.strip(),
            version=version,
            dependency_type=dependency_type.strip().lower(),
            source=source,
        ),
        "VALID",
    )


def validate_dependency_parse(
    dependencies: Iterable[object],
) -> DependencyParseValidationResult:

    if dependencies is None:
        return DependencyParseValidationResult(
            valid=False,
            dependencies=(),
            status="DEPENDENCIES_IS_NONE",
        )

    if isinstance(dependencies, (str, bytes)):
        return DependencyParseValidationResult(
            valid=False,
            dependencies=(),
            status="UNSUPPORTED_DEPENDENCY_COLLECTION",
        )

    try:
        items = tuple(dependencies)
    except TypeError:
        return DependencyParseValidationResult(
            valid=False,
            dependencies=(),
            status="UNSUPPORTED_DEPENDENCY_COLLECTION",
        )

    parsed: list[ParsedDependency] = []

    for item in items:
        dependency, status = _validate_dependency(item)

        if dependency is None:
            return DependencyParseValidationResult(
                valid=False,
                dependencies=(),
                status=status,
            )

        parsed.append(dependency)

    return DependencyParseValidationResult(
        valid=True,
        dependencies=tuple(parsed),
        status="VALIDATED",
    )
