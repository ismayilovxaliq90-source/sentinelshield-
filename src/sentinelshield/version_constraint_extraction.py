from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional


@dataclass(frozen=True)
class VersionConstraintDependency:
    name: str
    constraint: str
    dependency_type: str
    source: Optional[str] = None


@dataclass(frozen=True)
class VersionConstraintExtractionResult:
    dependencies: tuple[VersionConstraintDependency, ...]
    extracted: bool
    status: str


_CONSTRAINT_FIELDS = (
    "version_constraint",
    "constraint",
    "specifier",
    "version_spec",
    "requirement",
)


def _invalid(status: str) -> VersionConstraintExtractionResult:
    return VersionConstraintExtractionResult(
        dependencies=(),
        extracted=False,
        status=status,
    )


def _extract_constraint(dependency: object) -> tuple[Optional[str], str]:
    for field in _CONSTRAINT_FIELDS:
        if not hasattr(dependency, field):
            continue

        value = getattr(dependency, field)

        if value is None:
            continue

        if not isinstance(value, str):
            return None, "INVALID_VERSION_CONSTRAINT"

        value = value.strip()

        if not value:
            return None, "CONSTRAINT_EMPTY"

        return value, "EXTRACTED"

    return None, "CONSTRAINT_NOT_AVAILABLE"


def extract_version_constraints(
    dependencies: Iterable[object],
) -> VersionConstraintExtractionResult:
    if dependencies is None:
        return _invalid("DEPENDENCIES_IS_NONE")

    if isinstance(dependencies, (str, bytes)):
        return _invalid("UNSUPPORTED_DEPENDENCY_COLLECTION")

    try:
        items = tuple(dependencies)
    except TypeError:
        return _invalid("UNSUPPORTED_DEPENDENCY_COLLECTION")

    extracted: dict[
        tuple[str, str, str],
        VersionConstraintDependency,
    ] = {}

    for dependency in items:
        if dependency is None:
            return _invalid("INVALID_DEPENDENCY")

        if not hasattr(dependency, "name"):
            return _invalid("INVALID_DEPENDENCY")

        if not hasattr(dependency, "dependency_type"):
            return _invalid("INVALID_DEPENDENCY")

        name = getattr(dependency, "name")
        dependency_type = getattr(dependency, "dependency_type")
        source = getattr(dependency, "source", None)

        if not isinstance(name, str) or not name.strip():
            return _invalid("INVALID_DEPENDENCY_NAME")

        if not isinstance(dependency_type, str):
            return _invalid("INVALID_DEPENDENCY_TYPE")

        if source is not None and not isinstance(source, str):
            return _invalid("INVALID_DEPENDENCY_SOURCE")

        constraint, status = _extract_constraint(dependency)

        if status != "EXTRACTED":
            return _invalid(status)

        clean_name = name.strip()
        clean_type = dependency_type.strip().lower()

        key = (
            clean_name.casefold(),
            constraint.casefold(),
            clean_type,
        )

        extracted.setdefault(
            key,
            VersionConstraintDependency(
                name=clean_name,
                constraint=constraint,
                dependency_type=clean_type,
                source=source.strip() if source is not None else None,
            ),
        )

    result = tuple(
        sorted(
            extracted.values(),
            key=lambda dependency: (
                dependency.name.casefold(),
                0 if dependency.name[:1].islower() else 1,
                dependency.name,
                dependency.constraint.casefold(),
                dependency.constraint,
                dependency.dependency_type,
                dependency.source or "",
            ),
        )
    )

    return VersionConstraintExtractionResult(
        dependencies=result,
        extracted=True,
        status="EXTRACTED",
    )
