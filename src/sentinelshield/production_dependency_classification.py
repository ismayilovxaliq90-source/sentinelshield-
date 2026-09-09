from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional


@dataclass(frozen=True)
class ProductionDependency:
    name: str
    version: Optional[str]
    dependency_type: str
    source: Optional[str] = None


@dataclass(frozen=True)
class ProductionDependencyClassificationResult:
    dependencies: tuple[ProductionDependency, ...]
    classified: bool
    status: str


_ALLOWED_PRODUCTION_TYPES = frozenset({"production"})


def _validate_dependency(
    dependency: object,
) -> tuple[Optional[ProductionDependency], str]:
    if not hasattr(dependency, "name"):
        return None, "INVALID_DEPENDENCY"

    if not hasattr(dependency, "version"):
        return None, "INVALID_DEPENDENCY"

    if not hasattr(dependency, "dependency_type"):
        return None, "INVALID_DEPENDENCY"

    name = getattr(dependency, "name")
    version = getattr(dependency, "version")
    dependency_type = getattr(dependency, "dependency_type")
    source = getattr(dependency, "source", None)

    if not isinstance(name, str) or not name.strip():
        return None, "INVALID_DEPENDENCY_NAME"

    if version is not None and not isinstance(version, str):
        return None, "INVALID_DEPENDENCY_VERSION"

    if not isinstance(dependency_type, str):
        return None, "INVALID_DEPENDENCY_TYPE"

    if source is not None and not isinstance(source, str):
        return None, "INVALID_DEPENDENCY_SOURCE"

    return (
        ProductionDependency(
            name=name.strip(),
            version=version,
            dependency_type=dependency_type.strip().lower(),
            source=source,
        ),
        "VALID",
    )


def classify_production_dependencies(
    dependencies: Iterable[object],
) -> ProductionDependencyClassificationResult:
    """
    Classify production dependencies from an existing dependency inventory.

    Only dependencies whose dependency_type is exactly "production"
    are included in the resulting production inventory.

    The operation is strictly read-only.

    It does not:
      - install packages
      - modify manifests
      - modify lockfiles
      - execute package-manager commands
      - execute project code
    """

    if dependencies is None:
        return ProductionDependencyClassificationResult(
            dependencies=(),
            classified=False,
            status="DEPENDENCIES_IS_NONE",
        )

    if isinstance(dependencies, (str, bytes)):
        return ProductionDependencyClassificationResult(
            dependencies=(),
            classified=False,
            status="UNSUPPORTED_DEPENDENCY_COLLECTION",
        )

    try:
        items = tuple(dependencies)
    except TypeError:
        return ProductionDependencyClassificationResult(
            dependencies=(),
            classified=False,
            status="UNSUPPORTED_DEPENDENCY_COLLECTION",
        )

    production: list[ProductionDependency] = []

    for item in items:
        dependency, status = _validate_dependency(item)

        if dependency is None:
            return ProductionDependencyClassificationResult(
                dependencies=(),
                classified=False,
                status=status,
            )

        if dependency.dependency_type in _ALLOWED_PRODUCTION_TYPES:
            production.append(dependency)

    production.sort(
        key=lambda dependency: (
            dependency.name.casefold(),
            0 if dependency.name[:1].islower() else 1,
            dependency.name,
            dependency.version or "",
            dependency.source or "",
        )
    )

    return ProductionDependencyClassificationResult(
        dependencies=tuple(production),
        classified=True,
        status="CLASSIFIED",
    )


__all__ = [
    "ProductionDependency",
    "ProductionDependencyClassificationResult",
    "classify_production_dependencies",
]
