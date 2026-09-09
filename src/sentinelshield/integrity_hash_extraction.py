from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional


@dataclass(frozen=True)
class Dependency:
    name: str
    version: Optional[str] = None
    integrity: Optional[str] = None
    hash: Optional[str] = None
    source: Optional[str] = None


@dataclass(frozen=True)
class DependencyIntegrity:
    name: str
    integrity: Optional[str]
    hash: Optional[str]


@dataclass(frozen=True)
class IntegrityHashExtractionResult:
    dependencies: tuple[DependencyIntegrity, ...]
    extracted: bool
    status: str


def _validate(item: object) -> tuple[Optional[DependencyIntegrity], str]:
    if not hasattr(item, "name"):
        return None, "INVALID_DEPENDENCY"

    if not hasattr(item, "integrity"):
        return None, "INVALID_DEPENDENCY"

    if not hasattr(item, "hash"):
        return None, "INVALID_DEPENDENCY"

    name = getattr(item, "name")
    integrity = getattr(item, "integrity")
    dependency_hash = getattr(item, "hash")

    if not isinstance(name, str) or not name.strip():
        return None, "INVALID_DEPENDENCY_NAME"

    if integrity is not None and not isinstance(integrity, str):
        return None, "INVALID_INTEGRITY"

    if dependency_hash is not None and not isinstance(
        dependency_hash, str
    ):
        return None, "INVALID_HASH"

    integrity = (
        integrity.strip()
        if isinstance(integrity, str)
        else None
    )

    dependency_hash = (
        dependency_hash.strip()
        if isinstance(dependency_hash, str)
        else None
    )

    if integrity == "":
        integrity = None

    if dependency_hash == "":
        dependency_hash = None

    return (
        DependencyIntegrity(
            name=name.strip(),
            integrity=integrity,
            hash=dependency_hash,
        ),
        "VALID",
    )


def extract_integrity_hashes(
    dependencies: Iterable[object],
) -> IntegrityHashExtractionResult:

    if dependencies is None:
        return IntegrityHashExtractionResult(
            dependencies=(),
            extracted=False,
            status="DEPENDENCIES_IS_NONE",
        )

    if isinstance(dependencies, (str, bytes)):
        return IntegrityHashExtractionResult(
            dependencies=(),
            extracted=False,
            status="UNSUPPORTED_DEPENDENCY_COLLECTION",
        )

    try:
        items = tuple(dependencies)
    except TypeError:
        return IntegrityHashExtractionResult(
            dependencies=(),
            extracted=False,
            status="UNSUPPORTED_DEPENDENCY_COLLECTION",
        )

    extracted: list[DependencyIntegrity] = []

    for item in items:
        dependency, status = _validate(item)

        if dependency is None:
            return IntegrityHashExtractionResult(
                dependencies=(),
                extracted=False,
                status=status,
            )

        extracted.append(dependency)

    return IntegrityHashExtractionResult(
        dependencies=tuple(extracted),
        extracted=True,
        status="EXTRACTED",
    )


def extract_dependency_integrity_hashes(
    dependencies: Iterable[object],
) -> IntegrityHashExtractionResult:
    return extract_integrity_hashes(dependencies)
