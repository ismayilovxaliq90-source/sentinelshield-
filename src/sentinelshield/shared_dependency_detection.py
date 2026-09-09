from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional


@dataclass(frozen=True)
class DependencyNode:
    name: str
    version: Optional[str] = None


@dataclass(frozen=True)
class SharedDependencyResult:
    shared_dependencies: tuple[DependencyNode, ...]
    shared: bool
    status: str


def detect_shared_dependencies(
    dependency_groups: Iterable[Iterable[object]] | None,
) -> SharedDependencyResult:
    if dependency_groups is None:
        return SharedDependencyResult((), False, "DEPENDENCY_GROUPS_IS_NONE")

    if isinstance(dependency_groups, (str, bytes)):
        return SharedDependencyResult(
            (), False, "UNSUPPORTED_DEPENDENCY_GROUPS"
        )

    try:
        groups = tuple(dependency_groups)
    except TypeError:
        return SharedDependencyResult(
            (), False, "UNSUPPORTED_DEPENDENCY_GROUPS"
        )

    if not groups:
        return SharedDependencyResult((), False, "NO_DEPENDENCY_GROUPS")

    owners: dict[tuple[str, Optional[str]], set[int]] = {}

    for group_index, group in enumerate(groups):
        if isinstance(group, (str, bytes)):
            return SharedDependencyResult(
                (), False, "INVALID_DEPENDENCY_GROUP"
            )

        try:
            dependencies = tuple(group)
        except TypeError:
            return SharedDependencyResult(
                (), False, "INVALID_DEPENDENCY_GROUP"
            )

        seen_in_group: set[tuple[str, Optional[str]]] = set()

        for dependency in dependencies:
            if not hasattr(dependency, "name"):
                return SharedDependencyResult(
                    (), False, "INVALID_DEPENDENCY"
                )

            name = getattr(dependency, "name")
            version = getattr(dependency, "version", None)

            if not isinstance(name, str) or not name.strip():
                return SharedDependencyResult(
                    (), False, "INVALID_DEPENDENCY_NAME"
                )

            if version is not None and not isinstance(version, str):
                return SharedDependencyResult(
                    (), False, "INVALID_DEPENDENCY_VERSION"
                )

            key = (name.strip(), version)

            if key in seen_in_group:
                continue

            seen_in_group.add(key)
            owners.setdefault(key, set()).add(group_index)

    shared = [
        DependencyNode(name=name, version=version)
        for (name, version), group_indexes in owners.items()
        if len(group_indexes) > 1
    ]

    shared.sort(
        key=lambda dependency: (
            dependency.name.casefold(),
            dependency.name,
            dependency.version or "",
        )
    )

    return SharedDependencyResult(
        shared_dependencies=tuple(shared),
        shared=bool(shared),
        status="SHARED_DEPENDENCIES_FOUND" if shared else "NO_SHARED_DEPENDENCIES",
    )
