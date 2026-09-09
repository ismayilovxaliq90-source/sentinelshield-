from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional


@dataclass(frozen=True)
class DependencyNode:
    name: str
    version: Optional[str] = None


@dataclass(frozen=True)
class BlastRadiusResult:
    dependency: DependencyNode
    affected_dependents: tuple[DependencyNode, ...]
    blast_radius: int
    calculated: bool
    status: str


def calculate_dependency_blast_radius(
    dependency: object,
    dependents: Iterable[object] | None,
) -> BlastRadiusResult:
    if dependency is None:
        return BlastRadiusResult(
            DependencyNode("", None), (), 0, False, "DEPENDENCY_IS_NONE"
        )

    if not hasattr(dependency, "name"):
        return BlastRadiusResult(
            DependencyNode("", None), (), 0, False, "INVALID_DEPENDENCY"
        )

    name = getattr(dependency, "name")
    version = getattr(dependency, "version", None)

    if not isinstance(name, str) or not name.strip():
        return BlastRadiusResult(
            DependencyNode("", None), (), 0, False, "INVALID_DEPENDENCY_NAME"
        )

    if version is not None and not isinstance(version, str):
        return BlastRadiusResult(
            DependencyNode(name.strip(), None),
            (),
            0,
            False,
            "INVALID_DEPENDENCY_VERSION",
        )

    target = DependencyNode(name.strip(), version)

    if dependents is None:
        return BlastRadiusResult(
            target, (), 0, False, "DEPENDENTS_IS_NONE"
        )

    if isinstance(dependents, (str, bytes)):
        return BlastRadiusResult(
            target, (), 0, False, "UNSUPPORTED_DEPENDENTS"
        )

    try:
        items = tuple(dependents)
    except TypeError:
        return BlastRadiusResult(
            target, (), 0, False, "UNSUPPORTED_DEPENDENTS"
        )

    affected: list[DependencyNode] = []
    seen: set[tuple[str, Optional[str]]] = set()

    for item in items:
        if not hasattr(item, "name"):
            return BlastRadiusResult(
                target, (), 0, False, "INVALID_DEPENDENT"
            )

        item_name = getattr(item, "name")
        item_version = getattr(item, "version", None)

        if not isinstance(item_name, str) or not item_name.strip():
            return BlastRadiusResult(
                target, (), 0, False, "INVALID_DEPENDENT_NAME"
            )

        if item_version is not None and not isinstance(item_version, str):
            return BlastRadiusResult(
                target, (), 0, False, "INVALID_DEPENDENT_VERSION"
            )

        node = DependencyNode(item_name.strip(), item_version)
        key = (node.name, node.version)

        if key in seen:
            continue

        seen.add(key)

        if key != (target.name, target.version):
            affected.append(node)

    affected.sort(
        key=lambda node: (
            node.name.casefold(),
            node.name,
            node.version or "",
        )
    )

    return BlastRadiusResult(
        dependency=target,
        affected_dependents=tuple(affected),
        blast_radius=len(affected),
        calculated=True,
        status="CALCULATED",
    )
