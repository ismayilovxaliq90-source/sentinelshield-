from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional


@dataclass(frozen=True)
class Dependency:
    name: str
    version: Optional[str] = None


@dataclass(frozen=True)
class ChildDependencyMapping:
    parent: str
    children: tuple[str, ...]


@dataclass(frozen=True)
class ChildDependencyMappingResult:
    mappings: tuple[ChildDependencyMapping, ...]
    mapped: bool
    status: str


def map_child_dependencies(
    edges: Iterable[object],
) -> ChildDependencyMappingResult:
    if edges is None:
        return ChildDependencyMappingResult(
            mappings=(),
            mapped=False,
            status="EDGES_IS_NONE",
        )

    if isinstance(edges, (str, bytes)):
        return ChildDependencyMappingResult(
            mappings=(),
            mapped=False,
            status="UNSUPPORTED_EDGE_COLLECTION",
        )

    try:
        items = tuple(edges)
    except TypeError:
        return ChildDependencyMappingResult(
            mappings=(),
            mapped=False,
            status="UNSUPPORTED_EDGE_COLLECTION",
        )

    children: dict[str, set[str]] = {}

    for edge in items:
        if isinstance(edge, dict):
            parent = edge.get("parent")
            child = edge.get("child")
        elif isinstance(edge, (tuple, list)) and len(edge) == 2:
            parent, child = edge
        else:
            parent = getattr(edge, "parent", None)
            child = getattr(edge, "child", None)

        if not isinstance(parent, str) or not parent.strip():
            return ChildDependencyMappingResult(
                mappings=(),
                mapped=False,
                status="INVALID_PARENT",
            )

        if not isinstance(child, str) or not child.strip():
            return ChildDependencyMappingResult(
                mappings=(),
                mapped=False,
                status="INVALID_CHILD",
            )

        parent = parent.strip()
        child = child.strip()

        if parent == child:
            return ChildDependencyMappingResult(
                mappings=(),
                mapped=False,
                status="SELF_DEPENDENCY",
            )

        children.setdefault(parent, set()).add(child)

    mappings = tuple(
        ChildDependencyMapping(
            parent=parent,
            children=tuple(sorted(values)),
        )
        for parent, values in sorted(
            children.items(),
            key=lambda item: item[0],
        )
    )

    return ChildDependencyMappingResult(
        mappings=mappings,
        mapped=True,
        status="MAPPED",
    )
