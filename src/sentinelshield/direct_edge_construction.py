from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional


@dataclass(frozen=True)
class DirectDependency:
    name: str
    version: Optional[str] = None
    dependency_type: str = "production"
    source: Optional[str] = None


@dataclass(frozen=True)
class DirectDependencyEdge:
    parent: str
    child: str


@dataclass(frozen=True)
class DirectEdgeConstructionResult:
    edges: tuple[DirectDependencyEdge, ...]
    constructed: bool
    status: str


def construct_direct_edges(
    dependencies: Iterable[object],
) -> DirectEdgeConstructionResult:
    """
    Construct direct dependency edges from dependency records.

    A dependency record may optionally expose:
        parent
        name

    When parent is present, an edge parent -> name is created.

    Read-only operation.
    """

    if dependencies is None:
        return DirectEdgeConstructionResult(
            edges=(),
            constructed=False,
            status="DEPENDENCIES_IS_NONE",
        )

    if isinstance(dependencies, (str, bytes)):
        return DirectEdgeConstructionResult(
            edges=(),
            constructed=False,
            status="UNSUPPORTED_DEPENDENCY_COLLECTION",
        )

    try:
        items = tuple(dependencies)
    except TypeError:
        return DirectEdgeConstructionResult(
            edges=(),
            constructed=False,
            status="UNSUPPORTED_DEPENDENCY_COLLECTION",
        )

    edges: set[tuple[str, str]] = set()

    for dependency in items:
        name = getattr(dependency, "name", None)

        if not isinstance(name, str) or not name.strip():
            return DirectEdgeConstructionResult(
                edges=(),
                constructed=False,
                status="INVALID_DEPENDENCY_NAME",
            )

        name = name.strip()

        parent = getattr(dependency, "parent", None)

        if parent is None:
            continue

        if not isinstance(parent, str) or not parent.strip():
            return DirectEdgeConstructionResult(
                edges=(),
                constructed=False,
                status="INVALID_PARENT_NAME",
            )

        parent = parent.strip()

        if parent == name:
            return DirectEdgeConstructionResult(
                edges=(),
                constructed=False,
                status="SELF_DEPENDENCY",
            )

        edges.add((parent, name))

    result = tuple(
        DirectDependencyEdge(parent=parent, child=child)
        for parent, child in sorted(
            edges,
            key=lambda edge: (
                edge[0].casefold(),
                edge[0],
                edge[1].casefold(),
                edge[1],
            ),
        )
    )

    return DirectEdgeConstructionResult(
        edges=result,
        constructed=True,
        status="DIRECT_EDGES_CONSTRUCTED",
    )


def build_direct_edges(
    dependencies: Iterable[object],
) -> DirectEdgeConstructionResult:
    return construct_direct_edges(dependencies)
