from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable


@dataclass(frozen=True)
class TransitiveEdge:
    parent: str
    child: str


@dataclass(frozen=True)
class TransitiveEdgeConstructionResult:
    edges: tuple[TransitiveEdge, ...]
    constructed: bool
    status: str


def _name(value: object) -> str | None:
    if isinstance(value, str):
        value = value.strip()
        return value or None

    value = getattr(value, "name", None)

    if isinstance(value, str):
        value = value.strip()
        return value or None

    return None


def _children(value: object) -> Iterable[object] | None:
    for attribute in (
        "transitive_dependencies",
        "dependencies",
        "children",
    ):
        if hasattr(value, attribute):
            result = getattr(value, attribute)
            if result is None:
                return ()
            if isinstance(result, (str, bytes)):
                return None
            try:
                return tuple(result)
            except TypeError:
                return None

    return ()


def construct_transitive_edges(
    dependency_graph: Any,
) -> TransitiveEdgeConstructionResult:
    """
    TASK 89 — Transitive Edge Construction.

    Builds only transitive dependency edges from an existing dependency
    graph/inventory.

    Read-only:
      - no package installation
      - no package-manager execution
      - no project-code execution
      - no filesystem modification
    """

    if dependency_graph is None:
        return TransitiveEdgeConstructionResult(
            edges=(),
            constructed=False,
            status="GRAPH_IS_NONE",
        )

    if isinstance(dependency_graph, (str, bytes)):
        return TransitiveEdgeConstructionResult(
            edges=(),
            constructed=False,
            status="UNSUPPORTED_GRAPH_TYPE",
        )

    try:
        nodes = tuple(dependency_graph)
    except TypeError:
        return TransitiveEdgeConstructionResult(
            edges=(),
            constructed=False,
            status="UNSUPPORTED_GRAPH_TYPE",
        )

    edges: set[tuple[str, str]] = set()

    for node in nodes:
        parent = _name(node)

        if parent is None:
            return TransitiveEdgeConstructionResult(
                edges=(),
                constructed=False,
                status="INVALID_PARENT_NODE",
            )

        children = _children(node)

        if children is None:
            return TransitiveEdgeConstructionResult(
                edges=(),
                constructed=False,
                status="INVALID_CHILD_COLLECTION",
            )

        for child in children:
            child_name = _name(child)

            if child_name is None:
                return TransitiveEdgeConstructionResult(
                    edges=(),
                    constructed=False,
                    status="INVALID_CHILD_NODE",
                )

            if child_name == parent:
                continue

            edges.add((parent, child_name))

    result = tuple(
        TransitiveEdge(parent=parent, child=child)
        for parent, child in sorted(
            edges,
            key=lambda item: (
                item[0].casefold(),
                0 if item[0][:1].islower() else 1,
                item[0],
                item[1].casefold(),
                0 if item[1][:1].islower() else 1,
                item[1],
            ),
        )
    )

    return TransitiveEdgeConstructionResult(
        edges=result,
        constructed=True,
        status="CONSTRUCTED",
    )
