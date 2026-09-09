from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable


@dataclass(frozen=True)
class DependencyGraphSnapshot:
    nodes: tuple[Any, ...]
    edges: tuple[tuple[Any, Any], ...]
    node_count: int
    edge_count: int
    status: str


def create_dependency_graph_snapshot(
    nodes: Iterable[Any] | None,
    edges: Iterable[Any] | None,
) -> DependencyGraphSnapshot:
    if nodes is None:
        return DependencyGraphSnapshot(
            (), (), 0, 0, "NODES_IS_NONE"
        )

    if edges is None:
        return DependencyGraphSnapshot(
            (), (), 0, 0, "EDGES_IS_NONE"
        )

    if isinstance(nodes, (str, bytes)):
        return DependencyGraphSnapshot(
            (), (), 0, 0, "UNSUPPORTED_NODES_COLLECTION"
        )

    if isinstance(edges, (str, bytes)):
        return DependencyGraphSnapshot(
            (), (), 0, 0, "UNSUPPORTED_EDGES_COLLECTION"
        )

    try:
        node_items = tuple(nodes)
    except TypeError:
        return DependencyGraphSnapshot(
            (), (), 0, 0, "UNSUPPORTED_NODES_COLLECTION"
        )

    try:
        raw_edges = tuple(edges)
    except TypeError:
        return DependencyGraphSnapshot(
            (), (), len(node_items), 0,
            "UNSUPPORTED_EDGES_COLLECTION"
        )

    normalized_edges: list[tuple[Any, Any]] = []

    for edge in raw_edges:
        if (
            isinstance(edge, (tuple, list))
            and len(edge) == 2
        ):
            source, target = edge
        elif isinstance(edge, dict):
            if "source" in edge and "target" in edge:
                source = edge["source"]
                target = edge["target"]
            elif "parent" in edge and "child" in edge:
                source = edge["parent"]
                target = edge["child"]
            else:
                return DependencyGraphSnapshot(
                    node_items,
                    (),
                    len(node_items),
                    0,
                    "INVALID_EDGE",
                )
        else:
            return DependencyGraphSnapshot(
                node_items,
                (),
                len(node_items),
                0,
                "INVALID_EDGE",
            )

        normalized_edges.append((source, target))

    return DependencyGraphSnapshot(
        nodes=node_items,
        edges=tuple(normalized_edges),
        node_count=len(node_items),
        edge_count=len(normalized_edges),
        status="SNAPSHOT_CREATED",
    )
