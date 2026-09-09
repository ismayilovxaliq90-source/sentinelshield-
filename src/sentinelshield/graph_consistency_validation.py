from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable


@dataclass(frozen=True)
class GraphConsistencyResult:
    consistent: bool
    status: str
    node_count: int
    edge_count: int


def validate_dependency_graph(
    nodes: Iterable[Any] | None,
    edges: Iterable[Any] | None,
) -> GraphConsistencyResult:
    """
    TASK 99 — Graph Consistency Validation.

    Read-only validation of an already constructed dependency graph.

    Node identifiers must be unique.
    Every edge must reference existing nodes.
    Self-loops are rejected.
    Duplicate edges are rejected.
    """

    if nodes is None:
        return GraphConsistencyResult(
            False, "NODES_IS_NONE", 0, 0
        )

    if edges is None:
        return GraphConsistencyResult(
            False, "EDGES_IS_NONE", 0, 0
        )

    if isinstance(nodes, (str, bytes)):
        return GraphConsistencyResult(
            False, "UNSUPPORTED_NODES_COLLECTION", 0, 0
        )

    if isinstance(edges, (str, bytes)):
        return GraphConsistencyResult(
            False, "UNSUPPORTED_EDGES_COLLECTION", 0, 0
        )

    try:
        node_items = tuple(nodes)
    except TypeError:
        return GraphConsistencyResult(
            False, "UNSUPPORTED_NODES_COLLECTION", 0, 0
        )

    try:
        edge_items = tuple(edges)
    except TypeError:
        return GraphConsistencyResult(
            False, "UNSUPPORTED_EDGES_COLLECTION",
            len(node_items), 0
        )

    node_ids: set[Any] = set()

    for node in node_items:
        try:
            if isinstance(node, dict):
                if "id" not in node:
                    return GraphConsistencyResult(
                        False, "INVALID_NODE", len(node_items), 0
                    )
                node_id = node["id"]
            elif hasattr(node, "id"):
                node_id = node.id
            else:
                node_id = node

            hash(node_id)
        except (TypeError, AttributeError):
            return GraphConsistencyResult(
                False, "INVALID_NODE", len(node_items), 0
            )

        if node_id in node_ids:
            return GraphConsistencyResult(
                False, "DUPLICATE_NODE", len(node_items), 0
            )

        node_ids.add(node_id)

    edge_set: set[tuple[Any, Any]] = set()

    for edge in edge_items:
        try:
            if isinstance(edge, dict):
                if "parent" in edge and "child" in edge:
                    parent = edge["parent"]
                    child = edge["child"]
                elif "source" in edge and "target" in edge:
                    parent = edge["source"]
                    child = edge["target"]
                else:
                    return GraphConsistencyResult(
                        False, "INVALID_EDGE",
                        len(node_items), len(edge_items)
                    )
            elif (
                isinstance(edge, (tuple, list))
                and len(edge) == 2
            ):
                parent, child = edge
            elif hasattr(edge, "parent") and hasattr(edge, "child"):
                parent = edge.parent
                child = edge.child
            elif hasattr(edge, "source") and hasattr(edge, "target"):
                parent = edge.source
                child = edge.target
            else:
                return GraphConsistencyResult(
                    False, "INVALID_EDGE",
                    len(node_items), len(edge_items)
                )

            hash(parent)
            hash(child)

        except (TypeError, AttributeError):
            return GraphConsistencyResult(
                False, "INVALID_EDGE",
                len(node_items), len(edge_items)
            )

        if parent not in node_ids or child not in node_ids:
            return GraphConsistencyResult(
                False, "EDGE_REFERENCES_UNKNOWN_NODE",
                len(node_items), len(edge_items)
            )

        if parent == child:
            return GraphConsistencyResult(
                False, "SELF_LOOP",
                len(node_items), len(edge_items)
            )

        key = (parent, child)

        if key in edge_set:
            return GraphConsistencyResult(
                False, "DUPLICATE_EDGE",
                len(node_items), len(edge_items)
            )

        edge_set.add(key)

    return GraphConsistencyResult(
        True,
        "GRAPH_CONSISTENT",
        len(node_items),
        len(edge_items),
    )
