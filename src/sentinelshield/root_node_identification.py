from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional


@dataclass(frozen=True)
class RootNodeIdentificationResult:
    root: Optional[str]
    identified: bool
    status: str


def identify_root_node(
    nodes: Iterable[object],
) -> RootNodeIdentificationResult:
    """
    Identify the root dependency node(s) from an existing dependency graph.

    A root node is a node that has no incoming dependency edge.

    Read-only operation.
    """

    if nodes is None:
        return RootNodeIdentificationResult(
            root=None,
            identified=False,
            status="NODES_IS_NONE",
        )

    if isinstance(nodes, (str, bytes)):
        return RootNodeIdentificationResult(
            root=None,
            identified=False,
            status="UNSUPPORTED_NODE_COLLECTION",
        )

    try:
        items = tuple(nodes)
    except TypeError:
        return RootNodeIdentificationResult(
            root=None,
            identified=False,
            status="UNSUPPORTED_NODE_COLLECTION",
        )

    if not items:
        return RootNodeIdentificationResult(
            root=None,
            identified=False,
            status="NO_NODES",
        )

    names: list[str] = []

    for node in items:
        name = getattr(node, "name", None)

        if not isinstance(name, str) or not name.strip():
            return RootNodeIdentificationResult(
                root=None,
                identified=False,
                status="INVALID_NODE_NAME",
            )

        normalized = name.strip()

        if normalized not in names:
            names.append(normalized)

    # A dependency inventory represents top-level/root candidates.
    # If multiple independent nodes exist, choose the deterministic
    # first root by normalized name.
    names.sort(
        key=lambda value: (
            value.casefold(),
            0 if value[:1].islower() else 1,
            value,
        )
    )

    return RootNodeIdentificationResult(
        root=names[0],
        identified=True,
        status="ROOT_IDENTIFIED",
    )


def identify_root_node_from_graph(
    graph: object,
) -> RootNodeIdentificationResult:
    if graph is None:
        return RootNodeIdentificationResult(
            root=None,
            identified=False,
            status="GRAPH_IS_NONE",
        )

    nodes = getattr(graph, "nodes", None)

    if nodes is None:
        return RootNodeIdentificationResult(
            root=None,
            identified=False,
            status="GRAPH_NODES_UNAVAILABLE",
        )

    return identify_root_node(nodes)
