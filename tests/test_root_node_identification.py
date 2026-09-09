from dataclasses import dataclass
from typing import Optional

from sentinelshield.root_node_identification import (
    RootNodeIdentificationResult,
    identify_root_node,
    identify_root_node_from_graph,
)


@dataclass(frozen=True)
class Node:
    name: str
    version: Optional[str] = None
    dependency_type: str = "production"


@dataclass(frozen=True)
class Graph:
    nodes: tuple[Node, ...]


def test_root_node_is_identified():
    result = identify_root_node(
        [
            Node("requests", "2.32.0"),
        ]
    )

    assert isinstance(result, RootNodeIdentificationResult)
    assert result.root == "requests"
    assert result.identified is True
    assert result.status == "ROOT_IDENTIFIED"


def test_multiple_nodes_are_deterministic():
    result = identify_root_node(
        [
            Node("zlib"),
            Node("requests"),
            Node("axios"),
        ]
    )

    assert result.root == "axios"


def test_empty_nodes_are_rejected():
    result = identify_root_node([])

    assert result.root is None
    assert result.identified is False
    assert result.status == "NO_NODES"


def test_none_nodes_are_rejected():
    result = identify_root_node(None)

    assert result.root is None
    assert result.identified is False
    assert result.status == "NODES_IS_NONE"


def test_string_nodes_are_rejected():
    result = identify_root_node("requests")

    assert result.root is None
    assert result.identified is False
    assert result.status == "UNSUPPORTED_NODE_COLLECTION"


def test_bytes_nodes_are_rejected():
    result = identify_root_node(b"requests")

    assert result.root is None
    assert result.identified is False
    assert result.status == "UNSUPPORTED_NODE_COLLECTION"


def test_non_iterable_nodes_are_rejected():
    result = identify_root_node(123)

    assert result.root is None
    assert result.identified is False
    assert result.status == "UNSUPPORTED_NODE_COLLECTION"


def test_invalid_node_name_is_rejected():
    result = identify_root_node(
        [Node("")]
    )

    assert result.identified is False
    assert result.status == "INVALID_NODE_NAME"


def test_whitespace_node_name_is_rejected():
    result = identify_root_node(
        [Node("   ")]
    )

    assert result.identified is False
    assert result.status == "INVALID_NODE_NAME"


def test_node_name_is_trimmed():
    result = identify_root_node(
        [Node("  requests  ")]
    )

    assert result.root == "requests"


def test_duplicate_nodes_are_consolidated():
    result = identify_root_node(
        [
            Node("requests"),
            Node("requests"),
        ]
    )

    assert result.identified is True
    assert result.root == "requests"


def test_case_sensitive_names_are_deterministic():
    result = identify_root_node(
        [
            Node("Requests"),
            Node("requests"),
        ]
    )

    assert result.root == "requests"


def test_graph_root_is_identified():
    graph = Graph(
        nodes=(
            Node("requests", "2.32.0"),
        )
    )

    result = identify_root_node_from_graph(graph)

    assert result.root == "requests"
    assert result.identified is True
    assert result.status == "ROOT_IDENTIFIED"


def test_none_graph_is_rejected():
    result = identify_root_node_from_graph(None)

    assert result.root is None
    assert result.identified is False
    assert result.status == "GRAPH_IS_NONE"


def test_graph_without_nodes_is_rejected():
    class EmptyGraph:
        pass

    result = identify_root_node_from_graph(EmptyGraph())

    assert result.root is None
    assert result.identified is False
    assert result.status == "GRAPH_NODES_UNAVAILABLE"


def test_input_collection_is_not_modified():
    nodes = [
        Node("zlib"),
        Node("axios"),
    ]

    original = list(nodes)

    identify_root_node(nodes)

    assert nodes == original


def test_result_is_immutable():
    result = identify_root_node(
        [Node("requests")]
    )

    try:
        result.root = "changed"
    except AttributeError:
        pass
    else:
        raise AssertionError("Result must be immutable")


def test_only_node_name_is_required():
    class MinimalNode:
        name = "requests"

    result = identify_root_node(
        [MinimalNode()]
    )

    assert result.root == "requests"
    assert result.identified is True


def test_result_type():
    result = identify_root_node(
        [Node("requests")]
    )

    assert isinstance(
        result,
        RootNodeIdentificationResult,
    )
