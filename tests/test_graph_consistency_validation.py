from dataclasses import dataclass

from sentinelshield.graph_consistency_validation import (
    GraphConsistencyResult,
    validate_dependency_graph,
)


@dataclass(frozen=True)
class Node:
    id: str


@dataclass(frozen=True)
class Edge:
    parent: str
    child: str


def test_valid_graph():
    result = validate_dependency_graph(
        ["a", "b", "c"],
        [("a", "b"), ("b", "c")],
    )

    assert isinstance(result, GraphConsistencyResult)
    assert result.consistent is True
    assert result.status == "GRAPH_CONSISTENT"
    assert result.node_count == 3
    assert result.edge_count == 2


def test_empty_graph_is_consistent():
    result = validate_dependency_graph([], [])

    assert result.consistent is True
    assert result.status == "GRAPH_CONSISTENT"
    assert result.node_count == 0
    assert result.edge_count == 0


def test_none_nodes():
    result = validate_dependency_graph(None, [])

    assert result.consistent is False
    assert result.status == "NODES_IS_NONE"


def test_none_edges():
    result = validate_dependency_graph([], None)

    assert result.consistent is False
    assert result.status == "EDGES_IS_NONE"


def test_string_nodes_rejected():
    result = validate_dependency_graph("abc", [])

    assert result.consistent is False
    assert result.status == "UNSUPPORTED_NODES_COLLECTION"


def test_string_edges_rejected():
    result = validate_dependency_graph(["a"], "ab")

    assert result.consistent is False
    assert result.status == "UNSUPPORTED_EDGES_COLLECTION"


def test_non_iterable_nodes_rejected():
    result = validate_dependency_graph(123, [])

    assert result.consistent is False
    assert result.status == "UNSUPPORTED_NODES_COLLECTION"


def test_non_iterable_edges_rejected():
    result = validate_dependency_graph(["a"], 123)

    assert result.consistent is False
    assert result.status == "UNSUPPORTED_EDGES_COLLECTION"


def test_duplicate_nodes_rejected():
    result = validate_dependency_graph(
        ["a", "a"],
        [],
    )

    assert result.consistent is False
    assert result.status == "DUPLICATE_NODE"


def test_unknown_source_node_rejected():
    result = validate_dependency_graph(
        ["a", "b"],
        [("x", "b")],
    )

    assert result.consistent is False
    assert result.status == "EDGE_REFERENCES_UNKNOWN_NODE"


def test_unknown_target_node_rejected():
    result = validate_dependency_graph(
        ["a", "b"],
        [("a", "x")],
    )

    assert result.consistent is False
    assert result.status == "EDGE_REFERENCES_UNKNOWN_NODE"


def test_self_loop_rejected():
    result = validate_dependency_graph(
        ["a"],
        [("a", "a")],
    )

    assert result.consistent is False
    assert result.status == "SELF_LOOP"


def test_duplicate_edge_rejected():
    result = validate_dependency_graph(
        ["a", "b"],
        [("a", "b"), ("a", "b")],
    )

    assert result.consistent is False
    assert result.status == "DUPLICATE_EDGE"


def test_node_objects_are_supported():
    result = validate_dependency_graph(
        [Node("a"), Node("b")],
        [("a", "b")],
    )

    assert result.consistent is True
    assert result.status == "GRAPH_CONSISTENT"


def test_edge_objects_are_supported():
    result = validate_dependency_graph(
        ["a", "b"],
        [Edge("a", "b")],
    )

    assert result.consistent is True
    assert result.status == "GRAPH_CONSISTENT"


def test_dictionary_nodes_are_supported():
    result = validate_dependency_graph(
        [{"id": "a"}, {"id": "b"}],
        [("a", "b")],
    )

    assert result.consistent is True


def test_dictionary_source_target_edges_are_supported():
    result = validate_dependency_graph(
        ["a", "b"],
        [{"source": "a", "target": "b"}],
    )

    assert result.consistent is True


def test_dictionary_parent_child_edges_are_supported():
    result = validate_dependency_graph(
        ["a", "b"],
        [{"parent": "a", "child": "b"}],
    )

    assert result.consistent is True


def test_invalid_node_is_rejected():
    result = validate_dependency_graph(
        [{"name": "a"}],
        [],
    )

    assert result.consistent is False
    assert result.status == "INVALID_NODE"


def test_invalid_edge_is_rejected():
    result = validate_dependency_graph(
        ["a", "b"],
        [("a", "b", "c")],
    )

    assert result.consistent is False
    assert result.status == "INVALID_EDGE"


def test_input_collections_are_not_modified():
    nodes = ["b", "a"]
    edges = [("a", "b")]

    original_nodes = list(nodes)
    original_edges = list(edges)

    validate_dependency_graph(nodes, edges)

    assert nodes == original_nodes
    assert edges == original_edges


def test_result_is_immutable():
    result = validate_dependency_graph(
        ["a", "b"],
        [("a", "b")],
    )

    try:
        result.consistent = False
        assert False
    except AttributeError:
        pass


def test_counts_are_reported_for_invalid_edge():
    result = validate_dependency_graph(
        ["a", "b"],
        [("a", "x")],
    )

    assert result.node_count == 2
    assert result.edge_count == 1
