from dataclasses import dataclass

import pytest

from sentinelshield.transitive_edge_construction import (
    TransitiveEdge,
    TransitiveEdgeConstructionResult,
    construct_transitive_edges,
)


@dataclass(frozen=True)
class Dependency:
    name: str
    dependencies: tuple = ()


def test_constructs_transitive_edges():
    c = Dependency("C")
    b = Dependency("B", (c,))
    a = Dependency("A", (b,))

    result = construct_transitive_edges((a, b, c))

    assert result.constructed is True
    assert result.status == "CONSTRUCTED"
    assert result.edges == (
        TransitiveEdge("A", "B"),
        TransitiveEdge("B", "C"),
    )


def test_multiple_transitive_edges():
    d = Dependency("D")
    c = Dependency("C", (d,))
    b = Dependency("B", (c, d))
    a = Dependency("A", (b, c))

    result = construct_transitive_edges((a, b, c, d))

    assert set(result.edges) == {
        TransitiveEdge("A", "B"),
        TransitiveEdge("A", "C"),
        TransitiveEdge("B", "C"),
        TransitiveEdge("B", "D"),
        TransitiveEdge("C", "D"),
    }


def test_duplicate_edges_are_removed():
    b = Dependency("B")
    a1 = Dependency("A", (b,))
    a2 = Dependency("A", (b,))

    result = construct_transitive_edges((a1, a2, b))

    assert result.edges == (
        TransitiveEdge("A", "B"),
    )


def test_empty_graph():
    result = construct_transitive_edges(())

    assert isinstance(result, TransitiveEdgeConstructionResult)
    assert result.constructed is True
    assert result.status == "CONSTRUCTED"
    assert result.edges == ()


def test_none_graph():
    result = construct_transitive_edges(None)

    assert result.constructed is False
    assert result.status == "GRAPH_IS_NONE"
    assert result.edges == ()


def test_string_graph_rejected():
    result = construct_transitive_edges("A")

    assert result.constructed is False
    assert result.status == "UNSUPPORTED_GRAPH_TYPE"


def test_bytes_graph_rejected():
    result = construct_transitive_edges(b"A")

    assert result.constructed is False
    assert result.status == "UNSUPPORTED_GRAPH_TYPE"


def test_non_iterable_graph_rejected():
    result = construct_transitive_edges(123)

    assert result.constructed is False
    assert result.status == "UNSUPPORTED_GRAPH_TYPE"


def test_invalid_parent_node():
    result = construct_transitive_edges([object()])

    assert result.constructed is False
    assert result.status == "INVALID_PARENT_NODE"


def test_invalid_child_node():
    parent = Dependency("A", (object(),))

    result = construct_transitive_edges([parent])

    assert result.constructed is False
    assert result.status == "INVALID_CHILD_NODE"


def test_invalid_child_collection():
    class BadNode:
        name = "A"
        dependencies = 123

    result = construct_transitive_edges([BadNode()])

    assert result.constructed is False
    assert result.status == "INVALID_CHILD_COLLECTION"


def test_self_edge_is_not_created():
    node = Dependency("A")

    object.__setattr__(node, "dependencies", (node,))

    result = construct_transitive_edges([node])

    assert result.constructed is True
    assert result.edges == ()


def test_deterministic_order():
    d = Dependency("z")
    b = Dependency("b", (d,))
    a = Dependency("a", (b,))

    result = construct_transitive_edges((d, a, b))

    assert result.edges == (
        TransitiveEdge("a", "b"),
        TransitiveEdge("b", "z"),
    )


def test_result_is_immutable():
    result = construct_transitive_edges(())

    with pytest.raises(AttributeError):
        result.constructed = False


def test_edge_is_immutable():
    edge = TransitiveEdge("A", "B")

    with pytest.raises(AttributeError):
        edge.parent = "X"


def test_input_is_not_modified():
    child = Dependency("B")
    parent = Dependency("A", (child,))
    original = (parent, child)

    construct_transitive_edges(original)

    assert original == (parent, child)


def test_result_type():
    result = construct_transitive_edges(())

    assert isinstance(result, TransitiveEdgeConstructionResult)


def test_edge_type():
    child = Dependency("B")
    parent = Dependency("A", (child,))

    result = construct_transitive_edges((parent, child))

    assert isinstance(result.edges[0], TransitiveEdge)


def test_child_attribute_is_supported():
    class Node:
        def __init__(self, name, children=()):
            self.name = name
            self.children = children

    b = Node("B")
    a = Node("A", (b,))

    result = construct_transitive_edges((a, b))

    assert result.edges == (
        TransitiveEdge("A", "B"),
    )


def test_transitive_dependencies_attribute_is_supported():
    class Node:
        def __init__(self, name, transitive_dependencies=()):
            self.name = name
            self.transitive_dependencies = transitive_dependencies

    b = Node("B")
    a = Node("A", (b,))

    result = construct_transitive_edges((a, b))

    assert result.edges == (
        TransitiveEdge("A", "B"),
    )


def test_names_are_normalized():
    b = Dependency(" B ")
    a = Dependency(" A ", (b,))

    result = construct_transitive_edges((a, b))

    assert result.edges == (
        TransitiveEdge("A", "B"),
    )
