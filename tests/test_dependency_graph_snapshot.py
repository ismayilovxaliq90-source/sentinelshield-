from dataclasses import FrozenInstanceError

from sentinelshield.dependency_graph_snapshot import (
    DependencyGraphSnapshot,
    create_dependency_graph_snapshot,
)


def test_snapshot_created():
    result = create_dependency_graph_snapshot(
        ["app", "requests", "urllib3"],
        [
            ("app", "requests"),
            ("requests", "urllib3"),
        ],
    )

    assert isinstance(result, DependencyGraphSnapshot)
    assert result.nodes == ("app", "requests", "urllib3")
    assert result.edges == (
        ("app", "requests"),
        ("requests", "urllib3"),
    )
    assert result.node_count == 3
    assert result.edge_count == 2
    assert result.status == "SNAPSHOT_CREATED"


def test_empty_graph():
    result = create_dependency_graph_snapshot([], [])

    assert result.nodes == ()
    assert result.edges == ()
    assert result.node_count == 0
    assert result.edge_count == 0
    assert result.status == "SNAPSHOT_CREATED"


def test_none_nodes():
    result = create_dependency_graph_snapshot(None, [])

    assert result.status == "NODES_IS_NONE"
    assert result.node_count == 0
    assert result.edge_count == 0


def test_none_edges():
    result = create_dependency_graph_snapshot(["a"], None)

    assert result.status == "EDGES_IS_NONE"
    assert result.node_count == 0
    assert result.edge_count == 0


def test_string_nodes_rejected():
    result = create_dependency_graph_snapshot("abc", [])

    assert result.status == "UNSUPPORTED_NODES_COLLECTION"


def test_string_edges_rejected():
    result = create_dependency_graph_snapshot(["a"], "ab")

    assert result.status == "UNSUPPORTED_EDGES_COLLECTION"


def test_non_iterable_nodes_rejected():
    result = create_dependency_graph_snapshot(123, [])

    assert result.status == "UNSUPPORTED_NODES_COLLECTION"


def test_non_iterable_edges_rejected():
    result = create_dependency_graph_snapshot(["a"], 123)

    assert result.status == "UNSUPPORTED_EDGES_COLLECTION"


def test_dictionary_source_target_edge():
    result = create_dependency_graph_snapshot(
        ["a", "b"],
        [{"source": "a", "target": "b"}],
    )

    assert result.status == "SNAPSHOT_CREATED"
    assert result.edges == (("a", "b"),)


def test_dictionary_parent_child_edge():
    result = create_dependency_graph_snapshot(
        ["a", "b"],
        [{"parent": "a", "child": "b"}],
    )

    assert result.status == "SNAPSHOT_CREATED"
    assert result.edges == (("a", "b"),)


def test_invalid_edge():
    result = create_dependency_graph_snapshot(
        ["a", "b"],
        [("a", "b", "c")],
    )

    assert result.status == "INVALID_EDGE"


def test_input_lists_are_not_modified():
    nodes = ["b", "a"]
    edges = [("a", "b")]

    original_nodes = list(nodes)
    original_edges = list(edges)

    create_dependency_graph_snapshot(nodes, edges)

    assert nodes == original_nodes
    assert edges == original_edges


def test_snapshot_is_immutable():
    result = create_dependency_graph_snapshot(
        ["a"],
        [],
    )

    try:
        result.status = "changed"
        assert False
    except FrozenInstanceError:
        pass


def test_snapshot_preserves_node_order():
    result = create_dependency_graph_snapshot(
        ["z", "a", "m"],
        [],
    )

    assert result.nodes == ("z", "a", "m")


def test_snapshot_preserves_edge_order():
    result = create_dependency_graph_snapshot(
        ["a", "b", "c"],
        [
            ("b", "c"),
            ("a", "b"),
        ],
    )

    assert result.edges == (
        ("b", "c"),
        ("a", "b"),
    )


def test_duplicate_nodes_are_preserved_as_snapshot_data():
    result = create_dependency_graph_snapshot(
        ["a", "a"],
        [],
    )

    assert result.status == "SNAPSHOT_CREATED"
    assert result.nodes == ("a", "a")
    assert result.node_count == 2


def test_duplicate_edges_are_preserved_as_snapshot_data():
    result = create_dependency_graph_snapshot(
        ["a", "b"],
        [
            ("a", "b"),
            ("a", "b"),
        ],
    )

    assert result.status == "SNAPSHOT_CREATED"
    assert result.edge_count == 2


def test_snapshot_is_independent_of_input_list_changes():
    nodes = ["a", "b"]
    edges = [("a", "b")]

    result = create_dependency_graph_snapshot(nodes, edges)

    nodes.append("c")
    edges.append(("b", "c"))

    assert result.nodes == ("a", "b")
    assert result.edges == (("a", "b"),)


def test_tuple_input_is_supported():
    result = create_dependency_graph_snapshot(
        ("a", "b"),
        (("a", "b"),),
    )

    assert result.status == "SNAPSHOT_CREATED"


def test_generator_input_is_supported():
    result = create_dependency_graph_snapshot(
        (node for node in ["a", "b"]),
        ((edge) for edge in [("a", "b")]),
    )

    assert result.nodes == ("a", "b")
    assert result.edges == (("a", "b"),)


def test_counts_match_snapshot():
    result = create_dependency_graph_snapshot(
        ["a", "b", "c", "d"],
        [
            ("a", "b"),
            ("b", "c"),
            ("c", "d"),
        ],
    )

    assert result.node_count == len(result.nodes)
    assert result.edge_count == len(result.edges)


def test_read_only_operation_does_not_create_files(tmp_path):
    nodes = ["a"]
    edges = []

    before = sorted(
        str(path.relative_to(tmp_path))
        for path in tmp_path.rglob("*")
    )

    create_dependency_graph_snapshot(nodes, edges)

    after = sorted(
        str(path.relative_to(tmp_path))
        for path in tmp_path.rglob("*")
    )

    assert before == after
