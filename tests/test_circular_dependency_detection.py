from sentinelshield.circular_dependency_detection import (
    CircularDependencyResult,
    detect_circular_dependencies,
)


def test_no_cycle():
    result = detect_circular_dependencies(
        {
            "a": ["b"],
            "b": ["c"],
            "c": [],
        }
    )

    assert isinstance(result, CircularDependencyResult)
    assert result.checked is True
    assert result.has_cycles is False
    assert result.cycles == ()
    assert result.status == "NO_CIRCULAR_DEPENDENCIES"


def test_direct_cycle():
    result = detect_circular_dependencies(
        {
            "a": ["b"],
            "b": ["a"],
        }
    )

    assert result.has_cycles is True
    assert result.cycles == (("a", "b"),)
    assert result.status == "CIRCULAR_DEPENDENCIES_FOUND"


def test_three_node_cycle():
    result = detect_circular_dependencies(
        {
            "a": ["b"],
            "b": ["c"],
            "c": ["a"],
        }
    )

    assert result.has_cycles is True
    assert result.cycles == (("a", "b", "c"),)


def test_self_cycle():
    result = detect_circular_dependencies(
        {
            "a": ["a"],
        }
    )

    assert result.has_cycles is True
    assert result.cycles == (("a",),)


def test_multiple_cycles():
    result = detect_circular_dependencies(
        {
            "a": ["b"],
            "b": ["a"],
            "c": ["d"],
            "d": ["c"],
        }
    )

    assert result.has_cycles is True
    assert result.cycles == (
        ("a", "b"),
        ("c", "d"),
    )


def test_cycle_with_tail():
    result = detect_circular_dependencies(
        {
            "a": ["b"],
            "b": ["c"],
            "c": ["a"],
            "d": ["a"],
        }
    )

    assert result.cycles == (("a", "b", "c"),)


def test_missing_target_node_is_allowed():
    result = detect_circular_dependencies(
        {
            "a": ["b"],
        }
    )

    assert result.checked is True
    assert result.has_cycles is False


def test_none_graph():
    result = detect_circular_dependencies(None)

    assert result.checked is False
    assert result.has_cycles is False
    assert result.cycles == ()
    assert result.status == "GRAPH_IS_NONE"


def test_unsupported_graph_type():
    result = detect_circular_dependencies(["a", "b"])

    assert result.checked is False
    assert result.status == "UNSUPPORTED_GRAPH_TYPE"


def test_invalid_node_name():
    result = detect_circular_dependencies(
        {
            "": ["a"],
        }
    )

    assert result.checked is False
    assert result.status == "INVALID_NODE_NAME"


def test_whitespace_node_name():
    result = detect_circular_dependencies(
        {
            "   ": ["a"],
        }
    )

    assert result.checked is False
    assert result.status == "INVALID_NODE_NAME"


def test_invalid_child_name():
    result = detect_circular_dependencies(
        {
            "a": [""],
        }
    )

    assert result.checked is False
    assert result.status == "INVALID_CHILD_NAME"


def test_whitespace_child_name():
    result = detect_circular_dependencies(
        {
            "a": ["   "],
        }
    )

    assert result.checked is False
    assert result.status == "INVALID_CHILD_NAME"


def test_string_children_are_rejected():
    result = detect_circular_dependencies(
        {
            "a": "b",
        }
    )

    assert result.checked is False
    assert result.status == "INVALID_CHILDREN_COLLECTION"


def test_non_iterable_children_are_rejected():
    result = detect_circular_dependencies(
        {
            "a": 123,
        }
    )

    assert result.checked is False
    assert result.status == "INVALID_CHILDREN_COLLECTION"


def test_whitespace_is_normalized():
    result = detect_circular_dependencies(
        {
            " a ": [" b "],
            " b ": [" a "],
        }
    )

    assert result.has_cycles is True
    assert result.cycles == (("a", "b"),)


def test_input_graph_is_not_modified():
    graph = {
        "a": ["b"],
        "b": ["a"],
    }
    original = {
        "a": ["b"],
        "b": ["a"],
    }

    detect_circular_dependencies(graph)

    assert graph == original


def test_empty_graph():
    result = detect_circular_dependencies({})

    assert result.checked is True
    assert result.has_cycles is False
    assert result.cycles == ()
    assert result.status == "NO_CIRCULAR_DEPENDENCIES"


def test_deterministic_cycle_order():
    result = detect_circular_dependencies(
        {
            "z": ["a"],
            "a": ["b"],
            "b": ["a"],
            "x": ["y"],
            "y": ["x"],
        }
    )

    assert result.cycles == (
        ("a", "b"),
        ("x", "y"),
    )


def test_long_acyclic_chain():
    graph = {
        "a": ["b"],
        "b": ["c"],
        "c": ["d"],
        "d": ["e"],
        "e": [],
    }

    result = detect_circular_dependencies(graph)

    assert result.checked is True
    assert result.has_cycles is False


def test_cycle_detection_is_boolean_correct():
    cyclic = detect_circular_dependencies(
        {
            "a": ["b"],
            "b": ["a"],
        }
    )

    acyclic = detect_circular_dependencies(
        {
            "a": ["b"],
            "b": [],
        }
    )

    assert cyclic.has_cycles is True
    assert acyclic.has_cycles is False
