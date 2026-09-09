from sentinelshield.child_dependency_mapping import (
    ChildDependencyMapping,
    ChildDependencyMappingResult,
    map_child_dependencies,
)


def test_maps_children_to_parent():
    result = map_child_dependencies(
        [
            ("app", "requests"),
            ("app", "urllib3"),
            ("requests", "charset-normalizer"),
        ]
    )

    assert result.mapped is True
    assert result.status == "MAPPED"
    assert result.mappings == (
        ChildDependencyMapping(
            parent="app",
            children=("requests", "urllib3"),
        ),
        ChildDependencyMapping(
            parent="requests",
            children=("charset-normalizer",),
        ),
    )


def test_duplicate_edges_are_removed():
    result = map_child_dependencies(
        [
            ("app", "requests"),
            ("app", "requests"),
        ]
    )

    assert result.mappings == (
        ChildDependencyMapping(
            parent="app",
            children=("requests",),
        ),
    )


def test_parents_are_sorted():
    result = map_child_dependencies(
        [
            ("z", "b"),
            ("a", "c"),
            ("m", "d"),
        ]
    )

    assert [item.parent for item in result.mappings] == [
        "a",
        "m",
        "z",
    ]


def test_children_are_sorted():
    result = map_child_dependencies(
        [
            ("app", "z"),
            ("app", "a"),
            ("app", "m"),
        ]
    )

    assert result.mappings[0].children == (
        "a",
        "m",
        "z",
    )


def test_dict_edges_are_supported():
    result = map_child_dependencies(
        [
            {"parent": "app", "child": "requests"},
            {"parent": "app", "child": "urllib3"},
        ]
    )

    assert result.mapped is True
    assert result.mappings[0].children == (
        "requests",
        "urllib3",
    )


def test_object_edges_are_supported():
    class Edge:
        def __init__(self, parent, child):
            self.parent = parent
            self.child = child

    result = map_child_dependencies(
        [Edge("app", "requests")]
    )

    assert result.mapped is True
    assert result.mappings[0].parent == "app"
    assert result.mappings[0].children == ("requests",)


def test_none_is_rejected():
    result = map_child_dependencies(None)

    assert result.mapped is False
    assert result.status == "EDGES_IS_NONE"
    assert result.mappings == ()


def test_string_is_rejected():
    result = map_child_dependencies("app")

    assert result.mapped is False
    assert result.status == "UNSUPPORTED_EDGE_COLLECTION"


def test_non_iterable_is_rejected():
    result = map_child_dependencies(123)

    assert result.mapped is False
    assert result.status == "UNSUPPORTED_EDGE_COLLECTION"


def test_invalid_parent_is_rejected():
    result = map_child_dependencies(
        [(None, "requests")]
    )

    assert result.mapped is False
    assert result.status == "INVALID_PARENT"


def test_empty_parent_is_rejected():
    result = map_child_dependencies(
        [("   ", "requests")]
    )

    assert result.mapped is False
    assert result.status == "INVALID_PARENT"


def test_invalid_child_is_rejected():
    result = map_child_dependencies(
        [("app", None)]
    )

    assert result.mapped is False
    assert result.status == "INVALID_CHILD"


def test_empty_child_is_rejected():
    result = map_child_dependencies(
        [("app", "   ")]
    )

    assert result.mapped is False
    assert result.status == "INVALID_CHILD"


def test_self_dependency_is_rejected():
    result = map_child_dependencies(
        [("app", "app")]
    )

    assert result.mapped is False
    assert result.status == "SELF_DEPENDENCY"


def test_empty_edges_are_valid():
    result = map_child_dependencies([])

    assert isinstance(result, ChildDependencyMappingResult)
    assert result.mapped is True
    assert result.status == "MAPPED"
    assert result.mappings == ()


def test_whitespace_is_normalized():
    result = map_child_dependencies(
        [(" app ", " requests ")]
    )

    assert result.mappings == (
        ChildDependencyMapping(
            parent="app",
            children=("requests",),
        ),
    )


def test_input_is_not_modified():
    edges = [
        ("app", "z"),
        ("app", "a"),
    ]
    original = list(edges)

    map_child_dependencies(edges)

    assert edges == original


def test_result_is_immutable():
    result = map_child_dependencies(
        [("app", "requests")]
    )

    try:
        result.mapped = False
    except AttributeError:
        pass
    else:
        raise AssertionError("Result must be immutable")


def test_mapping_is_immutable():
    result = map_child_dependencies(
        [("app", "requests")]
    )

    try:
        result.mappings[0].parent = "changed"
    except AttributeError:
        pass
    else:
        raise AssertionError("Mapping must be immutable")


def test_result_type():
    result = map_child_dependencies(
        [("app", "requests")]
    )

    assert isinstance(
        result,
        ChildDependencyMappingResult,
    )


def test_mapping_type():
    result = map_child_dependencies(
        [("app", "requests")]
    )

    assert isinstance(
        result.mappings[0],
        ChildDependencyMapping,
    )
