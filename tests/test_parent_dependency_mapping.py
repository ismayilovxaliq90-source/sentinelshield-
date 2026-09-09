from dataclasses import dataclass

import pytest

from sentinelshield.parent_dependency_mapping import (
    ParentDependencyMappingResult,
    build_parent_dependency_mapping,
    map_parent_dependencies,
)


@dataclass(frozen=True)
class Dependency:
    name: str
    dependencies: tuple = ()


def test_parent_mapping():
    c = Dependency("C")
    b = Dependency("B", (c,))
    a = Dependency("A", (b,))

    result = map_parent_dependencies((a, b, c))

    assert result.mapped is True
    assert result.status == "MAPPED"
    assert result.parents == {
        "A": ("B",),
        "B": ("C",),
        "C": (),
    }


def test_multiple_children():
    b = Dependency("B")
    c = Dependency("C")
    a = Dependency("A", (b, c))

    result = map_parent_dependencies((a, b, c))

    assert result.parents["A"] == ("B", "C")


def test_empty_graph():
    result = map_parent_dependencies(())

    assert result.mapped is True
    assert result.status == "MAPPED"
    assert result.parents == {}


def test_none_graph():
    result = map_parent_dependencies(None)

    assert result.mapped is False
    assert result.status == "GRAPH_IS_NONE"
    assert result.parents == {}


def test_string_graph_rejected():
    result = map_parent_dependencies("A")

    assert result.mapped is False
    assert result.status == "UNSUPPORTED_GRAPH_TYPE"


def test_bytes_graph_rejected():
    result = map_parent_dependencies(b"A")

    assert result.mapped is False
    assert result.status == "UNSUPPORTED_GRAPH_TYPE"


def test_non_iterable_graph_rejected():
    result = map_parent_dependencies(123)

    assert result.mapped is False
    assert result.status == "UNSUPPORTED_GRAPH_TYPE"


def test_invalid_parent():
    result = map_parent_dependencies([object()])

    assert result.mapped is False
    assert result.status == "INVALID_PARENT_NODE"


def test_invalid_child():
    result = map_parent_dependencies(
        [Dependency("A", (object(),))]
    )

    assert result.mapped is False
    assert result.status == "INVALID_CHILD_NODE"


def test_invalid_child_collection():
    class Node:
        name = "A"
        dependencies = 123

    result = map_parent_dependencies([Node()])

    assert result.mapped is False
    assert result.status == "INVALID_CHILD_COLLECTION"


def test_self_dependency_is_ignored():
    node = Dependency("A")

    object.__setattr__(node, "dependencies", (node,))

    result = map_parent_dependencies([node])

    assert result.mapped is True
    assert result.parents == {"A": ()}


def test_duplicate_children_are_removed():
    b = Dependency("B")
    a = Dependency("A", (b, b))

    result = map_parent_dependencies((a, b))

    assert result.parents["A"] == ("B",)


def test_names_are_trimmed():
    b = Dependency(" B ")
    a = Dependency(" A ", (b,))

    result = map_parent_dependencies((a, b))

    assert result.parents == {
        "A": ("B",),
        "B": (),
    }


def test_deterministic_parent_order():
    z = Dependency("z")
    a = Dependency("a", (z,))
    b = Dependency("b", (z,))

    result = map_parent_dependencies((z, b, a))

    assert list(result.parents) == ["a", "b", "z"]


def test_deterministic_child_order():
    z = Dependency("z")
    a = Dependency("a")
    root = Dependency("root", (z, a))

    result = map_parent_dependencies((root, z, a))

    assert result.parents["root"] == ("a", "z")


def test_result_type():
    result = map_parent_dependencies(())

    assert isinstance(result, ParentDependencyMappingResult)


def test_input_is_not_modified():
    child = Dependency("B")
    parent = Dependency("A", (child,))
    graph = [parent, child]
    original = list(graph)

    map_parent_dependencies(graph)

    assert graph == original


def test_wrapper_function():
    child = Dependency("B")
    parent = Dependency("A", (child,))

    result = build_parent_dependency_mapping(
        (parent, child)
    )

    assert result.parents == {
        "A": ("B",),
        "B": (),
    }


def test_immutability():
    result = map_parent_dependencies(())

    with pytest.raises(AttributeError):
        result.mapped = False


def test_children_attribute_supported():
    class Node:
        def __init__(self, name, children=()):
            self.name = name
            self.children = children

    b = Node("B")
    a = Node("A", (b,))

    result = map_parent_dependencies((a, b))

    assert result.parents == {
        "A": ("B",),
        "B": (),
    }
