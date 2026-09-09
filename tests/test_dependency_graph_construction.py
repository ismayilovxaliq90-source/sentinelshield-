from dataclasses import dataclass
from typing import Optional

import pytest

from sentinelshield.dependency_graph_construction import (
    DependencyGraph,
    DependencyGraphConstructionResult,
    DependencyGraphNode,
    build_dependency_graph,
    construct_dependency_graph,
)


@dataclass(frozen=True)
class Dependency:
    name: str
    version: Optional[str]
    dependency_type: str
    source: Optional[str] = None


def test_graph_is_constructed():
    result = construct_dependency_graph(
        [
            Dependency("requests", "2.32.0", "production", "dependencies"),
            Dependency("pytest", "8.3.0", "development", "devDependencies"),
        ]
    )

    assert result.constructed is True
    assert result.status == "GRAPH_CONSTRUCTED"
    assert isinstance(result.graph, DependencyGraph)
    assert len(result.graph.nodes) == 2
    assert result.graph.edges == ()


def test_nodes_are_preserved():
    result = construct_dependency_graph(
        [
            Dependency("requests", "2.32.0", "production", "dependencies"),
        ]
    )

    assert result.graph.nodes == (
        DependencyGraphNode(
            name="requests",
            version="2.32.0",
            dependency_type="production",
            source="dependencies",
        ),
    )


def test_nodes_are_sorted_deterministically():
    result = construct_dependency_graph(
        [
            Dependency("zlib", "1.0.0", "production"),
            Dependency("express", "4.19.0", "production"),
            Dependency("axios", "1.7.0", "production"),
        ]
    )

    assert [node.name for node in result.graph.nodes] == [
        "axios",
        "express",
        "zlib",
    ]


def test_duplicate_identical_dependencies_are_consolidated():
    dependency = Dependency(
        "requests",
        "2.32.0",
        "production",
        "dependencies",
    )

    result = construct_dependency_graph(
        [dependency, dependency]
    )

    assert result.constructed is True
    assert len(result.graph.nodes) == 1


def test_conflicting_duplicate_dependencies_are_rejected():
    result = construct_dependency_graph(
        [
            Dependency("requests", "2.32.0", "production"),
            Dependency("requests", "2.31.0", "production"),
        ]
    )

    assert result.constructed is False
    assert result.status == "DUPLICATE_DEPENDENCY_CONFLICT"
    assert result.graph.nodes == ()


def test_empty_inventory_constructs_empty_graph():
    result = construct_dependency_graph([])

    assert result.constructed is True
    assert result.status == "GRAPH_CONSTRUCTED"
    assert result.graph.nodes == ()
    assert result.graph.edges == ()


def test_none_inventory_is_rejected():
    result = construct_dependency_graph(None)

    assert result.constructed is False
    assert result.status == "DEPENDENCIES_IS_NONE"


def test_string_inventory_is_rejected():
    result = construct_dependency_graph("requests")

    assert result.constructed is False
    assert result.status == "UNSUPPORTED_DEPENDENCY_COLLECTION"


def test_bytes_inventory_is_rejected():
    result = construct_dependency_graph(b"requests")

    assert result.constructed is False
    assert result.status == "UNSUPPORTED_DEPENDENCY_COLLECTION"


def test_non_iterable_inventory_is_rejected():
    result = construct_dependency_graph(123)

    assert result.constructed is False
    assert result.status == "UNSUPPORTED_DEPENDENCY_COLLECTION"


def test_invalid_dependency_name_is_rejected():
    result = construct_dependency_graph(
        [Dependency("", "1.0.0", "production")]
    )

    assert result.constructed is False
    assert result.status == "INVALID_DEPENDENCY_NAME"


def test_whitespace_dependency_name_is_rejected():
    result = construct_dependency_graph(
        [Dependency("   ", "1.0.0", "production")]
    )

    assert result.constructed is False
    assert result.status == "INVALID_DEPENDENCY_NAME"


def test_invalid_dependency_version_is_rejected():
    result = construct_dependency_graph(
        [Dependency("requests", 123, "production")]
    )

    assert result.constructed is False
    assert result.status == "INVALID_DEPENDENCY_VERSION"


def test_invalid_dependency_type_is_rejected():
    result = construct_dependency_graph(
        [Dependency("requests", "2.32.0", 123)]
    )

    assert result.constructed is False
    assert result.status == "INVALID_DEPENDENCY_TYPE"


def test_invalid_dependency_source_is_rejected():
    result = construct_dependency_graph(
        [Dependency("requests", "2.32.0", "production", 123)]
    )

    assert result.constructed is False
    assert result.status == "INVALID_DEPENDENCY_SOURCE"


def test_dependency_type_is_normalized():
    result = construct_dependency_graph(
        [Dependency("requests", "2.32.0", "  PRODUCTION  ")]
    )

    assert result.constructed is True
    assert result.graph.nodes[0].dependency_type == "production"


def test_version_none_is_allowed():
    result = construct_dependency_graph(
        [Dependency("requests", None, "production")]
    )

    assert result.constructed is True
    assert result.graph.nodes[0].version is None


def test_source_none_is_allowed():
    result = construct_dependency_graph(
        [Dependency("requests", "2.32.0", "production", None)]
    )

    assert result.constructed is True
    assert result.graph.nodes[0].source is None


def test_input_collection_is_not_modified():
    dependencies = [
        Dependency("zlib", "1.0.0", "production"),
        Dependency("axios", "1.7.0", "production"),
    ]

    original = list(dependencies)

    construct_dependency_graph(dependencies)

    assert dependencies == original


def test_result_type_is_correct():
    result = construct_dependency_graph([])

    assert isinstance(
        result,
        DependencyGraphConstructionResult,
    )


def test_build_dependency_graph_alias():
    result = build_dependency_graph(
        [Dependency("requests", "2.32.0", "production")]
    )

    assert result.constructed is True
    assert result.status == "GRAPH_CONSTRUCTED"


def test_graph_is_immutable():
    result = construct_dependency_graph(
        [Dependency("requests", "2.32.0", "production")]
    )

    with pytest.raises(AttributeError):
        result.graph = DependencyGraph(nodes=(), edges=())


def test_node_is_immutable():
    result = construct_dependency_graph(
        [Dependency("requests", "2.32.0", "production")]
    )

    with pytest.raises(AttributeError):
        result.graph.nodes[0].name = "changed"


def test_only_inventory_information_is_used():
    result = construct_dependency_graph(
        [
            Dependency("requests", "2.32.0", "production", "dependencies"),
            Dependency("pytest", "8.3.0", "development", "devDependencies"),
            Dependency("react", "18.3.0", "peer", "peerDependencies"),
        ]
    )

    assert {node.name for node in result.graph.nodes} == {
        "requests",
        "pytest",
        "react",
    }
    assert result.graph.edges == ()
