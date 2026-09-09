from dataclasses import dataclass
from typing import Optional

from sentinelshield.direct_edge_construction import (
    DirectDependencyEdge,
    DirectEdgeConstructionResult,
    build_direct_edges,
    construct_direct_edges,
)


@dataclass(frozen=True)
class Dependency:
    name: str
    version: Optional[str] = None
    dependency_type: str = "production"
    source: Optional[str] = None
    parent: Optional[str] = None


def test_direct_edge_is_constructed():
    result = construct_direct_edges(
        [
            Dependency(
                name="requests",
                version="2.32.0",
                parent="application",
            )
        ]
    )

    assert result.constructed is True
    assert result.status == "DIRECT_EDGES_CONSTRUCTED"
    assert result.edges == (
        DirectDependencyEdge(
            parent="application",
            child="requests",
        ),
    )


def test_multiple_direct_edges_are_constructed():
    result = construct_direct_edges(
        [
            Dependency("requests", parent="application"),
            Dependency("urllib3", parent="application"),
            Dependency("certifi", parent="application"),
        ]
    )

    assert result.edges == (
        DirectDependencyEdge("application", "certifi"),
        DirectDependencyEdge("application", "requests"),
        DirectDependencyEdge("application", "urllib3"),
    )


def test_dependency_without_parent_creates_no_edge():
    result = construct_direct_edges(
        [
            Dependency("requests"),
        ]
    )

    assert result.constructed is True
    assert result.edges == ()


def test_duplicate_edges_are_consolidated():
    dependency = Dependency(
        "requests",
        parent="application",
    )

    result = construct_direct_edges(
        [dependency, dependency]
    )

    assert result.edges == (
        DirectDependencyEdge(
            parent="application",
            child="requests",
        ),
    )


def test_edges_are_sorted_deterministically():
    result = construct_direct_edges(
        [
            Dependency("zlib", parent="app"),
            Dependency("axios", parent="app"),
            Dependency("express", parent="app"),
        ]
    )

    assert [edge.child for edge in result.edges] == [
        "axios",
        "express",
        "zlib",
    ]


def test_none_is_rejected():
    result = construct_direct_edges(None)

    assert result.constructed is False
    assert result.status == "DEPENDENCIES_IS_NONE"
    assert result.edges == ()


def test_string_is_rejected():
    result = construct_direct_edges("requests")

    assert result.constructed is False
    assert result.status == "UNSUPPORTED_DEPENDENCY_COLLECTION"


def test_bytes_is_rejected():
    result = construct_direct_edges(b"requests")

    assert result.constructed is False
    assert result.status == "UNSUPPORTED_DEPENDENCY_COLLECTION"


def test_non_iterable_is_rejected():
    result = construct_direct_edges(123)

    assert result.constructed is False
    assert result.status == "UNSUPPORTED_DEPENDENCY_COLLECTION"


def test_invalid_dependency_name_is_rejected():
    result = construct_direct_edges(
        [Dependency("")]
    )

    assert result.constructed is False
    assert result.status == "INVALID_DEPENDENCY_NAME"


def test_whitespace_dependency_name_is_rejected():
    result = construct_direct_edges(
        [Dependency("   ")]
    )

    assert result.constructed is False
    assert result.status == "INVALID_DEPENDENCY_NAME"


def test_invalid_parent_is_rejected():
    result = construct_direct_edges(
        [
            Dependency(
                "requests",
                parent="   ",
            )
        ]
    )

    assert result.constructed is False
    assert result.status == "INVALID_PARENT_NAME"


def test_self_dependency_is_rejected():
    result = construct_direct_edges(
        [
            Dependency(
                "requests",
                parent="requests",
            )
        ]
    )

    assert result.constructed is False
    assert result.status == "SELF_DEPENDENCY"


def test_parent_name_is_trimmed():
    result = construct_direct_edges(
        [
            Dependency(
                "requests",
                parent="  application  ",
            )
        ]
    )

    assert result.edges == (
        DirectDependencyEdge(
            parent="application",
            child="requests",
        ),
    )


def test_input_is_not_modified():
    dependencies = [
        Dependency("requests", parent="application"),
        Dependency("urllib3", parent="application"),
    ]

    original = list(dependencies)

    construct_direct_edges(dependencies)

    assert dependencies == original


def test_result_type():
    result = construct_direct_edges([])

    assert isinstance(
        result,
        DirectEdgeConstructionResult,
    )


def test_edge_type():
    result = construct_direct_edges(
        [
            Dependency(
                "requests",
                parent="application",
            )
        ]
    )

    assert isinstance(
        result.edges[0],
        DirectDependencyEdge,
    )


def test_empty_inventory_is_valid():
    result = construct_direct_edges([])

    assert result.constructed is True
    assert result.status == "DIRECT_EDGES_CONSTRUCTED"
    assert result.edges == ()


def test_build_alias():
    result = build_direct_edges(
        [
            Dependency(
                "requests",
                parent="application",
            )
        ]
    )

    assert result.constructed is True
    assert result.edges == (
        DirectDependencyEdge(
            "application",
            "requests",
        ),
    )


def test_edge_is_immutable():
    result = construct_direct_edges(
        [
            Dependency(
                "requests",
                parent="application",
            )
        ]
    )

    try:
        result.edges[0].parent = "changed"
    except AttributeError:
        pass
    else:
        raise AssertionError("Edge must be immutable")


def test_result_is_immutable():
    result = construct_direct_edges([])

    try:
        result.constructed = False
    except AttributeError:
        pass
    else:
        raise AssertionError("Result must be immutable")
