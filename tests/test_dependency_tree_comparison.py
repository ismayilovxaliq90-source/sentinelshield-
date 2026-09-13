import pytest

from sentinelshield.dependency_tree_comparison import (
    DependencyTreeComparisonInput,
    DependencyTreeEdge,
    compare_dependency_trees,
)


def test_identical_trees_are_unchanged():
    tree = {
        "app": {"requests", "urllib3"},
        "requests": {"urllib3"},
    }

    result = compare_dependency_trees(
        DependencyTreeComparisonInput(
            before_tree=tree,
            after_tree=tree,
        )
    )

    assert result.status == "UNCHANGED"
    assert result.has_change is False
    assert result.unchanged is True
    assert result.added_edges == ()
    assert result.removed_edges == ()


def test_added_dependency_edge_is_detected():
    result = compare_dependency_trees(
        DependencyTreeComparisonInput(
            before_tree={
                "app": {"requests"},
            },
            after_tree={
                "app": {"requests", "urllib3"},
            },
        )
    )

    assert result.status == "CHANGED"
    assert result.added_edges == (
        DependencyTreeEdge("app", "urllib3"),
    )
    assert result.removed_edges == ()


def test_removed_dependency_edge_is_detected():
    result = compare_dependency_trees(
        DependencyTreeComparisonInput(
            before_tree={
                "app": {"requests", "urllib3"},
            },
            after_tree={
                "app": {"requests"},
            },
        )
    )

    assert result.status == "CHANGED"
    assert result.removed_edges == (
        DependencyTreeEdge("app", "urllib3"),
    )
    assert result.added_edges == ()


def test_replaced_dependency_is_detected():
    result = compare_dependency_trees(
        DependencyTreeComparisonInput(
            before_tree={
                "app": {"requests"},
            },
            after_tree={
                "app": {"httpx"},
            },
        )
    )

    assert result.added_edges == (
        DependencyTreeEdge("app", "httpx"),
    )
    assert result.removed_edges == (
        DependencyTreeEdge("app", "requests"),
    )


def test_transitive_edge_change_is_detected():
    result = compare_dependency_trees(
        DependencyTreeComparisonInput(
            before_tree={
                "app": {"requests"},
                "requests": {"urllib3"},
            },
            after_tree={
                "app": {"requests"},
                "requests": {"urllib3", "certifi"},
            },
        )
    )

    assert result.added_edges == (
        DependencyTreeEdge("requests", "certifi"),
    )


def test_changed_nodes_are_deterministic():
    result = compare_dependency_trees(
        DependencyTreeComparisonInput(
            before_tree={
                "app": {"requests"},
            },
            after_tree={
                "app": {"httpx"},
            },
        )
    )

    assert result.changed_nodes == (
        "app",
        "httpx",
        "requests",
    )


def test_package_names_are_normalized():
    result = compare_dependency_trees(
        DependencyTreeComparisonInput(
            before_tree={
                "My_App": {"My_Dep"},
            },
            after_tree={
                "my-app": {"my_dep"},
            },
        )
    )

    assert result.status == "UNCHANGED"
    assert result.before_edges == (
        DependencyTreeEdge("my-app", "my-dep"),
    )


def test_duplicate_edges_are_collapsed():
    result = compare_dependency_trees(
        DependencyTreeComparisonInput(
            before_tree={
                "app": ["requests", "requests"],
            },
            after_tree={
                "app": ["requests"],
            },
        )
    )

    assert result.status == "UNCHANGED"
    assert len(result.before_edges) == 1


def test_self_dependency_is_rejected():
    with pytest.raises(
        ValueError,
        match="SELF_DEPENDENCY_EDGE_IS_NOT_ALLOWED",
    ):
        compare_dependency_trees(
            DependencyTreeComparisonInput(
                before_tree={
                    "app": {"app"},
                },
                after_tree={},
            )
        )


def test_invalid_input_is_rejected():
    with pytest.raises(
        TypeError,
        match="INPUT_MUST_BE_DEPENDENCY_TREE_COMPARISON_INPUT",
    ):
        compare_dependency_trees(None)
