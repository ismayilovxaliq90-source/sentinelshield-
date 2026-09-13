from sentinelshield.dependency_tree_security_comparison import *
import pytest

def test_added_edge():
    r = compare_dependency_tree_security(
        DependencyTreeSecurityComparisonInput(
            {"app": ("safe",)},
            {"app": ("safe", "new")},
        )
    )
    assert r.added_edges == ("app->new",)
    assert r.status == "FAIL"

def test_removed_edge():
    r = compare_dependency_tree_security(
        DependencyTreeSecurityComparisonInput(
            {"app": ("old", "safe")},
            {"app": ("safe",)},
        )
    )
    assert r.removed_edges == ("app->old",)
    assert r.status == "PASS"

def test_changed_node():
    r = compare_dependency_tree_security(
        DependencyTreeSecurityComparisonInput(
            {"app": ("a",)},
            {"app": ("b",)},
        )
    )
    assert r.changed_nodes == ("app",)

def test_unchanged():
    r = compare_dependency_tree_security(
        DependencyTreeSecurityComparisonInput(
            {"app": ("safe",)},
            {"app": ("safe",)},
        )
    )
    assert r.added_edges == ()
    assert r.removed_edges == ()
    assert r.changed_nodes == ()
    assert r.status == "PASS"

def test_wrapper():
    assert dependency_tree_security_comparison(
        DependencyTreeSecurityComparisonInput({}, {})
    ).status == "PASS"

@pytest.mark.parametrize("x",[None,{},1,"x"])
def test_bad_input(x):
    with pytest.raises(TypeError):
        compare_dependency_tree_security(x)

def test_bad_mapping():
    with pytest.raises(TypeError):
        compare_dependency_tree_security(
            DependencyTreeSecurityComparisonInput([], {})
        )

def test_bad_dependencies():
    with pytest.raises(TypeError):
        compare_dependency_tree_security(
            DependencyTreeSecurityComparisonInput({"app":[]}, {})
        )

def test_bad_node():
    with pytest.raises(TypeError):
        compare_dependency_tree_security(
            DependencyTreeSecurityComparisonInput({"":("a",)}, {})
        )

def test_sorted():
    r = compare_dependency_tree_security(
        DependencyTreeSecurityComparisonInput(
            {},
            {"z": ("d",), "a": ("b",)},
        )
    )
    assert r.added_edges == ("a->b", "z->d")
