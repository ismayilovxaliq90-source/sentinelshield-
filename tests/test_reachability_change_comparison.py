from sentinelshield.reachability_change_comparison import *
import pytest

def test_became_reachable():
    r = compare_reachability_changes(
        ReachabilityChangeComparisonInput({"A":False},{"A":True})
    )
    assert r.became_reachable == ("A",)
    assert r.status == "FAIL"

def test_became_unreachable():
    r = compare_reachability_changes(
        ReachabilityChangeComparisonInput({"A":True},{"A":False})
    )
    assert r.became_unreachable == ("A",)
    assert r.status == "PASS"

def test_unchanged():
    r = compare_reachability_changes(
        ReachabilityChangeComparisonInput({"A":True},{"A":True})
    )
    assert r.unchanged == ("A",)

def test_mixed():
    r = compare_reachability_changes(
        ReachabilityChangeComparisonInput(
            {"A":False,"B":True,"C":True},
            {"A":True,"B":False,"C":True},
        )
    )
    assert r.became_reachable == ("A",)
    assert r.became_unreachable == ("B",)
    assert r.unchanged == ("C",)
    assert r.status == "FAIL"

def test_wrapper():
    assert reachability_change_comparison(
        ReachabilityChangeComparisonInput({}, {})
    ).status == "PASS"

@pytest.mark.parametrize("x",[None,{},1,"x"])
def test_bad_input(x):
    with pytest.raises(TypeError):
        compare_reachability_changes(x)

def test_bad_mapping():
    with pytest.raises(TypeError):
        compare_reachability_changes(
            ReachabilityChangeComparisonInput([], {})
        )

def test_non_bool_rejected():
    with pytest.raises(TypeError):
        compare_reachability_changes(
            ReachabilityChangeComparisonInput({"A":1}, {})
        )

def test_empty():
    r = compare_reachability_changes(
        ReachabilityChangeComparisonInput({}, {})
    )
    assert r.became_reachable == ()
    assert r.became_unreachable == ()
    assert r.unchanged == ()

def test_sorted():
    r = compare_reachability_changes(
        ReachabilityChangeComparisonInput(
            {"Z":False,"A":False},
            {"Z":True,"A":True},
        )
    )
    assert r.became_reachable == ("A","Z")
