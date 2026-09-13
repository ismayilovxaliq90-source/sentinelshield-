from sentinelshield.severity_change_comparison import *
import pytest

def test_increased():
    r = compare_severity_changes(
        SeverityChangeComparisonInput({"CVE-1":"HIGH"},{"CVE-1":"CRITICAL"})
    )
    assert r.increased == ("CVE-1",)
    assert r.status == "FAIL"

def test_decreased():
    r = compare_severity_changes(
        SeverityChangeComparisonInput({"CVE-1":"CRITICAL"},{"CVE-1":"HIGH"})
    )
    assert r.decreased == ("CVE-1",)
    assert r.status == "PASS"

def test_unchanged():
    r = compare_severity_changes(
        SeverityChangeComparisonInput({"CVE-1":"HIGH"},{"CVE-1":"HIGH"})
    )
    assert r.unchanged == ("CVE-1",)

def test_mixed():
    r = compare_severity_changes(
        SeverityChangeComparisonInput(
            {"A":"LOW","B":"CRITICAL","C":"HIGH"},
            {"A":"HIGH","B":"HIGH","C":"HIGH"},
        )
    )
    assert r.increased == ("A",)
    assert r.decreased == ("B",)
    assert r.unchanged == ("C",)
    assert r.status == "FAIL"

def test_wrapper():
    assert severity_change_comparison(
        SeverityChangeComparisonInput({}, {})
    ).status == "PASS"

@pytest.mark.parametrize("x",[None,{},1,"x"])
def test_bad_input(x):
    with pytest.raises(TypeError):
        compare_severity_changes(x)

def test_bad_mapping():
    with pytest.raises(TypeError):
        compare_severity_changes(SeverityChangeComparisonInput([],{}))

def test_bad_id():
    with pytest.raises(TypeError):
        compare_severity_changes(
            SeverityChangeComparisonInput({"":"HIGH"}, {})
        )

def test_bad_severity():
    with pytest.raises(ValueError):
        compare_severity_changes(
            SeverityChangeComparisonInput({"CVE-1":"BAD"}, {})
        )

def test_empty():
    r = compare_severity_changes(
        SeverityChangeComparisonInput({}, {})
    )
    assert r.increased == () and r.decreased == () and r.unchanged == ()
