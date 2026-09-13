import pytest

from sentinelshield.remediation_diff_validation import (
    RemediationDiffValidationInput,
    validate_remediation_diff,
)


def test_expected_changes_pass():
    r = validate_remediation_diff(
        RemediationDiffValidationInput(("a.py", "b.py"), ("a.py",))
    )
    assert r.status == "PASS"
    assert r.unexpected_files == ()


def test_all_expected_changes_pass():
    r = validate_remediation_diff(
        RemediationDiffValidationInput(("a.py", "b.py"), ("a.py", "b.py"))
    )
    assert r.status == "PASS"


def test_unexpected_change_fails():
    r = validate_remediation_diff(
        RemediationDiffValidationInput(("a.py",), ("a.py", "x.py"))
    )
    assert r.status == "FAIL"
    assert r.unexpected_files == ("x.py",)


def test_forbidden_change_fails():
    r = validate_remediation_diff(
        RemediationDiffValidationInput(("a.py", "x.py"), ("x.py",), ("x.py",))
    )
    assert r.status == "FAIL"
    assert r.forbidden_changes == ("x.py",)


def test_duplicate_files_are_normalized():
    r = validate_remediation_diff(
        RemediationDiffValidationInput(("b.py", "a.py", "a.py"), ("a.py",))
    )
    assert r.expected_files == ("a.py", "b.py")


def test_results_are_sorted():
    r = validate_remediation_diff(
        RemediationDiffValidationInput(("a.py",), ("z.py", "y.py"))
    )
    assert r.unexpected_files == ("y.py", "z.py")


def test_non_tuple_expected_rejected():
    with pytest.raises(TypeError):
        validate_remediation_diff(
            RemediationDiffValidationInput(["a.py"], ("a.py",))
        )


def test_non_string_changed_rejected():
    with pytest.raises(TypeError):
        validate_remediation_diff(
            RemediationDiffValidationInput(("a.py",), ("a.py", 1))
        )


def test_null_path_rejected():
    with pytest.raises(ValueError):
        validate_remediation_diff(
            RemediationDiffValidationInput(("a.py", "\x00bad"), ("a.py",))
        )


def test_invalid_input_rejected():
    with pytest.raises(TypeError):
        validate_remediation_diff(None)
