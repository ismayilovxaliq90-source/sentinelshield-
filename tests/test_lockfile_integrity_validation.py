from sentinelshield.lockfile_integrity_validation import *
import pytest

def test_valid():
    r = validate_lockfile_integrity(
        LockfileIntegrityValidationInput({"a":"1"},{"a":"1"})
    )
    assert r.valid == ("a",) and r.status == "PASS"

def test_invalid():
    r = validate_lockfile_integrity(
        LockfileIntegrityValidationInput({"a":"1"},{"a":"2"})
    )
    assert r.invalid == ("a",) and r.status == "FAIL"

def test_missing():
    r = validate_lockfile_integrity(
        LockfileIntegrityValidationInput({"a":"1"}, {})
    )
    assert r.missing == ("a",) and r.status == "FAIL"

def test_unexpected():
    r = validate_lockfile_integrity(
        LockfileIntegrityValidationInput({}, {"a":"1"})
    )
    assert r.unexpected == ("a",) and r.status == "FAIL"

def test_mixed():
    r = validate_lockfile_integrity(
        LockfileIntegrityValidationInput(
            {"a":"1","b":"2"},
            {"a":"1","b":"3","c":"4"},
        )
    )
    assert r.valid == ("a",)
    assert r.invalid == ("b",)
    assert r.unexpected == ("c",)
    assert r.status == "FAIL"

def test_empty():
    assert validate_lockfile_integrity(
        LockfileIntegrityValidationInput({}, {})
    ).status == "PASS"

def test_wrapper():
    assert lockfile_integrity_validation(
        LockfileIntegrityValidationInput({}, {})
    ).status == "PASS"

@pytest.mark.parametrize("x",[None,{},1,"x"])
def test_bad_input(x):
    with pytest.raises(TypeError):
        validate_lockfile_integrity(x)

def test_bad_mapping():
    with pytest.raises(TypeError):
        validate_lockfile_integrity(
            LockfileIntegrityValidationInput([], {})
        )

def test_empty_value():
    with pytest.raises(TypeError):
        validate_lockfile_integrity(
            LockfileIntegrityValidationInput({"a":""}, {})
        )
