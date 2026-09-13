from sentinelshield.package_source_validation import *
import pytest

def test_valid():
    r = validate_package_sources(
        PackageSourceValidationInput({"a":"pypi"},{"a":"pypi"})
    )
    assert r.valid == ("a",) and r.status == "PASS"

def test_invalid():
    r = validate_package_sources(
        PackageSourceValidationInput({"a":"pypi"},{"a":"git"})
    )
    assert r.invalid == ("a",) and r.status == "FAIL"

def test_missing():
    r = validate_package_sources(
        PackageSourceValidationInput({"a":"pypi"}, {})
    )
    assert r.missing == ("a",)

def test_unexpected():
    r = validate_package_sources(
        PackageSourceValidationInput({}, {"a":"pypi"})
    )
    assert r.unexpected == ("a",)

def test_mixed():
    r = validate_package_sources(
        PackageSourceValidationInput(
            {"a":"pypi","b":"git"},
            {"a":"pypi","b":"local","c":"pypi"},
        )
    )
    assert r.valid == ("a",)
    assert r.invalid == ("b",)
    assert r.unexpected == ("c",)
    assert r.status == "FAIL"

def test_empty():
    assert validate_package_sources(
        PackageSourceValidationInput({}, {})
    ).status == "PASS"

def test_wrapper():
    assert package_source_validation(
        PackageSourceValidationInput({}, {})
    ).status == "PASS"

@pytest.mark.parametrize("x",[None,{},1,"x"])
def test_bad_input(x):
    with pytest.raises(TypeError):
        validate_package_sources(x)

def test_bad_mapping():
    with pytest.raises(TypeError):
        validate_package_sources(
            PackageSourceValidationInput([], {})
        )

def test_empty_source():
    with pytest.raises(TypeError):
        validate_package_sources(
            PackageSourceValidationInput({"a":""}, {})
        )
