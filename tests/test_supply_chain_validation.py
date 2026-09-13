from sentinelshield.supply_chain_validation import *
import pytest

def test_valid():
    r = validate_supply_chain(
        SupplyChainValidationInput({"pkg":"1.0"}, {"pkg":"https://repo"})
    )
    assert r.validated == ("pkg",)
    assert r.invalid == ()
    assert r.status == "PASS"

def test_missing_source():
    r = validate_supply_chain(
        SupplyChainValidationInput({"pkg":"1.0"}, {})
    )
    assert r.invalid == ("pkg",)
    assert r.status == "FAIL"

def test_missing_package():
    r = validate_supply_chain(
        SupplyChainValidationInput({}, {"pkg":"https://repo"})
    )
    assert r.invalid == ("pkg",)

def test_multiple():
    r = validate_supply_chain(
        SupplyChainValidationInput(
            {"a":"1","b":"2"},
            {"a":"repo","b":"repo"},
        )
    )
    assert r.validated == ("a","b")
    assert r.status == "PASS"

def test_wrapper():
    assert supply_chain_validation(
        SupplyChainValidationInput({}, {})
    ).status == "PASS"

@pytest.mark.parametrize("x",[None,{},1,"x"])
def test_bad_input(x):
    with pytest.raises(TypeError):
        validate_supply_chain(x)

def test_bad_packages_mapping():
    with pytest.raises(TypeError):
        validate_supply_chain(
            SupplyChainValidationInput([], {})
        )

def test_bad_sources_mapping():
    with pytest.raises(TypeError):
        validate_supply_chain(
            SupplyChainValidationInput({}, [])
        )

def test_empty_package_name():
    with pytest.raises(TypeError):
        validate_supply_chain(
            SupplyChainValidationInput({"":"1"}, {"":"repo"})
        )

def test_empty_source():
    with pytest.raises(TypeError):
        validate_supply_chain(
            SupplyChainValidationInput({"pkg":"1"}, {"pkg":""})
        )
