from sentinelshield.sbom_regeneration import *
import pytest

def test_regenerates():
    r = regenerate_sbom(
        SBOMRegenerationInput({"z":"2.0","a":"1.0"})
    )
    assert r.packages == (("a","1.0"),("z","2.0"))
    assert r.package_count == 2
    assert r.regenerated is True
    assert r.status == "PASS"

def test_empty():
    r = regenerate_sbom(SBOMRegenerationInput({}))
    assert r.packages == ()
    assert r.package_count == 0
    assert r.regenerated is True
    assert r.status == "PASS"

def test_wrapper():
    assert sbom_regeneration(
        SBOMRegenerationInput({})
    ).status == "PASS"

@pytest.mark.parametrize("x",[None,{},1,"x"])
def test_bad_input(x):
    with pytest.raises(TypeError):
        regenerate_sbom(x)

def test_bad_mapping():
    with pytest.raises(TypeError):
        regenerate_sbom(SBOMRegenerationInput([]))

def test_empty_name():
    with pytest.raises(TypeError):
        regenerate_sbom(SBOMRegenerationInput({"":"1"}))

def test_empty_version():
    with pytest.raises(TypeError):
        regenerate_sbom(SBOMRegenerationInput({"pkg":""}))

def test_non_string_name():
    with pytest.raises(TypeError):
        regenerate_sbom(SBOMRegenerationInput({1:"1"}))

def test_non_string_version():
    with pytest.raises(TypeError):
        regenerate_sbom(SBOMRegenerationInput({"pkg":1}))

def test_deterministic_order():
    r = regenerate_sbom(
        SBOMRegenerationInput({"b":"2","c":"3","a":"1"})
    )
    assert r.packages == (("a","1"),("b","2"),("c","3"))
