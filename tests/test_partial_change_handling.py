import pytest
from sentinelshield.partial_change_handling import *

def test_message_detects_partial():
    r=handle_partial_change(PartialChangeHandlingInput("FAIL","partial change applied"))
    assert (r.partial,r.category)==(True,"PARTIAL_CHANGE")
def test_missing_detects_partial():
    r=handle_partial_change(PartialChangeHandlingInput("FAIL","change failed",("a","b"),("a",)))
    assert r.partial and r.missing_files==("b",)
def test_unexpected():
    r=handle_partial_change(PartialChangeHandlingInput("FAIL","partial",("a",),("a","x")))
    assert r.unexpected_files==("x",)
def test_incomplete():
    assert handle_partial_change(PartialChangeHandlingInput("ERROR","incomplete update")).partial
def test_timeout():
    r=handle_partial_change(PartialChangeHandlingInput("TIMEOUT"))
    assert (r.category,r.partial)==("TIMEOUT",False)
def test_unknown():
    r=handle_partial_change(PartialChangeHandlingInput("ERROR","unrelated failure"))
    assert (r.category,r.partial)==("UNKNOWN",False)
def test_wrapper():
    assert partial_change_handling(PartialChangeHandlingInput("FAIL","interrupted")).partial
def test_wrong_input():
    with pytest.raises(TypeError): handle_partial_change(None)
def test_bad_status():
    with pytest.raises(ValueError): handle_partial_change(PartialChangeHandlingInput(""))
def test_bad_expected():
    with pytest.raises(TypeError): handle_partial_change(PartialChangeHandlingInput("FAIL","x",["a"]))
def test_bad_item():
    with pytest.raises(TypeError): handle_partial_change(PartialChangeHandlingInput("FAIL","x",(1,)))
def test_result():
    r=handle_partial_change(PartialChangeHandlingInput("FAIL","partial"))
    assert isinstance(r,PartialChangeHandlingResult)
    assert r.status=="PASS"
