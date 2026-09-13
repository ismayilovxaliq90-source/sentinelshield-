import pytest
from sentinelshield.test_failure_handling import *

def test_assertion():
    assert handle_test_failure(TestFailureHandlingInput("FAIL","assertion failed")).category=="ASSERTION"
def test_collection():
    assert handle_test_failure(TestFailureHandlingInput("ERROR","collection error")).category=="COLLECTION"
def test_import():
    assert handle_test_failure(TestFailureHandlingInput("ERROR","ModuleNotFoundError: no module named x")).category=="IMPORT"
def test_setup():
    assert handle_test_failure(TestFailureHandlingInput("FAIL","setup failed")).category=="SETUP"
def test_environment():
    assert handle_test_failure(TestFailureHandlingInput("ERROR","permission denied")).category=="ENVIRONMENT"
def test_timeout():
    assert handle_test_failure(TestFailureHandlingInput("TIMEOUT")).category=="TIMEOUT"
def test_unknown():
    assert handle_test_failure(TestFailureHandlingInput("ERROR","unknown test failure")).category=="UNKNOWN"
def test_wrapper():
    assert test_failure_handling(TestFailureHandlingInput("FAIL","assertion failed")).category=="ASSERTION"
def test_wrong_input():
    with pytest.raises(TypeError): handle_test_failure(None)
def test_bad_status():
    with pytest.raises(ValueError): handle_test_failure(TestFailureHandlingInput(""))
def test_bad_message():
    with pytest.raises(TypeError): handle_test_failure(TestFailureHandlingInput("FAIL",1))
def test_result():
    r=handle_test_failure(TestFailureHandlingInput("FAIL","assertion failed"))
    assert isinstance(r,TestFailureHandlingResult)
    assert r.status=="PASS"
