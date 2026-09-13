import pytest
from sentinelshield.runtime_failure_handling import *

def test_startup():
    assert handle_runtime_failure(RuntimeFailureHandlingInput("FAIL","application startup failed")).category=="STARTUP"
def test_crash():
    assert handle_runtime_failure(RuntimeFailureHandlingInput("ERROR","process crash")).category=="CRASH"
def test_exception():
    assert handle_runtime_failure(RuntimeFailureHandlingInput("ERROR","unhandled exception")).category=="EXCEPTION"
def test_resource():
    assert handle_runtime_failure(RuntimeFailureHandlingInput("FAIL","out of memory")).category=="RESOURCE"
def test_permission():
    assert handle_runtime_failure(RuntimeFailureHandlingInput("ERROR","permission denied")).category=="PERMISSION"
def test_network():
    assert handle_runtime_failure(RuntimeFailureHandlingInput("FAIL","connection refused")).category=="NETWORK"
def test_timeout():
    assert handle_runtime_failure(RuntimeFailureHandlingInput("TIMEOUT")).category=="TIMEOUT"
def test_unknown():
    assert handle_runtime_failure(RuntimeFailureHandlingInput("ERROR","unknown runtime failure")).category=="UNKNOWN"
def test_wrapper():
    assert runtime_failure_handling(RuntimeFailureHandlingInput("FAIL","process crash")).category=="CRASH"
def test_wrong_input():
    with pytest.raises(TypeError): handle_runtime_failure(None)
def test_bad_status():
    with pytest.raises(ValueError): handle_runtime_failure(RuntimeFailureHandlingInput(""))
def test_bad_message():
    with pytest.raises(TypeError): handle_runtime_failure(RuntimeFailureHandlingInput("FAIL",1))
def test_result():
    r=handle_runtime_failure(RuntimeFailureHandlingInput("FAIL","runtime crash"))
    assert isinstance(r,RuntimeFailureHandlingResult)
    assert r.status=="PASS"
