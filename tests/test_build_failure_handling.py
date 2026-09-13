import pytest
from sentinelshield.build_failure_handling import *

def test_compiler():
    assert handle_build_failure(BuildFailureHandlingInput("FAIL","compiler error")).category=="COMPILER"
def test_dependency():
    assert handle_build_failure(BuildFailureHandlingInput("ERROR","dependency not found")).category=="DEPENDENCY"
def test_configuration():
    assert handle_build_failure(BuildFailureHandlingInput("FAIL","invalid configuration")).category=="CONFIGURATION"
def test_resource():
    assert handle_build_failure(BuildFailureHandlingInput("FAIL","out of memory")).category=="RESOURCE"
def test_permission():
    assert handle_build_failure(BuildFailureHandlingInput("FAIL","permission denied")).category=="PERMISSION"
def test_timeout():
    assert handle_build_failure(BuildFailureHandlingInput("TIMEOUT")).category=="TIMEOUT"
def test_unknown():
    assert handle_build_failure(BuildFailureHandlingInput("ERROR","unknown build failure")).category=="UNKNOWN"
def test_wrapper():
    assert build_failure_handling(BuildFailureHandlingInput("FAIL","syntax error")).category=="COMPILER"
def test_wrong_input():
    with pytest.raises(TypeError): handle_build_failure(None)
def test_bad_status():
    with pytest.raises(ValueError): handle_build_failure(BuildFailureHandlingInput(""))
def test_bad_message():
    with pytest.raises(TypeError): handle_build_failure(BuildFailureHandlingInput("FAIL",1))
def test_result():
    r=handle_build_failure(BuildFailureHandlingInput("FAIL","compiler error"))
    assert isinstance(r,BuildFailureHandlingResult)
    assert r.status=="PASS"
