from sentinelshield.dependency_resolution_failure_handling import (
    DependencyResolutionFailureHandlingInput,
    DependencyResolutionFailureHandlingResult,
    handle_dependency_resolution_failure,
    dependency_resolution_failure_handling,
)
import pytest

def test_missing():
    r=handle_dependency_resolution_failure(DependencyResolutionFailureHandlingInput("FAIL","package not found","x"))
    assert (r.category,r.recoverable)==("MISSING",True)

def test_conflict():
    r=handle_dependency_resolution_failure(DependencyResolutionFailureHandlingInput("ERROR","dependency conflict","x"))
    assert r.category=="CONFLICT"

def test_version():
    r=handle_dependency_resolution_failure(DependencyResolutionFailureHandlingInput("FAIL","requires version >=2","x"))
    assert r.category=="VERSION"

def test_lockfile():
    r=handle_dependency_resolution_failure(DependencyResolutionFailureHandlingInput("FAIL","lockfile corrupted","x"))
    assert r.category=="LOCKFILE"

def test_timeout():
    r=handle_dependency_resolution_failure(DependencyResolutionFailureHandlingInput("TIMEOUT",""))
    assert (r.category,r.recoverable)==("TIMEOUT",False)

def test_unknown():
    r=handle_dependency_resolution_failure(DependencyResolutionFailureHandlingInput("ERROR","unexpected problem"))
    assert r.category=="UNKNOWN"

def test_wrapper():
    assert dependency_resolution_failure_handling(DependencyResolutionFailureHandlingInput("FAIL","missing package")).category=="MISSING"

def test_wrong_input():
    with pytest.raises(TypeError): handle_dependency_resolution_failure(None)

def test_bad_status():
    with pytest.raises(ValueError): handle_dependency_resolution_failure(DependencyResolutionFailureHandlingInput("","x"))

def test_bad_message():
    with pytest.raises(TypeError): handle_dependency_resolution_failure(DependencyResolutionFailureHandlingInput("FAIL",1))

def test_result_shape():
    r=handle_dependency_resolution_failure(DependencyResolutionFailureHandlingInput("FAIL","missing"))
    assert isinstance(r,DependencyResolutionFailureHandlingResult)
    assert set(r.__dataclass_fields__) == {"category","recoverable","package","status"}
