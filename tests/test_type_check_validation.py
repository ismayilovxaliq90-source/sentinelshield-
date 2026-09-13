from pathlib import Path
import sys
import pytest

sys.path.insert(0,"src")

from sentinelshield.type_check_validation import (
    TypeCheckValidationInput,TypeCheckValidationResult,
    validate_type_check,type_check_validation)

def test_pass():
    r=validate_type_check(TypeCheckValidationInput(Path.cwd(),(sys.executable,"-c","pass")))
    assert r.status=="PASS" and r.success is True and r.return_code==0

def test_fail():
    r=validate_type_check(TypeCheckValidationInput(Path.cwd(),(sys.executable,"-c","raise SystemExit(2)")))
    assert r.status=="FAIL" and r.success is False and r.return_code==2

def test_timeout():
    r=validate_type_check(TypeCheckValidationInput(Path.cwd(),(sys.executable,"-c","import time;time.sleep(2)"),1))
    assert r.status=="TIMEOUT" and r.timed_out is True

def test_wrapper():
    assert type_check_validation(TypeCheckValidationInput(Path.cwd(),(sys.executable,"-c","pass"))).status=="PASS"

def test_wrong_input():
    with pytest.raises(TypeError): validate_type_check(None)

def test_bad_root():
    with pytest.raises(ValueError):
        validate_type_check(TypeCheckValidationInput(Path("/no/such/root"),("true",)))

def test_empty_command():
    with pytest.raises(TypeError): validate_type_check(TypeCheckValidationInput(Path.cwd(),()))

def test_bad_command_item():
    with pytest.raises(TypeError): validate_type_check(TypeCheckValidationInput(Path.cwd(),("",)))

def test_bad_timeout():
    with pytest.raises(ValueError): validate_type_check(TypeCheckValidationInput(Path.cwd(),("true",),0))

def test_result_shape():
    r=validate_type_check(TypeCheckValidationInput(Path.cwd(),(sys.executable,"-c","pass")))
    assert isinstance(r,TypeCheckValidationResult)
