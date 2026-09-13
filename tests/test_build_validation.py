from pathlib import Path
import sys
import pytest

sys.path.insert(0, "src")

from sentinelshield.build_validation import (
    BuildValidationInput,
    BuildValidationResult,
    validate_build,
    build_validation,
)

def test_pass():
    r = validate_build(BuildValidationInput(Path.cwd(), (sys.executable, "-c", "print('ok')")))
    assert r.status == "PASS"
    assert r.success is True
    assert r.return_code == 0

def test_fail():
    r = validate_build(BuildValidationInput(Path.cwd(), (sys.executable, "-c", "raise SystemExit(2)")))
    assert r.status == "FAIL"
    assert r.success is False
    assert r.return_code == 2

def test_timeout():
    r = validate_build(BuildValidationInput(Path.cwd(), (sys.executable, "-c", "import time; time.sleep(2)"), 1))
    assert r.status == "TIMEOUT"
    assert r.timed_out is True

def test_wrapper():
    r = build_validation(BuildValidationInput(Path.cwd(), (sys.executable, "-c", "pass")))
    assert r.status == "PASS"

def test_wrong_input():
    with pytest.raises(TypeError):
        validate_build(None)

def test_bad_root():
    with pytest.raises(ValueError):
        validate_build(BuildValidationInput(Path("/no/such/root"), (sys.executable, "-c", "pass")))

def test_empty_command():
    with pytest.raises(TypeError):
        validate_build(BuildValidationInput(Path.cwd(), ()))

def test_bad_command_item():
    with pytest.raises(TypeError):
        validate_build(BuildValidationInput(Path.cwd(), ("",)))

def test_bad_timeout():
    with pytest.raises(ValueError):
        validate_build(BuildValidationInput(Path.cwd(), ("true",), 0))

def test_result_shape():
    r = validate_build(BuildValidationInput(Path.cwd(), (sys.executable, "-c", "pass")))
    assert isinstance(r, BuildValidationResult)
    assert r.command[0] == sys.executable
