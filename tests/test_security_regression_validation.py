from pathlib import Path
import sys
import pytest

sys.path.insert(0, "src")

from sentinelshield.security_regression_validation import (
    SecurityRegressionValidationInput,
    SecurityRegressionValidationResult,
    validate_security_regression,
    security_regression_validation,
)

ROOT = Path.cwd()

def test_pass():
    r = validate_security_regression(
        SecurityRegressionValidationInput(ROOT, (sys.executable, "-c", "pass"))
    )
    assert r.status == "PASS"
    assert r.success is True
    assert r.return_code == 0
    assert r.timed_out is False

def test_fail():
    r = validate_security_regression(
        SecurityRegressionValidationInput(
            ROOT, (sys.executable, "-c", "raise SystemExit(3)")
        )
    )
    assert r.status == "FAIL"
    assert r.success is False
    assert r.return_code == 3

def test_timeout():
    r = validate_security_regression(
        SecurityRegressionValidationInput(
            ROOT,
            (sys.executable, "-c", "import time; time.sleep(2)"),
            1,
        )
    )
    assert r.status == "TIMEOUT"
    assert r.timed_out is True
    assert r.return_code is None

def test_wrapper():
    r = security_regression_validation(
        SecurityRegressionValidationInput(ROOT, (sys.executable, "-c", "pass"))
    )
    assert r.status == "PASS"

def test_wrong_input():
    with pytest.raises(TypeError):
        validate_security_regression(None)

def test_bad_root():
    with pytest.raises(ValueError):
        validate_security_regression(
            SecurityRegressionValidationInput(Path("/no/such/root"), ("true",))
        )

def test_empty_command():
    with pytest.raises(TypeError):
        validate_security_regression(
            SecurityRegressionValidationInput(ROOT, ())
        )

def test_bad_command_item():
    with pytest.raises(TypeError):
        validate_security_regression(
            SecurityRegressionValidationInput(ROOT, ("",))
        )

def test_bad_timeout():
    with pytest.raises(ValueError):
        validate_security_regression(
            SecurityRegressionValidationInput(ROOT, ("true",), 0)
        )

def test_result_shape():
    r = validate_security_regression(
        SecurityRegressionValidationInput(
            ROOT, (sys.executable, "-c", "print('security')")
        )
    )
    assert isinstance(r, SecurityRegressionValidationResult)
    assert r.command[0] == sys.executable
    assert r.stdout.strip() == "security"
