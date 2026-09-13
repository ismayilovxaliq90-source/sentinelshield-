from pathlib import Path
import sys
import pytest

sys.path.insert(0, "src")

from sentinelshield.full_regression_validation import (
    FullRegressionValidationInput,
    FullRegressionValidationResult,
    validate_full_regression,
    full_regression_validation,
)

ROOT = Path.cwd()

def test_pass():
    r = validate_full_regression(
        FullRegressionValidationInput(ROOT, (sys.executable, "-c", "pass"))
    )
    assert r.status == "PASS"
    assert r.success is True
    assert r.return_code == 0
    assert r.timed_out is False

def test_fail():
    r = validate_full_regression(
        FullRegressionValidationInput(
            ROOT, (sys.executable, "-c", "raise SystemExit(4)")
        )
    )
    assert r.status == "FAIL"
    assert r.success is False
    assert r.return_code == 4

def test_timeout():
    r = validate_full_regression(
        FullRegressionValidationInput(
            ROOT,
            (sys.executable, "-c", "import time; time.sleep(2)"),
            1,
        )
    )
    assert r.status == "TIMEOUT"
    assert r.timed_out is True
    assert r.return_code is None

def test_wrapper():
    r = full_regression_validation(
        FullRegressionValidationInput(ROOT, (sys.executable, "-c", "pass"))
    )
    assert r.status == "PASS"

def test_wrong_input():
    with pytest.raises(TypeError):
        validate_full_regression(None)

def test_bad_root():
    with pytest.raises(ValueError):
        validate_full_regression(
            FullRegressionValidationInput(Path("/no/such/root"), ("true",))
        )

def test_empty_command():
    with pytest.raises(TypeError):
        validate_full_regression(
            FullRegressionValidationInput(ROOT, ())
        )

def test_bad_command_item():
    with pytest.raises(TypeError):
        validate_full_regression(
            FullRegressionValidationInput(ROOT, ("",))
        )

def test_bad_timeout():
    with pytest.raises(ValueError):
        validate_full_regression(
            FullRegressionValidationInput(ROOT, ("true",), 0)
        )

def test_result_shape():
    r = validate_full_regression(
        FullRegressionValidationInput(
            ROOT, (sys.executable, "-c", "print('regression')")
        )
    )
    assert isinstance(r, FullRegressionValidationResult)
    assert r.command[0] == sys.executable
    assert r.stdout.strip() == "regression"
