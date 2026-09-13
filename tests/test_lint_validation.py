from pathlib import Path
import sys
import pytest

sys.path.insert(0, "src")

from sentinelshield.lint_validation import (
    LintValidationInput,
    LintValidationResult,
    validate_lint,
    lint_validation,
)

ROOT = Path.cwd()

def test_pass():
    r = validate_lint(LintValidationInput(ROOT, (sys.executable, "-c", "pass")))
    assert r.status == "PASS"
    assert r.success is True
    assert r.return_code == 0
    assert r.timed_out is False

def test_fail():
    r = validate_lint(LintValidationInput(ROOT, (sys.executable, "-c", "raise SystemExit(2)")))
    assert r.status == "FAIL"
    assert r.success is False
    assert r.return_code == 2

def test_timeout():
    r = validate_lint(LintValidationInput(ROOT, (sys.executable, "-c", "import time; time.sleep(2)"), 1))
    assert r.status == "TIMEOUT"
    assert r.timed_out is True
    assert r.return_code is None

def test_wrapper():
    assert lint_validation(LintValidationInput(ROOT, (sys.executable, "-c", "pass"))).status == "PASS"

def test_wrong_input():
    with pytest.raises(TypeError):
        validate_lint(None)

def test_bad_root():
    with pytest.raises(ValueError):
        validate_lint(LintValidationInput(Path("/no/such/root"), ("true",)))

def test_empty_command():
    with pytest.raises(TypeError):
        validate_lint(LintValidationInput(ROOT, ()))

def test_bad_command_item():
    with pytest.raises(TypeError):
        validate_lint(LintValidationInput(ROOT, ("",)))

def test_bad_timeout():
    with pytest.raises(ValueError):
        validate_lint(LintValidationInput(ROOT, ("true",), 0))

def test_result_shape():
    r = validate_lint(LintValidationInput(ROOT, (sys.executable, "-c", "print('lint')")))
    assert isinstance(r, LintValidationResult)
    assert r.command[0] == sys.executable
    assert r.stdout.strip() == "lint"
