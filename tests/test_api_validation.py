import sys
import pytest

from sentinelshield.api_validation import APIValidationInput, validate_api


def test_api_validation_passes(tmp_path):
    r = validate_api(APIValidationInput(
        str(tmp_path),
        (sys.executable, "-c", "print('api ok')"),
    ))
    assert r.passed is True
    assert r.status == "PASS"
    assert r.return_code == 0
    assert "api ok" in r.stdout


def test_api_validation_failure(tmp_path):
    r = validate_api(APIValidationInput(
        str(tmp_path),
        (sys.executable, "-c", "raise SystemExit(5)"),
    ))
    assert r.passed is False
    assert r.status == "FAIL"
    assert r.return_code == 5


def test_api_validation_timeout(tmp_path):
    r = validate_api(APIValidationInput(
        str(tmp_path),
        (sys.executable, "-c", "import time; time.sleep(2)"),
        1,
    ))
    assert r.timed_out is True
    assert r.passed is False
    assert r.status == "TIMEOUT"


def test_invalid_input():
    with pytest.raises(TypeError):
        validate_api(None)


def test_command_must_be_tuple(tmp_path):
    with pytest.raises(TypeError):
        validate_api(APIValidationInput(
            str(tmp_path), [sys.executable, "-c", "print(1)"]
        ))


def test_empty_command_rejected(tmp_path):
    with pytest.raises(TypeError):
        validate_api(APIValidationInput(str(tmp_path), ()))


def test_invalid_command_item(tmp_path):
    with pytest.raises(TypeError):
        validate_api(APIValidationInput(str(tmp_path), (sys.executable, 1)))


def test_invalid_timeout(tmp_path):
    with pytest.raises(ValueError):
        validate_api(APIValidationInput(
            str(tmp_path), (sys.executable, "-c", "print(1)"), 0
        ))


def test_bool_timeout_rejected(tmp_path):
    with pytest.raises(TypeError):
        validate_api(APIValidationInput(
            str(tmp_path), (sys.executable, "-c", "print(1)"), True
        ))


def test_missing_root(tmp_path):
    with pytest.raises(FileNotFoundError):
        validate_api(APIValidationInput(
            str(tmp_path / "missing"),
            (sys.executable, "-c", "print(1)"),
        ))
