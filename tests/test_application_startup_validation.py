import sys
import pytest

from sentinelshield.application_startup_validation import (
    ApplicationStartupValidationInput,
    validate_application_startup,
)


def test_startup_success(tmp_path):
    r = validate_application_startup(
        ApplicationStartupValidationInput(
            str(tmp_path),
            (sys.executable, "-c", "print('started')"),
        )
    )
    assert r.started is True
    assert r.status == "PASS"
    assert r.return_code == 0


def test_startup_failure(tmp_path):
    r = validate_application_startup(
        ApplicationStartupValidationInput(
            str(tmp_path),
            (sys.executable, "-c", "raise SystemExit(4)"),
        )
    )
    assert r.started is False
    assert r.status == "FAIL"
    assert r.return_code == 4


def test_startup_timeout(tmp_path):
    r = validate_application_startup(
        ApplicationStartupValidationInput(
            str(tmp_path),
            (sys.executable, "-c", "import time; time.sleep(2)"),
            1,
        )
    )
    assert r.timed_out is True
    assert r.started is False
    assert r.status == "TIMEOUT"


def test_invalid_input():
    with pytest.raises(TypeError):
        validate_application_startup(None)


def test_empty_command_rejected(tmp_path):
    with pytest.raises(TypeError):
        validate_application_startup(
            ApplicationStartupValidationInput(str(tmp_path), ())
        )


def test_invalid_command_item(tmp_path):
    with pytest.raises(TypeError):
        validate_application_startup(
            ApplicationStartupValidationInput(str(tmp_path), (sys.executable, 1))
        )


def test_invalid_timeout(tmp_path):
    with pytest.raises(ValueError):
        validate_application_startup(
            ApplicationStartupValidationInput(
                str(tmp_path),
                (sys.executable, "-c", "print(1)"),
                0,
            )
        )


def test_bool_timeout_rejected(tmp_path):
    with pytest.raises(TypeError):
        validate_application_startup(
            ApplicationStartupValidationInput(
                str(tmp_path),
                (sys.executable, "-c", "print(1)"),
                True,
            )
        )


def test_missing_root(tmp_path):
    with pytest.raises(FileNotFoundError):
        validate_application_startup(
            ApplicationStartupValidationInput(
                str(tmp_path / "missing"),
                (sys.executable, "-c", "print(1)"),
            )
        )


def test_null_root_rejected(tmp_path):
    with pytest.raises(ValueError):
        validate_application_startup(
            ApplicationStartupValidationInput(
                str(tmp_path) + "\x00bad",
                (sys.executable, "-c", "print(1)"),
            )
        )
