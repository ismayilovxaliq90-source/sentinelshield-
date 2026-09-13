import sys
import pytest

from sentinelshield.database_compatibility_validation import (
    DatabaseCompatibilityValidationInput,
    validate_database_compatibility,
)


def test_compatible_database_passes(tmp_path):
    r = validate_database_compatibility(
        DatabaseCompatibilityValidationInput(
            str(tmp_path),
            (sys.executable, "-c", "print('compatible')"),
        )
    )
    assert r.compatible is True
    assert r.status == "PASS"
    assert r.return_code == 0


def test_incompatible_database_fails(tmp_path):
    r = validate_database_compatibility(
        DatabaseCompatibilityValidationInput(
            str(tmp_path),
            (sys.executable, "-c", "raise SystemExit(2)"),
        )
    )
    assert r.compatible is False
    assert r.status == "FAIL"
    assert r.return_code == 2


def test_timeout(tmp_path):
    r = validate_database_compatibility(
        DatabaseCompatibilityValidationInput(
            str(tmp_path),
            (sys.executable, "-c", "import time; time.sleep(2)"),
            1,
        )
    )
    assert r.timed_out is True
    assert r.compatible is False
    assert r.status == "TIMEOUT"


def test_invalid_input():
    with pytest.raises(TypeError):
        validate_database_compatibility(None)


def test_command_must_be_tuple(tmp_path):
    with pytest.raises(TypeError):
        validate_database_compatibility(
            DatabaseCompatibilityValidationInput(
                str(tmp_path), [sys.executable]
            )
        )


def test_empty_command_rejected(tmp_path):
    with pytest.raises(TypeError):
        validate_database_compatibility(
            DatabaseCompatibilityValidationInput(str(tmp_path), ())
        )


def test_invalid_command_item(tmp_path):
    with pytest.raises(TypeError):
        validate_database_compatibility(
            DatabaseCompatibilityValidationInput(
                str(tmp_path), (sys.executable, 1)
            )
        )


def test_invalid_timeout(tmp_path):
    with pytest.raises(ValueError):
        validate_database_compatibility(
            DatabaseCompatibilityValidationInput(
                str(tmp_path),
                (sys.executable, "-c", "print(1)"),
                0,
            )
        )


def test_bool_timeout_rejected(tmp_path):
    with pytest.raises(TypeError):
        validate_database_compatibility(
            DatabaseCompatibilityValidationInput(
                str(tmp_path),
                (sys.executable, "-c", "print(1)"),
                True,
            )
        )


def test_missing_project_root(tmp_path):
    with pytest.raises(FileNotFoundError):
        validate_database_compatibility(
            DatabaseCompatibilityValidationInput(
                str(tmp_path / "missing"),
                (sys.executable, "-c", "print(1)"),
            )
        )
