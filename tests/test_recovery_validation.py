import pytest
from sentinelshield.recovery_validation import (
    RecoveryValidationInput, RecoveryValidationResult,
    recovery_validation,
)

def test_all_present(tmp_path):
    (tmp_path / "a.txt").write_text("x")
    r = recovery_validation(RecoveryValidationInput(tmp_path, ("a.txt",)))
    assert r.status == "PASS"
    assert r.present == ("a.txt",)

def test_missing(tmp_path):
    r = recovery_validation(RecoveryValidationInput(tmp_path, ("a.txt",)))
    assert r.status == "FAIL"
    assert r.missing == ("a.txt",)

def test_directory_present(tmp_path):
    (tmp_path / "env").mkdir()
    r = recovery_validation(RecoveryValidationInput(tmp_path, ("env",)))
    assert r.status == "PASS"

def test_empty_paths(tmp_path):
    r = recovery_validation(RecoveryValidationInput(tmp_path, ()))
    assert r.status == "PASS"

def test_wrong_input():
    with pytest.raises(TypeError):
        recovery_validation(None)

def test_wrong_paths_type(tmp_path):
    with pytest.raises(TypeError):
        recovery_validation(RecoveryValidationInput(tmp_path, ["a"]))

def test_invalid_root(tmp_path):
    with pytest.raises(ValueError):
        recovery_validation(
            RecoveryValidationInput(tmp_path / "x", ())
        )

def test_empty_path(tmp_path):
    with pytest.raises(ValueError):
        recovery_validation(RecoveryValidationInput(tmp_path, ("",)))

def test_null_path(tmp_path):
    with pytest.raises(ValueError):
        recovery_validation(RecoveryValidationInput(tmp_path, ("a\0b",)))

def test_parent_path(tmp_path):
    with pytest.raises(ValueError):
        recovery_validation(RecoveryValidationInput(tmp_path, ("../a",)))

def test_absolute_path(tmp_path):
    with pytest.raises(ValueError):
        recovery_validation(
            RecoveryValidationInput(tmp_path, (str(tmp_path / "a"),))
        )

def test_result_type(tmp_path):
    r = recovery_validation(RecoveryValidationInput(tmp_path, ()))
    assert isinstance(r, RecoveryValidationResult)
