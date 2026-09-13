import sys
import pytest

from sentinelshield.unit_test_execution import (
    UnitTestExecutionInput,
    execute_unit_tests,
)


def test_successful_command(tmp_path):
    r = execute_unit_tests(
        UnitTestExecutionInput(
            str(tmp_path),
            (sys.executable, "-c", "print('PASS')"),
        )
    )
    assert r.passed is True
    assert r.status == "PASS"
    assert r.return_code == 0
    assert "PASS" in r.stdout


def test_failed_command(tmp_path):
    r = execute_unit_tests(
        UnitTestExecutionInput(
            str(tmp_path),
            (sys.executable, "-c", "raise SystemExit(3)"),
        )
    )
    assert r.passed is False
    assert r.status == "FAIL"
    assert r.return_code == 3


def test_timeout(tmp_path):
    r = execute_unit_tests(
        UnitTestExecutionInput(
            str(tmp_path),
            (sys.executable, "-c", "import time; time.sleep(2)"),
            1,
        )
    )
    assert r.timed_out is True
    assert r.status == "TIMEOUT"
    assert r.passed is False


def test_command_is_tuple(tmp_path):
    with pytest.raises(TypeError):
        execute_unit_tests(
            UnitTestExecutionInput(str(tmp_path), ["python", "-m", "pytest"])
        )


def test_empty_command_rejected(tmp_path):
    with pytest.raises(TypeError):
        execute_unit_tests(UnitTestExecutionInput(str(tmp_path), ()))


def test_invalid_timeout_rejected(tmp_path):
    with pytest.raises(ValueError):
        execute_unit_tests(
            UnitTestExecutionInput(
                str(tmp_path),
                (sys.executable, "-c", "print(1)"),
                0,
            )
        )


def test_bool_timeout_rejected(tmp_path):
    with pytest.raises(TypeError):
        execute_unit_tests(
            UnitTestExecutionInput(
                str(tmp_path),
                (sys.executable, "-c", "print(1)"),
                True,
            )
        )


def test_missing_root_rejected(tmp_path):
    with pytest.raises(FileNotFoundError):
        execute_unit_tests(
            UnitTestExecutionInput(str(tmp_path / "missing"))
        )


def test_invalid_input_rejected():
    with pytest.raises(TypeError):
        execute_unit_tests(None)


def test_non_string_command_argument_rejected(tmp_path):
    with pytest.raises(TypeError):
        execute_unit_tests(
            UnitTestExecutionInput(
                str(tmp_path),
                (sys.executable, 1),
            )
        )
