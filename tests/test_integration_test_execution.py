import sys
import pytest

from sentinelshield.integration_test_execution import (
    IntegrationTestExecutionInput,
    execute_integration_tests,
)


def test_success(tmp_path):
    r = execute_integration_tests(
        IntegrationTestExecutionInput(
            str(tmp_path),
            (sys.executable, "-c", "print('integration ok')"),
        )
    )
    assert r.passed is True
    assert r.status == "PASS"
    assert r.return_code == 0


def test_failure(tmp_path):
    r = execute_integration_tests(
        IntegrationTestExecutionInput(
            str(tmp_path),
            (sys.executable, "-c", "raise SystemExit(2)"),
        )
    )
    assert r.passed is False
    assert r.status == "FAIL"
    assert r.return_code == 2


def test_timeout(tmp_path):
    r = execute_integration_tests(
        IntegrationTestExecutionInput(
            str(tmp_path),
            (sys.executable, "-c", "import time; time.sleep(2)"),
            1,
        )
    )
    assert r.timed_out is True
    assert r.status == "TIMEOUT"


def test_invalid_input():
    with pytest.raises(TypeError):
        execute_integration_tests(None)


def test_invalid_command(tmp_path):
    with pytest.raises(TypeError):
        execute_integration_tests(
            IntegrationTestExecutionInput(str(tmp_path), ())
        )


def test_invalid_command_item(tmp_path):
    with pytest.raises(TypeError):
        execute_integration_tests(
            IntegrationTestExecutionInput(
                str(tmp_path), (sys.executable, 1)
            )
        )


def test_invalid_timeout(tmp_path):
    with pytest.raises(ValueError):
        execute_integration_tests(
            IntegrationTestExecutionInput(
                str(tmp_path),
                (sys.executable, "-c", "print(1)"),
                0,
            )
        )


def test_bool_timeout_rejected(tmp_path):
    with pytest.raises(TypeError):
        execute_integration_tests(
            IntegrationTestExecutionInput(
                str(tmp_path),
                (sys.executable, "-c", "print(1)"),
                True,
            )
        )


def test_missing_root(tmp_path):
    with pytest.raises(FileNotFoundError):
        execute_integration_tests(
            IntegrationTestExecutionInput(str(tmp_path / "missing"))
        )


def test_empty_root_rejected(tmp_path):
    with pytest.raises(ValueError):
        execute_integration_tests(
            IntegrationTestExecutionInput("")
        )
