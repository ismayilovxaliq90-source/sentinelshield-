from pathlib import Path
import sys

import pytest

from sentinelshield.execution_timeout_enforcement import (
    ExecutionTimeoutError,
    MAX_TIMEOUT_SECONDS,
    MIN_TIMEOUT_SECONDS,
    TimeoutExecutionResult,
    enforce_execution_timeout,
    validate_command,
    validate_timeout,
    validate_timeout_result,
)


def test_timeout_accepts_valid_value():
    assert validate_timeout(5) == 5.0


@pytest.mark.parametrize(
    "value",
    [
        0,
        -1,
        MIN_TIMEOUT_SECONDS / 2,
        MAX_TIMEOUT_SECONDS + 1,
        True,
        "5",
        None,
    ],
)
def test_invalid_timeout(value):
    with pytest.raises(ExecutionTimeoutError):
        validate_timeout(value)


def test_command_rejects_string():
    with pytest.raises(ExecutionTimeoutError):
        validate_command("echo hello")


def test_command_rejects_empty():
    with pytest.raises(ExecutionTimeoutError):
        validate_command([])


def test_command_rejects_non_string_argument():
    with pytest.raises(ExecutionTimeoutError):
        validate_command(["echo", 123])


def test_command_rejects_null():
    with pytest.raises(ExecutionTimeoutError):
        validate_command(["echo", "bad\x00value"])


def test_normal_execution(tmp_path):
    result = enforce_execution_timeout(
        [sys.executable, "-c", "print('ok')"],
        timeout_seconds=5,
        working_directory=tmp_path,
    )

    assert result.timed_out is False
    assert result.return_code == 0
    assert "ok" in result.stdout
    assert result.duration_seconds >= 0
    assert result.success
    assert validate_timeout_result(result)


def test_nonzero_execution(tmp_path):
    result = enforce_execution_timeout(
        [sys.executable, "-c", "import sys; sys.exit(7)"],
        timeout_seconds=5,
        working_directory=tmp_path,
    )

    assert result.timed_out is False
    assert result.return_code == 7
    assert result.success is False
    assert validate_timeout_result(result)


def test_timeout_is_enforced(tmp_path):
    result = enforce_execution_timeout(
        [
            sys.executable,
            "-c",
            "import time; time.sleep(10)",
        ],
        timeout_seconds=0.2,
        working_directory=tmp_path,
    )

    assert result.timed_out is True
    assert result.return_code != 0
    assert result.duration_seconds >= 0.1
    assert result.duration_seconds < 5
    assert "timed out" in result.stderr.lower()
    assert validate_timeout_result(result)


def test_working_directory_must_exist(tmp_path):
    missing = tmp_path / "missing"

    with pytest.raises(ExecutionTimeoutError):
        enforce_execution_timeout(
            ["echo", "x"],
            timeout_seconds=1,
            working_directory=missing,
        )


def test_working_directory_must_be_directory(tmp_path):
    file_path = tmp_path / "file"
    file_path.write_text("x")

    with pytest.raises(ExecutionTimeoutError):
        enforce_execution_timeout(
            ["echo", "x"],
            timeout_seconds=1,
            working_directory=file_path,
        )


def test_result_serialization():
    result = TimeoutExecutionResult(
        command=("echo", "ok"),
        return_code=0,
        timed_out=False,
        duration_seconds=0.25,
        stdout="ok\n",
        stderr="",
    )

    data = result.to_dict()

    assert data["command"] == ["echo", "ok"]
    assert data["return_code"] == 0
    assert data["timed_out"] is False
    assert data["success"] is True


def test_invalid_timeout_result():
    result = TimeoutExecutionResult(
        command=("echo", "x"),
        return_code=0,
        timed_out=True,
        duration_seconds=1,
        stdout="",
        stderr="timed out after 1 seconds",
    )

    assert validate_timeout_result(result) is False
