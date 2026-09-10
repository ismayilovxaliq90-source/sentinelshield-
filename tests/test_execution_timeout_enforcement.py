from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

from sentinelshield.execution_timeout_enforcement import (
    ExecutionTimeoutError,
    TimeoutExecutionResult,
    enforce_execution_timeout,
    execute_with_timeout,
    validate_timeout,
    validate_timeout_result,
)


def test_validate_positive_timeout():
    assert validate_timeout(1) == 1.0
    assert validate_timeout(0.5) == 0.5


@pytest.mark.parametrize("value", [0, -1, -0.5, True, False])
def test_invalid_timeout(value):
    with pytest.raises(ExecutionTimeoutError):
        validate_timeout(value)


@pytest.mark.parametrize(
    "command",
    [
        "",
        "python",
        b"python",
        [],
        [sys.executable, 123],
        [sys.executable, ""],
        [sys.executable, "\x00"],
    ],
)
def test_invalid_command(command, tmp_path: Path):
    with pytest.raises(ExecutionTimeoutError):
        execute_with_timeout(
            command,
            timeout_seconds=1,
            cwd=tmp_path,
        )


def test_relative_cwd_rejected():
    with pytest.raises(ExecutionTimeoutError):
        execute_with_timeout(
            [sys.executable, "-c", "print('ok')"],
            timeout_seconds=1,
            cwd=".",
        )


def test_missing_cwd_rejected(tmp_path: Path):
    missing = tmp_path / "missing"

    with pytest.raises(ExecutionTimeoutError):
        execute_with_timeout(
            [sys.executable, "-c", "print('ok')"],
            timeout_seconds=1,
            cwd=missing,
        )


def test_successful_execution(tmp_path: Path):
    result = execute_with_timeout(
        [sys.executable, "-c", "print('ok')"],
        timeout_seconds=3,
        cwd=tmp_path,
    )

    assert result.status == "COMPLETED"
    assert result.return_code == 0
    assert result.timed_out is False
    assert "ok" in result.stdout
    assert result.process_terminated is False
    assert validate_timeout_result(result)


def test_failed_execution(tmp_path: Path):
    result = execute_with_timeout(
        [sys.executable, "-c", "import sys; sys.exit(7)"],
        timeout_seconds=3,
        cwd=tmp_path,
    )

    assert result.status == "FAILED"
    assert result.return_code == 7
    assert result.timed_out is False
    assert validate_timeout_result(result)


def test_timeout_execution(tmp_path: Path):
    result = execute_with_timeout(
        [
            sys.executable,
            "-c",
            "import time; time.sleep(10)",
        ],
        timeout_seconds=0.25,
        cwd=tmp_path,
    )

    assert result.status == "TIMEOUT"
    assert result.timed_out is True
    assert result.process_terminated is True
    assert result.elapsed_seconds < 3
    assert validate_timeout_result(result)


def test_timeout_kills_child_process_group(tmp_path: Path):
    child = (
        "import subprocess,sys,time;"
        "subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']);"
        "time.sleep(30)"
    )

    result = execute_with_timeout(
        [sys.executable, "-c", child],
        timeout_seconds=0.25,
        cwd=tmp_path,
    )

    assert result.status == "TIMEOUT"
    assert result.timed_out is True
    assert result.process_terminated is True
    assert validate_timeout_result(result)


def test_environment_is_forwarded(tmp_path: Path):
    result = execute_with_timeout(
        [
            sys.executable,
            "-c",
            "import os; print(os.environ['SENTINEL_TEST_VALUE'])",
        ],
        timeout_seconds=2,
        cwd=tmp_path,
        env={"SENTINEL_TEST_VALUE": "safe"},
    )

    assert result.status == "COMPLETED"
    assert "safe" in result.stdout


def test_result_serialization():
    result = TimeoutExecutionResult(
        command=("python", "-c", "print(1)"),
        status="COMPLETED",
        return_code=0,
        timed_out=False,
        elapsed_seconds=0.1,
        stdout="1\n",
        stderr="",
        process_terminated=False,
    )

    data = result.to_dict()

    assert data["command"] == ["python", "-c", "print(1)"]
    assert data["status"] == "COMPLETED"
    assert data["timed_out"] is False


def test_invalid_result_rejected():
    result = TimeoutExecutionResult(
        command=("python",),
        status="TIMEOUT",
        return_code=0,
        timed_out=True,
        elapsed_seconds=1,
        stdout="",
        stderr="",
        process_terminated=True,
    )

    assert validate_timeout_result(result) is False


def test_timeout_does_not_wait_for_full_command_duration(tmp_path: Path):
    started = time.monotonic()

    result = enforce_execution_timeout(
        [sys.executable, "-c", "import time; time.sleep(10)"],
        timeout_seconds=0.2,
        cwd=tmp_path,
    )

    elapsed = time.monotonic() - started

    assert result.status == "TIMEOUT"
    assert elapsed < 3
