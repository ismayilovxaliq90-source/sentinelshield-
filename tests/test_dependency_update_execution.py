from pathlib import Path
import sys

import pytest

from sentinelshield.dependency_update_execution import (
    DependencyUpdateExecutionError,
    DependencyUpdatePolicy,
    execute_dependency_update,
    require_successful_dependency_update,
)


def test_successful_execution(tmp_path: Path):
    result = execute_dependency_update(
        (sys.executable, "-c", "print('success')"),
        working_directory=tmp_path,
    )

    assert result.success is True
    assert result.timed_out is False
    assert result.exit_code == 0
    assert "success" in result.stdout
    assert result.failure_reason is None


def test_non_zero_exit_is_failure(tmp_path: Path):
    result = execute_dependency_update(
        (sys.executable, "-c", "raise SystemExit(7)"),
        working_directory=tmp_path,
    )

    assert result.success is False
    assert result.timed_out is False
    assert result.exit_code == 7
    assert result.failure_reason == "NON_ZERO_EXIT_CODE"


def test_timeout_is_failure(tmp_path: Path):
    policy = DependencyUpdatePolicy(
        timeout_seconds=0.2,
    )

    result = execute_dependency_update(
        (
            sys.executable,
            "-c",
            "import time; time.sleep(10)",
        ),
        working_directory=tmp_path,
        policy=policy,
    )

    assert result.success is False
    assert result.timed_out is True
    assert result.failure_reason == "EXECUTION_TIMEOUT"


@pytest.mark.parametrize(
    "command",
    [
        "echo hello",
        "",
        (),
        [],
        ("echo", ""),
        ("echo", "bad\x00value"),
    ],
)
def test_invalid_command_is_rejected(tmp_path: Path, command):
    with pytest.raises(DependencyUpdateExecutionError):
        execute_dependency_update(
            command,
            working_directory=tmp_path,
        )


@pytest.mark.parametrize(
    "timeout",
    [0, -1, float("inf"), float("-inf"), float("nan"), True, "30"],
)
def test_invalid_timeout_is_rejected(tmp_path: Path, timeout):
    policy = DependencyUpdatePolicy(
        timeout_seconds=timeout,
    )

    with pytest.raises(DependencyUpdateExecutionError):
        execute_dependency_update(
            (sys.executable, "-c", "print('x')"),
            working_directory=tmp_path,
            policy=policy,
        )


def test_missing_directory_is_rejected(tmp_path: Path):
    with pytest.raises(DependencyUpdateExecutionError):
        execute_dependency_update(
            (sys.executable, "-c", "print('x')"),
            working_directory=tmp_path / "missing",
        )


def test_file_as_working_directory_is_rejected(tmp_path: Path):
    file_path = tmp_path / "file.txt"
    file_path.write_text("data", encoding="utf-8")

    with pytest.raises(DependencyUpdateExecutionError):
        execute_dependency_update(
            (sys.executable, "-c", "print('x')"),
            working_directory=file_path,
        )


def test_environment_is_allowlisted(tmp_path: Path):
    policy = DependencyUpdatePolicy(
        allowed_environment=("SAFE_VALUE",),
    )

    result = execute_dependency_update(
        (
            sys.executable,
            "-c",
            "import os; print(os.getenv('SAFE_VALUE', 'missing')); "
            "print(os.getenv('UNSAFE_VALUE', 'missing'))",
        ),
        working_directory=tmp_path,
        environment={
            "SAFE_VALUE": "allowed",
            "UNSAFE_VALUE": "blocked",
        },
        policy=policy,
    )

    assert result.success is True
    assert "allowed" in result.stdout
    assert "blocked" not in result.stdout


def test_environment_nul_is_rejected(tmp_path: Path):
    with pytest.raises(DependencyUpdateExecutionError):
        execute_dependency_update(
            (sys.executable, "-c", "print('x')"),
            working_directory=tmp_path,
            environment={"PATH": "bad\x00value"},
        )


def test_output_is_bounded(tmp_path: Path):
    policy = DependencyUpdatePolicy(
        max_output_bytes=32,
    )

    result = execute_dependency_update(
        (
            sys.executable,
            "-c",
            "print('x' * 1000)",
        ),
        working_directory=tmp_path,
        policy=policy,
    )

    assert result.success is True
    assert len(result.stdout.encode("utf-8")) <= 32


def test_allowed_nonzero_exit_code(tmp_path: Path):
    policy = DependencyUpdatePolicy(
        allowed_exit_codes=(0, 5),
    )

    result = execute_dependency_update(
        (
            sys.executable,
            "-c",
            "raise SystemExit(5)",
        ),
        working_directory=tmp_path,
        policy=policy,
    )

    assert result.success is True
    assert result.exit_code == 5


def test_require_successful_returns_result(tmp_path: Path):
    result = require_successful_dependency_update(
        (sys.executable, "-c", "print('ok')"),
        working_directory=tmp_path,
    )

    assert result.success is True


def test_require_successful_raises(tmp_path: Path):
    with pytest.raises(DependencyUpdateExecutionError):
        require_successful_dependency_update(
            (
                sys.executable,
                "-c",
                "raise SystemExit(3)",
            ),
            working_directory=tmp_path,
        )


def test_result_to_dict(tmp_path: Path):
    result = execute_dependency_update(
        (sys.executable, "-c", "print('ok')"),
        working_directory=tmp_path,
    )

    data = result.to_dict()

    assert data["success"] is True
    assert data["exit_code"] == 0
    assert data["working_directory"] == str(tmp_path.resolve())
    assert "duration_seconds" in data


def test_no_shell_metacharacter_execution(tmp_path: Path):
    result = execute_dependency_update(
        (
            sys.executable,
            "-c",
            "print('literal-safe')",
        ),
        working_directory=tmp_path,
    )

    assert result.success is True
    assert "literal-safe" in result.stdout
