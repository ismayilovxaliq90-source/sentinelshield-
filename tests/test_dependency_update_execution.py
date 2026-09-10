from pathlib import Path
import sys
import time

import pytest

from sentinelshield.dependency_update_execution import (
    DependencyUpdateExecutionError,
    DependencyUpdatePolicy,
    execute_dependency_update,
    require_successful_dependency_update,
)


def test_successful_command(tmp_path: Path):
    result = execute_dependency_update(
        (
            sys.executable,
            "-c",
            "print('update-check')",
        ),
        working_directory=tmp_path,
    )

    assert result.success is True
    assert result.timed_out is False
    assert result.exit_code == 0
    assert "update-check" in result.stdout
    assert result.failure_reason is None


def test_non_zero_exit_is_failure(tmp_path: Path):
    result = execute_dependency_update(
        (
            sys.executable,
            "-c",
            "raise SystemExit(7)",
        ),
        working_directory=tmp_path,
    )

    assert result.success is False
    assert result.exit_code == 7
    assert result.failure_reason == "NON_ZERO_EXIT_CODE"


def test_timeout_is_enforced(tmp_path: Path):
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
        "echo unsafe",
        (),
        [],
        ("echo", ""),
        ("echo", "safe\x00unsafe"),
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
    [0, -1, float("inf"), float("nan"), True, "10"],
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


def test_invalid_working_directory_is_rejected(tmp_path: Path):
    missing = tmp_path / "missing"

    with pytest.raises(DependencyUpdateExecutionError):
        execute_dependency_update(
            (sys.executable, "-c", "print('x')"),
            working_directory=missing,
        )


def test_file_working_directory_is_rejected(tmp_path: Path):
    file_path = tmp_path / "file.txt"
    file_path.write_text("x", encoding="utf-8")

    with pytest.raises(DependencyUpdateExecutionError):
        execute_dependency_update(
            (sys.executable, "-c", "print('x')"),
            working_directory=file_path,
        )


def test_shell_is_not_used(tmp_path: Path):
    result = execute_dependency_update(
        (
            sys.executable,
            "-c",
            "import os; print('shell', os.environ.get('SHELL'))",
        ),
        working_directory=tmp_path,
    )

    assert result.success is True


def test_environment_is_allowlisted(tmp_path: Path):
    policy = DependencyUpdatePolicy(
        environment_names=("SAFE_VALUE",),
    )

    result = execute_dependency_update(
        (
            sys.executable,
            "-c",
            "import os; print(os.getenv('SAFE_VALUE', 'missing'))",
        ),
        working_directory=tmp_path,
        environment={
            "SAFE_VALUE": "allowed",
            "UNSAFE_VALUE": "must-not-be-forwarded",
        },
        policy=policy,
    )

    assert result.success is True
    assert "allowed" in result.stdout
    assert "must-not-be-forwarded" not in result.stdout


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


def test_require_successful_returns_result(tmp_path: Path):
    result = require_successful_dependency_update(
        (
            sys.executable,
            "-c",
            "print('ok')",
        ),
        working_directory=tmp_path,
    )

    assert result.success is True


def test_require_successful_raises_on_failure(tmp_path: Path):
    with pytest.raises(DependencyUpdateExecutionError):
        require_successful_dependency_update(
            (
                sys.executable,
                "-c",
                "raise SystemExit(3)",
            ),
            working_directory=tmp_path,
        )


def test_duration_is_recorded(tmp_path: Path):
    result = execute_dependency_update(
        (
            sys.executable,
            "-c",
            "import time; time.sleep(0.05)",
        ),
        working_directory=tmp_path,
    )

    assert result.success is True
    assert result.duration_seconds >= 0.05


def test_result_to_dict(tmp_path: Path):
    result = execute_dependency_update(
        (
            sys.executable,
            "-c",
            "print('ok')",
        ),
        working_directory=tmp_path,
    )

    data = result.to_dict()

    assert data["success"] is True
    assert data["exit_code"] == 0
    assert "working_directory" in data


def test_allowed_nonzero_exit_code_can_be_configured(tmp_path: Path):
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


def test_timeout_does_not_return_before_process_is_stopped(tmp_path: Path):
    policy = DependencyUpdatePolicy(
        timeout_seconds=0.1,
    )

    started = time.monotonic()

    result = execute_dependency_update(
        (
            sys.executable,
            "-c",
            "import time; time.sleep(5)",
        ),
        working_directory=tmp_path,
        policy=policy,
    )

    elapsed = time.monotonic() - started

    assert result.timed_out is True
    assert elapsed < 5
