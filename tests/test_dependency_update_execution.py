from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

from sentinelshield.dependency_update_execution import (
    DependencyUpdateExecutionError,
    DependencyUpdatePolicy,
    DependencyUpdateResult,
    execute_dependency_update,
    require_successful_dependency_update,
)


def test_successful_execution(tmp_path: Path) -> None:
    result = execute_dependency_update(
        [sys.executable, "-c", "print('update-ok')"],
        tmp_path,
    )

    assert result.success is True
    assert result.timed_out is False
    assert result.exit_code == 0
    assert "update-ok" in result.stdout
    assert result.failure_reason is None


def test_nonzero_exit_is_failure(tmp_path: Path) -> None:
    result = execute_dependency_update(
        [sys.executable, "-c", "import sys; sys.exit(7)"],
        tmp_path,
    )

    assert result.success is False
    assert result.exit_code == 7
    assert result.failure_reason == "NON_ZERO_EXIT_CODE"


def test_allowed_nonzero_exit_code(tmp_path: Path) -> None:
    policy = DependencyUpdatePolicy(allowed_exit_codes=(0, 7))

    result = execute_dependency_update(
        [sys.executable, "-c", "import sys; sys.exit(7)"],
        tmp_path,
        policy=policy,
    )

    assert result.success is True
    assert result.exit_code == 7


def test_timeout(tmp_path: Path) -> None:
    policy = DependencyUpdatePolicy(timeout_seconds=0.2)

    result = execute_dependency_update(
        [
            sys.executable,
            "-c",
            "import time; time.sleep(10)",
        ],
        tmp_path,
        policy=policy,
    )

    assert result.success is False
    assert result.timed_out is True
    assert result.failure_reason == "TIMEOUT"


def test_command_string_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(DependencyUpdateExecutionError):
        execute_dependency_update(
            "python -c print('x')",
            tmp_path,
        )


def test_empty_command_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(DependencyUpdateExecutionError):
        execute_dependency_update([], tmp_path)


def test_empty_argument_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(DependencyUpdateExecutionError):
        execute_dependency_update(
            [sys.executable, ""],
            tmp_path,
        )


def test_nul_in_command_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(DependencyUpdateExecutionError):
        execute_dependency_update(
            [sys.executable, "-c", "print('x')\x00"],
            tmp_path,
        )


def test_control_character_in_command_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(DependencyUpdateExecutionError):
        execute_dependency_update(
            [sys.executable, "-c", "print('x')\x01"],
            tmp_path,
        )


def test_missing_working_directory_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(DependencyUpdateExecutionError):
        execute_dependency_update(
            [sys.executable, "-c", "print('x')"],
            tmp_path / "missing",
        )


def test_file_working_directory_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "file.txt"
    target.write_text("x", encoding="utf-8")

    with pytest.raises(DependencyUpdateExecutionError):
        execute_dependency_update(
            [sys.executable, "-c", "print('x')"],
            target,
        )


def test_explicit_allowed_environment(tmp_path: Path) -> None:
    result = execute_dependency_update(
        [
            sys.executable,
            "-c",
            "import os; print(os.environ.get('CI'))",
        ],
        tmp_path,
        environment={"CI": "true"},
    )

    assert result.success is True
    assert "true" in result.stdout


def test_explicit_disallowed_environment_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(DependencyUpdateExecutionError):
        execute_dependency_update(
            [sys.executable, "-c", "print('x')"],
            tmp_path,
            environment={"SECRET_TOKEN": "secret"},
        )


def test_inherited_environment_is_filtered(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("UNSAFE_TEST_VARIABLE", "must-not-be-forwarded")

    result = execute_dependency_update(
        [
            sys.executable,
            "-c",
            (
                "import os; "
                "print(os.environ.get('UNSAFE_TEST_VARIABLE', 'ABSENT'))"
            ),
        ],
        tmp_path,
    )

    assert result.success is True
    assert "ABSENT" in result.stdout


def test_nul_environment_value_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(DependencyUpdateExecutionError):
        execute_dependency_update(
            [sys.executable, "-c", "print('x')"],
            tmp_path,
            environment={"CI": "bad\x00value"},
        )


def test_output_is_bounded(tmp_path: Path) -> None:
    policy = DependencyUpdatePolicy(max_output_bytes=32)

    result = execute_dependency_update(
        [
            sys.executable,
            "-c",
            "print('x' * 1000)",
        ],
        tmp_path,
        policy=policy,
    )

    assert result.success is True
    assert len(result.stdout.encode("utf-8")) <= 32


def test_invalid_timeout_policy() -> None:
    with pytest.raises(ValueError):
        DependencyUpdatePolicy(timeout_seconds=0)

    with pytest.raises(ValueError):
        DependencyUpdatePolicy(timeout_seconds=-1)


def test_invalid_output_policy() -> None:
    with pytest.raises(ValueError):
        DependencyUpdatePolicy(max_output_bytes=0)


def test_require_successful_execution(tmp_path: Path) -> None:
    result = require_successful_dependency_update(
        [sys.executable, "-c", "print('required-ok')"],
        tmp_path,
    )

    assert isinstance(result, DependencyUpdateResult)
    assert result.success is True


def test_require_successful_execution_raises(tmp_path: Path) -> None:
    with pytest.raises(DependencyUpdateExecutionError):
        require_successful_dependency_update(
            [sys.executable, "-c", "import sys; sys.exit(2)"],
            tmp_path,
        )


def test_result_to_dict(tmp_path: Path) -> None:
    result = execute_dependency_update(
        [sys.executable, "-c", "print('dict-ok')"],
        tmp_path,
    )

    data = result.to_dict()

    assert data["success"] is True
    assert data["exit_code"] == 0
    assert data["working_directory"] == str(tmp_path.resolve())


def test_process_finishes_without_timeout(tmp_path: Path) -> None:
    start = time.monotonic()

    result = execute_dependency_update(
        [sys.executable, "-c", "print('fast')"],
        tmp_path,
    )

    assert result.success is True
    assert result.timed_out is False
    assert time.monotonic() - start < 10
