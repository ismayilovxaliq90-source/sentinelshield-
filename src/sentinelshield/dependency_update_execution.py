from __future__ import annotations

import os
import signal
import subprocess
import time
from dataclasses import dataclass
from math import isfinite
from pathlib import Path
from typing import Mapping, Sequence


class DependencyUpdateExecutionError(ValueError):
    """Raised when dependency update execution input is unsafe or invalid."""


@dataclass(frozen=True)
class DependencyUpdatePolicy:
    timeout_seconds: float = 300.0
    max_output_bytes: int = 1_048_576
    allowed_exit_codes: tuple[int, ...] = (0,)
    allowed_environment: tuple[str, ...] = (
        "PATH",
        "HOME",
        "LANG",
        "LC_ALL",
        "CI",
    )

    def __post_init__(self) -> None:
        if (
            not isinstance(self.timeout_seconds, (int, float))
            or isinstance(self.timeout_seconds, bool)
            or not isfinite(float(self.timeout_seconds))
            or self.timeout_seconds <= 0
        ):
            raise ValueError("timeout_seconds must be a finite positive number")

        if (
            not isinstance(self.max_output_bytes, int)
            or isinstance(self.max_output_bytes, bool)
            or self.max_output_bytes <= 0
        ):
            raise ValueError("max_output_bytes must be a positive integer")

        if not self.allowed_exit_codes:
            raise ValueError("allowed_exit_codes must not be empty")

        for code in self.allowed_exit_codes:
            if not isinstance(code, int) or isinstance(code, bool):
                raise ValueError("allowed_exit_codes must contain integers")

        if not self.allowed_environment:
            raise ValueError("allowed_environment must not be empty")

        for name in self.allowed_environment:
            if not isinstance(name, str) or not name:
                raise ValueError("environment names must be non-empty strings")
            if "\x00" in name:
                raise ValueError("environment names must not contain NUL")


@dataclass(frozen=True)
class DependencyUpdateResult:
    success: bool
    timed_out: bool
    exit_code: int | None
    stdout: str
    stderr: str
    duration_seconds: float
    working_directory: str
    failure_reason: str | None

    def to_dict(self) -> dict[str, object]:
        return {
            "success": self.success,
            "timed_out": self.timed_out,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration_seconds": self.duration_seconds,
            "working_directory": self.working_directory,
            "failure_reason": self.failure_reason,
        }


def _validate_command(command: Sequence[str]) -> tuple[str, ...]:
    if isinstance(command, (str, bytes, bytearray)):
        raise DependencyUpdateExecutionError(
            "command must be a sequence of arguments, not a string"
        )

    try:
        values = tuple(command)
    except TypeError as exc:
        raise DependencyUpdateExecutionError(
            "command must be a sequence of arguments"
        ) from exc

    if not values:
        raise DependencyUpdateExecutionError("command must not be empty")

    for index, argument in enumerate(values):
        if not isinstance(argument, str):
            raise DependencyUpdateExecutionError(
                f"command argument {index} must be a string"
            )

        if not argument:
            raise DependencyUpdateExecutionError(
                f"command argument {index} must not be empty"
            )

        if "\x00" in argument:
            raise DependencyUpdateExecutionError(
                f"command argument {index} contains NUL character"
            )

        if any(ord(char) < 32 and char not in "\t" for char in argument):
            raise DependencyUpdateExecutionError(
                f"command argument {index} contains a control character"
            )

    return values


def _validate_working_directory(
    working_directory: str | os.PathLike[str],
) -> Path:
    if isinstance(working_directory, (str, os.PathLike)):
        raw = os.fspath(working_directory)
    else:
        raise DependencyUpdateExecutionError(
            "working_directory must be a path"
        )

    if "\x00" in raw:
        raise DependencyUpdateExecutionError(
            "working_directory contains NUL character"
        )

    path = Path(raw)

    try:
        resolved = path.resolve(strict=True)
    except FileNotFoundError as exc:
        raise DependencyUpdateExecutionError(
            "working_directory does not exist"
        ) from exc
    except OSError as exc:
        raise DependencyUpdateExecutionError(
            "unable to resolve working_directory"
        ) from exc

    if not resolved.is_dir():
        raise DependencyUpdateExecutionError(
            "working_directory must be a directory"
        )

    return resolved


def _build_environment(
    environment: Mapping[str, str] | None,
    policy: DependencyUpdatePolicy,
) -> dict[str, str]:
    allowed = set(policy.allowed_environment)

    if environment is None:
        source = os.environ
    else:
        if not isinstance(environment, Mapping):
            raise DependencyUpdateExecutionError(
                "environment must be a mapping"
            )
        source = environment

    result: dict[str, str] = {}

    for name, value in source.items():
        if not isinstance(name, str):
            raise DependencyUpdateExecutionError(
                "environment variable names must be strings"
            )

        if name not in allowed:
            raise DependencyUpdateExecutionError(
                f"environment variable is not allowed: {name}"
            )

        if not isinstance(value, str):
            raise DependencyUpdateExecutionError(
                f"environment value must be a string: {name}"
            )

        if "\x00" in value:
            raise DependencyUpdateExecutionError(
                f"environment value contains NUL: {name}"
            )

        result[name] = value

    return result


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return

    try:
        os.killpg(process.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        return

    try:
        process.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass


def _decode_output(data: bytes, maximum: int) -> str:
    if len(data) > maximum:
        data = data[:maximum]
    return data.decode("utf-8", errors="replace")


def execute_dependency_update(
    command: Sequence[str],
    working_directory: str | os.PathLike[str],
    environment: Mapping[str, str] | None = None,
    policy: DependencyUpdatePolicy | None = None,
) -> DependencyUpdateResult:
    """
    Execute an already-authorized dependency update command.

    This function deliberately uses shell=False and does not perform
    package-manager command discovery or authorization itself.
    """

    active_policy = policy or DependencyUpdatePolicy()
    validated_command = _validate_command(command)
    cwd = _validate_working_directory(working_directory)
    env = _build_environment(environment, active_policy)

    start = time.monotonic()

    process: subprocess.Popen[bytes] | None = None

    try:
        process = subprocess.Popen(
            validated_command,
            cwd=str(cwd),
            env=env,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            close_fds=True,
        )

        try:
            stdout_data, stderr_data = process.communicate(
                timeout=active_policy.timeout_seconds
            )
            timed_out = False
        except subprocess.TimeoutExpired as exc:
            _terminate_process_group(process)
            stdout_data, stderr_data = process.communicate()
            timed_out = True

            stdout = _decode_output(
                stdout_data,
                active_policy.max_output_bytes,
            )
            stderr = _decode_output(
                stderr_data,
                active_policy.max_output_bytes,
            )

            duration = time.monotonic() - start

            return DependencyUpdateResult(
                success=False,
                timed_out=True,
                exit_code=process.returncode,
                stdout=stdout,
                stderr=stderr,
                duration_seconds=duration,
                working_directory=str(cwd),
                failure_reason="TIMEOUT",
            )

    except (OSError, ValueError) as exc:
        duration = time.monotonic() - start

        return DependencyUpdateResult(
            success=False,
            timed_out=False,
            exit_code=None if process is None else process.returncode,
            stdout="",
            stderr="",
            duration_seconds=duration,
            working_directory=str(cwd),
            failure_reason=f"EXECUTION_ERROR: {exc}",
        )

    stdout = _decode_output(
        stdout_data,
        active_policy.max_output_bytes,
    )
    stderr = _decode_output(
        stderr_data,
        active_policy.max_output_bytes,
    )

    duration = time.monotonic() - start
    exit_code = process.returncode

    if exit_code in active_policy.allowed_exit_codes:
        return DependencyUpdateResult(
            success=True,
            timed_out=timed_out,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=duration,
            working_directory=str(cwd),
            failure_reason=None,
        )

    return DependencyUpdateResult(
        success=False,
        timed_out=False,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        duration_seconds=duration,
        working_directory=str(cwd),
        failure_reason="NON_ZERO_EXIT_CODE",
    )


def require_successful_dependency_update(
    command: Sequence[str],
    working_directory: str | os.PathLike[str],
    environment: Mapping[str, str] | None = None,
    policy: DependencyUpdatePolicy | None = None,
) -> DependencyUpdateResult:
    result = execute_dependency_update(
        command=command,
        working_directory=working_directory,
        environment=environment,
        policy=policy,
    )

    if not result.success:
        raise DependencyUpdateExecutionError(
            result.failure_reason or "dependency update failed"
        )

    return result
