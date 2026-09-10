from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os
import signal
import subprocess
import time
from typing import Mapping, Sequence


class ExecutionTimeoutError(ValueError):
    """Raised when timeout enforcement input is invalid."""


MIN_TIMEOUT_SECONDS = 0.1
MAX_TIMEOUT_SECONDS = 3600.0


@dataclass(frozen=True)
class TimeoutExecutionResult:
    command: tuple[str, ...]
    return_code: int | None
    timed_out: bool
    duration_seconds: float
    stdout: str
    stderr: str

    @property
    def success(self) -> bool:
        return (
            not self.timed_out
            and self.return_code == 0
        )

    def to_dict(self) -> dict:
        return {
            "command": list(self.command),
            "return_code": self.return_code,
            "timed_out": self.timed_out,
            "duration_seconds": self.duration_seconds,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "success": self.success,
        }


def validate_timeout(timeout_seconds: float) -> float:
    if isinstance(timeout_seconds, bool):
        raise ExecutionTimeoutError("timeout must be numeric")

    if not isinstance(timeout_seconds, (int, float)):
        raise ExecutionTimeoutError("timeout must be numeric")

    timeout = float(timeout_seconds)

    if timeout < MIN_TIMEOUT_SECONDS:
        raise ExecutionTimeoutError(
            f"timeout must be >= {MIN_TIMEOUT_SECONDS}"
        )

    if timeout > MAX_TIMEOUT_SECONDS:
        raise ExecutionTimeoutError(
            f"timeout must be <= {MAX_TIMEOUT_SECONDS}"
        )

    return timeout


def validate_command(command: Sequence[str]) -> tuple[str, ...]:
    if isinstance(command, (str, bytes)):
        raise ExecutionTimeoutError(
            "command must be a sequence of arguments"
        )

    if not isinstance(command, Sequence):
        raise ExecutionTimeoutError(
            "command must be a sequence"
        )

    normalized = tuple(command)

    if not normalized:
        raise ExecutionTimeoutError("command must not be empty")

    for argument in normalized:
        if not isinstance(argument, str):
            raise ExecutionTimeoutError(
                "all command arguments must be strings"
            )
        if not argument:
            raise ExecutionTimeoutError(
                "command arguments must not be empty"
            )
        if "\x00" in argument:
            raise ExecutionTimeoutError(
                "NULL character is not allowed"
            )

    return normalized


def validate_working_directory(
    working_directory: str | Path,
) -> Path:
    path = Path(working_directory)

    if not path.exists():
        raise ExecutionTimeoutError(
            f"working directory does not exist: {path}"
        )

    if not path.is_dir():
        raise ExecutionTimeoutError(
            f"working directory is not a directory: {path}"
        )

    if path.is_symlink():
        raise ExecutionTimeoutError(
            "working directory must not be a symlink"
        )

    return path.resolve()


def _terminate_process_group(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return

    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return

    try:
        process.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

        try:
            process.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            pass


def enforce_execution_timeout(
    command: Sequence[str],
    *,
    timeout_seconds: float,
    working_directory: str | Path,
    environment: Mapping[str, str] | None = None,
) -> TimeoutExecutionResult:
    normalized_command = validate_command(command)
    timeout = validate_timeout(timeout_seconds)
    cwd = validate_working_directory(working_directory)

    if environment is None:
        env = dict(os.environ)
    else:
        env = {}

        for key, value in environment.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise ExecutionTimeoutError(
                    "environment keys and values must be strings"
                )

            if "\x00" in key or "\x00" in value:
                raise ExecutionTimeoutError(
                    "NULL character is not allowed in environment"
                )

            env[key] = value

    started = time.monotonic()

    try:
        process = subprocess.Popen(
            normalized_command,
            cwd=str(cwd),
            env=env,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            close_fds=True,
            start_new_session=True,
        )
    except OSError as error:
        duration = time.monotonic() - started

        return TimeoutExecutionResult(
            command=normalized_command,
            return_code=None,
            timed_out=False,
            duration_seconds=duration,
            stdout="",
            stderr=str(error),
        )

    try:
        stdout, stderr = process.communicate(timeout=timeout)

        duration = time.monotonic() - started

        return TimeoutExecutionResult(
            command=normalized_command,
            return_code=process.returncode,
            timed_out=False,
            duration_seconds=duration,
            stdout=stdout,
            stderr=stderr,
        )

    except subprocess.TimeoutExpired as error:
        _terminate_process_group(process)

        stdout, stderr = process.communicate()

        duration = time.monotonic() - started

        stdout_text = stdout or ""
        stderr_text = stderr or ""

        timeout_message = (
            f"execution timed out after {timeout:g} seconds"
        )

        if timeout_message not in stderr_text:
            stderr_text = (
                f"{stderr_text.rstrip()}\n{timeout_message}"
            ).strip()

        return TimeoutExecutionResult(
            command=normalized_command,
            return_code=process.returncode,
            timed_out=True,
            duration_seconds=duration,
            stdout=stdout_text,
            stderr=stderr_text,
        )


def validate_timeout_result(
    result: TimeoutExecutionResult,
) -> bool:
    if not isinstance(result, TimeoutExecutionResult):
        return False

    if not result.command:
        return False

    if result.duration_seconds < 0:
        return False

    if result.timed_out:
        if result.return_code == 0:
            return False
        if "timed out" not in result.stderr.lower():
            return False

    if not result.timed_out and result.return_code is None:
        return False

    return True


__all__ = [
    "ExecutionTimeoutError",
    "MAX_TIMEOUT_SECONDS",
    "MIN_TIMEOUT_SECONDS",
    "TimeoutExecutionResult",
    "enforce_execution_timeout",
    "validate_command",
    "validate_timeout",
    "validate_timeout_result",
    "validate_working_directory",
]
