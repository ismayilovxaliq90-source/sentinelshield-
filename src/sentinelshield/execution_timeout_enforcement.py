from __future__ import annotations

import os
import signal
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Sequence


class ExecutionTimeoutError(ValueError):
    """Raised when timeout configuration or execution input is invalid."""


@dataclass(frozen=True)
class TimeoutExecutionResult:
    command: tuple[str, ...]
    status: str
    return_code: int | None
    timed_out: bool
    elapsed_seconds: float
    stdout: str
    stderr: str
    process_terminated: bool
    termination_signal: int | None = None
    error: str | None = None
    metadata: Mapping[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "command": list(self.command),
            "status": self.status,
            "return_code": self.return_code,
            "timed_out": self.timed_out,
            "elapsed_seconds": self.elapsed_seconds,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "process_terminated": self.process_terminated,
            "termination_signal": self.termination_signal,
            "error": self.error,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class TimeoutConfiguration:
    timeout_seconds: float

    def __post_init__(self) -> None:
        if isinstance(self.timeout_seconds, bool):
            raise ExecutionTimeoutError("timeout_seconds must be numeric")

        if not isinstance(self.timeout_seconds, (int, float)):
            raise ExecutionTimeoutError("timeout_seconds must be numeric")

        if self.timeout_seconds <= 0:
            raise ExecutionTimeoutError(
                "timeout_seconds must be greater than zero"
            )

        if self.timeout_seconds != self.timeout_seconds:
            raise ExecutionTimeoutError("timeout_seconds must be finite")


def validate_timeout(timeout_seconds: float) -> float:
    config = TimeoutConfiguration(timeout_seconds)
    return float(config.timeout_seconds)


def _validate_command(command: Sequence[str]) -> tuple[str, ...]:
    if isinstance(command, (str, bytes)):
        raise ExecutionTimeoutError(
            "command must be a sequence of arguments, not a string"
        )

    if not isinstance(command, Sequence):
        raise ExecutionTimeoutError("command must be a sequence")

    normalized = tuple(command)

    if not normalized:
        raise ExecutionTimeoutError("command must not be empty")

    for argument in normalized:
        if not isinstance(argument, str):
            raise ExecutionTimeoutError(
                "command arguments must be strings"
            )
        if not argument:
            raise ExecutionTimeoutError(
                "command arguments must not be empty"
            )
        if "\x00" in argument:
            raise ExecutionTimeoutError(
                "NULL characters are not allowed"
            )

    return normalized


def _validate_cwd(cwd: str | os.PathLike[str]) -> Path:
    path = Path(cwd)

    if not path.is_absolute():
        raise ExecutionTimeoutError("cwd must be an absolute path")

    if not path.exists():
        raise ExecutionTimeoutError("cwd does not exist")

    if not path.is_dir():
        raise ExecutionTimeoutError("cwd must be a directory")

    if path.is_symlink():
        raise ExecutionTimeoutError("cwd must not be a symlink")

    return path.resolve()


def _terminate_process_group(
    process: subprocess.Popen[str],
) -> tuple[bool, int | None]:
    if process.poll() is not None:
        return False, None

    try:
        os.killpg(process.pid, signal.SIGTERM)
        return True, signal.SIGTERM
    except ProcessLookupError:
        return False, None
    except OSError:
        try:
            process.terminate()
            return True, signal.SIGTERM
        except OSError:
            return False, None


def _kill_process_group(
    process: subprocess.Popen[str],
) -> tuple[bool, int | None]:
    if process.poll() is not None:
        return False, None

    try:
        os.killpg(process.pid, signal.SIGKILL)
        return True, signal.SIGKILL
    except ProcessLookupError:
        return False, None
    except OSError:
        try:
            process.kill()
            return True, signal.SIGKILL
        except OSError:
            return False, None


def execute_with_timeout(
    command: Sequence[str],
    *,
    timeout_seconds: float,
    cwd: str | os.PathLike[str],
    env: Mapping[str, str] | None = None,
) -> TimeoutExecutionResult:
    normalized_command = _validate_command(command)
    timeout = validate_timeout(timeout_seconds)
    working_directory = _validate_cwd(cwd)

    safe_env = None
    if env is not None:
        safe_env = {}
        for key, value in env.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise ExecutionTimeoutError(
                    "environment keys and values must be strings"
                )
            if "\x00" in key or "\x00" in value:
                raise ExecutionTimeoutError(
                    "NULL characters are not allowed in environment"
                )
            safe_env[key] = value

    started = time.monotonic()

    try:
        process = subprocess.Popen(
            normalized_command,
            cwd=str(working_directory),
            env=safe_env,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            close_fds=True,
            start_new_session=True,
        )
    except (OSError, ValueError) as error:
        elapsed = time.monotonic() - started
        return TimeoutExecutionResult(
            command=normalized_command,
            status="FAILED",
            return_code=None,
            timed_out=False,
            elapsed_seconds=elapsed,
            stdout="",
            stderr="",
            process_terminated=False,
            error=str(error),
        )

    try:
        stdout, stderr = process.communicate(timeout=timeout)
        elapsed = time.monotonic() - started

        status = "COMPLETED" if process.returncode == 0 else "FAILED"

        return TimeoutExecutionResult(
            command=normalized_command,
            status=status,
            return_code=process.returncode,
            timed_out=False,
            elapsed_seconds=elapsed,
            stdout=stdout,
            stderr=stderr,
            process_terminated=False,
        )

    except subprocess.TimeoutExpired as timeout_error:
        elapsed = time.monotonic() - started

        terminated, termination_signal = _terminate_process_group(process)

        try:
            stdout, stderr = process.communicate(timeout=1.0)
        except subprocess.TimeoutExpired:
            killed, kill_signal = _kill_process_group(process)

            if killed:
                terminated = True
                termination_signal = kill_signal

            stdout, stderr = process.communicate()

        if not stdout and timeout_error.output:
            stdout = timeout_error.output

        if not stderr and timeout_error.stderr:
            stderr = timeout_error.stderr

        return TimeoutExecutionResult(
            command=normalized_command,
            status="TIMEOUT",
            return_code=process.returncode,
            timed_out=True,
            elapsed_seconds=elapsed,
            stdout=stdout or "",
            stderr=stderr or "",
            process_terminated=terminated,
            termination_signal=termination_signal,
            error="execution timeout exceeded",
        )


def enforce_execution_timeout(
    command: Sequence[str],
    *,
    timeout_seconds: float,
    cwd: str | os.PathLike[str],
    env: Mapping[str, str] | None = None,
) -> TimeoutExecutionResult:
    return execute_with_timeout(
        command,
        timeout_seconds=timeout_seconds,
        cwd=cwd,
        env=env,
    )


def validate_timeout_result(
    result: TimeoutExecutionResult,
) -> bool:
    if not isinstance(result, TimeoutExecutionResult):
        return False

    if result.status not in {"COMPLETED", "FAILED", "TIMEOUT"}:
        return False

    if result.elapsed_seconds < 0:
        return False

    if result.timed_out and result.status != "TIMEOUT":
        return False

    if result.status == "TIMEOUT" and not result.timed_out:
        return False

    if result.timed_out and not result.process_terminated:
        return False

    if result.status == "COMPLETED" and result.return_code != 0:
        return False

    if result.status == "COMPLETED" and result.timed_out:
        return False

    if result.status == "TIMEOUT" and result.return_code == 0:
        return False

    return True


__all__ = [
    "ExecutionTimeoutError",
    "TimeoutExecutionResult",
    "TimeoutConfiguration",
    "validate_timeout",
    "execute_with_timeout",
    "enforce_execution_timeout",
    "validate_timeout_result",
]
