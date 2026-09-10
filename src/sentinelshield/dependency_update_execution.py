from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os
import signal
import subprocess
import time
from collections.abc import Mapping, Sequence


class DependencyUpdateExecutionError(RuntimeError):
    """Raised when dependency update execution cannot be performed safely."""


@dataclass(frozen=True)
class DependencyUpdatePolicy:
    timeout_seconds: float = 300.0
    max_output_bytes: int = 1_048_576
    allowed_exit_codes: tuple[int, ...] = (0,)
    environment_names: tuple[str, ...] = (
        "PATH",
        "HOME",
        "LANG",
        "LC_ALL",
        "CI",
    )


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

    def to_dict(self) -> dict:
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
    if isinstance(command, (str, bytes)):
        raise DependencyUpdateExecutionError(
            "command must be a sequence of arguments"
        )

    try:
        values = tuple(command)
    except TypeError as error:
        raise DependencyUpdateExecutionError(
            "command must be iterable"
        ) from error

    if not values:
        raise DependencyUpdateExecutionError(
            "command must not be empty"
        )

    for index, value in enumerate(values):
        if not isinstance(value, str):
            raise DependencyUpdateExecutionError(
                f"command[{index}] must be a string"
            )

        if not value:
            raise DependencyUpdateExecutionError(
                f"command[{index}] must not be empty"
            )

        if "\x00" in value:
            raise DependencyUpdateExecutionError(
                f"command[{index}] contains NUL character"
            )

    return values


def _validate_timeout(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DependencyUpdateExecutionError(
            "timeout_seconds must be numeric"
        )

    timeout = float(value)

    if timeout <= 0:
        raise DependencyUpdateExecutionError(
            "timeout_seconds must be greater than zero"
        )

    if timeout != timeout or timeout == float("inf"):
        raise DependencyUpdateExecutionError(
            "timeout_seconds must be finite"
        )

    return timeout


def _validate_output_limit(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise DependencyUpdateExecutionError(
            "max_output_bytes must be integer"
        )

    if value <= 0:
        raise DependencyUpdateExecutionError(
            "max_output_bytes must be greater than zero"
        )

    return value


def _validate_working_directory(
    working_directory: str | os.PathLike[str],
) -> Path:
    try:
        path = Path(working_directory).expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise DependencyUpdateExecutionError(
            "working directory cannot be resolved"
        ) from error

    if not path.is_dir():
        raise DependencyUpdateExecutionError(
            "working directory must be a directory"
        )

    return path


def _safe_environment(
    environment: Mapping[str, str] | None,
    allowed_names: tuple[str, ...],
) -> dict[str, str]:
    source = os.environ if environment is None else environment

    if not isinstance(source, Mapping):
        raise DependencyUpdateExecutionError(
            "environment must be a mapping"
        )

    safe: dict[str, str] = {}

    for name in allowed_names:
        value = source.get(name)

        if value is None:
            continue

        if not isinstance(name, str) or not name:
            raise DependencyUpdateExecutionError(
                "environment variable name must be non-empty string"
            )

        if not isinstance(value, str):
            raise DependencyUpdateExecutionError(
                f"environment value for {name!r} must be string"
            )

        if "\x00" in value:
            raise DependencyUpdateExecutionError(
                f"environment value for {name!r} contains NUL"
            )

        safe[name] = value

    return safe


def _truncate_output(value: bytes, maximum: int) -> str:
    if len(value) > maximum:
        value = value[:maximum]

    return value.decode("utf-8", errors="replace")


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return

    try:
        os.killpg(process.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        try:
            process.terminate()
        except ProcessLookupError:
            return

    try:
        process.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            try:
                process.kill()
            except ProcessLookupError:
                return


def execute_dependency_update(
    command: Sequence[str],
    *,
    working_directory: str | os.PathLike[str],
    environment: Mapping[str, str] | None = None,
    policy: DependencyUpdatePolicy | None = None,
) -> DependencyUpdateResult:
    policy = policy or DependencyUpdatePolicy()

    if not isinstance(policy, DependencyUpdatePolicy):
        raise DependencyUpdateExecutionError(
            "policy must be DependencyUpdatePolicy"
        )

    command_vector = _validate_command(command)
    timeout = _validate_timeout(policy.timeout_seconds)
    output_limit = _validate_output_limit(policy.max_output_bytes)
    cwd = _validate_working_directory(working_directory)
    env = _safe_environment(
        environment,
        policy.environment_names,
    )

    started = time.monotonic()

    try:
        process = subprocess.Popen(
            command_vector,
            cwd=str(cwd),
            env=env,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            close_fds=True,
        )
    except (OSError, ValueError) as error:
        duration = time.monotonic() - started

        return DependencyUpdateResult(
            success=False,
            timed_out=False,
            exit_code=None,
            stdout="",
            stderr="",
            duration_seconds=duration,
            working_directory=str(cwd),
            failure_reason=f"EXECUTION_START_FAILED: {type(error).__name__}",
        )

    timed_out = False

    try:
        stdout_bytes, stderr_bytes = process.communicate(
            timeout=timeout
        )
    except subprocess.TimeoutExpired as error:
        timed_out = True

        _terminate_process_group(process)

        stdout_bytes, stderr_bytes = process.communicate()

        stdout_text = _truncate_output(
            stdout_bytes or error.stdout or b"",
            output_limit,
        )
        stderr_text = _truncate_output(
            stderr_bytes or error.stderr or b"",
            output_limit,
        )

        duration = time.monotonic() - started

        return DependencyUpdateResult(
            success=False,
            timed_out=True,
            exit_code=process.returncode,
            stdout=stdout_text,
            stderr=stderr_text,
            duration_seconds=duration,
            working_directory=str(cwd),
            failure_reason="EXECUTION_TIMEOUT",
        )

    duration = time.monotonic() - started

    stdout_text = _truncate_output(
        stdout_bytes,
        output_limit,
    )
    stderr_text = _truncate_output(
        stderr_bytes,
        output_limit,
    )

    success = process.returncode in policy.allowed_exit_codes

    return DependencyUpdateResult(
        success=success,
        timed_out=timed_out,
        exit_code=process.returncode,
        stdout=stdout_text,
        stderr=stderr_text,
        duration_seconds=duration,
        working_directory=str(cwd),
        failure_reason=None if success else "NON_ZERO_EXIT_CODE",
    )


def require_successful_dependency_update(
    command: Sequence[str],
    *,
    working_directory: str | os.PathLike[str],
    environment: Mapping[str, str] | None = None,
    policy: DependencyUpdatePolicy | None = None,
) -> DependencyUpdateResult:
    result = execute_dependency_update(
        command,
        working_directory=working_directory,
        environment=environment,
        policy=policy,
    )

    if not result.success:
        raise DependencyUpdateExecutionError(
            result.failure_reason or "dependency update failed"
        )

    return result
