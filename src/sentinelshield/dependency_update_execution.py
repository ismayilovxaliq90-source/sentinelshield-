from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from collections.abc import Mapping, Sequence
import math
import os
import signal
import subprocess
import time


class DependencyUpdateExecutionError(RuntimeError):
    """Unsafe or invalid dependency-update execution request."""


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


def _validate_policy(policy: DependencyUpdatePolicy) -> DependencyUpdatePolicy:
    if not isinstance(policy, DependencyUpdatePolicy):
        raise DependencyUpdateExecutionError(
            "policy must be DependencyUpdatePolicy"
        )

    timeout = policy.timeout_seconds

    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise DependencyUpdateExecutionError(
            "timeout_seconds must be numeric"
        )

    timeout = float(timeout)

    if not math.isfinite(timeout) or timeout <= 0:
        raise DependencyUpdateExecutionError(
            "timeout_seconds must be finite and greater than zero"
        )

    if (
        isinstance(policy.max_output_bytes, bool)
        or not isinstance(policy.max_output_bytes, int)
        or policy.max_output_bytes <= 0
    ):
        raise DependencyUpdateExecutionError(
            "max_output_bytes must be positive integer"
        )

    if not policy.allowed_exit_codes:
        raise DependencyUpdateExecutionError(
            "allowed_exit_codes must not be empty"
        )

    for code in policy.allowed_exit_codes:
        if isinstance(code, bool) or not isinstance(code, int):
            raise DependencyUpdateExecutionError(
                "allowed_exit_codes must contain integers"
            )

    for name in policy.allowed_environment:
        if not isinstance(name, str) or not name:
            raise DependencyUpdateExecutionError(
                "allowed_environment contains invalid name"
            )
        if "\x00" in name:
            raise DependencyUpdateExecutionError(
                "allowed_environment contains NUL"
            )

    return policy


def _validate_command(command: Sequence[str]) -> tuple[str, ...]:
    if isinstance(command, (str, bytes)):
        raise DependencyUpdateExecutionError(
            "command must be a sequence, not a string"
        )

    try:
        values = tuple(command)
    except TypeError as exc:
        raise DependencyUpdateExecutionError(
            "command must be an iterable sequence"
        ) from exc

    if not values:
        raise DependencyUpdateExecutionError(
            "command must not be empty"
        )

    for index, value in enumerate(values):
        if not isinstance(value, str):
            raise DependencyUpdateExecutionError(
                f"command[{index}] must be string"
            )

        if not value:
            raise DependencyUpdateExecutionError(
                f"command[{index}] must not be empty"
            )

        if "\x00" in value:
            raise DependencyUpdateExecutionError(
                f"command[{index}] contains NUL"
            )

    return values


def _validate_working_directory(
    working_directory: str | os.PathLike[str],
) -> Path:
    try:
        path = Path(working_directory).expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise DependencyUpdateExecutionError(
            "working directory cannot be resolved"
        ) from exc

    if not path.is_dir():
        raise DependencyUpdateExecutionError(
            "working directory must be a directory"
        )

    return path


def _build_environment(
    environment: Mapping[str, str] | None,
    allowed_names: tuple[str, ...],
) -> dict[str, str]:
    source = os.environ if environment is None else environment

    if not isinstance(source, Mapping):
        raise DependencyUpdateExecutionError(
            "environment must be a mapping"
        )

    result: dict[str, str] = {}

    for name in allowed_names:
        if name not in source:
            continue

        value = source[name]

        if not isinstance(value, str):
            raise DependencyUpdateExecutionError(
                f"environment value for {name!r} must be string"
            )

        if "\x00" in value:
            raise DependencyUpdateExecutionError(
                f"environment value for {name!r} contains NUL"
            )

        result[name] = value

    return result


def _decode_output(data: bytes, maximum: int) -> str:
    data = data[:maximum]
    return data.decode("utf-8", errors="replace")


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
    policy = _validate_policy(
        policy or DependencyUpdatePolicy()
    )

    command_vector = _validate_command(command)
    cwd = _validate_working_directory(working_directory)
    env = _build_environment(
        environment,
        policy.allowed_environment,
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
    except (OSError, ValueError) as exc:
        return DependencyUpdateResult(
            success=False,
            timed_out=False,
            exit_code=None,
            stdout="",
            stderr="",
            duration_seconds=time.monotonic() - started,
            working_directory=str(cwd),
            failure_reason=f"EXECUTION_START_FAILED:{type(exc).__name__}",
        )

    try:
        stdout, stderr = process.communicate(
            timeout=float(policy.timeout_seconds)
        )

    except subprocess.TimeoutExpired as exc:
        _terminate_process_group(process)
        stdout, stderr = process.communicate()

        if exc.stdout:
            stdout = stdout or exc.stdout

        if exc.stderr:
            stderr = stderr or exc.stderr

        return DependencyUpdateResult(
            success=False,
            timed_out=True,
            exit_code=process.returncode,
            stdout=_decode_output(
                stdout or b"",
                policy.max_output_bytes,
            ),
            stderr=_decode_output(
                stderr or b"",
                policy.max_output_bytes,
            ),
            duration_seconds=time.monotonic() - started,
            working_directory=str(cwd),
            failure_reason="EXECUTION_TIMEOUT",
        )

    success = process.returncode in policy.allowed_exit_codes

    return DependencyUpdateResult(
        success=success,
        timed_out=False,
        exit_code=process.returncode,
        stdout=_decode_output(
            stdout,
            policy.max_output_bytes,
        ),
        stderr=_decode_output(
            stderr,
            policy.max_output_bytes,
        ),
        duration_seconds=time.monotonic() - started,
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
