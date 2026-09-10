from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import signal
import subprocess
import time
from typing import Mapping, Sequence


class ResourceLimitError(ValueError):
    """Raised when resource-limit configuration is invalid."""


MIN_CPU_SECONDS = 0.1
MAX_CPU_SECONDS = 3600.0

MIN_MEMORY_MB = 16
MAX_MEMORY_MB = 65536

MIN_PROCESS_COUNT = 1
MAX_PROCESS_COUNT = 1024


@dataclass(frozen=True)
class ResourceLimits:
    max_cpu_seconds: float | None = None
    max_memory_mb: int | None = None
    max_processes: int | None = None

    def __post_init__(self) -> None:
        if self.max_cpu_seconds is not None:
            validate_cpu_limit(self.max_cpu_seconds)

        if self.max_memory_mb is not None:
            validate_memory_limit(self.max_memory_mb)

        if self.max_processes is not None:
            validate_process_limit(self.max_processes)

    def to_dict(self) -> dict:
        return {
            "max_cpu_seconds": self.max_cpu_seconds,
            "max_memory_mb": self.max_memory_mb,
            "max_processes": self.max_processes,
        }


@dataclass(frozen=True)
class ResourceUsage:
    cpu_seconds: float
    memory_mb: float
    process_count: int

    def __post_init__(self) -> None:
        if isinstance(self.cpu_seconds, bool):
            raise ResourceLimitError("cpu_seconds must be numeric")

        if not isinstance(self.cpu_seconds, (int, float)):
            raise ResourceLimitError("cpu_seconds must be numeric")

        if float(self.cpu_seconds) < 0:
            raise ResourceLimitError("cpu_seconds cannot be negative")

        if isinstance(self.memory_mb, bool):
            raise ResourceLimitError("memory_mb must be numeric")

        if not isinstance(self.memory_mb, (int, float)):
            raise ResourceLimitError("memory_mb must be numeric")

        if float(self.memory_mb) < 0:
            raise ResourceLimitError("memory_mb cannot be negative")

        if type(self.process_count) is not int:
            raise ResourceLimitError("process_count must be an integer")

        if self.process_count < 0:
            raise ResourceLimitError(
                "process_count cannot be negative"
            )

    def to_dict(self) -> dict:
        return {
            "cpu_seconds": float(self.cpu_seconds),
            "memory_mb": float(self.memory_mb),
            "process_count": self.process_count,
        }


@dataclass(frozen=True)
class ResourceLimitResult:
    command: tuple[str, ...]
    return_code: int | None
    usage: ResourceUsage
    limit_exceeded: bool
    exceeded_limits: tuple[str, ...]
    duration_seconds: float
    stdout: str
    stderr: str
    terminated: bool

    @property
    def success(self) -> bool:
        return (
            self.return_code == 0
            and not self.limit_exceeded
            and not self.terminated
        )

    def to_dict(self) -> dict:
        return {
            "command": list(self.command),
            "return_code": self.return_code,
            "usage": self.usage.to_dict(),
            "limit_exceeded": self.limit_exceeded,
            "exceeded_limits": list(self.exceeded_limits),
            "duration_seconds": self.duration_seconds,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "terminated": self.terminated,
            "success": self.success,
        }


def validate_cpu_limit(value: float) -> float:
    if isinstance(value, bool):
        raise ResourceLimitError(
            "CPU limit must be numeric"
        )

    if not isinstance(value, (int, float)):
        raise ResourceLimitError(
            "CPU limit must be numeric"
        )

    value = float(value)

    if value < MIN_CPU_SECONDS:
        raise ResourceLimitError(
            f"CPU limit must be >= {MIN_CPU_SECONDS}"
        )

    if value > MAX_CPU_SECONDS:
        raise ResourceLimitError(
            f"CPU limit must be <= {MAX_CPU_SECONDS}"
        )

    return value


def validate_memory_limit(value: int) -> int:
    if type(value) is not int:
        raise ResourceLimitError(
            "memory limit must be an integer"
        )

    if value < MIN_MEMORY_MB:
        raise ResourceLimitError(
            f"memory limit must be >= {MIN_MEMORY_MB} MB"
        )

    if value > MAX_MEMORY_MB:
        raise ResourceLimitError(
            f"memory limit must be <= {MAX_MEMORY_MB} MB"
        )

    return value


def validate_process_limit(value: int) -> int:
    if type(value) is not int:
        raise ResourceLimitError(
            "process limit must be an integer"
        )

    if value < MIN_PROCESS_COUNT:
        raise ResourceLimitError(
            f"process limit must be >= {MIN_PROCESS_COUNT}"
        )

    if value > MAX_PROCESS_COUNT:
        raise ResourceLimitError(
            f"process limit must be <= {MAX_PROCESS_COUNT}"
        )

    return value


def validate_command(command: Sequence[str]) -> tuple[str, ...]:
    if isinstance(command, (str, bytes)):
        raise ResourceLimitError(
            "command must be a sequence"
        )

    if not isinstance(command, Sequence):
        raise ResourceLimitError(
            "command must be a sequence"
        )

    normalized = tuple(command)

    if not normalized:
        raise ResourceLimitError(
            "command must not be empty"
        )

    for argument in normalized:
        if not isinstance(argument, str):
            raise ResourceLimitError(
                "command arguments must be strings"
            )

        if not argument:
            raise ResourceLimitError(
                "command arguments must not be empty"
            )

        if "\x00" in argument:
            raise ResourceLimitError(
                "NULL character is not allowed"
            )

    return normalized


def validate_working_directory(
    working_directory: str | Path,
) -> Path:
    path = Path(working_directory)

    if not path.exists():
        raise ResourceLimitError(
            f"working directory does not exist: {path}"
        )

    if not path.is_dir():
        raise ResourceLimitError(
            f"working directory is not a directory: {path}"
        )

    if path.is_symlink():
        raise ResourceLimitError(
            "working directory must not be a symlink"
        )

    return path.resolve()


def _process_group_pids(pid: int) -> list[int]:
    try:
        output = subprocess.check_output(
            ["pgrep", "-g", str(pid)],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError):
        return [pid]

    result: list[int] = []

    for line in output.splitlines():
        try:
            process_pid = int(line.strip())
        except ValueError:
            continue

        if process_pid > 0:
            result.append(process_pid)

    return result or [pid]


def _read_process_usage(pid: int) -> ResourceUsage:
    cpu_seconds = 0.0
    memory_mb = 0.0
    process_count = 1

    try:
        stat_path = Path(f"/proc/{pid}/stat")

        if stat_path.exists():
            fields = stat_path.read_text(
                encoding="utf-8",
                errors="replace",
            ).split()

            if len(fields) > 15:
                user_ticks = int(fields[13])
                system_ticks = int(fields[14])
                clock_ticks = os.sysconf(
                    os.sysconf_names["SC_CLK_TCK"]
                )

                cpu_seconds = (
                    user_ticks + system_ticks
                ) / float(clock_ticks)

    except (OSError, ValueError, KeyError):
        pass

    try:
        status_path = Path(f"/proc/{pid}/status")

        for line in status_path.read_text(
            encoding="utf-8",
            errors="replace",
        ).splitlines():
            if line.startswith("VmRSS:"):
                parts = line.split()

                if len(parts) >= 2:
                    memory_mb = int(parts[1]) / 1024.0

                break

    except (OSError, ValueError):
        pass

    process_count = len(_process_group_pids(pid))

    return ResourceUsage(
        cpu_seconds=cpu_seconds,
        memory_mb=memory_mb,
        process_count=process_count,
    )


def _exceeded_limits(
    usage: ResourceUsage,
    limits: ResourceLimits,
) -> tuple[str, ...]:
    exceeded: list[str] = []

    if (
        limits.max_cpu_seconds is not None
        and usage.cpu_seconds > limits.max_cpu_seconds
    ):
        exceeded.append("CPU")

    if (
        limits.max_memory_mb is not None
        and usage.memory_mb > limits.max_memory_mb
    ):
        exceeded.append("MEMORY")

    if (
        limits.max_processes is not None
        and usage.process_count > limits.max_processes
    ):
        exceeded.append("PROCESS_COUNT")

    return tuple(exceeded)


def _terminate_process_group(
    process: subprocess.Popen,
) -> None:
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


def enforce_resource_limits(
    command: Sequence[str],
    *,
    limits: ResourceLimits,
    working_directory: str | Path,
    environment: Mapping[str, str] | None = None,
    poll_interval: float = 0.05,
) -> ResourceLimitResult:
    normalized_command = validate_command(command)
    cwd = validate_working_directory(working_directory)

    if not isinstance(limits, ResourceLimits):
        raise ResourceLimitError(
            "limits must be ResourceLimits"
        )

    if isinstance(poll_interval, bool):
        raise ResourceLimitError(
            "poll interval must be numeric"
        )

    if not isinstance(poll_interval, (int, float)):
        raise ResourceLimitError(
            "poll interval must be numeric"
        )

    if poll_interval <= 0:
        raise ResourceLimitError(
            "poll interval must be positive"
        )

    if environment is None:
        env = dict(os.environ)
    else:
        env = {}

        for key, value in environment.items():
            if not isinstance(key, str):
                raise ResourceLimitError(
                    "environment keys must be strings"
                )

            if not isinstance(value, str):
                raise ResourceLimitError(
                    "environment values must be strings"
                )

            if "\x00" in key or "\x00" in value:
                raise ResourceLimitError(
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

        usage = ResourceUsage(
            cpu_seconds=0.0,
            memory_mb=0.0,
            process_count=0,
        )

        return ResourceLimitResult(
            command=normalized_command,
            return_code=None,
            usage=usage,
            limit_exceeded=False,
            exceeded_limits=(),
            duration_seconds=duration,
            stdout="",
            stderr=str(error),
            terminated=False,
        )

    last_usage = ResourceUsage(
        cpu_seconds=0.0,
        memory_mb=0.0,
        process_count=1,
    )

    while process.poll() is None:
        last_usage = _read_process_usage(process.pid)

        exceeded = _exceeded_limits(last_usage, limits)

        if exceeded:
            _terminate_process_group(process)

            stdout, stderr = process.communicate()

            duration = time.monotonic() - started

            message = (
                "resource limit exceeded: "
                + ", ".join(exceeded)
            )

            stderr_text = stderr or ""

            if message not in stderr_text:
                stderr_text = (
                    f"{stderr_text.rstrip()}\n{message}"
                ).strip()

            return ResourceLimitResult(
                command=normalized_command,
                return_code=process.returncode,
                usage=last_usage,
                limit_exceeded=True,
                exceeded_limits=exceeded,
                duration_seconds=duration,
                stdout=stdout or "",
                stderr=stderr_text,
                terminated=True,
            )

        time.sleep(float(poll_interval))

    stdout, stderr = process.communicate()

    last_usage = _read_process_usage(process.pid)

    duration = time.monotonic() - started

    exceeded = _exceeded_limits(last_usage, limits)

    return ResourceLimitResult(
        command=normalized_command,
        return_code=process.returncode,
        usage=last_usage,
        limit_exceeded=bool(exceeded),
        exceeded_limits=exceeded,
        duration_seconds=duration,
        stdout=stdout or "",
        stderr=stderr or "",
        terminated=False,
    )


def validate_resource_limit_result(
    result: ResourceLimitResult,
) -> bool:
    if not isinstance(result, ResourceLimitResult):
        return False

    if not result.command:
        return False

    if result.duration_seconds < 0:
        return False

    if result.usage.cpu_seconds < 0:
        return False

    if result.usage.memory_mb < 0:
        return False

    if result.usage.process_count < 0:
        return False

    if result.limit_exceeded:
        if not result.exceeded_limits:
            return False

        if not result.terminated:
            return False

    if not result.limit_exceeded:
        if result.exceeded_limits:
            return False

    return True


__all__ = [
    "MAX_CPU_SECONDS",
    "MAX_MEMORY_MB",
    "MAX_PROCESS_COUNT",
    "MIN_CPU_SECONDS",
    "MIN_MEMORY_MB",
    "MIN_PROCESS_COUNT",
    "ResourceLimitError",
    "ResourceLimitResult",
    "ResourceLimits",
    "ResourceUsage",
    "enforce_resource_limits",
    "validate_command",
    "validate_cpu_limit",
    "validate_memory_limit",
    "validate_process_limit",
    "validate_resource_limit_result",
    "validate_working_directory",
]
