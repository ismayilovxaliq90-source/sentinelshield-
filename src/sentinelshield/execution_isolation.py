from __future__ import annotations

import os
import signal
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

from sentinelshield.temporary_workspace import (
    TemporaryWorkspace,
    TemporaryWorkspaceError,
    workspace_contains,
)


class ExecutionIsolationError(RuntimeError):
    """Raised when an isolated execution boundary cannot be prepared."""


_DEFAULT_ENV_ALLOWLIST = frozenset(
    {
        "PATH",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "HOME",
        "TMPDIR",
        "TEMP",
        "TMP",
        "CI",
    }
)


@dataclass(frozen=True)
class ExecutionIsolation:
    workspace: TemporaryWorkspace
    cwd: Path
    command: tuple[str, ...]
    environment: tuple[tuple[str, str], ...]
    shell: bool
    start_new_session: bool

    def environment_dict(self) -> dict[str, str]:
        return dict(self.environment)

    def to_dict(self) -> dict[str, object]:
        return {
            "workspace": str(self.workspace.path),
            "cwd": str(self.cwd),
            "command": list(self.command),
            "environment": {
                key: value
                for key, value in self.environment
            },
            "shell": self.shell,
            "start_new_session": self.start_new_session,
        }


def _validate_command(
    command: Sequence[str],
) -> tuple[str, ...]:
    if isinstance(command, (str, bytes)):
        raise TypeError(
            "command must be a sequence of arguments, not a string"
        )

    try:
        values = tuple(command)
    except TypeError as exc:
        raise TypeError(
            "command must be an argument sequence"
        ) from exc

    if not values:
        raise ValueError(
            "command must contain at least one argument"
        )

    for index, argument in enumerate(values):
        if not isinstance(argument, str):
            raise TypeError(
                f"command argument {index} must be a string"
            )

        if not argument:
            raise ValueError(
                f"command argument {index} must not be empty"
            )

        if "\x00" in argument:
            raise ValueError(
                f"command argument {index} contains NULL"
            )

    return values


def _validate_environment(
    environment: Mapping[str, str] | None,
    allowlist: set[str] | frozenset[str],
) -> tuple[tuple[str, str], ...]:
    if environment is None:
        source = {
            key: value
            for key, value in os.environ.items()
            if key in allowlist
        }
    else:
        if not isinstance(environment, Mapping):
            raise TypeError(
                "environment must be a mapping"
            )

        source = dict(environment)

    result: list[tuple[str, str]] = []

    for key, value in source.items():
        if not isinstance(key, str):
            raise TypeError(
                "environment variable names must be strings"
            )

        if not isinstance(value, str):
            raise TypeError(
                f"environment variable {key!r} value must be a string"
            )

        if not key:
            raise ValueError(
                "environment variable name must not be empty"
            )

        if "\x00" in key or "\x00" in value:
            raise ValueError(
                f"NULL character in environment variable {key!r}"
            )

        if "=" in key:
            raise ValueError(
                f"invalid environment variable name: {key!r}"
            )

        if key not in allowlist:
            raise ExecutionIsolationError(
                f"Environment variable is not allowlisted: {key}"
            )

        result.append((key, value))

    result.sort(key=lambda item: item[0])

    return tuple(result)


def _validate_workspace(
    workspace: TemporaryWorkspace,
) -> Path:
    if not isinstance(
        workspace,
        TemporaryWorkspace,
    ):
        raise TypeError(
            "workspace must be a TemporaryWorkspace"
        )

    path = workspace.path

    if path.is_symlink():
        raise TemporaryWorkspaceError(
            "Execution workspace must not be a symlink"
        )

    if not path.is_dir():
        raise TemporaryWorkspaceError(
            "Execution workspace does not exist"
        )

    if not workspace.marker.is_file():
        raise TemporaryWorkspaceError(
            "Execution workspace marker is missing"
        )

    return path.resolve()


def prepare_execution_isolation(
    workspace: TemporaryWorkspace,
    command: Sequence[str],
    *,
    cwd: str | os.PathLike[str] | None = None,
    environment: Mapping[str, str] | None = None,
    environment_allowlist: set[str] | frozenset[str] | None = None,
) -> ExecutionIsolation:
    """
    Prepare a process-execution boundary.

    This function does not execute the command.
    """
    workspace_root = _validate_workspace(workspace)
    validated_command = _validate_command(command)

    allowlist = (
        _DEFAULT_ENV_ALLOWLIST
        if environment_allowlist is None
        else frozenset(environment_allowlist)
    )

    if not allowlist:
        raise ValueError(
            "environment allowlist must not be empty"
        )

    validated_environment = _validate_environment(
        environment,
        allowlist,
    )

    if cwd is None:
        execution_cwd = workspace_root
    else:
        requested_cwd = Path(cwd)

        if requested_cwd.is_absolute():
            candidate = requested_cwd.resolve(strict=False)
        else:
            candidate = (
                workspace_root / requested_cwd
            ).resolve(strict=False)

        if not workspace_contains(
            workspace,
            candidate,
        ):
            raise ExecutionIsolationError(
                "Execution cwd is outside temporary workspace"
            )

        execution_cwd = candidate

    if not execution_cwd.exists():
        raise ExecutionIsolationError(
            f"Execution cwd does not exist: {execution_cwd}"
        )

    if not execution_cwd.is_dir():
        raise ExecutionIsolationError(
            f"Execution cwd is not a directory: {execution_cwd}"
        )

    return ExecutionIsolation(
        workspace=workspace,
        cwd=execution_cwd,
        command=validated_command,
        environment=validated_environment,
        shell=False,
        start_new_session=True,
    )


def execute_isolated(
    isolation: ExecutionIsolation,
    *,
    timeout: float = 30.0,
) -> subprocess.CompletedProcess[str]:
    """
    Execute an already validated isolation specification.

    This API is intended for the isolated Server environment.
    """
    if not isinstance(
        isolation,
        ExecutionIsolation,
    ):
        raise TypeError(
            "isolation must be an ExecutionIsolation"
        )

    if timeout <= 0:
        raise ValueError(
            "timeout must be greater than zero"
        )

    workspace_root = _validate_workspace(
        isolation.workspace
    )

    cwd = isolation.cwd.resolve()

    if not workspace_contains(
        isolation.workspace,
        cwd,
    ):
        raise ExecutionIsolationError(
            "Execution cwd escaped workspace"
        )

    if isolation.shell is not False:
        raise ExecutionIsolationError(
            "Shell execution is prohibited"
        )

    if isolation.start_new_session is not True:
        raise ExecutionIsolationError(
            "Execution must use a new process session"
        )

    if not isolation.command:
        raise ExecutionIsolationError(
            "Execution command is empty"
        )

    for argument in isolation.command:
        if not isinstance(argument, str):
            raise ExecutionIsolationError(
                "Execution command contains non-string argument"
            )

        if "\x00" in argument:
            raise ExecutionIsolationError(
                "Execution command contains NULL"
            )

    environment = isolation.environment_dict()

    if "PATH" not in environment:
        raise ExecutionIsolationError(
            "PATH must be present in isolated environment"
        )

    process: subprocess.Popen[str] | None = None

    try:
        process = subprocess.Popen(
            list(isolation.command),
            cwd=str(cwd),
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
            start_new_session=True,
            close_fds=True,
        )

        stdout, stderr = process.communicate(
            timeout=timeout
        )

        return subprocess.CompletedProcess(
            args=list(isolation.command),
            returncode=process.returncode,
            stdout=stdout,
            stderr=stderr,
        )

    except subprocess.TimeoutExpired as exc:
        if process is not None:
            try:
                os.killpg(
                    process.pid,
                    signal.SIGKILL,
                )
            except (OSError, ProcessLookupError):
                try:
                    process.kill()
                except OSError:
                    pass

            process.communicate()

        raise ExecutionIsolationError(
            "Isolated process exceeded execution timeout"
        ) from exc

    except OSError as exc:
        raise ExecutionIsolationError(
            f"Unable to execute isolated command: {isolation.command[0]}"
        ) from exc

    finally:
        # Prevent accidental references to the workspace from
        # becoming part of an execution object lifecycle.
        _ = workspace_root
