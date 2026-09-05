from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from typing import Mapping, Sequence


class SafeCommandError(RuntimeError):
    """Raised when safe command execution fails."""


@dataclass(frozen=True)
class CommandResult:
    command: tuple[str, ...]
    return_code: int
    stdout: str
    stderr: str
    timed_out: bool


class SafeCommandExecutor:
    """
    Controlled command execution layer.

    Security properties:
    - shell=False
    - explicit command validation
    - controlled environment
    - timeout support
    - stdout/stderr captured separately
    """

    def __init__(self, timeout: float = 30.0) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be greater than zero")

        self.timeout = timeout

    @staticmethod
    def validate_command(
        command: Sequence[str],
    ) -> tuple[str, ...]:
        if isinstance(command, (str, bytes)):
            raise TypeError(
                "command must be a sequence of strings"
            )

        if not command:
            raise ValueError("command cannot be empty")

        normalized = tuple(command)

        for argument in normalized:
            if not isinstance(argument, str):
                raise TypeError(
                    "all command arguments must be strings"
                )

            if not argument:
                raise ValueError(
                    "command arguments cannot be empty"
                )

        return normalized

    @staticmethod
    def build_environment(
        extra_env: Mapping[str, str] | None = None,
    ) -> dict[str, str]:
        environment = {
            "PATH": os.environ.get("PATH", "")
        }

        if extra_env is not None:
            for key, value in extra_env.items():
                if not isinstance(key, str):
                    raise TypeError(
                        "environment keys must be strings"
                    )

                if not isinstance(value, str):
                    raise TypeError(
                        "environment values must be strings"
                    )

                if not key:
                    raise ValueError(
                        "environment keys cannot be empty"
                    )

                environment[key] = value

        return environment

    def execute(
        self,
        command: Sequence[str],
        *,
        extra_env: Mapping[str, str] | None = None,
        cwd: str | None = None,
        timeout: float | None = None,
    ) -> CommandResult:

        normalized = self.validate_command(command)

        effective_timeout = (
            self.timeout
            if timeout is None
            else timeout
        )

        if effective_timeout <= 0:
            raise ValueError(
                "timeout must be greater than zero"
            )

        environment = self.build_environment(extra_env)

        try:
            completed = subprocess.run(
                normalized,
                shell=False,
                capture_output=True,
                text=True,
                cwd=cwd,
                env=environment,
                timeout=effective_timeout,
                check=False,
            )

        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout or ""
            stderr = exc.stderr or ""

            if isinstance(stdout, bytes):
                stdout = stdout.decode(
                    "utf-8",
                    errors="replace",
                )

            if isinstance(stderr, bytes):
                stderr = stderr.decode(
                    "utf-8",
                    errors="replace",
                )

            return CommandResult(
                command=normalized,
                return_code=-1,
                stdout=stdout,
                stderr=stderr,
                timed_out=True,
            )

        except OSError as exc:
            raise SafeCommandError(
                f"command execution failed: {normalized[0]}"
            ) from exc

        return CommandResult(
            command=normalized,
            return_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            timed_out=False,
        )

    @staticmethod
    def is_successful(
        result: CommandResult,
    ) -> bool:
        return (
            result.return_code == 0
            and not result.timed_out
        )
