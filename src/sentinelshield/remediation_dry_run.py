from __future__ import annotations

from dataclasses import dataclass
import math
from pathlib import Path
from typing import Mapping, Sequence


class RemediationDryRunError(ValueError):
    """Raised when a remediation dry-run request is invalid."""


@dataclass(frozen=True)
class RemediationDryRunPolicy:
    max_arguments: int = 64
    max_argument_length: int = 4096
    timeout_seconds: float = 60.0
    max_timeout_seconds: float = 600.0
    allow_shell: bool = False


@dataclass(frozen=True)
class RemediationDryRunResult:
    valid: bool
    executable: str
    arguments: tuple[str, ...]
    working_directory: str
    environment_keys: tuple[str, ...]
    timeout_seconds: float
    executed: bool
    filesystem_modified: bool
    reason: str

    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "executable": self.executable,
            "arguments": list(self.arguments),
            "working_directory": self.working_directory,
            "environment_keys": list(self.environment_keys),
            "timeout_seconds": self.timeout_seconds,
            "executed": self.executed,
            "filesystem_modified": self.filesystem_modified,
            "reason": self.reason,
        }


_CONTROL_CHARS = frozenset(
    chr(value)
    for value in range(0, 32)
) | {chr(127)}

_FORBIDDEN_SHELL_TOKENS = (
    ";",
    "&&",
    "||",
    "|",
    "`",
    "$(",
    "${",
    ">",
    "<",
    "\n",
    "\r",
)


def _validate_policy(
    policy: RemediationDryRunPolicy,
) -> None:
    if not isinstance(policy, RemediationDryRunPolicy):
        raise RemediationDryRunError(
            "policy must be RemediationDryRunPolicy"
        )

    if (
        isinstance(policy.max_arguments, bool)
        or not isinstance(policy.max_arguments, int)
        or policy.max_arguments < 1
    ):
        raise RemediationDryRunError(
            "max_arguments must be a positive integer"
        )

    if (
        isinstance(policy.max_argument_length, bool)
        or not isinstance(policy.max_argument_length, int)
        or policy.max_argument_length < 1
    ):
        raise RemediationDryRunError(
            "max_argument_length must be a positive integer"
        )

    if (
        isinstance(policy.timeout_seconds, bool)
        or not isinstance(policy.timeout_seconds, (int, float))
        or not math.isfinite(float(policy.timeout_seconds))
        or policy.timeout_seconds <= 0
    ):
        raise RemediationDryRunError(
            "timeout_seconds must be finite and positive"
        )

    if (
        isinstance(policy.max_timeout_seconds, bool)
        or not isinstance(policy.max_timeout_seconds, (int, float))
        or not math.isfinite(float(policy.max_timeout_seconds))
        or policy.max_timeout_seconds <= 0
    ):
        raise RemediationDryRunError(
            "max_timeout_seconds must be finite and positive"
        )

    if policy.timeout_seconds > policy.max_timeout_seconds:
        raise RemediationDryRunError(
            "timeout_seconds cannot exceed max_timeout_seconds"
        )

    if not isinstance(policy.allow_shell, bool):
        raise RemediationDryRunError(
            "allow_shell must be bool"
        )

    if policy.allow_shell:
        raise RemediationDryRunError(
            "shell execution is forbidden for remediation dry-run"
        )


def _validate_text(
    value: object,
    field: str,
    max_length: int | None = None,
) -> str:
    if not isinstance(value, str):
        raise RemediationDryRunError(
            f"{field} must be a string"
        )

    if not value:
        raise RemediationDryRunError(
            f"{field} must not be empty"
        )

    if max_length is not None and len(value) > max_length:
        raise RemediationDryRunError(
            f"{field} exceeds maximum length"
        )

    if any(character in _CONTROL_CHARS for character in value):
        raise RemediationDryRunError(
            f"{field} contains control character"
        )

    return value


def _validate_command(
    command: Sequence[str],
    policy: RemediationDryRunPolicy,
) -> tuple[str, tuple[str, ...]]:
    if isinstance(command, (str, bytes)):
        raise RemediationDryRunError(
            "command must be a sequence of arguments"
        )

    try:
        values = tuple(command)
    except TypeError as error:
        raise RemediationDryRunError(
            "command must be a sequence"
        ) from error

    if not values:
        raise RemediationDryRunError(
            "command must not be empty"
        )

    if len(values) > policy.max_arguments:
        raise RemediationDryRunError(
            "command exceeds maximum argument count"
        )

    validated: list[str] = []

    for index, value in enumerate(values):
        text = _validate_text(
            value,
            f"command[{index}]",
            policy.max_argument_length,
        )

        for token in _FORBIDDEN_SHELL_TOKENS:
            if token in text:
                raise RemediationDryRunError(
                    f"shell token {token!r} is forbidden"
                )

        validated.append(text)

    executable = validated[0]

    if any(character.isspace() for character in executable):
        raise RemediationDryRunError(
            "executable must be a single command token"
        )

    return executable, tuple(validated[1:])


def _validate_environment(
    environment: Mapping[str, str] | None,
) -> tuple[str, ...]:
    if environment is None:
        return ()

    if not isinstance(environment, Mapping):
        raise RemediationDryRunError(
            "environment must be a mapping"
        )

    keys: list[str] = []

    for key, value in environment.items():
        _validate_text(key, "environment key")

        if "=" in key:
            raise RemediationDryRunError(
                "environment key must not contain '='"
            )

        _validate_text(value, f"environment[{key!r}]")
        keys.append(key)

    return tuple(sorted(keys))


def _validate_working_directory(
    working_directory: object,
) -> str:
    if isinstance(working_directory, Path):
        working_directory = str(working_directory)

    return _validate_text(
        working_directory,
        "working_directory",
    )


def prepare_remediation_dry_run(
    command: Sequence[str],
    *,
    working_directory: str | Path,
    environment: Mapping[str, str] | None = None,
    policy: RemediationDryRunPolicy | None = None,
) -> RemediationDryRunResult:
    """
    Validate a remediation command without executing it.

    Security property:
    this function never calls subprocess, os.system, shell execution,
    package managers, or filesystem mutation APIs.
    """
    policy = policy or RemediationDryRunPolicy()
    _validate_policy(policy)

    executable, arguments = _validate_command(
        command,
        policy,
    )

    working_directory_text = _validate_working_directory(
        working_directory
    )

    environment_keys = _validate_environment(environment)

    return RemediationDryRunResult(
        valid=True,
        executable=executable,
        arguments=arguments,
        working_directory=working_directory_text,
        environment_keys=environment_keys,
        timeout_seconds=float(policy.timeout_seconds),
        executed=False,
        filesystem_modified=False,
        reason="DRY_RUN_VALIDATED_WITHOUT_EXECUTION",
    )


def require_remediation_dry_run(
    command: Sequence[str],
    *,
    working_directory: str | Path,
    environment: Mapping[str, str] | None = None,
    policy: RemediationDryRunPolicy | None = None,
) -> RemediationDryRunResult:
    result = prepare_remediation_dry_run(
        command,
        working_directory=working_directory,
        environment=environment,
        policy=policy,
    )

    if not result.valid:
        raise RemediationDryRunError(
            result.reason
        )

    return result
