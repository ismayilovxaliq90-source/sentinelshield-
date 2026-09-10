from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence


class CommandAllowlistError(ValueError):
    """Raised when command allowlist input is invalid."""


@dataclass(frozen=True)
class CommandAllowlistPolicy:
    allowed_executables: frozenset[str]

    def __init__(self, allowed_executables: Iterable[str]) -> None:
        if isinstance(allowed_executables, (str, bytes)):
            raise CommandAllowlistError(
                "allowed_executables must be an iterable of strings"
            )

        try:
            values = tuple(allowed_executables)
        except TypeError as error:
            raise CommandAllowlistError(
                "allowed_executables must be iterable"
            ) from error

        for executable in values:
            if not isinstance(executable, str):
                raise CommandAllowlistError(
                    "allowlist entries must be strings"
                )

            if not executable:
                raise CommandAllowlistError(
                    "allowlist entries must not be empty"
                )

            if executable != executable.strip():
                raise CommandAllowlistError(
                    "allowlist entries must not contain surrounding whitespace"
                )

            if "\x00" in executable:
                raise CommandAllowlistError(
                    "allowlist entries must not contain NULL characters"
                )

            if "/" in executable or "\\" in executable:
                raise CommandAllowlistError(
                    "allowlist entries must contain executable names only"
                )

            if executable in {".", ".."}:
                raise CommandAllowlistError(
                    "invalid executable name"
                )

            if any(
                char in executable
                for char in ";|&><`$(){}[]*?!\n\r"
            ):
                raise CommandAllowlistError(
                    "allowlist entry contains shell metacharacters"
                )

        object.__setattr__(
            self,
            "allowed_executables",
            frozenset(values),
        )


@dataclass(frozen=True)
class CommandAllowlistResult:
    allowed: bool
    executable: str | None
    reason: str


def _validate_command_shape(command: Sequence[str]) -> tuple[str, ...]:
    if isinstance(command, (str, bytes)):
        raise CommandAllowlistError(
            "command must be a sequence of strings, not a string"
        )

    try:
        values = tuple(command)
    except TypeError as error:
        raise CommandAllowlistError(
            "command must be a sequence"
        ) from error

    if not values:
        raise CommandAllowlistError(
            "command must not be empty"
        )

    for item in values:
        if not isinstance(item, str):
            raise CommandAllowlistError(
                "command arguments must be strings"
            )

        if "\x00" in item:
            raise CommandAllowlistError(
                "command must not contain NULL characters"
            )

    return values


def _validate_executable_name(executable: str) -> None:
    if not executable:
        raise CommandAllowlistError(
            "executable must not be empty"
        )

    if executable != executable.strip():
        raise CommandAllowlistError(
            "executable must not contain surrounding whitespace"
        )

    if "/" in executable or "\\" in executable:
        raise CommandAllowlistError(
            "path-qualified executables are not allowed"
        )

    if executable in {".", ".."}:
        raise CommandAllowlistError(
            "dot executable names are not allowed"
        )

    if any(
        char in executable
        for char in ";|&><`$(){}[]*?!\n\r"
    ):
        raise CommandAllowlistError(
            "executable contains shell metacharacters"
        )


def validate_command_allowlist(
    command: Sequence[str],
    policy: CommandAllowlistPolicy,
) -> CommandAllowlistResult:
    if not isinstance(policy, CommandAllowlistPolicy):
        raise CommandAllowlistError(
            "policy must be CommandAllowlistPolicy"
        )

    values = _validate_command_shape(command)
    executable = values[0]

    _validate_executable_name(executable)

    if executable not in policy.allowed_executables:
        return CommandAllowlistResult(
            allowed=False,
            executable=executable,
            reason="EXECUTABLE_NOT_ALLOWED",
        )

    return CommandAllowlistResult(
        allowed=True,
        executable=executable,
        reason="COMMAND_ALLOWED",
    )


def require_allowed_command(
    command: Sequence[str],
    policy: CommandAllowlistPolicy,
) -> CommandAllowlistResult:
    result = validate_command_allowlist(command, policy)

    if not result.allowed:
        raise CommandAllowlistError(result.reason)

    return result
