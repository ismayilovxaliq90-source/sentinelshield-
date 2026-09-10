from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Sequence


class CommandAllowlistError(ValueError):
    """Raised when a command allowlist policy is invalid."""


# Shell syntax is intentionally forbidden at this layer.
# Argument-specific validation belongs to Task 189.
_SHELL_META_RE = re.compile(r"[;&|`$><\n\r]")


@dataclass(frozen=True)
class CommandAllowlistPolicy:
    """
    Immutable executable allowlist.

    The policy contains executable BASENAMES only.
    Path-qualified executables are deliberately rejected.

    Example:
        CommandAllowlistPolicy(
            allowed_commands=frozenset({"git", "python3"})
        )
    """

    allowed_commands: frozenset[str]

    def __post_init__(self) -> None:
        if not isinstance(self.allowed_commands, frozenset):
            raise TypeError("allowed_commands must be frozenset")

        for command in self.allowed_commands:
            if not isinstance(command, str):
                raise TypeError("allowlist entries must be strings")

            if not command:
                raise CommandAllowlistError(
                    "allowlist cannot contain an empty command"
                )

            if command != command.strip():
                raise CommandAllowlistError(
                    f"allowlist entry contains surrounding whitespace: {command!r}"
                )

            if command in {".", ".."}:
                raise CommandAllowlistError(
                    f"invalid allowlist executable: {command!r}"
                )

            if "/" in command or "\\" in command:
                raise CommandAllowlistError(
                    f"path-qualified executable is forbidden: {command!r}"
                )

            if _SHELL_META_RE.search(command):
                raise CommandAllowlistError(
                    f"shell metacharacter in allowlist entry: {command!r}"
                )

    @classmethod
    def from_iterable(
        cls,
        commands: Iterable[str],
    ) -> "CommandAllowlistPolicy":
        if isinstance(commands, (str, bytes)):
            raise TypeError("commands must be an iterable of executable names")

        try:
            values = frozenset(commands)
        except TypeError as exc:
            raise TypeError("commands must be iterable") from exc

        return cls(allowed_commands=values)


@dataclass(frozen=True)
class CommandAllowlistResult:
    """Result of command executable allowlist validation."""

    allowed: bool
    executable: str | None
    reason: str
    command_length: int

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "executable": self.executable,
            "reason": self.reason,
            "command_length": self.command_length,
        }


def _reject_invalid_command_shape(
    command: object,
) -> tuple[bool, str]:
    if isinstance(command, (str, bytes)):
        return False, "COMMAND_MUST_BE_SEQUENCE"

    if not isinstance(command, Sequence):
        return False, "COMMAND_MUST_BE_SEQUENCE"

    if len(command) == 0:
        return False, "COMMAND_IS_EMPTY"

    for item in command:
        if not isinstance(item, str):
            return False, "COMMAND_ELEMENT_MUST_BE_STRING"

        if item == "":
            return False, "COMMAND_ELEMENT_IS_EMPTY"

        if "\x00" in item:
            return False, "NULL_CHARACTER_NOT_ALLOWED"

    return True, "OK"


def _validate_executable_name(executable: str) -> str | None:
    """
    Validate only the executable component.

    Argument validation intentionally remains outside Task 188
    and belongs to Task 189.
    """
    if not executable:
        return "EXECUTABLE_IS_EMPTY"

    if executable != executable.strip():
        return "EXECUTABLE_WHITESPACE_NOT_ALLOWED"

    if executable in {".", ".."}:
        return "EXECUTABLE_PATH_NOT_ALLOWED"

    if "/" in executable or "\\" in executable:
        return "EXECUTABLE_PATH_NOT_ALLOWED"

    if _SHELL_META_RE.search(executable):
        return "EXECUTABLE_SHELL_SYNTAX_NOT_ALLOWED"

    if "\x00" in executable:
        return "NULL_CHARACTER_NOT_ALLOWED"

    return None


def validate_command_allowlist(
    command: object,
    policy: CommandAllowlistPolicy,
) -> CommandAllowlistResult:
    """
    Validate a command against an explicit executable allowlist.

    Security properties:
    - no shell execution
    - no executable lookup
    - no command execution
    - default deny
    - path-qualified executables rejected
    - argument validation deferred to Task 189
    """
    if not isinstance(policy, CommandAllowlistPolicy):
        raise TypeError("policy must be CommandAllowlistPolicy")

    valid_shape, reason = _reject_invalid_command_shape(command)

    if not valid_shape:
        length = (
            len(command)
            if isinstance(command, Sequence)
            and not isinstance(command, (str, bytes))
            else 0
        )

        return CommandAllowlistResult(
            allowed=False,
            executable=None,
            reason=reason,
            command_length=length,
        )

    executable = command[0]

    executable_error = _validate_executable_name(executable)

    if executable_error is not None:
        return CommandAllowlistResult(
            allowed=False,
            executable=executable,
            reason=executable_error,
            command_length=len(command),
        )

    if executable not in policy.allowed_commands:
        return CommandAllowlistResult(
            allowed=False,
            executable=executable,
            reason="EXECUTABLE_NOT_ALLOWLISTED",
            command_length=len(command),
        )

    return CommandAllowlistResult(
        allowed=True,
        executable=executable,
        reason="EXECUTABLE_ALLOWLISTED",
        command_length=len(command),
    )


def require_allowed_command(
    command: object,
    policy: CommandAllowlistPolicy,
) -> CommandAllowlistResult:
    """
    Fail closed when a command is not explicitly allowlisted.

    This function performs validation only.
    It NEVER executes the command.
    """
    result = validate_command_allowlist(command, policy)

    if not result.allowed:
        raise CommandAllowlistError(result.reason)

    return result
