from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence


class CommandAllowlistError(ValueError):
    """Raised when a command violates the executable allowlist."""


DEFAULT_ALLOWED_EXECUTABLES = frozenset(
    {
        "python",
        "python3",
        "node",
        "npm",
        "npx",
        "yarn",
        "pnpm",
        "go",
        "cargo",
        "rustc",
        "mvn",
        "gradle",
        "composer",
        "dotnet",
        "git",
    }
)


@dataclass(frozen=True)
class CommandAllowlistPolicy:
    allowed_executables: frozenset[str] = DEFAULT_ALLOWED_EXECUTABLES


@dataclass(frozen=True)
class CommandAllowlistResult:
    valid: bool
    executable: str | None
    reason: str | None = None


def _invalid(
    executable: str | None,
    reason: str,
) -> CommandAllowlistResult:
    return CommandAllowlistResult(
        valid=False,
        executable=executable,
        reason=reason,
    )


def validate_command_allowlist(
    command: Sequence[str],
    policy: CommandAllowlistPolicy | None = None,
) -> CommandAllowlistResult:
    """
    Validate only the executable portion of a command.

    Argument validation is intentionally excluded from Task 188 and belongs
    to Task 189.
    """
    if policy is None:
        policy = CommandAllowlistPolicy()

    if isinstance(command, (str, bytes)) or not isinstance(command, Sequence):
        return _invalid(None, "COMMAND_MUST_BE_A_SEQUENCE")

    if not command:
        return _invalid(None, "COMMAND_MUST_NOT_BE_EMPTY")

    executable = command[0]

    if not isinstance(executable, str):
        return _invalid(None, "EXECUTABLE_MUST_BE_STRING")

    if not executable:
        return _invalid(executable, "EXECUTABLE_MUST_NOT_BE_EMPTY")

    if "\x00" in executable:
        return _invalid(executable, "NULL_CHARACTER_NOT_ALLOWED")

    if any(ord(char) < 32 or ord(char) == 127 for char in executable):
        return _invalid(executable, "CONTROL_CHARACTER_NOT_ALLOWED")

    if any(char in executable for char in (";", "&", "|", "`", "$", ">", "<")):
        return _invalid(executable, "SHELL_METACHARACTER_NOT_ALLOWED")

    if "/" in executable or "\\" in executable:
        return _invalid(executable, "EXECUTABLE_PATH_NOT_ALLOWED")

    if executable not in policy.allowed_executables:
        return _invalid(executable, "EXECUTABLE_NOT_ALLOWED")

    return CommandAllowlistResult(
        valid=True,
        executable=executable,
        reason=None,
    )


def require_allowed_command(
    command: Sequence[str],
    policy: CommandAllowlistPolicy | None = None,
) -> None:
    result = validate_command_allowlist(command, policy)

    if not result.valid:
        raise CommandAllowlistError(
            result.reason or "COMMAND_NOT_ALLOWED"
        )
