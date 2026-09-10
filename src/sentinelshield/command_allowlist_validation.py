from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence


class CommandAllowlistError(ValueError):
    """Raised when the command allowlist policy is invalid."""


# Explicitly allowed executable names.
# Arguments are deliberately NOT validated here; that is Task 189.
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

# Characters which must never appear in the executable token.
# This prevents the executable field itself from becoming a shell-like
# command expression or an executable path.
_FORBIDDEN_EXECUTABLE_CHARS = frozenset(
    {
        "\x00",
        "\n",
        "\r",
        "\t",
        ";",
        "&",
        "|",
        ">",
        "<",
        "`",
        "$",
        "(",
        ")",
        "{",
        "}",
        "[",
        "]",
        "'",
        '"',
        "\\",
        "/",
    }
)


@dataclass(frozen=True)
class CommandAllowlistPolicy:
    """
    Immutable command executable allowlist.

    This policy controls executable identity only.
    Command arguments are intentionally handled by Task 189.
    """

    allowed_executables: frozenset[str] = DEFAULT_ALLOWED_EXECUTABLES

    def __post_init__(self) -> None:
        if not isinstance(self.allowed_executables, frozenset):
            raise TypeError("allowed_executables must be frozenset")

        if not self.allowed_executables:
            raise CommandAllowlistError(
                "allowed_executables cannot be empty"
            )

        normalized: set[str] = set()

        for executable in self.allowed_executables:
            if not isinstance(executable, str):
                raise TypeError(
                    "every allowed executable must be a string"
                )

            if not executable:
                raise CommandAllowlistError(
                    "allowed executable cannot be empty"
                )

            if executable != executable.strip():
                raise CommandAllowlistError(
                    "allowed executable cannot contain surrounding whitespace"
                )

            if executable.lower() != executable:
                raise CommandAllowlistError(
                    "allowed executable must be lowercase"
                )

            if any(
                character in _FORBIDDEN_EXECUTABLE_CHARS
                for character in executable
            ):
                raise CommandAllowlistError(
                    f"invalid executable token: {executable!r}"
                )

            normalized.add(executable)

        if normalized != set(self.allowed_executables):
            raise CommandAllowlistError(
                "allowed executable normalization mismatch"
            )

    def contains(self, executable: str) -> bool:
        return executable in self.allowed_executables


@dataclass(frozen=True)
class CommandAllowlistResult:
    allowed: bool
    executable: str | None
    reason: str
    policy: CommandAllowlistPolicy

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "executable": self.executable,
            "reason": self.reason,
            "policy": {
                "allowed_executables": sorted(
                    self.policy.allowed_executables
                )
            },
        }


def _invalid_result(
    reason: str,
    policy: CommandAllowlistPolicy,
    executable: str | None = None,
) -> CommandAllowlistResult:
    return CommandAllowlistResult(
        allowed=False,
        executable=executable,
        reason=reason,
        policy=policy,
    )


def _validate_executable_token(executable: object) -> str:
    if not isinstance(executable, str):
        raise TypeError("executable must be a string")

    if not executable:
        raise CommandAllowlistError(
            "executable cannot be empty"
        )

    if executable != executable.strip():
        raise CommandAllowlistError(
            "executable cannot contain surrounding whitespace"
        )

    if any(
        character in _FORBIDDEN_EXECUTABLE_CHARS
        for character in executable
    ):
        raise CommandAllowlistError(
            "executable contains forbidden characters"
        )

    # Executable must be a simple command name, never a filesystem path.
    if executable in {".", ".."}:
        raise CommandAllowlistError(
            "relative path executable is not allowed"
        )

    # Shell-like whitespace inside executable token is forbidden.
    if any(character.isspace() for character in executable):
        raise CommandAllowlistError(
            "executable cannot contain whitespace"
        )

    # Allowlist entries are intentionally exact and case-sensitive.
    return executable


def validate_command_allowlist(
    command: Sequence[str] | Iterable[str],
    policy: CommandAllowlistPolicy | None = None,
) -> CommandAllowlistResult:
    """
    Validate only the executable portion of a command.

    Security properties:
    - command must be an argument sequence, never a shell string;
    - executable must be a simple executable name;
    - executable must be explicitly allowlisted;
    - no command is executed;
    - arguments are not interpreted or executed.

    Argument validation belongs to Task 189.
    """
    active_policy = policy or CommandAllowlistPolicy()

    if isinstance(command, (str, bytes, bytearray)):
        return _invalid_result(
            "COMMAND_MUST_BE_ARGUMENT_SEQUENCE",
            active_policy,
        )

    if not isinstance(command, Sequence):
        try:
            command = tuple(command)
        except TypeError:
            return _invalid_result(
                "COMMAND_MUST_BE_ARGUMENT_SEQUENCE",
                active_policy,
            )

    if not command:
        return _invalid_result(
            "COMMAND_IS_EMPTY",
            active_policy,
        )

    executable_raw = command[0]

    try:
        executable = _validate_executable_token(executable_raw)
    except TypeError:
        return _invalid_result(
            "EXECUTABLE_TYPE_INVALID",
            active_policy,
        )
    except CommandAllowlistError as exc:
        reason = str(exc)

        if "empty" in reason:
            code = "EXECUTABLE_IS_EMPTY"
        elif "whitespace" in reason:
            code = "EXECUTABLE_WHITESPACE_FORBIDDEN"
        elif "relative path" in reason:
            code = "EXECUTABLE_PATH_FORBIDDEN"
        else:
            code = "EXECUTABLE_TOKEN_INVALID"

        return _invalid_result(
            code,
            active_policy,
        )

    if not active_policy.contains(executable):
        return _invalid_result(
            "EXECUTABLE_NOT_ALLOWLISTED",
            active_policy,
            executable,
        )

    return CommandAllowlistResult(
        allowed=True,
        executable=executable,
        reason="EXECUTABLE_ALLOWLISTED",
        policy=active_policy,
    )


def require_allowed_command(
    command: Sequence[str] | Iterable[str],
    policy: CommandAllowlistPolicy | None = None,
) -> CommandAllowlistResult:
    """
    Reject a command when its executable is not allowlisted.

    No command execution occurs.
    """
    result = validate_command_allowlist(command, policy)

    if not result.allowed:
        raise CommandAllowlistError(result.reason)

    return result
