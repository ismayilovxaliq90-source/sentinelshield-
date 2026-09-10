from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Optional, Sequence


DEFAULT_MAX_ARGUMENTS = 64
DEFAULT_MAX_ARGUMENT_LENGTH = 4096

# Shell/control syntax that must never be accepted as an execution argument.
_SHELL_METACHARACTERS = frozenset(
    {
        ";",
        "&",
        "|",
        "`",
        "$",
        ">",
        "<",
        "\n",
        "\r",
    }
)

# Common shell substitution / command chaining patterns.
_DANGEROUS_PATTERNS = (
    re.compile(r"\$\("),
    re.compile(r"\$\{"),
    re.compile(r"`"),
    re.compile(r"&&"),
    re.compile(r"\|\|"),
    re.compile(r";"),
    re.compile(r">>"),
    re.compile(r"<<"),
)


class CommandArgumentValidationError(ValueError):
    """Raised when command arguments are structurally invalid."""


@dataclass(frozen=True)
class CommandArgumentPolicy:
    """
    Security policy for command argument validation.

    The policy validates tokens only. It never executes a command.
    """

    max_arguments: int = DEFAULT_MAX_ARGUMENTS
    max_argument_length: int = DEFAULT_MAX_ARGUMENT_LENGTH
    allow_empty_arguments: bool = False
    reject_path_traversal: bool = True

    def __post_init__(self) -> None:
        if (
            isinstance(self.max_arguments, bool)
            or not isinstance(self.max_arguments, int)
        ):
            raise TypeError("max_arguments must be int")

        if (
            isinstance(self.max_argument_length, bool)
            or not isinstance(self.max_argument_length, int)
        ):
            raise TypeError("max_argument_length must be int")

        if self.max_arguments < 1:
            raise CommandArgumentValidationError(
                "max_arguments must be >= 1"
            )

        if self.max_argument_length < 1:
            raise CommandArgumentValidationError(
                "max_argument_length must be >= 1"
            )

        if not isinstance(self.allow_empty_arguments, bool):
            raise TypeError("allow_empty_arguments must be bool")

        if not isinstance(self.reject_path_traversal, bool):
            raise TypeError("reject_path_traversal must be bool")


@dataclass(frozen=True)
class CommandArgumentResult:
    allowed: bool
    command: Optional[str]
    arguments: tuple[str, ...]
    reason: str
    rejected_index: Optional[int]
    argument_count: int

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "command": self.command,
            "arguments": list(self.arguments),
            "reason": self.reason,
            "rejected_index": self.rejected_index,
            "argument_count": self.argument_count,
        }


def _is_control_character(value: str) -> bool:
    """
    Reject ASCII control characters.

    Space (0x20) and above are allowed. DEL (0x7f) is also rejected.
    """
    return any(
        ord(character) < 0x20 or ord(character) == 0x7F
        for character in value
    )


def _contains_shell_syntax(value: str) -> bool:
    if any(character in value for character in _SHELL_METACHARACTERS):
        return True

    return any(pattern.search(value) for pattern in _DANGEROUS_PATTERNS)


def _contains_path_traversal(value: str) -> bool:
    """
    Detect explicit path traversal components.

    Both POSIX and Windows separators are checked because command
    arguments can be passed across different runner environments.
    """
    normalized = value.replace("\\", "/")

    components = normalized.split("/")

    return any(component == ".." for component in components)


def _validate_argument(
    argument: object,
    index: int,
    policy: CommandArgumentPolicy,
) -> Optional[str]:
    if not isinstance(argument, str):
        return "ARGUMENT_NOT_STRING"

    if "\x00" in argument:
        return "NULL_CHARACTER_NOT_ALLOWED"

    if _is_control_character(argument):
        return "CONTROL_CHARACTER_NOT_ALLOWED"

    if len(argument) > policy.max_argument_length:
        return "ARGUMENT_TOO_LONG"

    if not argument and not policy.allow_empty_arguments:
        return "EMPTY_ARGUMENT_NOT_ALLOWED"

    if _contains_shell_syntax(argument):
        return "SHELL_SYNTAX_NOT_ALLOWED"

    if (
        policy.reject_path_traversal
        and _contains_path_traversal(argument)
    ):
        return "PATH_TRAVERSAL_NOT_ALLOWED"

    return None


def validate_command_arguments(
    command: object,
    arguments: Sequence[str] | Iterable[str],
    policy: CommandArgumentPolicy | None = None,
) -> CommandArgumentResult:
    """
    Validate command arguments without executing anything.

    Important security properties:
      - command is a separate token
      - arguments are separate tokens
      - no shell parsing is performed
      - no subprocess is created
      - no filesystem changes are performed
      - no environment changes are performed
    """
    active_policy = policy or CommandArgumentPolicy()

    if not isinstance(command, str):
        return CommandArgumentResult(
            allowed=False,
            command=None,
            arguments=(),
            reason="COMMAND_NOT_STRING",
            rejected_index=None,
            argument_count=0,
        )

    if not command:
        return CommandArgumentResult(
            allowed=False,
            command=None,
            arguments=(),
            reason="COMMAND_EMPTY",
            rejected_index=None,
            argument_count=0,
        )

    if "\x00" in command:
        return CommandArgumentResult(
            allowed=False,
            command=None,
            arguments=(),
            reason="COMMAND_NULL_CHARACTER_NOT_ALLOWED",
            rejected_index=None,
            argument_count=0,
        )

    if _is_control_character(command):
        return CommandArgumentResult(
            allowed=False,
            command=None,
            arguments=(),
            reason="COMMAND_CONTROL_CHARACTER_NOT_ALLOWED",
            rejected_index=None,
            argument_count=0,
        )

    if _contains_shell_syntax(command):
        return CommandArgumentResult(
            allowed=False,
            command=None,
            arguments=(),
            reason="COMMAND_SHELL_SYNTAX_NOT_ALLOWED",
            rejected_index=None,
            argument_count=0,
        )

    if not isinstance(arguments, Iterable):
        return CommandArgumentResult(
            allowed=False,
            command=command,
            arguments=(),
            reason="ARGUMENTS_NOT_ITERABLE",
            rejected_index=None,
            argument_count=0,
        )

    # Strings are iterable but are not valid argument lists.
    if isinstance(arguments, (str, bytes, bytearray)):
        return CommandArgumentResult(
            allowed=False,
            command=command,
            arguments=(),
            reason="ARGUMENTS_MUST_BE_SEQUENCE",
            rejected_index=None,
            argument_count=0,
        )

    try:
        materialized = tuple(arguments)
    except (TypeError, ValueError):
        return CommandArgumentResult(
            allowed=False,
            command=command,
            arguments=(),
            reason="ARGUMENTS_CANNOT_BE_MATERIALIZED",
            rejected_index=None,
            argument_count=0,
        )

    if len(materialized) > active_policy.max_arguments:
        return CommandArgumentResult(
            allowed=False,
            command=command,
            arguments=materialized,
            reason="TOO_MANY_ARGUMENTS",
            rejected_index=active_policy.max_arguments,
            argument_count=len(materialized),
        )

    for index, argument in enumerate(materialized):
        reason = _validate_argument(
            argument=argument,
            index=index,
            policy=active_policy,
        )

        if reason is not None:
            return CommandArgumentResult(
                allowed=False,
                command=command,
                arguments=materialized,
                reason=reason,
                rejected_index=index,
                argument_count=len(materialized),
            )

    return CommandArgumentResult(
        allowed=True,
        command=command,
        arguments=materialized,
        reason="COMMAND_ARGUMENTS_VALID",
        rejected_index=None,
        argument_count=len(materialized),
    )


def validate_command_vector(
    command_vector: Sequence[str],
    policy: CommandArgumentPolicy | None = None,
) -> CommandArgumentResult:
    """
    Validate a complete argv-style vector.

    Example:
        ("python", "-m", "pytest", "-q")

    The first token is treated as the command and all remaining
    tokens are treated as arguments.
    """
    if isinstance(command_vector, (str, bytes, bytearray)):
        return CommandArgumentResult(
            allowed=False,
            command=None,
            arguments=(),
            reason="COMMAND_VECTOR_MUST_BE_SEQUENCE",
            rejected_index=None,
            argument_count=0,
        )

    try:
        vector = tuple(command_vector)
    except (TypeError, ValueError):
        return CommandArgumentResult(
            allowed=False,
            command=None,
            arguments=(),
            reason="COMMAND_VECTOR_INVALID",
            rejected_index=None,
            argument_count=0,
        )

    if not vector:
        return CommandArgumentResult(
            allowed=False,
            command=None,
            arguments=(),
            reason="COMMAND_VECTOR_EMPTY",
            rejected_index=None,
            argument_count=0,
        )

    command = vector[0]

    return validate_command_arguments(
        command=command,
        arguments=vector[1:],
        policy=policy,
    )


def require_valid_command_arguments(
    command: object,
    arguments: Sequence[str] | Iterable[str],
    policy: CommandArgumentPolicy | None = None,
) -> CommandArgumentResult:
    """
    Fail closed when command arguments do not satisfy the policy.
    """
    result = validate_command_arguments(
        command=command,
        arguments=arguments,
        policy=policy,
    )

    if not result.allowed:
        raise CommandArgumentValidationError(result.reason)

    return result
