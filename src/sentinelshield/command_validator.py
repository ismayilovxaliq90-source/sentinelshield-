from __future__ import annotations

import shlex
from dataclasses import dataclass


class CommandValidationError(ValueError):
    """Raised when a command violates SentinelShield command policy."""


@dataclass(frozen=True)
class ValidatedCommand:
    program: str
    arguments: tuple[str, ...]

    @property
    def argv(self) -> tuple[str, ...]:
        return (self.program, *self.arguments)


class CommandValidator:
    """
    Minimum Safe Core command validator.

    The validator performs policy checks before a command is allowed
    to reach the execution layer.
    """

    DEFAULT_ALLOWED_COMMANDS = frozenset(
        {
            "python",
            "python3",
            "pytest",
            "git",
        }
    )

    BLOCKED_TOKENS = frozenset(
        {
            ";",
            "&&",
            "||",
            "|",
            ">",
            ">>",
            "<",
            "<<",
            "`",
            "$(",
            "${",
        }
    )

    def __init__(
        self,
        allowed_commands: set[str] | frozenset[str] | None = None,
    ) -> None:
        self.allowed_commands = frozenset(
            allowed_commands
            if allowed_commands is not None
            else self.DEFAULT_ALLOWED_COMMANDS
        )

    def validate(self, command: str) -> ValidatedCommand:
        if not isinstance(command, str):
            raise CommandValidationError("command must be a string")

        command = command.strip()

        if not command:
            raise CommandValidationError("empty command is not allowed")

        self._check_blocked_tokens(command)

        try:
            argv = shlex.split(command, posix=True)
        except ValueError as exc:
            raise CommandValidationError(
                f"invalid command syntax: {exc}"
            ) from exc

        if not argv:
            raise CommandValidationError("empty command is not allowed")

        program = argv[0]

        if program not in self.allowed_commands:
            raise CommandValidationError(
                f"command is not allowed: {program}"
            )

        arguments = tuple(argv[1:])

        self._validate_arguments(arguments)

        return ValidatedCommand(
            program=program,
            arguments=arguments,
        )

    def _check_blocked_tokens(self, command: str) -> None:
        for token in self.BLOCKED_TOKENS:
            if token in command:
                raise CommandValidationError(
                    f"blocked shell operator: {token}"
                )

    def _validate_arguments(self, arguments: tuple[str, ...]) -> None:
        for argument in arguments:
            if "\x00" in argument:
                raise CommandValidationError(
                    "NUL byte is not allowed in command arguments"
                )

            if argument.startswith("~"):
                raise CommandValidationError(
                    "home-directory expansion is not allowed"
                )

            if argument.startswith("$"):
                raise CommandValidationError(
                    "environment expansion is not allowed"
                )

    def is_safe(self, command: str) -> bool:
        try:
            self.validate(command)
        except CommandValidationError:
            return False
        return True
