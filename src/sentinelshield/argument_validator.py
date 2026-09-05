from __future__ import annotations

from dataclasses import dataclass


class ArgumentValidationError(ValueError):
    """Raised when a command argument violates SentinelShield policy."""


@dataclass(frozen=True)
class ValidatedArguments:
    arguments: tuple[str, ...]

    @property
    def values(self) -> tuple[str, ...]:
        return self.arguments


class ArgumentValidator:
    """
    Validates command arguments independently from the command name.

    This layer does not execute anything.
    It only applies deterministic argument safety rules.
    """

    MAX_ARGUMENTS = 128
    MAX_ARGUMENT_LENGTH = 4096

    BLOCKED_ARGUMENTS = frozenset(
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
        }
    )

    def validate(
        self,
        arguments: list[str] | tuple[str, ...],
    ) -> ValidatedArguments:

        if not isinstance(arguments, (list, tuple)):
            raise ArgumentValidationError(
                "arguments must be a list or tuple"
            )

        if len(arguments) > self.MAX_ARGUMENTS:
            raise ArgumentValidationError(
                f"too many arguments: {len(arguments)}"
            )

        validated: list[str] = []

        for argument in arguments:
            if not isinstance(argument, str):
                raise ArgumentValidationError(
                    "every argument must be a string"
                )

            if "\x00" in argument:
                raise ArgumentValidationError(
                    "NUL byte is not allowed"
                )

            if len(argument) > self.MAX_ARGUMENT_LENGTH:
                raise ArgumentValidationError(
                    "argument exceeds maximum length"
                )

            if argument in self.BLOCKED_ARGUMENTS:
                raise ArgumentValidationError(
                    f"blocked argument: {argument}"
                )

            if argument.startswith("$"):
                raise ArgumentValidationError(
                    "environment expansion is not allowed"
                )

            if argument.startswith("~"):
                raise ArgumentValidationError(
                    "home-directory expansion is not allowed"
                )

            if "\n" in argument or "\r" in argument:
                raise ArgumentValidationError(
                    "newline characters are not allowed"
                )

            validated.append(argument)

        return ValidatedArguments(
            arguments=tuple(validated)
        )

    def is_safe(
        self,
        arguments: list[str] | tuple[str, ...],
    ) -> bool:
        try:
            self.validate(arguments)
        except ArgumentValidationError:
            return False

        return True
