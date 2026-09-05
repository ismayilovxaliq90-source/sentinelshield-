from __future__ import annotations

from dataclasses import dataclass
import re


class EnvironmentVariableValidationError(ValueError):
    """Raised when an environment variable violates SentinelShield policy."""


@dataclass(frozen=True)
class ValidatedEnvironment:
    variables: tuple[tuple[str, str], ...]

    @property
    def values(self) -> dict[str, str]:
        return dict(self.variables)


class EnvironmentVariableValidator:
    """
    Validates environment variables before command execution.

    This validator does not modify the process environment.
    It only validates the supplied environment mapping.
    """

    MAX_VARIABLES = 128
    MAX_NAME_LENGTH = 128
    MAX_VALUE_LENGTH = 4096

    NAME_PATTERN = re.compile(
        r"^[A-Za-z_][A-Za-z0-9_]*$"
    )

    BLOCKED_NAMES = frozenset(
        {
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "PYTHONPATH",
            "PYTHONHOME",
            "PYTHONSTARTUP",
            "BASH_ENV",
            "ENV",
        }
    )

    def validate(
        self,
        environment: dict[str, str],
    ) -> ValidatedEnvironment:

        if not isinstance(environment, dict):
            raise EnvironmentVariableValidationError(
                "environment must be a dictionary"
            )

        if len(environment) > self.MAX_VARIABLES:
            raise EnvironmentVariableValidationError(
                f"too many environment variables: {len(environment)}"
            )

        validated: list[tuple[str, str]] = []

        for name, value in environment.items():

            if not isinstance(name, str):
                raise EnvironmentVariableValidationError(
                    "environment variable name must be a string"
                )

            if not isinstance(value, str):
                raise EnvironmentVariableValidationError(
                    f"environment variable value must be a string: {name}"
                )

            if not name:
                raise EnvironmentVariableValidationError(
                    "environment variable name cannot be empty"
                )

            if len(name) > self.MAX_NAME_LENGTH:
                raise EnvironmentVariableValidationError(
                    f"environment variable name is too long: {name}"
                )

            if len(value) > self.MAX_VALUE_LENGTH:
                raise EnvironmentVariableValidationError(
                    f"environment variable value is too long: {name}"
                )

            if not self.NAME_PATTERN.fullmatch(name):
                raise EnvironmentVariableValidationError(
                    f"invalid environment variable name: {name}"
                )

            if name in self.BLOCKED_NAMES:
                raise EnvironmentVariableValidationError(
                    f"blocked environment variable: {name}"
                )

            if "\x00" in name or "\x00" in value:
                raise EnvironmentVariableValidationError(
                    f"NUL byte is not allowed: {name}"
                )

            if "\n" in value or "\r" in value:
                raise EnvironmentVariableValidationError(
                    f"newline is not allowed in environment value: {name}"
                )

            validated.append((name, value))

        return ValidatedEnvironment(
            variables=tuple(validated)
        )

    def is_safe(
        self,
        environment: dict[str, str],
    ) -> bool:
        try:
            self.validate(environment)
        except EnvironmentVariableValidationError:
            return False

        return True
