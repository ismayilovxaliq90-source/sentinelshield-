from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Iterable, Mapping, Sequence


class SecretExposureError(ValueError):
    """Raised when secret-exposure validation cannot be performed safely."""


_SECRET_NAME_MARKERS = (
    "PASSWORD",
    "PASSWD",
    "SECRET",
    "TOKEN",
    "API_KEY",
    "APIKEY",
    "PRIVATE_KEY",
    "PRIVATEKEY",
    "CREDENTIAL",
    "CREDENTIALS",
    "AUTH",
    "ACCESS_KEY",
    "ACCESSKEY",
)

_REDACTED = "[REDACTED]"


@dataclass(frozen=True)
class SecretExposurePolicy:
    reject_secret_named_environment: bool = True
    reject_control_characters: bool = True
    max_command_argument_length: int = 4096
    max_environment_name_length: int = 256
    max_environment_value_length: int = 8192
    redaction_marker: str = _REDACTED

    def __post_init__(self) -> None:
        if isinstance(self.max_command_argument_length, bool):
            raise TypeError("max_command_argument_length must be an integer")

        if isinstance(self.max_environment_name_length, bool):
            raise TypeError("max_environment_name_length must be an integer")

        if isinstance(self.max_environment_value_length, bool):
            raise TypeError("max_environment_value_length must be an integer")

        if not isinstance(self.max_command_argument_length, int):
            raise TypeError("max_command_argument_length must be an integer")

        if not isinstance(self.max_environment_name_length, int):
            raise TypeError("max_environment_name_length must be an integer")

        if not isinstance(self.max_environment_value_length, int):
            raise TypeError("max_environment_value_length must be an integer")

        if self.max_command_argument_length <= 0:
            raise ValueError("max_command_argument_length must be positive")

        if self.max_environment_name_length <= 0:
            raise ValueError("max_environment_name_length must be positive")

        if self.max_environment_value_length <= 0:
            raise ValueError("max_environment_value_length must be positive")

        if not isinstance(self.redaction_marker, str):
            raise TypeError("redaction_marker must be a string")

        if not self.redaction_marker:
            raise ValueError("redaction_marker must not be empty")

        if any(
            ord(char) < 32 or ord(char) == 127
            for char in self.redaction_marker
        ):
            raise ValueError("redaction_marker contains control characters")


@dataclass(frozen=True)
class SecretExposureResult:
    safe: bool
    failures: tuple[str, ...]
    redacted_command: tuple[str, ...]
    redacted_environment: Mapping[str, str]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "redacted_command",
            tuple(self.redacted_command),
        )
        object.__setattr__(
            self,
            "redacted_environment",
            MappingProxyType(dict(self.redacted_environment)),
        )

    @property
    def exposed(self) -> bool:
        return not self.safe


def _validate_text(
    value: str,
    *,
    field: str,
    reject_control_characters: bool,
) -> list[str]:
    failures: list[str] = []

    if reject_control_characters:
        for char in value:
            code = ord(char)

            if code == 0:
                failures.append(f"{field}:NULL_CHARACTER")
                break

            if code < 32 or code == 127:
                failures.append(f"{field}:CONTROL_CHARACTER")
                break

    return failures


def _is_secret_name(name: str) -> bool:
    normalized = name.upper()

    return any(marker in normalized for marker in _SECRET_NAME_MARKERS)


def _safe_secret_values(
    secret_values: Iterable[str] | None,
) -> tuple[str, ...]:
    if secret_values is None:
        return ()

    if isinstance(secret_values, (str, bytes)):
        raise TypeError("secret_values must be an iterable of strings")

    values: list[str] = []

    for value in secret_values:
        if not isinstance(value, str):
            raise TypeError("every secret value must be a string")

        if value:
            values.append(value)

    return tuple(dict.fromkeys(values))


def _redact_text(
    value: str,
    secret_values: tuple[str, ...],
    marker: str,
) -> str:
    result = value

    for secret in sorted(secret_values, key=len, reverse=True):
        result = result.replace(secret, marker)

    return result


def validate_secret_exposure(
    command: Sequence[str],
    environment: Mapping[str, str],
    *,
    secret_values: Iterable[str] | None = None,
    policy: SecretExposurePolicy | None = None,
) -> SecretExposureResult:
    """
    Validate that command arguments and environment cannot expose secrets.

    This function performs validation only. It never executes a command and
    never mutates the supplied command or environment.
    """

    if policy is None:
        policy = SecretExposurePolicy()

    if isinstance(command, (str, bytes)):
        raise TypeError("command must be a sequence of string arguments")

    if not isinstance(environment, Mapping):
        raise TypeError("environment must be a mapping")

    secret_values_tuple = _safe_secret_values(secret_values)

    failures: list[str] = []
    redacted_command: list[str] = []

    for index, argument in enumerate(command):
        if not isinstance(argument, str):
            raise TypeError("every command argument must be a string")

        if len(argument) > policy.max_command_argument_length:
            failures.append(
                f"COMMAND_ARGUMENT_TOO_LONG:{index}"
            )

        failures.extend(
            _validate_text(
                argument,
                field=f"COMMAND_ARGUMENT:{index}",
                reject_control_characters=policy.reject_control_characters,
            )
        )

        if any(secret and secret in argument for secret in secret_values_tuple):
            failures.append(
                f"SECRET_EXPOSED_IN_COMMAND:{index}"
            )

        redacted_command.append(
            _redact_text(
                argument,
                secret_values_tuple,
                policy.redaction_marker,
            )
        )

    redacted_environment: dict[str, str] = {}

    for name, value in environment.items():
        if not isinstance(name, str):
            raise TypeError("environment variable names must be strings")

        if not isinstance(value, str):
            raise TypeError("environment variable values must be strings")

        if len(name) > policy.max_environment_name_length:
            failures.append(
                f"ENVIRONMENT_NAME_TOO_LONG:{name}"
            )

        if len(value) > policy.max_environment_value_length:
            failures.append(
                f"ENVIRONMENT_VALUE_TOO_LONG:{name}"
            )

        failures.extend(
            _validate_text(
                name,
                field=f"ENVIRONMENT_NAME:{name}",
                reject_control_characters=policy.reject_control_characters,
            )
        )

        failures.extend(
            _validate_text(
                value,
                field=f"ENVIRONMENT_VALUE:{name}",
                reject_control_characters=policy.reject_control_characters,
            )
        )

        if (
            policy.reject_secret_named_environment
            and _is_secret_name(name)
        ):
            if value:
                failures.append(
                    f"SECRET_NAMED_ENVIRONMENT:{name}"
                )

        if any(secret and secret in value for secret in secret_values_tuple):
            failures.append(
                f"SECRET_EXPOSED_IN_ENVIRONMENT:{name}"
            )

        redacted_environment[name] = _redact_text(
            value,
            secret_values_tuple,
            policy.redaction_marker,
        )

    unique_failures = tuple(dict.fromkeys(failures))

    return SecretExposureResult(
        safe=not unique_failures,
        failures=unique_failures,
        redacted_command=tuple(redacted_command),
        redacted_environment=redacted_environment,
    )


def validate_secret_exposure_vector(
    command: Sequence[str],
    environment: Mapping[str, str],
    *,
    secret_values: Iterable[str] | None = None,
    policy: SecretExposurePolicy | None = None,
) -> SecretExposureResult:
    return validate_secret_exposure(
        command,
        environment,
        secret_values=secret_values,
        policy=policy,
    )


def require_no_secret_exposure(
    command: Sequence[str],
    environment: Mapping[str, str],
    *,
    secret_values: Iterable[str] | None = None,
    policy: SecretExposurePolicy | None = None,
) -> SecretExposureResult:
    result = validate_secret_exposure(
        command,
        environment,
        secret_values=secret_values,
        policy=policy,
    )

    if not result.safe:
        raise SecretExposureError(
            "Secret exposure validation failed: "
            + ", ".join(result.failures)
        )

    return result
