from __future__ import annotations

from dataclasses import dataclass
import re
from types import MappingProxyType
from typing import Mapping


class EnvironmentVariableValidationError(ValueError):
    """Raised when environment-variable validation fails."""


@dataclass(frozen=True)
class EnvironmentVariablePolicy:
    allowed_names: frozenset[str]
    required_names: frozenset[str] = frozenset()
    max_name_length: int = 256
    max_value_length: int = 8192
    reject_secret_like_names: bool = True
    reject_control_characters: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.allowed_names, frozenset):
            object.__setattr__(
                self,
                "allowed_names",
                frozenset(self.allowed_names),
            )

        if not isinstance(self.required_names, frozenset):
            object.__setattr__(
                self,
                "required_names",
                frozenset(self.required_names),
            )

        if self.max_name_length <= 0:
            raise ValueError("max_name_length must be positive")

        if self.max_value_length < 0:
            raise ValueError("max_value_length must not be negative")

        unknown_required = self.required_names - self.allowed_names
        if unknown_required:
            raise ValueError(
                "required_names must be contained in allowed_names"
            )


@dataclass(frozen=True)
class EnvironmentVariableValidationResult:
    valid: bool
    environment: Mapping[str, str]
    failures: tuple[str, ...]


_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

_SECRET_NAME_PATTERNS = (
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


def _contains_control(value: str) -> bool:
    return any(
        ord(character) < 32 or ord(character) == 127
        for character in value
    )


def _is_secret_like(name: str) -> bool:
    upper = name.upper()

    return any(
        pattern in upper
        for pattern in _SECRET_NAME_PATTERNS
    )


def _failure(
    failures: list[str],
    code: str,
) -> None:
    if code not in failures:
        failures.append(code)


def validate_environment_variables(
    environment: Mapping[str, str],
    policy: EnvironmentVariablePolicy,
) -> EnvironmentVariableValidationResult:
    failures: list[str] = {}
    normalized: dict[str, str] = {}

    if not isinstance(environment, Mapping):
        return EnvironmentVariableValidationResult(
            valid=False,
            environment=MappingProxyType({}),
            failures=("INVALID_ENVIRONMENT_TYPE",),
        )

    for name, value in environment.items():
        if not isinstance(name, str):
            _failure(failures, "INVALID_VARIABLE_NAME_TYPE")
            continue

        if len(name) == 0:
            _failure(failures, "EMPTY_VARIABLE_NAME")
            continue

        if len(name) > policy.max_name_length:
            _failure(failures, "VARIABLE_NAME_TOO_LONG")
            continue

        if not _NAME_RE.fullmatch(name):
            _failure(failures, "INVALID_VARIABLE_NAME")
            continue

        if policy.reject_control_characters and _contains_control(name):
            _failure(failures, "CONTROL_CHARACTER_IN_NAME")
            continue

        if name not in policy.allowed_names:
            _failure(failures, "VARIABLE_NOT_ALLOWED")
            continue

        if (
            policy.reject_secret_like_names
            and _is_secret_like(name)
        ):
            _failure(failures, "SECRET_LIKE_VARIABLE_REJECTED")
            continue

        if not isinstance(value, str):
            _failure(failures, "INVALID_VARIABLE_VALUE_TYPE")
            continue

        if len(value) > policy.max_value_length:
            _failure(failures, "VARIABLE_VALUE_TOO_LONG")
            continue

        if policy.reject_control_characters and _contains_control(value):
            _failure(failures, "CONTROL_CHARACTER_IN_VALUE")
            continue

        normalized[name] = value

    missing = policy.required_names - normalized.keys()

    if missing:
        _failure(failures, "REQUIRED_VARIABLE_MISSING")

    return EnvironmentVariableValidationResult(
        valid=not failures,
        environment=MappingProxyType(dict(normalized)),
        failures=tuple(failures),
    )


def validate_environment(
    environment: Mapping[str, str],
    allowed_names: frozenset[str],
    required_names: frozenset[str] = frozenset(),
) -> EnvironmentVariableValidationResult:
    policy = EnvironmentVariablePolicy(
        allowed_names=frozenset(allowed_names),
        required_names=frozenset(required_names),
    )

    return validate_environment_variables(
        environment,
        policy,
    )


def require_valid_environment(
    environment: Mapping[str, str],
    policy: EnvironmentVariablePolicy,
) -> Mapping[str, str]:
    result = validate_environment_variables(
        environment,
        policy,
    )

    if not result.valid:
        raise EnvironmentVariableValidationError(
            ";".join(result.failures)
        )

    return result.environment


__all__ = [
    "EnvironmentVariableValidationError",
    "EnvironmentVariablePolicy",
    "EnvironmentVariableValidationResult",
    "validate_environment_variables",
    "validate_environment",
    "require_valid_environment",
]
