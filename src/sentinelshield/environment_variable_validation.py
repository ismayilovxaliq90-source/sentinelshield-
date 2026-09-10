from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping
import re


class EnvironmentVariableValidationError(ValueError):
    """Raised when an environment mapping violates the validation policy."""


@dataclass(frozen=True)
class EnvironmentVariablePolicy:
    """
    Security policy for execution environment variables.

    The default policy is intentionally restrictive:
    - variables must be explicitly allowlisted;
    - secret-like variable names are rejected;
    - names and values have bounded sizes;
    - required variables must exist.
    """

    allowed_names: frozenset[str] = field(default_factory=frozenset)
    required_names: frozenset[str] = field(default_factory=frozenset)

    reject_secret_names: bool = True
    reject_control_characters: bool = True

    max_name_length: int = 256
    max_value_length: int = 8192

    secret_name_patterns: tuple[str, ...] = (
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


@dataclass(frozen=True)
class EnvironmentVariableValidationResult:
    """Immutable result of environment-variable validation."""

    valid: bool
    environment: Mapping[str, str]
    failures: tuple[str, ...]
    accepted_names: tuple[str, ...]
    rejected_names: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "valid": self.valid,
            "environment": dict(self.environment),
            "failures": list(self.failures),
            "accepted_names": list(self.accepted_names),
            "rejected_names": list(self.rejected_names),
        }


_NAME_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

_CONTROL_CHARACTER_PATTERN = re.compile(
    r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]"
)


def _contains_control_characters(value: str) -> bool:
    return bool(_CONTROL_CHARACTER_PATTERN.search(value))


def _is_secret_name(
    name: str,
    policy: EnvironmentVariablePolicy,
) -> bool:
    upper_name = name.upper()

    for pattern in policy.secret_name_patterns:
        if pattern in upper_name:
            return True

    return False


def _validate_policy(policy: EnvironmentVariablePolicy) -> list[str]:
    failures: list[str] = []

    if not isinstance(policy, EnvironmentVariablePolicy):
        failures.append("INVALID_POLICY")
        return failures

    if policy.max_name_length <= 0:
        failures.append("INVALID_MAX_NAME_LENGTH")

    if policy.max_value_length <= 0:
        failures.append("INVALID_MAX_VALUE_LENGTH")

    if not isinstance(policy.allowed_names, frozenset):
        failures.append("INVALID_ALLOWED_NAMES_TYPE")

    if not isinstance(policy.required_names, frozenset):
        failures.append("INVALID_REQUIRED_NAMES_TYPE")

    if not policy.required_names.issubset(policy.allowed_names):
        failures.append("REQUIRED_NAME_NOT_ALLOWLISTED")

    return failures


def validate_environment_variables(
    environment: Mapping[str, str] | None,
    policy: EnvironmentVariablePolicy | None = None,
) -> EnvironmentVariableValidationResult:
    """
    Validate an environment mapping without executing anything.

    No subprocess, filesystem modification, installation, or environment
    mutation is performed by this function.
    """

    if policy is None:
        policy = EnvironmentVariablePolicy()

    failures: list[str] = []
    accepted_names: list[str] = []
    rejected_names: list[str] = []

    failures.extend(_validate_policy(policy))

    if environment is None:
        failures.append("ENVIRONMENT_IS_NONE")

        return EnvironmentVariableValidationResult(
            valid=False,
            environment=MappingProxyType({}),
            failures=tuple(failures),
            accepted_names=(),
            rejected_names=(),
        )

    if not isinstance(environment, Mapping):
        failures.append("INVALID_ENVIRONMENT_TYPE")

        return EnvironmentVariableValidationResult(
            valid=False,
            environment=MappingProxyType({}),
            failures=tuple(failures),
            accepted_names=(),
            rejected_names=(),
        )

    validated: dict[str, str] = {}

    for name, value in environment.items():
        name_failed = False

        if not isinstance(name, str):
            failures.append("VARIABLE_NAME_NOT_STRING")
            rejected_names.append(repr(name))
            continue

        if len(name) > policy.max_name_length:
            failures.append(f"VARIABLE_NAME_TOO_LONG:{name}")
            rejected_names.append(name)
            continue

        if not name:
            failures.append("VARIABLE_NAME_EMPTY")
            rejected_names.append(name)
            continue

        if not _NAME_PATTERN.fullmatch(name):
            failures.append(f"INVALID_VARIABLE_NAME:{name}")
            rejected_names.append(name)
            continue

        if policy.reject_control_characters and _contains_control_characters(name):
            failures.append(f"CONTROL_CHARACTER_IN_NAME:{name}")
            rejected_names.append(name)
            continue

        if name not in policy.allowed_names:
            failures.append(f"VARIABLE_NOT_ALLOWLISTED:{name}")
            rejected_names.append(name)
            continue

        if policy.reject_secret_names and _is_secret_name(name, policy):
            failures.append(f"SECRET_VARIABLE_REJECTED:{name}")
            rejected_names.append(name)
            continue

        if not isinstance(value, str):
            failures.append(f"VARIABLE_VALUE_NOT_STRING:{name}")
            rejected_names.append(name)
            continue

        if len(value) > policy.max_value_length:
            failures.append(f"VARIABLE_VALUE_TOO_LONG:{name}")
            rejected_names.append(name)
            continue

        if policy.reject_control_characters and _contains_control_characters(value):
            failures.append(f"CONTROL_CHARACTER_IN_VALUE:{name}")
            rejected_names.append(name)
            continue

        validated[name] = value
        accepted_names.append(name)

    for required_name in sorted(policy.required_names):
        if required_name not in environment:
            failures.append(f"REQUIRED_VARIABLE_MISSING:{required_name}")
            continue

        if required_name not in validated:
            failures.append(f"REQUIRED_VARIABLE_INVALID:{required_name}")

    return EnvironmentVariableValidationResult(
        valid=not failures,
        environment=MappingProxyType(dict(validated)),
        failures=tuple(failures),
        accepted_names=tuple(sorted(accepted_names)),
        rejected_names=tuple(rejected_names),
    )


def validate_environment(
    environment: Mapping[str, str] | None,
    allowed_names: set[str] | frozenset[str] | None = None,
    required_names: set[str] | frozenset[str] | None = None,
    *,
    reject_secret_names: bool = True,
    reject_control_characters: bool = True,
    max_name_length: int = 256,
    max_value_length: int = 8192,
) -> EnvironmentVariableValidationResult:
    """
    Convenience API for callers that do not need to construct a policy
    explicitly.
    """

    policy = EnvironmentVariablePolicy(
        allowed_names=frozenset(allowed_names or ()),
        required_names=frozenset(required_names or ()),
        reject_secret_names=reject_secret_names,
        reject_control_characters=reject_control_characters,
        max_name_length=max_name_length,
        max_value_length=max_value_length,
    )

    return validate_environment_variables(environment, policy)


def require_valid_environment(
    environment: Mapping[str, str] | None,
    policy: EnvironmentVariablePolicy | None = None,
) -> Mapping[str, str]:
    """
    Validate and return an immutable environment.

    Raises EnvironmentVariableValidationError on failure.
    """

    result = validate_environment_variables(environment, policy)

    if not result.valid:
        raise EnvironmentVariableValidationError(
            "; ".join(result.failures)
        )

    return result.environment
