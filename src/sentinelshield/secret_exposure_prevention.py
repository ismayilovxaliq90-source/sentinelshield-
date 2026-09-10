from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping
import re


class SecretExposurePreventionError(ValueError):
    """Raised when secret-exposure validation cannot be completed safely."""


@dataclass(frozen=True)
class SecretExposurePolicy:
    """
    Policy controlling detection and masking of secret material.

    Secret names are matched case-insensitively.
    Explicit secret values are also detected when supplied.
    """

    secret_names: frozenset[str] = field(default_factory=frozenset)

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

    mask: str = "***REDACTED***"
    minimum_secret_length: int = 4
    reject_control_characters: bool = True


@dataclass(frozen=True)
class SecretExposure:
    """One detected secret exposure."""

    location: str
    reason: str
    secret_name: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        return {
            "location": self.location,
            "reason": self.reason,
            "secret_name": self.secret_name,
        }


@dataclass(frozen=True)
class SecretExposureResult:
    """Immutable secret-exposure validation result."""

    safe: bool
    exposures: tuple[SecretExposure, ...]
    redacted: Any

    @property
    def valid(self) -> bool:
        return self.safe

    def to_dict(self) -> dict[str, Any]:
        return {
            "safe": self.safe,
            "valid": self.valid,
            "exposures": [
                exposure.to_dict()
                for exposure in self.exposures
            ],
            "redacted": self.redacted,
        }


def _validate_policy(
    policy: SecretExposurePolicy,
) -> None:
    if not isinstance(policy, SecretExposurePolicy):
        raise SecretExposurePreventionError(
            "INVALID_POLICY"
        )

    if not isinstance(policy.mask, str) or not policy.mask:
        raise SecretExposurePreventionError(
            "INVALID_MASK"
        )

    if policy.minimum_secret_length < 1:
        raise SecretExposurePreventionError(
            "INVALID_MINIMUM_SECRET_LENGTH"
        )

    if policy.reject_control_characters:
        if any(
            ord(char) < 32 and char not in "\t"
            for char in policy.mask
        ):
            raise SecretExposurePreventionError(
                "CONTROL_CHARACTER_IN_MASK"
            )


def _is_secret_name(
    name: str,
    policy: SecretExposurePolicy,
) -> bool:
    upper_name = name.upper()

    explicit_names = {
        item.upper()
        for item in policy.secret_names
        if isinstance(item, str)
    }

    if upper_name in explicit_names:
        return True

    return any(
        pattern.upper() in upper_name
        for pattern in policy.secret_name_patterns
    )


def _contains_control_characters(value: str) -> bool:
    return bool(
        re.search(
            r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]",
            value,
        )
    )


def _mask_string(
    value: str,
    secrets: tuple[str, ...],
    policy: SecretExposurePolicy,
) -> tuple[str, bool]:
    result = value
    exposed = False

    for secret in secrets:
        if not isinstance(secret, str):
            continue

        if len(secret) < policy.minimum_secret_length:
            continue

        if secret and secret in result:
            result = result.replace(secret, policy.mask)
            exposed = True

    return result, exposed


def _collect_secret_values(
    environment: Mapping[str, Any] | None,
    policy: SecretExposurePolicy,
) -> tuple[tuple[str, str], tuple[str, ...]]:
    """
    Return:
      1. secret-name/value pairs
      2. secret values suitable for masking

    Values are retained only inside this function and never returned
    in exposure diagnostics.
    """

    if environment is None:
        return (), ()

    pairs: list[tuple[str, str]] = []
    values: list[str] = []

    for name, value in environment.items():
        if not isinstance(name, str):
            continue

        if _is_secret_name(name, policy):
            if isinstance(value, str) and value:
                pairs.append((name, value))
                values.append(value)

    for name in policy.secret_names:
        if not isinstance(name, str):
            continue

        if name in environment:
            value = environment[name]
            if isinstance(value, str) and value:
                if (name, value) not in pairs:
                    pairs.append((name, value))
                values.append(value)

    unique_values = tuple(
        sorted(
            set(values),
            key=lambda item: (-len(item), item),
        )
    )

    return tuple(pairs), unique_values


def _redact_value(
    value: Any,
    secrets: tuple[str, ...],
    policy: SecretExposurePolicy,
    location: str,
    exposures: list[SecretExposure],
) -> Any:
    if isinstance(value, str):
        redacted, exposed = _mask_string(
            value,
            secrets,
            policy,
        )

        if exposed:
            exposures.append(
                SecretExposure(
                    location=location,
                    reason="SECRET_VALUE_EXPOSURE",
                )
            )

        return redacted

    if isinstance(value, Mapping):
        redacted_mapping: dict[Any, Any] = {}

        for key, item in value.items():
            key_location = (
                f"{location}.{key}"
                if location
                else str(key)
            )

            if isinstance(key, str) and _is_secret_name(
                key,
                policy,
            ):
                exposures.append(
                    SecretExposure(
                        location=key_location,
                        reason="SECRET_NAME_EXPOSURE",
                        secret_name=key,
                    )
                )

                redacted_mapping[key] = policy.mask
                continue

            redacted_mapping[key] = _redact_value(
                item,
                secrets,
                policy,
                key_location,
                exposures,
            )

        return MappingProxyType(redacted_mapping)

    if isinstance(value, (list, tuple)):
        items = []

        for index, item in enumerate(value):
            item_location = (
                f"{location}[{index}]"
                if location
                else f"[{index}]"
            )

            items.append(
                _redact_value(
                    item,
                    secrets,
                    policy,
                    item_location,
                    exposures,
                )
            )

        return tuple(items) if isinstance(value, tuple) else tuple(items)

    if isinstance(value, set):
        return frozenset(
            _redact_value(
                item,
                secrets,
                policy,
                f"{location}[]",
                exposures,
            )
            for item in value
        )

    return value


def inspect_secret_exposure(
    value: Any,
    *,
    environment: Mapping[str, Any] | None = None,
    policy: SecretExposurePolicy | None = None,
    location: str = "value",
) -> SecretExposureResult:
    """
    Inspect arbitrary data for secret exposure.

    This function performs no command execution, filesystem modification,
    package installation, network access, or environment mutation.
    """

    if policy is None:
        policy = SecretExposurePolicy()

    _validate_policy(policy)

    exposures: list[SecretExposure] = []

    _, environment_secret_values = _collect_secret_values(
        environment,
        policy,
    )

    redacted_environment = _redact_value(
        environment if environment is not None else {},
        environment_secret_values,
        policy,
        "environment",
        exposures,
    )

    all_secret_values = list(environment_secret_values)

    if isinstance(value, Mapping):
        for key, item in value.items():
            if (
                isinstance(key, str)
                and _is_secret_name(key, policy)
                and isinstance(item, str)
                and item
            ):
                all_secret_values.append(item)

    unique_secrets = tuple(
        sorted(
            set(all_secret_values),
            key=lambda item: (-len(item), item),
        )
    )

    redacted_value = _redact_value(
        value,
        unique_secrets,
        policy,
        location,
        exposures,
    )

    if environment is not None:
        for name, secret_value in _collect_secret_values(
            environment,
            policy,
        )[0]:
            if secret_value:
                exposures.append(
                    SecretExposure(
                        location=f"environment.{name}",
                        reason="SECRET_VALUE_PRESENT",
                        secret_name=name,
                    )
                )

    # Deduplicate exposure records while preserving order.
    unique_exposures: list[SecretExposure] = []
    seen: set[tuple[str, str, str | None]] = set()

    for exposure in exposures:
        key = (
            exposure.location,
            exposure.reason,
            exposure.secret_name,
        )

        if key not in seen:
            seen.add(key)
            unique_exposures.append(exposure)

    # Redact the environment separately so its secret values can never
    # survive inside the returned object.
    if environment is not None:
        redacted_environment = _redact_value(
            environment,
            unique_secrets,
            policy,
            "environment",
            [],
        )

    combined = {
        "value": redacted_value,
        "environment": redacted_environment,
    }

    return SecretExposureResult(
        safe=not unique_exposures,
        exposures=tuple(unique_exposures),
        redacted=MappingProxyType(combined),
    )


def validate_secret_exposure(
    value: Any,
    *,
    environment: Mapping[str, Any] | None = None,
    policy: SecretExposurePolicy | None = None,
    location: str = "value",
) -> SecretExposureResult:
    """Compatibility alias for the primary inspection API."""

    return inspect_secret_exposure(
        value,
        environment=environment,
        policy=policy,
        location=location,
    )


def redact_secrets(
    value: Any,
    *,
    environment: Mapping[str, Any] | None = None,
    policy: SecretExposurePolicy | None = None,
) -> Any:
    """
    Return a redacted representation.

    Raises SecretExposurePreventionError for invalid policy.
    """

    result = inspect_secret_exposure(
        value,
        environment=environment,
        policy=policy,
    )

    return result.redacted


def require_no_secret_exposure(
    value: Any,
    *,
    environment: Mapping[str, Any] | None = None,
    policy: SecretExposurePolicy | None = None,
    location: str = "value",
) -> Any:
    """
    Require a safe value.

    The raised error contains only non-secret exposure metadata.
    Secret values are never included in the exception text.
    """

    result = inspect_secret_exposure(
        value,
        environment=environment,
        policy=policy,
        location=location,
    )

    if not result.safe:
        reasons = sorted(
            {
                exposure.reason
                for exposure in result.exposures
            }
        )

        locations = sorted(
            {
                exposure.location
                for exposure in result.exposures
            }
        )

        raise SecretExposurePreventionError(
            "SECRET_EXPOSURE_DETECTED:"
            + ",".join(reasons)
            + ":"
            + ",".join(locations)
        )

    return result.redacted


def validate_command_secret_exposure(
    command: list[str] | tuple[str, ...],
    *,
    environment: Mapping[str, Any] | None = None,
    policy: SecretExposurePolicy | None = None,
) -> SecretExposureResult:
    """
    Inspect command arguments and environment for secret exposure.

    The command is inspected as data only; it is never executed.
    """

    if not isinstance(command, (list, tuple)):
        raise SecretExposurePreventionError(
            "COMMAND_MUST_BE_SEQUENCE"
        )

    return inspect_secret_exposure(
        tuple(command),
        environment=environment,
        policy=policy,
        location="command",
    )
