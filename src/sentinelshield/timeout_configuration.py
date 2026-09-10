from __future__ import annotations

from dataclasses import dataclass
import math
from numbers import Real


class TimeoutConfigurationError(ValueError):
    """Raised when timeout configuration is invalid or unsafe."""


@dataclass(frozen=True)
class TimeoutPolicy:
    default_timeout: float = 60.0
    minimum_timeout: float = 0.1
    maximum_timeout: float = 600.0


@dataclass(frozen=True)
class TimeoutConfigurationResult:
    valid: bool
    timeout: float
    minimum_timeout: float
    maximum_timeout: float
    reason: str

    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "timeout": self.timeout,
            "minimum_timeout": self.minimum_timeout,
            "maximum_timeout": self.maximum_timeout,
            "reason": self.reason,
        }


def _validate_number(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, Real):
        raise TimeoutConfigurationError(
            f"{field} must be a finite numeric value"
        )

    converted = float(value)

    if not math.isfinite(converted):
        raise TimeoutConfigurationError(
            f"{field} must be finite"
        )

    return converted


def validate_timeout_policy(
    policy: TimeoutPolicy | None = None,
) -> TimeoutConfigurationResult:
    policy = policy or TimeoutPolicy()

    if not isinstance(policy, TimeoutPolicy):
        raise TimeoutConfigurationError(
            "policy must be TimeoutPolicy"
        )

    minimum = _validate_number(
        policy.minimum_timeout,
        "minimum_timeout",
    )
    maximum = _validate_number(
        policy.maximum_timeout,
        "maximum_timeout",
    )
    default = _validate_number(
        policy.default_timeout,
        "default_timeout",
    )

    if minimum <= 0:
        raise TimeoutConfigurationError(
            "minimum_timeout must be greater than zero"
        )

    if maximum <= 0:
        raise TimeoutConfigurationError(
            "maximum_timeout must be greater than zero"
        )

    if minimum > maximum:
        raise TimeoutConfigurationError(
            "minimum_timeout cannot exceed maximum_timeout"
        )

    if not minimum <= default <= maximum:
        raise TimeoutConfigurationError(
            "default_timeout must be within configured bounds"
        )

    return TimeoutConfigurationResult(
        valid=True,
        timeout=default,
        minimum_timeout=minimum,
        maximum_timeout=maximum,
        reason="VALID_TIMEOUT_POLICY",
    )


def configure_timeout(
    timeout: object | None = None,
    policy: TimeoutPolicy | None = None,
) -> TimeoutConfigurationResult:
    policy_result = validate_timeout_policy(policy)

    if timeout is None:
        selected = policy_result.timeout
    else:
        selected = _validate_number(timeout, "timeout")

    if selected <= 0:
        raise TimeoutConfigurationError(
            "timeout must be greater than zero"
        )

    if selected < policy_result.minimum_timeout:
        raise TimeoutConfigurationError(
            "timeout is below minimum allowed value"
        )

    if selected > policy_result.maximum_timeout:
        raise TimeoutConfigurationError(
            "timeout exceeds maximum allowed value"
        )

    return TimeoutConfigurationResult(
        valid=True,
        timeout=selected,
        minimum_timeout=policy_result.minimum_timeout,
        maximum_timeout=policy_result.maximum_timeout,
        reason="VALID_TIMEOUT",
    )


def require_valid_timeout(
    timeout: object | None = None,
    policy: TimeoutPolicy | None = None,
) -> float:
    result = configure_timeout(
        timeout=timeout,
        policy=policy,
    )

    return result.timeout
