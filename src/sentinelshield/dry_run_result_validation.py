from __future__ import annotations

from dataclasses import dataclass
import math

from .remediation_dry_run import (
    RemediationDryRunResult,
)


class DryRunResultValidationError(ValueError):
    """Raised when a dry-run result is invalid or unsafe."""


@dataclass(frozen=True)
class DryRunValidationPolicy:
    max_arguments: int = 64
    minimum_timeout_seconds: float = 0.1
    maximum_timeout_seconds: float = 600.0


@dataclass(frozen=True)
class DryRunValidationResult:
    valid: bool
    executable: str
    argument_count: int
    timeout_seconds: float
    executed: bool
    filesystem_modified: bool
    reason: str

    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "executable": self.executable,
            "argument_count": self.argument_count,
            "timeout_seconds": self.timeout_seconds,
            "executed": self.executed,
            "filesystem_modified": self.filesystem_modified,
            "reason": self.reason,
        }


def _validate_policy(
    policy: DryRunValidationPolicy,
) -> None:
    if not isinstance(policy, DryRunValidationPolicy):
        raise DryRunResultValidationError(
            "policy must be DryRunValidationPolicy"
        )

    if (
        isinstance(policy.max_arguments, bool)
        or not isinstance(policy.max_arguments, int)
        or policy.max_arguments < 1
    ):
        raise DryRunResultValidationError(
            "max_arguments must be a positive integer"
        )

    for field_name, value in (
        (
            "minimum_timeout_seconds",
            policy.minimum_timeout_seconds,
        ),
        (
            "maximum_timeout_seconds",
            policy.maximum_timeout_seconds,
        ),
    ):
        if isinstance(value, bool):
            raise DryRunResultValidationError(
                f"{field_name} must be finite numeric value"
            )

        if not isinstance(value, (int, float)):
            raise DryRunResultValidationError(
                f"{field_name} must be finite numeric value"
            )

        if not math.isfinite(float(value)):
            raise DryRunResultValidationError(
                f"{field_name} must be finite"
            )

        if float(value) <= 0:
            raise DryRunResultValidationError(
                f"{field_name} must be positive"
            )

    if (
        policy.minimum_timeout_seconds
        > policy.maximum_timeout_seconds
    ):
        raise DryRunResultValidationError(
            "minimum timeout cannot exceed maximum timeout"
        )


def validate_dry_run_result(
    result: RemediationDryRunResult,
    policy: DryRunValidationPolicy | None = None,
) -> DryRunValidationResult:
    policy = policy or DryRunValidationPolicy()
    _validate_policy(policy)

    if not isinstance(result, RemediationDryRunResult):
        raise DryRunResultValidationError(
            "result must be RemediationDryRunResult"
        )

    if result.valid is not True:
        raise DryRunResultValidationError(
            "dry-run result is not marked valid"
        )

    if result.executed is not False:
        raise DryRunResultValidationError(
            "dry-run indicates execution occurred"
        )

    if result.filesystem_modified is not False:
        raise DryRunResultValidationError(
            "dry-run indicates filesystem modification"
        )

    if not isinstance(result.executable, str):
        raise DryRunResultValidationError(
            "executable must be string"
        )

    if not result.executable:
        raise DryRunResultValidationError(
            "executable must not be empty"
        )

    if any(character.isspace() for character in result.executable):
        raise DryRunResultValidationError(
            "executable must be a single command token"
        )

    if not isinstance(result.arguments, tuple):
        raise DryRunResultValidationError(
            "arguments must be tuple"
        )

    if len(result.arguments) > policy.max_arguments:
        raise DryRunResultValidationError(
            "argument count exceeds policy"
        )

    for index, argument in enumerate(result.arguments):
        if not isinstance(argument, str):
            raise DryRunResultValidationError(
                f"argument {index} must be string"
            )

        if not argument:
            raise DryRunResultValidationError(
                f"argument {index} must not be empty"
            )

    timeout = result.timeout_seconds

    if isinstance(timeout, bool) or not isinstance(
        timeout,
        (int, float),
    ):
        raise DryRunResultValidationError(
            "timeout must be numeric"
        )

    timeout = float(timeout)

    if not math.isfinite(timeout):
        raise DryRunResultValidationError(
            "timeout must be finite"
        )

    if timeout < policy.minimum_timeout_seconds:
        raise DryRunResultValidationError(
            "timeout is below policy minimum"
        )

    if timeout > policy.maximum_timeout_seconds:
        raise DryRunResultValidationError(
            "timeout exceeds policy maximum"
        )

    if not isinstance(result.working_directory, str):
        raise DryRunResultValidationError(
            "working_directory must be string"
        )

    if not result.working_directory:
        raise DryRunResultValidationError(
            "working_directory must not be empty"
        )

    if not isinstance(result.environment_keys, tuple):
        raise DryRunResultValidationError(
            "environment_keys must be tuple"
        )

    for key in result.environment_keys:
        if not isinstance(key, str) or not key:
            raise DryRunResultValidationError(
                "environment keys must be non-empty strings"
            )

    return DryRunValidationResult(
        valid=True,
        executable=result.executable,
        argument_count=len(result.arguments),
        timeout_seconds=timeout,
        executed=False,
        filesystem_modified=False,
        reason="DRY_RUN_RESULT_VALID",
    )


def require_valid_dry_run_result(
    result: RemediationDryRunResult,
    policy: DryRunValidationPolicy | None = None,
) -> DryRunValidationResult:
    return validate_dry_run_result(
        result,
        policy=policy,
    )
