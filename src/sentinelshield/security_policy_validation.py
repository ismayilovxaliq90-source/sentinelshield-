from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .remediation_policy_loading import RemediationPolicy


@dataclass(frozen=True)
class SecurityPolicyValidationResult:
    valid: bool
    reasons: tuple[str, ...]
    errors: tuple[str, ...]


@dataclass(frozen=True)
class SecurityPolicyValidationInput:
    policy: RemediationPolicy


def _validate_policy_type(
    policy: object,
) -> RemediationPolicy:
    if policy is None:
        raise TypeError("POLICY_IS_NONE")

    if not isinstance(policy, RemediationPolicy):
        raise TypeError(
            "POLICY_MUST_BE_REMEDIATION_POLICY"
        )

    return policy


def _validate_version_entries(
    versions: Iterable[str],
    field: str,
) -> tuple[str, ...]:
    result: list[str] = []

    for version in versions:
        if not isinstance(version, str):
            raise TypeError(
                f"{field}_ITEM_MUST_BE_STRING"
            )

        normalized = version.strip()

        if not normalized:
            raise ValueError(
                f"{field}_ITEM_IS_EMPTY"
            )

        result.append(normalized)

    return tuple(dict.fromkeys(result))


def validate_security_policy(
    request: SecurityPolicyValidationInput,
) -> SecurityPolicyValidationResult:
    if request is None:
        raise TypeError("INPUT_IS_NONE")

    if not isinstance(
        request,
        SecurityPolicyValidationInput,
    ):
        raise TypeError(
            "INPUT_MUST_BE_SECURITY_POLICY_VALIDATION_INPUT"
        )

    policy = _validate_policy_type(request.policy)

    errors: list[str] = []
    reasons: list[str] = []

    # --------------------------------------------------------
    # Identity
    # --------------------------------------------------------

    if not isinstance(policy.policy_name, str):
        errors.append("POLICY_NAME_MUST_BE_STRING")
    elif not policy.policy_name.strip():
        errors.append("POLICY_NAME_IS_EMPTY")

    if not isinstance(policy.version, str):
        errors.append("VERSION_MUST_BE_STRING")
    elif not policy.version.strip():
        errors.append("VERSION_IS_EMPTY")

    # --------------------------------------------------------
    # Version collections
    # --------------------------------------------------------

    try:
        allowed_versions = _validate_version_entries(
            policy.allowed_versions,
            "ALLOWED_VERSIONS",
        )
    except (TypeError, ValueError) as error:
        errors.append(str(error))
        allowed_versions = ()

    try:
        forbidden_versions = _validate_version_entries(
            policy.forbidden_versions,
            "FORBIDDEN_VERSIONS",
        )
    except (TypeError, ValueError) as error:
        errors.append(str(error))
        forbidden_versions = ()

    conflict_versions = (
        set(allowed_versions)
        & set(forbidden_versions)
    )

    if conflict_versions:
        errors.append(
            "ALLOWED_FORBIDDEN_VERSION_CONFLICT"
        )

    # --------------------------------------------------------
    # Upgrade distance
    # --------------------------------------------------------

    distance = policy.maximum_upgrade_distance

    if distance is not None:
        if isinstance(distance, bool):
            errors.append(
                "MAXIMUM_UPGRADE_DISTANCE_MUST_BE_INTEGER"
            )
        elif not isinstance(distance, int):
            errors.append(
                "MAXIMUM_UPGRADE_DISTANCE_MUST_BE_INTEGER"
            )
        elif distance < 0:
            errors.append(
                "MAXIMUM_UPGRADE_DISTANCE_MUST_BE_NON_NEGATIVE"
            )

    # --------------------------------------------------------
    # Boolean security controls
    # --------------------------------------------------------

    boolean_fields = (
        (
            "allow_major_upgrades",
            policy.allow_major_upgrades,
        ),
        (
            "allow_production_dependencies",
            policy.allow_production_dependencies,
        ),
        (
            "allow_development_dependencies",
            policy.allow_development_dependencies,
        ),
        (
            "automated_remediation",
            policy.automated_remediation,
        ),
        (
            "manual_approval_required",
            policy.manual_approval_required,
        ),
    )

    for field, value in boolean_fields:
        if not isinstance(value, bool):
            errors.append(
                f"{field.upper()}_MUST_BE_BOOL"
            )

    # --------------------------------------------------------
    # Risk threshold
    # --------------------------------------------------------

    threshold = policy.risk_threshold

    if threshold is not None:
        if isinstance(threshold, bool):
            errors.append(
                "RISK_THRESHOLD_MUST_BE_NUMERIC"
            )
        elif not isinstance(threshold, (int, float)):
            errors.append(
                "RISK_THRESHOLD_MUST_BE_NUMERIC"
            )
        elif not 0 <= float(threshold) <= 100:
            errors.append(
                "RISK_THRESHOLD_OUT_OF_RANGE"
            )

    # --------------------------------------------------------
    # Scope / dependency policy
    # --------------------------------------------------------

    if not isinstance(policy.change_scope, str):
        errors.append(
            "CHANGE_SCOPE_MUST_BE_STRING"
        )
    elif not policy.change_scope.strip():
        errors.append(
            "CHANGE_SCOPE_IS_EMPTY"
        )

    if not isinstance(
        policy.dependency_policy,
        str,
    ):
        errors.append(
            "DEPENDENCY_POLICY_MUST_BE_STRING"
        )
    elif not policy.dependency_policy.strip():
        errors.append(
            "DEPENDENCY_POLICY_IS_EMPTY"
        )

    # --------------------------------------------------------
    # Security policy rules
    # --------------------------------------------------------

    if (
        policy.automated_remediation
        and policy.manual_approval_required
    ):
        reasons.append(
            "AUTOMATED_REMEDIATION_REQUIRES_APPROVAL"
        )

    if (
        policy.automated_remediation
        and not policy.manual_approval_required
    ):
        reasons.append(
            "AUTOMATED_REMEDIATION_ALLOWED"
        )

    if policy.allow_major_upgrades:
        reasons.append(
            "MAJOR_UPGRADES_ALLOWED"
        )
    else:
        reasons.append(
            "MAJOR_UPGRADES_RESTRICTED"
        )

    if policy.allow_production_dependencies:
        reasons.append(
            "PRODUCTION_DEPENDENCIES_ALLOWED"
        )
    else:
        reasons.append(
            "PRODUCTION_DEPENDENCIES_RESTRICTED"
        )

    if policy.allow_development_dependencies:
        reasons.append(
            "DEVELOPMENT_DEPENDENCIES_ALLOWED"
        )
    else:
        reasons.append(
            "DEVELOPMENT_DEPENDENCIES_RESTRICTED"
        )

    if threshold is None:
        reasons.append(
            "NO_RISK_THRESHOLD_CONFIGURED"
        )
    else:
        reasons.append(
            "RISK_THRESHOLD_CONFIGURED"
        )

    if distance is None:
        reasons.append(
            "NO_MAXIMUM_UPGRADE_DISTANCE_CONFIGURED"
        )
    else:
        reasons.append(
            "MAXIMUM_UPGRADE_DISTANCE_CONFIGURED"
        )

    if not conflict_versions:
        reasons.append(
            "VERSION_POLICY_CONSISTENT"
        )

    # --------------------------------------------------------
    # Final result
    # --------------------------------------------------------

    # Remove duplicate error strings while preserving order.
    errors = list(dict.fromkeys(errors))

    if errors:
        return SecurityPolicyValidationResult(
            valid=False,
            reasons=tuple(reasons),
            errors=tuple(errors),
        )

    reasons.append(
        "SECURITY_POLICY_VALID"
    )

    return SecurityPolicyValidationResult(
        valid=True,
        reasons=tuple(dict.fromkeys(reasons)),
        errors=(),
    )


def security_policy_validation(
    request: SecurityPolicyValidationInput,
) -> SecurityPolicyValidationResult:
    return validate_security_policy(request)


def check_security_policy(
    request: SecurityPolicyValidationInput,
) -> SecurityPolicyValidationResult:
    return validate_security_policy(request)


def is_security_policy_valid(
    request: SecurityPolicyValidationInput,
) -> bool:
    return validate_security_policy(request).valid


__all__ = [
    "SecurityPolicyValidationResult",
    "SecurityPolicyValidationInput",
    "validate_security_policy",
    "security_policy_validation",
    "check_security_policy",
    "is_security_policy_valid",
]
