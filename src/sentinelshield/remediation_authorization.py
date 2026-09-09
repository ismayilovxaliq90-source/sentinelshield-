from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class RemediationAuthorizationInput:
    policy_valid: Any
    security_policy_valid: Any
    version_policy_allowed: Any
    automated_remediation_eligible: Any
    manual_approval_required: Any
    risk_threshold_passed: Any
    change_scope_allowed: Any
    dependency_policy_allowed: Any


@dataclass(frozen=True)
class RemediationAuthorizationResult:
    authorized: bool
    status: str
    reasons: tuple[str, ...]


def _as_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value

    if isinstance(value, int) and value in (0, 1):
        return bool(value)

    if isinstance(value, str):
        normalized = value.strip().lower()

        if normalized in {
            "true",
            "yes",
            "allowed",
            "allow",
            "pass",
            "passed",
            "valid",
            "eligible",
        }:
            return True

        if normalized in {
            "false",
            "no",
            "denied",
            "deny",
            "fail",
            "failed",
            "invalid",
            "ineligible",
        }:
            return False

    return None


def authorize_remediation(
    authorization: RemediationAuthorizationInput,
) -> RemediationAuthorizationResult:
    if not isinstance(
        authorization,
        RemediationAuthorizationInput,
    ):
        return RemediationAuthorizationResult(
            authorized=False,
            status="INVALID_AUTHORIZATION_INPUT",
            reasons=("INVALID_INPUT_TYPE",),
        )

    fields = (
        ("policy_valid", authorization.policy_valid),
        (
            "security_policy_valid",
            authorization.security_policy_valid,
        ),
        (
            "version_policy_allowed",
            authorization.version_policy_allowed,
        ),
        (
            "automated_remediation_eligible",
            authorization.automated_remediation_eligible,
        ),
        (
            "manual_approval_required",
            authorization.manual_approval_required,
        ),
        (
            "risk_threshold_passed",
            authorization.risk_threshold_passed,
        ),
        (
            "change_scope_allowed",
            authorization.change_scope_allowed,
        ),
        (
            "dependency_policy_allowed",
            authorization.dependency_policy_allowed,
        ),
    )

    normalized: dict[str, bool] = {}

    for name, value in fields:
        result = _as_bool(value)

        if result is None:
            return RemediationAuthorizationResult(
                authorized=False,
                status="INVALID_AUTHORIZATION_SIGNAL",
                reasons=(f"INVALID_{name.upper()}",),
            )

        normalized[name] = result

    failed: list[str] = []

    if not normalized["policy_valid"]:
        failed.append("POLICY_INVALID")

    if not normalized["security_policy_valid"]:
        failed.append("SECURITY_POLICY_INVALID")

    if not normalized["version_policy_allowed"]:
        failed.append("VERSION_POLICY_NOT_ALLOWED")

    if not normalized["automated_remediation_eligible"]:
        failed.append("AUTOMATED_REMEDIATION_NOT_ELIGIBLE")

    if normalized["manual_approval_required"]:
        failed.append("MANUAL_APPROVAL_REQUIRED")

    if not normalized["risk_threshold_passed"]:
        failed.append("RISK_THRESHOLD_NOT_PASSED")

    if not normalized["change_scope_allowed"]:
        failed.append("CHANGE_SCOPE_NOT_ALLOWED")

    if not normalized["dependency_policy_allowed"]:
        failed.append("DEPENDENCY_POLICY_NOT_ALLOWED")

    if failed:
        return RemediationAuthorizationResult(
            authorized=False,
            status="REMEDIATION_NOT_AUTHORIZED",
            reasons=tuple(failed),
        )

    return RemediationAuthorizationResult(
        authorized=True,
        status="REMEDIATION_AUTHORIZED",
        reasons=("ALL_AUTHORIZATION_GATES_PASSED",),
    )


def remediation_authorization(
    authorization: RemediationAuthorizationInput,
) -> RemediationAuthorizationResult:
    return authorize_remediation(authorization)
