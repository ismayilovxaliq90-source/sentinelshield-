from __future__ import annotations

from dataclasses import dataclass

from .remediation_policy_loading import RemediationPolicy


@dataclass(frozen=True)
class ChangeScopeGateInput:
    policy: RemediationPolicy
    requested_change_scope: str


@dataclass(frozen=True)
class ChangeScopeGateResult:
    allowed: bool
    requested_change_scope: str
    policy_change_scope: str
    reason: str


def _normalize_scope(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(
            f"{field}_MUST_BE_STRING"
        )

    normalized = value.strip()

    if not normalized:
        raise ValueError(
            f"{field}_IS_EMPTY"
        )

    return normalized.casefold()


def evaluate_change_scope_gate(
    request: ChangeScopeGateInput,
) -> ChangeScopeGateResult:
    if request is None:
        raise TypeError("INPUT_IS_NONE")

    if not isinstance(
        request,
        ChangeScopeGateInput,
    ):
        raise TypeError(
            "INPUT_MUST_BE_CHANGE_SCOPE_GATE_INPUT"
        )

    if request.policy is None:
        raise TypeError("POLICY_IS_NONE")

    if not isinstance(
        request.policy,
        RemediationPolicy,
    ):
        raise TypeError(
            "POLICY_MUST_BE_REMEDIATION_POLICY"
        )

    requested_scope = _normalize_scope(
        request.requested_change_scope,
        "REQUESTED_CHANGE_SCOPE",
    )

    policy_scope = _normalize_scope(
        request.policy.change_scope,
        "POLICY_CHANGE_SCOPE",
    )

    if requested_scope == policy_scope:
        return ChangeScopeGateResult(
            allowed=True,
            requested_change_scope=requested_scope,
            policy_change_scope=policy_scope,
            reason="CHANGE_SCOPE_ALLOWED",
        )

    return ChangeScopeGateResult(
        allowed=False,
        requested_change_scope=requested_scope,
        policy_change_scope=policy_scope,
        reason="CHANGE_SCOPE_FORBIDDEN",
    )


def change_scope_gate(
    request: ChangeScopeGateInput,
) -> ChangeScopeGateResult:
    return evaluate_change_scope_gate(request)


def check_change_scope(
    request: ChangeScopeGateInput,
) -> ChangeScopeGateResult:
    return evaluate_change_scope_gate(request)


def is_change_scope_allowed(
    request: ChangeScopeGateInput,
) -> bool:
    return evaluate_change_scope_gate(request).allowed


__all__ = [
    "ChangeScopeGateInput",
    "ChangeScopeGateResult",
    "evaluate_change_scope_gate",
    "change_scope_gate",
    "check_change_scope",
    "is_change_scope_allowed",
]
