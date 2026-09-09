from __future__ import annotations

from dataclasses import dataclass

from .remediation_policy_loading import RemediationPolicy


@dataclass(frozen=True)
class ManualApprovalRequirementInput:
    policy: RemediationPolicy


@dataclass(frozen=True)
class ManualApprovalRequirementResult:
    approval_required: bool
    manual_approval_required: bool
    reason: str


def evaluate_manual_approval_requirement(
    request: ManualApprovalRequirementInput,
) -> ManualApprovalRequirementResult:
    if request is None:
        raise TypeError("INPUT_IS_NONE")

    if not isinstance(
        request,
        ManualApprovalRequirementInput,
    ):
        raise TypeError(
            "INPUT_MUST_BE_MANUAL_APPROVAL_REQUIREMENT_INPUT"
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

    approval_required = request.policy.manual_approval_required

    if not isinstance(approval_required, bool):
        raise TypeError(
            "MANUAL_APPROVAL_REQUIRED_MUST_BE_BOOLEAN"
        )

    if approval_required:
        return ManualApprovalRequirementResult(
            approval_required=True,
            manual_approval_required=True,
            reason="MANUAL_APPROVAL_REQUIRED",
        )

    return ManualApprovalRequirementResult(
        approval_required=False,
        manual_approval_required=False,
        reason="MANUAL_APPROVAL_NOT_REQUIRED",
    )


def manual_approval_requirement(
    request: ManualApprovalRequirementInput,
) -> ManualApprovalRequirementResult:
    return evaluate_manual_approval_requirement(request)


def check_manual_approval_requirement(
    request: ManualApprovalRequirementInput,
) -> ManualApprovalRequirementResult:
    return evaluate_manual_approval_requirement(request)


def is_manual_approval_required(
    request: ManualApprovalRequirementInput,
) -> bool:
    return evaluate_manual_approval_requirement(request).approval_required


__all__ = [
    "ManualApprovalRequirementInput",
    "ManualApprovalRequirementResult",
    "evaluate_manual_approval_requirement",
    "manual_approval_requirement",
    "check_manual_approval_requirement",
    "is_manual_approval_required",
]
