from __future__ import annotations

from dataclasses import dataclass

from .remediation_policy_loading import RemediationPolicy


@dataclass(frozen=True)
class AutomatedRemediationEligibilityInput:
    policy: RemediationPolicy


@dataclass(frozen=True)
class AutomatedRemediationEligibilityResult:
    eligible: bool
    automated_remediation: bool
    reason: str


def evaluate_automated_remediation_eligibility(
    request: AutomatedRemediationEligibilityInput,
) -> AutomatedRemediationEligibilityResult:
    if request is None:
        raise TypeError("INPUT_IS_NONE")

    if not isinstance(
        request,
        AutomatedRemediationEligibilityInput,
    ):
        raise TypeError(
            "INPUT_MUST_BE_AUTOMATED_REMEDIATION_ELIGIBILITY_INPUT"
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

    automated = request.policy.automated_remediation

    if not isinstance(automated, bool):
        raise TypeError(
            "AUTOMATED_REMEDIATION_MUST_BE_BOOLEAN"
        )

    if automated:
        return AutomatedRemediationEligibilityResult(
            eligible=True,
            automated_remediation=True,
            reason="AUTOMATED_REMEDIATION_ELIGIBLE",
        )

    return AutomatedRemediationEligibilityResult(
        eligible=False,
        automated_remediation=False,
        reason="AUTOMATED_REMEDIATION_NOT_ELIGIBLE",
    )


def automated_remediation_eligibility(
    request: AutomatedRemediationEligibilityInput,
) -> AutomatedRemediationEligibilityResult:
    return evaluate_automated_remediation_eligibility(request)


def check_automated_remediation_eligibility(
    request: AutomatedRemediationEligibilityInput,
) -> AutomatedRemediationEligibilityResult:
    return evaluate_automated_remediation_eligibility(request)


def is_automated_remediation_eligible(
    request: AutomatedRemediationEligibilityInput,
) -> bool:
    return evaluate_automated_remediation_eligibility(request).eligible


__all__ = [
    "AutomatedRemediationEligibilityInput",
    "AutomatedRemediationEligibilityResult",
    "evaluate_automated_remediation_eligibility",
    "automated_remediation_eligibility",
    "check_automated_remediation_eligibility",
    "is_automated_remediation_eligible",
]
