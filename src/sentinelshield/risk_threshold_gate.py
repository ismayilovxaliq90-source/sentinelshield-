from __future__ import annotations

from dataclasses import dataclass
import math

from .remediation_policy_loading import RemediationPolicy


@dataclass(frozen=True)
class RiskThresholdGateInput:
    policy: RemediationPolicy
    risk_score: float


@dataclass(frozen=True)
class RiskThresholdGateResult:
    allowed: bool
    risk_score: float
    risk_threshold: float
    reason: str


def _validate_score(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(
        value, (int, float)
    ):
        raise TypeError(
            f"{field}_MUST_BE_NUMERIC"
        )

    result = float(value)

    if not math.isfinite(result):
        raise ValueError(
            f"{field}_MUST_BE_FINITE"
        )

    if not 0.0 <= result <= 100.0:
        raise ValueError(
            f"{field}_MUST_BE_BETWEEN_0_AND_100"
        )

    return result


def evaluate_risk_threshold_gate(
    request: RiskThresholdGateInput,
) -> RiskThresholdGateResult:
    if request is None:
        raise TypeError("INPUT_IS_NONE")

    if not isinstance(
        request,
        RiskThresholdGateInput,
    ):
        raise TypeError(
            "INPUT_MUST_BE_RISK_THRESHOLD_GATE_INPUT"
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

    risk_score = _validate_score(
        request.risk_score,
        "RISK_SCORE",
    )

    risk_threshold = _validate_score(
        request.policy.risk_threshold,
        "RISK_THRESHOLD",
    )

    if risk_score <= risk_threshold:
        return RiskThresholdGateResult(
            allowed=True,
            risk_score=risk_score,
            risk_threshold=risk_threshold,
            reason="RISK_SCORE_WITHIN_THRESHOLD",
        )

    return RiskThresholdGateResult(
        allowed=False,
        risk_score=risk_score,
        risk_threshold=risk_threshold,
        reason="RISK_SCORE_EXCEEDS_THRESHOLD",
    )


def risk_threshold_gate(
    request: RiskThresholdGateInput,
) -> RiskThresholdGateResult:
    return evaluate_risk_threshold_gate(request)


def check_risk_threshold(
    request: RiskThresholdGateInput,
) -> RiskThresholdGateResult:
    return evaluate_risk_threshold_gate(request)


def is_risk_threshold_allowed(
    request: RiskThresholdGateInput,
) -> bool:
    return evaluate_risk_threshold_gate(request).allowed


__all__ = [
    "RiskThresholdGateInput",
    "RiskThresholdGateResult",
    "evaluate_risk_threshold_gate",
    "risk_threshold_gate",
    "check_risk_threshold",
    "is_risk_threshold_allowed",
]
