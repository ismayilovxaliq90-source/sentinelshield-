from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Optional, Sequence


class TriageRiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class TriageAction(str, Enum):
    MONITOR = "MONITOR"
    REVIEW = "REVIEW"
    INVESTIGATE = "INVESTIGATE"
    IMMEDIATE_RESPONSE = "IMMEDIATE_RESPONSE"


class AnalystPriority(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class TriageDecisionInput:
    endpoint_signal_score: Optional[float] = None
    authentication_anomaly_score: Optional[float] = None
    process_behavior_risk_score: Optional[float] = None
    malware_file_reputation_score: Optional[float] = None


@dataclass(frozen=True)
class TriageDecision:
    risk_level: TriageRiskLevel
    recommended_action: TriageAction
    analyst_priority: AnalystPriority
    score: float
    explanation: tuple[str, ...]
    evidence: tuple[str, ...]


@dataclass(frozen=True)
class TriageDecisionGenerationResult:
    decision: TriageDecision


def _validate_score(value: Any, field_name: str) -> Optional[float]:
    if value is None:
        return None

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{field_name} must be numeric or None")

    numeric = float(value)

    if numeric != numeric:
        raise ValueError(f"{field_name} must not be NaN")

    if numeric < 0.0 or numeric > 100.0:
        raise ValueError(f"{field_name} must be between 0 and 100")

    return numeric


def _normalize_input(
    value: TriageDecisionInput | Mapping[str, Any],
) -> TriageDecisionInput:
    if isinstance(value, TriageDecisionInput):
        return TriageDecisionInput(
            endpoint_signal_score=_validate_score(
                value.endpoint_signal_score,
                "endpoint_signal_score",
            ),
            authentication_anomaly_score=_validate_score(
                value.authentication_anomaly_score,
                "authentication_anomaly_score",
            ),
            process_behavior_risk_score=_validate_score(
                value.process_behavior_risk_score,
                "process_behavior_risk_score",
            ),
            malware_file_reputation_score=_validate_score(
                value.malware_file_reputation_score,
                "malware_file_reputation_score",
            ),
        )

    if isinstance(value, Mapping):
        allowed = {
            "endpoint_signal_score",
            "authentication_anomaly_score",
            "process_behavior_risk_score",
            "malware_file_reputation_score",
        }

        unknown = set(value.keys()) - allowed
        if unknown:
            raise TypeError(
                "Unsupported triage input fields: "
                + ", ".join(sorted(str(item) for item in unknown))
            )

        return TriageDecisionInput(
            endpoint_signal_score=_validate_score(
                value.get("endpoint_signal_score"),
                "endpoint_signal_score",
            ),
            authentication_anomaly_score=_validate_score(
                value.get("authentication_anomaly_score"),
                "authentication_anomaly_score",
            ),
            process_behavior_risk_score=_validate_score(
                value.get("process_behavior_risk_score"),
                "process_behavior_risk_score",
            ),
            malware_file_reputation_score=_validate_score(
                value.get("malware_file_reputation_score"),
                "malware_file_reputation_score",
            ),
        )

    raise TypeError(
        "Triage decision input must be TriageDecisionInput or Mapping"
    )


def _risk_level(score: float) -> TriageRiskLevel:
    if score >= 75.0:
        return TriageRiskLevel.CRITICAL
    if score >= 50.0:
        return TriageRiskLevel.HIGH
    if score >= 25.0:
        return TriageRiskLevel.MEDIUM
    return TriageRiskLevel.LOW


def _action(level: TriageRiskLevel) -> TriageAction:
    if level is TriageRiskLevel.CRITICAL:
        return TriageAction.IMMEDIATE_RESPONSE
    if level is TriageRiskLevel.HIGH:
        return TriageAction.INVESTIGATE
    if level is TriageRiskLevel.MEDIUM:
        return TriageAction.REVIEW
    return TriageAction.MONITOR


def _priority(level: TriageRiskLevel) -> AnalystPriority:
    return AnalystPriority(level.value)


def _score_components(data: TriageDecisionInput) -> list[tuple[str, float]]:
    components = [
        ("endpoint_signal_score", data.endpoint_signal_score),
        (
            "authentication_anomaly_score",
            data.authentication_anomaly_score,
        ),
        (
            "process_behavior_risk_score",
            data.process_behavior_risk_score,
        ),
        (
            "malware_file_reputation_score",
            data.malware_file_reputation_score,
        ),
    ]

    return [
        (name, value)
        for name, value in components
        if value is not None
    ]


def _calculate_score(data: TriageDecisionInput) -> float:
    components = _score_components(data)

    if not components:
        return 0.0

    # Equal weighting is intentional: Task 139 combines the four
    # upstream triage signals without inventing additional weighting.
    score = sum(value for _, value in components) / len(components)

    return round(max(0.0, min(100.0, score)), 2)


def _build_explanation(
    data: TriageDecisionInput,
    score: float,
    level: TriageRiskLevel,
    action: TriageAction,
) -> tuple[str, ...]:
    explanations: list[str] = []

    components = _score_components(data)

    if not components:
        explanations.append("NO_TRIAGE_SIGNAL_AVAILABLE")
    else:
        for name, value in components:
            if value >= 75.0:
                explanations.append(f"HIGH_{name.upper()}")
            elif value >= 50.0:
                explanations.append(f"ELEVATED_{name.upper()}")
            elif value >= 25.0:
                explanations.append(f"MODERATE_{name.upper()}")

    explanations.append(f"TRIAGE_RISK_LEVEL_{level.value}")
    explanations.append(f"RECOMMENDED_ACTION_{action.value}")
    explanations.append(f"TRIAGE_SCORE_{score:.2f}")

    return tuple(explanations)


def _build_evidence(data: TriageDecisionInput) -> tuple[str, ...]:
    evidence: list[str] = []

    for name, value in _score_components(data):
        evidence.append(f"{name}={value:.2f}")

    if not evidence:
        evidence.append("NO_UPSTREAM_EVIDENCE")

    return tuple(evidence)


def generate_triage_decision(
    value: TriageDecisionInput | Mapping[str, Any],
) -> TriageDecisionGenerationResult:
    if value is None:
        raise TypeError("Triage decision input must not be None")

    data = _normalize_input(value)
    score = _calculate_score(data)
    level = _risk_level(score)
    action = _action(level)
    priority = _priority(level)

    decision = TriageDecision(
        risk_level=level,
        recommended_action=action,
        analyst_priority=priority,
        score=score,
        explanation=_build_explanation(
            data,
            score,
            level,
            action,
        ),
        evidence=_build_evidence(data),
    )

    return TriageDecisionGenerationResult(decision=decision)


# Public alias required by the task.
triage_decision_generation = generate_triage_decision
