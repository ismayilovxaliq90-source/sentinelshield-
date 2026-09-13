from __future__ import annotations

from dataclasses import dataclass
from typing import Any


class RiskAssessmentEvidenceError(ValueError):
    """Raised when risk assessment evidence is invalid."""


@dataclass(frozen=True)
class RiskAssessmentEvidenceInput:
    risk_level: str
    score: float
    findings: tuple[str, ...] = ()
    source: str = "risk_assessment"


@dataclass(frozen=True)
class RiskAssessmentEvidence:
    risk_level: str
    score: float
    findings: tuple[str, ...]
    source: str


@dataclass(frozen=True)
class RiskAssessmentEvidenceResult:
    valid: bool
    evidence: RiskAssessmentEvidence | None
    reason: str | None = None


def _validate_item(value: Any, field: str) -> None:
    if not isinstance(value, str):
        raise TypeError(f"{field}_MUST_BE_STRING")
    if not value.strip():
        raise RiskAssessmentEvidenceError(f"{field}_MUST_NOT_BE_EMPTY")


def create_risk_assessment_evidence(
    request: RiskAssessmentEvidenceInput,
) -> RiskAssessmentEvidence:
    if not isinstance(request, RiskAssessmentEvidenceInput):
        raise TypeError("INPUT_MUST_BE_RISK_ASSESSMENT_EVIDENCE_INPUT")

    _validate_item(request.risk_level, "RISK_LEVEL")
    _validate_item(request.source, "SOURCE")

    if isinstance(request.score, bool) or not isinstance(
        request.score, (int, float)
    ):
        raise TypeError("SCORE_MUST_BE_NUMBER")

    if request.score < 0:
        raise RiskAssessmentEvidenceError("SCORE_MUST_NOT_BE_NEGATIVE")

    if not isinstance(request.findings, tuple):
        raise TypeError("FINDINGS_MUST_BE_TUPLE")

    for finding in request.findings:
        _validate_item(finding, "FINDING")

    return RiskAssessmentEvidence(
        risk_level=request.risk_level.strip(),
        score=float(request.score),
        findings=tuple(item.strip() for item in request.findings),
        source=request.source.strip(),
    )


def create_risk_assessment_evidence_result(
    request: RiskAssessmentEvidenceInput,
) -> RiskAssessmentEvidenceResult:
    evidence = create_risk_assessment_evidence(request)
    return RiskAssessmentEvidenceResult(
        valid=True,
        evidence=evidence,
        reason=None,
    )


def validate_risk_assessment_evidence(
    evidence: RiskAssessmentEvidence,
) -> bool:
    if not isinstance(evidence, RiskAssessmentEvidence):
        raise TypeError("EVIDENCE_MUST_BE_RISK_ASSESSMENT_EVIDENCE")

    _validate_item(evidence.risk_level, "RISK_LEVEL")
    _validate_item(evidence.source, "SOURCE")

    if isinstance(evidence.score, bool) or not isinstance(
        evidence.score, (int, float)
    ):
        raise TypeError("SCORE_MUST_BE_NUMBER")

    if evidence.score < 0:
        raise RiskAssessmentEvidenceError("SCORE_MUST_NOT_BE_NEGATIVE")

    if not isinstance(evidence.findings, tuple):
        raise TypeError("FINDINGS_MUST_BE_TUPLE")

    for finding in evidence.findings:
        _validate_item(finding, "FINDING")

    return True
