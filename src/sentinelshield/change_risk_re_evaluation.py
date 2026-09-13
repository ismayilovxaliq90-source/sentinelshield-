from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


__test__ = False


@dataclass(frozen=True)
class ChangeRiskReEvaluationInput:
    previous_score: float
    blast_radius: Iterable[str]
    changed_files: Iterable[str]
    critical_files: Iterable[str] = ()
    security_sensitive_files: Iterable[str] = ()


@dataclass(frozen=True)
class ChangeRiskReEvaluationResult:
    previous_score: float
    blast_radius_count: int
    changed_file_count: int
    critical_file_count: int
    security_sensitive_file_count: int
    score: float
    level: str
    status: str

    @property
    def increased(self) -> bool:
        return self.score > self.previous_score

    @property
    def decreased(self) -> bool:
        return self.score < self.previous_score

    @property
    def unchanged(self) -> bool:
        return self.score == self.previous_score


def _paths(values: Iterable[str]) -> set[str]:
    if isinstance(values, (str, bytes)):
        raise TypeError("PATH_COLLECTION_MUST_BE_ITERABLE")

    try:
        result = set()
        for value in values:
            if not isinstance(value, str):
                raise TypeError("PATH_MUST_BE_STRING")
            value = value.strip().replace("\\", "/")
            if value:
                result.add(value)
        return result
    except TypeError as exc:
        if str(exc) == "PATH_MUST_BE_STRING":
            raise
        raise TypeError("PATH_COLLECTION_MUST_BE_ITERABLE") from exc


def _validate(request: ChangeRiskReEvaluationInput) -> None:
    if not isinstance(request, ChangeRiskReEvaluationInput):
        raise TypeError(
            "INPUT_MUST_BE_CHANGE_RISK_RE_EVALUATION_INPUT"
        )

    if isinstance(request.previous_score, bool):
        raise TypeError("PREVIOUS_SCORE_MUST_BE_NUMBER")

    if not isinstance(request.previous_score, (int, float)):
        raise TypeError("PREVIOUS_SCORE_MUST_BE_NUMBER")

    if not 0 <= request.previous_score <= 100:
        raise ValueError("PREVIOUS_SCORE_OUT_OF_RANGE")

    _paths(request.blast_radius)
    _paths(request.changed_files)
    _paths(request.critical_files)
    _paths(request.security_sensitive_files)


def re_evaluate_change_risk(
    request: ChangeRiskReEvaluationInput,
) -> ChangeRiskReEvaluationResult:
    _validate(request)

    blast_radius = _paths(request.blast_radius)
    changed_files = _paths(request.changed_files)
    critical_files = _paths(request.critical_files)
    sensitive_files = _paths(request.security_sensitive_files)

    score = float(request.previous_score)

    score += min(len(blast_radius) * 5, 30)
    score += min(len(changed_files) * 2, 20)
    score += min(len(critical_files) * 10, 25)
    score += min(len(sensitive_files) * 10, 25)

    score = min(score, 100.0)

    if score >= 80:
        level = "CRITICAL"
    elif score >= 60:
        level = "HIGH"
    elif score >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"

    if score > request.previous_score:
        status = "INCREASED"
    elif score < request.previous_score:
        status = "DECREASED"
    else:
        status = "UNCHANGED"

    return ChangeRiskReEvaluationResult(
        previous_score=float(request.previous_score),
        blast_radius_count=len(blast_radius),
        changed_file_count=len(changed_files),
        critical_file_count=len(critical_files),
        security_sensitive_file_count=len(sensitive_files),
        score=score,
        level=level,
        status=status,
    )


def change_risk_re_evaluation(
    request: ChangeRiskReEvaluationInput,
) -> ChangeRiskReEvaluationResult:
    return re_evaluate_change_risk(request)
