from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class RiskScoreInput:
    """
    Normalized inputs used to calculate the final vulnerability risk score.
    """

    cvss: float | int | None = None
    urgency_score: float | int | None = None
    confidence_score: float | int | None = None
    exploitability_score: float | int | None = None
    reachability_score: float | int | None = None
    exposure_score: float | int | None = None


@dataclass(frozen=True)
class RiskScoreResult:
    score: float
    level: RiskLevel
    input: RiskScoreInput
    reasons: tuple[str, ...]


class RiskScoreCalculator:
    """
    Calculates a deterministic vulnerability risk score.

    Read-only calculation only.
    No filesystem mutation.
    No project code execution.
    """

    _WEIGHTS = {
        "cvss": 25.0,
        "urgency_score": 25.0,
        "confidence_score": 15.0,
        "exploitability_score": 15.0,
        "reachability_score": 10.0,
        "exposure_score": 10.0,
    }

    _ALLOWED_FIELDS = frozenset(_WEIGHTS)

    def calculate(
        self,
        value: RiskScoreInput | Mapping[str, Any] | None,
    ) -> RiskScoreResult:

        if value is None:
            raise TypeError("INPUT_IS_NONE")

        if isinstance(value, RiskScoreInput):
            data = value

        elif isinstance(value, Mapping):
            unknown = set(value) - self._ALLOWED_FIELDS

            if unknown:
                raise TypeError(
                    "UNSUPPORTED_INPUT_FIELD: "
                    + ", ".join(sorted(str(item) for item in unknown))
                )

            data = RiskScoreInput(
                cvss=value.get("cvss"),
                urgency_score=value.get("urgency_score"),
                confidence_score=value.get("confidence_score"),
                exploitability_score=value.get(
                    "exploitability_score"
                ),
                reachability_score=value.get(
                    "reachability_score"
                ),
                exposure_score=value.get(
                    "exposure_score"
                ),
            )

        else:
            raise TypeError("UNSUPPORTED_INPUT_TYPE")

        normalized = self._normalize(data)

        score = self._calculate_score(normalized)

        level = self._classify(score)

        reasons = self._build_reasons(normalized, score, level)

        return RiskScoreResult(
            score=score,
            level=level,
            input=normalized,
            reasons=reasons,
        )

    @staticmethod
    def _normalize(
        value: RiskScoreInput,
    ) -> RiskScoreInput:

        cvss = RiskScoreCalculator._normalize_range(
            value.cvss,
            "cvss",
            0.0,
            10.0,
        )

        urgency_score = RiskScoreCalculator._normalize_range(
            value.urgency_score,
            "urgency_score",
            0.0,
            100.0,
        )

        confidence_score = RiskScoreCalculator._normalize_range(
            value.confidence_score,
            "confidence_score",
            0.0,
            100.0,
        )

        exploitability_score = (
            RiskScoreCalculator._normalize_range(
                value.exploitability_score,
                "exploitability_score",
                0.0,
                100.0,
            )
        )

        reachability_score = (
            RiskScoreCalculator._normalize_range(
                value.reachability_score,
                "reachability_score",
                0.0,
                100.0,
            )
        )

        exposure_score = RiskScoreCalculator._normalize_range(
            value.exposure_score,
            "exposure_score",
            0.0,
            100.0,
        )

        return RiskScoreInput(
            cvss=cvss,
            urgency_score=urgency_score,
            confidence_score=confidence_score,
            exploitability_score=exploitability_score,
            reachability_score=reachability_score,
            exposure_score=exposure_score,
        )

    @staticmethod
    def _normalize_range(
        value: float | int | None,
        field_name: str,
        minimum: float,
        maximum: float,
    ) -> float:

        if value is None:
            return 0.0

        if isinstance(value, bool) or not isinstance(
            value,
            (int, float),
        ):
            raise TypeError(
                f"INVALID_{field_name.upper()}_TYPE"
            )

        numeric = float(value)

        if numeric < minimum or numeric > maximum:
            raise ValueError(
                f"{field_name.upper()}_OUT_OF_RANGE"
            )

        return numeric

    @classmethod
    def _calculate_score(
        cls,
        value: RiskScoreInput,
    ) -> float:

        cvss_component = (
            (float(value.cvss or 0.0) / 10.0)
            * cls._WEIGHTS["cvss"]
        )

        urgency_component = (
            (float(value.urgency_score or 0.0) / 100.0)
            * cls._WEIGHTS["urgency_score"]
        )

        confidence_component = (
            (float(value.confidence_score or 0.0) / 100.0)
            * cls._WEIGHTS["confidence_score"]
        )

        exploitability_component = (
            (float(value.exploitability_score or 0.0) / 100.0)
            * cls._WEIGHTS["exploitability_score"]
        )

        reachability_component = (
            (float(value.reachability_score or 0.0) / 100.0)
            * cls._WEIGHTS["reachability_score"]
        )

        exposure_component = (
            (float(value.exposure_score or 0.0) / 100.0)
            * cls._WEIGHTS["exposure_score"]
        )

        score = (
            cvss_component
            + urgency_component
            + confidence_component
            + exploitability_component
            + reachability_component
            + exposure_component
        )

        score = max(0.0, min(100.0, score))

        return round(score, 2)

    @staticmethod
    def _classify(score: float) -> RiskLevel:

        if score < 25.0:
            return RiskLevel.LOW

        if score < 50.0:
            return RiskLevel.MEDIUM

        if score < 75.0:
            return RiskLevel.HIGH

        return RiskLevel.CRITICAL

    @staticmethod
    def _build_reasons(
        value: RiskScoreInput,
        score: float,
        level: RiskLevel,
    ) -> tuple[str, ...]:

        reasons: list[str] = []

        if value.cvss and value.cvss >= 9.0:
            reasons.append("HIGH_CVSS")

        if value.urgency_score >= 75.0:
            reasons.append("HIGH_REMEDIATION_URGENCY")

        if value.confidence_score >= 75.0:
            reasons.append("HIGH_CONFIDENCE")

        if value.exploitability_score >= 75.0:
            reasons.append("HIGH_EXPLOITABILITY")

        if value.reachability_score >= 75.0:
            reasons.append("HIGH_REACHABILITY")

        if value.exposure_score >= 75.0:
            reasons.append("HIGH_EXPOSURE")

        reasons.append(
            f"RISK_LEVEL_{level.value}"
        )

        reasons.append(
            f"RISK_SCORE_{score:.2f}"
        )

        return tuple(reasons)


def calculate_risk_score(
    value: RiskScoreInput | Mapping[str, Any] | None,
) -> RiskScoreResult:
    return RiskScoreCalculator().calculate(value)


# Public compatibility alias.
risk_score_calculation = calculate_risk_score
