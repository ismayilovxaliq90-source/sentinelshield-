from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Sequence


@dataclass(frozen=True)
class CandidateRiskInput:
    package_name: str
    current_version: str
    candidate_version: str

    breaking_change: bool = False
    major_upgrade: bool = False
    minor_upgrade: bool = False
    patch_upgrade: bool = False

    security_score: Optional[float] = None
    compatibility_score: Optional[float] = None
    confidence_score: Optional[float] = None

    upgrade_distance: Optional[int] = None
    original_index: int = 0


@dataclass(frozen=True)
class CandidateRiskScore:
    package_name: str
    current_version: str
    candidate_version: str

    risk_score: float
    risk_level: str

    breaking_change: bool
    major_upgrade: bool
    minor_upgrade: bool
    patch_upgrade: bool

    security_score: float
    compatibility_score: float
    confidence_score: float

    upgrade_distance: int
    original_index: int
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class CandidateRiskScoringResult:
    scores: tuple[CandidateRiskScore, ...]
    total: int
    high_risk_count: int
    medium_risk_count: int
    low_risk_count: int


def _validate_text(value: object, error: str) -> str:
    if not isinstance(value, str):
        raise TypeError(error)

    value = value.strip()

    if not value:
        raise ValueError(error.replace("MUST_BE_STRING", "IS_EMPTY"))

    return value


def _validate_bool(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise TypeError(f"{field}_MUST_BE_BOOL")
    return value


def _validate_score(
    value: object,
    field: str,
    default: float = 0.0,
) -> float:
    if value is None:
        return default

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{field}_MUST_BE_NUMERIC")

    value = float(value)

    if not 0 <= value <= 100:
        raise ValueError(f"{field}_OUT_OF_RANGE")

    return value


def _validate_distance(value: object) -> int:
    if value is None:
        return 0

    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("UPGRADE_DISTANCE_MUST_BE_INTEGER")

    if value < 0:
        raise ValueError("UPGRADE_DISTANCE_MUST_BE_NON_NEGATIVE")

    return value


def _validate_index(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("ORIGINAL_INDEX_MUST_BE_INTEGER")

    if value < 0:
        raise ValueError("ORIGINAL_INDEX_MUST_BE_NON_NEGATIVE")

    return value


def _risk_level(score: float) -> str:
    if score < 25:
        return "LOW"

    if score < 50:
        return "MEDIUM"

    if score < 75:
        return "HIGH"

    return "CRITICAL"


def _score_candidate(
    item: CandidateRiskInput,
) -> CandidateRiskScore:
    package_name = _validate_text(
        item.package_name,
        "PACKAGE_NAME_MUST_BE_STRING",
    )

    current_version = _validate_text(
        item.current_version,
        "CURRENT_VERSION_MUST_BE_STRING",
    )

    candidate_version = _validate_text(
        item.candidate_version,
        "CANDIDATE_VERSION_MUST_BE_STRING",
    )

    breaking_change = _validate_bool(
        item.breaking_change,
        "BREAKING_CHANGE",
    )

    major_upgrade = _validate_bool(
        item.major_upgrade,
        "MAJOR_UPGRADE",
    )

    minor_upgrade = _validate_bool(
        item.minor_upgrade,
        "MINOR_UPGRADE",
    )

    patch_upgrade = _validate_bool(
        item.patch_upgrade,
        "PATCH_UPGRADE",
    )

    security_score = _validate_score(
        item.security_score,
        "SECURITY_SCORE",
    )

    compatibility_score = _validate_score(
        item.compatibility_score,
        "COMPATIBILITY_SCORE",
    )

    confidence_score = _validate_score(
        item.confidence_score,
        "CONFIDENCE_SCORE",
    )

    upgrade_distance = _validate_distance(
        item.upgrade_distance,
    )

    original_index = _validate_index(
        item.original_index,
    )

    # Risk components:
    # breaking change        -> 35%
    # upgrade distance       -> 20%
    # security weakness      -> 20%
    # compatibility deficit  -> 15%
    # confidence deficit     -> 10%
    #
    # Higher result = higher remediation candidate risk.

    breaking_component = 100.0 if breaking_change else 0.0

    distance_component = min(
        float(upgrade_distance),
        100.0,
    )

    security_component = 100.0 - security_score
    compatibility_component = 100.0 - compatibility_score
    confidence_component = 100.0 - confidence_score

    score = (
        breaking_component * 0.35
        + distance_component * 0.20
        + security_component * 0.20
        + compatibility_component * 0.15
        + confidence_component * 0.10
    )

    # Upgrade-type refinement.
    if major_upgrade:
        score += 5.0
    elif minor_upgrade:
        score += 2.0
    elif patch_upgrade:
        score += 0.0

    score = round(
        min(max(score, 0.0), 100.0),
        2,
    )

    level = _risk_level(score)

    reasons: list[str] = []

    if breaking_change:
        reasons.append("BREAKING_CHANGE")

    if major_upgrade:
        reasons.append("MAJOR_UPGRADE")
    elif minor_upgrade:
        reasons.append("MINOR_UPGRADE")
    elif patch_upgrade:
        reasons.append("PATCH_UPGRADE")

    if upgrade_distance >= 100:
        reasons.append("LARGE_UPGRADE_DISTANCE")
    elif upgrade_distance >= 10:
        reasons.append("MODERATE_UPGRADE_DISTANCE")

    if security_score < 50:
        reasons.append("LOW_SECURITY_SCORE")

    if compatibility_score < 50:
        reasons.append("LOW_COMPATIBILITY_SCORE")

    if confidence_score < 50:
        reasons.append("LOW_CONFIDENCE_SCORE")

    reasons.append(f"RISK_LEVEL_{level}")
    reasons.append(f"RISK_SCORE_{score:.2f}")

    return CandidateRiskScore(
        package_name=package_name,
        current_version=current_version,
        candidate_version=candidate_version,
        risk_score=score,
        risk_level=level,
        breaking_change=breaking_change,
        major_upgrade=major_upgrade,
        minor_upgrade=minor_upgrade,
        patch_upgrade=patch_upgrade,
        security_score=security_score,
        compatibility_score=compatibility_score,
        confidence_score=confidence_score,
        upgrade_distance=upgrade_distance,
        original_index=original_index,
        reasons=tuple(reasons),
    )


def score_candidate_risk(
    candidates: Sequence[CandidateRiskInput],
) -> CandidateRiskScoringResult:
    if candidates is None:
        raise TypeError("CANDIDATES_IS_NONE")

    if isinstance(candidates, (str, bytes, bytearray)):
        raise TypeError("CANDIDATES_MUST_BE_SEQUENCE")

    if not isinstance(candidates, Sequence):
        raise TypeError("CANDIDATES_MUST_BE_SEQUENCE")

    scores = tuple(
        _score_candidate(item)
        if isinstance(item, CandidateRiskInput)
        else _score_candidate(
            CandidateRiskInput(**item)
        )
        if isinstance(item, dict)
        else (_ for _ in ()).throw(
            TypeError(
                f"UNSUPPORTED_CANDIDATE_TYPE:{index}"
            )
        )
        for index, item in enumerate(candidates)
    )

    ordered = tuple(
        sorted(
            scores,
            key=lambda item: (
                -item.risk_score,
                item.original_index,
            ),
        )
    )

    high_risk_count = sum(
        item.risk_level in {"HIGH", "CRITICAL"}
        for item in ordered
    )

    medium_risk_count = sum(
        item.risk_level == "MEDIUM"
        for item in ordered
    )

    low_risk_count = sum(
        item.risk_level == "LOW"
        for item in ordered
    )

    return CandidateRiskScoringResult(
        scores=ordered,
        total=len(ordered),
        high_risk_count=high_risk_count,
        medium_risk_count=medium_risk_count,
        low_risk_count=low_risk_count,
    )


# Public aliases.
candidate_risk_scoring = score_candidate_risk
calculate_candidate_risk = score_candidate_risk


__all__ = [
    "CandidateRiskInput",
    "CandidateRiskScore",
    "CandidateRiskScoringResult",
    "score_candidate_risk",
    "candidate_risk_scoring",
    "calculate_candidate_risk",
]
