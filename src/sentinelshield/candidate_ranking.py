from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Sequence


@dataclass(frozen=True)
class CandidateRankingInput:
    package_name: str
    current_version: str
    candidate_version: str

    risk_score: float
    risk_level: str = ""

    security_score: float = 0.0
    compatibility_score: float = 0.0
    confidence_score: float = 0.0

    breaking_change: bool = False
    major_upgrade: bool = False
    minor_upgrade: bool = False
    patch_upgrade: bool = False

    upgrade_distance: int = 0
    original_index: int = 0


@dataclass(frozen=True)
class RankedCandidate:
    rank: int
    package_name: str
    current_version: str
    candidate_version: str

    risk_score: float
    risk_level: str

    security_score: float
    compatibility_score: float
    confidence_score: float

    breaking_change: bool
    major_upgrade: bool
    minor_upgrade: bool
    patch_upgrade: bool

    upgrade_distance: int
    original_index: int


@dataclass(frozen=True)
class CandidateRankingResult:
    candidates: tuple[RankedCandidate, ...]
    total: int


def _text(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field}_MUST_BE_STRING")

    value = value.strip()

    if not value:
        raise ValueError(f"{field}_IS_EMPTY")

    return value


def _score(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{field}_MUST_BE_NUMERIC")

    value = float(value)

    if not 0 <= value <= 100:
        raise ValueError(f"{field}_OUT_OF_RANGE")

    return value


def _bool(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise TypeError(f"{field}_MUST_BE_BOOL")

    return value


def _non_negative_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{field}_MUST_BE_INTEGER")

    if value < 0:
        raise ValueError(f"{field}_MUST_BE_NON_NEGATIVE")

    return value


def _risk_level(score: float) -> str:
    if score < 25:
        return "LOW"
    if score < 50:
        return "MEDIUM"
    if score < 75:
        return "HIGH"
    return "CRITICAL"


def _normalize(item: CandidateRankingInput) -> CandidateRankingInput:
    risk_score = _score(item.risk_score, "RISK_SCORE")

    supplied_level = item.risk_level.strip().upper()

    if supplied_level and supplied_level not in {
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    }:
        raise ValueError("INVALID_RISK_LEVEL")

    calculated_level = _risk_level(risk_score)

    if supplied_level and supplied_level != calculated_level:
        raise ValueError("RISK_LEVEL_MISMATCH")

    return CandidateRankingInput(
        package_name=_text(item.package_name, "PACKAGE_NAME"),
        current_version=_text(
            item.current_version,
            "CURRENT_VERSION",
        ),
        candidate_version=_text(
            item.candidate_version,
            "CANDIDATE_VERSION",
        ),
        risk_score=round(risk_score, 2),
        risk_level=calculated_level,
        security_score=_score(
            item.security_score,
            "SECURITY_SCORE",
        ),
        compatibility_score=_score(
            item.compatibility_score,
            "COMPATIBILITY_SCORE",
        ),
        confidence_score=_score(
            item.confidence_score,
            "CONFIDENCE_SCORE",
        ),
        breaking_change=_bool(
            item.breaking_change,
            "BREAKING_CHANGE",
        ),
        major_upgrade=_bool(
            item.major_upgrade,
            "MAJOR_UPGRADE",
        ),
        minor_upgrade=_bool(
            item.minor_upgrade,
            "MINOR_UPGRADE",
        ),
        patch_upgrade=_bool(
            item.patch_upgrade,
            "PATCH_UPGRADE",
        ),
        upgrade_distance=_non_negative_int(
            item.upgrade_distance,
            "UPGRADE_DISTANCE",
        ),
        original_index=_non_negative_int(
            item.original_index,
            "ORIGINAL_INDEX",
        ),
    )


def _from_mapping(item: dict) -> CandidateRankingInput:
    try:
        return CandidateRankingInput(**item)
    except TypeError as error:
        raise TypeError(
            "INVALID_CANDIDATE_MAPPING"
        ) from error


def rank_candidates(
    candidates: Sequence[
        CandidateRankingInput | dict
    ],
) -> CandidateRankingResult:
    if candidates is None:
        raise TypeError("CANDIDATES_IS_NONE")

    if isinstance(candidates, (str, bytes, bytearray)):
        raise TypeError("CANDIDATES_MUST_BE_SEQUENCE")

    if not isinstance(candidates, Sequence):
        raise TypeError("CANDIDATES_MUST_BE_SEQUENCE")

    normalized: list[CandidateRankingInput] = []

    for index, item in enumerate(candidates):
        if isinstance(item, CandidateRankingInput):
            candidate = item
        elif isinstance(item, dict):
            candidate = _from_mapping(item)
        else:
            raise TypeError(
                f"UNSUPPORTED_CANDIDATE_TYPE:{index}"
            )

        normalized.append(_normalize(candidate))

    # Ranking policy:
    # 1. Lowest risk score first.
    # 2. Higher compatibility score first.
    # 3. Higher security score first.
    # 4. Higher confidence first.
    # 5. Non-breaking before breaking.
    # 6. Smaller upgrade distance first.
    # 7. Original index for deterministic tie-breaking.
    ordered = sorted(
        normalized,
        key=lambda item: (
            item.risk_score,
            -item.compatibility_score,
            -item.security_score,
            -item.confidence_score,
            item.breaking_change,
            item.upgrade_distance,
            item.original_index,
        ),
    )

    ranked = tuple(
        RankedCandidate(
            rank=index,
            package_name=item.package_name,
            current_version=item.current_version,
            candidate_version=item.candidate_version,
            risk_score=item.risk_score,
            risk_level=item.risk_level,
            security_score=item.security_score,
            compatibility_score=item.compatibility_score,
            confidence_score=item.confidence_score,
            breaking_change=item.breaking_change,
            major_upgrade=item.major_upgrade,
            minor_upgrade=item.minor_upgrade,
            patch_upgrade=item.patch_upgrade,
            upgrade_distance=item.upgrade_distance,
            original_index=item.original_index,
        )
        for index, item in enumerate(ordered, start=1)
    )

    return CandidateRankingResult(
        candidates=ranked,
        total=len(ranked),
    )


# Public aliases.
candidate_ranking = rank_candidates
rank_remediation_candidates = rank_candidates


__all__ = [
    "CandidateRankingInput",
    "RankedCandidate",
    "CandidateRankingResult",
    "rank_candidates",
    "candidate_ranking",
    "rank_remediation_candidates",
]
