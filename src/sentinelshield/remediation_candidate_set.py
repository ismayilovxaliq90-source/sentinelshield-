from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence


@dataclass(frozen=True)
class RemediationCandidate:
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
class RemediationCandidateSet:
    candidates: tuple[RemediationCandidate, ...]
    total: int
    selected_count: int
    excluded_count: int


@dataclass(frozen=True)
class RemediationCandidateSetInput:
    candidates: Sequence[RemediationCandidate | dict]
    max_candidates: int | None = None
    max_risk_score: float | None = None
    include_breaking_changes: bool = True


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

    return round(value, 2)


def _bool(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise TypeError(f"{field}_MUST_BE_BOOL")
    return value


def _integer(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{field}_MUST_BE_INTEGER")

    if value < 0:
        raise ValueError(f"{field}_MUST_BE_NON_NEGATIVE")

    return value


def _normalize_candidate(
    item: RemediationCandidate | dict,
) -> RemediationCandidate:
    if isinstance(item, dict):
        try:
            item = RemediationCandidate(**item)
        except TypeError as error:
            raise TypeError(
                "INVALID_CANDIDATE_MAPPING"
            ) from error

    if not isinstance(item, RemediationCandidate):
        raise TypeError("UNSUPPORTED_CANDIDATE_TYPE")

    risk_score = _score(
        item.risk_score,
        "RISK_SCORE",
    )

    risk_level = _text(
        item.risk_level,
        "RISK_LEVEL",
    ).upper()

    if risk_level not in {
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    }:
        raise ValueError("INVALID_RISK_LEVEL")

    return RemediationCandidate(
        package_name=_text(
            item.package_name,
            "PACKAGE_NAME",
        ),
        current_version=_text(
            item.current_version,
            "CURRENT_VERSION",
        ),
        candidate_version=_text(
            item.candidate_version,
            "CANDIDATE_VERSION",
        ),
        risk_score=risk_score,
        risk_level=risk_level,
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
        upgrade_distance=_integer(
            item.upgrade_distance,
            "UPGRADE_DISTANCE",
        ),
        original_index=_integer(
            item.original_index,
            "ORIGINAL_INDEX",
        ),
    )


def _candidate_key(
    candidate: RemediationCandidate,
) -> tuple[str, str, str]:
    return (
        candidate.package_name.lower(),
        candidate.current_version,
        candidate.candidate_version,
    )


def build_remediation_candidate_set(
    request: RemediationCandidateSetInput,
) -> RemediationCandidateSet:
    if request is None:
        raise TypeError("INPUT_IS_NONE")

    if not isinstance(
        request,
        RemediationCandidateSetInput,
    ):
        raise TypeError(
            "INPUT_MUST_BE_REMEDIATION_CANDIDATE_SET_INPUT"
        )

    candidates = request.candidates

    if candidates is None:
        raise TypeError("CANDIDATES_IS_NONE")

    if isinstance(
        candidates,
        (str, bytes, bytearray),
    ):
        raise TypeError("CANDIDATES_MUST_BE_SEQUENCE")

    if not isinstance(candidates, Sequence):
        raise TypeError("CANDIDATES_MUST_BE_SEQUENCE")

    if request.max_candidates is not None:
        max_candidates = _integer(
            request.max_candidates,
            "MAX_CANDIDATES",
        )

        if max_candidates == 0:
            return RemediationCandidateSet(
                candidates=(),
                total=0,
                selected_count=0,
                excluded_count=len(candidates),
            )
    else:
        max_candidates = None

    if request.max_risk_score is not None:
        max_risk_score = _score(
            request.max_risk_score,
            "MAX_RISK_SCORE",
        )
    else:
        max_risk_score = None

    include_breaking_changes = _bool(
        request.include_breaking_changes,
        "INCLUDE_BREAKING_CHANGES",
    )

    normalized: list[RemediationCandidate] = []

    for item in candidates:
        normalized.append(
            _normalize_candidate(item)
        )

    # Deduplicate the same package/current/candidate tuple.
    unique: dict[
        tuple[str, str, str],
        RemediationCandidate,
    ] = {}

    for candidate in normalized:
        key = _candidate_key(candidate)

        existing = unique.get(key)

        if existing is None:
            unique[key] = candidate
            continue

        # Keep the stronger risk signal.
        if (
            candidate.risk_score > existing.risk_score
            or (
                candidate.risk_score
                == existing.risk_score
                and candidate.original_index
                < existing.original_index
            )
        ):
            unique[key] = candidate

    filtered = list(unique.values())

    if max_risk_score is not None:
        filtered = [
            candidate
            for candidate in filtered
            if candidate.risk_score <= max_risk_score
        ]

    if not include_breaking_changes:
        filtered = [
            candidate
            for candidate in filtered
            if not candidate.breaking_change
        ]

    # Candidate set order:
    # 1. Lowest risk first.
    # 2. Higher compatibility first.
    # 3. Higher security first.
    # 4. Higher confidence first.
    # 5. Non-breaking first.
    # 6. Smaller upgrade distance.
    # 7. Original index.
    filtered.sort(
        key=lambda candidate: (
            candidate.risk_score,
            -candidate.compatibility_score,
            -candidate.security_score,
            -candidate.confidence_score,
            candidate.breaking_change,
            candidate.upgrade_distance,
            candidate.original_index,
        )
    )

    if max_candidates is not None:
        selected = filtered[:max_candidates]
    else:
        selected = filtered

    result = tuple(selected)

    return RemediationCandidateSet(
        candidates=result,
        total=len(result),
        selected_count=len(result),
        excluded_count=len(candidates) - len(result),
    )


# Public aliases.
remediation_candidate_set = build_remediation_candidate_set
create_remediation_candidate_set = build_remediation_candidate_set


__all__ = [
    "RemediationCandidate",
    "RemediationCandidateSet",
    "RemediationCandidateSetInput",
    "build_remediation_candidate_set",
    "remediation_candidate_set",
    "create_remediation_candidate_set",
]
