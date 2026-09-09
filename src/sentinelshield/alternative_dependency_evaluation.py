from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Sequence


@dataclass(frozen=True)
class AlternativeDependency:
    package_name: str
    candidate_version: str
    security_score: float = 0.0
    compatibility_score: float = 0.0
    maintenance_score: float = 0.0
    migration_effort: float = 0.0


@dataclass(frozen=True)
class AlternativeDependencyEvaluation:
    package_name: str
    candidate_version: str
    security_score: float
    compatibility_score: float
    maintenance_score: float
    migration_effort: float
    evaluation_score: float
    recommended: bool
    reasons: tuple[str, ...]
    original_index: int


@dataclass(frozen=True)
class AlternativeDependencyEvaluationResult:
    evaluations: tuple[AlternativeDependencyEvaluation, ...]
    total: int
    recommended_package: Optional[str]
    recommended_version: Optional[str]


def _validate_score(value: object, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name}_MUST_BE_NUMERIC")

    value = float(value)

    if not 0.0 <= value <= 100.0:
        raise ValueError(f"{name}_OUT_OF_RANGE")

    return round(value, 2)


def _validate_migration_effort(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("MIGRATION_EFFORT_MUST_BE_NUMERIC")

    value = float(value)

    if not 0.0 <= value <= 100.0:
        raise ValueError("MIGRATION_EFFORT_OUT_OF_RANGE")

    return round(value, 2)


def _parse_version(value: object) -> tuple[int, int, int]:
    if not isinstance(value, str):
        raise TypeError("VERSION_MUST_BE_STRING")

    value = value.strip()

    if not value:
        raise ValueError("VERSION_IS_EMPTY")

    if value.startswith(("v", "V")):
        value = value[1:]

    value = value.split("-", 1)[0]
    value = value.split("+", 1)[0]

    parts = value.split(".")

    if not 1 <= len(parts) <= 3:
        raise ValueError("VERSION_MUST_HAVE_ONE_TO_THREE_COMPONENTS")

    if not all(part.isdigit() for part in parts):
        raise ValueError("VERSION_COMPONENTS_MUST_BE_NUMERIC")

    numbers = [int(part) for part in parts]

    while len(numbers) < 3:
        numbers.append(0)

    return tuple(numbers)


def _validate_package_name(value: object) -> str:
    if not isinstance(value, str):
        raise TypeError("PACKAGE_NAME_MUST_BE_STRING")

    value = value.strip()

    if not value:
        raise ValueError("PACKAGE_NAME_IS_EMPTY")

    return value


def evaluate_alternative_dependencies(
    alternatives: Sequence[AlternativeDependency],
) -> AlternativeDependencyEvaluationResult:
    if isinstance(alternatives, (str, bytes, bytearray)):
        raise TypeError("ALTERNATIVES_MUST_BE_SEQUENCE")

    if not isinstance(alternatives, Sequence):
        raise TypeError("ALTERNATIVES_MUST_BE_SEQUENCE")

    evaluations: list[AlternativeDependencyEvaluation] = []
    seen: set[tuple[str, tuple[int, int, int]]] = set()

    for index, alternative in enumerate(alternatives):
        if not isinstance(alternative, AlternativeDependency):
            raise TypeError(
                f"ALTERNATIVE_MUST_BE_ALTERNATIVE_DEPENDENCY:{index}"
            )

        package_name = _validate_package_name(
            alternative.package_name
        )

        candidate_version = alternative.candidate_version.strip()

        _parse_version(candidate_version)

        security_score = _validate_score(
            alternative.security_score,
            "SECURITY_SCORE",
        )

        compatibility_score = _validate_score(
            alternative.compatibility_score,
            "COMPATIBILITY_SCORE",
        )

        maintenance_score = _validate_score(
            alternative.maintenance_score,
            "MAINTENANCE_SCORE",
        )

        migration_effort = _validate_migration_effort(
            alternative.migration_effort
        )

        version_key = _parse_version(candidate_version)
        identity = (package_name, version_key)

        if identity in seen:
            continue

        seen.add(identity)

        # Positive factors:
        # security       = 35%
        # compatibility  = 30%
        # maintenance    = 20%
        #
        # Migration effort is a penalty:
        # migration      = 15%
        evaluation_score = (
            security_score * 0.35
            + compatibility_score * 0.30
            + maintenance_score * 0.20
            + (100.0 - migration_effort) * 0.15
        )

        evaluation_score = round(
            max(0.0, min(100.0, evaluation_score)),
            2,
        )

        reasons: list[str] = []

        if security_score >= 75:
            reasons.append("STRONG_SECURITY")
        elif security_score < 50:
            reasons.append("SECURITY_CONCERN")

        if compatibility_score >= 75:
            reasons.append("STRONG_COMPATIBILITY")
        elif compatibility_score < 50:
            reasons.append("COMPATIBILITY_CONCERN")

        if maintenance_score >= 75:
            reasons.append("STRONG_MAINTENANCE")
        elif maintenance_score < 50:
            reasons.append("MAINTENANCE_CONCERN")

        if migration_effort <= 25:
            reasons.append("LOW_MIGRATION_EFFORT")
        elif migration_effort >= 75:
            reasons.append("HIGH_MIGRATION_EFFORT")

        if not reasons:
            reasons.append("BALANCED_ALTERNATIVE")

        evaluations.append(
            AlternativeDependencyEvaluation(
                package_name=package_name,
                candidate_version=candidate_version,
                security_score=security_score,
                compatibility_score=compatibility_score,
                maintenance_score=maintenance_score,
                migration_effort=migration_effort,
                evaluation_score=evaluation_score,
                recommended=False,
                reasons=tuple(reasons),
                original_index=index,
            )
        )

    evaluations.sort(
        key=lambda item: (
            -item.evaluation_score,
            item.migration_effort,
            -item.security_score,
            -item.compatibility_score,
            item.package_name,
            _parse_version(item.candidate_version),
            item.original_index,
        )
    )

    if evaluations:
        best = evaluations[0]

        evaluations = [
            AlternativeDependencyEvaluation(
                package_name=item.package_name,
                candidate_version=item.candidate_version,
                security_score=item.security_score,
                compatibility_score=item.compatibility_score,
                maintenance_score=item.maintenance_score,
                migration_effort=item.migration_effort,
                evaluation_score=item.evaluation_score,
                recommended=(
                    item.package_name == best.package_name
                    and _parse_version(item.candidate_version)
                    == _parse_version(best.candidate_version)
                ),
                reasons=item.reasons,
                original_index=item.original_index,
            )
            for item in evaluations
        ]

        recommended_package = best.package_name
        recommended_version = best.candidate_version
    else:
        recommended_package = None
        recommended_version = None

    return AlternativeDependencyEvaluationResult(
        evaluations=tuple(evaluations),
        total=len(evaluations),
        recommended_package=recommended_package,
        recommended_version=recommended_version,
    )


# Public aliases.
alternative_dependency_evaluation = evaluate_alternative_dependencies
evaluate_dependency_alternatives = evaluate_alternative_dependencies


__all__ = [
    "AlternativeDependency",
    "AlternativeDependencyEvaluation",
    "AlternativeDependencyEvaluationResult",
    "evaluate_alternative_dependencies",
    "alternative_dependency_evaluation",
    "evaluate_dependency_alternatives",
]
