from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class DependencyCriticalityAssessment:
    dependency_name: str
    criticality: str = "UNKNOWN"
    score: float | None = None
    direct: bool | None = None
    production: bool | None = None
    runtime: bool | None = None
    internet_exposed: bool | None = None


@dataclass(frozen=True)
class DependencyCriticalityAssessmentResult:
    assessments: tuple[DependencyCriticalityAssessment, ...]
    assessed: bool
    status: str


_NAME_FIELDS = (
    "name",
    "package_name",
    "dependency_name",
    "package",
    "dependency",
)

_CRITICALITY_FIELDS = (
    "criticality",
    "dependency_criticality",
    "criticality_level",
    "criticality_rating",
)

_SCORE_FIELDS = (
    "criticality_score",
    "dependency_criticality_score",
)

_DIRECT_FIELDS = (
    "direct",
    "is_direct",
    "direct_dependency",
)

_PRODUCTION_FIELDS = (
    "production",
    "is_production",
    "production_dependency",
    "production_exposed",
)

_RUNTIME_FIELDS = (
    "runtime",
    "is_runtime",
    "runtime_dependency",
    "runtime_exposed",
)

_INTERNET_FIELDS = (
    "internet_exposed",
    "exposed_to_internet",
    "internet_exposure",
)


_CRITICALITY_ALIASES = {
    "CRITICAL": "CRITICAL",
    "CRIT": "CRITICAL",
    "VERY HIGH": "CRITICAL",
    "VERY_HIGH": "CRITICAL",
    "VERY-HIGH": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "MED": "MEDIUM",
    "MODERATE": "MEDIUM",
    "LOW": "LOW",
    "MINIMAL": "MINIMAL",
    "NONE": "MINIMAL",
    "INFORMATIONAL": "MINIMAL",
    "INFO": "MINIMAL",
    "UNKNOWN": "UNKNOWN",
}


def _read_field(record: Any, fields: tuple[str, ...]) -> Any:
    if isinstance(record, Mapping):
        for field in fields:
            if field in record:
                return record[field]
        return None

    for field in fields:
        try:
            value = getattr(record, field)
        except AttributeError:
            continue

        if callable(value):
            continue

        return value

    return None


def _normalize_name(value: Any) -> str | None:
    if value is None or isinstance(value, (bytes, bytearray)):
        return None

    if not isinstance(value, str):
        return None

    value = value.strip().lower()

    if not value:
        return None

    value = value.replace("_", "-").replace(".", "-")

    while "--" in value:
        value = value.replace("--", "-")

    return value


def _normalize_bool(value: Any) -> bool | None:
    if value is None:
        return None

    if isinstance(value, bool):
        return value

    if isinstance(value, int) and value in (0, 1):
        return bool(value)

    if isinstance(value, str):
        normalized = value.strip().lower()

        if normalized in {
            "true",
            "yes",
            "y",
            "1",
            "direct",
            "production",
            "runtime",
            "exposed",
            "active",
        }:
            return True

        if normalized in {
            "false",
            "no",
            "n",
            "0",
            "transitive",
            "development",
            "not exposed",
            "not_exposed",
            "inactive",
        }:
            return False

    return None


def _normalize_score(value: Any) -> float | None:
    if value is None:
        return None

    if isinstance(value, bool):
        return None

    if isinstance(value, (int, float)):
        score = float(value)
    elif isinstance(value, str):
        try:
            score = float(value.strip())
        except ValueError:
            return None
    else:
        return None

    if score < 0 or score > 100:
        return None

    return score


def _normalize_criticality(value: Any) -> str | None:
    if value is None:
        return None

    if not isinstance(value, str):
        return None

    normalized = value.strip().upper()

    if not normalized:
        return None

    return _CRITICALITY_ALIASES.get(normalized)


def _criticality_from_score(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "MINIMAL"


def _derive_criticality(
    *,
    explicit: str | None,
    score: float | None,
    direct: bool | None,
    production: bool | None,
    runtime: bool | None,
    internet_exposed: bool | None,
) -> str:
    if explicit is not None:
        return explicit

    if score is not None:
        return _criticality_from_score(score)

    points = 0

    if direct is True:
        points += 20

    if production is True:
        points += 35

    if runtime is True:
        points += 25

    if internet_exposed is True:
        points += 20

    if points >= 80:
        return "CRITICAL"
    if points >= 60:
        return "HIGH"
    if points >= 30:
        return "MEDIUM"
    if points > 0:
        return "LOW"

    return "UNKNOWN"


def _normalize_collection(value: Any) -> tuple[Any, ...] | None:
    if value is None:
        return None

    if isinstance(value, (str, bytes, bytearray)):
        return None

    if isinstance(value, Mapping):
        return (value,)

    try:
        return tuple(value)
    except TypeError:
        return None


def assess_dependency_criticality(
    dependencies: Any,
) -> DependencyCriticalityAssessmentResult:
    if dependencies is None:
        return DependencyCriticalityAssessmentResult(
            assessments=(),
            assessed=False,
            status="DEPENDENCIES_IS_NONE",
        )

    collection = _normalize_collection(dependencies)

    if collection is None:
        return DependencyCriticalityAssessmentResult(
            assessments=(),
            assessed=False,
            status="UNSUPPORTED_DEPENDENCY_COLLECTION",
        )

    if not collection:
        return DependencyCriticalityAssessmentResult(
            assessments=(),
            assessed=False,
            status="NO_DEPENDENCIES",
        )

    results: dict[str, DependencyCriticalityAssessment] = {}

    for record in collection:
        if record is None or isinstance(
            record,
            (str, bytes, bytearray, int, float, bool),
        ):
            return DependencyCriticalityAssessmentResult(
                assessments=(),
                assessed=False,
                status="INVALID_DEPENDENCY_RECORD",
            )

        name_value = _read_field(record, _NAME_FIELDS)
        name = _normalize_name(name_value)

        if name is None:
            return DependencyCriticalityAssessmentResult(
                assessments=(),
                assessed=False,
                status="INVALID_DEPENDENCY_NAME",
            )

        explicit_value = _read_field(
            record,
            _CRITICALITY_FIELDS,
        )

        if explicit_value is None:
            explicit = None
        else:
            explicit = _normalize_criticality(explicit_value)

            if explicit is None:
                return DependencyCriticalityAssessmentResult(
                    assessments=(),
                    assessed=False,
                    status="INVALID_CRITICALITY_METADATA",
                )

        score_value = _read_field(record, _SCORE_FIELDS)

        if score_value is None:
            score = None
        else:
            score = _normalize_score(score_value)

            if score is None:
                return DependencyCriticalityAssessmentResult(
                    assessments=(),
                    assessed=False,
                    status="INVALID_CRITICALITY_SCORE",
                )

        direct_value = _read_field(record, _DIRECT_FIELDS)
        direct = _normalize_bool(direct_value)

        if direct_value is not None and direct is None:
            return DependencyCriticalityAssessmentResult(
                assessments=(),
                assessed=False,
                status="INVALID_DIRECT_METADATA",
            )

        production_value = _read_field(
            record,
            _PRODUCTION_FIELDS,
        )
        production = _normalize_bool(production_value)

        if production_value is not None and production is None:
            return DependencyCriticalityAssessmentResult(
                assessments=(),
                assessed=False,
                status="INVALID_PRODUCTION_METADATA",
            )

        runtime_value = _read_field(record, _RUNTIME_FIELDS)
        runtime = _normalize_bool(runtime_value)

        if runtime_value is not None and runtime is None:
            return DependencyCriticalityAssessmentResult(
                assessments=(),
                assessed=False,
                status="INVALID_RUNTIME_METADATA",
            )

        internet_value = _read_field(record, _INTERNET_FIELDS)
        internet_exposed = _normalize_bool(internet_value)

        if internet_value is not None and internet_exposed is None:
            return DependencyCriticalityAssessmentResult(
                assessments=(),
                assessed=False,
                status="INVALID_INTERNET_EXPOSURE_METADATA",
            )

        criticality = _derive_criticality(
            explicit=explicit,
            score=score,
            direct=direct,
            production=production,
            runtime=runtime,
            internet_exposed=internet_exposed,
        )

        candidate = DependencyCriticalityAssessment(
            dependency_name=name,
            criticality=criticality,
            score=score,
            direct=direct,
            production=production,
            runtime=runtime,
            internet_exposed=internet_exposed,
        )

        existing = results.get(name)

        if existing is None:
            results[name] = candidate
        else:
            # Keep the stronger assessment when duplicate records exist.
            rank = {
                "UNKNOWN": 0,
                "MINIMAL": 1,
                "LOW": 2,
                "MEDIUM": 3,
                "HIGH": 4,
                "CRITICAL": 5,
            }

            if rank[candidate.criticality] > rank[existing.criticality]:
                results[name] = candidate
            elif rank[candidate.criticality] == rank[existing.criticality]:
                results[name] = candidate

    assessments = tuple(
        results[name]
        for name in sorted(results)
    )

    return DependencyCriticalityAssessmentResult(
        assessments=assessments,
        assessed=True,
        status="DEPENDENCY_CRITICALITY_ASSESSED",
    )


def dependency_criticality_assessment(
    dependencies: Any,
) -> DependencyCriticalityAssessmentResult:
    return assess_dependency_criticality(dependencies)
