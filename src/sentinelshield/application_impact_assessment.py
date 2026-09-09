from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ApplicationImpactAssessment:
    identifier: str
    package_name: str | None = None
    impact: str = "UNKNOWN"
    score: float | None = None
    business_impact: str | None = None
    data_impact: str | None = None
    service_impact: str | None = None


@dataclass(frozen=True)
class ApplicationImpactAssessmentResult:
    assessments: tuple[ApplicationImpactAssessment, ...]
    assessed: bool
    status: str


_IDENTIFIER_FIELDS = (
    "identifier",
    "id",
    "vulnerability_id",
    "vuln_id",
    "cve",
    "ghsa",
)

_PACKAGE_FIELDS = (
    "package_name",
    "package",
    "dependency_name",
    "dependency",
    "affected_package",
    "affected_package_name",
)

_IMPACT_FIELDS = (
    "application_impact",
    "impact",
    "impact_level",
)

_SCORE_FIELDS = (
    "application_impact_score",
    "impact_score",
)

_BUSINESS_FIELDS = (
    "business_impact",
)

_DATA_FIELDS = (
    "data_impact",
)

_SERVICE_FIELDS = (
    "service_impact",
)


_IMPACT_ALIASES = {
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
    "INFO": "MINIMAL",
    "INFORMATIONAL": "MINIMAL",
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


def _normalize_identifier(value: Any) -> str | None:
    if value is None or isinstance(value, (bytes, bytearray)):
        return None

    if not isinstance(value, str):
        return None

    value = value.strip().upper()
    return value or None


def _normalize_package(value: Any) -> str | None:
    if value is None:
        return None

    if isinstance(value, (bytes, bytearray)):
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


def _normalize_impact(value: Any) -> str | None:
    if value is None:
        return None

    if not isinstance(value, str):
        return None

    normalized = value.strip().upper()

    if not normalized:
        return None

    return _IMPACT_ALIASES.get(normalized)


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


def _normalize_context(value: Any) -> str | None:
    if value is None:
        return None

    if not isinstance(value, str):
        return None

    value = value.strip().upper()
    return value or None


def _impact_from_score(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "MINIMAL"


def _derive_impact(
    explicit: str | None,
    score: float | None,
    business_impact: str | None,
    data_impact: str | None,
    service_impact: str | None,
) -> str:
    if explicit is not None:
        return explicit

    if score is not None:
        return _impact_from_score(score)

    critical_values = {"CRITICAL"}
    high_values = {"CRITICAL", "HIGH"}
    medium_values = {"CRITICAL", "HIGH", "MEDIUM"}

    contexts = (
        business_impact,
        data_impact,
        service_impact,
    )

    if any(value in critical_values for value in contexts):
        return "CRITICAL"

    if any(value in high_values for value in contexts):
        return "HIGH"

    if any(value in medium_values for value in contexts):
        return "MEDIUM"

    if any(value == "LOW" for value in contexts):
        return "LOW"

    if any(value == "MINIMAL" for value in contexts):
        return "MINIMAL"

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


def assess_application_impact(
    vulnerabilities: Any,
) -> ApplicationImpactAssessmentResult:
    if vulnerabilities is None:
        return ApplicationImpactAssessmentResult(
            assessments=(),
            assessed=False,
            status="VULNERABILITIES_IS_NONE",
        )

    collection = _normalize_collection(vulnerabilities)

    if collection is None:
        return ApplicationImpactAssessmentResult(
            assessments=(),
            assessed=False,
            status="UNSUPPORTED_VULNERABILITY_COLLECTION",
        )

    if not collection:
        return ApplicationImpactAssessmentResult(
            assessments=(),
            assessed=False,
            status="NO_VULNERABILITIES",
        )

    results: dict[
        tuple[str, str | None],
        ApplicationImpactAssessment,
    ] = {}

    for record in collection:
        if record is None or isinstance(
            record,
            (str, bytes, bytearray, int, float, bool),
        ):
            return ApplicationImpactAssessmentResult(
                assessments=(),
                assessed=False,
                status="INVALID_VULNERABILITY_RECORD",
            )

        identifier = _normalize_identifier(
            _read_field(record, _IDENTIFIER_FIELDS)
        )

        if identifier is None:
            return ApplicationImpactAssessmentResult(
                assessments=(),
                assessed=False,
                status="INVALID_VULNERABILITY_IDENTIFIER",
            )

        package_value = _read_field(record, _PACKAGE_FIELDS)

        if package_value is None:
            package_name = None
        else:
            package_name = _normalize_package(package_value)

            if not isinstance(package_value, str):
                return ApplicationImpactAssessmentResult(
                    assessments=(),
                    assessed=False,
                    status="INVALID_VULNERABILITY_PACKAGE",
                )

        impact_value = _read_field(record, _IMPACT_FIELDS)

        if impact_value is None:
            explicit_impact = None
        else:
            explicit_impact = _normalize_impact(impact_value)

            if explicit_impact is None:
                return ApplicationImpactAssessmentResult(
                    assessments=(),
                    assessed=False,
                    status="INVALID_APPLICATION_IMPACT_METADATA",
                )

        score_value = _read_field(record, _SCORE_FIELDS)

        if score_value is None:
            score = None
        else:
            score = _normalize_score(score_value)

            if score is None:
                return ApplicationImpactAssessmentResult(
                    assessments=(),
                    assessed=False,
                    status="INVALID_APPLICATION_IMPACT_SCORE",
                )

        business_value = _read_field(record, _BUSINESS_FIELDS)
        business_impact = _normalize_context(business_value)

        if business_value is not None and business_impact is None:
            return ApplicationImpactAssessmentResult(
                assessments=(),
                assessed=False,
                status="INVALID_BUSINESS_IMPACT_METADATA",
            )

        data_value = _read_field(record, _DATA_FIELDS)
        data_impact = _normalize_context(data_value)

        if data_value is not None and data_impact is None:
            return ApplicationImpactAssessmentResult(
                assessments=(),
                assessed=False,
                status="INVALID_DATA_IMPACT_METADATA",
            )

        service_value = _read_field(record, _SERVICE_FIELDS)
        service_impact = _normalize_context(service_value)

        if service_value is not None and service_impact is None:
            return ApplicationImpactAssessmentResult(
                assessments=(),
                assessed=False,
                status="INVALID_SERVICE_IMPACT_METADATA",
            )

        impact = _derive_impact(
            explicit_impact,
            score,
            business_impact,
            data_impact,
            service_impact,
        )

        candidate = ApplicationImpactAssessment(
            identifier=identifier,
            package_name=package_name,
            impact=impact,
            score=score,
            business_impact=business_impact,
            data_impact=data_impact,
            service_impact=service_impact,
        )

        key = (identifier, package_name)

        rank = {
            "UNKNOWN": 0,
            "MINIMAL": 1,
            "LOW": 2,
            "MEDIUM": 3,
            "HIGH": 4,
            "CRITICAL": 5,
        }

        existing = results.get(key)

        if existing is None:
            results[key] = candidate
        elif rank[candidate.impact] > rank[existing.impact]:
            results[key] = candidate
        elif rank[candidate.impact] == rank[existing.impact]:
            if (
                candidate.score is not None
                and (
                    existing.score is None
                    or candidate.score > existing.score
                )
            ):
                results[key] = candidate

    assessments = tuple(
        results[key]
        for key in sorted(
            results,
            key=lambda item: (
                item[0],
                item[1] is not None,
                item[1] or "",
            ),
        )
    )

    return ApplicationImpactAssessmentResult(
        assessments=assessments,
        assessed=True,
        status="APPLICATION_IMPACT_ASSESSED",
    )


def application_impact_assessment(
    vulnerabilities: Any,
) -> ApplicationImpactAssessmentResult:
    return assess_application_impact(vulnerabilities)
