from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class FalsePositiveCandidate:
    identifier: str
    package_name: str | None = None
    candidate: bool = False
    reasons: tuple[str, ...] = ()
    confidence: str = "LOW"


@dataclass(frozen=True)
class FalsePositiveCandidateDetectionResult:
    candidates: tuple[FalsePositiveCandidate, ...]
    detected: bool
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

_FALSE_POSITIVE_FIELDS = (
    "false_positive",
    "is_false_positive",
)

_FALSE_POSITIVE_CANDIDATE_FIELDS = (
    "false_positive_candidate",
    "is_false_positive_candidate",
)

_AFFECTED_FIELDS = (
    "affected",
    "is_affected",
    "affected_version",
)

_REACHABILITY_FIELDS = (
    "reachable",
    "is_reachable",
    "reachability",
    "dependency_reachable",
)

_RUNTIME_FIELDS = (
    "runtime_exposed",
    "runtime_exposure",
    "exposed_at_runtime",
    "runtime",
)

_PRODUCTION_FIELDS = (
    "production_exposed",
    "production_exposure",
    "exposed_in_production",
    "production",
)

_INTERNET_FIELDS = (
    "internet_exposed",
    "internet_exposure",
    "exposed_to_internet",
    "internet",
)

_CONFIDENCE_FIELDS = (
    "confidence",
    "confidence_level",
)


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
            "affected",
            "reachable",
            "exposed",
            "candidate",
        }:
            return True

        if normalized in {
            "false",
            "no",
            "n",
            "0",
            "unaffected",
            "not affected",
            "not_affected",
            "not-affected",
            "unreachable",
            "not reachable",
            "not_reachable",
            "not-reachable",
            "not exposed",
            "not_exposed",
            "not-exposed",
            "not a candidate",
        }:
            return False

    return None


def _normalize_confidence(value: Any) -> str | None:
    if value is None:
        return None

    if not isinstance(value, str):
        return None

    normalized = value.strip().upper()

    aliases = {
        "VERY HIGH": "HIGH",
        "VERY_HIGH": "HIGH",
        "VERY-HIGH": "HIGH",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "MED": "MEDIUM",
        "MODERATE": "MEDIUM",
        "LOW": "LOW",
        "MINIMAL": "LOW",
        "UNKNOWN": "LOW",
    }

    return aliases.get(normalized)


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


def _calculate_confidence(
    reasons: tuple[str, ...],
) -> str:
    if len(reasons) >= 3:
        return "HIGH"

    if len(reasons) == 2:
        return "MEDIUM"

    if len(reasons) == 1:
        return "LOW"

    return "LOW"


def detect_false_positive_candidates(
    vulnerabilities: Any,
) -> FalsePositiveCandidateDetectionResult:
    if vulnerabilities is None:
        return FalsePositiveCandidateDetectionResult(
            candidates=(),
            detected=False,
            status="VULNERABILITIES_IS_NONE",
        )

    collection = _normalize_collection(vulnerabilities)

    if collection is None:
        return FalsePositiveCandidateDetectionResult(
            candidates=(),
            detected=False,
            status="UNSUPPORTED_VULNERABILITY_COLLECTION",
        )

    if not collection:
        return FalsePositiveCandidateDetectionResult(
            candidates=(),
            detected=False,
            status="NO_VULNERABILITIES",
        )

    results: dict[
        tuple[str, str | None],
        FalsePositiveCandidate,
    ] = {}

    for record in collection:
        if record is None or isinstance(
            record,
            (str, bytes, bytearray, int, float, bool),
        ):
            return FalsePositiveCandidateDetectionResult(
                candidates=(),
                detected=False,
                status="INVALID_VULNERABILITY_RECORD",
            )

        identifier = _normalize_identifier(
            _read_field(record, _IDENTIFIER_FIELDS)
        )

        if identifier is None:
            return FalsePositiveCandidateDetectionResult(
                candidates=(),
                detected=False,
                status="INVALID_VULNERABILITY_IDENTIFIER",
            )

        package_value = _read_field(record, _PACKAGE_FIELDS)

        if package_value is None:
            package_name = None
        else:
            package_name = _normalize_package(package_value)

            if not isinstance(package_value, str):
                return FalsePositiveCandidateDetectionResult(
                    candidates=(),
                    detected=False,
                    status="INVALID_VULNERABILITY_PACKAGE",
                )

        reasons: list[str] = []

        explicit_fp = _read_field(
            record,
            _FALSE_POSITIVE_FIELDS,
        )

        if explicit_fp is not None:
            normalized_fp = _normalize_bool(explicit_fp)

            if normalized_fp is None:
                return FalsePositiveCandidateDetectionResult(
                    candidates=(),
                    detected=False,
                    status="INVALID_FALSE_POSITIVE_METADATA",
                )

            if normalized_fp:
                reasons.append("EXPLICIT_FALSE_POSITIVE")

        explicit_candidate = _read_field(
            record,
            _FALSE_POSITIVE_CANDIDATE_FIELDS,
        )

        if explicit_candidate is not None:
            normalized_candidate = _normalize_bool(
                explicit_candidate
            )

            if normalized_candidate is None:
                return FalsePositiveCandidateDetectionResult(
                    candidates=(),
                    detected=False,
                    status="INVALID_FALSE_POSITIVE_CANDIDATE_METADATA",
                )

            if normalized_candidate:
                reasons.append("EXPLICIT_FALSE_POSITIVE_CANDIDATE")

        affected_value = _read_field(
            record,
            _AFFECTED_FIELDS,
        )

        if affected_value is not None:
            affected = _normalize_bool(affected_value)

            if affected is None:
                return FalsePositiveCandidateDetectionResult(
                    candidates=(),
                    detected=False,
                    status="INVALID_AFFECTED_METADATA",
                )

            if affected is False:
                reasons.append("PACKAGE_NOT_AFFECTED")

        reachable_value = _read_field(
            record,
            _REACHABILITY_FIELDS,
        )

        if reachable_value is not None:
            reachable = _normalize_bool(reachable_value)

            if reachable is None:
                return FalsePositiveCandidateDetectionResult(
                    candidates=(),
                    detected=False,
                    status="INVALID_REACHABILITY_METADATA",
                )

            if reachable is False:
                reasons.append("NOT_REACHABLE")

        runtime_value = _read_field(
            record,
            _RUNTIME_FIELDS,
        )

        if runtime_value is not None:
            runtime_exposed = _normalize_bool(runtime_value)

            if runtime_exposed is None:
                return FalsePositiveCandidateDetectionResult(
                    candidates=(),
                    detected=False,
                    status="INVALID_RUNTIME_EXPOSURE_METADATA",
                )

            if runtime_exposed is False:
                reasons.append("NOT_RUNTIME_EXPOSED")

        production_value = _read_field(
            record,
            _PRODUCTION_FIELDS,
        )

        if production_value is not None:
            production_exposed = _normalize_bool(
                production_value
            )

            if production_exposed is None:
                return FalsePositiveCandidateDetectionResult(
                    candidates=(),
                    detected=False,
                    status="INVALID_PRODUCTION_EXPOSURE_METADATA",
                )

            if production_exposed is False:
                reasons.append("NOT_PRODUCTION_EXPOSED")

        internet_value = _read_field(
            record,
            _INTERNET_FIELDS,
        )

        if internet_value is not None:
            internet_exposed = _normalize_bool(internet_value)

            if internet_exposed is None:
                return FalsePositiveCandidateDetectionResult(
                    candidates=(),
                    detected=False,
                    status="INVALID_INTERNET_EXPOSURE_METADATA",
                )

            if internet_exposed is False:
                reasons.append("NOT_INTERNET_EXPOSED")

        confidence_value = _read_field(
            record,
            _CONFIDENCE_FIELDS,
        )

        if confidence_value is None:
            confidence = _calculate_confidence(tuple(reasons))
        else:
            confidence = _normalize_confidence(confidence_value)

            if confidence is None:
                return FalsePositiveCandidateDetectionResult(
                    candidates=(),
                    detected=False,
                    status="INVALID_CONFIDENCE_METADATA",
                )

        unique_reasons = tuple(dict.fromkeys(reasons))
        candidate = bool(unique_reasons)

        item = FalsePositiveCandidate(
            identifier=identifier,
            package_name=package_name,
            candidate=candidate,
            reasons=unique_reasons,
            confidence=confidence,
        )

        key = (identifier, package_name)
        existing = results.get(key)

        if existing is None:
            results[key] = item
        else:
            combined_reasons = tuple(
                dict.fromkeys(
                    existing.reasons + item.reasons
                )
            )

            results[key] = FalsePositiveCandidate(
                identifier=identifier,
                package_name=package_name,
                candidate=bool(combined_reasons),
                reasons=combined_reasons,
                confidence=_calculate_confidence(
                    combined_reasons
                ),
            )

    candidates = tuple(
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

    return FalsePositiveCandidateDetectionResult(
        candidates=candidates,
        detected=True,
        status="FALSE_POSITIVE_CANDIDATES_DETECTED",
    )


def false_positive_candidate_detection(
    vulnerabilities: Any,
) -> FalsePositiveCandidateDetectionResult:
    return detect_false_positive_candidates(vulnerabilities)
