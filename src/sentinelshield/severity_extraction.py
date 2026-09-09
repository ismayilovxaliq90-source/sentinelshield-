from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Severity:
    identifier: str
    severity: str


@dataclass(frozen=True)
class SeverityExtractionResult:
    severities: tuple[Severity, ...]
    extracted: bool
    status: str


_SEVERITY_FIELDS = (
    "severity",
    "severity_level",
    "severity_rating",
)

_IDENTIFIER_FIELDS = (
    "identifier",
    "id",
    "vulnerability_id",
    "vuln_id",
    "cve",
    "ghsa",
)

_SEVERITY_ALIASES = {
    "CRIT": "CRITICAL",
    "CRITICAL": "CRITICAL",
    "CRITICALITY": "CRITICAL",
    "HIGH": "HIGH",
    "MED": "MEDIUM",
    "MEDIUM": "MEDIUM",
    "MODERATE": "MEDIUM",
    "LOW": "LOW",
    "INFO": "INFORMATIONAL",
    "INFORMATIONAL": "INFORMATIONAL",
    "UNKNOWN": "UNKNOWN",
}


def _read_field(value: Any, fields: tuple[str, ...]) -> Any:
    if isinstance(value, dict):
        for field in fields:
            if field in value:
                return value[field]
        return None

    for field in fields:
        try:
            result = getattr(value, field)
        except AttributeError:
            continue

        if result is not None:
            return result

    return None


def _normalize_identifier(value: Any) -> str | None:
    if value is None:
        return None

    if isinstance(value, bytes):
        return None

    if not isinstance(value, str):
        return None

    normalized = value.strip().upper()

    if not normalized:
        return None

    return normalized


def _normalize_severity(value: Any) -> str | None:
    if not isinstance(value, str):
        return None

    normalized = value.strip().upper()

    if not normalized:
        return None

    return _SEVERITY_ALIASES.get(normalized)


def _extract_single(vulnerability: Any) -> Severity | None:
    identifier_value = _read_field(
        vulnerability,
        _IDENTIFIER_FIELDS,
    )

    identifier = _normalize_identifier(identifier_value)

    if identifier is None:
        raise ValueError("INVALID_VULNERABILITY_IDENTIFIER")

    severity_value = _read_field(
        vulnerability,
        _SEVERITY_FIELDS,
    )

    severity = _normalize_severity(severity_value)

    if severity is None:
        raise ValueError("INVALID_SEVERITY")

    return Severity(
        identifier=identifier,
        severity=severity,
    )


def extract_severities(
    vulnerabilities: Any,
) -> SeverityExtractionResult:
    if vulnerabilities is None:
        return SeverityExtractionResult(
            severities=(),
            extracted=False,
            status="VULNERABILITIES_IS_NONE",
        )

    if isinstance(vulnerabilities, (str, bytes, bytearray, dict)):
        if isinstance(vulnerabilities, dict):
            collection = (vulnerabilities,)
        else:
            return SeverityExtractionResult(
                severities=(),
                extracted=False,
                status="UNSUPPORTED_VULNERABILITY_COLLECTION",
            )
    else:
        try:
            collection = tuple(vulnerabilities)
        except TypeError:
            return SeverityExtractionResult(
                severities=(),
                extracted=False,
                status="UNSUPPORTED_VULNERABILITY_COLLECTION",
            )

    if not collection:
        return SeverityExtractionResult(
            severities=(),
            extracted=False,
            status="NO_VULNERABILITIES",
        )

    extracted: set[Severity] = set()

    for vulnerability in collection:
        try:
            severity = _extract_single(vulnerability)
        except ValueError as error:
            return SeverityExtractionResult(
                severities=(),
                extracted=False,
                status=str(error),
            )

        if severity is not None:
            extracted.add(severity)

    if not extracted:
        return SeverityExtractionResult(
            severities=(),
            extracted=False,
            status="NO_SEVERITIES",
        )

    ordered = tuple(
        sorted(
            extracted,
            key=lambda item: (
                item.identifier,
                item.severity,
            ),
        )
    )

    return SeverityExtractionResult(
        severities=ordered,
        extracted=True,
        status="SEVERITIES_EXTRACTED",
    )


def extract_severity(
    vulnerability: Any,
) -> SeverityExtractionResult:
    return extract_severities((vulnerability,))
