from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any


_IDENTIFIER_FIELDS = (
    "identifier",
    "id",
    "vulnerability_id",
    "vuln_id",
    "cve",
    "ghsa",
)

_SEVERITY_FIELDS = (
    "severity",
    "severity_level",
    "severity_rating",
)

_PACKAGE_FIELDS = (
    "package",
    "package_name",
    "dependency",
    "dependency_name",
    "affected_package",
    "affected_package_name",
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


@dataclass(frozen=True)
class HighVulnerability:
    identifier: str
    package_name: str | None = None
    severity: str = "HIGH"


@dataclass(frozen=True)
class HighSeverityClassificationResult:
    vulnerabilities: tuple[HighVulnerability, ...]
    classified: bool
    status: str


def _read_field(value: Any, fields: tuple[str, ...]) -> tuple[bool, Any]:
    if isinstance(value, dict):
        for field in fields:
            if field in value:
                return True, value[field]
        return False, None

    for field in fields:
        if hasattr(value, field):
            try:
                return True, getattr(value, field)
            except Exception:
                return False, None

    return False, None


def _normalize_identifier(value: Any) -> str | None:
    if value is None or isinstance(value, (bytes, bytearray)):
        return None

    if not isinstance(value, str):
        return None

    value = value.strip().upper()
    return value or None


def _normalize_severity(value: Any) -> str | None:
    if value is None or isinstance(value, (bytes, bytearray)):
        return None

    if not isinstance(value, str):
        return None

    value = value.strip().upper()
    if not value:
        return None

    return _SEVERITY_ALIASES.get(value, value)


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


def _normalize_collection(value: Any) -> tuple[Any, ...] | None:
    if value is None:
        return None

    if isinstance(value, (str, bytes, bytearray)):
        return None

    if isinstance(value, dict):
        return (value,)

    if isinstance(value, Iterable):
        try:
            return tuple(value)
        except Exception:
            return None

    return None


def classify_high_severity(
    vulnerabilities: Any,
) -> HighSeverityClassificationResult:
    if vulnerabilities is None:
        return HighSeverityClassificationResult(
            vulnerabilities=(),
            classified=False,
            status="VULNERABILITIES_IS_NONE",
        )

    collection = _normalize_collection(vulnerabilities)

    if collection is None:
        return HighSeverityClassificationResult(
            vulnerabilities=(),
            classified=False,
            status="UNSUPPORTED_VULNERABILITY_COLLECTION",
        )

    if not collection:
        return HighSeverityClassificationResult(
            vulnerabilities=(),
            classified=False,
            status="NO_VULNERABILITIES",
        )

    high: set[HighVulnerability] = set()

    for vulnerability in collection:
        found_identifier, identifier_value = _read_field(
            vulnerability,
            _IDENTIFIER_FIELDS,
        )

        if not found_identifier:
            return HighSeverityClassificationResult(
                vulnerabilities=(),
                classified=False,
                status="INVALID_VULNERABILITY_RECORD",
            )

        identifier = _normalize_identifier(identifier_value)

        if identifier is None:
            return HighSeverityClassificationResult(
                vulnerabilities=(),
                classified=False,
                status="INVALID_VULNERABILITY_IDENTIFIER",
            )

        found_severity, severity_value = _read_field(
            vulnerability,
            _SEVERITY_FIELDS,
        )

        if not found_severity:
            return HighSeverityClassificationResult(
                vulnerabilities=(),
                classified=False,
                status="INVALID_VULNERABILITY_SEVERITY",
            )

        severity = _normalize_severity(severity_value)

        if severity is None:
            return HighSeverityClassificationResult(
                vulnerabilities=(),
                classified=False,
                status="INVALID_VULNERABILITY_SEVERITY",
            )

        if severity != "HIGH":
            continue

        found_package, package_value = _read_field(
            vulnerability,
            _PACKAGE_FIELDS,
        )

        if found_package:
            if package_value is not None and not isinstance(
                package_value,
                str,
            ):
                return HighSeverityClassificationResult(
                    vulnerabilities=(),
                    classified=False,
                    status="INVALID_VULNERABILITY_PACKAGE",
                )

            package_name = _normalize_package(package_value)
        else:
            package_name = None

        high.add(
            HighVulnerability(
                identifier=identifier,
                package_name=package_name,
            )
        )

    ordered = tuple(
        sorted(
            high,
            key=lambda item: (
                item.identifier,
                item.package_name or "",
            ),
        )
    )

    if not ordered:
        return HighSeverityClassificationResult(
            vulnerabilities=(),
            classified=True,
            status="NO_HIGH_VULNERABILITIES",
        )

    return HighSeverityClassificationResult(
        vulnerabilities=ordered,
        classified=True,
        status="HIGH_VULNERABILITIES_CLASSIFIED",
    )


def high_severity_classification(
    vulnerabilities: Any,
) -> HighSeverityClassificationResult:
    return classify_high_severity(vulnerabilities)


__all__ = [
    "HighVulnerability",
    "HighSeverityClassificationResult",
    "classify_high_severity",
    "high_severity_classification",
]
