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
class MediumVulnerability:
    identifier: str
    package_name: str | None = None
    severity: str = "MEDIUM"


@dataclass(frozen=True)
class MediumSeverityClassificationResult:
    vulnerabilities: tuple[MediumVulnerability, ...]
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


def classify_medium_severity(
    vulnerabilities: Any,
) -> MediumSeverityClassificationResult:
    if vulnerabilities is None:
        return MediumSeverityClassificationResult(
            vulnerabilities=(),
            classified=False,
            status="VULNERABILITIES_IS_NONE",
        )

    collection = _normalize_collection(vulnerabilities)

    if collection is None:
        return MediumSeverityClassificationResult(
            vulnerabilities=(),
            classified=False,
            status="UNSUPPORTED_VULNERABILITY_COLLECTION",
        )

    if not collection:
        return MediumSeverityClassificationResult(
            vulnerabilities=(),
            classified=False,
            status="NO_VULNERABILITIES",
        )

    medium: set[MediumVulnerability] = set()

    for vulnerability in collection:
        found_identifier, identifier_value = _read_field(
            vulnerability,
            _IDENTIFIER_FIELDS,
        )

        if not found_identifier:
            return MediumSeverityClassificationResult(
                vulnerabilities=(),
                classified=False,
                status="INVALID_VULNERABILITY_RECORD",
            )

        identifier = _normalize_identifier(identifier_value)

        if identifier is None:
            return MediumSeverityClassificationResult(
                vulnerabilities=(),
                classified=False,
                status="INVALID_VULNERABILITY_IDENTIFIER",
            )

        found_severity, severity_value = _read_field(
            vulnerability,
            _SEVERITY_FIELDS,
        )

        if not found_severity:
            return MediumSeverityClassificationResult(
                vulnerabilities=(),
                classified=False,
                status="INVALID_VULNERABILITY_SEVERITY",
            )

        severity = _normalize_severity(severity_value)

        if severity is None:
            return MediumSeverityClassificationResult(
                vulnerabilities=(),
                classified=False,
                status="INVALID_VULNERABILITY_SEVERITY",
            )

        if severity != "MEDIUM":
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
                return MediumSeverityClassificationResult(
                    vulnerabilities=(),
                    classified=False,
                    status="INVALID_VULNERABILITY_PACKAGE",
                )

            package_name = _normalize_package(package_value)
        else:
            package_name = None

        medium.add(
            MediumVulnerability(
                identifier=identifier,
                package_name=package_name,
            )
        )

    ordered = tuple(
        sorted(
            medium,
            key=lambda item: (
                item.identifier,
                item.package_name or "",
            ),
        )
    )

    if not ordered:
        return MediumSeverityClassificationResult(
            vulnerabilities=(),
            classified=True,
            status="NO_MEDIUM_VULNERABILITIES",
        )

    return MediumSeverityClassificationResult(
        vulnerabilities=ordered,
        classified=True,
        status="MEDIUM_VULNERABILITIES_CLASSIFIED",
    )


def medium_severity_classification(
    vulnerabilities: Any,
) -> MediumSeverityClassificationResult:
    return classify_medium_severity(vulnerabilities)


__all__ = [
    "MediumVulnerability",
    "MediumSeverityClassificationResult",
    "classify_medium_severity",
    "medium_severity_classification",
]
