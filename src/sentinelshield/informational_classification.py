from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Iterable, Mapping
from typing import Any


@dataclass(frozen=True)
class InformationalVulnerability:
    identifier: str
    package_name: str | None = None
    severity: str = "INFORMATIONAL"


@dataclass(frozen=True)
class InformationalClassificationResult:
    vulnerabilities: tuple[InformationalVulnerability, ...]
    classified: bool
    status: str


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
    "package_name",
    "package",
    "dependency_name",
    "dependency",
    "affected_package",
    "affected_package_name",
)

_SEVERITY_ALIASES = {
    "INFO": "INFORMATIONAL",
    "INFORMATIONAL": "INFORMATIONAL",
    "CRIT": "CRITICAL",
    "CRITICAL": "CRITICAL",
    "CRITICALITY": "CRITICAL",
    "HIGH": "HIGH",
    "MED": "MEDIUM",
    "MEDIUM": "MEDIUM",
    "MODERATE": "MEDIUM",
    "LOW": "LOW",
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


def _normalize_severity(value: Any) -> str | None:
    if not isinstance(value, str):
        return None

    normalized = value.strip().upper()
    if not normalized:
        return None

    return _SEVERITY_ALIASES.get(normalized)


def _normalize_collection(
    vulnerabilities: Any,
) -> tuple[Any, ...] | None:
    if vulnerabilities is None:
        return None

    if isinstance(vulnerabilities, (str, bytes, bytearray)):
        return None

    if isinstance(vulnerabilities, Mapping):
        return (vulnerabilities,)

    try:
        return tuple(vulnerabilities)
    except TypeError:
        return None


def classify_informational_severity(
    vulnerabilities: Any,
) -> InformationalClassificationResult:
    if vulnerabilities is None:
        return InformationalClassificationResult(
            vulnerabilities=(),
            classified=False,
            status="VULNERABILITIES_IS_NONE",
        )

    collection = _normalize_collection(vulnerabilities)

    if collection is None:
        return InformationalClassificationResult(
            vulnerabilities=(),
            classified=False,
            status="UNSUPPORTED_VULNERABILITY_COLLECTION",
        )

    if not collection:
        return InformationalClassificationResult(
            vulnerabilities=(),
            classified=False,
            status="NO_VULNERABILITIES",
        )

    results: set[tuple[str, str | None]] = set()

    for record in collection:
        if record is None or isinstance(
            record, (str, bytes, bytearray, int, float, bool)
        ):
            return InformationalClassificationResult(
                vulnerabilities=(),
                classified=False,
                status="INVALID_VULNERABILITY_RECORD",
            )

        identifier = _normalize_identifier(
            _read_field(record, _IDENTIFIER_FIELDS)
        )

        if identifier is None:
            return InformationalClassificationResult(
                vulnerabilities=(),
                classified=False,
                status="INVALID_VULNERABILITY_IDENTIFIER",
            )

        severity = _normalize_severity(
            _read_field(record, _SEVERITY_FIELDS)
        )

        if severity is None:
            return InformationalClassificationResult(
                vulnerabilities=(),
                classified=False,
                status="INVALID_VULNERABILITY_SEVERITY",
            )

        package_value = _read_field(record, _PACKAGE_FIELDS)

        if package_value is not None:
            package_name = _normalize_package(package_value)

            if isinstance(package_value, str) and package_value.strip():
                if package_name is None:
                    return InformationalClassificationResult(
                        vulnerabilities=(),
                        classified=False,
                        status="INVALID_VULNERABILITY_PACKAGE",
                    )
            elif not isinstance(package_value, str):
                return InformationalClassificationResult(
                    vulnerabilities=(),
                    classified=False,
                    status="INVALID_VULNERABILITY_PACKAGE",
                )
        else:
            package_name = None

        if severity == "INFORMATIONAL":
            results.add((identifier, package_name))

    if not results:
        return InformationalClassificationResult(
            vulnerabilities=(),
            classified=False,
            status="NO_INFORMATIONAL_VULNERABILITIES",
        )

    classified = tuple(
        InformationalVulnerability(
            identifier=identifier,
            package_name=package_name,
        )
        for identifier, package_name in sorted(
            results,
            key=lambda item: (
                item[0],
                item[1] is not None,
                item[1] or "",
            ),
        )
    )

    return InformationalClassificationResult(
        vulnerabilities=classified,
        classified=True,
        status="INFORMATIONAL_VULNERABILITIES_CLASSIFIED",
    )


def informational_classification(
    vulnerabilities: Any,
) -> InformationalClassificationResult:
    return classify_informational_severity(vulnerabilities)
