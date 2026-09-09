from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class RuntimeExposureAssessment:
    identifier: str
    package_name: str | None = None
    exposed: bool | None = None
    status: str = "UNKNOWN"


@dataclass(frozen=True)
class RuntimeExposureAssessmentResult:
    assessments: tuple[RuntimeExposureAssessment, ...]
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

_RUNTIME_EXPOSURE_FIELDS = (
    "runtime_exposed",
    "runtime_exposure",
    "exposed_at_runtime",
    "runtime",
    "runtime_exposure_status",
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


def _normalize_exposure(value: Any) -> bool | None:
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
            "exposed",
            "runtime_exposed",
            "runtime-exposed",
            "active",
        }:
            return True

        if normalized in {
            "false",
            "no",
            "n",
            "0",
            "not exposed",
            "not_exposed",
            "not-exposed",
            "unexposed",
            "inactive",
        }:
            return False

    return None


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


def assess_runtime_exposure(
    vulnerabilities: Any,
) -> RuntimeExposureAssessmentResult:
    if vulnerabilities is None:
        return RuntimeExposureAssessmentResult(
            assessments=(),
            assessed=False,
            status="VULNERABILITIES_IS_NONE",
        )

    collection = _normalize_collection(vulnerabilities)

    if collection is None:
        return RuntimeExposureAssessmentResult(
            assessments=(),
            assessed=False,
            status="UNSUPPORTED_VULNERABILITY_COLLECTION",
        )

    if not collection:
        return RuntimeExposureAssessmentResult(
            assessments=(),
            assessed=False,
            status="NO_VULNERABILITIES",
        )

    results: dict[
        tuple[str, str | None],
        RuntimeExposureAssessment,
    ] = {}

    for record in collection:
        if record is None or isinstance(
            record,
            (str, bytes, bytearray, int, float, bool),
        ):
            return RuntimeExposureAssessmentResult(
                assessments=(),
                assessed=False,
                status="INVALID_VULNERABILITY_RECORD",
            )

        identifier = _normalize_identifier(
            _read_field(record, _IDENTIFIER_FIELDS)
        )

        if identifier is None:
            return RuntimeExposureAssessmentResult(
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
                return RuntimeExposureAssessmentResult(
                    assessments=(),
                    assessed=False,
                    status="INVALID_VULNERABILITY_PACKAGE",
                )

        exposure_value = _read_field(
            record,
            _RUNTIME_EXPOSURE_FIELDS,
        )

        if exposure_value is None:
            exposed = None
            status = "UNKNOWN"
        else:
            exposed = _normalize_exposure(exposure_value)

            if exposed is None:
                return RuntimeExposureAssessmentResult(
                    assessments=(),
                    assessed=False,
                    status="INVALID_RUNTIME_EXPOSURE_METADATA",
                )

            status = "EXPOSED" if exposed else "NOT_EXPOSED"

        key = (identifier, package_name)

        results[key] = RuntimeExposureAssessment(
            identifier=identifier,
            package_name=package_name,
            exposed=exposed,
            status=status,
        )

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

    return RuntimeExposureAssessmentResult(
        assessments=assessments,
        assessed=True,
        status="RUNTIME_EXPOSURE_ASSESSED",
    )


def runtime_exposure_assessment(
    vulnerabilities: Any,
) -> RuntimeExposureAssessmentResult:
    return assess_runtime_exposure(vulnerabilities)
