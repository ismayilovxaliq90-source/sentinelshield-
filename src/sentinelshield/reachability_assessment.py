from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Mapping
from typing import Any


@dataclass(frozen=True)
class ReachabilityAssessment:
    identifier: str
    package_name: str | None = None
    reachable: bool | None = None
    status: str = "UNKNOWN"


@dataclass(frozen=True)
class ReachabilityAssessmentResult:
    assessments: tuple[ReachabilityAssessment, ...]
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

_REACHABILITY_FIELDS = (
    "reachable",
    "is_reachable",
    "reachability",
    "dependency_reachable",
    "reachable_from_root",
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


def _normalize_reachability(value: Any) -> bool | None:
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
            "reachable",
        }:
            return True

        if normalized in {
            "false",
            "no",
            "n",
            "0",
            "not reachable",
            "not_reachable",
            "unreachable",
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


def assess_reachability(
    vulnerabilities: Any,
) -> ReachabilityAssessmentResult:
    if vulnerabilities is None:
        return ReachabilityAssessmentResult(
            assessments=(),
            assessed=False,
            status="VULNERABILITIES_IS_NONE",
        )

    collection = _normalize_collection(vulnerabilities)

    if collection is None:
        return ReachabilityAssessmentResult(
            assessments=(),
            assessed=False,
            status="UNSUPPORTED_VULNERABILITY_COLLECTION",
        )

    if not collection:
        return ReachabilityAssessmentResult(
            assessments=(),
            assessed=False,
            status="NO_VULNERABILITIES",
        )

    results: dict[
        tuple[str, str | None],
        ReachabilityAssessment,
    ] = {}

    for record in collection:
        if record is None or isinstance(
            record,
            (str, bytes, bytearray, int, float, bool),
        ):
            return ReachabilityAssessmentResult(
                assessments=(),
                assessed=False,
                status="INVALID_VULNERABILITY_RECORD",
            )

        identifier = _normalize_identifier(
            _read_field(record, _IDENTIFIER_FIELDS)
        )

        if identifier is None:
            return ReachabilityAssessmentResult(
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
                return ReachabilityAssessmentResult(
                    assessments=(),
                    assessed=False,
                    status="INVALID_VULNERABILITY_PACKAGE",
                )

        reachability_value = _read_field(
            record,
            _REACHABILITY_FIELDS,
        )

        if reachability_value is None:
            reachable = None
            status = "UNKNOWN"
        else:
            reachable = _normalize_reachability(reachability_value)

            if reachable is None:
                return ReachabilityAssessmentResult(
                    assessments=(),
                    assessed=False,
                    status="INVALID_REACHABILITY_METADATA",
                )

            status = (
                "REACHABLE"
                if reachable
                else "NOT_REACHABLE"
            )

        key = (identifier, package_name)

        results[key] = ReachabilityAssessment(
            identifier=identifier,
            package_name=package_name,
            reachable=reachable,
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

    return ReachabilityAssessmentResult(
        assessments=assessments,
        assessed=True,
        status="REACHABILITY_ASSESSED",
    )


def reachability_assessment(
    vulnerabilities: Any,
) -> ReachabilityAssessmentResult:
    return assess_reachability(vulnerabilities)
