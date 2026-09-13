from __future__ import annotations

from dataclasses import dataclass


class FinalRemediationReportError(ValueError):
    """Raised when final remediation report data is invalid."""


@dataclass(frozen=True)
class FinalRemediationReportInput:
    report_id: str
    status: str
    project: str
    summary: str
    dependency_count: int
    vulnerability_count: int
    remediated_count: int
    remaining_count: int
    report_digest: str
    audit_reference: str


@dataclass(frozen=True)
class FinalRemediationReport:
    report_id: str
    status: str
    project: str
    summary: str
    dependency_count: int
    vulnerability_count: int
    remediated_count: int
    remaining_count: int
    report_digest: str
    audit_reference: str


def _text(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field}_MUST_BE_STRING")

    value = value.strip()
    if not value:
        raise FinalRemediationReportError(
            f"{field}_MUST_NOT_BE_EMPTY"
        )

    return value


def _count(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{field}_MUST_BE_INTEGER")

    if value < 0:
        raise FinalRemediationReportError(
            f"{field}_MUST_NOT_BE_NEGATIVE"
        )

    return value


def _validate_counts(
    vulnerability_count: int,
    remediated_count: int,
    remaining_count: int,
) -> None:
    if remediated_count + remaining_count > vulnerability_count:
        raise FinalRemediationReportError(
            "REMEDIATION_COUNTS_EXCEED_VULNERABILITIES"
        )


def create_final_remediation_report(
    request: FinalRemediationReportInput,
) -> FinalRemediationReport:
    if not isinstance(request, FinalRemediationReportInput):
        raise TypeError(
            "INPUT_MUST_BE_FINAL_REMEDIATION_REPORT_INPUT"
        )

    dependency_count = _count(
        request.dependency_count,
        "DEPENDENCY_COUNT",
    )
    vulnerability_count = _count(
        request.vulnerability_count,
        "VULNERABILITY_COUNT",
    )
    remediated_count = _count(
        request.remediated_count,
        "REMEDIATED_COUNT",
    )
    remaining_count = _count(
        request.remaining_count,
        "REMAINING_COUNT",
    )

    _validate_counts(
        vulnerability_count,
        remediated_count,
        remaining_count,
    )

    return FinalRemediationReport(
        report_id=_text(request.report_id, "REPORT_ID"),
        status=_text(request.status, "STATUS"),
        project=_text(request.project, "PROJECT"),
        summary=_text(request.summary, "SUMMARY"),
        dependency_count=dependency_count,
        vulnerability_count=vulnerability_count,
        remediated_count=remediated_count,
        remaining_count=remaining_count,
        report_digest=_text(
            request.report_digest,
            "REPORT_DIGEST",
        ),
        audit_reference=_text(
            request.audit_reference,
            "AUDIT_REFERENCE",
        ),
    )


def validate_final_remediation_report(
    report: FinalRemediationReport,
) -> bool:
    if not isinstance(report, FinalRemediationReport):
        raise TypeError(
            "REPORT_MUST_BE_FINAL_REMEDIATION_REPORT"
        )

    _text(report.report_id, "REPORT_ID")
    _text(report.status, "STATUS")
    _text(report.project, "PROJECT")
    _text(report.summary, "SUMMARY")

    dependency_count = _count(
        report.dependency_count,
        "DEPENDENCY_COUNT",
    )
    vulnerability_count = _count(
        report.vulnerability_count,
        "VULNERABILITY_COUNT",
    )
    remediated_count = _count(
        report.remediated_count,
        "REMEDIATED_COUNT",
    )
    remaining_count = _count(
        report.remaining_count,
        "REMAINING_COUNT",
    )

    if dependency_count < 0:
        raise FinalRemediationReportError(
            "DEPENDENCY_COUNT_MUST_NOT_BE_NEGATIVE"
        )

    _validate_counts(
        vulnerability_count,
        remediated_count,
        remaining_count,
    )

    _text(report.report_digest, "REPORT_DIGEST")
    _text(report.audit_reference, "AUDIT_REFERENCE")

    return True
