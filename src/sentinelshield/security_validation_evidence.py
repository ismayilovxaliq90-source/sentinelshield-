from __future__ import annotations

from dataclasses import dataclass


class SecurityValidationEvidenceError(ValueError):
    """Raised when security validation evidence is invalid."""


@dataclass(frozen=True)
class SecurityValidationEvidenceInput:
    validation_id: str
    status: str
    checks_total: int
    checks_passed: int
    checks_failed: int
    checks_skipped: int
    result_digest: str
    audit_reference: str


@dataclass(frozen=True)
class SecurityValidationEvidence:
    validation_id: str
    status: str
    checks_total: int
    checks_passed: int
    checks_failed: int
    checks_skipped: int
    result_digest: str
    audit_reference: str


def _text(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field}_MUST_BE_STRING")

    value = value.strip()
    if not value:
        raise SecurityValidationEvidenceError(
            f"{field}_MUST_NOT_BE_EMPTY"
        )

    return value


def _count(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{field}_MUST_BE_INTEGER")

    if value < 0:
        raise SecurityValidationEvidenceError(
            f"{field}_MUST_NOT_BE_NEGATIVE"
        )

    return value


def _validate_counts(
    total: int,
    passed: int,
    failed: int,
    skipped: int,
) -> None:
    if passed + failed + skipped != total:
        raise SecurityValidationEvidenceError(
            "CHECK_COUNTS_MUST_MATCH_TOTAL"
        )


def create_security_validation_evidence(
    request: SecurityValidationEvidenceInput,
) -> SecurityValidationEvidence:
    if not isinstance(
        request,
        SecurityValidationEvidenceInput,
    ):
        raise TypeError(
            "INPUT_MUST_BE_SECURITY_VALIDATION_EVIDENCE_INPUT"
        )

    total = _count(request.checks_total, "CHECKS_TOTAL")
    passed = _count(request.checks_passed, "CHECKS_PASSED")
    failed = _count(request.checks_failed, "CHECKS_FAILED")
    skipped = _count(request.checks_skipped, "CHECKS_SKIPPED")

    _validate_counts(total, passed, failed, skipped)

    return SecurityValidationEvidence(
        validation_id=_text(
            request.validation_id,
            "VALIDATION_ID",
        ),
        status=_text(request.status, "STATUS"),
        checks_total=total,
        checks_passed=passed,
        checks_failed=failed,
        checks_skipped=skipped,
        result_digest=_text(
            request.result_digest,
            "RESULT_DIGEST",
        ),
        audit_reference=_text(
            request.audit_reference,
            "AUDIT_REFERENCE",
        ),
    )


def validate_security_validation_evidence(
    evidence: SecurityValidationEvidence,
) -> bool:
    if not isinstance(
        evidence,
        SecurityValidationEvidence,
    ):
        raise TypeError(
            "EVIDENCE_MUST_BE_SECURITY_VALIDATION_EVIDENCE"
        )

    _text(evidence.validation_id, "VALIDATION_ID")
    _text(evidence.status, "STATUS")

    total = _count(evidence.checks_total, "CHECKS_TOTAL")
    passed = _count(evidence.checks_passed, "CHECKS_PASSED")
    failed = _count(evidence.checks_failed, "CHECKS_FAILED")
    skipped = _count(evidence.checks_skipped, "CHECKS_SKIPPED")

    _validate_counts(total, passed, failed, skipped)

    _text(evidence.result_digest, "RESULT_DIGEST")
    _text(evidence.audit_reference, "AUDIT_REFERENCE")

    return True
