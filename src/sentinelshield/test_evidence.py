from __future__ import annotations

from dataclasses import dataclass


class TestEvidenceError(ValueError):
    """Raised when test evidence is invalid."""


@dataclass(frozen=True)
class TestEvidenceInput:
    test_run_id: str
    status: str
    total_tests: int
    passed: int
    failed: int
    skipped: int
    duration_seconds: float
    result_digest: str
    audit_reference: str


@dataclass(frozen=True)
class TestEvidence:
    test_run_id: str
    status: str
    total_tests: int
    passed: int
    failed: int
    skipped: int
    duration_seconds: float
    result_digest: str
    audit_reference: str


def _text(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field}_MUST_BE_STRING")

    value = value.strip()
    if not value:
        raise TestEvidenceError(f"{field}_MUST_NOT_BE_EMPTY")

    return value


def _count(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{field}_MUST_BE_INTEGER")

    if value < 0:
        raise TestEvidenceError(f"{field}_MUST_NOT_BE_NEGATIVE")

    return value


def create_test_evidence(
    request: TestEvidenceInput,
) -> TestEvidence:
    if not isinstance(request, TestEvidenceInput):
        raise TypeError("INPUT_MUST_BE_TEST_EVIDENCE_INPUT")

    total = _count(request.total_tests, "TOTAL_TESTS")
    passed = _count(request.passed, "PASSED")
    failed = _count(request.failed, "FAILED")
    skipped = _count(request.skipped, "SKIPPED")

    if passed + failed + skipped != total:
        raise TestEvidenceError("TEST_COUNTS_MUST_MATCH_TOTAL")

    if isinstance(request.duration_seconds, bool) or not isinstance(
        request.duration_seconds, (int, float)
    ):
        raise TypeError("DURATION_SECONDS_MUST_BE_NUMBER")

    if request.duration_seconds < 0:
        raise TestEvidenceError(
            "DURATION_SECONDS_MUST_NOT_BE_NEGATIVE"
        )

    return TestEvidence(
        test_run_id=_text(request.test_run_id, "TEST_RUN_ID"),
        status=_text(request.status, "STATUS"),
        total_tests=total,
        passed=passed,
        failed=failed,
        skipped=skipped,
        duration_seconds=float(request.duration_seconds),
        result_digest=_text(request.result_digest, "RESULT_DIGEST"),
        audit_reference=_text(
            request.audit_reference,
            "AUDIT_REFERENCE",
        ),
    )


def validate_test_evidence(evidence: TestEvidence) -> bool:
    if not isinstance(evidence, TestEvidence):
        raise TypeError("EVIDENCE_MUST_BE_TEST_EVIDENCE")

    _text(evidence.test_run_id, "TEST_RUN_ID")
    _text(evidence.status, "STATUS")

    total = _count(evidence.total_tests, "TOTAL_TESTS")
    passed = _count(evidence.passed, "PASSED")
    failed = _count(evidence.failed, "FAILED")
    skipped = _count(evidence.skipped, "SKIPPED")

    if passed + failed + skipped != total:
        raise TestEvidenceError("TEST_COUNTS_MUST_MATCH_TOTAL")

    if isinstance(evidence.duration_seconds, bool) or not isinstance(
        evidence.duration_seconds, (int, float)
    ):
        raise TypeError("DURATION_SECONDS_MUST_BE_NUMBER")

    if evidence.duration_seconds < 0:
        raise TestEvidenceError(
            "DURATION_SECONDS_MUST_NOT_BE_NEGATIVE"
        )

    _text(evidence.result_digest, "RESULT_DIGEST")
    _text(evidence.audit_reference, "AUDIT_REFERENCE")

    return True
