from __future__ import annotations

from dataclasses import dataclass


class ChangeDiffEvidenceError(ValueError):
    """Raised when change diff evidence is invalid."""


@dataclass(frozen=True)
class ChangeDiffEvidenceInput:
    change_id: str
    status: str
    files_changed: int
    additions: int
    deletions: int
    diff_digest: str
    audit_reference: str


@dataclass(frozen=True)
class ChangeDiffEvidence:
    change_id: str
    status: str
    files_changed: int
    additions: int
    deletions: int
    diff_digest: str
    audit_reference: str


def _text(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field}_MUST_BE_STRING")

    value = value.strip()
    if not value:
        raise ChangeDiffEvidenceError(
            f"{field}_MUST_NOT_BE_EMPTY"
        )

    return value


def _count(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{field}_MUST_BE_INTEGER")

    if value < 0:
        raise ChangeDiffEvidenceError(
            f"{field}_MUST_NOT_BE_NEGATIVE"
        )

    return value


def create_change_diff_evidence(
    request: ChangeDiffEvidenceInput,
) -> ChangeDiffEvidence:
    if not isinstance(request, ChangeDiffEvidenceInput):
        raise TypeError(
            "INPUT_MUST_BE_CHANGE_DIFF_EVIDENCE_INPUT"
        )

    return ChangeDiffEvidence(
        change_id=_text(request.change_id, "CHANGE_ID"),
        status=_text(request.status, "STATUS"),
        files_changed=_count(
            request.files_changed,
            "FILES_CHANGED",
        ),
        additions=_count(request.additions, "ADDITIONS"),
        deletions=_count(request.deletions, "DELETIONS"),
        diff_digest=_text(
            request.diff_digest,
            "DIFF_DIGEST",
        ),
        audit_reference=_text(
            request.audit_reference,
            "AUDIT_REFERENCE",
        ),
    )


def validate_change_diff_evidence(
    evidence: ChangeDiffEvidence,
) -> bool:
    if not isinstance(evidence, ChangeDiffEvidence):
        raise TypeError(
            "EVIDENCE_MUST_BE_CHANGE_DIFF_EVIDENCE"
        )

    _text(evidence.change_id, "CHANGE_ID")
    _text(evidence.status, "STATUS")
    _count(evidence.files_changed, "FILES_CHANGED")
    _count(evidence.additions, "ADDITIONS")
    _count(evidence.deletions, "DELETIONS")
    _text(evidence.diff_digest, "DIFF_DIGEST")
    _text(evidence.audit_reference, "AUDIT_REFERENCE")

    return True
