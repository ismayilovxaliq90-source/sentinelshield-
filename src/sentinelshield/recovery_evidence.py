from __future__ import annotations

from dataclasses import dataclass


class RecoveryEvidenceError(ValueError):
    """Raised when recovery evidence is invalid."""


@dataclass(frozen=True)
class RecoveryEvidenceInput:
    recovery_id: str
    status: str
    action: str
    environment: str
    result: str
    validation_status: str
    state_digest: str
    audit_reference: str


@dataclass(frozen=True)
class RecoveryEvidence:
    recovery_id: str
    status: str
    action: str
    environment: str
    result: str
    validation_status: str
    state_digest: str
    audit_reference: str


def _text(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field}_MUST_BE_STRING")

    value = value.strip()
    if not value:
        raise RecoveryEvidenceError(
            f"{field}_MUST_NOT_BE_EMPTY"
        )

    return value


def create_recovery_evidence(
    request: RecoveryEvidenceInput,
) -> RecoveryEvidence:
    if not isinstance(request, RecoveryEvidenceInput):
        raise TypeError(
            "INPUT_MUST_BE_RECOVERY_EVIDENCE_INPUT"
        )

    return RecoveryEvidence(
        recovery_id=_text(request.recovery_id, "RECOVERY_ID"),
        status=_text(request.status, "STATUS"),
        action=_text(request.action, "ACTION"),
        environment=_text(
            request.environment,
            "ENVIRONMENT",
        ),
        result=_text(request.result, "RESULT"),
        validation_status=_text(
            request.validation_status,
            "VALIDATION_STATUS",
        ),
        state_digest=_text(
            request.state_digest,
            "STATE_DIGEST",
        ),
        audit_reference=_text(
            request.audit_reference,
            "AUDIT_REFERENCE",
        ),
    )


def validate_recovery_evidence(
    evidence: RecoveryEvidence,
) -> bool:
    if not isinstance(evidence, RecoveryEvidence):
        raise TypeError(
            "EVIDENCE_MUST_BE_RECOVERY_EVIDENCE"
        )

    _text(evidence.recovery_id, "RECOVERY_ID")
    _text(evidence.status, "STATUS")
    _text(evidence.action, "ACTION")
    _text(evidence.environment, "ENVIRONMENT")
    _text(evidence.result, "RESULT")
    _text(evidence.validation_status, "VALIDATION_STATUS")
    _text(evidence.state_digest, "STATE_DIGEST")
    _text(evidence.audit_reference, "AUDIT_REFERENCE")

    return True
