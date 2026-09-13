from __future__ import annotations

from dataclasses import dataclass


class ExecutionEvidenceError(ValueError):
    """Raised when execution evidence is invalid."""


@dataclass(frozen=True)
class ExecutionEvidenceInput:
    execution_id: str
    status: str
    environment: str
    result: str
    return_code: int
    command_digest: str
    audit_reference: str


@dataclass(frozen=True)
class ExecutionEvidence:
    execution_id: str
    status: str
    environment: str
    result: str
    return_code: int
    command_digest: str
    audit_reference: str


def _text(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field}_MUST_BE_STRING")

    value = value.strip()

    if not value:
        raise ExecutionEvidenceError(
            f"{field}_MUST_NOT_BE_EMPTY"
        )

    return value


def create_execution_evidence(
    request: ExecutionEvidenceInput,
) -> ExecutionEvidence:
    if not isinstance(request, ExecutionEvidenceInput):
        raise TypeError(
            "INPUT_MUST_BE_EXECUTION_EVIDENCE_INPUT"
        )

    execution_id = _text(request.execution_id, "EXECUTION_ID")
    status = _text(request.status, "STATUS")
    environment = _text(request.environment, "ENVIRONMENT")
    result = _text(request.result, "RESULT")
    command_digest = _text(
        request.command_digest,
        "COMMAND_DIGEST",
    )
    audit_reference = _text(
        request.audit_reference,
        "AUDIT_REFERENCE",
    )

    if isinstance(request.return_code, bool) or not isinstance(
        request.return_code,
        int,
    ):
        raise TypeError("RETURN_CODE_MUST_BE_INTEGER")

    return ExecutionEvidence(
        execution_id=execution_id,
        status=status,
        environment=environment,
        result=result,
        return_code=request.return_code,
        command_digest=command_digest,
        audit_reference=audit_reference,
    )


def validate_execution_evidence(
    evidence: ExecutionEvidence,
) -> bool:
    if not isinstance(evidence, ExecutionEvidence):
        raise TypeError(
            "EVIDENCE_MUST_BE_EXECUTION_EVIDENCE"
        )

    _text(evidence.execution_id, "EXECUTION_ID")
    _text(evidence.status, "STATUS")
    _text(evidence.environment, "ENVIRONMENT")
    _text(evidence.result, "RESULT")
    _text(evidence.command_digest, "COMMAND_DIGEST")
    _text(evidence.audit_reference, "AUDIT_REFERENCE")

    if isinstance(evidence.return_code, bool) or not isinstance(
        evidence.return_code,
        int,
    ):
        raise TypeError("RETURN_CODE_MUST_BE_INTEGER")

    return True
