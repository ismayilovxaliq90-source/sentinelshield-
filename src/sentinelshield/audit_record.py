from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Mapping

__test__ = False


@dataclass(frozen=True)
class AuditRecordInput:
    task_id: str
    action: str
    status: str
    details: Mapping[str, str] | None = None


@dataclass(frozen=True)
class AuditRecord:
    task_id: str
    action: str
    status: str
    details: tuple[tuple[str, str], ...]
    timestamp: str


def _validate(request: AuditRecordInput) -> None:
    if not isinstance(request, AuditRecordInput):
        raise TypeError("INPUT_MUST_BE_AUDIT_RECORD_INPUT")

    for name in ("task_id", "action", "status"):
        value = getattr(request, name)
        if not isinstance(value, str):
            raise TypeError(f"{name.upper()}_MUST_BE_STRING")
        if not value.strip():
            raise ValueError(f"{name.upper()}_MUST_BE_NON_EMPTY")
        if "\x00" in value:
            raise ValueError(f"{name.upper()}_NULL_CHARACTER_NOT_ALLOWED")

    if request.details is not None and not isinstance(request.details, Mapping):
        raise TypeError("DETAILS_MUST_BE_MAPPING")

    if request.details is not None:
        for key, value in request.details.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise TypeError("DETAILS_KEYS_AND_VALUES_MUST_BE_STRINGS")


def create_audit_record(request: AuditRecordInput) -> AuditRecord:
    _validate(request)

    details = tuple(
        sorted((key, value) for key, value in (request.details or {}).items())
    )

    return AuditRecord(
        task_id=request.task_id.strip(),
        action=request.action.strip(),
        status=request.status.strip(),
        details=details,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


def audit_record(request: AuditRecordInput) -> AuditRecord:
    return create_audit_record(request)


audit_record.__test__ = False

def audit_record(request):
    return create_audit_record(request)

audit_record.__test__ = False
