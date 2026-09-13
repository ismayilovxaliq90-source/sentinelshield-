from dataclasses import dataclass


class Task2HandoffError(ValueError):
    pass


@dataclass(frozen=True)
class Task2Handoff:
    handoff_id: str
    status: str
    task_reference: str
    delivery_package_reference: str
    acceptance_reference: str
    tasks_total: int
    handoff_digest: str
    audit_reference: str


def _text(value, name):
    if not isinstance(value, str) or not value.strip():
        raise Task2HandoffError(
            f"{name.upper()}_MUST_BE_NONEMPTY_STRING"
        )
    return value.strip()


def _count(value, name):
    if isinstance(value, bool) or not isinstance(value, int):
        raise Task2HandoffError(
            f"{name.upper()}_MUST_BE_INTEGER"
        )
    if value < 0:
        raise Task2HandoffError(
            f"{name.upper()}_MUST_BE_NONNEGATIVE"
        )
    return value


def validate_task_2_handoff(record):
    if not isinstance(record, Task2Handoff):
        raise TypeError("INPUT_MUST_BE_TASK_2_HANDOFF")

    for name in (
        "handoff_id",
        "status",
        "task_reference",
        "delivery_package_reference",
        "acceptance_reference",
        "handoff_digest",
        "audit_reference",
    ):
        _text(getattr(record, name), name)

    _count(record.tasks_total, "tasks_total")

    if record.status.strip().lower() not in {"ready", "handed_off", "complete"}:
        raise Task2HandoffError("INVALID_HANDOFF_STATUS")

    if record.tasks_total != 297:
        raise Task2HandoffError("TASK_TOTAL_MUST_BE_297")

    return record


def create_task_2_handoff(
    handoff_id,
    status,
    task_reference,
    delivery_package_reference,
    acceptance_reference,
    tasks_total,
    handoff_digest,
    audit_reference,
):
    record = Task2Handoff(
        handoff_id=_text(handoff_id, "handoff_id"),
        status=_text(status, "status"),
        task_reference=_text(task_reference, "task_reference"),
        delivery_package_reference=_text(
            delivery_package_reference,
            "delivery_package_reference",
        ),
        acceptance_reference=_text(
            acceptance_reference,
            "acceptance_reference",
        ),
        tasks_total=tasks_total,
        handoff_digest=_text(handoff_digest, "handoff_digest"),
        audit_reference=_text(audit_reference, "audit_reference"),
    )
    return validate_task_2_handoff(record)
