from dataclasses import dataclass


class FinalAcceptanceTaskStatusError(ValueError):
    pass


@dataclass(frozen=True)
class FinalAcceptanceTaskStatus:
    acceptance_id: str
    status: str
    delivery_package_reference: str
    tasks_total: int
    tasks_completed: int
    tasks_failed: int
    tasks_pending: int
    acceptance_digest: str
    audit_reference: str


def _text(value, name):
    if not isinstance(value, str) or not value.strip():
        raise FinalAcceptanceTaskStatusError(
            f"{name.upper()}_MUST_BE_NONEMPTY_STRING"
        )
    return value.strip()


def _count(value, name):
    if isinstance(value, bool) or not isinstance(value, int):
        raise FinalAcceptanceTaskStatusError(
            f"{name.upper()}_MUST_BE_INTEGER"
        )
    if value < 0:
        raise FinalAcceptanceTaskStatusError(
            f"{name.upper()}_MUST_BE_NONNEGATIVE"
        )
    return value


def validate_final_acceptance_task_status(record):
    if not isinstance(record, FinalAcceptanceTaskStatus):
        raise TypeError("INPUT_MUST_BE_FINAL_ACCEPTANCE_TASK_STATUS")

    for name in (
        "acceptance_id",
        "status",
        "delivery_package_reference",
        "acceptance_digest",
        "audit_reference",
    ):
        _text(getattr(record, name), name)

    for name in (
        "tasks_total",
        "tasks_completed",
        "tasks_failed",
        "tasks_pending",
    ):
        _count(getattr(record, name), name)

    if record.status.strip().lower() not in {"accepted", "complete"}:
        raise FinalAcceptanceTaskStatusError("INVALID_ACCEPTANCE_STATUS")

    if record.tasks_total != 297:
        raise FinalAcceptanceTaskStatusError("TASK_TOTAL_MUST_BE_297")

    if (
        record.tasks_completed
        + record.tasks_failed
        + record.tasks_pending
        != record.tasks_total
    ):
        raise FinalAcceptanceTaskStatusError("TASK_COUNTS_DO_NOT_MATCH_TOTAL")

    return record


def create_final_acceptance_task_status(
    acceptance_id,
    status,
    delivery_package_reference,
    tasks_total,
    tasks_completed,
    tasks_failed,
    tasks_pending,
    acceptance_digest,
    audit_reference,
):
    record = FinalAcceptanceTaskStatus(
        acceptance_id=_text(acceptance_id, "acceptance_id"),
        status=_text(status, "status"),
        delivery_package_reference=_text(
            delivery_package_reference,
            "delivery_package_reference",
        ),
        tasks_total=tasks_total,
        tasks_completed=tasks_completed,
        tasks_failed=tasks_failed,
        tasks_pending=tasks_pending,
        acceptance_digest=_text(acceptance_digest, "acceptance_digest"),
        audit_reference=_text(audit_reference, "audit_reference"),
    )
    return validate_final_acceptance_task_status(record)
