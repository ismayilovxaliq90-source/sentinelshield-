from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Sequence


class QueuePriority(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class QueueAction(str, Enum):
    IMMEDIATE_REMEDIATION = "IMMEDIATE_REMEDIATION"
    REMEDIATION_REVIEW = "REMEDIATION_REVIEW"
    SCHEDULE_REMEDIATION = "SCHEDULE_REMEDIATION"
    MONITOR = "MONITOR"


_PRIORITY_ORDER = {
    QueuePriority.CRITICAL: 4,
    QueuePriority.HIGH: 3,
    QueuePriority.MEDIUM: 2,
    QueuePriority.LOW: 1,
}


@dataclass(frozen=True)
class RemediationQueueInput:
    vulnerability_id: str
    triage_score: float
    risk_level: str
    recommended_action: str
    analyst_priority: str


@dataclass(frozen=True)
class RemediationQueueItem:
    queue_rank: int
    vulnerability_id: str
    triage_score: float
    priority: QueuePriority
    action: QueueAction
    original_index: int


@dataclass(frozen=True)
class RemediationQueueResult:
    items: tuple[RemediationQueueItem, ...]
    total: int


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field} must be a string")

    value = value.strip()

    if not value:
        raise ValueError(f"{field} must not be empty")

    return value


def _score(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("triage_score must be numeric")

    result = float(value)

    if result != result:
        raise ValueError("triage_score must not be NaN")

    if result < 0 or result > 100:
        raise ValueError("triage_score must be between 0 and 100")

    return round(result, 2)


def _normalize_item(
    value: RemediationQueueInput | Mapping[str, Any],
) -> RemediationQueueInput:
    if isinstance(value, RemediationQueueInput):
        return RemediationQueueInput(
            vulnerability_id=_text(
                value.vulnerability_id,
                "vulnerability_id",
            ),
            triage_score=_score(value.triage_score),
            risk_level=_text(value.risk_level, "risk_level").upper(),
            recommended_action=_text(
                value.recommended_action,
                "recommended_action",
            ).upper(),
            analyst_priority=_text(
                value.analyst_priority,
                "analyst_priority",
            ).upper(),
        )

    if isinstance(value, Mapping):
        allowed = {
            "vulnerability_id",
            "triage_score",
            "risk_level",
            "recommended_action",
            "analyst_priority",
        }

        unknown = set(value) - allowed
        if unknown:
            raise TypeError(
                "Unsupported queue input fields: "
                + ", ".join(sorted(str(x) for x in unknown))
            )

        required = {
            "vulnerability_id",
            "triage_score",
            "risk_level",
            "recommended_action",
            "analyst_priority",
        }

        missing = required - set(value)
        if missing:
            raise ValueError(
                "Missing queue input fields: "
                + ", ".join(sorted(missing))
            )

        return RemediationQueueInput(
            vulnerability_id=_text(
                value["vulnerability_id"],
                "vulnerability_id",
            ),
            triage_score=_score(value["triage_score"]),
            risk_level=_text(
                value["risk_level"],
                "risk_level",
            ).upper(),
            recommended_action=_text(
                value["recommended_action"],
                "recommended_action",
            ).upper(),
            analyst_priority=_text(
                value["analyst_priority"],
                "analyst_priority",
            ).upper(),
        )

    raise TypeError(
        "Queue item must be RemediationQueueInput or Mapping"
    )


def _priority(item: RemediationQueueInput) -> QueuePriority:
    value = item.analyst_priority

    if value in QueuePriority.__members__:
        return QueuePriority[value]

    if item.risk_level in QueuePriority.__members__:
        return QueuePriority[item.risk_level]

    score = item.triage_score

    if score >= 75:
        return QueuePriority.CRITICAL
    if score >= 50:
        return QueuePriority.HIGH
    if score >= 25:
        return QueuePriority.MEDIUM

    return QueuePriority.LOW


def _action(priority: QueuePriority) -> QueueAction:
    if priority is QueuePriority.CRITICAL:
        return QueueAction.IMMEDIATE_REMEDIATION

    if priority is QueuePriority.HIGH:
        return QueueAction.REMEDIATION_REVIEW

    if priority is QueuePriority.MEDIUM:
        return QueueAction.SCHEDULE_REMEDIATION

    return QueueAction.MONITOR


def create_remediation_queue(
    values: Sequence[
        RemediationQueueInput | Mapping[str, Any]
    ],
) -> RemediationQueueResult:
    if values is None:
        raise TypeError("Queue input must not be None")

    if isinstance(values, (str, bytes, bytearray)):
        raise TypeError("Queue input must be a sequence of items")

    try:
        source = list(values)
    except TypeError as exc:
        raise TypeError(
            "Queue input must be a sequence of items"
        ) from exc

    normalized: list[
        tuple[int, RemediationQueueInput, QueuePriority]
    ] = []

    for index, value in enumerate(source):
        if value is None:
            raise ValueError(f"Queue item is None at index {index}")

        item = _normalize_item(value)
        priority = _priority(item)

        normalized.append((index, item, priority))

    normalized.sort(
        key=lambda entry: (
            -_PRIORITY_ORDER[entry[2]],
            -entry[1].triage_score,
            entry[0],
        )
    )

    result_items = []

    for rank, (original_index, item, priority) in enumerate(
        normalized,
        start=1,
    ):
        result_items.append(
            RemediationQueueItem(
                queue_rank=rank,
                vulnerability_id=item.vulnerability_id,
                triage_score=item.triage_score,
                priority=priority,
                action=_action(priority),
                original_index=original_index,
            )
        )

    return RemediationQueueResult(
        items=tuple(result_items),
        total=len(result_items),
    )


# Public alias.
remediation_queue_creation = create_remediation_queue
