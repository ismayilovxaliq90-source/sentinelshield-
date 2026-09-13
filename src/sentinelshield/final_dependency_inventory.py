from __future__ import annotations

from dataclasses import dataclass


class FinalDependencyInventoryError(ValueError):
    """Raised when final dependency inventory is invalid."""


@dataclass(frozen=True)
class FinalDependencyInventoryInput:
    inventory_id: str
    status: str
    dependency_count: int
    direct_count: int
    transitive_count: int
    inventory_digest: str
    audit_reference: str


@dataclass(frozen=True)
class FinalDependencyInventory:
    inventory_id: str
    status: str
    dependency_count: int
    direct_count: int
    transitive_count: int
    inventory_digest: str
    audit_reference: str


def _text(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field}_MUST_BE_STRING")

    value = value.strip()
    if not value:
        raise FinalDependencyInventoryError(
            f"{field}_MUST_NOT_BE_EMPTY"
        )

    return value


def _count(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{field}_MUST_BE_INTEGER")

    if value < 0:
        raise FinalDependencyInventoryError(
            f"{field}_MUST_NOT_BE_NEGATIVE"
        )

    return value


def _validate_counts(
    dependency_count: int,
    direct_count: int,
    transitive_count: int,
) -> None:
    if direct_count + transitive_count != dependency_count:
        raise FinalDependencyInventoryError(
            "DEPENDENCY_COUNTS_MUST_MATCH_TOTAL"
        )


def create_final_dependency_inventory(
    request: FinalDependencyInventoryInput,
) -> FinalDependencyInventory:
    if not isinstance(
        request,
        FinalDependencyInventoryInput,
    ):
        raise TypeError(
            "INPUT_MUST_BE_FINAL_DEPENDENCY_INVENTORY_INPUT"
        )

    total = _count(
        request.dependency_count,
        "DEPENDENCY_COUNT",
    )
    direct = _count(request.direct_count, "DIRECT_COUNT")
    transitive = _count(
        request.transitive_count,
        "TRANSITIVE_COUNT",
    )

    _validate_counts(total, direct, transitive)

    return FinalDependencyInventory(
        inventory_id=_text(
            request.inventory_id,
            "INVENTORY_ID",
        ),
        status=_text(request.status, "STATUS"),
        dependency_count=total,
        direct_count=direct,
        transitive_count=transitive,
        inventory_digest=_text(
            request.inventory_digest,
            "INVENTORY_DIGEST",
        ),
        audit_reference=_text(
            request.audit_reference,
            "AUDIT_REFERENCE",
        ),
    )


def validate_final_dependency_inventory(
    inventory: FinalDependencyInventory,
) -> bool:
    if not isinstance(
        inventory,
        FinalDependencyInventory,
    ):
        raise TypeError(
            "INVENTORY_MUST_BE_FINAL_DEPENDENCY_INVENTORY"
        )

    _text(inventory.inventory_id, "INVENTORY_ID")
    _text(inventory.status, "STATUS")

    total = _count(
        inventory.dependency_count,
        "DEPENDENCY_COUNT",
    )
    direct = _count(inventory.direct_count, "DIRECT_COUNT")
    transitive = _count(
        inventory.transitive_count,
        "TRANSITIVE_COUNT",
    )

    _validate_counts(total, direct, transitive)

    _text(inventory.inventory_digest, "INVENTORY_DIGEST")
    _text(inventory.audit_reference, "AUDIT_REFERENCE")

    return True
