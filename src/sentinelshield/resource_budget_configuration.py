from __future__ import annotations

from dataclasses import dataclass
from numbers import Integral


class ResourceBudgetError(ValueError):
    """Raised when a resource budget is invalid or unsafe."""


@dataclass(frozen=True)
class ResourceBudgetPolicy:
    default_cpu_seconds: int = 300
    minimum_cpu_seconds: int = 1
    maximum_cpu_seconds: int = 3600

    default_memory_mb: int = 1024
    minimum_memory_mb: int = 16
    maximum_memory_mb: int = 16384

    default_disk_mb: int = 2048
    minimum_disk_mb: int = 16
    maximum_disk_mb: int = 32768

    default_processes: int = 32
    minimum_processes: int = 1
    maximum_processes: int = 256


@dataclass(frozen=True)
class ResourceBudget:
    cpu_seconds: int
    memory_mb: int
    disk_mb: int
    processes: int

    def to_dict(self) -> dict:
        return {
            "cpu_seconds": self.cpu_seconds,
            "memory_mb": self.memory_mb,
            "disk_mb": self.disk_mb,
            "processes": self.processes,
        }


@dataclass(frozen=True)
class ResourceBudgetResult:
    valid: bool
    budget: ResourceBudget
    reason: str

    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "budget": self.budget.to_dict(),
            "reason": self.reason,
        }


def _validate_positive_integer(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, Integral):
        raise ResourceBudgetError(
            f"{field} must be a positive integer"
        )

    value = int(value)

    if value <= 0:
        raise ResourceBudgetError(
            f"{field} must be greater than zero"
        )

    return value


def _validate_range(
    value: object,
    field: str,
    minimum: object,
    maximum: object,
) -> int:
    value_int = _validate_positive_integer(value, field)
    minimum_int = _validate_positive_integer(minimum, f"{field}.minimum")
    maximum_int = _validate_positive_integer(maximum, f"{field}.maximum")

    if minimum_int > maximum_int:
        raise ResourceBudgetError(
            f"{field} minimum cannot exceed maximum"
        )

    if value_int < minimum_int:
        raise ResourceBudgetError(
            f"{field} is below minimum allowed value"
        )

    if value_int > maximum_int:
        raise ResourceBudgetError(
            f"{field} exceeds maximum allowed value"
        )

    return value_int


def validate_resource_budget_policy(
    policy: ResourceBudgetPolicy | None = None,
) -> ResourceBudgetPolicy:
    if policy is None:
        policy = ResourceBudgetPolicy()

    if not isinstance(policy, ResourceBudgetPolicy):
        raise ResourceBudgetError(
            "policy must be ResourceBudgetPolicy"
        )

    _validate_range(
        policy.default_cpu_seconds,
        "default_cpu_seconds",
        policy.minimum_cpu_seconds,
        policy.maximum_cpu_seconds,
    )

    _validate_range(
        policy.default_memory_mb,
        "default_memory_mb",
        policy.minimum_memory_mb,
        policy.maximum_memory_mb,
    )

    _validate_range(
        policy.default_disk_mb,
        "default_disk_mb",
        policy.minimum_disk_mb,
        policy.maximum_disk_mb,
    )

    _validate_range(
        policy.default_processes,
        "default_processes",
        policy.minimum_processes,
        policy.maximum_processes,
    )

    return policy


def configure_resource_budget(
    *,
    cpu_seconds: object | None = None,
    memory_mb: object | None = None,
    disk_mb: object | None = None,
    processes: object | None = None,
    policy: ResourceBudgetPolicy | None = None,
) -> ResourceBudgetResult:
    policy = validate_resource_budget_policy(policy)

    cpu = (
        policy.default_cpu_seconds
        if cpu_seconds is None
        else _validate_range(
            cpu_seconds,
            "cpu_seconds",
            policy.minimum_cpu_seconds,
            policy.maximum_cpu_seconds,
        )
    )

    memory = (
        policy.default_memory_mb
        if memory_mb is None
        else _validate_range(
            memory_mb,
            "memory_mb",
            policy.minimum_memory_mb,
            policy.maximum_memory_mb,
        )
    )

    disk = (
        policy.default_disk_mb
        if disk_mb is None
        else _validate_range(
            disk_mb,
            "disk_mb",
            policy.minimum_disk_mb,
            policy.maximum_disk_mb,
        )
    )

    process_count = (
        policy.default_processes
        if processes is None
        else _validate_range(
            processes,
            "processes",
            policy.minimum_processes,
            policy.maximum_processes,
        )
    )

    budget = ResourceBudget(
        cpu_seconds=cpu,
        memory_mb=memory,
        disk_mb=disk,
        processes=process_count,
    )

    return ResourceBudgetResult(
        valid=True,
        budget=budget,
        reason="VALID_RESOURCE_BUDGET",
    )


def require_valid_resource_budget(
    *,
    cpu_seconds: object | None = None,
    memory_mb: object | None = None,
    disk_mb: object | None = None,
    processes: object | None = None,
    policy: ResourceBudgetPolicy | None = None,
) -> ResourceBudget:
    result = configure_resource_budget(
        cpu_seconds=cpu_seconds,
        memory_mb=memory_mb,
        disk_mb=disk_mb,
        processes=processes,
        policy=policy,
    )

    return result.budget
