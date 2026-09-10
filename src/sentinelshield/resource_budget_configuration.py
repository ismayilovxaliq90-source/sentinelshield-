from __future__ import annotations

from dataclasses import dataclass
import math
from numbers import Real


class ResourceBudgetConfigurationError(ValueError):
    """Raised when a resource budget is invalid or unsafe."""


@dataclass(frozen=True)
class ResourceBudgetPolicy:
    cpu_percent: float = 100.0
    memory_mb: float = 2048.0
    disk_mb: float = 4096.0
    process_limit: int = 32

    max_cpu_percent: float = 100.0
    max_memory_mb: float = 16384.0
    max_disk_mb: float = 32768.0
    max_process_limit: int = 256


@dataclass(frozen=True)
class ResourceBudgetResult:
    valid: bool
    cpu_percent: float
    memory_mb: float
    disk_mb: float
    process_limit: int
    reason: str

    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "cpu_percent": self.cpu_percent,
            "memory_mb": self.memory_mb,
            "disk_mb": self.disk_mb,
            "process_limit": self.process_limit,
            "reason": self.reason,
        }


def _finite_number(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, Real):
        raise ResourceBudgetConfigurationError(
            f"{field} must be a finite numeric value"
        )

    converted = float(value)

    if not math.isfinite(converted):
        raise ResourceBudgetConfigurationError(
            f"{field} must be finite"
        )

    return converted


def _positive_number(value: object, field: str) -> float:
    converted = _finite_number(value, field)

    if converted <= 0:
        raise ResourceBudgetConfigurationError(
            f"{field} must be greater than zero"
        )

    return converted


def _positive_integer(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ResourceBudgetConfigurationError(
            f"{field} must be a positive integer"
        )

    if value <= 0:
        raise ResourceBudgetConfigurationError(
            f"{field} must be greater than zero"
        )

    return value


def validate_resource_budget_policy(
    policy: ResourceBudgetPolicy | None = None,
) -> ResourceBudgetResult:
    policy = policy or ResourceBudgetPolicy()

    if not isinstance(policy, ResourceBudgetPolicy):
        raise ResourceBudgetConfigurationError(
            "policy must be ResourceBudgetPolicy"
        )

    cpu = _finite_number(policy.cpu_percent, "cpu_percent")
    memory = _positive_number(policy.memory_mb, "memory_mb")
    disk = _positive_number(policy.disk_mb, "disk_mb")
    processes = _positive_integer(
        policy.process_limit,
        "process_limit",
    )

    max_cpu = _finite_number(
        policy.max_cpu_percent,
        "max_cpu_percent",
    )
    max_memory = _positive_number(
        policy.max_memory_mb,
        "max_memory_mb",
    )
    max_disk = _positive_number(
        policy.max_disk_mb,
        "max_disk_mb",
    )
    max_processes = _positive_integer(
        policy.max_process_limit,
        "max_process_limit",
    )

    if cpu <= 0 or cpu > 100:
        raise ResourceBudgetConfigurationError(
            "cpu_percent must be greater than zero and at most 100"
        )

    if max_cpu <= 0 or max_cpu > 100:
        raise ResourceBudgetConfigurationError(
            "max_cpu_percent must be greater than zero and at most 100"
        )

    if max_cpu < cpu:
        raise ResourceBudgetConfigurationError(
            "max_cpu_percent cannot be below cpu_percent"
        )

    if memory > max_memory:
        raise ResourceBudgetConfigurationError(
            "memory_mb exceeds maximum allowed budget"
        )

    if disk > max_disk:
        raise ResourceBudgetConfigurationError(
            "disk_mb exceeds maximum allowed budget"
        )

    if processes > max_processes:
        raise ResourceBudgetConfigurationError(
            "process_limit exceeds maximum allowed budget"
        )

    if max_processes > 1000000:
        raise ResourceBudgetConfigurationError(
            "max_process_limit is unsafe"
        )

    return ResourceBudgetResult(
        valid=True,
        cpu_percent=cpu,
        memory_mb=memory,
        disk_mb=disk,
        process_limit=processes,
        reason="VALID_RESOURCE_BUDGET",
    )


def configure_resource_budget(
    *,
    cpu_percent: object | None = None,
    memory_mb: object | None = None,
    disk_mb: object | None = None,
    process_limit: object | None = None,
    policy: ResourceBudgetPolicy | None = None,
) -> ResourceBudgetResult:
    policy = policy or ResourceBudgetPolicy()

    validated = validate_resource_budget_policy(policy)

    cpu = (
        validated.cpu_percent
        if cpu_percent is None
        else _finite_number(cpu_percent, "cpu_percent")
    )

    memory = (
        validated.memory_mb
        if memory_mb is None
        else _positive_number(memory_mb, "memory_mb")
    )

    disk = (
        validated.disk_mb
        if disk_mb is None
        else _positive_number(disk_mb, "disk_mb")
    )

    processes = (
        validated.process_limit
        if process_limit is None
        else _positive_integer(process_limit, "process_limit")
    )

    if cpu <= 0 or cpu > 100:
        raise ResourceBudgetConfigurationError(
            "cpu_percent must be greater than zero and at most 100"
        )

    if cpu > policy.max_cpu_percent:
        raise ResourceBudgetConfigurationError(
            "cpu_percent exceeds maximum allowed budget"
        )

    if memory > policy.max_memory_mb:
        raise ResourceBudgetConfigurationError(
            "memory_mb exceeds maximum allowed budget"
        )

    if disk > policy.max_disk_mb:
        raise ResourceBudgetConfigurationError(
            "disk_mb exceeds maximum allowed budget"
        )

    if processes > policy.max_process_limit:
        raise ResourceBudgetConfigurationError(
            "process_limit exceeds maximum allowed budget"
        )

    return ResourceBudgetResult(
        valid=True,
        cpu_percent=cpu,
        memory_mb=memory,
        disk_mb=disk,
        process_limit=processes,
        reason="VALID_RESOURCE_BUDGET",
    )


def require_valid_resource_budget(
    **kwargs: object,
) -> ResourceBudgetResult:
    return configure_resource_budget(**kwargs)
