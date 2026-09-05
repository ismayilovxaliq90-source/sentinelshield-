from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class EnforcementDecision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"


@dataclass(frozen=True)
class EnforcementResult:
    decision: EnforcementDecision
    safe: bool
    failures: tuple[str, ...]
    reason: str


class ResourceEnforcement:
    """
    Converts resource-gate results into an explicit execution decision.

    This layer does not kill processes and does not modify resources.
    It only determines whether execution may continue.
    """

    def evaluate(
        self,
        *,
        cpu_percent: float,
        ram_percent: float,
        storage_percent: float,
        cpu_limit: float = 80.0,
        ram_limit: float = 80.0,
        storage_limit: float = 90.0,
    ) -> EnforcementResult:

        values = {
            "cpu_percent": cpu_percent,
            "ram_percent": ram_percent,
            "storage_percent": storage_percent,
            "cpu_limit": cpu_limit,
            "ram_limit": ram_limit,
            "storage_limit": storage_limit,
        }

        for name, value in values.items():
            if not isinstance(value, (int, float)):
                raise TypeError(
                    f"{name} must be numeric"
                )

        for name in (
            "cpu_percent",
            "ram_percent",
            "storage_percent",
        ):
            if not 0 <= values[name] <= 100:
                raise ValueError(
                    f"{name} must be between 0 and 100"
                )

        for name in (
            "cpu_limit",
            "ram_limit",
            "storage_limit",
        ):
            if not 0 < values[name] <= 100:
                raise ValueError(
                    f"{name} must be between 0 and 100"
                )

        failures: list[str] = []

        if cpu_percent > cpu_limit:
            failures.append("CPU_LIMIT")

        if ram_percent > ram_limit:
            failures.append("RAM_LIMIT")

        if storage_percent > storage_limit:
            failures.append("STORAGE_LIMIT")

        if failures:
            return EnforcementResult(
                decision=EnforcementDecision.BLOCK,
                safe=False,
                failures=tuple(failures),
                reason="resource limit exceeded",
            )

        return EnforcementResult(
            decision=EnforcementDecision.ALLOW,
            safe=True,
            failures=(),
            reason="resources within configured limits",
        )

    def require_allowed(
        self,
        **kwargs,
    ) -> EnforcementResult:
        result = self.evaluate(**kwargs)

        if result.decision == EnforcementDecision.BLOCK:
            raise PermissionError(
                "resource enforcement blocked execution: "
                + ", ".join(result.failures)
            )

        return result
