from __future__ import annotations

from dataclasses import dataclass

from sentinelshield.resource_enforcement import ResourceEnforcement
from sentinelshield.resource_sampler import ResourceSampler


@dataclass(frozen=True)
class LiveResourceDecision:
    cpu_percent: float
    ram_percent: float
    storage_percent: float
    allowed: bool
    blocked: bool
    decision: str
    failures: tuple[str, ...]
    reason: str


class LiveResourceEnforcer:
    """
    Connects the real resource sampler to SentinelShield's
    resource-enforcement policy.

    This class makes a policy decision only.
    It does not kill processes or modify the monitored project.
    """

    def __init__(
        self,
        sampler: ResourceSampler | None = None,
        enforcement: ResourceEnforcement | None = None,
    ):
        self.sampler = (
            sampler
            if sampler is not None
            else ResourceSampler()
        )

        self.enforcement = (
            enforcement
            if enforcement is not None
            else ResourceEnforcement()
        )

    def check(self) -> LiveResourceDecision:
        snapshot = self.sampler.sample()

        result = self.enforcement.evaluate(
            cpu_percent=snapshot.cpu_percent,
            ram_percent=snapshot.ram_percent,
            storage_percent=snapshot.storage_percent,
        )

        return LiveResourceDecision(
            cpu_percent=snapshot.cpu_percent,
            ram_percent=snapshot.ram_percent,
            storage_percent=snapshot.storage_percent,
            allowed=result.safe,
            blocked=not result.safe,
            decision=result.decision.value,
            failures=tuple(result.failures),
            reason=result.reason,
        )
