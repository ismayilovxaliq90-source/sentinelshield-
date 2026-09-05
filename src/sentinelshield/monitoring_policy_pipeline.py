from __future__ import annotations

from dataclasses import dataclass

from sentinelshield.policy import PolicyEngine, SentinelPolicy
from sentinelshield.resource_enforcement import (
    EnforcementDecision,
    EnforcementResult,
    ResourceEnforcement,
)


@dataclass(frozen=True)
class ResourceSnapshot:
    cpu_percent: float
    ram_percent: float
    storage_percent: float


@dataclass(frozen=True)
class PipelineResult:
    snapshot: ResourceSnapshot
    enforcement: EnforcementResult
    policy_mode: str
    allowed: bool
    blocked: bool


class MonitoringPolicyPipeline:
    def __init__(
        self,
        policy_engine: PolicyEngine | None = None,
        enforcement: ResourceEnforcement | None = None,
    ) -> None:
        self._policy_engine = policy_engine or PolicyEngine()
        self._enforcement = enforcement or ResourceEnforcement()

    @property
    def policy_engine(self) -> PolicyEngine:
        return self._policy_engine

    def evaluate(
        self,
        *,
        cpu_percent: float,
        ram_percent: float,
        storage_percent: float,
    ) -> PipelineResult:

        snapshot = ResourceSnapshot(
            cpu_percent=float(cpu_percent),
            ram_percent=float(ram_percent),
            storage_percent=float(storage_percent),
        )

        policy = self._policy_engine.policy
        limits = policy.resource_limits

        if policy.mode.value == "MONITOR":
            enforcement = self._enforcement.evaluate(
                cpu_percent=snapshot.cpu_percent,
                ram_percent=snapshot.ram_percent,
                storage_percent=snapshot.storage_percent,
                cpu_limit=limits["cpu"],
                ram_limit=limits["ram"],
                storage_limit=limits["storage"],
            )

            # MONITOR mode never converts the result into an active block.
            if enforcement.decision == EnforcementDecision.BLOCK:
                enforcement = EnforcementResult(
                    decision=EnforcementDecision.ALLOW,
                    safe=True,
                    failures=enforcement.failures,
                    reason="MONITOR_ONLY: " + enforcement.reason,
                )

        else:
            enforcement = self._enforcement.evaluate(
                cpu_percent=snapshot.cpu_percent,
                ram_percent=snapshot.ram_percent,
                storage_percent=snapshot.storage_percent,
                cpu_limit=limits["cpu"],
                ram_limit=limits["ram"],
                storage_limit=limits["storage"],
            )

        return PipelineResult(
            snapshot=snapshot,
            enforcement=enforcement,
            policy_mode=policy.mode.value,
            allowed=enforcement.decision == EnforcementDecision.ALLOW,
            blocked=enforcement.decision == EnforcementDecision.BLOCK,
        )


def build_pipeline(policy: SentinelPolicy | None = None) -> MonitoringPolicyPipeline:
    return MonitoringPolicyPipeline(
        policy_engine=PolicyEngine(policy or SentinelPolicy()),
        enforcement=ResourceEnforcement(),
    )
