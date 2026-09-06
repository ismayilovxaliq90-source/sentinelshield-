from __future__ import annotations

from dataclasses import dataclass

from sentinelshield.live_resource_enforcement import (
    LiveResourceEnforcer,
)


@dataclass(frozen=True)
class PolicyViolation:
    violated: bool
    decision: str
    failures: tuple[str, ...]
    reason: str


class PolicyViolationDetector:
    """
    Converts a live resource-enforcement decision into
    an explicit policy-violation result.

    This detector observes the decision only.
    It does not execute, terminate, or modify anything.
    """

    def __init__(
        self,
        enforcer: LiveResourceEnforcer,
    ):
        self.enforcer = enforcer

    def check(self) -> PolicyViolation:
        result = self.enforcer.check()

        return PolicyViolation(
            violated=result.blocked,
            decision=result.decision,
            failures=tuple(result.failures),
            reason=result.reason,
        )
