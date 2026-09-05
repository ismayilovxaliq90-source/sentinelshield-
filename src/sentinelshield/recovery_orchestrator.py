from __future__ import annotations

from dataclasses import dataclass

from sentinelshield.project_orchestrator import ProjectOrchestrator
from sentinelshield.self_healing import (
    RecoveryAction,
    SelfHealingController,
)


@dataclass(frozen=True)
class RecoveryResult:
    project: str
    attempted: bool
    action: RecoveryAction
    success: bool
    reason: str


class RecoveryOrchestrator:
    """
    Safe recovery boundary.

    Decides whether recovery is permitted.
    Does not execute arbitrary shell commands.
    """

    def __init__(
        self,
        orchestrator: ProjectOrchestrator | None = None,
    ):
        self.orchestrator = orchestrator or ProjectOrchestrator()
        self.healing = SelfHealingController(self.orchestrator)

    def evaluate(self, name: str) -> RecoveryResult:
        decision = self.healing.evaluate(name)

        if decision.action == RecoveryAction.NONE:
            return RecoveryResult(
                project=name,
                attempted=False,
                action=decision.action,
                success=True,
                reason="PROJECT_HEALTHY",
            )

        if decision.action == RecoveryAction.BLOCK:
            return RecoveryResult(
                project=name,
                attempted=False,
                action=decision.action,
                success=False,
                reason=decision.reason,
            )

        if decision.action == RecoveryAction.RECOVER:
            return RecoveryResult(
                project=name,
                attempted=True,
                action=decision.action,
                success=False,
                reason="RECOVERY_REQUIRED",
            )

        return RecoveryResult(
            project=name,
            attempted=False,
            action=RecoveryAction.BLOCK,
            success=False,
            reason="UNKNOWN_RECOVERY_ACTION",
        )
