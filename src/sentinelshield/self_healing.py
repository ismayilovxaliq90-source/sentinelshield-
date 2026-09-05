from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from sentinelshield.project_orchestrator import (
    OrchestrationResult,
    ProjectOrchestrator,
)


class RecoveryAction(str, Enum):
    NONE = "NONE"
    RECOVER = "RECOVER"
    BLOCK = "BLOCK"


@dataclass(frozen=True)
class RecoveryDecision:
    project: str
    action: RecoveryAction
    reason: str
    safe: bool


class SelfHealingController:
    """
    Safe recovery decision layer.

    This component decides whether recovery is allowed.
    It does NOT execute arbitrary commands or modify projects.
    """

    def __init__(
        self,
        orchestrator: ProjectOrchestrator | None = None,
    ):
        self.orchestrator = orchestrator or ProjectOrchestrator()

    def evaluate(
        self,
        name: str,
    ) -> RecoveryDecision:
        if not isinstance(name, str):
            raise TypeError("name must be str")

        result: OrchestrationResult = self.orchestrator.inspect(name)

        if result.accepted:
            return RecoveryDecision(
                project=name,
                action=RecoveryAction.NONE,
                reason="PROJECT_HEALTHY",
                safe=True,
            )

        if result.reason == "PROJECT_DISABLED":
            return RecoveryDecision(
                project=name,
                action=RecoveryAction.BLOCK,
                reason="PROJECT_DISABLED",
                safe=True,
            )

        if result.reason == "HEALTH_CHECK_FAILED":
            return RecoveryDecision(
                project=name,
                action=RecoveryAction.RECOVER,
                reason="HEALTH_CHECK_FAILED",
                safe=True,
            )

        return RecoveryDecision(
            project=name,
            action=RecoveryAction.BLOCK,
            reason="UNKNOWN_ORCHESTRATION_STATE",
            safe=True,
        )

    def should_recover(self, name: str) -> bool:
        return self.evaluate(name).action == RecoveryAction.RECOVER
