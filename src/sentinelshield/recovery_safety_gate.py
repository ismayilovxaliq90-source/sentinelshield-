from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from sentinelshield.recovery_orchestrator import RecoveryResult
from sentinelshield.self_healing import RecoveryAction


class RecoveryDecision(str, Enum):
    EXECUTE = "EXECUTE"
    DENY = "DENY"


@dataclass(frozen=True)
class RecoveryGateResult:
    project: str
    decision: RecoveryDecision
    allowed: bool
    reason: str


class RecoverySafetyGate:
    """
    Final authorization layer for recovery.

    This class authorizes recovery only.
    It does not execute commands, restart services, or modify files.
    """

    def decide(self, result: RecoveryResult) -> RecoveryGateResult:
        if not isinstance(result, RecoveryResult):
            raise TypeError("result must be RecoveryResult")

        if result.action == RecoveryAction.RECOVER:
            return RecoveryGateResult(
                project=result.project,
                decision=RecoveryDecision.EXECUTE,
                allowed=True,
                reason="RECOVERY_AUTHORIZED",
            )

        if result.action == RecoveryAction.NONE:
            return RecoveryGateResult(
                project=result.project,
                decision=RecoveryDecision.DENY,
                allowed=False,
                reason="NO_RECOVERY_REQUIRED",
            )

        return RecoveryGateResult(
            project=result.project,
            decision=RecoveryDecision.DENY,
            allowed=False,
            reason="RECOVERY_BLOCKED",
        )

    def require_allowed(self, result: RecoveryGateResult) -> None:
        if not isinstance(result, RecoveryGateResult):
            raise TypeError("result must be RecoveryGateResult")

        if not result.allowed:
            raise PermissionError(
                f"recovery denied: {result.project} | {result.reason}"
            )
