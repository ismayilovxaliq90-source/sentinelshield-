from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from sentinelshield.policy_violation_detector import (
    PolicyViolationDetector,
)


@dataclass(frozen=True)
class RecoveryResult:
    attempted: bool
    recovered: bool
    action: str
    reason: str


class RecoveryManager:
    """
    Handles recovery after a policy violation.

    Recovery is deliberately callback-based at this stage.
    No process termination or destructive operation is performed
    by this component itself.
    """

    def __init__(
        self,
        detector: PolicyViolationDetector,
        recovery_action: Callable[[], bool],
    ):
        self.detector = detector
        self.recovery_action = recovery_action

    def recover(self) -> RecoveryResult:
        violation = self.detector.check()

        if not violation.violated:
            return RecoveryResult(
                attempted=False,
                recovered=False,
                action="NONE",
                reason="NO_VIOLATION",
            )

        try:
            success = bool(
                self.recovery_action()
            )
        except Exception as exc:
            return RecoveryResult(
                attempted=True,
                recovered=False,
                action="RECOVERY_ACTION",
                reason=f"RECOVERY_FAILED:{exc}",
            )

        if success:
            return RecoveryResult(
                attempted=True,
                recovered=True,
                action="RECOVERY_ACTION",
                reason="RECOVERED",
            )

        return RecoveryResult(
            attempted=True,
            recovered=False,
            action="RECOVERY_ACTION",
            reason="RECOVERY_FAILED",
        )
