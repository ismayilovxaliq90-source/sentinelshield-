from __future__ import annotations

from sentinelshield.audit_engine import AuditEngine
from sentinelshield.recovery_orchestrator import RecoveryResult
from sentinelshield.recovery_safety_gate import (
    RecoveryDecision,
    RecoveryGateResult,
    RecoverySafetyGate,
)


class RecoveryAudit:
    """
    Records recovery decisions and results in the SentinelShield audit log.
    """

    def __init__(
        self,
        audit: AuditEngine | None = None,
        gate: RecoverySafetyGate | None = None,
    ):
        self.audit = audit or AuditEngine()
        self.gate = gate or RecoverySafetyGate()

    def evaluate_and_record(
        self,
        recovery_result: RecoveryResult,
    ) -> RecoveryGateResult:
        gate_result = self.gate.decide(recovery_result)

        self.audit.record(
            event="RECOVERY_DECISION",
            action="RECOVERY",
            decision=gate_result.decision.value,
            reason=gate_result.reason,
            executed=False,
        )

        return gate_result

    def record_execution(
        self,
        gate_result: RecoveryGateResult,
        *,
        success: bool,
    ) -> None:
        if not isinstance(gate_result, RecoveryGateResult):
            raise TypeError("gate_result must be RecoveryGateResult")

        self.audit.record(
            event="RECOVERY_EXECUTED" if success else "RECOVERY_FAILED",
            action="RECOVERY",
            decision=gate_result.decision.value,
            reason=(
                "RECOVERY_SUCCESS"
                if success
                else "RECOVERY_FAILED"
            ),
            executed=bool(success),
        )
