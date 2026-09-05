from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from sentinelshield.audit_engine import AuditEngine
from sentinelshield.live_monitor import LiveMonitor
from sentinelshield.project_orchestrator import ProjectOrchestrator
from sentinelshield.recovery_audit import RecoveryAudit
from sentinelshield.recovery_executor import (
    RecoveryExecutor,
    RecoveryOperation,
)
from sentinelshield.recovery_orchestrator import RecoveryOrchestrator


@dataclass(frozen=True)
class LiveRecoveryResult:
    project: str
    healthy: bool
    recovery_required: bool
    authorized: bool
    executed: bool
    success: bool
    reason: str


class LiveRecoveryLoop:
    """
    Connects live resource monitoring with project recovery.

    No arbitrary shell commands are executed.
    """

    def __init__(
        self,
        live_monitor: LiveMonitor | None = None,
        orchestrator: ProjectOrchestrator | None = None,
        audit: AuditEngine | None = None,
    ):
        self.live_monitor = live_monitor or LiveMonitor()
        self.orchestrator = orchestrator or ProjectOrchestrator()
        self.audit = audit or AuditEngine()

        self.recovery = RecoveryOrchestrator(
            self.orchestrator
        )

        self.recovery_audit = RecoveryAudit(
            audit=self.audit
        )

        self.executor = RecoveryExecutor()

    def run_once(
        self,
        *,
        project: str,
        path: str | Path,
    ) -> LiveRecoveryResult:

        cycle = self.live_monitor.sample_once()

        if cycle.result.blocked:
            self.audit.record(
                event="RESOURCE_BLOCK",
                action="RECOVERY",
                decision="DENY",
                reason="RESOURCE_POLICY_BLOCK",
                executed=False,
            )

            return LiveRecoveryResult(
                project=project,
                healthy=False,
                recovery_required=False,
                authorized=False,
                executed=False,
                success=False,
                reason="RESOURCE_POLICY_BLOCK",
            )

        recovery_result = self.recovery.evaluate(project)

        gate_result = (
            self.recovery_audit
            .evaluate_and_record(recovery_result)
        )

        if not gate_result.allowed:
            return LiveRecoveryResult(
                project=project,
                healthy=recovery_result.reason
                == "PROJECT_HEALTHY",
                recovery_required=False,
                authorized=False,
                executed=False,
                success=recovery_result.success,
                reason=gate_result.reason,
            )

        execution = self.executor.execute(
            gate_result,
            operation=RecoveryOperation.RECREATE_DIRECTORY,
            path=path,
        )

        self.recovery_audit.record_execution(
            gate_result,
            success=execution.success,
        )

        return LiveRecoveryResult(
            project=project,
            healthy=False,
            recovery_required=True,
            authorized=True,
            executed=execution.executed,
            success=execution.success,
            reason=execution.reason,
        )
