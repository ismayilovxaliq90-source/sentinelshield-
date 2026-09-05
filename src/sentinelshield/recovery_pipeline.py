from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from sentinelshield.audit_engine import AuditEngine
from sentinelshield.project_orchestrator import ProjectOrchestrator
from sentinelshield.recovery_audit import RecoveryAudit
from sentinelshield.recovery_executor import (
    RecoveryExecutor,
    RecoveryOperation,
)
from sentinelshield.recovery_orchestrator import RecoveryOrchestrator


@dataclass(frozen=True)
class PipelineResult:
    project: str
    recovery_required: bool
    authorized: bool
    executed: bool
    success: bool
    reason: str


class RecoveryPipeline:
    """
    Complete safe recovery pipeline.

    Health
      -> Recovery decision
      -> Safety gate
      -> Executor
      -> Audit
    """

    def __init__(
        self,
        orchestrator: ProjectOrchestrator | None = None,
        audit: AuditEngine | None = None,
    ):
        self.orchestrator = (
            orchestrator or ProjectOrchestrator()
        )

        self.audit = audit or AuditEngine()

        self.recovery = RecoveryOrchestrator(
            self.orchestrator
        )

        self.recovery_audit = RecoveryAudit(
            audit=self.audit
        )

        self.executor = RecoveryExecutor()

    def run(
        self,
        name: str,
        *,
        path: str | Path,
    ) -> PipelineResult:

        recovery_result = self.recovery.evaluate(name)

        gate_result = (
            self.recovery_audit
            .evaluate_and_record(recovery_result)
        )

        if not gate_result.allowed:
            return PipelineResult(
                project=name,
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

        return PipelineResult(
            project=name,
            recovery_required=True,
            authorized=True,
            executed=execution.executed,
            success=execution.success,
            reason=execution.reason,
        )
