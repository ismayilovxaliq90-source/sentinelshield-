from __future__ import annotations

from dataclasses import dataclass

from sentinelshield.action_controller import ActionController, ActionDecision
from sentinelshield.monitoring_policy_pipeline import PipelineResult
from sentinelshield.safe_command import SafeCommandExecutor
from sentinelshield.audit_engine import AuditEngine


@dataclass(frozen=True)
class GatewayResult:
    decision: ActionDecision
    action: str
    executed: bool
    returncode: int | None
    stdout: str
    stderr: str
    reason: str

    @property
    def allowed(self) -> bool:
        return self.decision == ActionDecision.EXECUTE


class SafeExecutionGateway:
    """
    Final authorization boundary before safe command execution.

    DENY => command execution is never attempted.
    ALLOW => SafeCommandExecutor is invoked.
    """

    def __init__(
        self,
        action_controller: ActionController | None = None,
        executor: SafeCommandExecutor | None = None,
        audit: AuditEngine | None = None,
    ) -> None:
        self._controller = action_controller or ActionController()
        self._executor = executor or SafeCommandExecutor()
        self._audit = audit or AuditEngine()

    def execute(
        self,
        pipeline_result: PipelineResult,
        *,
        action: str,
        command: list[str],
        timeout: float = 30.0,
    ) -> GatewayResult:

        decision = self._controller.decide(
            pipeline_result,
            action=action,
        )

        if decision.decision != ActionDecision.EXECUTE:
            self._audit.record(
                event="ACTION_DENIED",
                action=decision.action,
                decision=ActionDecision.DENY.value,
                reason=decision.reason,
                executed=False,
            )

            return GatewayResult(
                decision=ActionDecision.DENY,
                action=decision.action,
                executed=False,
                returncode=None,
                stdout="",
                stderr="",
                reason=decision.reason,
            )

        if not isinstance(command, list):
            raise TypeError("command must be list[str]")

        if not command:
            raise ValueError("command must not be empty")

        if not all(isinstance(item, str) and item for item in command):
            raise TypeError("command must contain non-empty strings")

        result = self._executor.run(
            command,
            timeout=timeout,
        )

        self._audit.record(
            event="ACTION_EXECUTED",
            action=decision.action,
            decision=ActionDecision.EXECUTE.value,
            reason="EXECUTED",
            executed=True,
        )

        return GatewayResult(
            decision=ActionDecision.EXECUTE,
            action=decision.action,
            executed=True,
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
            reason="EXECUTED",
        )
