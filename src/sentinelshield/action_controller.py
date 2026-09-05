from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from sentinelshield.monitoring_policy_pipeline import PipelineResult


class ActionDecision(str, Enum):
    EXECUTE = "EXECUTE"
    DENY = "DENY"


@dataclass(frozen=True)
class ActionResult:
    decision: ActionDecision
    action: str
    allowed: bool
    reason: str


class ActionController:
    """
    Converts a validated pipeline decision into an explicit action decision.

    This component does NOT execute shell commands and does NOT terminate
    processes. It only authorizes or denies the requested action.
    """

    def decide(
        self,
        pipeline_result: PipelineResult,
        *,
        action: str,
    ) -> ActionResult:

        if not isinstance(pipeline_result, PipelineResult):
            raise TypeError("pipeline_result must be PipelineResult")

        if not isinstance(action, str):
            raise TypeError("action must be str")

        action = action.strip()

        if not action:
            raise ValueError("action must not be empty")

        if pipeline_result.blocked:
            return ActionResult(
                decision=ActionDecision.DENY,
                action=action,
                allowed=False,
                reason="RESOURCE_POLICY_BLOCK",
            )

        if not pipeline_result.allowed:
            return ActionResult(
                decision=ActionDecision.DENY,
                action=action,
                allowed=False,
                reason="POLICY_DENIED",
            )

        return ActionResult(
            decision=ActionDecision.EXECUTE,
            action=action,
            allowed=True,
            reason="POLICY_ALLOWED",
        )

    def require_execute(self, result: ActionResult) -> None:
        if not isinstance(result, ActionResult):
            raise TypeError("result must be ActionResult")

        if result.decision != ActionDecision.EXECUTE:
            raise PermissionError(
                f"action denied: {result.action} | {result.reason}"
            )

    def require_denied(self, result: ActionResult) -> None:
        if not isinstance(result, ActionResult):
            raise TypeError("result must be ActionResult")

        if result.decision != ActionDecision.DENY:
            raise AssertionError(
                f"action unexpectedly allowed: {result.action}"
            )
