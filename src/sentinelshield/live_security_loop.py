from __future__ import annotations

from sentinelshield.action_controller import ActionController
from sentinelshield.audit_engine import AuditEngine
from sentinelshield.live_monitor import LiveMonitor
from sentinelshield.safe_execution_gateway import (
    GatewayResult,
    SafeExecutionGateway,
)


class LiveSecurityLoop:
    """
    Connects live monitoring to authorization, execution and audit.

    Resource observation -> policy evaluation -> action authorization
    -> safe execution -> audit.
    """

    def __init__(
        self,
        live_monitor: LiveMonitor | None = None,
        gateway: SafeExecutionGateway | None = None,
        audit: AuditEngine | None = None,
    ):
        self._live_monitor = live_monitor or LiveMonitor()
        self._audit = audit or AuditEngine()
        self._gateway = gateway or SafeExecutionGateway(
            action_controller=ActionController(),
            audit=self._audit,
        )

    @property
    def live_monitor(self):
        return self._live_monitor

    @property
    def gateway(self):
        return self._gateway

    @property
    def audit(self):
        return self._audit

    def evaluate_action(
        self,
        *,
        action: str,
        command: list[str],
    ) -> GatewayResult:
        cycle = self._live_monitor.sample_once()

        return self._gateway.execute(
            cycle.result,
            action=action,
            command=command,
        )

    def run(
        self,
        *,
        action: str,
        command: list[str],
        max_cycles: int | None = None,
        on_result=None,
    ) -> int:
        if not action:
            raise ValueError("action must not be empty")

        if not isinstance(command, list) or not command:
            raise ValueError("command must be a non-empty list")

        completed = 0

        def process_cycle(cycle):
            nonlocal completed

            result = self._gateway.execute(
                cycle.result,
                action=action,
                command=command,
            )

            completed += 1

            if on_result is not None:
                on_result(result)

        self._live_monitor.run(
            max_cycles=max_cycles,
            on_cycle=process_cycle,
        )

        return completed
