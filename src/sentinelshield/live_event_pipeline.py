from __future__ import annotations

from dataclasses import dataclass

from sentinelshield.alert_dispatcher import Alert, AlertDispatcher
from sentinelshield.audit_engine import AuditEngine
from sentinelshield.event_audit_bridge import EventAuditBridge
from sentinelshield.event_engine import EventEngine, EventType
from sentinelshield.live_recovery_loop import LiveRecoveryLoop


@dataclass(frozen=True)
class LiveEventResult:
    project: str
    event_type: EventType
    event_reason: str
    alert_created: bool
    alert: Alert | None


class LiveEventPipeline:
    """
    Converts live recovery results into SecurityEvents,
    persists them to AuditEngine, and produces alerts.
    """

    def __init__(
        self,
        live_recovery: LiveRecoveryLoop | None = None,
        audit: AuditEngine | None = None,
    ):
        self.audit = audit or AuditEngine()
        self.live_recovery = live_recovery or LiveRecoveryLoop(
            audit=self.audit
        )
        self.event_engine = EventEngine()
        self.event_bridge = EventAuditBridge(
            audit=self.audit
        )
        self.alert_dispatcher = AlertDispatcher()

    def run_once(
        self,
        *,
        project: str,
        path: str,
    ) -> LiveEventResult:

        recovery = self.live_recovery.run_once(
            project=project,
            path=path,
        )

        if recovery.reason == "RESOURCE_POLICY_BLOCK":
            event_type = EventType.RESOURCE_BLOCK
            reason = recovery.reason

        elif recovery.recovery_required and recovery.success:
            event_type = EventType.RECOVERY_SUCCESS
            reason = recovery.reason

        elif recovery.recovery_required and not recovery.success:
            event_type = EventType.RECOVERY_FAILED
            reason = recovery.reason

        elif recovery.healthy:
            event_type = EventType.PROJECT_HEALTHY
            reason = recovery.reason

        else:
            event_type = EventType.ACTION_DENIED
            reason = recovery.reason

        event = self.event_engine.create(
            event_type=event_type,
            project=project,
            reason=reason,
        )

        self.event_bridge.record(event)

        alert = self.alert_dispatcher.dispatch(event)

        return LiveEventResult(
            project=project,
            event_type=event.event_type,
            event_reason=event.reason,
            alert_created=alert is not None,
            alert=alert,
        )
