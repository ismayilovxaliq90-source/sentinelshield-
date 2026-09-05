from datetime import datetime, timedelta, timezone
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from sentinelshield.audit_engine import AuditEngine
from sentinelshield.alert_deduplicator import AlertDeduplicator
from sentinelshield.alert_dispatcher import AlertDispatcher
from sentinelshield.alert_store import AlertStore
from sentinelshield.event_audit_bridge import EventAuditBridge
from sentinelshield.event_engine import EventEngine, EventType
from sentinelshield.live_event_pipeline import LiveEventPipeline
from sentinelshield.live_recovery_loop import LiveRecoveryLoop
from sentinelshield.monitoring_policy_pipeline import build_pipeline
from sentinelshield.persistent_alert_pipeline import (
    PersistentAlertPipeline,
)
from sentinelshield.project_orchestrator import ProjectOrchestrator
from sentinelshield.recovery_audit import RecoveryAudit
from sentinelshield.recovery_executor import RecoveryExecutor
from sentinelshield.recovery_orchestrator import RecoveryOrchestrator
from sentinelshield.recovery_pipeline import RecoveryPipeline
from sentinelshield.recovery_safety_gate import RecoverySafetyGate
from sentinelshield.safe_execution_gateway import (
    SafeExecutionGateway,
)
from sentinelshield.action_controller import ActionController


class SafeMonitor:
    def sample_once(self):
        return SimpleNamespace(
            number=1,
            result=SimpleNamespace(
                allowed=True,
                blocked=False,
            ),
        )


class BlockedMonitor:
    def sample_once(self):
        return SimpleNamespace(
            number=1,
            result=SimpleNamespace(
                allowed=False,
                blocked=True,
            ),
        )


class FakeExecutor:
    def __init__(self):
        self.calls = []

    def run(self, command, timeout=30.0):
        self.calls.append((command, timeout))

        return SimpleNamespace(
            returncode=0,
            stdout="OK",
            stderr="",
        )


def test_end_to_end_acceptance():
    with TemporaryDirectory() as tmp:
        root = Path(tmp)

        # ---------------------------------------------------------
        # 1. PROJECT REGISTRY
        # ---------------------------------------------------------
        project = root / "demo"
        project.mkdir()

        (project / "main.py").write_text(
            "print('demo')\n",
            encoding="utf-8",
        )

        registry = ProjectOrchestrator()

        registry.register(
            name="demo",
            path=str(project),
        )

        # ---------------------------------------------------------
        # 2. HEALTH / ORCHESTRATION
        # ---------------------------------------------------------
        ready = registry.inspect("demo")

        assert ready.accepted is True
        assert ready.health.healthy is True

        # ---------------------------------------------------------
        # 3. MONITOR -> POLICY -> ENFORCEMENT
        # ---------------------------------------------------------
        pipeline = build_pipeline()

        safe = pipeline.evaluate(
            cpu_percent=20,
            ram_percent=20,
            storage_percent=20,
        )

        blocked = pipeline.evaluate(
            cpu_percent=95,
            ram_percent=20,
            storage_percent=20,
        )

        assert safe.allowed is True
        assert safe.blocked is False

        assert blocked.allowed is False
        assert blocked.blocked is True

        # ---------------------------------------------------------
        # 4. ACTION -> SAFE EXECUTION GATEWAY
        # ---------------------------------------------------------
        fake_executor = FakeExecutor()

        audit_path = root / "audit.jsonl"
        audit = AuditEngine(audit_path)

        gateway = SafeExecutionGateway(
            action_controller=ActionController(),
            executor=fake_executor,
            audit=audit,
        )

        executed = gateway.execute(
            safe,
            action="HEALTH_CHECK",
            command=["echo", "safe"],
        )

        denied = gateway.execute(
            blocked,
            action="START_PROJECT",
            command=["echo", "blocked"],
        )

        assert executed.executed is True
        assert executed.allowed is True

        assert denied.executed is False
        assert denied.allowed is False

        assert len(fake_executor.calls) == 1

        # ---------------------------------------------------------
        # 5. PROJECT FAILURE -> RECOVERY
        # ---------------------------------------------------------
        shutil.rmtree(project)

        recovery = RecoveryPipeline(
            orchestrator=registry,
            audit=audit,
        )

        recovered = recovery.run(
            "demo",
            path=project,
        )

        assert recovered.authorized is True
        assert recovered.executed is True
        assert recovered.success is True
        assert project.exists()

        # ---------------------------------------------------------
        # 6. LIVE EVENT -> AUDIT -> ALERT
        # ---------------------------------------------------------
        blocked_monitor = BlockedMonitor()

        live_recovery = LiveRecoveryLoop(
            live_monitor=blocked_monitor,
            orchestrator=registry,
            audit=audit,
        )

        live_events = LiveEventPipeline(
            live_recovery=live_recovery,
            audit=audit,
        )

        # Remove project again so the state is intentionally abnormal.
        shutil.rmtree(project)

        event_result = live_events.run_once(
            project="demo",
            path=str(project),
        )

        assert event_result.event_type == EventType.RESOURCE_BLOCK
        assert event_result.alert_created is True
        assert event_result.alert is not None

        # ---------------------------------------------------------
        # 7. ALERT -> DEDUP -> PERSISTENT STORE
        # ---------------------------------------------------------
        alert_store = AlertStore(
            root / "alerts.jsonl"
        )

        alert_pipeline = PersistentAlertPipeline(
            store=alert_store,
            deduplicator=AlertDeduplicator(
                cooldown_seconds=300
            ),
        )

        now = datetime.now(timezone.utc)

        first = alert_pipeline.process(
            event_result.alert,
            now=now,
        )

        duplicate = alert_pipeline.process(
            event_result.alert,
            now=now + timedelta(seconds=10),
        )

        assert first.stored is True
        assert duplicate.stored is False
        assert duplicate.suppressed is True

        assert alert_store.count() == 1

        # ---------------------------------------------------------
        # 8. RESTART PERSISTENCE
        # ---------------------------------------------------------
        restarted_store = AlertStore(
            root / "alerts.jsonl"
        )

        assert restarted_store.count() == 1

        # ---------------------------------------------------------
        # 9. COMPLETE AUDIT
        # ---------------------------------------------------------
        audit_records = audit.read_all()

        assert len(audit_records) >= 4

        assert any(
            item["event"] == "ACTION_EXECUTED"
            for item in audit_records
        )

        assert any(
            item["event"] == "ACTION_DENIED"
            for item in audit_records
        )

        assert any(
            item["event"] == "RECOVERY_DECISION"
            for item in audit_records
        )

        assert any(
            item["event"] == "RECOVERY_EXECUTED"
            for item in audit_records
        )

        assert any(
            item["event"] == "RESOURCE_BLOCK"
            for item in audit_records
        )
