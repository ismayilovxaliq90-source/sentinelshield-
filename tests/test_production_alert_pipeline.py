from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from sentinelshield.audit_engine import AuditEngine
from sentinelshield.alert_store import AlertStore
from sentinelshield.live_event_pipeline import LiveEventPipeline
from sentinelshield.live_recovery_loop import LiveRecoveryLoop
from sentinelshield.production_alert_pipeline import (
    ProductionAlertPipeline,
)
from sentinelshield.project_orchestrator import ProjectOrchestrator


BASE = datetime(
    2026,
    1,
    1,
    tzinfo=timezone.utc,
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


def make_pipeline(tmp_path):
    project = tmp_path / "demo"
    project.mkdir()

    orchestrator = ProjectOrchestrator()

    orchestrator.register(
        name="demo",
        path=str(project),
    )

    audit = AuditEngine(
        tmp_path / "audit.jsonl"
    )

    recovery = LiveRecoveryLoop(
        live_monitor=BlockedMonitor(),
        orchestrator=orchestrator,
        audit=audit,
    )

    live_events = LiveEventPipeline(
        live_recovery=recovery,
        audit=audit,
    )

    store = AlertStore(
        tmp_path / "alerts.jsonl"
    )

    production = ProductionAlertPipeline(
        live_event_pipeline=live_events,
        alert_store=store,
        cooldown_seconds=300,
    )

    return production, project, store


def test_block_creates_and_persists_alert(tmp_path):
    pipeline, project, store = make_pipeline(
        tmp_path
    )

    result, persisted = pipeline.run_once(
        project="demo",
        path=str(project),
        now=BASE,
    )

    assert result.event_type.value == "RESOURCE_BLOCK"
    assert result.alert_created is True

    assert persisted is not None
    assert persisted.stored is True
    assert persisted.suppressed is False

    assert store.count() == 1


def test_duplicate_alert_is_suppressed(tmp_path):
    pipeline, project, store = make_pipeline(
        tmp_path
    )

    first, first_persisted = pipeline.run_once(
        project="demo",
        path=str(project),
        now=BASE,
    )

    second, second_persisted = pipeline.run_once(
        project="demo",
        path=str(project),
        now=BASE + timedelta(seconds=10),
    )

    assert first_persisted is not None
    assert first_persisted.stored is True

    assert second_persisted is not None
    assert second_persisted.stored is False
    assert second_persisted.suppressed is True
    assert second_persisted.reason == "DUPLICATE_SUPPRESSED"

    assert store.count() == 1


def test_alert_allowed_after_cooldown(tmp_path):
    pipeline, project, store = make_pipeline(
        tmp_path
    )

    pipeline.run_once(
        project="demo",
        path=str(project),
        now=BASE,
    )

    _, persisted = pipeline.run_once(
        project="demo",
        path=str(project),
        now=BASE + timedelta(seconds=301),
    )

    assert persisted is not None
    assert persisted.stored is True
    assert persisted.reason == "COOLDOWN_EXPIRED"

    assert store.count() == 2


def test_persistent_alert_survives_restart(tmp_path):
    pipeline, project, store = make_pipeline(
        tmp_path
    )

    pipeline.run_once(
        project="demo",
        path=str(project),
        now=BASE,
    )

    restarted = AlertStore(
        tmp_path / "alerts.jsonl"
    )

    assert restarted.count() == 1


def test_full_chain_creates_critical_alert(tmp_path):
    pipeline, project, store = make_pipeline(
        tmp_path
    )

    result, persisted = pipeline.run_once(
        project="demo",
        path=str(project),
        now=BASE,
    )

    assert result.alert is not None
    assert result.alert.severity.value == "CRITICAL"

    assert persisted is not None
    assert persisted.alert.severity.value == "CRITICAL"

    assert store.read_all()[0]["severity"] == "CRITICAL"


def test_audit_and_persistent_alert_both_exist(tmp_path):
    pipeline, project, store = make_pipeline(
        tmp_path
    )

    pipeline.run_once(
        project="demo",
        path=str(project),
        now=BASE,
    )

    audit_records = (
        pipeline
        .live_event_pipeline
        .audit
        .read_all()
    )

    assert len(audit_records) == 2
    assert store.count() == 1


def test_no_alert_means_no_persistence(tmp_path):
    project = tmp_path / "demo"
    project.mkdir()

    orchestrator = ProjectOrchestrator()

    orchestrator.register(
        name="demo",
        path=str(project),
    )

    audit = AuditEngine(
        tmp_path / "audit.jsonl"
    )

    class SafeMonitor:
        def sample_once(self):
            return SimpleNamespace(
                number=1,
                result=SimpleNamespace(
                    allowed=True,
                    blocked=False,
                ),
            )

    recovery = LiveRecoveryLoop(
        live_monitor=SafeMonitor(),
        orchestrator=orchestrator,
        audit=audit,
    )

    live_events = LiveEventPipeline(
        live_recovery=recovery,
        audit=audit,
    )

    store = AlertStore(
        tmp_path / "alerts.jsonl"
    )

    pipeline = ProductionAlertPipeline(
        live_event_pipeline=live_events,
        alert_store=store,
    )

    result, persisted = pipeline.run_once(
        project="demo",
        path=str(project),
        now=BASE,
    )

    assert result.alert_created is False
    assert persisted is None
    assert store.count() == 0
