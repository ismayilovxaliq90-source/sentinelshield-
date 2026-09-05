from pathlib import Path
from types import SimpleNamespace

from sentinelshield.audit_engine import AuditEngine
from sentinelshield.live_event_pipeline import LiveEventPipeline
from sentinelshield.live_recovery_loop import LiveRecoveryLoop
from sentinelshield.project_orchestrator import ProjectOrchestrator


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


def make_orchestrator(tmp_path):
    orchestrator = ProjectOrchestrator()

    project = tmp_path / "demo"
    project.mkdir()

    orchestrator.register(
        name="demo",
        path=str(project),
    )

    return orchestrator, project


def make_pipeline(tmp_path, monitor):
    orchestrator, project = make_orchestrator(tmp_path)

    audit = AuditEngine(
        tmp_path / "audit.jsonl"
    )

    recovery = LiveRecoveryLoop(
        live_monitor=monitor,
        orchestrator=orchestrator,
        audit=audit,
    )

    pipeline = LiveEventPipeline(
        live_recovery=recovery,
        audit=audit,
    )

    return pipeline, orchestrator, project, audit


def test_healthy_project_creates_info_event(tmp_path):
    pipeline, _, project, audit = make_pipeline(
        tmp_path,
        SafeMonitor(),
    )

    result = pipeline.run_once(
        project="demo",
        path=project,
    )

    assert result.event_type.value == "PROJECT_HEALTHY"
    assert result.alert_created is False
    assert result.alert is None

    events = audit.read_all()

    assert len(events) == 2
    assert events[-1]["event"] == "PROJECT_HEALTHY"
    assert events[-1]["decision"] == "INFO"


def test_failed_project_creates_recovery_alert(tmp_path):
    pipeline, _, project, audit = make_pipeline(
        tmp_path,
        SafeMonitor(),
    )

    project.rmdir()

    result = pipeline.run_once(
        project="demo",
        path=project,
    )

    assert result.event_type.value == "RECOVERY_SUCCESS"
    assert result.alert_created is False
    assert result.alert is None

    events = audit.read_all()

    assert any(
        event["event"] == "RECOVERY_EXECUTED"
        for event in events
    )

    assert events[-1]["event"] == "RECOVERY_SUCCESS"
    assert events[-1]["decision"] == "INFO"

    assert project.exists()


def test_resource_block_creates_critical_alert(tmp_path):
    pipeline, _, project, audit = make_pipeline(
        tmp_path,
        BlockedMonitor(),
    )

    project.rmdir()

    result = pipeline.run_once(
        project="demo",
        path=project,
    )

    assert result.event_type.value == "RESOURCE_BLOCK"
    assert result.alert_created is True
    assert result.alert is not None
    assert result.alert.severity.value == "CRITICAL"

    events = audit.read_all()

    assert len(events) == 2
    assert events[0]["event"] == "RESOURCE_BLOCK"
    assert events[0]["decision"] == "DENY"

    assert events[1]["event"] == "RESOURCE_BLOCK"
    assert events[1]["decision"] == "CRITICAL"

    assert not project.exists()


def test_audit_and_event_are_both_present(tmp_path):
    pipeline, _, project, audit = make_pipeline(
        tmp_path,
        SafeMonitor(),
    )

    pipeline.run_once(
        project="demo",
        path=project,
    )

    events = audit.read_all()

    assert len(events) == 2
    assert all("event" in event for event in events)
    assert all("reason" in event for event in events)


def test_alert_contains_project_context(tmp_path):
    pipeline, _, project, audit = make_pipeline(
        tmp_path,
        BlockedMonitor(),
    )

    result = pipeline.run_once(
        project="demo",
        path=project,
    )

    assert result.alert is not None
    assert result.alert.project == "demo"
    assert "demo" in result.alert.message


def test_result_is_immutable(tmp_path):
    pipeline, _, project, _ = make_pipeline(
        tmp_path,
        SafeMonitor(),
    )

    result = pipeline.run_once(
        project="demo",
        path=project,
    )

    try:
        result.event_type = None
        assert False
    except AttributeError:
        pass
