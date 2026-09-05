from sentinelshield.audit_engine import AuditEngine
from sentinelshield.project_orchestrator import ProjectOrchestrator
from sentinelshield.recovery_pipeline import (
    PipelineResult,
    RecoveryPipeline,
)


def test_complete_recovery_pipeline(tmp_path):
    project = tmp_path / "demo"
    project.mkdir()

    audit_file = tmp_path / "audit.jsonl"

    orchestrator = ProjectOrchestrator()

    orchestrator.register(
        name="demo",
        path=str(project),
    )

    # Simulate project failure.
    project.rmdir()

    pipeline = RecoveryPipeline(
        orchestrator=orchestrator,
        audit=AuditEngine(audit_file),
    )

    result = pipeline.run(
        "demo",
        path=project,
    )

    assert isinstance(result, PipelineResult)
    assert result.project == "demo"
    assert result.recovery_required is True
    assert result.authorized is True
    assert result.executed is True
    assert result.success is True
    assert result.reason == "DIRECTORY_RECREATED"

    assert project.exists()
    assert project.is_dir()

    events = AuditEngine(audit_file).read_all()

    assert len(events) == 2
    assert events[0]["event"] == "RECOVERY_DECISION"
    assert events[1]["event"] == "RECOVERY_EXECUTED"


def test_healthy_project_does_not_execute_recovery(tmp_path):
    project = tmp_path / "demo"
    project.mkdir()

    audit_file = tmp_path / "audit.jsonl"

    orchestrator = ProjectOrchestrator()

    orchestrator.register(
        name="demo",
        path=str(project),
    )

    pipeline = RecoveryPipeline(
        orchestrator=orchestrator,
        audit=AuditEngine(audit_file),
    )

    result = pipeline.run(
        "demo",
        path=project,
    )

    assert result.authorized is False
    assert result.executed is False
    assert result.success is True
    assert result.reason == "NO_RECOVERY_REQUIRED"

    assert project.exists()


def test_disabled_project_cannot_recover(tmp_path):
    project = tmp_path / "demo"
    project.mkdir()

    audit_file = tmp_path / "audit.jsonl"

    orchestrator = ProjectOrchestrator()

    orchestrator.register(
        name="demo",
        path=str(project),
        enabled=False,
    )

    pipeline = RecoveryPipeline(
        orchestrator=orchestrator,
        audit=AuditEngine(audit_file),
    )

    result = pipeline.run(
        "demo",
        path=project,
    )

    assert result.authorized is False
    assert result.executed is False
    assert result.success is False
    assert result.reason == "RECOVERY_BLOCKED"


def test_missing_project_path_is_recreated(tmp_path):
    project = tmp_path / "missing"

    orchestrator = ProjectOrchestrator()

    # Register the parent so the registry accepts the record.
    registered = tmp_path / "registered"
    registered.mkdir()

    orchestrator.register(
        name="demo",
        path=str(registered),
    )

    # Remove the registered path to create a health failure.
    registered.rmdir()

    pipeline = RecoveryPipeline(
        orchestrator=orchestrator,
        audit=AuditEngine(
            tmp_path / "audit.jsonl"
        ),
    )

    result = pipeline.run(
        "demo",
        path=project,
    )

    assert result.authorized is True
    assert result.executed is True
    assert result.success is True
    assert project.exists()


def test_pipeline_is_idempotent(tmp_path):
    project = tmp_path / "demo"
    project.mkdir()

    audit_file = tmp_path / "audit.jsonl"

    orchestrator = ProjectOrchestrator()

    orchestrator.register(
        name="demo",
        path=str(project),
    )

    project.rmdir()

    pipeline = RecoveryPipeline(
        orchestrator=orchestrator,
        audit=AuditEngine(audit_file),
    )

    first = pipeline.run(
        "demo",
        path=project,
    )

    assert first.success is True
    assert project.exists()

    second = pipeline.run(
        "demo",
        path=project,
    )

    assert second.executed is False
    assert second.success is True
    assert second.reason == "NO_RECOVERY_REQUIRED"
