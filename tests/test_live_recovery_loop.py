from pathlib import Path
from types import SimpleNamespace

from sentinelshield.audit_engine import AuditEngine
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


def test_healthy_project_requires_no_recovery(tmp_path):
    orchestrator, project = make_orchestrator(tmp_path)

    audit = AuditEngine(tmp_path / "audit.jsonl")

    loop = LiveRecoveryLoop(
        live_monitor=SafeMonitor(),
        orchestrator=orchestrator,
        audit=audit,
    )

    result = loop.run_once(
        project="demo",
        path=project,
    )

    assert result.healthy is True
    assert result.recovery_required is False
    assert result.authorized is False
    assert result.executed is False
    assert result.success is True
    assert result.reason == "NO_RECOVERY_REQUIRED"


def test_failed_project_is_recovered(tmp_path):
    orchestrator, project = make_orchestrator(tmp_path)

    project.rmdir()

    audit = AuditEngine(tmp_path / "audit.jsonl")

    loop = LiveRecoveryLoop(
        live_monitor=SafeMonitor(),
        orchestrator=orchestrator,
        audit=audit,
    )

    result = loop.run_once(
        project="demo",
        path=project,
    )

    assert result.healthy is False
    assert result.recovery_required is True
    assert result.authorized is True
    assert result.executed is True
    assert result.success is True
    assert result.reason == "DIRECTORY_RECREATED"

    assert project.exists()
    assert project.is_dir()


def test_resource_block_prevents_recovery(tmp_path):
    orchestrator, project = make_orchestrator(tmp_path)

    project.rmdir()

    audit = AuditEngine(tmp_path / "audit.jsonl")

    loop = LiveRecoveryLoop(
        live_monitor=BlockedMonitor(),
        orchestrator=orchestrator,
        audit=audit,
    )

    result = loop.run_once(
        project="demo",
        path=project,
    )

    assert result.recovery_required is False
    assert result.authorized is False
    assert result.executed is False
    assert result.success is False
    assert result.reason == "RESOURCE_POLICY_BLOCK"

    assert not project.exists()

    events = audit.read_all()

    assert len(events) == 1
    assert events[0]["event"] == "RESOURCE_BLOCK"


def test_recovery_is_audited(tmp_path):
    orchestrator, project = make_orchestrator(tmp_path)

    project.rmdir()

    audit = AuditEngine(tmp_path / "audit.jsonl")

    loop = LiveRecoveryLoop(
        live_monitor=SafeMonitor(),
        orchestrator=orchestrator,
        audit=audit,
    )

    loop.run_once(
        project="demo",
        path=project,
    )

    events = audit.read_all()

    assert len(events) == 2
    assert events[0]["event"] == "RECOVERY_DECISION"
    assert events[1]["event"] == "RECOVERY_EXECUTED"


def test_recovery_loop_is_idempotent(tmp_path):
    orchestrator, project = make_orchestrator(tmp_path)

    project.rmdir()

    audit = AuditEngine(tmp_path / "audit.jsonl")

    loop = LiveRecoveryLoop(
        live_monitor=SafeMonitor(),
        orchestrator=orchestrator,
        audit=audit,
    )

    first = loop.run_once(
        project="demo",
        path=project,
    )

    second = loop.run_once(
        project="demo",
        path=project,
    )

    assert first.success is True
    assert first.executed is True

    assert second.success is True
    assert second.executed is False
    assert second.reason == "NO_RECOVERY_REQUIRED"
