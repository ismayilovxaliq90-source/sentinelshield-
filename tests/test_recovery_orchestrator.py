import pytest

from sentinelshield.project_orchestrator import ProjectOrchestrator
from sentinelshield.recovery_orchestrator import (
    RecoveryOrchestrator,
    RecoveryResult,
)
from sentinelshield.self_healing import RecoveryAction


def test_healthy_project_needs_no_recovery(tmp_path):
    project = tmp_path / "demo"
    project.mkdir()

    orchestrator = ProjectOrchestrator()
    orchestrator.register(
        name="demo",
        path=str(project),
    )

    recovery = RecoveryOrchestrator(orchestrator)
    result = recovery.evaluate("demo")

    assert isinstance(result, RecoveryResult)
    assert result.attempted is False
    assert result.action == RecoveryAction.NONE
    assert result.success is True
    assert result.reason == "PROJECT_HEALTHY"


def test_failed_project_requires_recovery(tmp_path):
    project = tmp_path / "demo"
    project.mkdir()

    orchestrator = ProjectOrchestrator()
    orchestrator.register(
        name="demo",
        path=str(project),
    )

    project.rmdir()

    recovery = RecoveryOrchestrator(orchestrator)
    result = recovery.evaluate("demo")

    assert result.attempted is True
    assert result.action == RecoveryAction.RECOVER
    assert result.success is False
    assert result.reason == "RECOVERY_REQUIRED"


def test_disabled_project_is_blocked(tmp_path):
    project = tmp_path / "demo"
    project.mkdir()

    orchestrator = ProjectOrchestrator()
    orchestrator.register(
        name="demo",
        path=str(project),
        enabled=False,
    )

    recovery = RecoveryOrchestrator(orchestrator)
    result = recovery.evaluate("demo")

    assert result.attempted is False
    assert result.action == RecoveryAction.BLOCK
    assert result.success is False
    assert result.reason == "PROJECT_DISABLED"


def test_unknown_project_rejected():
    recovery = RecoveryOrchestrator()

    with pytest.raises(KeyError):
        recovery.evaluate("missing")


def test_result_is_immutable(tmp_path):
    project = tmp_path / "demo"
    project.mkdir()

    orchestrator = ProjectOrchestrator()
    orchestrator.register(
        name="demo",
        path=str(project),
    )

    result = RecoveryOrchestrator(
        orchestrator
    ).evaluate("demo")

    with pytest.raises(AttributeError):
        result.success = False
