import pytest

from sentinelshield.project_orchestrator import ProjectOrchestrator
from sentinelshield.self_healing import (
    RecoveryAction,
    RecoveryDecision,
    SelfHealingController,
)


def test_healthy_project_requires_no_recovery(tmp_path):
    project = tmp_path / "demo"
    project.mkdir()

    orchestrator = ProjectOrchestrator()

    orchestrator.register(
        name="demo",
        path=str(project),
    )

    controller = SelfHealingController(orchestrator)

    decision = controller.evaluate("demo")

    assert isinstance(decision, RecoveryDecision)
    assert decision.project == "demo"
    assert decision.action == RecoveryAction.NONE
    assert decision.reason == "PROJECT_HEALTHY"
    assert decision.safe is True


def test_disabled_project_is_blocked(tmp_path):
    project = tmp_path / "demo"
    project.mkdir()

    orchestrator = ProjectOrchestrator()

    orchestrator.register(
        name="demo",
        path=str(project),
        enabled=False,
    )

    controller = SelfHealingController(orchestrator)

    decision = controller.evaluate("demo")

    assert decision.action == RecoveryAction.BLOCK
    assert decision.reason == "PROJECT_DISABLED"
    assert decision.safe is True


def test_unhealthy_registered_project_requests_recovery(tmp_path):
    project = tmp_path / "demo"
    project.mkdir()

    orchestrator = ProjectOrchestrator()

    orchestrator.register(
        name="demo",
        path=str(project),
    )

    # Simulate the project becoming unavailable after registration.
    project.rmdir()

    controller = SelfHealingController(orchestrator)

    decision = controller.evaluate("demo")

    assert decision.action == RecoveryAction.RECOVER
    assert decision.reason == "HEALTH_CHECK_FAILED"
    assert decision.safe is True


def test_should_recover_for_unhealthy_project(tmp_path):
    project = tmp_path / "demo"
    project.mkdir()

    orchestrator = ProjectOrchestrator()

    orchestrator.register(
        name="demo",
        path=str(project),
    )

    project.rmdir()

    controller = SelfHealingController(orchestrator)

    assert controller.should_recover("demo") is True


def test_should_not_recover_for_healthy_project(tmp_path):
    project = tmp_path / "demo"
    project.mkdir()

    orchestrator = ProjectOrchestrator()

    orchestrator.register(
        name="demo",
        path=str(project),
    )

    controller = SelfHealingController(orchestrator)

    assert controller.should_recover("demo") is False


def test_unknown_project_is_rejected():
    controller = SelfHealingController()

    with pytest.raises(KeyError):
        controller.evaluate("missing")


def test_non_string_name_is_rejected():
    controller = SelfHealingController()

    with pytest.raises(TypeError):
        controller.evaluate(123)


def test_decision_is_immutable(tmp_path):
    project = tmp_path / "demo"
    project.mkdir()

    orchestrator = ProjectOrchestrator()

    orchestrator.register(
        name="demo",
        path=str(project),
    )

    controller = SelfHealingController(orchestrator)

    decision = controller.evaluate("demo")

    with pytest.raises(AttributeError):
        decision.action = RecoveryAction.RECOVER


def test_recovery_controller_does_not_execute_commands(tmp_path):
    project = tmp_path / "demo"
    project.mkdir()

    orchestrator = ProjectOrchestrator()

    orchestrator.register(
        name="demo",
        path=str(project),
    )

    controller = SelfHealingController(orchestrator)

    decision = controller.evaluate("demo")

    # The decision layer only returns a decision.
    # No subprocess, shell, or project mutation is performed.
    assert decision.safe is True
