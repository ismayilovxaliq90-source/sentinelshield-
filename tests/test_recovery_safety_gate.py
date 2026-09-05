import pytest

from sentinelshield.project_orchestrator import ProjectOrchestrator
from sentinelshield.recovery_orchestrator import RecoveryOrchestrator
from sentinelshield.recovery_safety_gate import (
    RecoveryDecision,
    RecoveryGateResult,
    RecoverySafetyGate,
)
from sentinelshield.self_healing import RecoveryAction


def test_recovery_is_authorized(tmp_path):
    project = tmp_path / "demo"
    project.mkdir()

    orchestrator = ProjectOrchestrator()
    orchestrator.register(
        name="demo",
        path=str(project),
    )

    project.rmdir()

    recovery = RecoveryOrchestrator(orchestrator)
    recovery_result = recovery.evaluate("demo")

    gate = RecoverySafetyGate()
    result = gate.decide(recovery_result)

    assert isinstance(result, RecoveryGateResult)
    assert result.project == "demo"
    assert result.decision == RecoveryDecision.EXECUTE
    assert result.allowed is True
    assert result.reason == "RECOVERY_AUTHORIZED"


def test_healthy_project_denies_recovery(tmp_path):
    project = tmp_path / "demo"
    project.mkdir()

    orchestrator = ProjectOrchestrator()
    orchestrator.register(
        name="demo",
        path=str(project),
    )

    recovery_result = RecoveryOrchestrator(
        orchestrator
    ).evaluate("demo")

    result = RecoverySafetyGate().decide(recovery_result)

    assert result.decision == RecoveryDecision.DENY
    assert result.allowed is False
    assert result.reason == "NO_RECOVERY_REQUIRED"


def test_disabled_project_denies_recovery(tmp_path):
    project = tmp_path / "demo"
    project.mkdir()

    orchestrator = ProjectOrchestrator()
    orchestrator.register(
        name="demo",
        path=str(project),
        enabled=False,
    )

    recovery_result = RecoveryOrchestrator(
        orchestrator
    ).evaluate("demo")

    result = RecoverySafetyGate().decide(recovery_result)

    assert result.decision == RecoveryDecision.DENY
    assert result.allowed is False
    assert result.reason == "RECOVERY_BLOCKED"


def test_invalid_input_rejected():
    with pytest.raises(TypeError):
        RecoverySafetyGate().decide(object())


def test_require_allowed_accepts_authorized():
    result = RecoveryGateResult(
        project="demo",
        decision=RecoveryDecision.EXECUTE,
        allowed=True,
        reason="RECOVERY_AUTHORIZED",
    )

    RecoverySafetyGate().require_allowed(result)


def test_require_allowed_rejects_denied():
    result = RecoveryGateResult(
        project="demo",
        decision=RecoveryDecision.DENY,
        allowed=False,
        reason="RECOVERY_BLOCKED",
    )

    with pytest.raises(PermissionError):
        RecoverySafetyGate().require_allowed(result)


def test_gate_result_is_immutable():
    result = RecoveryGateResult(
        project="demo",
        decision=RecoveryDecision.EXECUTE,
        allowed=True,
        reason="RECOVERY_AUTHORIZED",
    )

    with pytest.raises(AttributeError):
        result.allowed = False


def test_execute_only_for_recover_action(tmp_path):
    project = tmp_path / "demo"
    project.mkdir()

    orchestrator = ProjectOrchestrator()
    orchestrator.register(
        name="demo",
        path=str(project),
    )

    project.rmdir()

    recovery_result = RecoveryOrchestrator(
        orchestrator
    ).evaluate("demo")

    assert recovery_result.action == RecoveryAction.RECOVER

    gate_result = RecoverySafetyGate().decide(
        recovery_result
    )

    assert gate_result.decision == RecoveryDecision.EXECUTE
