import pytest

from sentinelshield.audit_engine import AuditEngine
from sentinelshield.project_orchestrator import ProjectOrchestrator
from sentinelshield.recovery_audit import RecoveryAudit
from sentinelshield.recovery_orchestrator import RecoveryOrchestrator
from sentinelshield.recovery_safety_gate import (
    RecoveryDecision,
    RecoveryGateResult,
)


def build_failure(tmp_path):
    project = tmp_path / "demo"
    project.mkdir()

    orchestrator = ProjectOrchestrator()

    orchestrator.register(
        name="demo",
        path=str(project),
    )

    project.rmdir()

    return RecoveryOrchestrator(orchestrator).evaluate("demo")


def build_healthy(tmp_path):
    project = tmp_path / "demo"
    project.mkdir()

    orchestrator = ProjectOrchestrator()

    orchestrator.register(
        name="demo",
        path=str(project),
    )

    return RecoveryOrchestrator(orchestrator).evaluate("demo")


def test_recovery_decision_is_audited(tmp_path):
    recovery_result = build_failure(tmp_path)

    audit = AuditEngine(tmp_path / "audit.jsonl")
    recovery_audit = RecoveryAudit(audit=audit)

    result = recovery_audit.evaluate_and_record(
        recovery_result
    )

    assert result.decision == RecoveryDecision.EXECUTE
    assert result.allowed is True

    events = audit.read_all()

    assert len(events) == 1
    assert events[0]["event"] == "RECOVERY_DECISION"
    assert events[0]["decision"] == "EXECUTE"
    assert events[0]["executed"] is False


def test_healthy_project_is_audited_as_denied(tmp_path):
    recovery_result = build_healthy(tmp_path)

    audit = AuditEngine(tmp_path / "audit.jsonl")
    recovery_audit = RecoveryAudit(audit=audit)

    result = recovery_audit.evaluate_and_record(
        recovery_result
    )

    assert result.decision == RecoveryDecision.DENY
    assert result.allowed is False

    event = audit.read_all()[0]

    assert event["event"] == "RECOVERY_DECISION"
    assert event["decision"] == "DENY"
    assert event["executed"] is False


def test_successful_recovery_execution_is_audited(tmp_path):
    recovery_result = build_failure(tmp_path)

    audit = AuditEngine(tmp_path / "audit.jsonl")
    recovery_audit = RecoveryAudit(audit=audit)

    gate_result = recovery_audit.evaluate_and_record(
        recovery_result
    )

    recovery_audit.record_execution(
        gate_result,
        success=True,
    )

    events = audit.read_all()

    assert len(events) == 2
    assert events[1]["event"] == "RECOVERY_EXECUTED"
    assert events[1]["decision"] == "EXECUTE"
    assert events[1]["executed"] is True


def test_failed_recovery_execution_is_audited(tmp_path):
    recovery_result = build_failure(tmp_path)

    audit = AuditEngine(tmp_path / "audit.jsonl")
    recovery_audit = RecoveryAudit(audit=audit)

    gate_result = recovery_audit.evaluate_and_record(
        recovery_result
    )

    recovery_audit.record_execution(
        gate_result,
        success=False,
    )

    events = audit.read_all()

    assert len(events) == 2
    assert events[1]["event"] == "RECOVERY_FAILED"
    assert events[1]["executed"] is False


def test_invalid_gate_result_rejected(tmp_path):
    recovery_audit = RecoveryAudit(
        audit=AuditEngine(tmp_path / "audit.jsonl")
    )

    with pytest.raises(TypeError):
        recovery_audit.record_execution(
            object(),
            success=True,
        )


def test_audit_persists_jsonl(tmp_path):
    recovery_result = build_failure(tmp_path)

    audit = AuditEngine(tmp_path / "audit.jsonl")
    recovery_audit = RecoveryAudit(audit=audit)

    recovery_audit.evaluate_and_record(
        recovery_result
    )

    assert (tmp_path / "audit.jsonl").exists()
    assert len(
        (tmp_path / "audit.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ) == 1
