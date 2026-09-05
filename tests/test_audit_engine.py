import json

import pytest

from sentinelshield.audit_engine import AuditEngine


def test_record_creates_audit_file(tmp_path):
    audit = AuditEngine(tmp_path / "audit.jsonl")

    result = audit.record(
        event="POLICY_DECISION",
        action="START_PROJECT",
        decision="DENY",
        reason="RESOURCE_POLICY_BLOCK",
        executed=False,
    )

    assert result["event"] == "POLICY_DECISION"
    assert result["decision"] == "DENY"
    assert result["executed"] is False


def test_record_is_persisted(tmp_path):
    path = tmp_path / "audit.jsonl"
    audit = AuditEngine(path)

    audit.record(
        event="ACTION",
        action="TEST",
        decision="EXECUTE",
        reason="POLICY_ALLOWED",
        executed=True,
    )

    lines = path.read_text(encoding="utf-8").splitlines()

    assert len(lines) == 1

    data = json.loads(lines[0])
    assert data["action"] == "TEST"
    assert data["executed"] is True


def test_read_all(tmp_path):
    audit = AuditEngine(tmp_path / "audit.jsonl")

    audit.record(
        event="A",
        action="ONE",
        decision="EXECUTE",
        reason="OK",
        executed=True,
    )

    audit.record(
        event="B",
        action="TWO",
        decision="DENY",
        reason="BLOCKED",
        executed=False,
    )

    events = audit.read_all()

    assert len(events) == 2
    assert events[0]["action"] == "ONE"
    assert events[1]["decision"] == "DENY"


def test_empty_event_rejected(tmp_path):
    audit = AuditEngine(tmp_path / "audit.jsonl")

    with pytest.raises(ValueError):
        audit.record(
            event="",
            action="TEST",
            decision="DENY",
            reason="TEST",
        )


def test_empty_action_rejected(tmp_path):
    audit = AuditEngine(tmp_path / "audit.jsonl")

    with pytest.raises(ValueError):
        audit.record(
            event="TEST",
            action="",
            decision="DENY",
            reason="TEST",
        )


def test_missing_file_returns_empty(tmp_path):
    audit = AuditEngine(tmp_path / "missing.jsonl")

    assert audit.read_all() == []
