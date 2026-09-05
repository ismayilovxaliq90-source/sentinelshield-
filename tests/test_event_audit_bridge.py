import json

import pytest

from sentinelshield.audit_engine import AuditEngine
from sentinelshield.event_audit_bridge import EventAuditBridge
from sentinelshield.event_engine import (
    EventEngine,
    EventSeverity,
    EventType,
    SecurityEvent,
)


def test_event_is_written_to_audit(tmp_path):
    audit = AuditEngine(tmp_path / "audit.jsonl")
    bridge = EventAuditBridge(audit)

    event = EventEngine().create(
        event_type=EventType.RESOURCE_BLOCK,
        project="demo",
        reason="CPU_LIMIT",
    )

    result = bridge.record(event)

    assert result["event"] == "RESOURCE_BLOCK"
    assert result["decision"] == "CRITICAL"
    assert result["reason"] == "CPU_LIMIT"
    assert result["executed"] is False

    events = audit.read_all()

    assert len(events) == 1
    assert events[0]["event"] == "RESOURCE_BLOCK"


def test_many_events_are_written(tmp_path):
    audit = AuditEngine(tmp_path / "audit.jsonl")
    bridge = EventAuditBridge(audit)
    engine = EventEngine()

    events = [
        engine.create(
            event_type=EventType.PROJECT_HEALTHY,
            project="demo",
            reason="OK",
        ),
        engine.create(
            event_type=EventType.RESOURCE_BLOCK,
            project="demo",
            reason="CPU_LIMIT",
        ),
        engine.create(
            event_type=EventType.RECOVERY_REQUIRED,
            project="demo",
            reason="HEALTH_CHECK_FAILED",
        ),
    ]

    results = bridge.record_many(events)

    assert len(results) == 3
    assert len(audit.read_all()) == 3


def test_invalid_event_rejected(tmp_path):
    bridge = EventAuditBridge(
        AuditEngine(tmp_path / "audit.jsonl")
    )

    with pytest.raises(TypeError):
        bridge.record(object())


def test_invalid_events_list_rejected(tmp_path):
    bridge = EventAuditBridge(
        AuditEngine(tmp_path / "audit.jsonl")
    )

    with pytest.raises(TypeError):
        bridge.record_many("bad")


def test_audit_json_is_valid(tmp_path):
    path = tmp_path / "audit.jsonl"
    audit = AuditEngine(path)
    bridge = EventAuditBridge(audit)

    event = SecurityEvent(
        event_type=EventType.RECOVERY_SUCCESS,
        severity=EventSeverity.INFO,
        project="demo",
        reason="DONE",
        timestamp_utc="2026-01-01T00:00:00+00:00",
    )

    bridge.record(event)

    data = json.loads(
        path.read_text(encoding="utf-8").splitlines()[0]
    )

    assert data["event"] == "RECOVERY_SUCCESS"
    assert data["decision"] == "INFO"
    assert data["reason"] == "DONE"


def test_bridge_uses_supplied_audit(tmp_path):
    audit = AuditEngine(tmp_path / "audit.jsonl")
    bridge = EventAuditBridge(audit)

    assert bridge.audit is audit


def test_record_many_preserves_order(tmp_path):
    audit = AuditEngine(tmp_path / "audit.jsonl")
    bridge = EventAuditBridge(audit)
    engine = EventEngine()

    events = [
        engine.create(
            event_type=EventType.ACTION_DENIED,
            project="one",
            reason="A",
        ),
        engine.create(
            event_type=EventType.RECOVERY_FAILED,
            project="two",
            reason="B",
        ),
    ]

    bridge.record_many(events)

    stored = audit.read_all()

    assert stored[0]["event"] == "ACTION_DENIED"
    assert stored[0]["reason"] == "A"
    assert stored[1]["event"] == "RECOVERY_FAILED"
    assert stored[1]["reason"] == "B"
