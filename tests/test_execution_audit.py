import json

import pytest

from sentinelshield.execution_audit import (
    AuditEvent,
    ExecutionAudit,
)


class FakeClock:
    def __init__(self, value=1000.0):
        self.value = value

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


def test_audit_can_be_created():
    audit = ExecutionAudit()

    assert audit.count() == 0


def test_initial_events_are_empty():
    audit = ExecutionAudit()

    assert audit.events() == ()
    assert audit.last_event() is None


def test_record_creates_audit_event():
    audit = ExecutionAudit()

    event = audit.record(
        execution_id="exec-1",
        event_type="START",
        status="RUNNING",
        message="execution started",
    )

    assert isinstance(event, AuditEvent)
    assert event.sequence == 1
    assert event.execution_id == "exec-1"
    assert event.event_type == "START"
    assert event.status == "RUNNING"


def test_timestamp_is_recorded():
    clock = FakeClock(1234.5)
    audit = ExecutionAudit(clock=clock)

    event = audit.record(
        execution_id="exec-1",
        event_type="START",
        status="RUNNING",
        message="started",
    )

    assert event.timestamp == 1234.5


def test_sequence_increments():
    audit = ExecutionAudit()

    first = audit.record(
        execution_id="exec-1",
        event_type="START",
        status="RUNNING",
        message="started",
    )

    second = audit.record(
        execution_id="exec-1",
        event_type="END",
        status="SUCCESS",
        message="completed",
    )

    assert first.sequence == 1
    assert second.sequence == 2


def test_last_event_returns_latest():
    audit = ExecutionAudit()

    audit.record(
        execution_id="exec-1",
        event_type="START",
        status="RUNNING",
        message="started",
    )

    event = audit.record(
        execution_id="exec-1",
        event_type="END",
        status="SUCCESS",
        message="completed",
    )

    assert audit.last_event() == event


def test_events_returns_tuple():
    audit = ExecutionAudit()

    audit.record(
        execution_id="exec-1",
        event_type="START",
        status="RUNNING",
        message="started",
    )

    assert isinstance(audit.events(), tuple)


def test_count_is_correct():
    audit = ExecutionAudit()

    audit.record(
        execution_id="exec-1",
        event_type="START",
        status="RUNNING",
        message="started",
    )

    audit.record(
        execution_id="exec-1",
        event_type="END",
        status="SUCCESS",
        message="completed",
    )

    assert audit.count() == 2


def test_empty_execution_id_is_rejected():
    audit = ExecutionAudit()

    with pytest.raises(ValueError):
        audit.record(
            execution_id="",
            event_type="START",
            status="RUNNING",
            message="started",
        )


def test_invalid_execution_id_type_is_rejected():
    audit = ExecutionAudit()

    with pytest.raises(TypeError):
        audit.record(
            execution_id=123,
            event_type="START",
            status="RUNNING",
            message="started",
        )


def test_empty_event_type_is_rejected():
    audit = ExecutionAudit()

    with pytest.raises(ValueError):
        audit.record(
            execution_id="exec-1",
            event_type="",
            status="RUNNING",
            message="started",
        )


def test_empty_status_is_rejected():
    audit = ExecutionAudit()

    with pytest.raises(ValueError):
        audit.record(
            execution_id="exec-1",
            event_type="START",
            status="",
            message="started",
        )


def test_empty_message_is_rejected():
    audit = ExecutionAudit()

    with pytest.raises(ValueError):
        audit.record(
            execution_id="exec-1",
            event_type="START",
            status="RUNNING",
            message="",
        )


def test_secret_message_is_redacted():
    audit = ExecutionAudit()

    event = audit.record(
        execution_id="exec-1",
        event_type="ERROR",
        status="FAILED",
        message="password=super-secret-value",
    )

    assert "super-secret-value" not in event.message
    assert "[REDACTED]" in event.message


def test_api_key_message_is_redacted():
    audit = ExecutionAudit()

    event = audit.record(
        execution_id="exec-1",
        event_type="ERROR",
        status="FAILED",
        message="api_key=super-secret-value",
    )

    assert "super-secret-value" not in event.message
    assert "[REDACTED]" in event.message


def test_redact_rejects_non_string():
    with pytest.raises(TypeError):
        ExecutionAudit.redact(123)


def test_command_digest_is_sha256():
    digest = ExecutionAudit.command_digest(
        ["python", "-m", "pytest"]
    )

    assert len(digest) == 64
    assert all(
        character in "0123456789abcdef"
        for character in digest
    )


def test_same_command_has_same_digest():
    first = ExecutionAudit.command_digest(
        ["python", "-m", "pytest"]
    )

    second = ExecutionAudit.command_digest(
        ["python", "-m", "pytest"]
    )

    assert first == second


def test_different_command_has_different_digest():
    first = ExecutionAudit.command_digest(
        ["python", "-m", "pytest"]
    )

    second = ExecutionAudit.command_digest(
        ["python", "-m", "unittest"]
    )

    assert first != second


def test_command_digest_rejects_string():
    with pytest.raises(TypeError):
        ExecutionAudit.command_digest(
            "python -m pytest"
        )


def test_command_digest_rejects_empty_command():
    with pytest.raises(ValueError):
        ExecutionAudit.command_digest([])


def test_command_digest_rejects_non_string_items():
    with pytest.raises(TypeError):
        ExecutionAudit.command_digest(
            ["python", 123]
        )


def test_command_digest_is_stored_on_event():
    audit = ExecutionAudit()

    event = audit.record(
        execution_id="exec-1",
        event_type="START",
        status="RUNNING",
        message="started",
        command=["python", "-m", "pytest"],
    )

    assert event.command_digest == (
        ExecutionAudit.command_digest(
            ["python", "-m", "pytest"]
        )
    )


def test_command_digest_does_not_store_command():
    audit = ExecutionAudit()

    event = audit.record(
        execution_id="exec-1",
        event_type="START",
        status="RUNNING",
        message="started",
        command=[
            "python",
            "--token=very-secret",
        ],
    )

    assert "very-secret" not in str(event)


def test_events_are_immutable():
    audit = ExecutionAudit()

    event = audit.record(
        execution_id="exec-1",
        event_type="START",
        status="RUNNING",
        message="started",
    )

    with pytest.raises(AttributeError):
        event.status = "FAILED"


def test_clear_removes_events():
    audit = ExecutionAudit()

    audit.record(
        execution_id="exec-1",
        event_type="START",
        status="RUNNING",
        message="started",
    )

    audit.clear()

    assert audit.count() == 0
    assert audit.events() == ()
    assert audit.last_event() is None


def test_clear_resets_sequence():
    audit = ExecutionAudit()

    audit.record(
        execution_id="exec-1",
        event_type="START",
        status="RUNNING",
        message="started",
    )

    audit.clear()

    event = audit.record(
        execution_id="exec-2",
        event_type="START",
        status="RUNNING",
        message="started",
    )

    assert event.sequence == 1


def test_export_json_is_valid_json():
    audit = ExecutionAudit()

    audit.record(
        execution_id="exec-1",
        event_type="START",
        status="RUNNING",
        message="started",
    )

    payload = audit.export_json()
    parsed = json.loads(payload)

    assert isinstance(parsed, list)
    assert len(parsed) == 1


def test_export_json_contains_expected_fields():
    audit = ExecutionAudit()

    audit.record(
        execution_id="exec-1",
        event_type="END",
        status="SUCCESS",
        message="completed",
    )

    payload = json.loads(audit.export_json())

    assert set(payload[0]) == {
        "command_digest",
        "event_type",
        "execution_id",
        "message",
        "sequence",
        "status",
        "timestamp",
    }


def test_export_json_is_deterministic():
    clock = FakeClock(1000)

    first = ExecutionAudit(clock=clock)
    second = ExecutionAudit(clock=clock)

    first.record(
        execution_id="exec-1",
        event_type="END",
        status="SUCCESS",
        message="completed",
    )

    second.record(
        execution_id="exec-1",
        event_type="END",
        status="SUCCESS",
        message="completed",
    )

    assert first.export_json() == second.export_json()


def test_multiple_events_preserve_order():
    audit = ExecutionAudit()

    audit.record(
        execution_id="exec-1",
        event_type="START",
        status="RUNNING",
        message="started",
    )

    audit.record(
        execution_id="exec-1",
        event_type="END",
        status="SUCCESS",
        message="completed",
    )

    events = audit.events()

    assert events[0].event_type == "START"
    assert events[1].event_type == "END"
