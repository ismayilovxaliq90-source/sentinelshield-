import json

import pytest

from sentinelshield.event_engine import (
    EventEngine,
    EventSeverity,
    EventType,
    SecurityEvent,
)


def test_resource_block_is_critical():
    event = EventEngine().create(
        event_type=EventType.RESOURCE_BLOCK,
        project="demo",
        reason="CPU_LIMIT",
    )

    assert isinstance(event, SecurityEvent)
    assert event.severity == EventSeverity.CRITICAL


def test_action_denied_is_critical():
    event = EventEngine().create(
        event_type=EventType.ACTION_DENIED,
        project="demo",
        reason="RESOURCE_POLICY_BLOCK",
    )

    assert event.severity == EventSeverity.CRITICAL


def test_recovery_required_is_warning():
    event = EventEngine().create(
        event_type=EventType.RECOVERY_REQUIRED,
        project="demo",
        reason="HEALTH_CHECK_FAILED",
    )

    assert event.severity == EventSeverity.WARNING


def test_recovery_success_is_info():
    event = EventEngine().create(
        event_type=EventType.RECOVERY_SUCCESS,
        project="demo",
        reason="RECOVERY_COMPLETED",
    )

    assert event.severity == EventSeverity.INFO


def test_recovery_failed_is_critical():
    event = EventEngine().create(
        event_type=EventType.RECOVERY_FAILED,
        project="demo",
        reason="RECOVERY_ERROR",
    )

    assert event.severity == EventSeverity.CRITICAL


def test_project_healthy_is_info():
    event = EventEngine().create(
        event_type=EventType.PROJECT_HEALTHY,
        project="demo",
        reason="OK",
    )

    assert event.severity == EventSeverity.INFO


def test_project_name_is_trimmed():
    event = EventEngine().create(
        event_type=EventType.PROJECT_HEALTHY,
        project="  demo  ",
        reason="  OK  ",
    )

    assert event.project == "demo"
    assert event.reason == "OK"


def test_empty_project_rejected():
    with pytest.raises(ValueError):
        EventEngine().create(
            event_type=EventType.PROJECT_HEALTHY,
            project=" ",
            reason="OK",
        )


def test_empty_reason_rejected():
    with pytest.raises(ValueError):
        EventEngine().create(
            event_type=EventType.PROJECT_HEALTHY,
            project="demo",
            reason=" ",
        )


def test_invalid_event_type_rejected():
    with pytest.raises(TypeError):
        EventEngine().create(
            event_type="RESOURCE_BLOCK",
            project="demo",
            reason="CPU_LIMIT",
        )


def test_invalid_project_type_rejected():
    with pytest.raises(TypeError):
        EventEngine().create(
            event_type=EventType.PROJECT_HEALTHY,
            project=123,
            reason="OK",
        )


def test_invalid_reason_type_rejected():
    with pytest.raises(TypeError):
        EventEngine().create(
            event_type=EventType.PROJECT_HEALTHY,
            project="demo",
            reason=123,
        )


def test_as_dict_contains_expected_fields():
    event = EventEngine().create(
        event_type=EventType.ACTION_EXECUTED,
        project="demo",
        reason="EXECUTED",
    )

    data = event.as_dict()

    assert data["event_type"] == "ACTION_EXECUTED"
    assert data["severity"] == "INFO"
    assert data["project"] == "demo"
    assert data["reason"] == "EXECUTED"
    assert "timestamp_utc" in data


def test_as_json_is_valid_json():
    event = EventEngine().create(
        event_type=EventType.ACTION_EXECUTED,
        project="demo",
        reason="EXECUTED",
    )

    data = json.loads(event.as_json())

    assert data["event_type"] == "ACTION_EXECUTED"
    assert data["severity"] == "INFO"


def test_json_is_deterministically_sorted():
    event = SecurityEvent(
        event_type=EventType.PROJECT_HEALTHY,
        severity=EventSeverity.INFO,
        project="demo",
        reason="OK",
        timestamp_utc="2026-01-01T00:00:00+00:00",
    )

    first = event.as_json()
    second = event.as_json()

    assert first == second


def test_event_is_immutable():
    event = SecurityEvent(
        event_type=EventType.PROJECT_HEALTHY,
        severity=EventSeverity.INFO,
        project="demo",
        reason="OK",
        timestamp_utc="2026-01-01T00:00:00+00:00",
    )

    with pytest.raises(AttributeError):
        event.project = "changed"


def test_enum_values_are_stable():
    assert EventType.RESOURCE_BLOCK.value == "RESOURCE_BLOCK"
    assert EventType.RECOVERY_REQUIRED.value == "RECOVERY_REQUIRED"
    assert EventSeverity.CRITICAL.value == "CRITICAL"


def test_multiple_event_types():
    engine = EventEngine()

    events = [
        engine.create(
            event_type=event_type,
            project="demo",
            reason="TEST",
        )
        for event_type in EventType
    ]

    assert len(events) == len(EventType)
    assert all(event.project == "demo" for event in events)


def test_timestamp_is_utc():
    event = EventEngine().create(
        event_type=EventType.PROJECT_HEALTHY,
        project="demo",
        reason="OK",
    )

    assert event.timestamp_utc.endswith("+00:00")
