import pytest

from sentinelshield.alert_dispatcher import (
    Alert,
    AlertDispatcher,
)
from sentinelshield.event_engine import (
    EventEngine,
    EventSeverity,
    EventType,
    SecurityEvent,
)


def test_critical_event_creates_alert():
    event = EventEngine().create(
        event_type=EventType.RESOURCE_BLOCK,
        project="demo",
        reason="CPU_LIMIT",
    )

    alert = AlertDispatcher().create_alert(event)

    assert isinstance(alert, Alert)
    assert alert.event_type == EventType.RESOURCE_BLOCK
    assert alert.severity == EventSeverity.CRITICAL
    assert alert.project == "demo"
    assert alert.reason == "CPU_LIMIT"


def test_warning_event_creates_alert():
    event = EventEngine().create(
        event_type=EventType.RECOVERY_REQUIRED,
        project="demo",
        reason="HEALTH_CHECK_FAILED",
    )

    alert = AlertDispatcher().create_alert(event)

    assert alert is not None
    assert alert.severity == EventSeverity.WARNING


def test_info_event_does_not_create_alert():
    event = EventEngine().create(
        event_type=EventType.PROJECT_HEALTHY,
        project="demo",
        reason="OK",
    )

    alert = AlertDispatcher().create_alert(event)

    assert alert is None


def test_action_denied_creates_alert():
    event = EventEngine().create(
        event_type=EventType.ACTION_DENIED,
        project="demo",
        reason="RESOURCE_POLICY_BLOCK",
    )

    alert = AlertDispatcher().dispatch(event)

    assert alert is not None
    assert alert.event_type == EventType.ACTION_DENIED
    assert alert.severity == EventSeverity.CRITICAL


def test_recovery_failed_creates_alert():
    event = EventEngine().create(
        event_type=EventType.RECOVERY_FAILED,
        project="demo",
        reason="RECOVERY_ERROR",
    )

    alert = AlertDispatcher().dispatch(event)

    assert alert is not None
    assert alert.severity == EventSeverity.CRITICAL


def test_dispatch_many_filters_info_events():
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

    alerts = AlertDispatcher().dispatch_many(events)

    assert len(alerts) == 2
    assert alerts[0].event_type == EventType.RESOURCE_BLOCK
    assert alerts[1].event_type == EventType.RECOVERY_REQUIRED


def test_dispatch_many_preserves_order():
    engine = EventEngine()

    events = [
        engine.create(
            event_type=EventType.ACTION_DENIED,
            project="a",
            reason="A",
        ),
        engine.create(
            event_type=EventType.RECOVERY_FAILED,
            project="b",
            reason="B",
        ),
    ]

    alerts = AlertDispatcher().dispatch_many(events)

    assert alerts[0].project == "a"
    assert alerts[1].project == "b"


def test_alert_message_contains_context():
    event = SecurityEvent(
        event_type=EventType.RESOURCE_BLOCK,
        severity=EventSeverity.CRITICAL,
        project="demo",
        reason="RAM_LIMIT",
        timestamp_utc="2026-01-01T00:00:00+00:00",
    )

    alert = AlertDispatcher().create_alert(event)

    assert alert is not None
    assert "RESOURCE_BLOCK" in alert.message
    assert "demo" in alert.message
    assert "RAM_LIMIT" in alert.message


def test_invalid_event_rejected():
    with pytest.raises(TypeError):
        AlertDispatcher().create_alert(object())


def test_invalid_events_list_rejected():
    with pytest.raises(TypeError):
        AlertDispatcher().dispatch_many("bad")


def test_alert_is_immutable():
    event = EventEngine().create(
        event_type=EventType.RESOURCE_BLOCK,
        project="demo",
        reason="CPU_LIMIT",
    )

    alert = AlertDispatcher().create_alert(event)

    assert alert is not None

    with pytest.raises(AttributeError):
        alert.project = "changed"


def test_dispatch_matches_create_alert():
    event = EventEngine().create(
        event_type=EventType.RECOVERY_REQUIRED,
        project="demo",
        reason="HEALTH_CHECK_FAILED",
    )

    dispatcher = AlertDispatcher()

    assert dispatcher.dispatch(event) == dispatcher.create_alert(event)


def test_healthy_events_produce_zero_alerts():
    engine = EventEngine()

    events = [
        engine.create(
            event_type=EventType.PROJECT_HEALTHY,
            project="one",
            reason="OK",
        ),
        engine.create(
            event_type=EventType.ACTION_EXECUTED,
            project="two",
            reason="EXECUTED",
        ),
        engine.create(
            event_type=EventType.RECOVERY_SUCCESS,
            project="three",
            reason="DONE",
        ),
    ]

    alerts = AlertDispatcher().dispatch_many(events)

    assert alerts == ()


def test_all_critical_event_types_alert():
    engine = EventEngine()

    critical = [
        EventType.RESOURCE_BLOCK,
        EventType.ACTION_DENIED,
        EventType.RECOVERY_FAILED,
    ]

    events = [
        engine.create(
            event_type=item,
            project="demo",
            reason="TEST",
        )
        for item in critical
    ]

    alerts = AlertDispatcher().dispatch_many(events)

    assert len(alerts) == 3
    assert all(
        alert.severity == EventSeverity.CRITICAL
        for alert in alerts
    )


def test_warning_event_only():
    event = EventEngine().create(
        event_type=EventType.RECOVERY_REQUIRED,
        project="demo",
        reason="FAIL",
    )

    alerts = AlertDispatcher().dispatch_many([event])

    assert len(alerts) == 1
    assert alerts[0].severity == EventSeverity.WARNING
