from sentinelshield.alert_dedup_bridge import (
    Alert,
    AlertDedupStore,
    AlertDispatcher,
)
from sentinelshield.violation_event_bridge import (
    ViolationEvent,
)


def event(
    failures=("CPU",),
    reason="RESOURCE_LIMIT",
):
    return ViolationEvent(
        event_type="POLICY_VIOLATION",
        timestamp="2026-01-01T00:00:00+00:00",
        decision="BLOCK",
        failures=failures,
        reason=reason,
    )


def test_first_event_creates_alert():
    dispatcher = AlertDispatcher(
        AlertDedupStore()
    )

    alert = dispatcher.dispatch(event())

    assert isinstance(alert, Alert)
    assert alert.decision == "BLOCK"
    assert alert.failures == ("CPU",)
    assert alert.reason == "RESOURCE_LIMIT"


def test_duplicate_event_is_suppressed():
    dispatcher = AlertDispatcher(
        AlertDedupStore()
    )

    first = dispatcher.dispatch(event())
    second = dispatcher.dispatch(event())

    assert first is not None
    assert second is None
    assert len(dispatcher.alerts) == 1


def test_different_failure_creates_new_alert():
    dispatcher = AlertDispatcher(
        AlertDedupStore()
    )

    first = dispatcher.dispatch(
        event(("CPU",))
    )

    second = dispatcher.dispatch(
        event(("RAM",))
    )

    assert first is not None
    assert second is not None
    assert first.alert_id != second.alert_id
    assert len(dispatcher.alerts) == 2


def test_different_reason_creates_new_alert():
    dispatcher = AlertDispatcher(
        AlertDedupStore()
    )

    first = dispatcher.dispatch(
        event(reason="RESOURCE_LIMIT")
    )

    second = dispatcher.dispatch(
        event(reason="MEMORY_LIMIT")
    )

    assert first is not None
    assert second is not None
    assert first.alert_id != second.alert_id


def test_alert_id_is_stable():
    dispatcher = AlertDispatcher(
        AlertDedupStore()
    )

    first = dispatcher._alert_id(event())
    second = dispatcher._alert_id(event())

    assert first == second


def test_alert_id_changes_for_different_events():
    dispatcher = AlertDispatcher(
        AlertDedupStore()
    )

    first = dispatcher._alert_id(
        event(("CPU",))
    )

    second = dispatcher._alert_id(
        event(("RAM",))
    )

    assert first != second


def test_failures_are_tuple():
    dispatcher = AlertDispatcher(
        AlertDedupStore()
    )

    alert = dispatcher.dispatch(
        event(["CPU", "RAM"])
    )

    assert alert is not None
    assert isinstance(alert.failures, tuple)


def test_alert_is_immutable():
    dispatcher = AlertDispatcher(
        AlertDedupStore()
    )

    alert = dispatcher.dispatch(event())

    assert alert is not None

    try:
        alert.decision = "ALLOW"
        assert False
    except AttributeError:
        pass


def test_dedup_store_tracks_alert():
    store = AlertDedupStore()

    assert store.contains("abc") is False

    store.add("abc")

    assert store.contains("abc") is True


def test_multiple_duplicates_create_one_alert():
    dispatcher = AlertDispatcher(
        AlertDedupStore()
    )

    for _ in range(10):
        dispatcher.dispatch(event())

    assert len(dispatcher.alerts) == 1
