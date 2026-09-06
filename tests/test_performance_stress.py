from __future__ import annotations

import time

from sentinelshield.alert_dedup_bridge import (
    AlertDedupStore,
    AlertDispatcher,
)
from sentinelshield.violation_event_bridge import (
    ViolationEvent,
)


def make_event():
    return ViolationEvent(
        event_type="POLICY_VIOLATION",
        timestamp="2026-01-01T00:00:00+00:00",
        decision="BLOCK",
        failures=("CPU",),
        reason="RESOURCE_LIMIT",
    )


def test_alert_dedup_handles_10000_duplicates():
    dispatcher = AlertDispatcher(
        AlertDedupStore()
    )

    event = make_event()

    start = time.perf_counter()

    for _ in range(10_000):
        dispatcher.dispatch(event)

    elapsed = time.perf_counter() - start

    assert len(dispatcher.alerts) == 1
    assert elapsed < 5.0


def test_alert_dispatch_handles_many_unique_events():
    dispatcher = AlertDispatcher(
        AlertDedupStore()
    )

    start = time.perf_counter()

    for index in range(2_000):
        event = ViolationEvent(
            event_type="POLICY_VIOLATION",
            timestamp=f"2026-01-01T00:00:{index % 60:02d}+00:00",
            decision="BLOCK",
            failures=(f"RESOURCE_{index}",),
            reason="RESOURCE_LIMIT",
        )

        dispatcher.dispatch(event)

    elapsed = time.perf_counter() - start

    assert len(dispatcher.alerts) == 2_000
    assert elapsed < 5.0


def test_event_creation_is_fast():
    event = make_event()

    start = time.perf_counter()

    events = [
        ViolationEvent(
            event_type=event.event_type,
            timestamp=event.timestamp,
            decision=event.decision,
            failures=event.failures,
            reason=event.reason,
        )
        for _ in range(10_000)
    ]

    elapsed = time.perf_counter() - start

    assert len(events) == 10_000
    assert elapsed < 5.0


def test_dedup_memory_state_remains_consistent():
    dispatcher = AlertDispatcher(
        AlertDedupStore()
    )

    events = []

    for index in range(1_000):
        events.append(
            ViolationEvent(
                event_type="POLICY_VIOLATION",
                timestamp="2026-01-01T00:00:00+00:00",
                decision="BLOCK",
                failures=(f"CPU_{index}",),
                reason="RESOURCE_LIMIT",
            )
        )

    for event in events:
        dispatcher.dispatch(event)

    assert len(dispatcher.alerts) == 1_000

    for event in events:
        dispatcher.dispatch(event)

    assert len(dispatcher.alerts) == 1_000
