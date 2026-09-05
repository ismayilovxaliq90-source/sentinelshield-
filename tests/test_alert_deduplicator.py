from datetime import datetime, timedelta, timezone

import pytest

from sentinelshield.alert_deduplicator import (
    AlertDeduplicator,
    DeduplicationResult,
)
from sentinelshield.alert_dispatcher import AlertDispatcher
from sentinelshield.event_engine import (
    EventEngine,
    EventType,
)


BASE = datetime(
    2026,
    1,
    1,
    tzinfo=timezone.utc,
)


def make_alert(
    project="demo",
    reason="CPU_LIMIT",
):
    event = EventEngine().create(
        event_type=EventType.RESOURCE_BLOCK,
        project=project,
        reason=reason,
    )

    alert = AlertDispatcher().dispatch(event)

    assert alert is not None

    return alert


def test_first_alert_is_allowed():
    dedup = AlertDeduplicator(
        cooldown_seconds=300
    )

    result = dedup.allow(
        make_alert(),
        now=BASE,
    )

    assert isinstance(result, DeduplicationResult)
    assert result.allowed is True
    assert result.reason == "NEW_ALERT"


def test_duplicate_is_suppressed():
    dedup = AlertDeduplicator(
        cooldown_seconds=300
    )

    alert = make_alert()

    first = dedup.allow(
        alert,
        now=BASE,
    )

    second = dedup.allow(
        alert,
        now=BASE + timedelta(seconds=10),
    )

    assert first.allowed is True
    assert second.allowed is False
    assert second.reason == "DUPLICATE_SUPPRESSED"


def test_alert_allowed_after_cooldown():
    dedup = AlertDeduplicator(
        cooldown_seconds=300
    )

    alert = make_alert()

    dedup.allow(
        alert,
        now=BASE,
    )

    result = dedup.allow(
        alert,
        now=BASE + timedelta(seconds=300),
    )

    assert result.allowed is True
    assert result.reason == "COOLDOWN_EXPIRED"


def test_different_projects_are_not_duplicates():
    dedup = AlertDeduplicator(
        cooldown_seconds=300
    )

    first = dedup.allow(
        make_alert(project="one"),
        now=BASE,
    )

    second = dedup.allow(
        make_alert(project="two"),
        now=BASE,
    )

    assert first.allowed is True
    assert second.allowed is True


def test_different_reasons_are_not_duplicates():
    dedup = AlertDeduplicator(
        cooldown_seconds=300
    )

    first = dedup.allow(
        make_alert(reason="CPU_LIMIT"),
        now=BASE,
    )

    second = dedup.allow(
        make_alert(reason="RAM_LIMIT"),
        now=BASE,
    )

    assert first.allowed is True
    assert second.allowed is True


def test_different_event_types_are_not_duplicates():
    dedup = AlertDeduplicator(
        cooldown_seconds=300
    )

    engine = EventEngine()
    dispatcher = AlertDispatcher()

    first_event = engine.create(
        event_type=EventType.RESOURCE_BLOCK,
        project="demo",
        reason="LIMIT",
    )

    second_event = engine.create(
        event_type=EventType.ACTION_DENIED,
        project="demo",
        reason="LIMIT",
    )

    first_alert = dispatcher.dispatch(first_event)
    second_alert = dispatcher.dispatch(second_event)

    assert first_alert is not None
    assert second_alert is not None

    first = dedup.allow(
        first_alert,
        now=BASE,
    )

    second = dedup.allow(
        second_alert,
        now=BASE,
    )

    assert first.allowed is True
    assert second.allowed is True


def test_reset_allows_alert_again():
    dedup = AlertDeduplicator(
        cooldown_seconds=300
    )

    alert = make_alert()

    dedup.allow(
        alert,
        now=BASE,
    )

    dedup.reset()

    result = dedup.allow(
        alert,
        now=BASE + timedelta(seconds=1),
    )

    assert result.allowed is True
    assert result.reason == "NEW_ALERT"


def test_size_tracks_keys():
    dedup = AlertDeduplicator(
        cooldown_seconds=300
    )

    assert dedup.size() == 0

    dedup.allow(
        make_alert(project="one"),
        now=BASE,
    )

    dedup.allow(
        make_alert(project="two"),
        now=BASE,
    )

    assert dedup.size() == 2


def test_zero_cooldown_allows_repeated_alerts():
    dedup = AlertDeduplicator(
        cooldown_seconds=0
    )

    alert = make_alert()

    first = dedup.allow(
        alert,
        now=BASE,
    )

    second = dedup.allow(
        alert,
        now=BASE + timedelta(seconds=1),
    )

    assert first.allowed is True
    assert second.allowed is True
    assert second.reason == "COOLDOWN_EXPIRED"


def test_negative_cooldown_rejected():
    with pytest.raises(ValueError):
        AlertDeduplicator(
            cooldown_seconds=-1
        )


def test_invalid_cooldown_type_rejected():
    with pytest.raises(TypeError):
        AlertDeduplicator(
            cooldown_seconds=1.5
        )


def test_invalid_alert_rejected():
    dedup = AlertDeduplicator()

    with pytest.raises(TypeError):
        dedup.allow(
            object(),
            now=BASE,
        )


def test_naive_datetime_rejected():
    dedup = AlertDeduplicator()

    with pytest.raises(ValueError):
        dedup.allow(
            make_alert(),
            now=datetime(2026, 1, 1),
        )


def test_result_is_immutable():
    result = DeduplicationResult(
        allowed=True,
        reason="NEW_ALERT",
    )

    with pytest.raises(AttributeError):
        result.allowed = False


def test_alert_key_is_stable():
    dedup = AlertDeduplicator()

    alert = make_alert()

    key1 = dedup._key(alert)
    key2 = dedup._key(alert)

    assert key1 == key2


def test_multiple_duplicate_alerts_only_first_allowed():
    dedup = AlertDeduplicator(
        cooldown_seconds=300
    )

    alert = make_alert()

    results = [
        dedup.allow(
            alert,
            now=BASE + timedelta(seconds=i),
        )
        for i in range(5)
    ]

    assert results[0].allowed is True
    assert all(
        result.allowed is False
        for result in results[1:]
    )


def test_cooldown_is_independent_per_project():
    dedup = AlertDeduplicator(
        cooldown_seconds=300
    )

    a = make_alert(project="a")
    b = make_alert(project="b")

    dedup.allow(a, now=BASE)

    result = dedup.allow(
        b,
        now=BASE + timedelta(seconds=1),
    )

    assert result.allowed is True
