from datetime import datetime, timedelta, timezone

import pytest

from sentinelshield.alert_deduplicator import AlertDeduplicator
from sentinelshield.alert_dispatcher import AlertDispatcher
from sentinelshield.alert_store import AlertStore
from sentinelshield.event_engine import EventEngine, EventType
from sentinelshield.persistent_alert_pipeline import (
    PersistentAlertPipeline,
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


def make_pipeline(tmp_path, cooldown=300):
    store = AlertStore(
        tmp_path / "alerts.jsonl"
    )

    dedup = AlertDeduplicator(
        cooldown_seconds=cooldown
    )

    pipeline = PersistentAlertPipeline(
        store=store,
        deduplicator=dedup,
    )

    return pipeline, store


def test_first_alert_is_stored(tmp_path):
    pipeline, store = make_pipeline(tmp_path)

    result = pipeline.process(
        make_alert(),
        now=BASE,
    )

    assert result.stored is True
    assert result.suppressed is False
    assert result.reason == "NEW_ALERT"

    assert store.count() == 1


def test_duplicate_is_not_stored(tmp_path):
    pipeline, store = make_pipeline(tmp_path)

    alert = make_alert()

    first = pipeline.process(
        alert,
        now=BASE,
    )

    second = pipeline.process(
        alert,
        now=BASE + timedelta(seconds=10),
    )

    assert first.stored is True
    assert second.stored is False
    assert second.suppressed is True
    assert second.reason == "DUPLICATE_SUPPRESSED"

    assert store.count() == 1


def test_alert_stored_after_cooldown(tmp_path):
    pipeline, store = make_pipeline(tmp_path)

    alert = make_alert()

    pipeline.process(
        alert,
        now=BASE,
    )

    result = pipeline.process(
        alert,
        now=BASE + timedelta(seconds=300),
    )

    assert result.stored is True
    assert result.reason == "COOLDOWN_EXPIRED"

    assert store.count() == 2


def test_different_projects_are_stored(tmp_path):
    pipeline, store = make_pipeline(tmp_path)

    first = pipeline.process(
        make_alert(project="one"),
        now=BASE,
    )

    second = pipeline.process(
        make_alert(project="two"),
        now=BASE,
    )

    assert first.stored is True
    assert second.stored is True
    assert store.count() == 2


def test_different_reasons_are_stored(tmp_path):
    pipeline, store = make_pipeline(tmp_path)

    first = pipeline.process(
        make_alert(reason="CPU_LIMIT"),
        now=BASE,
    )

    second = pipeline.process(
        make_alert(reason="RAM_LIMIT"),
        now=BASE,
    )

    assert first.stored is True
    assert second.stored is True
    assert store.count() == 2


def test_restart_preserves_stored_alerts(tmp_path):
    pipeline, store = make_pipeline(tmp_path)

    pipeline.process(
        make_alert(),
        now=BASE,
    )

    assert store.count() == 1

    # Simulate application restart.
    restarted_store = AlertStore(
        tmp_path / "alerts.jsonl"
    )

    assert restarted_store.count() == 1


def test_new_pipeline_can_read_old_alerts(tmp_path):
    path = tmp_path / "alerts.jsonl"

    pipeline1 = PersistentAlertPipeline(
        store=AlertStore(path),
        deduplicator=AlertDeduplicator(
            cooldown_seconds=300
        ),
    )

    pipeline1.process(
        make_alert(),
        now=BASE,
    )

    pipeline2 = PersistentAlertPipeline(
        store=AlertStore(path),
        deduplicator=AlertDeduplicator(
            cooldown_seconds=300
        ),
    )

    assert pipeline2.count() == 1


def test_count_matches_store(tmp_path):
    pipeline, store = make_pipeline(tmp_path)

    assert pipeline.count() == store.count()

    pipeline.process(
        make_alert(),
        now=BASE,
    )

    assert pipeline.count() == 1
    assert pipeline.count() == store.count()


def test_invalid_alert_is_rejected(tmp_path):
    pipeline, _ = make_pipeline(tmp_path)

    with pytest.raises(TypeError):
        pipeline.process(
            object(),
            now=BASE,
        )


def test_result_is_immutable(tmp_path):
    pipeline, _ = make_pipeline(tmp_path)

    result = pipeline.process(
        make_alert(),
        now=BASE,
    )

    with pytest.raises(AttributeError):
        result.stored = False


def test_many_duplicates_only_one_persisted(tmp_path):
    pipeline, store = make_pipeline(tmp_path)

    alert = make_alert()

    results = []

    for i in range(10):
        results.append(
            pipeline.process(
                alert,
                now=BASE + timedelta(seconds=i),
            )
        )

    assert results[0].stored is True

    assert all(
        result.stored is False
        for result in results[1:]
    )

    assert store.count() == 1


def test_multiple_alert_types_are_persisted(tmp_path):
    pipeline, store = make_pipeline(tmp_path)

    engine = EventEngine()
    dispatcher = AlertDispatcher()

    events = [
        engine.create(
            event_type=EventType.RESOURCE_BLOCK,
            project="demo",
            reason="CPU",
        ),
        engine.create(
            event_type=EventType.ACTION_DENIED,
            project="demo",
            reason="POLICY",
        ),
        engine.create(
            event_type=EventType.RECOVERY_FAILED,
            project="demo",
            reason="ERROR",
        ),
    ]

    for event in events:
        alert = dispatcher.dispatch(event)
        assert alert is not None

        result = pipeline.process(
            alert,
            now=BASE,
        )

        assert result.stored is True

    assert store.count() == 3


def test_suppressed_alert_remains_available_in_result(tmp_path):
    pipeline, store = make_pipeline(tmp_path)

    alert = make_alert()

    pipeline.process(
        alert,
        now=BASE,
    )

    result = pipeline.process(
        alert,
        now=BASE + timedelta(seconds=1),
    )

    assert result.alert == alert
    assert result.suppressed is True
    assert store.count() == 1


def test_zero_cooldown_persists_repeated_alerts(tmp_path):
    pipeline, store = make_pipeline(
        tmp_path,
        cooldown=0,
    )

    alert = make_alert()

    first = pipeline.process(
        alert,
        now=BASE,
    )

    second = pipeline.process(
        alert,
        now=BASE + timedelta(seconds=1),
    )

    assert first.stored is True
    assert second.stored is True
    assert store.count() == 2
