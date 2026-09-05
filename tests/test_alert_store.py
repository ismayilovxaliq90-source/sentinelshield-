import json

import pytest

from sentinelshield.alert_dispatcher import (
    AlertDispatcher,
)
from sentinelshield.alert_store import AlertStore
from sentinelshield.event_engine import (
    EventEngine,
    EventType,
)


def make_alert():
    event = EventEngine().create(
        event_type=EventType.RESOURCE_BLOCK,
        project="demo",
        reason="CPU_LIMIT",
    )

    return AlertDispatcher().create_alert(event)


def test_save_alert(tmp_path):
    store = AlertStore(
        tmp_path / "alerts.jsonl"
    )

    alert = make_alert()

    assert alert is not None

    store.save(alert)

    records = store.read_all()

    assert len(records) == 1
    assert records[0]["event_type"] == "RESOURCE_BLOCK"
    assert records[0]["severity"] == "CRITICAL"
    assert records[0]["project"] == "demo"
    assert records[0]["reason"] == "CPU_LIMIT"


def test_store_creates_parent_directory(tmp_path):
    path = tmp_path / "nested" / "alerts.jsonl"

    store = AlertStore(path)

    assert path.parent.exists()


def test_empty_store_returns_empty_list(tmp_path):
    store = AlertStore(
        tmp_path / "alerts.jsonl"
    )

    assert store.read_all() == []
    assert store.count() == 0


def test_multiple_alerts(tmp_path):
    store = AlertStore(
        tmp_path / "alerts.jsonl"
    )

    engine = EventEngine()
    dispatcher = AlertDispatcher()

    events = [
        engine.create(
            event_type=EventType.RESOURCE_BLOCK,
            project="one",
            reason="CPU",
        ),
        engine.create(
            event_type=EventType.ACTION_DENIED,
            project="two",
            reason="POLICY",
        ),
        engine.create(
            event_type=EventType.RECOVERY_FAILED,
            project="three",
            reason="ERROR",
        ),
    ]

    alerts = dispatcher.dispatch_many(events)

    store.save_many(alerts)

    assert store.count() == 3


def test_order_is_preserved(tmp_path):
    store = AlertStore(
        tmp_path / "alerts.jsonl"
    )

    engine = EventEngine()
    dispatcher = AlertDispatcher()

    events = [
        engine.create(
            event_type=EventType.ACTION_DENIED,
            project="first",
            reason="A",
        ),
        engine.create(
            event_type=EventType.RECOVERY_FAILED,
            project="second",
            reason="B",
        ),
    ]

    store.save_many(
        dispatcher.dispatch_many(events)
    )

    records = store.read_all()

    assert records[0]["project"] == "first"
    assert records[1]["project"] == "second"


def test_persistence_survives_new_store_instance(tmp_path):
    path = tmp_path / "alerts.jsonl"

    store1 = AlertStore(path)
    alert = make_alert()

    assert alert is not None

    store1.save(alert)

    # Simulate application restart.
    store2 = AlertStore(path)

    records = store2.read_all()

    assert len(records) == 1
    assert records[0]["project"] == "demo"


def test_clear_removes_storage(tmp_path):
    path = tmp_path / "alerts.jsonl"

    store = AlertStore(path)
    alert = make_alert()

    assert alert is not None

    store.save(alert)

    assert store.count() == 1

    store.clear()

    assert store.count() == 0
    assert not path.exists()


def test_invalid_alert_rejected(tmp_path):
    store = AlertStore(
        tmp_path / "alerts.jsonl"
    )

    with pytest.raises(TypeError):
        store.save(object())


def test_invalid_collection_rejected(tmp_path):
    store = AlertStore(
        tmp_path / "alerts.jsonl"
    )

    with pytest.raises(TypeError):
        store.save_many("bad")


def test_jsonl_format(tmp_path):
    path = tmp_path / "alerts.jsonl"

    store = AlertStore(path)
    alert = make_alert()

    assert alert is not None

    store.save(alert)

    lines = path.read_text(
        encoding="utf-8"
    ).splitlines()

    assert len(lines) == 1

    parsed = json.loads(lines[0])

    assert parsed["event_type"] == "RESOURCE_BLOCK"


def test_each_record_is_valid_json(tmp_path):
    store = AlertStore(
        tmp_path / "alerts.jsonl"
    )

    engine = EventEngine()
    dispatcher = AlertDispatcher()

    events = [
        engine.create(
            event_type=EventType.RESOURCE_BLOCK,
            project="one",
            reason="CPU",
        ),
        engine.create(
            event_type=EventType.RECOVERY_FAILED,
            project="two",
            reason="ERROR",
        ),
    ]

    store.save_many(
        dispatcher.dispatch_many(events)
    )

    for record in store.read_all():
        assert isinstance(record, dict)
        assert "event_type" in record
        assert "severity" in record
        assert "project" in record
        assert "message" in record
        assert "reason" in record


def test_count_matches_read_all(tmp_path):
    store = AlertStore(
        tmp_path / "alerts.jsonl"
    )

    assert store.count() == len(
        store.read_all()
    )

    alert = make_alert()

    assert alert is not None

    store.save(alert)

    assert store.count() == len(
        store.read_all()
    )
