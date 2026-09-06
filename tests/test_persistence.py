from pathlib import Path

import pytest

from sentinelshield.persistence import (
    PersistentState,
    StateStore,
)


def make_state():
    return PersistentState(
        last_decision="BLOCK",
        last_reason="RECOVERED",
        recovery_count=3,
    )


def test_state_save_and_load(tmp_path):
    store = StateStore(
        tmp_path / "state.json"
    )

    state = make_state()

    store.save(state)

    loaded = store.load()

    assert loaded == state


def test_missing_state_returns_none(tmp_path):
    store = StateStore(
        tmp_path / "missing.json"
    )

    assert store.load() is None


def test_save_creates_parent_directory(tmp_path):
    path = (
        tmp_path
        / "nested"
        / "state"
        / "state.json"
    )

    store = StateStore(path)

    store.save(make_state())

    assert path.exists()


def test_state_exists(tmp_path):
    store = StateStore(
        tmp_path / "state.json"
    )

    assert store.exists() is False

    store.save(make_state())

    assert store.exists() is True


def test_round_trip_preserves_types(tmp_path):
    store = StateStore(
        tmp_path / "state.json"
    )

    state = PersistentState(
        last_decision="ALLOW",
        last_reason="SAFE",
        recovery_count=0,
    )

    store.save(state)
    loaded = store.load()

    assert isinstance(
        loaded,
        PersistentState,
    )

    assert isinstance(
        loaded.recovery_count,
        int,
    )


def test_second_save_replaces_previous_state(tmp_path):
    store = StateStore(
        tmp_path / "state.json"
    )

    first = PersistentState(
        last_decision="BLOCK",
        last_reason="LIMIT",
        recovery_count=1,
    )

    second = PersistentState(
        last_decision="ALLOW",
        last_reason="RECOVERED",
        recovery_count=2,
    )

    store.save(first)
    store.save(second)

    assert store.load() == second


def test_state_file_is_valid_json(tmp_path):
    store = StateStore(
        tmp_path / "state.json"
    )

    store.save(make_state())

    text = (
        tmp_path / "state.json"
    ).read_text(
        encoding="utf-8"
    )

    assert text.startswith("{")
    assert text.endswith("}")


def test_corrupt_state_raises(tmp_path):
    path = tmp_path / "state.json"

    path.write_text(
        "{invalid",
        encoding="utf-8",
    )

    store = StateStore(path)

    with pytest.raises(Exception):
        store.load()


def test_state_is_immutable():
    state = make_state()

    with pytest.raises(AttributeError):
        state.last_decision = "ALLOW"


def test_atomic_save_leaves_no_temp_files(tmp_path):
    store = StateStore(
        tmp_path / "state.json"
    )

    store.save(make_state())

    temporary_files = list(
        tmp_path.glob(
            ".sentinelshield-*.tmp"
        )
    )

    assert temporary_files == []
