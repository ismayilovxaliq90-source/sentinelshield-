from pathlib import Path

import pytest

from sentinelshield.storage_monitor import (
    StorageMonitor,
    StorageMonitorError,
    StorageReading,
)


@pytest.fixture
def monitor():
    return StorageMonitor(".")


def test_storage_reading_has_valid_structure(monitor):
    reading = monitor.read()

    assert isinstance(reading, StorageReading)
    assert reading.path
    assert reading.total_bytes > 0
    assert reading.free_bytes >= 0
    assert reading.used_bytes >= 0
    assert 0.0 <= reading.usage_percent <= 100.0


def test_used_plus_free_equals_total(monitor):
    reading = monitor.read()

    assert (
        reading.used_bytes
        + reading.free_bytes
        == reading.total_bytes
    )


def test_total_storage_is_positive(monitor):
    reading = monitor.read()

    assert reading.total_bytes > 0


def test_free_storage_does_not_exceed_total(monitor):
    reading = monitor.read()

    assert (
        reading.free_bytes
        <= reading.total_bytes
    )


def test_used_storage_does_not_exceed_total(monitor):
    reading = monitor.read()

    assert (
        reading.used_bytes
        <= reading.total_bytes
    )


def test_usage_percentage_is_bounded(monitor):
    reading = monitor.read()

    assert 0.0 <= reading.usage_percent <= 100.0


def test_valid_reading_is_accepted():
    reading = StorageReading(
        path="/workspace",
        total_bytes=1000,
        free_bytes=400,
        used_bytes=600,
        usage_percent=60.0,
    )

    assert StorageMonitor.is_valid_reading(
        reading
    ) is True


def test_empty_path_is_rejected():
    reading = StorageReading(
        path="",
        total_bytes=1000,
        free_bytes=400,
        used_bytes=600,
        usage_percent=60.0,
    )

    assert StorageMonitor.is_valid_reading(
        reading
    ) is False


def test_negative_total_is_rejected():
    reading = StorageReading(
        path="/workspace",
        total_bytes=-1,
        free_bytes=0,
        used_bytes=0,
        usage_percent=0.0,
    )

    assert StorageMonitor.is_valid_reading(
        reading
    ) is False


def test_negative_free_is_rejected():
    reading = StorageReading(
        path="/workspace",
        total_bytes=1000,
        free_bytes=-1,
        used_bytes=1001,
        usage_percent=100.0,
    )

    assert StorageMonitor.is_valid_reading(
        reading
    ) is False


def test_negative_used_is_rejected():
    reading = StorageReading(
        path="/workspace",
        total_bytes=1000,
        free_bytes=1000,
        used_bytes=-1,
        usage_percent=0.0,
    )

    assert StorageMonitor.is_valid_reading(
        reading
    ) is False


def test_free_greater_than_total_is_rejected():
    reading = StorageReading(
        path="/workspace",
        total_bytes=1000,
        free_bytes=1001,
        used_bytes=0,
        usage_percent=0.0,
    )

    assert StorageMonitor.is_valid_reading(
        reading
    ) is False


def test_used_greater_than_total_is_rejected():
    reading = StorageReading(
        path="/workspace",
        total_bytes=1000,
        free_bytes=0,
        used_bytes=1001,
        usage_percent=100.0,
    )

    assert StorageMonitor.is_valid_reading(
        reading
    ) is False


def test_usage_above_100_is_rejected():
    reading = StorageReading(
        path="/workspace",
        total_bytes=1000,
        free_bytes=0,
        used_bytes=1000,
        usage_percent=100.1,
    )

    assert StorageMonitor.is_valid_reading(
        reading
    ) is False


def test_usage_below_zero_is_rejected():
    reading = StorageReading(
        path="/workspace",
        total_bytes=1000,
        free_bytes=1000,
        used_bytes=0,
        usage_percent=-0.1,
    )

    assert StorageMonitor.is_valid_reading(
        reading
    ) is False


def test_non_reading_object_is_rejected():
    assert StorageMonitor.is_valid_reading(
        "invalid"
    ) is False


def test_custom_existing_path_is_supported(tmp_path):
    monitor = StorageMonitor(
        str(tmp_path)
    )

    reading = monitor.read()

    assert reading.path == str(
        Path(tmp_path).resolve()
    )
    assert reading.total_bytes > 0


def test_missing_path_is_reported(tmp_path):
    missing = tmp_path / "does-not-exist"

    monitor = StorageMonitor(
        str(missing)
    )

    with pytest.raises(StorageMonitorError):
        monitor.read()


def test_non_string_path_is_rejected():
    with pytest.raises(TypeError):
        StorageMonitor(123)


def test_empty_constructor_path_is_rejected():
    with pytest.raises(ValueError):
        StorageMonitor("")


def test_monitor_only_reads_storage():
    monitor = StorageMonitor(".")

    before = monitor.read()
    after = monitor.read()

    assert before.total_bytes == after.total_bytes
    assert before.path == after.path


def test_storage_reading_path_is_absolute():
    monitor = StorageMonitor(".")

    reading = monitor.read()

    assert Path(reading.path).is_absolute()
