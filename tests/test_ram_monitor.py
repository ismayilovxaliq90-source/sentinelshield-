import pytest

from sentinelshield.ram_monitor import (
    RAMMonitor,
    RAMMonitorError,
    RAMReading,
)


@pytest.fixture
def monitor():
    return RAMMonitor()


def test_ram_reading_has_valid_structure(monitor):
    reading = monitor.read()

    assert isinstance(reading, RAMReading)
    assert reading.total_bytes > 0
    assert reading.available_bytes >= 0
    assert reading.used_bytes >= 0
    assert 0.0 <= reading.usage_percent <= 100.0


def test_used_plus_available_equals_total(monitor):
    reading = monitor.read()

    assert (
        reading.used_bytes
        + reading.available_bytes
        == reading.total_bytes
    )


def test_total_ram_is_positive(monitor):
    reading = monitor.read()

    assert reading.total_bytes > 0


def test_available_ram_does_not_exceed_total(monitor):
    reading = monitor.read()

    assert (
        reading.available_bytes
        <= reading.total_bytes
    )


def test_used_ram_does_not_exceed_total(monitor):
    reading = monitor.read()

    assert (
        reading.used_bytes
        <= reading.total_bytes
    )


def test_usage_percentage_is_bounded(monitor):
    reading = monitor.read()

    assert 0.0 <= reading.usage_percent <= 100.0


def test_valid_reading_is_accepted():
    reading = RAMReading(
        total_bytes=1000,
        available_bytes=400,
        used_bytes=600,
        usage_percent=60.0,
    )

    assert RAMMonitor.is_valid_reading(
        reading
    ) is True


def test_negative_total_is_rejected():
    reading = RAMReading(
        total_bytes=-1,
        available_bytes=0,
        used_bytes=0,
        usage_percent=0.0,
    )

    assert RAMMonitor.is_valid_reading(
        reading
    ) is False


def test_negative_available_is_rejected():
    reading = RAMReading(
        total_bytes=1000,
        available_bytes=-1,
        used_bytes=1001,
        usage_percent=100.0,
    )

    assert RAMMonitor.is_valid_reading(
        reading
    ) is False


def test_negative_used_is_rejected():
    reading = RAMReading(
        total_bytes=1000,
        available_bytes=1000,
        used_bytes=-1,
        usage_percent=0.0,
    )

    assert RAMMonitor.is_valid_reading(
        reading
    ) is False


def test_available_greater_than_total_is_rejected():
    reading = RAMReading(
        total_bytes=1000,
        available_bytes=1001,
        used_bytes=0,
        usage_percent=0.0,
    )

    assert RAMMonitor.is_valid_reading(
        reading
    ) is False


def test_used_greater_than_total_is_rejected():
    reading = RAMReading(
        total_bytes=1000,
        available_bytes=0,
        used_bytes=1001,
        usage_percent=100.0,
    )

    assert RAMMonitor.is_valid_reading(
        reading
    ) is False


def test_usage_above_100_is_rejected():
    reading = RAMReading(
        total_bytes=1000,
        available_bytes=0,
        used_bytes=1000,
        usage_percent=100.1,
    )

    assert RAMMonitor.is_valid_reading(
        reading
    ) is False


def test_usage_below_zero_is_rejected():
    reading = RAMReading(
        total_bytes=1000,
        available_bytes=1000,
        used_bytes=0,
        usage_percent=-0.1,
    )

    assert RAMMonitor.is_valid_reading(
        reading
    ) is False


def test_non_reading_object_is_rejected():
    assert RAMMonitor.is_valid_reading(
        "invalid"
    ) is False


def test_meminfo_is_readable(monitor):
    values = monitor._read_meminfo()

    assert isinstance(values, dict)
    assert "MemTotal" in values
    assert "MemAvailable" in values


def test_monitor_does_not_modify_memory_state():
    monitor = RAMMonitor()

    first = monitor.read()
    second = monitor.read()

    assert first.total_bytes == second.total_bytes
    assert first.total_bytes > 0


def test_ram_reading_is_bounded(monitor):
    reading = monitor.read()

    assert 0.0 <= reading.usage_percent <= 100.0
