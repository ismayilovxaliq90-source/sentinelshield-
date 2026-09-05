import pytest

from sentinelshield.cpu_monitor import (
    CPUReading,
    CPUMonitor,
    CPUMonitorError,
)


def test_cpu_monitor_rejects_zero_interval():
    with pytest.raises(ValueError):
        CPUMonitor(sample_interval=0)


def test_cpu_monitor_rejects_negative_interval():
    with pytest.raises(ValueError):
        CPUMonitor(sample_interval=-1)


def test_cpu_count_is_positive():
    monitor = CPUMonitor()

    assert monitor.cpu_count() >= 1


def test_cpu_reading_has_valid_structure():
    monitor = CPUMonitor(
        sample_interval=0.01
    )

    reading = monitor.read()

    assert isinstance(reading, CPUReading)
    assert 0.0 <= reading.percent <= 100.0
    assert reading.sample_interval == 0.01
    assert reading.cpu_count >= 1


def test_cpu_reading_is_valid():
    monitor = CPUMonitor(
        sample_interval=0.01
    )

    reading = monitor.read()

    assert monitor.is_valid_reading(
        reading
    ) is True


def test_invalid_reading_is_rejected():
    monitor = CPUMonitor()

    invalid = CPUReading(
        percent=101.0,
        sample_interval=0.1,
        cpu_count=1,
    )

    assert monitor.is_valid_reading(
        invalid
    ) is False


def test_negative_cpu_reading_is_rejected():
    monitor = CPUMonitor()

    invalid = CPUReading(
        percent=-1.0,
        sample_interval=0.1,
        cpu_count=1,
    )

    assert monitor.is_valid_reading(
        invalid
    ) is False


def test_zero_cpu_count_is_rejected():
    monitor = CPUMonitor()

    invalid = CPUReading(
        percent=20.0,
        sample_interval=0.1,
        cpu_count=0,
    )

    assert monitor.is_valid_reading(
        invalid
    ) is False


def test_zero_sample_interval_reading_is_rejected():
    monitor = CPUMonitor()

    invalid = CPUReading(
        percent=20.0,
        sample_interval=0,
        cpu_count=1,
    )

    assert monitor.is_valid_reading(
        invalid
    ) is False


def test_non_reading_object_is_rejected():
    monitor = CPUMonitor()

    assert monitor.is_valid_reading(
        "invalid"
    ) is False


def test_cpu_reading_is_deterministically_bounded():
    monitor = CPUMonitor(
        sample_interval=0.01
    )

    first = monitor.read()
    second = monitor.read()

    assert 0.0 <= first.percent <= 100.0
    assert 0.0 <= second.percent <= 100.0


def test_cpu_count_matches_positive_system_value():
    monitor = CPUMonitor()

    assert isinstance(
        monitor.cpu_count(),
        int,
    )
    assert monitor.cpu_count() > 0


def test_cpu_monitor_default_interval_is_valid():
    monitor = CPUMonitor()

    assert monitor.sample_interval > 0


def test_cpu_reading_preserves_sample_interval():
    monitor = CPUMonitor(
        sample_interval=0.02
    )

    reading = monitor.read()

    assert reading.sample_interval == 0.02


def test_cpu_reading_preserves_cpu_count():
    monitor = CPUMonitor(
        sample_interval=0.01
    )

    reading = monitor.read()

    assert reading.cpu_count == monitor.cpu_count()
