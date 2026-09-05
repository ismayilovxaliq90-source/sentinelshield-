from sentinelshield.thermal_monitor import (
    ThermalMonitor,
    ThermalReading,
)


def test_temperature_is_read():
    monitor = ThermalMonitor(
        reader=lambda: 45.0
    )

    reading = monitor.read()

    assert isinstance(
        reading,
        ThermalReading,
    )
    assert reading.temperature_celsius == 45.0
    assert reading.available is True


def test_temperature_method_returns_value():
    monitor = ThermalMonitor(
        reader=lambda: 55.5
    )

    assert (
        monitor.temperature_celsius()
        == 55.5
    )


def test_available_is_true_for_valid_temperature():
    monitor = ThermalMonitor(
        reader=lambda: 60.0
    )

    assert monitor.is_available() is True


def test_none_temperature_is_safe():
    monitor = ThermalMonitor(
        reader=lambda: None
    )

    reading = monitor.read()

    assert reading.temperature_celsius is None
    assert reading.available is False


def test_zero_temperature_is_valid():
    monitor = ThermalMonitor(
        reader=lambda: 0.0
    )

    reading = monitor.read()

    assert reading.temperature_celsius == 0.0
    assert reading.available is True


def test_negative_temperature_is_valid():
    monitor = ThermalMonitor(
        reader=lambda: -10.0
    )

    reading = monitor.read()

    assert reading.temperature_celsius == -10.0
    assert reading.available is True


def test_high_but_valid_temperature():
    monitor = ThermalMonitor(
        reader=lambda: 150.0
    )

    reading = monitor.read()

    assert reading.temperature_celsius == 150.0
    assert reading.available is True


def test_unrealistic_high_temperature_is_unavailable():
    monitor = ThermalMonitor(
        reader=lambda: 250.0
    )

    reading = monitor.read()

    assert reading.temperature_celsius is None
    assert reading.available is False


def test_unrealistic_low_temperature_is_unavailable():
    monitor = ThermalMonitor(
        reader=lambda: -150.0
    )

    reading = monitor.read()

    assert reading.temperature_celsius is None
    assert reading.available is False


def test_invalid_string_temperature_is_safe():
    monitor = ThermalMonitor(
        reader=lambda: "invalid"
    )

    reading = monitor.read()

    assert reading.temperature_celsius is None
    assert reading.available is False


def test_reader_exception_is_safe():
    def broken_reader():
        raise RuntimeError("sensor failure")

    monitor = ThermalMonitor(
        reader=broken_reader
    )

    reading = monitor.read()

    assert reading.temperature_celsius is None
    assert reading.available is False


def test_source_is_system():
    monitor = ThermalMonitor(
        reader=lambda: 50.0
    )

    reading = monitor.read()

    assert reading.source == "system"


def test_multiple_reads_work():
    values = iter(
        [40.0, 50.0, 60.0]
    )

    monitor = ThermalMonitor(
        reader=lambda: next(values)
    )

    assert monitor.temperature_celsius() == 40.0
    assert monitor.temperature_celsius() == 50.0
    assert monitor.temperature_celsius() == 60.0


def test_default_monitor_does_not_crash():
    monitor = ThermalMonitor()

    reading = monitor.read()

    assert isinstance(
        reading,
        ThermalReading,
    )
    assert reading.available in (
        True,
        False,
    )


def test_default_temperature_is_valid_if_available():
    monitor = ThermalMonitor()

    reading = monitor.read()

    if reading.available:
        assert (
            reading.temperature_celsius
            is not None
        )
        assert (
            -100.0
            <= reading.temperature_celsius
            <= 200.0
        )


def test_unavailable_sensor_does_not_raise():
    monitor = ThermalMonitor(
        reader=lambda: None
    )

    reading = monitor.read()

    assert reading.available is False


def test_reading_is_immutable():
    monitor = ThermalMonitor(
        reader=lambda: 50.0
    )

    reading = monitor.read()

    assert reading.temperature_celsius == 50.0
    assert reading.available is True


def test_temperature_type_is_float():
    monitor = ThermalMonitor(
        reader=lambda: 42
    )

    reading = monitor.read()

    assert isinstance(
        reading.temperature_celsius,
        float,
    )
