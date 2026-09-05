import pytest

from sentinelshield.ram_monitor import RamMonitor
from sentinelshield.ram_resource_gate import (
    RamResourceDenied,
    RamResourceGate,
)


def test_ram_monitor_imports():
    monitor = RamMonitor(reader=lambda: 25.0)
    assert monitor.usage_percent() == 25.0


def test_ram_below_limit_is_allowed():
    monitor = RamMonitor(reader=lambda: 40.0)
    gate = RamResourceGate(
        maximum_usage_percent=80.0,
        monitor=monitor,
    )

    decision = gate.check()

    assert decision.allowed is True
    assert decision.usage_percent == 40.0
    assert decision.maximum_usage_percent == 80.0


def test_ram_at_limit_is_allowed():
    monitor = RamMonitor(reader=lambda: 80.0)
    gate = RamResourceGate(
        maximum_usage_percent=80.0,
        monitor=monitor,
    )

    decision = gate.check()

    assert decision.allowed is True


def test_ram_above_limit_is_rejected():
    monitor = RamMonitor(reader=lambda: 81.0)
    gate = RamResourceGate(
        maximum_usage_percent=80.0,
        monitor=monitor,
    )

    with pytest.raises(RamResourceDenied):
        gate.check()


def test_limit_zero():
    monitor = RamMonitor(reader=lambda: 0.0)
    gate = RamResourceGate(
        maximum_usage_percent=0.0,
        monitor=monitor,
    )

    assert gate.check().allowed is True


def test_limit_above_100_is_rejected():
    with pytest.raises(ValueError):
        RamResourceGate(maximum_usage_percent=101)


def test_negative_limit_is_rejected():
    with pytest.raises(ValueError):
        RamResourceGate(maximum_usage_percent=-1)


def test_ram_reading_is_clamped_to_100():
    monitor = RamMonitor(reader=lambda: 150.0)
    assert monitor.usage_percent() == 100.0


def test_negative_ram_reading_is_clamped_to_zero():
    monitor = RamMonitor(reader=lambda: -10.0)
    assert monitor.usage_percent() == 0.0
