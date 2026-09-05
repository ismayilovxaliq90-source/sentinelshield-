import pytest

from sentinelshield.cpu_monitor import CpuMonitor
from sentinelshield.cpu_resource_gate import (
    CpuResourceDenied,
    CpuResourceGate,
)


def test_cpu_monitor_imports():
    monitor = CpuMonitor(reader=lambda: 25.0)
    assert monitor.usage_percent() == 25.0


def test_cpu_below_limit_is_allowed():
    monitor = CpuMonitor(reader=lambda: 40.0)
    gate = CpuResourceGate(
        maximum_usage_percent=80.0,
        monitor=monitor,
    )

    decision = gate.check()

    assert decision.allowed is True
    assert decision.usage_percent == 40.0
    assert decision.maximum_usage_percent == 80.0


def test_cpu_at_limit_is_allowed():
    monitor = CpuMonitor(reader=lambda: 80.0)
    gate = CpuResourceGate(
        maximum_usage_percent=80.0,
        monitor=monitor,
    )

    decision = gate.check()

    assert decision.allowed is True


def test_cpu_above_limit_is_rejected():
    monitor = CpuMonitor(reader=lambda: 81.0)
    gate = CpuResourceGate(
        maximum_usage_percent=80.0,
        monitor=monitor,
    )

    with pytest.raises(CpuResourceDenied):
        gate.check()


def test_limit_zero():
    monitor = CpuMonitor(reader=lambda: 0.0)
    gate = CpuResourceGate(
        maximum_usage_percent=0.0,
        monitor=monitor,
    )

    assert gate.check().allowed is True


def test_limit_above_100_is_rejected():
    with pytest.raises(ValueError):
        CpuResourceGate(maximum_usage_percent=101)


def test_negative_limit_is_rejected():
    with pytest.raises(ValueError):
        CpuResourceGate(maximum_usage_percent=-1)


def test_cpu_reading_is_clamped_to_100():
    monitor = CpuMonitor(reader=lambda: 150.0)
    assert monitor.usage_percent() == 100.0


def test_negative_cpu_reading_is_clamped_to_zero():
    monitor = CpuMonitor(reader=lambda: -10.0)
    assert monitor.usage_percent() == 0.0
