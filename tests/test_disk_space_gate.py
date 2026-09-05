import pytest

from sentinelshield.disk_space_gate import (
    DiskSpaceDenied,
    DiskSpaceGate,
    DiskSpaceGateError,
)
from sentinelshield.storage_monitor import (
    StorageMonitor,
    StorageReading,
)


def make_reading(
    free_bytes: int,
    total_bytes: int = 1000,
) -> StorageReading:
    used_bytes = total_bytes - free_bytes

    usage_percent = (
        used_bytes / total_bytes
    ) * 100.0

    return StorageReading(
        path="/workspace",
        total_bytes=total_bytes,
        free_bytes=free_bytes,
        used_bytes=used_bytes,
        usage_percent=usage_percent,
    )


def test_negative_minimum_space_is_rejected():
    with pytest.raises(ValueError):
        DiskSpaceGate(
            minimum_free_bytes=-1
        )


def test_non_integer_minimum_space_is_rejected():
    with pytest.raises(TypeError):
        DiskSpaceGate(
            minimum_free_bytes=100.5
        )


def test_exact_minimum_space_is_allowed():
    gate = DiskSpaceGate(
        minimum_free_bytes=400
    )

    decision = gate.evaluate(
        make_reading(400)
    )

    assert decision.allowed is True


def test_space_above_minimum_is_allowed():
    gate = DiskSpaceGate(
        minimum_free_bytes=400
    )

    decision = gate.evaluate(
        make_reading(600)
    )

    assert decision.allowed is True


def test_space_below_minimum_is_blocked():
    gate = DiskSpaceGate(
        minimum_free_bytes=400
    )

    decision = gate.evaluate(
        make_reading(399)
    )

    assert decision.allowed is False


def test_enforce_allows_sufficient_space():
    gate = DiskSpaceGate(
        minimum_free_bytes=400
    )

    decision = gate.enforce()

    assert decision.allowed is True


def test_enforce_blocks_insufficient_space():
    gate = DiskSpaceGate(
        minimum_free_bytes=400
    )

    reading = make_reading(399)

    class FakeMonitor:
        def read(self):
            return reading

    gate.monitor = FakeMonitor()

    with pytest.raises(DiskSpaceDenied):
        gate.enforce()


def test_is_allowed_true_when_space_is_sufficient():
    gate = DiskSpaceGate(
        minimum_free_bytes=400
    )

    assert gate.is_allowed() is True


def test_is_allowed_false_when_space_is_insufficient():
    gate = DiskSpaceGate(
        minimum_free_bytes=400
    )

    reading = make_reading(399)

    original_monitor = gate.monitor

    class FakeMonitor:
        def read(self):
            return reading

    gate.monitor = FakeMonitor()

    assert gate.is_allowed() is False

    gate.monitor = original_monitor


def test_invalid_reading_is_rejected():
    gate = DiskSpaceGate(
        minimum_free_bytes=400
    )

    invalid = StorageReading(
        path="",
        total_bytes=1000,
        free_bytes=400,
        used_bytes=600,
        usage_percent=60.0,
    )

    with pytest.raises(DiskSpaceGateError):
        gate.evaluate(invalid)


def test_decision_contains_free_space():
    gate = DiskSpaceGate(
        minimum_free_bytes=400
    )

    decision = gate.evaluate(
        make_reading(700)
    )

    assert decision.free_bytes == 700


def test_decision_contains_minimum():
    gate = DiskSpaceGate(
        minimum_free_bytes=400
    )

    decision = gate.evaluate(
        make_reading(700)
    )

    assert decision.minimum_free_bytes == 400


def test_decision_contains_path():
    gate = DiskSpaceGate(
        minimum_free_bytes=400
    )

    decision = gate.evaluate(
        make_reading(700)
    )

    assert decision.path == "/workspace"


def test_decision_contains_usage():
    gate = DiskSpaceGate(
        minimum_free_bytes=400
    )

    decision = gate.evaluate(
        make_reading(700)
    )

    assert decision.usage_percent == 30.0


def test_zero_minimum_allows_valid_storage():
    gate = DiskSpaceGate(
        minimum_free_bytes=0
    )

    decision = gate.evaluate(
        make_reading(0)
    )

    assert decision.allowed is True


def test_gate_does_not_modify_storage_reading():
    reading = make_reading(600)

    gate = DiskSpaceGate(
        minimum_free_bytes=400
    )

    gate.evaluate(reading)

    assert reading.free_bytes == 600
    assert reading.used_bytes == 400


def test_gate_uses_storage_monitor_by_default():
    gate = DiskSpaceGate(
        minimum_free_bytes=1
    )

    assert isinstance(
        gate.monitor,
        StorageMonitor,
    )


def test_check_reads_current_storage():
    gate = DiskSpaceGate(
        minimum_free_bytes=1
    )

    decision = gate.check()

    assert decision.allowed is True
    assert decision.free_bytes >= 1
    assert decision.minimum_free_bytes == 1


def test_enforce_returns_decision():
    gate = DiskSpaceGate(
        minimum_free_bytes=1
    )

    decision = gate.enforce()

    assert decision.allowed is True
