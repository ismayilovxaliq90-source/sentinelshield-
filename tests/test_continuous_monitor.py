import pytest

from sentinelshield.continuous_monitor import ContinuousMonitor
from sentinelshield.monitoring_policy_pipeline import build_pipeline


def test_run_once_creates_cycle():
    monitor = ContinuousMonitor(
        pipeline=build_pipeline(),
        interval_seconds=1,
    )

    cycle = monitor.run_once(
        cpu_percent=20,
        ram_percent=30,
        storage_percent=40,
    )

    assert cycle.number == 1
    assert cycle.result.allowed is True
    assert monitor.cycle_number == 1


def test_run_once_detects_block():
    monitor = ContinuousMonitor(
        pipeline=build_pipeline(),
        interval_seconds=1,
    )

    cycle = monitor.run_once(
        cpu_percent=95,
        ram_percent=20,
        storage_percent=20,
    )

    assert cycle.result.blocked is True
    assert cycle.result.allowed is False


def test_multiple_cycles():
    monitor = ContinuousMonitor(
        pipeline=build_pipeline(),
        interval_seconds=1,
        sleeper=lambda _: None,
    )

    values = iter([
        (10, 20, 30),
        (20, 30, 40),
        (95, 30, 40),
    ])

    cycles = []

    completed = monitor.run(
        lambda: next(values),
        max_cycles=3,
        on_cycle=cycles.append,
    )

    assert completed == 3
    assert len(cycles) == 3
    assert cycles[0].result.allowed is True
    assert cycles[1].result.allowed is True
    assert cycles[2].result.blocked is True


def test_cycle_numbers_are_sequential():
    monitor = ContinuousMonitor(
        interval_seconds=1,
    )

    a = monitor.run_once(
        cpu_percent=10,
        ram_percent=10,
        storage_percent=10,
    )

    b = monitor.run_once(
        cpu_percent=10,
        ram_percent=10,
        storage_percent=10,
    )

    assert a.number == 1
    assert b.number == 2


def test_max_cycles_required_to_finish_test_run():
    monitor = ContinuousMonitor(
        interval_seconds=1,
        sleeper=lambda _: None,
    )

    completed = monitor.run(
        lambda: (10, 10, 10),
        max_cycles=5,
    )

    assert completed == 5
    assert monitor.running is False


def test_stop():
    monitor = ContinuousMonitor(interval_seconds=1)

    monitor.stop()

    assert monitor.running is False


def test_invalid_interval():
    with pytest.raises(ValueError):
        ContinuousMonitor(interval_seconds=0)


def test_invalid_sampler():
    monitor = ContinuousMonitor(interval_seconds=1)

    with pytest.raises(TypeError):
        monitor.run(
            "not-callable",
            max_cycles=1,
        )


def test_invalid_max_cycles():
    monitor = ContinuousMonitor(interval_seconds=1)

    with pytest.raises(ValueError):
        monitor.run(
            lambda: (10, 10, 10),
            max_cycles=0,
        )


def test_invalid_max_cycles_type():
    monitor = ContinuousMonitor(interval_seconds=1)

    with pytest.raises(TypeError):
        monitor.run(
            lambda: (10, 10, 10),
            max_cycles="3",
        )


def test_callback_receives_cycle():
    monitor = ContinuousMonitor(
        interval_seconds=1,
        sleeper=lambda _: None,
    )

    received = []

    monitor.run(
        lambda: (10, 10, 10),
        max_cycles=1,
        on_cycle=received.append,
    )

    assert len(received) == 1
    assert received[0].number == 1


def test_interval_is_used():
    sleeps = []

    monitor = ContinuousMonitor(
        interval_seconds=2.5,
        sleeper=sleeps.append,
    )

    monitor.run(
        lambda: (10, 10, 10),
        max_cycles=2,
    )

    assert sleeps == [2.5]


def test_monitoring_is_deterministic():
    monitor = ContinuousMonitor(
        interval_seconds=1,
    )

    a = monitor.run_once(
        cpu_percent=50,
        ram_percent=50,
        storage_percent=50,
    )

    b = monitor.run_once(
        cpu_percent=50,
        ram_percent=50,
        storage_percent=50,
    )

    assert a.result.snapshot == b.result.snapshot
