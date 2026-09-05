from types import SimpleNamespace

from sentinelshield.live_monitor import LiveMonitor


class FakeSampler:
    def __init__(self):
        self.calls = 0

    def sample(self):
        self.calls += 1

        return SimpleNamespace(
            cpu_percent=20.0,
            ram_percent=30.0,
            storage_percent=40.0,
        )


class FakeMonitor:
    def __init__(self):
        self.calls = []

    def run_once(self, **kwargs):
        self.calls.append(kwargs)

        return SimpleNamespace(
            number=len(self.calls),
            result=SimpleNamespace(
                allowed=True,
                blocked=False,
            ),
        )

    def run(self, sampler, max_cycles=None, on_cycle=None):
        count = 0

        while max_cycles is None or count < max_cycles:
            cpu, ram, storage = sampler()

            count += 1

            cycle = SimpleNamespace(
                number=count,
                result=SimpleNamespace(
                    allowed=True,
                    blocked=False,
                ),
            )

            if on_cycle:
                on_cycle(cycle)

        return count


def test_sample_once_reads_real_sampler():
    sampler = FakeSampler()
    monitor = FakeMonitor()

    live = LiveMonitor(
        sampler=sampler,
        monitor=monitor,
    )

    cycle = live.sample_once()

    assert sampler.calls == 1
    assert len(monitor.calls) == 1

    assert monitor.calls[0] == {
        "cpu_percent": 20.0,
        "ram_percent": 30.0,
        "storage_percent": 40.0,
    }

    assert cycle.number == 1


def test_run_connects_sampler_to_monitor():
    sampler = FakeSampler()
    monitor = FakeMonitor()

    live = LiveMonitor(
        sampler=sampler,
        monitor=monitor,
    )

    completed = live.run(max_cycles=3)

    assert completed == 3
    assert sampler.calls == 3


def test_callback_receives_cycles():
    sampler = FakeSampler()
    monitor = FakeMonitor()
    received = []

    live = LiveMonitor(
        sampler=sampler,
        monitor=monitor,
    )

    live.run(
        max_cycles=2,
        on_cycle=received.append,
    )

    assert len(received) == 2
    assert received[0].number == 1
    assert received[1].number == 2


def test_monitor_property():
    monitor = FakeMonitor()

    live = LiveMonitor(
        sampler=FakeSampler(),
        monitor=monitor,
    )

    assert live.monitor is monitor
