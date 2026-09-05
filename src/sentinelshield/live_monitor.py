from __future__ import annotations

from sentinelshield.continuous_monitor import ContinuousMonitor, MonitorCycle
from sentinelshield.resource_sampler import ResourceSampler


class LiveMonitor:
    """
    Connects the real host resource sampler to ContinuousMonitor.

    This component only observes and evaluates.
    It does not kill processes or modify the host.
    """

    def __init__(
        self,
        sampler: ResourceSampler | None = None,
        monitor: ContinuousMonitor | None = None,
    ):
        self._sampler = sampler or ResourceSampler()
        self._monitor = monitor or ContinuousMonitor()

    @property
    def monitor(self):
        return self._monitor

    def sample_once(self) -> MonitorCycle:
        snapshot = self._sampler.sample()

        return self._monitor.run_once(
            cpu_percent=snapshot.cpu_percent,
            ram_percent=snapshot.ram_percent,
            storage_percent=snapshot.storage_percent,
        )

    def run(
        self,
        *,
        max_cycles: int | None = None,
        on_cycle=None,
    ) -> int:
        return self._monitor.run(
            self._sample,
            max_cycles=max_cycles,
            on_cycle=on_cycle,
        )

    def _sample(self):
        snapshot = self._sampler.sample()

        return (
            snapshot.cpu_percent,
            snapshot.ram_percent,
            snapshot.storage_percent,
        )
