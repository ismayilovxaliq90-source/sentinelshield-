from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable

from sentinelshield.monitoring_policy_pipeline import (
    MonitoringPolicyPipeline,
    PipelineResult,
)


@dataclass(frozen=True)
class MonitorCycle:
    number: int
    result: PipelineResult


class ContinuousMonitor:
    def __init__(
        self,
        pipeline: MonitoringPolicyPipeline | None = None,
        interval_seconds: float = 5.0,
        clock: Callable[[], float] | None = None,
        sleeper: Callable[[float], None] | None = None,
    ) -> None:
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be > 0")

        self._pipeline = pipeline or MonitoringPolicyPipeline()
        self._interval = float(interval_seconds)
        self._clock = clock or time.monotonic
        self._sleeper = sleeper or time.sleep
        self._running = False
        self._cycle_number = 0

    @property
    def running(self) -> bool:
        return self._running

    @property
    def cycle_number(self) -> int:
        return self._cycle_number

    def stop(self) -> None:
        self._running = False

    def run_once(
        self,
        *,
        cpu_percent: float,
        ram_percent: float,
        storage_percent: float,
    ) -> MonitorCycle:
        self._cycle_number += 1

        result = self._pipeline.evaluate(
            cpu_percent=cpu_percent,
            ram_percent=ram_percent,
            storage_percent=storage_percent,
        )

        return MonitorCycle(
            number=self._cycle_number,
            result=result,
        )

    def run(
        self,
        sampler: Callable[[], tuple[float, float, float]],
        *,
        max_cycles: int | None = None,
        on_cycle: Callable[[MonitorCycle], None] | None = None,
    ) -> int:
        if not callable(sampler):
            raise TypeError("sampler must be callable")

        if max_cycles is not None:
            if not isinstance(max_cycles, int):
                raise TypeError("max_cycles must be int")
            if max_cycles <= 0:
                raise ValueError("max_cycles must be > 0")

        if on_cycle is not None and not callable(on_cycle):
            raise TypeError("on_cycle must be callable")

        self._running = True
        completed = 0

        while self._running:
            cpu, ram, storage = sampler()

            cycle = self.run_once(
                cpu_percent=cpu,
                ram_percent=ram,
                storage_percent=storage,
            )

            completed += 1

            if on_cycle is not None:
                on_cycle(cycle)

            if max_cycles is not None and completed >= max_cycles:
                self._running = False
                break

            self._sleeper(self._interval)

        return completed
