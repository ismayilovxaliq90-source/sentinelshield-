from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Callable, Any


class CPUMonitorError(RuntimeError):
    """Raised when CPU monitoring fails or returns invalid data."""


@dataclass(frozen=True)
class CPUReading:
    percent: float
    sample_interval: float
    cpu_count: int


class CPUMonitor:
    """
    Read-only CPU monitor.

    Supports:
      - real CPU sampling through psutil
      - deterministic injected readers for tests
      - bounded CPU percentage values
    """

    def __init__(
        self,
        reader: Callable[[], Any] | None = None,
        sample_interval: float = 0.1,
    ) -> None:
        if sample_interval <= 0:
            raise ValueError(
                "sample_interval must be greater than zero"
            )

        self._reader = reader
        self.sample_interval = float(sample_interval)

    @staticmethod
    def cpu_count() -> int:
        count = os.cpu_count()

        if count is None or count < 1:
            raise CPUMonitorError(
                "unable to determine CPU count"
            )

        return int(count)

    @staticmethod
    def _system_reader() -> float:
        try:
            import psutil

            value = float(
                psutil.cpu_percent(
                    interval=None
                )
            )
            return value

        except Exception:
            return 0.0

    def _read_value(self) -> float:
        reader = (
            self._reader
            if self._reader is not None
            else self._system_reader
        )

        try:
            value = float(reader())
        except Exception as exc:
            raise CPUMonitorError(
                "CPU reader failed"
            ) from exc

        if value < 0.0:
            value = 0.0

        if value > 100.0:
            value = 100.0

        return value

    def read(self) -> CPUReading:
        value = self._read_value()

        return CPUReading(
            percent=value,
            sample_interval=self.sample_interval,
            cpu_count=self.cpu_count(),
        )

    def usage_percent(self) -> float:
        return self.read().percent

    def is_valid_reading(
        self,
        reading: CPUReading,
    ) -> bool:
        if not isinstance(
            reading,
            CPUReading,
        ):
            return False

        if not 0.0 <= reading.percent <= 100.0:
            return False

        if reading.sample_interval <= 0:
            return False

        if reading.cpu_count < 1:
            return False

        return True


# Compatibility aliases used by existing SentinelShield tests.
CpuMonitor = CPUMonitor
CpuReading = CPUReading
CPUReadingData = CPUReading

# Compatibility property expected by CPU Resource Gate.
def _cpu_usage_percent(self) -> float:
    return self.percent


CPUReading.usage_percent = property(_cpu_usage_percent)
