from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable


class ThermalMonitorError(RuntimeError):
    """Raised when thermal monitoring fails unexpectedly."""


@dataclass(frozen=True)
class ThermalReading:
    temperature_celsius: float | None
    available: bool
    source: str


class ThermalMonitor:
    """
    Safe thermal observation layer.

    The monitor only reads available thermal information.
    It does not change fan settings, CPU settings, or system state.
    """

    def __init__(
        self,
        reader: Callable[[], float | None] | None = None,
    ) -> None:
        self._reader = (
            reader
            if reader is not None
            else self._read_system_temperature
        )

    @staticmethod
    def _read_system_temperature() -> float | None:
        thermal_root = Path("/sys/class/thermal")

        if not thermal_root.exists():
            return None

        temperatures: list[float] = []

        try:
            for zone in sorted(
                thermal_root.glob("thermal_zone*/temp")
            ):
                try:
                    raw = zone.read_text(
                        encoding="utf-8"
                    ).strip()

                    if not raw:
                        continue

                    value = float(raw)

                    # Linux thermal sysfs normally reports
                    # millidegrees Celsius.
                    if abs(value) > 200:
                        value /= 1000.0

                    if -100.0 <= value <= 200.0:
                        temperatures.append(value)

                except (
                    OSError,
                    ValueError,
                ):
                    continue

        except OSError:
            return None

        if not temperatures:
            return None

        return max(temperatures)

    def read(self) -> ThermalReading:
        try:
            temperature = self._reader()
        except Exception:
            return ThermalReading(
                temperature_celsius=None,
                available=False,
                source="system",
            )

        if temperature is None:
            return ThermalReading(
                temperature_celsius=None,
                available=False,
                source="system",
            )

        try:
            value = float(temperature)
        except (TypeError, ValueError):
            return ThermalReading(
                temperature_celsius=None,
                available=False,
                source="system",
            )

        if not -100.0 <= value <= 200.0:
            return ThermalReading(
                temperature_celsius=None,
                available=False,
                source="system",
            )

        return ThermalReading(
            temperature_celsius=value,
            available=True,
            source="system",
        )

    def temperature_celsius(self) -> float | None:
        return self.read().temperature_celsius

    def is_available(self) -> bool:
        return self.read().available
