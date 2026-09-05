from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


class RAMMonitorError(RuntimeError):
    """Raised when RAM monitoring fails or returns invalid data."""


@dataclass(frozen=True)
class RAMReading:
    total_bytes: int
    available_bytes: int
    used_bytes: int
    usage_percent: float


class RAMMonitor:
    """
    Read-only RAM monitor.

    The monitor never modifies system memory.
    """

    def __init__(
        self,
        reader: Callable[[], Any] | None = None,
    ) -> None:
        self._reader = reader

    def _read_meminfo(self) -> dict[str, int]:
        values: dict[str, int] = {}

        try:
            with open(
                "/proc/meminfo",
                "r",
                encoding="utf-8",
            ) as file:
                for line in file:
                    parts = line.split()

                    if len(parts) < 2:
                        continue

                    key = parts[0].rstrip(":")

                    try:
                        value = int(parts[1])
                    except ValueError:
                        continue

                    unit = (
                        parts[2].lower()
                        if len(parts) >= 3
                        else ""
                    )

                    if unit == "kb":
                        value *= 1024
                    elif unit == "mb":
                        value *= 1024 * 1024
                    elif unit == "gb":
                        value *= 1024 * 1024 * 1024

                    values[key] = value

        except OSError as exc:
            raise RAMMonitorError(
                "unable to read /proc/meminfo"
            ) from exc

        if "MemTotal" not in values:
            raise RAMMonitorError(
                "MemTotal is missing"
            )

        if "MemAvailable" not in values:
            raise RAMMonitorError(
                "MemAvailable is missing"
            )

        return values

    # Public compatibility name
    def read_meminfo(self) -> dict[str, int]:
        return self._read_meminfo()

    def _default_reader(self) -> RAMReading:
        meminfo = self._read_meminfo()

        total = int(meminfo["MemTotal"])
        available = int(meminfo["MemAvailable"])

        used = total - available

        usage_percent = (
            (used / total) * 100.0
            if total > 0
            else 0.0
        )

        return RAMReading(
            total_bytes=total,
            available_bytes=available,
            used_bytes=used,
            usage_percent=usage_percent,
        )

    def _coerce_reading(self, raw: Any) -> RAMReading:
        if isinstance(raw, RAMReading):
            return raw

        if isinstance(raw, dict):
            try:
                return RAMReading(
                    total_bytes=int(raw["total_bytes"]),
                    available_bytes=int(
                        raw["available_bytes"]
                    ),
                    used_bytes=int(
                        raw["used_bytes"]
                    ),
                    usage_percent=float(
                        raw["usage_percent"]
                    ),
                )
            except (
                KeyError,
                TypeError,
                ValueError,
            ) as exc:
                raise RAMMonitorError(
                    "invalid RAM reading dictionary"
                ) from exc

        if isinstance(raw, (tuple, list)):
            if len(raw) != 4:
                raise RAMMonitorError(
                    "RAM reading sequence must contain 4 values"
                )

            try:
                return RAMReading(
                    total_bytes=int(raw[0]),
                    available_bytes=int(raw[1]),
                    used_bytes=int(raw[2]),
                    usage_percent=float(raw[3]),
                )
            except (
                TypeError,
                ValueError,
            ) as exc:
                raise RAMMonitorError(
                    "invalid RAM reading sequence"
                ) from exc

        if isinstance(raw, (int, float)):
            usage = float(raw)

            # Compatibility behavior:
            # values below 0 become 0, values above 100 become 100.
            usage = max(0.0, min(100.0, usage))

            total = 1_000_000
            used = int(
                total * usage / 100.0
            )
            available = total - used

            return RAMReading(
                total_bytes=total,
                available_bytes=available,
                used_bytes=used,
                usage_percent=usage,
            )

        raise RAMMonitorError(
            "unsupported RAM reader result"
        )

    def read(self) -> RAMReading:
        if self._reader is None:
            reading = self._default_reader()
        else:
            try:
                raw = self._reader()
            except Exception as exc:
                raise RAMMonitorError(
                    "RAM reader failed"
                ) from exc

            reading = self._coerce_reading(raw)

        if not self.is_valid_reading(reading):
            raise RAMMonitorError(
                "invalid RAM reading"
            )

        return reading

    def usage_percent(self) -> float:
        return self.read().usage_percent

    @staticmethod
    def is_valid_reading(
        reading: RAMReading,
    ) -> bool:
        if not isinstance(
            reading,
            RAMReading,
        ):
            return False

        if reading.total_bytes <= 0:
            return False

        if reading.available_bytes < 0:
            return False

        if reading.used_bytes < 0:
            return False

        if (
            reading.available_bytes
            > reading.total_bytes
        ):
            return False

        if (
            reading.used_bytes
            > reading.total_bytes
        ):
            return False

        if (
            reading.used_bytes
            + reading.available_bytes
            != reading.total_bytes
        ):
            return False

        if not (
            0.0
            <= reading.usage_percent
            <= 100.0
        ):
            return False

        expected_usage = (
            reading.used_bytes
            / reading.total_bytes
        ) * 100.0

        if abs(
            expected_usage
            - reading.usage_percent
        ) > 0.01:
            return False

        return True


# Compatibility aliases used by existing tests.
RamReading = RAMReading
RamMonitor = RAMMonitor
