from __future__ import annotations

import os
from dataclasses import dataclass


class StorageMonitorError(RuntimeError):
    """Raised when storage monitoring cannot be completed safely."""


@dataclass(frozen=True)
class StorageReading:
    path: str
    total_bytes: int
    free_bytes: int
    used_bytes: int
    usage_percent: float


class StorageMonitor:
    """
    Minimal filesystem storage monitoring layer.

    This monitor only reads filesystem statistics.
    It does not create, delete, or modify files.
    It does not enforce storage limits.
    """

    def __init__(self, path: str = ".") -> None:
        if not isinstance(path, str):
            raise TypeError("path must be a string")

        if not path:
            raise ValueError("path cannot be empty")

        self.path = os.path.abspath(path)

    def read(self) -> StorageReading:
        try:
            statistics = os.statvfs(self.path)
        except OSError as exc:
            raise StorageMonitorError(
                f"unable to read storage statistics: {self.path}"
            ) from exc

        block_size = statistics.f_frsize

        if block_size <= 0:
            raise StorageMonitorError(
                "invalid filesystem block size"
            )

        total_bytes = (
            statistics.f_blocks
            * block_size
        )

        free_bytes = (
            statistics.f_bavail
            * block_size
        )

        if total_bytes <= 0:
            raise StorageMonitorError(
                "invalid total storage value"
            )

        if free_bytes < 0:
            raise StorageMonitorError(
                "invalid free storage value"
            )

        if free_bytes > total_bytes:
            raise StorageMonitorError(
                "free storage exceeds total storage"
            )

        used_bytes = total_bytes - free_bytes

        usage_percent = (
            used_bytes / total_bytes
        ) * 100.0

        usage_percent = max(
            0.0,
            min(100.0, usage_percent),
        )

        return StorageReading(
            path=self.path,
            total_bytes=total_bytes,
            free_bytes=free_bytes,
            used_bytes=used_bytes,
            usage_percent=usage_percent,
        )

    @staticmethod
    def is_valid_reading(
        reading: StorageReading,
    ) -> bool:
        if not isinstance(reading, StorageReading):
            return False

        if not reading.path:
            return False

        if reading.total_bytes <= 0:
            return False

        if reading.free_bytes < 0:
            return False

        if reading.used_bytes < 0:
            return False

        if reading.free_bytes > reading.total_bytes:
            return False

        if reading.used_bytes > reading.total_bytes:
            return False

        if not 0.0 <= reading.usage_percent <= 100.0:
            return False

        return True
