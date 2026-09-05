from __future__ import annotations

from dataclasses import dataclass

from sentinelshield.storage_monitor import (
    StorageMonitor,
    StorageReading,
)


class DiskSpaceGateError(RuntimeError):
    """Raised when disk space gate evaluation fails."""


class DiskSpaceDenied(DiskSpaceGateError):
    """Raised when available disk space is below the configured minimum."""


@dataclass(frozen=True)
class DiskSpaceDecision:
    allowed: bool
    path: str
    free_bytes: int
    minimum_free_bytes: int
    usage_percent: float


class DiskSpaceGate:
    """
    Deterministic disk-space safety gate.

    The gate only evaluates available storage.
    It does not modify files or storage state.
    """

    def __init__(
        self,
        minimum_free_bytes: int,
        monitor: StorageMonitor | None = None,
    ) -> None:
        if not isinstance(minimum_free_bytes, int):
            raise TypeError(
                "minimum_free_bytes must be an integer"
            )

        if minimum_free_bytes < 0:
            raise ValueError(
                "minimum_free_bytes cannot be negative"
            )

        self.minimum_free_bytes = minimum_free_bytes
        self.monitor = monitor or StorageMonitor(".")

    def evaluate(
        self,
        reading: StorageReading,
    ) -> DiskSpaceDecision:
        if not StorageMonitor.is_valid_reading(reading):
            raise DiskSpaceGateError(
                "invalid storage reading"
            )

        allowed = (
            reading.free_bytes
            >= self.minimum_free_bytes
        )

        return DiskSpaceDecision(
            allowed=allowed,
            path=reading.path,
            free_bytes=reading.free_bytes,
            minimum_free_bytes=self.minimum_free_bytes,
            usage_percent=reading.usage_percent,
        )

    def check(self) -> DiskSpaceDecision:
        reading = self.monitor.read()

        return self.evaluate(reading)

    def enforce(self) -> DiskSpaceDecision:
        decision = self.check()

        if not decision.allowed:
            raise DiskSpaceDenied(
                "insufficient free disk space"
            )

        return decision

    def is_allowed(self) -> bool:
        try:
            self.enforce()
        except DiskSpaceGateError:
            return False

        return True
