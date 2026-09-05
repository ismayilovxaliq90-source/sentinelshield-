from __future__ import annotations

import time
from dataclasses import dataclass

from sentinelshield.service_health import SystemdServiceHealth


@dataclass(frozen=True)
class WatchdogResult:
    service: str
    healthy: bool
    checks: int


class SentinelShieldWatchdog:
    def __init__(
        self,
        service: str = "sentinelshield.service",
    ):
        self.health = SystemdServiceHealth(service)
        self.checks = 0

    def check_once(self) -> WatchdogResult:
        result = self.health.check()
        self.checks += 1

        return WatchdogResult(
            service=result.service,
            healthy=result.healthy,
            checks=self.checks,
        )

    def run(
        self,
        interval_seconds: int = 30,
        iterations: int | None = None,
    ):
        if interval_seconds <= 0:
            raise ValueError(
                "interval_seconds must be > 0"
            )

        completed = 0

        while (
            iterations is None
            or completed < iterations
        ):
            yield self.check_once()

            completed += 1

            if (
                iterations is None
                or completed < iterations
            ):
                time.sleep(interval_seconds)


# Backward-compatible core component.
# ADDIM 33 introduced SentinelShieldWatchdog; the original
# core architecture expects a component named Watchdog.
class Watchdog(SentinelShieldWatchdog):
    pass


class WatchdogError(RuntimeError):
    pass
