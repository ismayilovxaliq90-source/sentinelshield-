from __future__ import annotations

from dataclasses import dataclass

from sentinelshield.ram_monitor import RamMonitor


class RamResourceDenied(RuntimeError):
    """Raised when RAM usage exceeds the configured safety limit."""


@dataclass(frozen=True)
class RamGateDecision:
    allowed: bool
    usage_percent: float
    maximum_usage_percent: float
    reason: str


class RamResourceGate:
    def __init__(
        self,
        maximum_usage_percent: float = 80.0,
        monitor: RamMonitor | None = None,
    ) -> None:
        if maximum_usage_percent < 0 or maximum_usage_percent > 100:
            raise ValueError("maximum_usage_percent must be between 0 and 100")

        self.maximum_usage_percent = float(maximum_usage_percent)
        self.monitor = monitor or RamMonitor()

    def check(self) -> RamGateDecision:
        usage = float(self.monitor.usage_percent())

        if usage > self.maximum_usage_percent:
            raise RamResourceDenied(
                f"RAM usage {usage:.2f}% exceeds "
                f"maximum allowed {self.maximum_usage_percent:.2f}%"
            )

        return RamGateDecision(
            allowed=True,
            usage_percent=usage,
            maximum_usage_percent=self.maximum_usage_percent,
            reason="RAM usage within configured limit",
        )

    def evaluate(self) -> RamGateDecision:
        return self.check()
