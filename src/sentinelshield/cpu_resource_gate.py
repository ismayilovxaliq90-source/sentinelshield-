from __future__ import annotations

from dataclasses import dataclass

from .cpu_monitor import CPUMonitor, CPUReading


class CpuResourceDenied(RuntimeError):
    """Raised when CPU usage exceeds the configured safe limit."""


@dataclass(frozen=True)
class CPUResourceDecision:
    allowed: bool
    usage_percent: float
    maximum_usage_percent: float
    reason: str


class CpuResourceGate:
    """
    CPU resource safety gate.

    It evaluates CPU usage against a maximum allowed percentage.
    A denied execution raises CpuResourceDenied through check().
    """

    def __init__(
        self,
        maximum_usage_percent: float = 80.0,
        monitor: CPUMonitor | None = None,
    ) -> None:
        maximum_usage_percent = float(
            maximum_usage_percent
        )

        if not 0.0 <= maximum_usage_percent <= 100.0:
            raise ValueError(
                "maximum_usage_percent must be between 0 and 100"
            )

        self.monitor = (
            monitor
            if monitor is not None
            else CPUMonitor()
        )

        self.maximum_usage_percent = (
            maximum_usage_percent
        )

    def evaluate(
        self,
        reading: CPUReading | None = None,
    ) -> CPUResourceDecision:
        if reading is None:
            reading = self.monitor.read()

        if not isinstance(reading, CPUReading):
            raise TypeError(
                "reading must be a CPUReading"
            )

        usage = float(
            reading.usage_percent
        )

        allowed = (
            usage <= self.maximum_usage_percent
        )

        if allowed:
            reason = "CPU usage within allowed limit"
        else:
            reason = "CPU usage exceeds allowed limit"

        return CPUResourceDecision(
            allowed=allowed,
            usage_percent=usage,
            maximum_usage_percent=(
                self.maximum_usage_percent
            ),
            reason=reason,
        )

    def enforce(
        self,
        reading: CPUReading | None = None,
    ) -> CPUResourceDecision:
        decision = self.evaluate(reading)

        if not decision.allowed:
            raise CpuResourceDenied(
                "CPU RESOURCE DENIED: "
                f"{decision.usage_percent:.2f}% > "
                f"{decision.maximum_usage_percent:.2f}%"
            )

        return decision

    def check(
        self,
        reading: CPUReading | None = None,
    ) -> CPUResourceDecision:
        return self.enforce(reading)

    def is_allowed(
        self,
        reading: CPUReading | None = None,
    ) -> bool:
        return self.evaluate(reading).allowed


# Compatibility aliases used by existing SentinelShield tests.
CPUMonitorGate = CpuResourceGate
CPUResourceGate = CpuResourceGate
