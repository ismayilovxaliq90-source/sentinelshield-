from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


class ThermalGateError(RuntimeError):
    """Base error for thermal-gate failures."""


class ThermalLimitExceeded(ThermalGateError):
    """Raised when the measured temperature exceeds the configured limit."""


class ThermalReadingInvalid(ThermalGateError):
    """Raised when the temperature reading is missing or invalid."""


@dataclass(frozen=True)
class ThermalDecision:
    allowed: bool
    temperature_c: Optional[float]
    limit_c: float
    reason: str


class ThermalGate:
    """
    Safety gate for thermal conditions.

    The gate blocks execution when:
      - the reading is missing/invalid
      - the temperature is at or above the configured limit
    """

    def __init__(self, maximum_c: float = 85.0) -> None:
        if maximum_c <= 0:
            raise ValueError("maximum_c must be greater than zero")

        self.maximum_c = float(maximum_c)

    def evaluate(self, temperature_c: Optional[float]) -> ThermalDecision:
        if temperature_c is None:
            return ThermalDecision(
                allowed=False,
                temperature_c=None,
                limit_c=self.maximum_c,
                reason="THERMAL READING UNAVAILABLE",
            )

        try:
            temperature = float(temperature_c)
        except (TypeError, ValueError):
            return ThermalDecision(
                allowed=False,
                temperature_c=None,
                limit_c=self.maximum_c,
                reason="THERMAL READING INVALID",
            )

        if temperature != temperature:
            return ThermalDecision(
                allowed=False,
                temperature_c=None,
                limit_c=self.maximum_c,
                reason="THERMAL READING INVALID",
            )

        if temperature >= self.maximum_c:
            return ThermalDecision(
                allowed=False,
                temperature_c=temperature,
                limit_c=self.maximum_c,
                reason="THERMAL LIMIT EXCEEDED",
            )

        return ThermalDecision(
            allowed=True,
            temperature_c=temperature,
            limit_c=self.maximum_c,
            reason="THERMAL OK",
        )

    def enforce(self, temperature_c: Optional[float]) -> ThermalDecision:
        decision = self.evaluate(temperature_c)

        if not decision.allowed:
            if decision.reason == "THERMAL LIMIT EXCEEDED":
                raise ThermalLimitExceeded(
                    f"temperature={decision.temperature_c}C "
                    f"limit={decision.limit_c}C"
                )

            raise ThermalReadingInvalid(decision.reason)

        return decision

    def check(self, temperature_c: Optional[float]) -> bool:
        return self.evaluate(temperature_c).allowed
