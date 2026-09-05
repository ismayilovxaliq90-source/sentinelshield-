from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class EmergencyStopError(RuntimeError):
    """Raised when emergency-stop policy is violated."""


class StopReason(str, Enum):
    MANUAL = "MANUAL"
    WATCHDOG = "WATCHDOG"
    TIMEOUT = "TIMEOUT"
    RESOURCE = "RESOURCE"
    FAILURE = "FAILURE"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class EmergencyStopState:
    active: bool
    reason: StopReason | None
    message: str
    generation: int


class EmergencyStop:
    """
    Deterministic emergency-stop state controller.

    This component does not kill processes.
    It records stop state and blocks execution while active.
    """

    def __init__(self) -> None:
        self._active = False
        self._reason: StopReason | None = None
        self._message = ""
        self._generation = 0

    @property
    def active(self) -> bool:
        return self._active

    def state(self) -> EmergencyStopState:
        return EmergencyStopState(
            active=self._active,
            reason=self._reason,
            message=self._message,
            generation=self._generation,
        )

    def trigger(
        self,
        reason: StopReason = StopReason.MANUAL,
        message: str = "",
    ) -> EmergencyStopState:
        if not isinstance(reason, StopReason):
            raise TypeError("reason must be a StopReason")

        if not isinstance(message, str):
            raise TypeError("message must be a string")

        if self._active:
            return self.state()

        self._active = True
        self._reason = reason
        self._message = message
        self._generation += 1

        return self.state()

    def require_clear(self) -> None:
        if self._active:
            raise EmergencyStopError(
                "emergency stop is active"
            )

    def can_execute(self) -> bool:
        return not self._active

    def clear(self) -> EmergencyStopState:
        if not self._active:
            raise EmergencyStopError(
                "emergency stop is not active"
            )

        self._active = False
        self._reason = None
        self._message = ""
        self._generation += 1

        return self.state()

    def reset(self) -> EmergencyStopState:
        self._active = False
        self._reason = None
        self._message = ""
        self._generation += 1

        return self.state()
