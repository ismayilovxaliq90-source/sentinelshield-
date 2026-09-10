from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import threading


class EmergencyStopError(RuntimeError):
    """Raised when emergency-stop state cannot be used safely."""


class EmergencyStopState(str, Enum):
    READY = "READY"
    STOPPED = "STOPPED"


@dataclass(frozen=True)
class EmergencyStopStatus:
    state: EmergencyStopState
    stopped: bool
    reason: str | None
    generation: int

    def to_dict(self) -> dict:
        return {
            "state": self.state.value,
            "stopped": self.stopped,
            "reason": self.reason,
            "generation": self.generation,
        }


class EmergencyStopController:
    """
    Thread-safe emergency-stop state controller.

    This class only controls execution authorization state.
    It does not create, kill, or modify operating-system processes.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._state = EmergencyStopState.READY
        self._reason: str | None = None
        self._generation = 0

    def status(self) -> EmergencyStopStatus:
        with self._lock:
            return EmergencyStopStatus(
                state=self._state,
                stopped=self._state is EmergencyStopState.STOPPED,
                reason=self._reason,
                generation=self._generation,
            )

    def trigger(self, reason: str) -> EmergencyStopStatus:
        if not isinstance(reason, str):
            raise EmergencyStopError(
                "stop reason must be a string"
            )

        reason = reason.strip()

        if not reason:
            raise EmergencyStopError(
                "stop reason must not be empty"
            )

        if "\x00" in reason:
            raise EmergencyStopError(
                "stop reason contains NULL character"
            )

        with self._lock:
            if self._state is EmergencyStopState.STOPPED:
                return self.status()

            self._state = EmergencyStopState.STOPPED
            self._reason = reason
            self._generation += 1

            return self.status()

    def reset(self) -> EmergencyStopStatus:
        with self._lock:
            self._state = EmergencyStopState.READY
            self._reason = None
            self._generation += 1

            return self.status()

    def is_stopped(self) -> bool:
        with self._lock:
            return self._state is EmergencyStopState.STOPPED

    def require_execution_allowed(self) -> None:
        with self._lock:
            if self._state is EmergencyStopState.STOPPED:
                reason = self._reason or "unspecified"
                raise EmergencyStopError(
                    f"execution blocked by emergency stop: {reason}"
                )


def create_emergency_stop_controller() -> EmergencyStopController:
    return EmergencyStopController()


def get_emergency_stop_status(
    controller: EmergencyStopController,
) -> EmergencyStopStatus:
    if not isinstance(controller, EmergencyStopController):
        raise EmergencyStopError(
            "controller must be EmergencyStopController"
        )

    return controller.status()


def trigger_emergency_stop(
    controller: EmergencyStopController,
    reason: str,
) -> EmergencyStopStatus:
    if not isinstance(controller, EmergencyStopController):
        raise EmergencyStopError(
            "controller must be EmergencyStopController"
        )

    return controller.trigger(reason)


def reset_emergency_stop(
    controller: EmergencyStopController,
) -> EmergencyStopStatus:
    if not isinstance(controller, EmergencyStopController):
        raise EmergencyStopError(
            "controller must be EmergencyStopController"
        )

    return controller.reset()


def require_execution_allowed(
    controller: EmergencyStopController,
) -> None:
    if not isinstance(controller, EmergencyStopController):
        raise EmergencyStopError(
            "controller must be EmergencyStopController"
        )

    controller.require_execution_allowed()
