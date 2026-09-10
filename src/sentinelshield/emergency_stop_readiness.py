from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


class EmergencyStopError(ValueError):
    """Raised when emergency-stop readiness validation fails."""


@dataclass(frozen=True)
class EmergencyStopPolicy:
    require_callback: bool = True
    initially_stopped: bool = False


@dataclass(frozen=True)
class EmergencyStopReadinessResult:
    ready: bool
    stopped: bool
    callback_available: bool
    reason: str

    def to_dict(self) -> dict:
        return {
            "ready": self.ready,
            "stopped": self.stopped,
            "callback_available": self.callback_available,
            "reason": self.reason,
        }


class EmergencyStopController:
    """
    In-memory emergency-stop controller.

    This class does not start, stop, kill, or modify any real process.
    It only maintains an explicit control state.
    """

    def __init__(
        self,
        callback: Callable[[], object] | None = None,
        *,
        policy: EmergencyStopPolicy | None = None,
    ) -> None:
        self._policy = policy or EmergencyStopPolicy()

        if not isinstance(self._policy, EmergencyStopPolicy):
            raise EmergencyStopError(
                "policy must be EmergencyStopPolicy"
            )

        if not isinstance(self._policy.require_callback, bool):
            raise EmergencyStopError(
                "require_callback must be bool"
            )

        if not isinstance(self._policy.initially_stopped, bool):
            raise EmergencyStopError(
                "initially_stopped must be bool"
            )

        if callback is not None and not callable(callback):
            raise EmergencyStopError(
                "callback must be callable or None"
            )

        self._callback = callback
        self._stopped = self._policy.initially_stopped

    @property
    def stopped(self) -> bool:
        return self._stopped

    @property
    def callback_available(self) -> bool:
        return self._callback is not None

    def readiness(self) -> EmergencyStopReadinessResult:
        if self._policy.require_callback and self._callback is None:
            return EmergencyStopReadinessResult(
                ready=False,
                stopped=self._stopped,
                callback_available=False,
                reason="STOP_CALLBACK_REQUIRED",
            )

        if self._stopped:
            return EmergencyStopReadinessResult(
                ready=False,
                stopped=True,
                callback_available=self.callback_available,
                reason="EMERGENCY_STOP_ACTIVE",
            )

        return EmergencyStopReadinessResult(
            ready=True,
            stopped=False,
            callback_available=self.callback_available,
            reason="EMERGENCY_STOP_READY",
        )

    def request_stop(self) -> bool:
        self._stopped = True

        if self._callback is None:
            return True

        try:
            self._callback()
        except Exception:
            return False

        return True

    def reset(self) -> None:
        self._stopped = False

    def require_ready(self) -> EmergencyStopReadinessResult:
        result = self.readiness()

        if not result.ready:
            raise EmergencyStopError(result.reason)

        return result


def validate_emergency_stop_readiness(
    controller: EmergencyStopController,
) -> EmergencyStopReadinessResult:
    if not isinstance(controller, EmergencyStopController):
        raise EmergencyStopError(
            "controller must be EmergencyStopController"
        )

    return controller.readiness()


def require_emergency_stop_readiness(
    controller: EmergencyStopController,
) -> EmergencyStopReadinessResult:
    if not isinstance(controller, EmergencyStopController):
        raise EmergencyStopError(
            "controller must be EmergencyStopController"
        )

    return controller.require_ready()
