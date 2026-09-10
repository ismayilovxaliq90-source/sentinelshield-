from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import threading
import time


class EmergencyStopError(RuntimeError):
    """Raised when emergency-stop state cannot be safely managed."""


class EmergencyStopState(str, Enum):
    READY = "READY"
    STOP_REQUESTED = "STOP_REQUESTED"
    STOPPED = "STOPPED"


@dataclass(frozen=True)
class EmergencyStopResult:
    ready: bool
    stop_requested: bool
    stopped: bool
    state: EmergencyStopState
    reason: str

    def to_dict(self) -> dict:
        return {
            "ready": self.ready,
            "stop_requested": self.stop_requested,
            "stopped": self.stopped,
            "state": self.state.value,
            "reason": self.reason,
        }


class EmergencyStopController:
    """
    Thread-safe emergency-stop state controller.

    This class only manages stop state.
    It does not execute, terminate, kill, or modify any process.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._state = EmergencyStopState.READY
        self._requested_at: float | None = None
        self._reason: str | None = None

    @property
    def state(self) -> EmergencyStopState:
        with self._lock:
            return self._state

    @property
    def is_ready(self) -> bool:
        with self._lock:
            return self._state == EmergencyStopState.READY

    @property
    def is_stop_requested(self) -> bool:
        with self._lock:
            return self._state in (
                EmergencyStopState.STOP_REQUESTED,
                EmergencyStopState.STOPPED,
            )

    @property
    def is_stopped(self) -> bool:
        with self._lock:
            return self._state == EmergencyStopState.STOPPED

    @property
    def requested_at(self) -> float | None:
        with self._lock:
            return self._requested_at

    @property
    def reason(self) -> str | None:
        with self._lock:
            return self._reason

    def request_stop(self, reason: str = "EMERGENCY_STOP") -> EmergencyStopResult:
        if not isinstance(reason, str):
            raise EmergencyStopError("reason must be a string")

        reason = reason.strip()

        if not reason:
            raise EmergencyStopError("reason must not be empty")

        with self._lock:
            if self._state == EmergencyStopState.READY:
                self._state = EmergencyStopState.STOP_REQUESTED
                self._requested_at = time.monotonic()
                self._reason = reason

            elif self._state == EmergencyStopState.STOP_REQUESTED:
                # Idempotent: retain the original request and reason.
                pass

            elif self._state == EmergencyStopState.STOPPED:
                # A stopped controller must never return to READY implicitly.
                pass

            return self._result_locked()

    def confirm_stopped(self) -> EmergencyStopResult:
        with self._lock:
            if self._state == EmergencyStopState.READY:
                raise EmergencyStopError(
                    "cannot confirm STOPPED before stop was requested"
                )

            self._state = EmergencyStopState.STOPPED

            return self._result_locked()

    def should_stop(self) -> bool:
        with self._lock:
            return self._state in (
                EmergencyStopState.STOP_REQUESTED,
                EmergencyStopState.STOPPED,
            )

    def status(self) -> EmergencyStopResult:
        with self._lock:
            return self._result_locked()

    def _result_locked(self) -> EmergencyStopResult:
        return EmergencyStopResult(
            ready=self._state == EmergencyStopState.READY,
            stop_requested=self._state
            in (
                EmergencyStopState.STOP_REQUESTED,
                EmergencyStopState.STOPPED,
            ),
            stopped=self._state == EmergencyStopState.STOPPED,
            state=self._state,
            reason=self._reason or "",
        )


def create_emergency_stop_controller() -> EmergencyStopController:
    """
    Create a fresh controller in READY state.

    No process, command, thread, or external resource is executed.
    """
    return EmergencyStopController()


def validate_emergency_stop_readiness(
    controller: EmergencyStopController,
) -> EmergencyStopResult:
    if not isinstance(controller, EmergencyStopController):
        raise EmergencyStopError(
            "controller must be EmergencyStopController"
        )

    result = controller.status()

    if result.state not in EmergencyStopState:
        raise EmergencyStopError("invalid emergency-stop state")

    if result.state == EmergencyStopState.READY:
        if result.stop_requested or result.stopped:
            raise EmergencyStopError(
                "READY state contains stop flags"
            )

    if result.state == EmergencyStopState.STOP_REQUESTED:
        if not result.stop_requested or result.stopped:
            raise EmergencyStopError(
                "STOP_REQUESTED state is inconsistent"
            )

    if result.state == EmergencyStopState.STOPPED:
        if not result.stop_requested or not result.stopped:
            raise EmergencyStopError(
                "STOPPED state is inconsistent"
            )

    return result


def require_execution_allowed(
    controller: EmergencyStopController,
) -> None:
    if not isinstance(controller, EmergencyStopController):
        raise EmergencyStopError(
            "controller must be EmergencyStopController"
        )

    if controller.should_stop():
        raise EmergencyStopError(
            "execution blocked by emergency stop"
        )
