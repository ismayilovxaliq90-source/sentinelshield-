from __future__ import annotations

import time
from dataclasses import dataclass


class TimeoutControllerError(RuntimeError):
    """Raised when timeout policy is violated."""


@dataclass(frozen=True)
class TimeoutState:
    timeout: float
    elapsed: float
    expired: bool


class TimeoutController:
    """
    Deterministic execution timeout controller.

    This controller does not terminate processes itself.
    It only tracks elapsed time and determines whether
    the configured timeout has expired.
    """

    def __init__(self, timeout: float) -> None:
        if timeout <= 0:
            raise ValueError(
                "timeout must be greater than zero"
            )

        self.timeout = float(timeout)
        self._started_at: float | None = None

    def start(self) -> None:
        self._started_at = time.monotonic()

    def elapsed(self) -> float:
        if self._started_at is None:
            raise TimeoutControllerError(
                "timeout controller has not been started"
            )

        return max(
            0.0,
            time.monotonic() - self._started_at,
        )

    def expired(self) -> bool:
        return self.elapsed() >= self.timeout

    def remaining(self) -> float:
        return max(
            0.0,
            self.timeout - self.elapsed(),
        )

    def state(self) -> TimeoutState:
        elapsed = self.elapsed()

        return TimeoutState(
            timeout=self.timeout,
            elapsed=elapsed,
            expired=elapsed >= self.timeout,
        )

    def check(self) -> TimeoutState:
        state = self.state()

        if state.expired:
            raise TimeoutControllerError(
                f"execution timeout expired: {self.timeout}"
            )

        return state
