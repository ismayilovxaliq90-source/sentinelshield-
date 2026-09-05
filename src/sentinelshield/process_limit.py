from __future__ import annotations

from dataclasses import dataclass


class ProcessLimitError(RuntimeError):
    """Raised when the configured process limit is violated."""


@dataclass(frozen=True)
class ProcessLimitState:
    limit: int
    active: int
    allowed: bool


class ProcessLimit:
    """
    Deterministic process-count limit controller.

    This component does not create or terminate processes.
    It only evaluates whether an observed process count
    is within the configured policy.
    """

    DEFAULT_LIMIT = 16

    def __init__(self, limit: int = DEFAULT_LIMIT) -> None:
        if not isinstance(limit, int):
            raise TypeError(
                "limit must be an integer"
            )

        if isinstance(limit, bool):
            raise TypeError(
                "limit must be an integer"
            )

        if limit < 1:
            raise ValueError(
                "limit must be greater than zero"
            )

        self.limit = limit

    def check(self, active: int) -> ProcessLimitState:
        if not isinstance(active, int):
            raise TypeError(
                "active process count must be an integer"
            )

        if isinstance(active, bool):
            raise TypeError(
                "active process count must be an integer"
            )

        if active < 0:
            raise ValueError(
                "active process count cannot be negative"
            )

        allowed = active <= self.limit

        return ProcessLimitState(
            limit=self.limit,
            active=active,
            allowed=allowed,
        )

    def is_allowed(self, active: int) -> bool:
        return self.check(active).allowed

    def require_allowed(self, active: int) -> ProcessLimitState:
        state = self.check(active)

        if not state.allowed:
            raise ProcessLimitError(
                f"process limit exceeded: "
                f"{state.active} > {state.limit}"
            )

        return state
