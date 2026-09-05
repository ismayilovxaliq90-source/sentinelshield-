from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class RecoveryError(RuntimeError):
    """Raised when recovery policy is violated."""


class RecoveryStatus(str, Enum):
    IDLE = "IDLE"
    REQUIRED = "REQUIRED"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"


@dataclass(frozen=True)
class RecoveryPlan:
    reason: str
    actions: tuple[str, ...]


@dataclass(frozen=True)
class RecoveryState:
    status: RecoveryStatus
    reason: str
    actions_completed: int
    total_actions: int


class RecoveryController:
    """
    Task 33 — Recovery Controller.

    Creates and tracks a deterministic recovery plan.

    This component does not execute arbitrary commands,
    restart processes, or modify files by itself.
    """

    def __init__(self) -> None:
        self._status = RecoveryStatus.IDLE
        self._reason = ""
        self._actions_completed = 0
        self._total_actions = 0

    @property
    def status(self) -> RecoveryStatus:
        return self._status

    def state(self) -> RecoveryState:
        return RecoveryState(
            status=self._status,
            reason=self._reason,
            actions_completed=self._actions_completed,
            total_actions=self._total_actions,
        )

    def require_recovery(
        self,
        reason: str,
        actions: tuple[str, ...] | list[str],
    ) -> RecoveryPlan:
        if not isinstance(reason, str):
            raise TypeError("reason must be a string")

        if not reason.strip():
            raise ValueError("reason cannot be empty")

        if not isinstance(actions, (tuple, list)):
            raise TypeError(
                "actions must be a tuple or list"
            )

        normalized = tuple(actions)

        for action in normalized:
            if not isinstance(action, str):
                raise TypeError(
                    "all recovery actions must be strings"
                )

            if not action.strip():
                raise ValueError(
                    "recovery actions cannot be empty"
                )

        self._status = RecoveryStatus.REQUIRED
        self._reason = reason
        self._actions_completed = 0
        self._total_actions = len(normalized)

        return RecoveryPlan(
            reason=reason,
            actions=normalized,
        )

    def start(self) -> RecoveryState:
        if self._status != RecoveryStatus.REQUIRED:
            raise RecoveryError(
                "recovery must be required before start"
            )

        self._status = RecoveryStatus.RUNNING

        return self.state()

    def complete_action(self) -> RecoveryState:
        if self._status != RecoveryStatus.RUNNING:
            raise RecoveryError(
                "recovery is not running"
            )

        if self._actions_completed >= self._total_actions:
            raise RecoveryError(
                "all recovery actions are already complete"
            )

        self._actions_completed += 1

        return self.state()

    def succeed(self) -> RecoveryState:
        if self._status != RecoveryStatus.RUNNING:
            raise RecoveryError(
                "recovery is not running"
            )

        if self._actions_completed != self._total_actions:
            raise RecoveryError(
                "recovery cannot succeed before all actions complete"
            )

        self._status = RecoveryStatus.SUCCESS

        return self.state()

    def fail(self, reason: str = "") -> RecoveryState:
        if self._status != RecoveryStatus.RUNNING:
            raise RecoveryError(
                "recovery is not running"
            )

        if reason:
            self._reason = reason

        self._status = RecoveryStatus.FAILED

        return self.state()

    def reset(self) -> RecoveryState:
        self._status = RecoveryStatus.IDLE
        self._reason = ""
        self._actions_completed = 0
        self._total_actions = 0

        return self.state()
