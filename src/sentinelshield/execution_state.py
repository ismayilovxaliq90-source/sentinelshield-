from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from time import monotonic


class ExecutionStateError(RuntimeError):
    """Raised when an execution state transition is invalid."""


class ExecutionStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    STOPPED = "STOPPED"


FINAL_STATES = frozenset(
    {
        ExecutionStatus.SUCCESS,
        ExecutionStatus.FAILED,
        ExecutionStatus.TIMED_OUT,
        ExecutionStatus.STOPPED,
    }
)


@dataclass(frozen=True)
class ExecutionStateSnapshot:
    execution_id: str
    status: ExecutionStatus
    created_at: float
    updated_at: float
    return_code: int | None = None
    message: str = ""


class ExecutionStateTracker:
    """
    Tracks the lifecycle of one execution.

    The tracker does not execute commands.
    It only records deterministic execution state transitions.
    """

    def __init__(
        self,
        execution_id: str,
        *,
        clock=None,
    ) -> None:
        if not isinstance(execution_id, str):
            raise TypeError(
                "execution_id must be a string"
            )

        execution_id = execution_id.strip()

        if not execution_id:
            raise ValueError(
                "execution_id cannot be empty"
            )

        self.execution_id = execution_id
        self._clock = clock or monotonic

        timestamp = self._clock()

        self._state = ExecutionStateSnapshot(
            execution_id=self.execution_id,
            status=ExecutionStatus.PENDING,
            created_at=timestamp,
            updated_at=timestamp,
        )

    @property
    def status(self) -> ExecutionStatus:
        return self._state.status

    def snapshot(self) -> ExecutionStateSnapshot:
        return self._state

    def start(
        self,
        message: str = "",
    ) -> ExecutionStateSnapshot:
        self._transition(
            ExecutionStatus.RUNNING,
            message=message,
        )

        return self._state

    def succeed(
        self,
        return_code: int = 0,
        message: str = "",
    ) -> ExecutionStateSnapshot:
        if return_code != 0:
            raise ValueError(
                "successful execution must have return_code 0"
            )

        self._transition(
            ExecutionStatus.SUCCESS,
            return_code=return_code,
            message=message,
        )

        return self._state

    def fail(
        self,
        return_code: int | None = None,
        message: str = "",
    ) -> ExecutionStateSnapshot:
        self._transition(
            ExecutionStatus.FAILED,
            return_code=return_code,
            message=message,
        )

        return self._state

    def timeout(
        self,
        message: str = "",
    ) -> ExecutionStateSnapshot:
        self._transition(
            ExecutionStatus.TIMED_OUT,
            message=message,
        )

        return self._state

    def stop(
        self,
        message: str = "",
    ) -> ExecutionStateSnapshot:
        self._transition(
            ExecutionStatus.STOPPED,
            message=message,
        )

        return self._state

    def is_final(self) -> bool:
        return self._state.status in FINAL_STATES

    def _transition(
        self,
        new_status: ExecutionStatus,
        *,
        return_code: int | None = None,
        message: str = "",
    ) -> None:
        current = self._state.status

        if current == ExecutionStatus.PENDING:
            allowed = {
                ExecutionStatus.RUNNING,
                ExecutionStatus.FAILED,
                ExecutionStatus.STOPPED,
            }
        elif current == ExecutionStatus.RUNNING:
            allowed = {
                ExecutionStatus.SUCCESS,
                ExecutionStatus.FAILED,
                ExecutionStatus.TIMED_OUT,
                ExecutionStatus.STOPPED,
            }
        else:
            allowed = set()

        if new_status not in allowed:
            raise ExecutionStateError(
                f"invalid state transition: "
                f"{current.value} -> {new_status.value}"
            )

        timestamp = self._clock()

        self._state = ExecutionStateSnapshot(
            execution_id=self.execution_id,
            status=new_status,
            created_at=self._state.created_at,
            updated_at=timestamp,
            return_code=return_code,
            message=message,
        )
