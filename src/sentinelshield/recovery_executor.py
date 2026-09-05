from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from sentinelshield.recovery_safety_gate import (
    RecoveryDecision,
    RecoveryGateResult,
)


class RecoveryOperation(str, Enum):
    VERIFY_PATH = "VERIFY_PATH"
    RECREATE_DIRECTORY = "RECREATE_DIRECTORY"


@dataclass(frozen=True)
class RecoveryExecutionResult:
    project: str
    operation: RecoveryOperation
    executed: bool
    success: bool
    reason: str


class RecoveryExecutor:
    """
    Executes only explicitly approved recovery operations.

    No shell commands are accepted or executed.
    """

    def execute(
        self,
        gate_result: RecoveryGateResult,
        *,
        operation: RecoveryOperation,
        path: str | Path,
    ) -> RecoveryExecutionResult:

        if not isinstance(gate_result, RecoveryGateResult):
            raise TypeError("gate_result must be RecoveryGateResult")

        if not gate_result.allowed:
            return RecoveryExecutionResult(
                project=gate_result.project,
                operation=operation,
                executed=False,
                success=False,
                reason="RECOVERY_NOT_AUTHORIZED",
            )

        if gate_result.decision != RecoveryDecision.EXECUTE:
            return RecoveryExecutionResult(
                project=gate_result.project,
                operation=operation,
                executed=False,
                success=False,
                reason="INVALID_RECOVERY_DECISION",
            )

        if not isinstance(operation, RecoveryOperation):
            raise TypeError(
                "operation must be RecoveryOperation"
            )

        if not isinstance(path, (str, Path)):
            raise TypeError("path must be str or Path")

        target = Path(path).expanduser()

        if operation == RecoveryOperation.VERIFY_PATH:
            success = target.exists() and target.is_dir()

            return RecoveryExecutionResult(
                project=gate_result.project,
                operation=operation,
                executed=True,
                success=success,
                reason=(
                    "PATH_VERIFIED"
                    if success
                    else "PATH_NOT_AVAILABLE"
                ),
            )

        if operation == RecoveryOperation.RECREATE_DIRECTORY:
            if target.exists():
                if target.is_dir():
                    return RecoveryExecutionResult(
                        project=gate_result.project,
                        operation=operation,
                        executed=True,
                        success=True,
                        reason="DIRECTORY_ALREADY_EXISTS",
                    )

                return RecoveryExecutionResult(
                    project=gate_result.project,
                    operation=operation,
                    executed=False,
                    success=False,
                    reason="TARGET_IS_NOT_DIRECTORY",
                )

            target.mkdir(parents=True, exist_ok=False)

            return RecoveryExecutionResult(
                project=gate_result.project,
                operation=operation,
                executed=True,
                success=True,
                reason="DIRECTORY_RECREATED",
            )

        return RecoveryExecutionResult(
            project=gate_result.project,
            operation=operation,
            executed=False,
            success=False,
            reason="UNSUPPORTED_OPERATION",
        )
