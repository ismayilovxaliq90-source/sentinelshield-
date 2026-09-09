from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, TypeVar


T = TypeVar("T")


@dataclass(frozen=True)
class FilesystemOperationResult:
    success: bool
    value: T | None
    error_type: str | None
    reason: str


class FilesystemErrorHandler:
    """
    Safely wraps filesystem operations.

    The handler does not execute arbitrary project code.
    The supplied operation is expected to be a filesystem-only
    callable controlled by SentinelShield.
    """

    def execute(
        self,
        operation: Callable[[], T],
    ) -> FilesystemOperationResult[T]:

        try:
            value = operation()

        except PermissionError:
            return FilesystemOperationResult(
                success=False,
                value=None,
                error_type="PermissionError",
                reason="FILESYSTEM_PERMISSION_DENIED",
            )

        except OSError as exc:
            return FilesystemOperationResult(
                success=False,
                value=None,
                error_type=type(exc).__name__,
                reason="FILESYSTEM_OS_ERROR",
            )

        except RuntimeError as exc:
            return FilesystemOperationResult(
                success=False,
                value=None,
                error_type=type(exc).__name__,
                reason="FILESYSTEM_RUNTIME_ERROR",
            )

        return FilesystemOperationResult(
            success=True,
            value=value,
            error_type=None,
            reason="FILESYSTEM_OPERATION_SUCCESS",
        )


def safe_exists(path: str | Path) -> FilesystemOperationResult[bool]:
    handler = FilesystemErrorHandler()

    return handler.execute(
        lambda: Path(path).exists()
    )


def safe_is_dir(path: str | Path) -> FilesystemOperationResult[bool]:
    handler = FilesystemErrorHandler()

    return handler.execute(
        lambda: Path(path).is_dir()
    )


def safe_is_file(path: str | Path) -> FilesystemOperationResult[bool]:
    handler = FilesystemErrorHandler()

    return handler.execute(
        lambda: Path(path).is_file()
    )
