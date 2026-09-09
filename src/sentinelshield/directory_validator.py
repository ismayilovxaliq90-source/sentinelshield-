from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class DirectoryValidationResult:
    valid: bool
    path: Path | None
    reason: str


class DirectoryValidator:
    """
    Validates that a project path exists and is a directory.

    Read-only filesystem operation.
    Does not execute project code or modify the filesystem.
    """

    def validate(
        self,
        value: Any,
    ) -> DirectoryValidationResult:

        if value is None:
            return DirectoryValidationResult(
                valid=False,
                path=None,
                reason="PATH_IS_NONE",
            )

        if not isinstance(value, (str, Path)):
            return DirectoryValidationResult(
                valid=False,
                path=None,
                reason="UNSUPPORTED_PATH_TYPE",
            )

        if isinstance(value, str):
            value = value.strip()

            if not value:
                return DirectoryValidationResult(
                    valid=False,
                    path=None,
                    reason="PATH_IS_EMPTY",
                )

        path = Path(value).expanduser()

        if "\x00" in str(path):
            return DirectoryValidationResult(
                valid=False,
                path=None,
                reason="NULL_CHARACTER_NOT_ALLOWED",
            )

        try:
            if not path.exists():
                return DirectoryValidationResult(
                    valid=False,
                    path=path,
                    reason="PATH_NOT_FOUND",
                )

            if not path.is_dir():
                return DirectoryValidationResult(
                    valid=False,
                    path=path,
                    reason="PATH_IS_NOT_DIRECTORY",
                )

        except PermissionError:
            return DirectoryValidationResult(
                valid=False,
                path=path,
                reason="FILESYSTEM_PERMISSION_DENIED",
            )

        except OSError:
            return DirectoryValidationResult(
                valid=False,
                path=path,
                reason="FILESYSTEM_OS_ERROR",
            )

        return DirectoryValidationResult(
            valid=True,
            path=path,
            reason="DIRECTORY_VALID",
        )


def validate_directory(
    value: Any,
) -> DirectoryValidationResult:
    return DirectoryValidator().validate(value)
