from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ProjectExistenceResult:
    exists: bool
    path: Path | None
    reason: str


class ProjectExistenceValidator:
    """
    Checks whether a project path exists.

    Read-only filesystem operation.
    No project code or shell command is executed.
    """

    def validate(
        self,
        value: Any,
    ) -> ProjectExistenceResult:

        if value is None:
            return ProjectExistenceResult(
                exists=False,
                path=None,
                reason="PATH_IS_NONE",
            )

        if not isinstance(value, (str, Path)):
            return ProjectExistenceResult(
                exists=False,
                path=None,
                reason="UNSUPPORTED_PATH_TYPE",
            )

        if isinstance(value, str):
            value = value.strip()

            if not value:
                return ProjectExistenceResult(
                    exists=False,
                    path=None,
                    reason="PATH_IS_EMPTY",
                )

        path = Path(value).expanduser()

        if "\x00" in str(path):
            return ProjectExistenceResult(
                exists=False,
                path=None,
                reason="NULL_CHARACTER_NOT_ALLOWED",
            )

        try:
            exists = path.exists()

        except PermissionError:
            return ProjectExistenceResult(
                exists=False,
                path=path,
                reason="FILESYSTEM_PERMISSION_DENIED",
            )

        except OSError:
            return ProjectExistenceResult(
                exists=False,
                path=path,
                reason="FILESYSTEM_OS_ERROR",
            )

        return ProjectExistenceResult(
            exists=exists,
            path=path,
            reason=(
                "PROJECT_EXISTS"
                if exists
                else "PROJECT_NOT_FOUND"
            ),
        )


def validate_project_existence(
    value: Any,
) -> ProjectExistenceResult:
    return ProjectExistenceValidator().validate(value)
