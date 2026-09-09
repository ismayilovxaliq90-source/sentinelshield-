from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class PathValidationResult:
    valid: bool
    original: Any
    normalized: str | None
    reason: str


class ProjectPathValidator:
    """
    Validates project path input only.

    This class does not:
      - access project files
      - execute project code
      - execute shell commands
      - install packages
      - modify the filesystem
    """

    def validate(
        self,
        project_path: Any,
    ) -> PathValidationResult:

        if project_path is None:
            return PathValidationResult(
                valid=False,
                original=project_path,
                normalized=None,
                reason="PATH_IS_NONE",
            )

        if isinstance(project_path, str):
            value = project_path.strip()

            if not value:
                return PathValidationResult(
                    valid=False,
                    original=project_path,
                    normalized=None,
                    reason="PATH_IS_EMPTY",
                )

            if "\x00" in value:
                return PathValidationResult(
                    valid=False,
                    original=project_path,
                    normalized=None,
                    reason="NULL_CHARACTER_NOT_ALLOWED",
                )

            try:
                Path(value)
            except (TypeError, ValueError, OSError) as exc:
                return PathValidationResult(
                    valid=False,
                    original=project_path,
                    normalized=None,
                    reason=f"INVALID_PATH:{type(exc).__name__}",
                )

            return PathValidationResult(
                valid=True,
                original=project_path,
                normalized=value,
                reason="VALID",
            )

        if isinstance(project_path, Path):
            value = str(project_path)

            if "\x00" in value:
                return PathValidationResult(
                    valid=False,
                    original=project_path,
                    normalized=None,
                    reason="NULL_CHARACTER_NOT_ALLOWED",
                )

            return PathValidationResult(
                valid=True,
                original=project_path,
                normalized=value,
                reason="VALID",
            )

        return PathValidationResult(
            valid=False,
            original=project_path,
            normalized=None,
            reason="UNSUPPORTED_PATH_TYPE",
        )


def validate_project_path(
    project_path: Any,
) -> PathValidationResult:
    return ProjectPathValidator().validate(project_path)
