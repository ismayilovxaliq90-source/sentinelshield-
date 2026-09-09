from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class PathTypeValidationResult:
    valid: bool
    value_type: str
    reason: str


SUPPORTED_PATH_TYPES = (str, Path)


class ProjectPathTypeValidator:
    """
    Validates the Python type of a project path.

    This validator is deliberately filesystem-independent.
    It does not resolve, access, execute, or modify anything.
    """

    def validate(self, value: Any) -> PathTypeValidationResult:
        if value is None:
            return PathTypeValidationResult(
                valid=False,
                value_type="NoneType",
                reason="PATH_TYPE_IS_NONE",
            )

        if isinstance(value, Path):
            return PathTypeValidationResult(
                valid=True,
                value_type="Path",
                reason="SUPPORTED_PATH_TYPE",
            )

        if isinstance(value, str):
            return PathTypeValidationResult(
                valid=True,
                value_type="str",
                reason="SUPPORTED_PATH_TYPE",
            )

        return PathTypeValidationResult(
            valid=False,
            value_type=type(value).__name__,
            reason="UNSUPPORTED_PATH_TYPE",
        )


def validate_project_path_type(
    value: Any,
) -> PathTypeValidationResult:
    return ProjectPathTypeValidator().validate(value)
