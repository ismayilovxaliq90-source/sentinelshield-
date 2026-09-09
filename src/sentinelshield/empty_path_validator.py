from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class EmptyPathValidationResult:
    valid: bool
    reason: str


class EmptyPathValidator:
    """
    Validates whether a project path contains a usable value.

    This validator does not access or modify the filesystem.
    """

    def validate(self, value: Any) -> EmptyPathValidationResult:
        if value is None:
            return EmptyPathValidationResult(
                valid=False,
                reason="PATH_IS_NONE",
            )

        if isinstance(value, str):
            if not value.strip():
                return EmptyPathValidationResult(
                    valid=False,
                    reason="PATH_IS_EMPTY",
                )

            return EmptyPathValidationResult(
                valid=True,
                reason="PATH_IS_NOT_EMPTY",
            )

        if isinstance(value, Path):
            if not str(value).strip():
                return EmptyPathValidationResult(
                    valid=False,
                    reason="PATH_IS_EMPTY",
                )

            return EmptyPathValidationResult(
                valid=True,
                reason="PATH_IS_NOT_EMPTY",
            )

        return EmptyPathValidationResult(
            valid=False,
            reason="UNSUPPORTED_PATH_TYPE",
        )


def validate_empty_path(value: Any) -> EmptyPathValidationResult:
    return EmptyPathValidator().validate(value)
