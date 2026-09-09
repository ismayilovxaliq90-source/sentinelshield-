from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class NullCharacterValidationResult:
    valid: bool
    reason: str


class NullCharacterProtector:
    """
    Rejects project paths containing NULL characters.

    This validation is filesystem-independent.
    """

    def validate(
        self,
        value: Any,
    ) -> NullCharacterValidationResult:

        if value is None:
            return NullCharacterValidationResult(
                valid=False,
                reason="PATH_IS_NONE",
            )

        if isinstance(value, Path):
            value = str(value)

        if not isinstance(value, str):
            return NullCharacterValidationResult(
                valid=False,
                reason="UNSUPPORTED_PATH_TYPE",
            )

        if "\x00" in value:
            return NullCharacterValidationResult(
                valid=False,
                reason="NULL_CHARACTER_NOT_ALLOWED",
            )

        return NullCharacterValidationResult(
            valid=True,
            reason="NO_NULL_CHARACTER",
        )


def validate_null_character(
    value: Any,
) -> NullCharacterValidationResult:
    return NullCharacterProtector().validate(value)
