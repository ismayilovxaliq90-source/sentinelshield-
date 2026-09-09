from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sentinelshield.project_context import ProjectContext


@dataclass(frozen=True)
class ProjectContextValidationResult:
    valid: bool
    reason: str


class ProjectContextValidator:
    """
    Validates a previously-created ProjectContext.

    Validation is data-only and read-only.
    """

    def validate(
        self,
        context: Any,
    ) -> ProjectContextValidationResult:

        if context is None:
            return ProjectContextValidationResult(
                valid=False,
                reason="CONTEXT_IS_NONE",
            )

        if not isinstance(context, ProjectContext):
            return ProjectContextValidationResult(
                valid=False,
                reason="INVALID_CONTEXT_TYPE",
            )

        if not isinstance(
            context.project_path,
            Path,
        ):
            return ProjectContextValidationResult(
                valid=False,
                reason="INVALID_PROJECT_PATH",
            )

        path_string = str(context.project_path)

        if not path_string.strip():
            return ProjectContextValidationResult(
                valid=False,
                reason="PROJECT_PATH_IS_EMPTY",
            )

        if "\x00" in path_string:
            return ProjectContextValidationResult(
                valid=False,
                reason="NULL_CHARACTER_NOT_ALLOWED",
            )

        if not isinstance(
            context.project_identity,
            str,
        ):
            return ProjectContextValidationResult(
                valid=False,
                reason="INVALID_PROJECT_IDENTITY",
            )

        if not context.project_identity.strip():
            return ProjectContextValidationResult(
                valid=False,
                reason="PROJECT_IDENTITY_IS_EMPTY",
            )

        if not isinstance(context.exists, bool):
            return ProjectContextValidationResult(
                valid=False,
                reason="INVALID_EXISTS_FLAG",
            )

        if not isinstance(
            context.is_directory,
            bool,
        ):
            return ProjectContextValidationResult(
                valid=False,
                reason="INVALID_DIRECTORY_FLAG",
            )

        if context.exists and not context.is_directory:
            return ProjectContextValidationResult(
                valid=False,
                reason="EXISTING_PROJECT_IS_NOT_DIRECTORY",
            )

        return ProjectContextValidationResult(
            valid=True,
            reason="PROJECT_CONTEXT_VALID",
        )


def validate_project_context(
    context: Any,
) -> ProjectContextValidationResult:
    return ProjectContextValidator().validate(context)
