from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ProjectContext:
    project_path: Path
    project_identity: str
    exists: bool
    is_directory: bool


@dataclass(frozen=True)
class ProjectContextResult:
    valid: bool
    context: ProjectContext | None
    reason: str


class ProjectContextBuilder:
    """
    Creates an immutable project context from validated project data.

    This component only constructs data.
    It does not execute project code or modify the filesystem.
    """

    def create(
        self,
        project_path: Any,
        project_identity: Any,
        exists: Any = True,
        is_directory: Any = True,
    ) -> ProjectContextResult:

        if project_path is None:
            return ProjectContextResult(
                valid=False,
                context=None,
                reason="PATH_IS_NONE",
            )

        if not isinstance(project_path, (str, Path)):
            return ProjectContextResult(
                valid=False,
                context=None,
                reason="UNSUPPORTED_PATH_TYPE",
            )

        if isinstance(project_path, str):
            project_path = project_path.strip()

            if not project_path:
                return ProjectContextResult(
                    valid=False,
                    context=None,
                    reason="PATH_IS_EMPTY",
                )

        project_path = Path(project_path).expanduser()

        if "\x00" in str(project_path):
            return ProjectContextResult(
                valid=False,
                context=None,
                reason="NULL_CHARACTER_NOT_ALLOWED",
            )

        if not isinstance(project_identity, str):
            return ProjectContextResult(
                valid=False,
                context=None,
                reason="IDENTITY_IS_INVALID",
            )

        project_identity = project_identity.strip()

        if not project_identity:
            return ProjectContextResult(
                valid=False,
                context=None,
                reason="IDENTITY_IS_EMPTY",
            )

        if not isinstance(exists, bool):
            return ProjectContextResult(
                valid=False,
                context=None,
                reason="EXISTS_FLAG_INVALID",
            )

        if not isinstance(is_directory, bool):
            return ProjectContextResult(
                valid=False,
                context=None,
                reason="DIRECTORY_FLAG_INVALID",
            )

        if exists and not is_directory:
            return ProjectContextResult(
                valid=False,
                context=None,
                reason="EXISTING_PROJECT_IS_NOT_DIRECTORY",
            )

        context = ProjectContext(
            project_path=project_path,
            project_identity=project_identity,
            exists=exists,
            is_directory=is_directory,
        )

        return ProjectContextResult(
            valid=True,
            context=context,
            reason="PROJECT_CONTEXT_CREATED",
        )


def create_project_context(
    project_path: Any,
    project_identity: Any,
    exists: Any = True,
    is_directory: Any = True,
) -> ProjectContextResult:
    return ProjectContextBuilder().create(
        project_path,
        project_identity,
        exists,
        is_directory,
    )
