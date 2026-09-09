from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class GitRepositoryDetectionResult:
    is_git_repository: bool
    repository_path: Path | None
    git_path: Path | None
    git_marker_type: str | None
    reason: str


class GitRepositoryDetector:
    """
    Detects whether a directory is a Git repository
    using filesystem markers only.

    No git command is executed.
    No project code is executed.
    """

    def detect(
        self,
        value: Any,
    ) -> GitRepositoryDetectionResult:

        if value is None:
            return GitRepositoryDetectionResult(
                is_git_repository=False,
                repository_path=None,
                git_path=None,
                git_marker_type=None,
                reason="PATH_IS_NONE",
            )

        if not isinstance(value, (str, Path)):
            return GitRepositoryDetectionResult(
                is_git_repository=False,
                repository_path=None,
                git_path=None,
                git_marker_type=None,
                reason="UNSUPPORTED_PATH_TYPE",
            )

        if isinstance(value, str):
            value = value.strip()

            if not value:
                return GitRepositoryDetectionResult(
                    is_git_repository=False,
                    repository_path=None,
                    git_path=None,
                    git_marker_type=None,
                    reason="PATH_IS_EMPTY",
                )

        raw_path = str(value)

        if "\x00" in raw_path:
            return GitRepositoryDetectionResult(
                is_git_repository=False,
                repository_path=None,
                git_path=None,
                git_marker_type=None,
                reason="NULL_CHARACTER_NOT_ALLOWED",
            )

        try:
            path = (
                Path(value)
                .expanduser()
                .resolve(strict=False)
            )
        except (OSError, RuntimeError, ValueError) as exc:
            return GitRepositoryDetectionResult(
                is_git_repository=False,
                repository_path=None,
                git_path=None,
                git_marker_type=None,
                reason=(
                    "PATH_RESOLUTION_FAILED:"
                    f"{type(exc).__name__}"
                ),
            )

        if path.exists() and not path.is_dir():
            path = path.parent

        git_path = path / ".git"

        try:
            if git_path.is_dir():
                return GitRepositoryDetectionResult(
                    is_git_repository=True,
                    repository_path=path,
                    git_path=git_path,
                    git_marker_type="DIRECTORY",
                    reason="GIT_DIRECTORY_FOUND",
                )

            if git_path.is_file():
                return GitRepositoryDetectionResult(
                    is_git_repository=True,
                    repository_path=path,
                    git_path=git_path,
                    git_marker_type="FILE",
                    reason="GIT_FILE_FOUND",
                )

        except OSError as exc:
            return GitRepositoryDetectionResult(
                is_git_repository=False,
                repository_path=path,
                git_path=git_path,
                git_marker_type=None,
                reason=(
                    "GIT_MARKER_CHECK_FAILED:"
                    f"{type(exc).__name__}"
                ),
            )

        return GitRepositoryDetectionResult(
            is_git_repository=False,
            repository_path=path,
            git_path=None,
            git_marker_type=None,
            reason="GIT_REPOSITORY_NOT_FOUND",
        )


def detect_git_repository(
    value: Any,
) -> GitRepositoryDetectionResult:
    return GitRepositoryDetector().detect(value)
