from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


EXCLUDED_DIRECTORIES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".tox",
        "dist",
        "build",
        "target",
    }
)


@dataclass(frozen=True)
class ProjectBoundaryResult:
    valid: bool
    project_root: Path | None
    boundary_root: Path | None
    excluded_paths: tuple[Path, ...]
    reason: str


class ProjectBoundaryDetector:
    """
    Determines the filesystem boundary of a project.

    Read-only:
    - does not execute project code
    - does not invoke package managers
    - does not modify the filesystem
    """

    def detect(
        self,
        value: Any,
    ) -> ProjectBoundaryResult:

        if value is None:
            return ProjectBoundaryResult(
                valid=False,
                project_root=None,
                boundary_root=None,
                excluded_paths=(),
                reason="PATH_IS_NONE",
            )

        if not isinstance(value, (str, Path)):
            return ProjectBoundaryResult(
                valid=False,
                project_root=None,
                boundary_root=None,
                excluded_paths=(),
                reason="UNSUPPORTED_PATH_TYPE",
            )

        if isinstance(value, str):
            value = value.strip()

            if not value:
                return ProjectBoundaryResult(
                    valid=False,
                    project_root=None,
                    boundary_root=None,
                    excluded_paths=(),
                    reason="PATH_IS_EMPTY",
                )

        raw_value = str(value)

        if "\x00" in raw_value:
            return ProjectBoundaryResult(
                valid=False,
                project_root=None,
                boundary_root=None,
                excluded_paths=(),
                reason="NULL_CHARACTER_NOT_ALLOWED",
            )

        try:
            path = (
                Path(value)
                .expanduser()
                .resolve(strict=False)
            )
        except (OSError, RuntimeError, ValueError) as exc:
            return ProjectBoundaryResult(
                valid=False,
                project_root=None,
                boundary_root=None,
                excluded_paths=(),
                reason=(
                    "PATH_RESOLUTION_FAILED:"
                    f"{type(exc).__name__}"
                ),
            )

        if path.exists() and not path.is_dir():
            path = path.parent

        if not path.exists():
            return ProjectBoundaryResult(
                valid=False,
                project_root=path,
                boundary_root=None,
                excluded_paths=(),
                reason="DIRECTORY_NOT_FOUND",
            )

        if not path.is_dir():
            return ProjectBoundaryResult(
                valid=False,
                project_root=path,
                boundary_root=None,
                excluded_paths=(),
                reason="PATH_IS_NOT_DIRECTORY",
            )

        excluded = self._discover_excluded_paths(path)

        return ProjectBoundaryResult(
            valid=True,
            project_root=path,
            boundary_root=path,
            excluded_paths=excluded,
            reason="PROJECT_BOUNDARY_VALID",
        )

    def _discover_excluded_paths(
        self,
        root: Path,
    ) -> tuple[Path, ...]:

        found: list[Path] = []

        try:
            entries = sorted(
                root.iterdir(),
                key=lambda item: item.name,
            )
        except OSError:
            return ()

        for entry in entries:
            if entry.name not in EXCLUDED_DIRECTORIES:
                continue

            try:
                if entry.is_dir():
                    found.append(entry)
            except OSError:
                continue

        return tuple(found)


def detect_project_boundary(
    value: Any,
) -> ProjectBoundaryResult:
    return ProjectBoundaryDetector().detect(value)
