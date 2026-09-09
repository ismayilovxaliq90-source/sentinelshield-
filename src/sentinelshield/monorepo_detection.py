from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


MANIFEST_MARKERS = (
    "pyproject.toml",
    "package.json",
    "pom.xml",
    "build.gradle",
    "settings.gradle",
    "go.mod",
    "Cargo.toml",
    "composer.json",
    "Gemfile",
    "Pipfile",
)

WORKSPACE_MARKERS = (
    "pnpm-workspace.yaml",
    "lerna.json",
    "nx.json",
    "rush.json",
)

IGNORED_DIRECTORIES = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".tox",
    "dist",
    "build",
    "target",
}


@dataclass(frozen=True)
class MonorepoDetectionResult:
    is_monorepo: bool
    repository_path: Path | None
    project_roots: tuple[Path, ...]
    workspace_markers: tuple[str, ...]
    reason: str


class MonorepoDetector:
    """
    Detects likely monorepo structures using filesystem metadata only.

    No package manager, build tool, Git command, or project code is executed.
    """

    def detect(
        self,
        value: Any,
    ) -> MonorepoDetectionResult:

        if value is None:
            return MonorepoDetectionResult(
                is_monorepo=False,
                repository_path=None,
                project_roots=(),
                workspace_markers=(),
                reason="PATH_IS_NONE",
            )

        if not isinstance(value, (str, Path)):
            return MonorepoDetectionResult(
                is_monorepo=False,
                repository_path=None,
                project_roots=(),
                workspace_markers=(),
                reason="UNSUPPORTED_PATH_TYPE",
            )

        if isinstance(value, str):
            value = value.strip()

            if not value:
                return MonorepoDetectionResult(
                    is_monorepo=False,
                    repository_path=None,
                    project_roots=(),
                    workspace_markers=(),
                    reason="PATH_IS_EMPTY",
                )

        raw_path = str(value)

        if "\x00" in raw_path:
            return MonorepoDetectionResult(
                is_monorepo=False,
                repository_path=None,
                project_roots=(),
                workspace_markers=(),
                reason="NULL_CHARACTER_NOT_ALLOWED",
            )

        try:
            root = (
                Path(value)
                .expanduser()
                .resolve(strict=False)
            )
        except (OSError, RuntimeError, ValueError) as exc:
            return MonorepoDetectionResult(
                is_monorepo=False,
                repository_path=None,
                project_roots=(),
                workspace_markers=(),
                reason=(
                    "PATH_RESOLUTION_FAILED:"
                    f"{type(exc).__name__}"
                ),
            )

        if root.exists() and not root.is_dir():
            root = root.parent

        if not root.exists():
            return MonorepoDetectionResult(
                is_monorepo=False,
                repository_path=root,
                project_roots=(),
                workspace_markers=(),
                reason="DIRECTORY_NOT_FOUND",
            )

        if not root.is_dir():
            return MonorepoDetectionResult(
                is_monorepo=False,
                repository_path=root,
                project_roots=(),
                workspace_markers=(),
                reason="PATH_IS_NOT_DIRECTORY",
            )

        workspace_markers = self._workspace_markers(root)
        project_roots = self._discover_projects(root)

        is_monorepo = (
            len(project_roots) >= 2
            or bool(workspace_markers)
        )

        if is_monorepo:
            reason = "MONOREPO_DETECTED"
        else:
            reason = "MONOREPO_NOT_DETECTED"

        return MonorepoDetectionResult(
            is_monorepo=is_monorepo,
            repository_path=root,
            project_roots=project_roots,
            workspace_markers=workspace_markers,
            reason=reason,
        )

    def _workspace_markers(
        self,
        root: Path,
    ) -> tuple[str, ...]:

        found: list[str] = []

        for marker in WORKSPACE_MARKERS:
            if (root / marker).is_file():
                found.append(marker)

        return tuple(found)

    def _discover_projects(
        self,
        root: Path,
    ) -> tuple[Path, ...]:

        projects: set[Path] = set()

        # Root itself can be a project.
        if self._has_manifest(root):
            projects.add(root)

        try:
            children = sorted(
                root.iterdir(),
                key=lambda path: path.name,
            )
        except OSError:
            return tuple(sorted(projects))

        for child in children:
            if not child.is_dir():
                continue

            if child.name in IGNORED_DIRECTORIES:
                continue

            if child.is_symlink():
                continue

            if self._has_manifest(child):
                projects.add(child)

            # One additional level supports common layouts:
            # packages/a, packages/b
            try:
                grandchildren = sorted(
                    child.iterdir(),
                    key=lambda path: path.name,
                )
            except OSError:
                continue

            for grandchild in grandchildren:
                if not grandchild.is_dir():
                    continue

                if grandchild.name in IGNORED_DIRECTORIES:
                    continue

                if grandchild.is_symlink():
                    continue

                if self._has_manifest(grandchild):
                    projects.add(grandchild)

        return tuple(
            sorted(
                projects,
                key=lambda path: str(path),
            )
        )

    def _has_manifest(
        self,
        directory: Path,
    ) -> bool:

        for marker in MANIFEST_MARKERS:
            try:
                if (directory / marker).is_file():
                    return True
            except OSError:
                continue

        try:
            for path in directory.iterdir():
                if (
                    path.is_file()
                    and path.suffix.lower()
                    in {".sln", ".csproj", ".fsproj", ".vbproj"}
                ):
                    return True
        except OSError:
            return False

        return False


def detect_monorepo(
    value: Any,
) -> MonorepoDetectionResult:
    return MonorepoDetector().detect(value)
