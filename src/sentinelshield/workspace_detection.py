from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


WORKSPACE_MARKERS = (
    "pnpm-workspace.yaml",
    "lerna.json",
    "nx.json",
    "rush.json",
)

PACKAGE_JSON = "package.json"


@dataclass(frozen=True)
class WorkspaceDetectionResult:
    is_workspace: bool
    workspace_path: Path | None
    markers: tuple[str, ...]
    package_projects: tuple[Path, ...]
    reason: str


class WorkspaceDetector:
    """
    Detects workspace configuration using filesystem metadata only.

    No package manager or project code is executed.
    """

    def detect(
        self,
        value: Any,
    ) -> WorkspaceDetectionResult:

        if value is None:
            return WorkspaceDetectionResult(
                is_workspace=False,
                workspace_path=None,
                markers=(),
                package_projects=(),
                reason="PATH_IS_NONE",
            )

        if not isinstance(value, (str, Path)):
            return WorkspaceDetectionResult(
                is_workspace=False,
                workspace_path=None,
                markers=(),
                package_projects=(),
                reason="UNSUPPORTED_PATH_TYPE",
            )

        if isinstance(value, str):
            value = value.strip()

            if not value:
                return WorkspaceDetectionResult(
                    is_workspace=False,
                    workspace_path=None,
                    markers=(),
                    package_projects=(),
                    reason="PATH_IS_EMPTY",
                )

        raw_path = str(value)

        if "\x00" in raw_path:
            return WorkspaceDetectionResult(
                is_workspace=False,
                workspace_path=None,
                markers=(),
                package_projects=(),
                reason="NULL_CHARACTER_NOT_ALLOWED",
            )

        try:
            root = (
                Path(value)
                .expanduser()
                .resolve(strict=False)
            )
        except (OSError, RuntimeError, ValueError) as exc:
            return WorkspaceDetectionResult(
                is_workspace=False,
                workspace_path=None,
                markers=(),
                package_projects=(),
                reason=(
                    "PATH_RESOLUTION_FAILED:"
                    f"{type(exc).__name__}"
                ),
            )

        if root.exists() and not root.is_dir():
            root = root.parent

        if not root.exists():
            return WorkspaceDetectionResult(
                is_workspace=False,
                workspace_path=root,
                markers=(),
                package_projects=(),
                reason="DIRECTORY_NOT_FOUND",
            )

        if not root.is_dir():
            return WorkspaceDetectionResult(
                is_workspace=False,
                workspace_path=root,
                markers=(),
                package_projects=(),
                reason="PATH_IS_NOT_DIRECTORY",
            )

        markers = self._find_markers(root)
        package_projects = self._find_package_projects(root)

        is_workspace = bool(markers)

        if is_workspace:
            reason = "WORKSPACE_MARKER_FOUND"
        elif len(package_projects) >= 2:
            reason = "MULTIPLE_PACKAGE_PROJECTS_FOUND"
            is_workspace = True
        else:
            reason = "WORKSPACE_NOT_DETECTED"

        return WorkspaceDetectionResult(
            is_workspace=is_workspace,
            workspace_path=root,
            markers=markers,
            package_projects=package_projects,
            reason=reason,
        )

    def _find_markers(
        self,
        root: Path,
    ) -> tuple[str, ...]:

        found: list[str] = []

        for marker in WORKSPACE_MARKERS:
            try:
                if (root / marker).is_file():
                    found.append(marker)
            except OSError:
                continue

        return tuple(found)

    def _find_package_projects(
        self,
        root: Path,
    ) -> tuple[Path, ...]:

        projects: set[Path] = set()

        try:
            children = sorted(
                root.iterdir(),
                key=lambda path: path.name,
            )
        except OSError:
            return ()

        for child in children:
            if not child.is_dir():
                continue

            if child.name in {
                ".git",
                "node_modules",
                ".venv",
                "venv",
                "__pycache__",
                "dist",
                "build",
                "target",
            }:
                continue

            if child.is_symlink():
                continue

            try:
                if (child / PACKAGE_JSON).is_file():
                    projects.add(child)
            except OSError:
                continue

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

                if grandchild.name in {
                    ".git",
                    "node_modules",
                    ".venv",
                    "venv",
                    "__pycache__",
                    "dist",
                    "build",
                    "target",
                }:
                    continue

                if grandchild.is_symlink():
                    continue

                try:
                    if (grandchild / PACKAGE_JSON).is_file():
                        projects.add(grandchild)
                except OSError:
                    continue

        return tuple(
            sorted(
                projects,
                key=lambda path: str(path),
            )
        )


def detect_workspace(
    value: Any,
) -> WorkspaceDetectionResult:
    return WorkspaceDetector().detect(value)
