from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


BUILD_GRADLE_FILENAMES = frozenset(
    {
        "build.gradle",
        "build.gradle.kts",
    }
)


@dataclass(frozen=True)
class BuildGradleDiscoveryResult:
    found: bool
    path: Path | None
    kind: str
    reason: str


class BuildGradleDiscoverer:
    """
    Read-only discovery of Gradle build files.

    This task only inspects filesystem entries.
    It never executes Gradle, evaluates build scripts,
    installs dependencies, or modifies the filesystem.
    """

    def discover(
        self,
        project_path: Any,
    ) -> BuildGradleDiscoveryResult:

        if project_path is None:
            return BuildGradleDiscoveryResult(
                found=False,
                path=None,
                kind="NONE",
                reason="PROJECT_PATH_IS_NONE",
            )

        if isinstance(project_path, Path):
            root = project_path
        elif isinstance(project_path, str):
            if not project_path.strip():
                return BuildGradleDiscoveryResult(
                    found=False,
                    path=None,
                    kind="NONE",
                    reason="PROJECT_PATH_IS_EMPTY",
                )
            root = Path(project_path.strip())
        else:
            return BuildGradleDiscoveryResult(
                found=False,
                path=None,
                kind="NONE",
                reason="UNSUPPORTED_PROJECT_PATH_TYPE",
            )

        try:
            if not root.exists():
                return BuildGradleDiscoveryResult(
                    found=False,
                    path=None,
                    kind="NONE",
                    reason="PROJECT_PATH_DOES_NOT_EXIST",
                )

            if not root.is_dir():
                return BuildGradleDiscoveryResult(
                    found=False,
                    path=None,
                    kind="NONE",
                    reason="PROJECT_PATH_IS_NOT_DIRECTORY",
                )

            candidates = []

            for filename in BUILD_GRADLE_FILENAMES:
                candidate = root / filename

                try:
                    if candidate.is_file():
                        candidates.append(candidate)
                except (OSError, PermissionError):
                    continue

            if not candidates:
                return BuildGradleDiscoveryResult(
                    found=False,
                    path=None,
                    kind="NONE",
                    reason="BUILD_GRADLE_NOT_FOUND",
                )

            # Deterministic selection:
            # prefer the conventional Groovy build.gradle.
            candidates.sort(
                key=lambda item: (
                    0 if item.name == "build.gradle" else 1,
                    item.name,
                )
            )

            selected = candidates[0]

            if selected.name == "build.gradle":
                kind = "BUILD_GRADLE"
            else:
                kind = "BUILD_GRADLE_KTS"

            return BuildGradleDiscoveryResult(
                found=True,
                path=selected,
                kind=kind,
                reason="BUILD_GRADLE_FOUND",
            )

        except PermissionError:
            return BuildGradleDiscoveryResult(
                found=False,
                path=None,
                kind="NONE",
                reason="PROJECT_PATH_PERMISSION_DENIED",
            )
        except OSError:
            return BuildGradleDiscoveryResult(
                found=False,
                path=None,
                kind="NONE",
                reason="PROJECT_PATH_OS_ERROR",
            )


def discover_build_gradle(
    project_path: Any,
) -> BuildGradleDiscoveryResult:
    return BuildGradleDiscoverer().discover(project_path)
