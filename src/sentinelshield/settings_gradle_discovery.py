from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


SETTINGS_GRADLE_FILENAMES = frozenset(
    {
        "settings.gradle",
        "settings.gradle.kts",
    }
)


@dataclass(frozen=True)
class SettingsGradleDiscoveryResult:
    found: bool
    path: Path | None
    kind: str
    reason: str


class SettingsGradleDiscoverer:
    """
    Read-only discovery of Gradle settings files.

    This task only inspects filesystem entries.
    It never executes Gradle or evaluates the settings script.
    It never installs dependencies and never modifies the filesystem.
    """

    def discover(
        self,
        project_path: Any,
    ) -> SettingsGradleDiscoveryResult:

        if project_path is None:
            return SettingsGradleDiscoveryResult(
                found=False,
                path=None,
                kind="NONE",
                reason="PROJECT_PATH_IS_NONE",
            )

        if isinstance(project_path, Path):
            root = project_path
        elif isinstance(project_path, str):
            normalized = project_path.strip()

            if not normalized:
                return SettingsGradleDiscoveryResult(
                    found=False,
                    path=None,
                    kind="NONE",
                    reason="PROJECT_PATH_IS_EMPTY",
                )

            root = Path(normalized)
        else:
            return SettingsGradleDiscoveryResult(
                found=False,
                path=None,
                kind="NONE",
                reason="UNSUPPORTED_PROJECT_PATH_TYPE",
            )

        try:
            if not root.exists():
                return SettingsGradleDiscoveryResult(
                    found=False,
                    path=None,
                    kind="NONE",
                    reason="PROJECT_PATH_DOES_NOT_EXIST",
                )

            if not root.is_dir():
                return SettingsGradleDiscoveryResult(
                    found=False,
                    path=None,
                    kind="NONE",
                    reason="PROJECT_PATH_IS_NOT_DIRECTORY",
                )

            candidates: list[Path] = []

            for filename in SETTINGS_GRADLE_FILENAMES:
                candidate = root / filename

                try:
                    if candidate.is_file():
                        candidates.append(candidate)
                except (OSError, PermissionError):
                    continue

            if not candidates:
                return SettingsGradleDiscoveryResult(
                    found=False,
                    path=None,
                    kind="NONE",
                    reason="SETTINGS_GRADLE_NOT_FOUND",
                )

            # Deterministic preference:
            # conventional Groovy settings.gradle first.
            candidates.sort(
                key=lambda item: (
                    0 if item.name == "settings.gradle" else 1,
                    item.name,
                )
            )

            selected = candidates[0]

            if selected.name == "settings.gradle":
                kind = "SETTINGS_GRADLE"
            else:
                kind = "SETTINGS_GRADLE_KTS"

            return SettingsGradleDiscoveryResult(
                found=True,
                path=selected,
                kind=kind,
                reason="SETTINGS_GRADLE_FOUND",
            )

        except PermissionError:
            return SettingsGradleDiscoveryResult(
                found=False,
                path=None,
                kind="NONE",
                reason="PROJECT_PATH_PERMISSION_DENIED",
            )
        except OSError:
            return SettingsGradleDiscoveryResult(
                found=False,
                path=None,
                kind="NONE",
                reason="PROJECT_PATH_OS_ERROR",
            )


def discover_settings_gradle(
    project_path: Any,
) -> SettingsGradleDiscoveryResult:
    return SettingsGradleDiscoverer().discover(project_path)
