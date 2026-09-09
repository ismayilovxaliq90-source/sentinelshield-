from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


REPOSITORY_MARKERS = (
    ".git",
)

PROJECT_MARKERS = (
    "pyproject.toml",
    "requirements.txt",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "go.mod",
    "Cargo.toml",
    "pom.xml",
    "build.gradle",
    "settings.gradle",
    "composer.json",
    "Gemfile",
    "Pipfile",
)

PROJECT_FILE_SUFFIXES = (
    ".sln",
    ".csproj",
    ".fsproj",
    ".vbproj",
)


@dataclass(frozen=True)
class RepositoryRootDetectionResult:
    found: bool
    root: Path | None
    markers: tuple[str, ...]
    reason: str


class RepositoryRootDetector:
    """
    Detects the nearest repository/project root by walking
    from a starting path toward the filesystem root.

    This detector is read-only and never executes project code.
    """

    def detect(
        self,
        value: Any,
    ) -> RepositoryRootDetectionResult:

        if value is None:
            return RepositoryRootDetectionResult(
                found=False,
                root=None,
                markers=(),
                reason="PATH_IS_NONE",
            )

        if not isinstance(value, (str, Path)):
            return RepositoryRootDetectionResult(
                found=False,
                root=None,
                markers=(),
                reason="UNSUPPORTED_PATH_TYPE",
            )

        if isinstance(value, str):
            value = value.strip()

            if not value:
                return RepositoryRootDetectionResult(
                    found=False,
                    root=None,
                    markers=(),
                    reason="PATH_IS_EMPTY",
                )

        raw_path = str(value)

        if "\x00" in raw_path:
            return RepositoryRootDetectionResult(
                found=False,
                root=None,
                markers=(),
                reason="NULL_CHARACTER_NOT_ALLOWED",
            )

        try:
            start = (
                Path(value)
                .expanduser()
                .resolve(strict=False)
            )
        except (OSError, RuntimeError, ValueError) as exc:
            return RepositoryRootDetectionResult(
                found=False,
                root=None,
                markers=(),
                reason=(
                    "PATH_RESOLUTION_FAILED:"
                    f"{type(exc).__name__}"
                ),
            )

        if start.exists() and not start.is_dir():
            start = start.parent

        current = start

        while True:
            markers = self._detect_markers(current)

            if markers:
                return RepositoryRootDetectionResult(
                    found=True,
                    root=current,
                    markers=markers,
                    reason="REPOSITORY_ROOT_FOUND",
                )

            parent = current.parent

            if parent == current:
                break

            current = parent

        return RepositoryRootDetectionResult(
            found=False,
            root=None,
            markers=(),
            reason="REPOSITORY_ROOT_NOT_FOUND",
        )

    def _detect_markers(
        self,
        directory: Path,
    ) -> tuple[str, ...]:

        found: list[str] = []

        for marker in REPOSITORY_MARKERS:
            if (directory / marker).exists():
                found.append(marker)

        for marker in PROJECT_MARKERS:
            if (directory / marker).is_file():
                found.append(marker)

        try:
            for suffix in PROJECT_FILE_SUFFIXES:
                if any(
                    path.is_file()
                    and path.suffix.lower() == suffix
                    for path in directory.iterdir()
                ):
                    found.append(f"*{suffix}")
        except OSError:
            pass

        return tuple(found)


def detect_repository_root(
    value: Any,
) -> RepositoryRootDetectionResult:
    return RepositoryRootDetector().detect(value)
