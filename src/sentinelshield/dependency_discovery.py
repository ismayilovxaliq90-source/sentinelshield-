from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


PROJECT_MARKERS = (
    ".git",
    "pyproject.toml",
    "requirements.txt",
    "requirements-dev.txt",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "Cargo.toml",
    "go.mod",
)


@dataclass(frozen=True)
class DiscoveryResult:
    status: str
    start_path: Path
    root_path: Path | None
    markers: tuple[str, ...]
    reason: str


class RepositoryDiscovery:
    """
    Read-only repository/project root discovery.

    This component never:
      - executes project code
      - executes shell commands
      - installs packages
      - modifies files
      - reads file contents
    """

    def __init__(self, markers: tuple[str, ...] = PROJECT_MARKERS) -> None:
        self._markers = tuple(markers)

    def discover(self, start_path: str | Path) -> DiscoveryResult:
        raw = Path(start_path).expanduser()

        try:
            resolved = raw.resolve(strict=False)
        except (OSError, RuntimeError) as exc:
            return DiscoveryResult(
                status="INVALID",
                start_path=raw,
                root_path=None,
                markers=(),
                reason=f"PATH_RESOLUTION_FAILED:{type(exc).__name__}",
            )

        if not resolved.exists():
            return DiscoveryResult(
                status="NOT_FOUND",
                start_path=resolved,
                root_path=None,
                markers=(),
                reason="START_PATH_DOES_NOT_EXIST",
            )

        start = resolved.parent if resolved.is_file() else resolved

        current = start

        while True:
            found = self._markers_in(current)

            if ".git" in found or len(found) >= 2:
                return DiscoveryResult(
                    status="FOUND",
                    start_path=resolved,
                    root_path=current,
                    markers=found,
                    reason="REPOSITORY_ROOT_DISCOVERED",
                )

            parent = current.parent

            if parent == current:
                break

            current = parent

        return DiscoveryResult(
            status="NOT_FOUND",
            start_path=resolved,
            root_path=None,
            markers=(),
            reason="NO_REPOSITORY_MARKER_FOUND",
        )

    def _markers_in(self, directory: Path) -> tuple[str, ...]:
        found: list[str] = []

        for marker in self._markers:
            candidate = directory / marker

            try:
                if candidate.exists():
                    found.append(marker)
            except OSError:
                # Unreadable marker must not abort discovery.
                continue

        return tuple(sorted(found))


def discover_repository(start_path: str | Path) -> DiscoveryResult:
    return RepositoryDiscovery().discover(start_path)
