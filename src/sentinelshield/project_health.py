from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from sentinelshield.project_registry import ProjectRecord


@dataclass(frozen=True)
class ProjectHealth:
    project: str
    path: str
    healthy: bool
    exists: bool
    is_directory: bool
    readable: bool
    python_files: int
    reasons: tuple[str, ...]


class ProjectHealthChecker:
    """
    Read-only health checker for registered projects.
    """

    def check(self, project: ProjectRecord) -> ProjectHealth:
        if not isinstance(project, ProjectRecord):
            raise TypeError("project must be ProjectRecord")

        path = Path(project.path)
        reasons: list[str] = []

        exists = path.exists()
        is_directory = path.is_dir() if exists else False
        readable = False
        python_files = 0

        if not exists:
            reasons.append("PATH_NOT_FOUND")
        elif not is_directory:
            reasons.append("NOT_DIRECTORY")
        else:
            try:
                readable = bool(path.stat().st_mode & 0o444)
            except OSError:
                readable = False

            if not readable:
                reasons.append("NOT_READABLE")

            if readable:
                try:
                    python_files = sum(
                        1
                        for item in path.rglob("*.py")
                        if item.is_file()
                    )
                except OSError:
                    reasons.append("SCAN_FAILED")

        healthy = (
            exists
            and is_directory
            and readable
            and "SCAN_FAILED" not in reasons
        )

        if healthy and not reasons:
            reasons.append("OK")

        return ProjectHealth(
            project=project.name,
            path=str(path),
            healthy=healthy,
            exists=exists,
            is_directory=is_directory,
            readable=readable,
            python_files=python_files,
            reasons=tuple(reasons),
        )

    def require_healthy(self, health: ProjectHealth) -> None:
        if not isinstance(health, ProjectHealth):
            raise TypeError("health must be ProjectHealth")

        if not health.healthy:
            raise RuntimeError(
                f"project unhealthy: {health.project} | "
                f"{', '.join(health.reasons)}"
            )
