from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class PathResolutionResult:
    valid: bool
    original: Any
    resolved: Path | None
    reason: str


class ProjectPathResolver:
    """
    Resolve a project path without executing project code
    or modifying the filesystem.
    """

    def resolve(
        self,
        value: str | Path,
    ) -> PathResolutionResult:

        if value is None:
            return PathResolutionResult(
                valid=False,
                original=value,
                resolved=None,
                reason="PATH_IS_NONE",
            )

        if not isinstance(value, (str, Path)):
            return PathResolutionResult(
                valid=False,
                original=value,
                resolved=None,
                reason="UNSUPPORTED_PATH_TYPE",
            )

        if isinstance(value, str):
            value = value.strip()

        if not str(value):
            return PathResolutionResult(
                valid=False,
                original=value,
                resolved=None,
                reason="PATH_IS_EMPTY",
            )

        if "\x00" in str(value):
            return PathResolutionResult(
                valid=False,
                original=value,
                resolved=None,
                reason="NULL_CHARACTER_NOT_ALLOWED",
            )

        try:
            path = Path(value).expanduser()
            resolved = path.resolve(strict=False)

        except (OSError, RuntimeError, ValueError) as exc:
            return PathResolutionResult(
                valid=False,
                original=value,
                resolved=None,
                reason=f"PATH_RESOLUTION_FAILED:{type(exc).__name__}",
            )

        return PathResolutionResult(
            valid=True,
            original=value,
            resolved=resolved,
            reason="PATH_RESOLVED",
        )


def resolve_project_path(
    value: str | Path,
) -> PathResolutionResult:
    return ProjectPathResolver().resolve(value)
