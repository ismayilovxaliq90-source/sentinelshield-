from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


PNPM_LOCKFILE_NAME = "pnpm-lock.yaml"


@dataclass(frozen=True)
class PnpmLockfileDiscoveryResult:
    found: bool
    lockfile: Path | None
    reason: str


class PnpmLockfileDetector:
    """
    Detects pnpm-lock.yaml in a project directory.

    This detector is strictly read-only:
    - it does not execute pnpm;
    - it does not install packages;
    - it does not modify files;
    - it only checks filesystem metadata.
    """

    def discover(
        self,
        project_path: Any,
    ) -> PnpmLockfileDiscoveryResult:

        if project_path is None:
            return PnpmLockfileDiscoveryResult(
                found=False,
                lockfile=None,
                reason="PATH_IS_NONE",
            )

        if isinstance(project_path, str):
            if not project_path.strip():
                return PnpmLockfileDiscoveryResult(
                    found=False,
                    lockfile=None,
                    reason="PATH_IS_EMPTY",
                )

        if not isinstance(project_path, (str, Path)):
            return PnpmLockfileDiscoveryResult(
                found=False,
                lockfile=None,
                reason="UNSUPPORTED_PATH_TYPE",
            )

        raw_path = str(project_path)

        if "\x00" in raw_path:
            return PnpmLockfileDiscoveryResult(
                found=False,
                lockfile=None,
                reason="NULL_CHARACTER_NOT_ALLOWED",
            )

        try:
            path = Path(project_path).expanduser().resolve(
                strict=False
            )
        except (OSError, RuntimeError, ValueError) as exc:
            return PnpmLockfileDiscoveryResult(
                found=False,
                lockfile=None,
                reason=(
                    "PATH_RESOLUTION_FAILED:"
                    f"{type(exc).__name__}"
                ),
            )

        try:
            if not path.exists():
                return PnpmLockfileDiscoveryResult(
                    found=False,
                    lockfile=None,
                    reason="PROJECT_PATH_NOT_FOUND",
                )

            if not path.is_dir():
                return PnpmLockfileDiscoveryResult(
                    found=False,
                    lockfile=None,
                    reason="PROJECT_PATH_NOT_DIRECTORY",
                )

            lockfile = path / PNPM_LOCKFILE_NAME

            if lockfile.is_file():
                return PnpmLockfileDiscoveryResult(
                    found=True,
                    lockfile=lockfile,
                    reason="PNPM_LOCKFILE_FOUND",
                )

            return PnpmLockfileDiscoveryResult(
                found=False,
                lockfile=None,
                reason="PNPM_LOCKFILE_NOT_FOUND",
            )

        except (OSError, PermissionError) as exc:
            return PnpmLockfileDiscoveryResult(
                found=False,
                lockfile=None,
                reason=(
                    "FILESYSTEM_ERROR:"
                    f"{type(exc).__name__}"
                ),
            )


def discover_pnpm_lockfile(
    project_path: Any,
) -> PnpmLockfileDiscoveryResult:
    return PnpmLockfileDetector().discover(project_path)
