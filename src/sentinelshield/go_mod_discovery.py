from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


GO_MOD_FILENAME = "go.mod"


@dataclass(frozen=True)
class GoModDiscoveryResult:
    found: bool
    path: Path | None
    reason: str


class GoModDiscovery:
    """
    Discovers a go.mod file directly under the supplied project root.

    This operation is read-only:
    - does not create files
    - does not modify files
    - does not execute Go tooling
    - does not install dependencies
    """

    def discover(self, project_root: Any) -> GoModDiscoveryResult:
        if project_root is None:
            return GoModDiscoveryResult(
                found=False,
                path=None,
                reason="PROJECT_ROOT_IS_NONE",
            )

        if isinstance(project_root, str):
            if not project_root.strip():
                return GoModDiscoveryResult(
                    found=False,
                    path=None,
                    reason="PROJECT_ROOT_IS_EMPTY",
                )
            project_root = Path(project_root)

        elif not isinstance(project_root, Path):
            return GoModDiscoveryResult(
                found=False,
                path=None,
                reason="UNSUPPORTED_PROJECT_ROOT_TYPE",
            )

        try:
            root = project_root.expanduser()

            if not root.exists():
                return GoModDiscoveryResult(
                    found=False,
                    path=None,
                    reason="PROJECT_ROOT_NOT_FOUND",
                )

            if not root.is_dir():
                return GoModDiscoveryResult(
                    found=False,
                    path=None,
                    reason="PROJECT_ROOT_NOT_DIRECTORY",
                )

            go_mod = root / GO_MOD_FILENAME

            if not go_mod.exists():
                return GoModDiscoveryResult(
                    found=False,
                    path=None,
                    reason="GO_MOD_NOT_FOUND",
                )

            if not go_mod.is_file():
                return GoModDiscoveryResult(
                    found=False,
                    path=None,
                    reason="GO_MOD_NOT_FILE",
                )

            return GoModDiscoveryResult(
                found=True,
                path=go_mod,
                reason="GO_MOD_FOUND",
            )

        except PermissionError:
            return GoModDiscoveryResult(
                found=False,
                path=None,
                reason="FILESYSTEM_PERMISSION_DENIED",
            )
        except OSError:
            return GoModDiscoveryResult(
                found=False,
                path=None,
                reason="FILESYSTEM_OS_ERROR",
            )


def discover_go_mod(project_root: Any) -> GoModDiscoveryResult:
    return GoModDiscovery().discover(project_root)
