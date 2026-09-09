from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


GO_SUM_FILENAME = "go.sum"


@dataclass(frozen=True)
class GoSumDiscoveryResult:
    found: bool
    path: Path | None
    reason: str


class GoSumDiscovery:
    """
    Read-only discovery of a go.sum file directly under a project root.

    This task MUST NOT:
      - execute Go commands
      - install packages
      - modify the repository
      - create files
      - read or parse the contents of go.sum

    It only determines whether the expected go.sum file exists
    directly beneath the supplied project root.
    """

    def discover(self, project_root: Any) -> GoSumDiscoveryResult:
        if project_root is None:
            return GoSumDiscoveryResult(
                found=False,
                path=None,
                reason="PROJECT_ROOT_IS_NONE",
            )

        if isinstance(project_root, str):
            if not project_root.strip():
                return GoSumDiscoveryResult(
                    found=False,
                    path=None,
                    reason="PROJECT_ROOT_IS_EMPTY",
                )
            project_root = Path(project_root)

        elif not isinstance(project_root, Path):
            return GoSumDiscoveryResult(
                found=False,
                path=None,
                reason="UNSUPPORTED_PROJECT_ROOT_TYPE",
            )

        try:
            root = project_root.expanduser()

            if not root.exists():
                return GoSumDiscoveryResult(
                    found=False,
                    path=None,
                    reason="PROJECT_ROOT_NOT_FOUND",
                )

            if not root.is_dir():
                return GoSumDiscoveryResult(
                    found=False,
                    path=None,
                    reason="PROJECT_ROOT_NOT_DIRECTORY",
                )

            go_sum = root / GO_SUM_FILENAME

            if not go_sum.exists():
                return GoSumDiscoveryResult(
                    found=False,
                    path=None,
                    reason="GO_SUM_NOT_FOUND",
                )

            if not go_sum.is_file():
                return GoSumDiscoveryResult(
                    found=False,
                    path=None,
                    reason="GO_SUM_NOT_FILE",
                )

            return GoSumDiscoveryResult(
                found=True,
                path=go_sum,
                reason="GO_SUM_FOUND",
            )

        except PermissionError:
            return GoSumDiscoveryResult(
                found=False,
                path=None,
                reason="FILESYSTEM_PERMISSION_DENIED",
            )
        except OSError:
            return GoSumDiscoveryResult(
                found=False,
                path=None,
                reason="FILESYSTEM_OS_ERROR",
            )


def discover_go_sum(project_root: Any) -> GoSumDiscoveryResult:
    return GoSumDiscovery().discover(project_root)
