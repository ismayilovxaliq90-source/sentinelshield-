from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class PomXmlDiscoveryResult:
    discovered: bool
    files: tuple[Path, ...]
    reason: str


class PomXmlDiscovery:
    """
    Discovers pom.xml files inside a project tree.

    This task is read-only:
    - no Maven execution
    - no package installation
    - no build/test execution
    - no filesystem modification
    """

    FILENAME = "pom.xml"

    def discover(self, project_path: Any) -> PomXmlDiscoveryResult:
        if project_path is None:
            return PomXmlDiscoveryResult(
                discovered=False,
                files=(),
                reason="PROJECT_PATH_IS_NONE",
            )

        if isinstance(project_path, str):
            if not project_path.strip():
                return PomXmlDiscoveryResult(
                    discovered=False,
                    files=(),
                    reason="PROJECT_PATH_IS_EMPTY",
                )
            project_path = Path(project_path)

        elif not isinstance(project_path, Path):
            return PomXmlDiscoveryResult(
                discovered=False,
                files=(),
                reason="UNSUPPORTED_PROJECT_PATH_TYPE",
            )

        try:
            root = project_path.expanduser().resolve()
        except (OSError, RuntimeError):
            return PomXmlDiscoveryResult(
                discovered=False,
                files=(),
                reason="PROJECT_PATH_RESOLUTION_FAILED",
            )

        try:
            if not root.exists():
                return PomXmlDiscoveryResult(
                    discovered=False,
                    files=(),
                    reason="PROJECT_PATH_NOT_FOUND",
                )

            if not root.is_dir():
                return PomXmlDiscoveryResult(
                    discovered=False,
                    files=(),
                    reason="PROJECT_PATH_NOT_DIRECTORY",
                )

            discovered_files = tuple(
                sorted(
                    (
                        path
                        for path in root.rglob(self.FILENAME)
                        if path.is_file()
                    ),
                    key=lambda path: path.as_posix(),
                )
            )

        except (OSError, RuntimeError):
            return PomXmlDiscoveryResult(
                discovered=False,
                files=(),
                reason="POM_XML_DISCOVERY_FAILED",
            )

        if not discovered_files:
            return PomXmlDiscoveryResult(
                discovered=False,
                files=(),
                reason="POM_XML_NOT_FOUND",
            )

        return PomXmlDiscoveryResult(
            discovered=True,
            files=discovered_files,
            reason="POM_XML_DISCOVERY_SUCCESS",
        )


def discover_pom_xml(project_path: Any) -> PomXmlDiscoveryResult:
    return PomXmlDiscovery().discover(project_path)
