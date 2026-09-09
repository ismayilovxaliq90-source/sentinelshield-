from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


CI_MARKERS = {
    ".github/workflows": "github-actions",
    ".gitlab-ci.yml": "gitlab-ci",
    ".circleci/config.yml": "circleci",
    "Jenkinsfile": "jenkins",
    "azure-pipelines.yml": "azure-pipelines",
    ".travis.yml": "travis-ci",
    "bitbucket-pipelines.yml": "bitbucket-pipelines",
}

IGNORED = {
    ".git", ".hg", ".svn", ".venv", "venv",
    "node_modules", "__pycache__", ".pytest_cache",
    "build", "dist", "target",
}


@dataclass(frozen=True)
class CICDDiscoveryResult:
    found: bool
    root: Path | None
    systems: tuple[str, ...]
    markers: tuple[Path, ...]
    reason: str


class CICDDiscovery:
    def discover(self, value: Any) -> CICDDiscoveryResult:
        if value is None:
            return CICDDiscoveryResult(False, None, (), (), "PATH_IS_NONE")

        if not isinstance(value, (str, Path)):
            return CICDDiscoveryResult(
                False, None, (), (), "UNSUPPORTED_PATH_TYPE"
            )

        if isinstance(value, str):
            value = value.strip()
            if not value:
                return CICDDiscoveryResult(
                    False, None, (), (), "PATH_IS_EMPTY"
                )

        raw = str(value)

        if "\x00" in raw:
            return CICDDiscoveryResult(
                False, None, (), (), "NULL_CHARACTER_NOT_ALLOWED"
            )

        try:
            root = Path(value).expanduser().resolve(strict=False)
        except (OSError, RuntimeError, ValueError) as exc:
            return CICDDiscoveryResult(
                False, None, (), (),
                f"PATH_RESOLUTION_FAILED:{type(exc).__name__}",
            )

        if not root.exists():
            return CICDDiscoveryResult(
                False, root, (), (), "PATH_DOES_NOT_EXIST"
            )

        if not root.is_dir():
            return CICDDiscoveryResult(
                False, root, (), (), "PATH_IS_NOT_DIRECTORY"
            )

        markers = []
        systems = set()

        stack = [root]

        while stack:
            current = stack.pop()

            try:
                entries = list(current.iterdir())
            except OSError:
                continue

            for entry in entries:
                try:
                    if entry.is_dir():
                        if entry.name in IGNORED:
                            continue

                        rel = entry.relative_to(root).as_posix()

                        if rel in CI_MARKERS:
                            systems.add(CI_MARKERS[rel])
                            markers.append(entry)

                        stack.append(entry)
                        continue

                    if not entry.is_file():
                        continue

                    rel = entry.relative_to(root).as_posix()
                    system = CI_MARKERS.get(rel)

                    if system is None:
                        system = CI_MARKERS.get(entry.name)

                    if system:
                        systems.add(system)
                        markers.append(entry)

                except OSError:
                    continue

        markers = sorted(set(markers), key=str)
        systems = sorted(systems)

        if systems:
            return CICDDiscoveryResult(
                True, root, tuple(systems),
                tuple(markers), "CI_CD_CONFIG_FOUND"
            )

        return CICDDiscoveryResult(
            False, root, (), (), "CI_CD_CONFIG_NOT_FOUND"
        )


def discover_ci_cd(value: Any) -> CICDDiscoveryResult:
    return CICDDiscovery().discover(value)
