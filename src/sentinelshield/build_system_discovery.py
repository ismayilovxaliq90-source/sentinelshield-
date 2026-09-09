from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


BUILD_MARKERS = {
    "Makefile": "make",
    "makefile": "make",
    "GNUmakefile": "make",
    "CMakeLists.txt": "cmake",
    "build.gradle": "gradle",
    "build.gradle.kts": "gradle",
    "pom.xml": "maven",
    "Cargo.toml": "cargo",
    "go.mod": "go",
    "package.json": "npm",
    "setup.py": "python-setuptools",
    "pyproject.toml": "python-build",
    "mix.exs": "mix",
    "Rakefile": "rake",
}

IGNORED_DIRECTORIES = {
    ".git", ".hg", ".svn", ".venv", "venv",
    "node_modules", "__pycache__", ".pytest_cache",
    "build", "dist", "target",
}


@dataclass(frozen=True)
class BuildSystemDiscoveryResult:
    found: bool
    root: Path | None
    systems: tuple[str, ...]
    markers: tuple[Path, ...]
    reason: str


class BuildSystemDiscovery:
    def discover(self, value: Any) -> BuildSystemDiscoveryResult:
        if value is None:
            return BuildSystemDiscoveryResult(
                False, None, (), (), "PATH_IS_NONE"
            )

        if not isinstance(value, (str, Path)):
            return BuildSystemDiscoveryResult(
                False, None, (), (), "UNSUPPORTED_PATH_TYPE"
            )

        if isinstance(value, str):
            value = value.strip()
            if not value:
                return BuildSystemDiscoveryResult(
                    False, None, (), (), "PATH_IS_EMPTY"
                )

        raw = str(value)

        if "\x00" in raw:
            return BuildSystemDiscoveryResult(
                False, None, (), (), "NULL_CHARACTER_NOT_ALLOWED"
            )

        try:
            root = Path(value).expanduser().resolve(strict=False)
        except (OSError, RuntimeError, ValueError) as exc:
            return BuildSystemDiscoveryResult(
                False,
                None,
                (),
                (),
                f"PATH_RESOLUTION_FAILED:{type(exc).__name__}",
            )

        if not root.exists():
            return BuildSystemDiscoveryResult(
                False, root, (), (), "PATH_DOES_NOT_EXIST"
            )

        if not root.is_dir():
            return BuildSystemDiscoveryResult(
                False, root, (), (), "PATH_IS_NOT_DIRECTORY"
            )

        markers: list[Path] = []
        systems: set[str] = set()

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
                        if entry.name not in IGNORED_DIRECTORIES:
                            stack.append(entry)
                        continue

                    if not entry.is_file():
                        continue

                    system = BUILD_MARKERS.get(entry.name)

                    if system:
                        markers.append(entry)
                        systems.add(system)

                except OSError:
                    continue

        markers = sorted(set(markers), key=str)
        systems = sorted(systems)

        if systems:
            return BuildSystemDiscoveryResult(
                True,
                root,
                tuple(systems),
                tuple(markers),
                "BUILD_SYSTEMS_FOUND",
            )

        return BuildSystemDiscoveryResult(
            False,
            root,
            (),
            (),
            "BUILD_SYSTEMS_NOT_FOUND",
        )


def discover_build_system(
    value: Any,
) -> BuildSystemDiscoveryResult:
    return BuildSystemDiscovery().discover(value)
