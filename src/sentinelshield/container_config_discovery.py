from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


CONTAINER_MARKERS = {
    "Dockerfile": "docker",
    "Dockerfile.dev": "docker",
    "Dockerfile.prod": "docker",
    "docker-compose.yml": "docker-compose",
    "docker-compose.yaml": "docker-compose",
    "compose.yml": "docker-compose",
    "compose.yaml": "docker-compose",
}

IGNORED = {
    ".git", ".hg", ".svn", ".venv", "venv",
    "node_modules", "__pycache__", ".pytest_cache",
    "build", "dist", "target",
}


@dataclass(frozen=True)
class ContainerDiscoveryResult:
    found: bool
    root: Path | None
    systems: tuple[str, ...]
    markers: tuple[Path, ...]
    reason: str


def discover_container_config(value: Any) -> ContainerDiscoveryResult:
    if value is None:
        return ContainerDiscoveryResult(False, None, (), (), "PATH_IS_NONE")

    if not isinstance(value, (str, Path)):
        return ContainerDiscoveryResult(
            False, None, (), (), "UNSUPPORTED_PATH_TYPE"
        )

    if isinstance(value, str):
        value = value.strip()
        if not value:
            return ContainerDiscoveryResult(
                False, None, (), (), "PATH_IS_EMPTY"
            )

    raw = str(value)

    if "\x00" in raw:
        return ContainerDiscoveryResult(
            False, None, (), (), "NULL_CHARACTER_NOT_ALLOWED"
        )

    try:
        root = Path(value).expanduser().resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        return ContainerDiscoveryResult(
            False, None, (), (),
            f"PATH_RESOLUTION_FAILED:{type(exc).__name__}",
        )

    if not root.exists():
        return ContainerDiscoveryResult(
            False, root, (), (), "PATH_DOES_NOT_EXIST"
        )

    if not root.is_dir():
        return ContainerDiscoveryResult(
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
                    if entry.name not in IGNORED:
                        stack.append(entry)
                    continue

                if entry.is_file():
                    system = CONTAINER_MARKERS.get(entry.name)
                    if system:
                        markers.append(entry)
                        systems.add(system)

            except OSError:
                continue

    markers = sorted(set(markers), key=str)
    systems = sorted(systems)

    if systems:
        return ContainerDiscoveryResult(
            True, root, tuple(systems),
            tuple(markers), "CONTAINER_CONFIG_FOUND"
        )

    return ContainerDiscoveryResult(
        False, root, (), (), "CONTAINER_CONFIG_NOT_FOUND"
    )
