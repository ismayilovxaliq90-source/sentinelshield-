from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


IGNORE_MARKERS = {
    ".gitignore": "git",
    ".git/info/exclude": "git-info",
    ".dockerignore": "docker",
    ".npmignore": "npm",
    ".eslintignore": "eslint",
    ".prettierignore": "prettier",
    ".terraformignore": "terraform",
    ".hgignore": "mercurial",
    ".bzrignore": "bazaar",
}

IGNORED_DIRECTORIES = {
    ".git", ".hg", ".svn", ".venv", "venv",
    "node_modules", "__pycache__", ".pytest_cache",
    "build", "dist", "target",
}


@dataclass(frozen=True)
class IgnoreFileDiscoveryResult:
    found: bool
    root: Path | None
    types: tuple[str, ...]
    markers: tuple[Path, ...]
    reason: str


def discover_ignore_files(value: Any) -> IgnoreFileDiscoveryResult:
    if value is None:
        return IgnoreFileDiscoveryResult(
            False, None, (), (), "PATH_IS_NONE"
        )

    if not isinstance(value, (str, Path)):
        return IgnoreFileDiscoveryResult(
            False, None, (), (), "UNSUPPORTED_PATH_TYPE"
        )

    if isinstance(value, str):
        value = value.strip()
        if not value:
            return IgnoreFileDiscoveryResult(
                False, None, (), (), "PATH_IS_EMPTY"
            )

    raw = str(value)

    if "\x00" in raw:
        return IgnoreFileDiscoveryResult(
            False, None, (), (), "NULL_CHARACTER_NOT_ALLOWED"
        )

    try:
        root = Path(value).expanduser().resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        return IgnoreFileDiscoveryResult(
            False,
            None,
            (),
            (),
            f"PATH_RESOLUTION_FAILED:{type(exc).__name__}",
        )

    if not root.exists():
        return IgnoreFileDiscoveryResult(
            False, root, (), (), "PATH_DOES_NOT_EXIST"
        )

    if not root.is_dir():
        return IgnoreFileDiscoveryResult(
            False, root, (), (), "PATH_IS_NOT_DIRECTORY"
        )

    markers: list[Path] = []
    types: set[str] = set()
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
                    rel = entry.relative_to(root).as_posix()

                    if rel == ".git":
                        info_exclude = entry / "info" / "exclude"
                        if info_exclude.is_file():
                            markers.append(info_exclude)
                            types.add("git-info")

                    if entry.name not in IGNORED_DIRECTORIES:
                        stack.append(entry)

                    continue

                if not entry.is_file():
                    continue

                marker_type = IGNORE_MARKERS.get(entry.name)

                if marker_type:
                    markers.append(entry)
                    types.add(marker_type)

            except (OSError, ValueError):
                continue

    markers = sorted(set(markers), key=str)
    types = sorted(types)

    if types:
        return IgnoreFileDiscoveryResult(
            True,
            root,
            tuple(types),
            tuple(markers),
            "IGNORE_FILES_FOUND",
        )

    return IgnoreFileDiscoveryResult(
        False,
        root,
        (),
        (),
        "IGNORE_FILES_NOT_FOUND",
    )
