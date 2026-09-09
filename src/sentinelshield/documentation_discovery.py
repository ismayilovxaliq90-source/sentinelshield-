from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


DOC_FILES = {
    "README": "readme",
    "README.md": "readme",
    "README.rst": "readme",
    "README.txt": "readme",
    "CHANGELOG": "changelog",
    "CHANGELOG.md": "changelog",
    "CHANGELOG.rst": "changelog",
    "CONTRIBUTING": "contributing",
    "CONTRIBUTING.md": "contributing",
    "CONTRIBUTING.rst": "contributing",
    "LICENSE": "license",
    "LICENSE.md": "license",
    "LICENSE.txt": "license",
}

DOC_DIRECTORIES = {"docs": "docs", "documentation": "documentation"}

IGNORED = {
    ".git", ".hg", ".svn", ".venv", "venv",
    "node_modules", "__pycache__", ".pytest_cache",
    "build", "dist", "target",
}


@dataclass(frozen=True)
class DocumentationDiscoveryResult:
    found: bool
    root: Path | None
    categories: tuple[str, ...]
    markers: tuple[Path, ...]
    reason: str


def discover_documentation(value: Any) -> DocumentationDiscoveryResult:
    if value is None:
        return DocumentationDiscoveryResult(
            False, None, (), (), "PATH_IS_NONE"
        )

    if not isinstance(value, (str, Path)):
        return DocumentationDiscoveryResult(
            False, None, (), (), "UNSUPPORTED_PATH_TYPE"
        )

    if isinstance(value, str):
        value = value.strip()
        if not value:
            return DocumentationDiscoveryResult(
                False, None, (), (), "PATH_IS_EMPTY"
            )

    raw = str(value)

    if "\x00" in raw:
        return DocumentationDiscoveryResult(
            False, None, (), (), "NULL_CHARACTER_NOT_ALLOWED"
        )

    try:
        root = Path(value).expanduser().resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        return DocumentationDiscoveryResult(
            False, None, (), (),
            f"PATH_RESOLUTION_FAILED:{type(exc).__name__}",
        )

    if not root.exists():
        return DocumentationDiscoveryResult(
            False, root, (), (), "PATH_DOES_NOT_EXIST"
        )

    if not root.is_dir():
        return DocumentationDiscoveryResult(
            False, root, (), (), "PATH_IS_NOT_DIRECTORY"
        )

    markers: list[Path] = []
    categories: set[str] = set()
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

                    category = DOC_DIRECTORIES.get(entry.name.lower())
                    if category:
                        categories.add(category)
                        markers.append(entry)

                    stack.append(entry)
                    continue

                if not entry.is_file():
                    continue

                category = DOC_FILES.get(entry.name)
                if category is None:
                    category = DOC_FILES.get(entry.name.upper())

                if category:
                    categories.add(category)
                    markers.append(entry)

            except OSError:
                continue

    markers = sorted(set(markers), key=str)
    categories = sorted(categories)

    if categories:
        return DocumentationDiscoveryResult(
            True,
            root,
            tuple(categories),
            tuple(markers),
            "DOCUMENTATION_FOUND",
        )

    return DocumentationDiscoveryResult(
        False,
        root,
        (),
        (),
        "DOCUMENTATION_NOT_FOUND",
    )
