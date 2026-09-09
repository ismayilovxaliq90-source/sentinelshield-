from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


IGNORED_DIRECTORIES = {
    ".git", ".hg", ".svn", ".venv", "venv", "env", ".env",
    "node_modules", "__pycache__", ".pytest_cache",
    "build", "dist", "target",
}

TARGET_NAME = "pyproject.toml"


@dataclass(frozen=True)
class PyProjectDiscoveryResult:
    found: bool
    root: Path | None
    files: tuple[Path, ...]
    count: int
    reason: str


def discover_pyproject(value: Any) -> PyProjectDiscoveryResult:
    if value is None:
        return PyProjectDiscoveryResult(
            False, None, (), 0, "PATH_IS_NONE"
        )

    if not isinstance(value, (str, Path)):
        return PyProjectDiscoveryResult(
            False, None, (), 0, "UNSUPPORTED_PATH_TYPE"
        )

    if isinstance(value, str):
        value = value.strip()
        if not value:
            return PyProjectDiscoveryResult(
                False, None, (), 0, "PATH_IS_EMPTY"
            )

    raw = str(value)

    if "\x00" in raw:
        return PyProjectDiscoveryResult(
            False, None, (), 0, "NULL_CHARACTER_NOT_ALLOWED"
        )

    try:
        root = Path(value).expanduser().resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        return PyProjectDiscoveryResult(
            False,
            None,
            (),
            0,
            f"PATH_RESOLUTION_FAILED:{type(exc).__name__}",
        )

    if not root.exists():
        return PyProjectDiscoveryResult(
            False, root, (), 0, "PATH_DOES_NOT_EXIST"
        )

    if not root.is_dir():
        return PyProjectDiscoveryResult(
            False, root, (), 0, "PATH_IS_NOT_DIRECTORY"
        )

    found: list[Path] = []
    stack = [root]

    while stack:
        current = stack.pop()

        try:
            entries = sorted(
                current.iterdir(),
                key=lambda p: (not p.is_dir(), p.name.lower()),
            )
        except OSError:
            continue

        for entry in entries:
            try:
                if entry.is_symlink():
                    continue

                if entry.is_dir():
                    if entry.name in IGNORED_DIRECTORIES:
                        continue
                    stack.append(entry)
                    continue

                if entry.is_file() and entry.name == TARGET_NAME:
                    found.append(entry.relative_to(root))

            except (OSError, ValueError):
                continue

    found.sort(key=lambda p: p.as_posix())

    if not found:
        return PyProjectDiscoveryResult(
            False,
            root,
            (),
            0,
            "PYPROJECT_TOML_NOT_FOUND",
        )

    return PyProjectDiscoveryResult(
        True,
        root,
        tuple(found),
        len(found),
        "PYPROJECT_TOML_DISCOVERED",
    )
