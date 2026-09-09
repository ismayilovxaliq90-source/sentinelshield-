from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


IGNORED_DIRECTORIES = {
    ".git", ".hg", ".svn",
    ".venv", "venv", "env", ".env",
    "node_modules", "__pycache__", ".pytest_cache",
    "build", "dist", "target",
}

TARGET_NAME = "Pipfile"


@dataclass(frozen=True)
class PipfileDiscoveryResult:
    found: bool
    root: Path | None
    files: tuple[Path, ...]
    count: int
    reason: str


def discover_pipfiles(value: Any) -> PipfileDiscoveryResult:
    if value is None:
        return PipfileDiscoveryResult(
            False, None, (), 0, "PATH_IS_NONE"
        )

    if not isinstance(value, (str, Path)):
        return PipfileDiscoveryResult(
            False, None, (), 0, "UNSUPPORTED_PATH_TYPE"
        )

    if isinstance(value, str):
        value = value.strip()
        if not value:
            return PipfileDiscoveryResult(
                False, None, (), 0, "PATH_IS_EMPTY"
            )

    raw = str(value)

    if "\x00" in raw:
        return PipfileDiscoveryResult(
            False, None, (), 0,
            "NULL_CHARACTER_NOT_ALLOWED"
        )

    try:
        root = Path(value).expanduser().resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        return PipfileDiscoveryResult(
            False, None, (), 0,
            f"PATH_RESOLUTION_FAILED:{type(exc).__name__}"
        )

    if not root.exists():
        return PipfileDiscoveryResult(
            False, root, (), 0, "PATH_DOES_NOT_EXIST"
        )

    if not root.is_dir():
        return PipfileDiscoveryResult(
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

    files = tuple(found)

    return PipfileDiscoveryResult(
        bool(files),
        root,
        files,
        len(files),
        "PIPFILE_DISCOVERED" if files else "PIPFILE_NOT_FOUND",
    )
