from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


TARGET_NAME = "pipfile.lock"

IGNORED_DIRECTORIES = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    ".env",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    "build",
    "dist",
    "target",
}


@dataclass(frozen=True)
class PipfileLockDiscoveryResult:
    found: bool
    root: Path | None
    files: tuple[Path, ...]
    count: int
    reason: str


def discover_pipfile_lock(value: Any) -> PipfileLockDiscoveryResult:
    if value is None:
        return PipfileLockDiscoveryResult(
            False, None, (), 0, "PATH_IS_NONE"
        )

    if not isinstance(value, (str, Path)):
        return PipfileLockDiscoveryResult(
            False, None, (), 0, "UNSUPPORTED_PATH_TYPE"
        )

    if isinstance(value, str):
        value = value.strip()
        if not value:
            return PipfileLockDiscoveryResult(
                False, None, (), 0, "PATH_IS_EMPTY"
            )

    raw = str(value)

    if "\x00" in raw:
        return PipfileLockDiscoveryResult(
            False, None, (), 0, "NULL_CHARACTER_NOT_ALLOWED"
        )

    try:
        root = Path(value).expanduser().resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        return PipfileLockDiscoveryResult(
            False,
            None,
            (),
            0,
            f"PATH_RESOLUTION_FAILED:{type(exc).__name__}",
        )

    if not root.exists():
        return PipfileLockDiscoveryResult(
            False, root, (), 0, "PATH_DOES_NOT_EXIST"
        )

    if not root.is_dir():
        return PipfileLockDiscoveryResult(
            False, root, (), 0, "PATH_IS_NOT_DIRECTORY"
        )

    discovered: list[Path] = []
    stack: list[Path] = [root]

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

                if entry.is_file() and entry.name.lower() == TARGET_NAME:
                    discovered.append(entry.relative_to(root))

            except (OSError, ValueError):
                continue

    discovered.sort(key=lambda p: p.as_posix())

    return PipfileLockDiscoveryResult(
        bool(discovered),
        root,
        tuple(discovered),
        len(discovered),
        "PIPFILE_LOCK_DISCOVERED"
        if discovered
        else "PIPFILE_LOCK_NOT_FOUND",
    )
