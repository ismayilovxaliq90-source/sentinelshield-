from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


IGNORED_DIRECTORIES = {
    ".git", ".hg", ".svn", ".venv", "venv", "env", ".env",
    "node_modules", "__pycache__", ".pytest_cache",
    "build", "dist", "target", ".next", ".nuxt",
}


@dataclass(frozen=True)
class YarnLockDiscoveryResult:
    found: bool
    root: Path | None
    files: tuple[Path, ...]
    file_count: int
    reason: str


def discover_yarn_lock(value: Any) -> YarnLockDiscoveryResult:
    if value is None:
        return YarnLockDiscoveryResult(
            False, None, (), 0, "PATH_IS_NONE"
        )

    if not isinstance(value, (str, Path)):
        return YarnLockDiscoveryResult(
            False, None, (), 0, "UNSUPPORTED_PATH_TYPE"
        )

    if isinstance(value, str):
        value = value.strip()
        if not value:
            return YarnLockDiscoveryResult(
                False, None, (), 0, "PATH_IS_EMPTY"
            )

    raw = str(value)

    if "\x00" in raw:
        return YarnLockDiscoveryResult(
            False, None, (), 0,
            "NULL_CHARACTER_NOT_ALLOWED"
        )

    try:
        root = Path(value).expanduser().resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        return YarnLockDiscoveryResult(
            False, None, (), 0,
            f"PATH_RESOLUTION_FAILED:{type(exc).__name__}"
        )

    if not root.exists():
        return YarnLockDiscoveryResult(
            False, root, (), 0, "PATH_DOES_NOT_EXIST"
        )

    if not root.is_dir():
        return YarnLockDiscoveryResult(
            False, root, (), 0, "PATH_IS_NOT_DIRECTORY"
        )

    discovered: list[Path] = []
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

                if entry.is_file() and entry.name == "yarn.lock":
                    discovered.append(entry.relative_to(root))

            except (OSError, ValueError):
                continue

    files = tuple(
        sorted(discovered, key=lambda p: p.as_posix())
    )

    if files:
        return YarnLockDiscoveryResult(
            True,
            root,
            files,
            len(files),
            "YARN_LOCK_FOUND",
        )

    return YarnLockDiscoveryResult(
        False,
        root,
        (),
        0,
        "YARN_LOCK_NOT_FOUND",
    )


def discover_yarn_locks(value: Any) -> YarnLockDiscoveryResult:
    return discover_yarn_lock(value)
