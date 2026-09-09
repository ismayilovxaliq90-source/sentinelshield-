from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


IGNORED_DIRECTORIES = {
    ".git", ".hg", ".svn", ".venv", "venv", "env", ".env",
    "node_modules", "__pycache__", ".pytest_cache",
    "build", "dist", "target",
}


@dataclass(frozen=True)
class PackageLockDiscoveryResult:
    found: bool
    root: Path | None
    files: tuple[Path, ...]
    count: int
    lockfile_version: int | None
    reason: str


def _read_lockfile_version(path: Path) -> int | None:
    try:
        import json

        data = json.loads(path.read_text(encoding="utf-8"))

        if not isinstance(data, dict):
            return None

        version = data.get("lockfileVersion")

        if isinstance(version, bool):
            return None

        if isinstance(version, int):
            return version

        if isinstance(version, float) and version.is_integer():
            return int(version)

        return None
    except (OSError, UnicodeError, ValueError):
        return None


def discover_package_lock(value: Any) -> PackageLockDiscoveryResult:
    if value is None:
        return PackageLockDiscoveryResult(
            False, None, (), 0, None, "PATH_IS_NONE"
        )

    if not isinstance(value, (str, Path)):
        return PackageLockDiscoveryResult(
            False, None, (), 0, None, "UNSUPPORTED_PATH_TYPE"
        )

    if isinstance(value, str):
        value = value.strip()
        if not value:
            return PackageLockDiscoveryResult(
                False, None, (), 0, None, "PATH_IS_EMPTY"
            )

    raw = str(value)

    if "\x00" in raw:
        return PackageLockDiscoveryResult(
            False, None, (), 0, None,
            "NULL_CHARACTER_NOT_ALLOWED"
        )

    try:
        root = Path(value).expanduser().resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        return PackageLockDiscoveryResult(
            False, None, (), 0, None,
            f"PATH_RESOLUTION_FAILED:{type(exc).__name__}"
        )

    if not root.exists():
        return PackageLockDiscoveryResult(
            False, root, (), 0, None, "PATH_DOES_NOT_EXIST"
        )

    if not root.is_dir():
        return PackageLockDiscoveryResult(
            False, root, (), 0, None, "PATH_IS_NOT_DIRECTORY"
        )

    matches: list[Path] = []
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

                if entry.is_file() and entry.name == "package-lock.json":
                    matches.append(entry.relative_to(root))

            except (OSError, ValueError):
                continue

    matches.sort(key=lambda p: p.as_posix())

    if not matches:
        return PackageLockDiscoveryResult(
            False,
            root,
            (),
            0,
            None,
            "PACKAGE_LOCK_NOT_FOUND",
        )

    lockfile_version = None

    if len(matches) == 1:
        lockfile_version = _read_lockfile_version(root / matches[0])

    return PackageLockDiscoveryResult(
        True,
        root,
        tuple(matches),
        len(matches),
        lockfile_version,
        "PACKAGE_LOCK_DISCOVERED",
    )


def discover_package_lockfile(
    value: Any,
) -> PackageLockDiscoveryResult:
    return discover_package_lock(value)
