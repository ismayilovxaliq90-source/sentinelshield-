from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


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
class PackageJsonDiscoveryResult:
    found: bool
    root: Path | None
    files: tuple[Path, ...]
    count: int
    reason: str


def discover_package_json(value: Any) -> PackageJsonDiscoveryResult:
    if value is None:
        return PackageJsonDiscoveryResult(
            False, None, (), 0, "PATH_IS_NONE"
        )

    if not isinstance(value, (str, Path)):
        return PackageJsonDiscoveryResult(
            False, None, (), 0, "UNSUPPORTED_PATH_TYPE"
        )

    if isinstance(value, str):
        value = value.strip()
        if not value:
            return PackageJsonDiscoveryResult(
                False, None, (), 0, "PATH_IS_EMPTY"
            )

    raw = str(value)

    if "\x00" in raw:
        return PackageJsonDiscoveryResult(
            False, None, (), 0, "NULL_CHARACTER_NOT_ALLOWED"
        )

    try:
        root = Path(value).expanduser().resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        return PackageJsonDiscoveryResult(
            False,
            None,
            (),
            0,
            f"PATH_RESOLUTION_FAILED:{type(exc).__name__}",
        )

    if not root.exists():
        return PackageJsonDiscoveryResult(
            False, root, (), 0, "PATH_DOES_NOT_EXIST"
        )

    if not root.is_dir():
        return PackageJsonDiscoveryResult(
            False, root, (), 0, "PATH_IS_NOT_DIRECTORY"
        )

    discovered: list[Path] = []
    stack: list[Path] = [root]

    while stack:
        current = stack.pop()

        try:
            entries = sorted(
                current.iterdir(),
                key=lambda p: (not p.is_dir(), p.name),
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

                if entry.is_file() and entry.name == "package.json":
                    discovered.append(entry.relative_to(root))

            except (OSError, ValueError):
                continue

    discovered.sort(key=lambda p: p.as_posix())

    files = tuple(discovered)

    return PackageJsonDiscoveryResult(
        found=bool(files),
        root=root,
        files=files,
        count=len(files),
        reason=(
            "PACKAGE_JSON_FOUND"
            if files
            else "PACKAGE_JSON_NOT_FOUND"
        ),
    )


def discover_package_json_files(
    value: Any,
) -> PackageJsonDiscoveryResult:
    return discover_package_json(value)
