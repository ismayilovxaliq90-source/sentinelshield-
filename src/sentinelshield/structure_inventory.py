from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


IGNORED_DIRECTORIES = {
    ".git", ".hg", ".svn", ".venv", "venv",
    "node_modules", "__pycache__", ".pytest_cache",
    "build", "dist", "target",
}


@dataclass(frozen=True)
class StructureInventoryResult:
    found: bool
    root: Path | None
    files: tuple[Path, ...]
    directories: tuple[Path, ...]
    file_count: int
    directory_count: int
    max_depth: int
    reason: str


class StructureInventory:
    def collect(self, value: Any) -> StructureInventoryResult:
        if value is None:
            return StructureInventoryResult(
                False, None, (), (), 0, 0, 0, "PATH_IS_NONE"
            )

        if not isinstance(value, (str, Path)):
            return StructureInventoryResult(
                False, None, (), (), 0, 0, 0,
                "UNSUPPORTED_PATH_TYPE"
            )

        if isinstance(value, str):
            value = value.strip()
            if not value:
                return StructureInventoryResult(
                    False, None, (), (), 0, 0, 0,
                    "PATH_IS_EMPTY"
                )

        raw = str(value)

        if "\x00" in raw:
            return StructureInventoryResult(
                False, None, (), (), 0, 0, 0,
                "NULL_CHARACTER_NOT_ALLOWED"
            )

        try:
            root = Path(value).expanduser().resolve(strict=False)
        except (OSError, RuntimeError, ValueError) as exc:
            return StructureInventoryResult(
                False, None, (), (), 0, 0, 0,
                f"PATH_RESOLUTION_FAILED:{type(exc).__name__}"
            )

        if not root.exists():
            return StructureInventoryResult(
                False, root, (), (), 0, 0, 0,
                "PATH_DOES_NOT_EXIST"
            )

        if not root.is_dir():
            return StructureInventoryResult(
                False, root, (), (), 0, 0, 0,
                "PATH_IS_NOT_DIRECTORY"
            )

        files: list[Path] = []
        directories: list[Path] = []
        max_depth = 0
        stack: list[tuple[Path, int]] = [(root, 0)]

        while stack:
            current, depth = stack.pop()

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

                        relative = entry.relative_to(root)
                        entry_depth = len(relative.parts)

                        directories.append(relative)
                        max_depth = max(max_depth, entry_depth)
                        stack.append((entry, entry_depth))
                        continue

                    if entry.is_file():
                        relative = entry.relative_to(root)
                        files.append(relative)
                        file_depth = len(relative.parts) - 1
                        max_depth = max(max_depth, file_depth)

                except (OSError, ValueError):
                    continue

        files.sort(key=lambda p: p.as_posix())
        directories.sort(key=lambda p: p.as_posix())

        return StructureInventoryResult(
            True,
            root,
            tuple(files),
            tuple(directories),
            len(files),
            len(directories),
            max_depth,
            "STRUCTURE_INVENTORY_CREATED",
        )


def collect_structure_inventory(
    value: Any,
) -> StructureInventoryResult:
    return StructureInventory().collect(value)
