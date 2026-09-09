from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


DOTNET_PROJECT_EXTENSIONS = frozenset({
    ".csproj",
    ".fsproj",
    ".vbproj",
})


@dataclass(frozen=True)
class DotNetProjectFileDiscoveryResult:
    repository_root: Optional[Path]
    files: tuple[Path, ...]
    found: bool
    status: str


def _resolve_root(
    repository_root: object,
) -> tuple[Optional[Path], str]:
    if repository_root is None:
        return None, "PATH_IS_NONE"

    if not isinstance(repository_root, (str, Path)):
        return None, "UNSUPPORTED_PATH_TYPE"

    raw = str(repository_root).strip()

    if not raw:
        return None, "PATH_IS_EMPTY"

    if "\x00" in raw:
        return None, "NULL_CHARACTER_NOT_ALLOWED"

    try:
        root = Path(raw).expanduser().resolve(strict=True)
    except FileNotFoundError:
        return None, "PATH_NOT_FOUND"
    except OSError:
        return None, "PATH_RESOLUTION_ERROR"

    try:
        if not root.is_dir():
            return None, "NOT_A_DIRECTORY"
    except OSError:
        return None, "FILESYSTEM_ERROR"

    return root, "VALID"


def _inside_root(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def discover_dotnet_project_files(
    repository_root: object,
) -> DotNetProjectFileDiscoveryResult:
    root, status = _resolve_root(repository_root)

    if root is None:
        return DotNetProjectFileDiscoveryResult(
            repository_root=None,
            files=(),
            found=False,
            status=status,
        )

    discovered: set[Path] = set()

    try:
        for current_root, dir_names, file_names in os.walk(
            root,
            topdown=True,
            followlinks=False,
        ):
            current = Path(current_root)

            dir_names[:] = [
                name
                for name in dir_names
                if not (current / name).is_symlink()
            ]

            for filename in file_names:
                candidate = current / filename

                if candidate.suffix.lower() not in DOTNET_PROJECT_EXTENSIONS:
                    continue

                try:
                    if candidate.is_symlink():
                        continue

                    if not candidate.is_file():
                        continue

                    resolved = candidate.resolve(strict=True)

                    if not resolved.is_file():
                        continue

                    if not _inside_root(resolved, root):
                        continue

                    discovered.add(resolved)

                except (OSError, RuntimeError):
                    continue

    except (OSError, RuntimeError):
        return DotNetProjectFileDiscoveryResult(
            repository_root=root,
            files=(),
            found=False,
            status="DISCOVERY_ERROR",
        )

    files = tuple(sorted(discovered, key=str))

    return DotNetProjectFileDiscoveryResult(
        repository_root=root,
        files=files,
        found=bool(files),
        status="FOUND" if files else "NOT_FOUND",
    )
