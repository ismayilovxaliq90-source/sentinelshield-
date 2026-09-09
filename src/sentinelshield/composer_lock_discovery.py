from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple


COMPOSER_LOCK_FILENAME = "composer.lock"


@dataclass(frozen=True)
class ComposerLockDiscoveryResult:
    repository_root: Optional[Path]
    files: Tuple[Path, ...]
    found: bool
    status: str


def _resolve_root(repository_root: object) -> tuple[Optional[Path], str]:
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

    if not root.is_dir():
        return None, "NOT_A_DIRECTORY"

    return root, "VALID"


def _is_within_root(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root)
        return True
    except ValueError:
        return False


def discover_composer_lock(repository_root: object) -> ComposerLockDiscoveryResult:
    root, validation_status = _resolve_root(repository_root)

    if root is None:
        return ComposerLockDiscoveryResult(
            repository_root=None,
            files=(),
            found=False,
            status=validation_status,
        )

    discovered: list[Path] = []

    try:
        for current_root, dir_names, file_names in __import__("os").walk(
            root,
            topdown=True,
            followlinks=False,
        ):
            current = Path(current_root)

            # Never traverse symlink directories.
            safe_dirs = []
            for name in dir_names:
                candidate = current / name
                try:
                    if candidate.is_symlink():
                        continue
                except OSError:
                    continue
                safe_dirs.append(name)
            dir_names[:] = safe_dirs

            for filename in file_names:
                if filename != COMPOSER_LOCK_FILENAME:
                    continue

                candidate = current / filename

                try:
                    if candidate.is_symlink():
                        continue

                    resolved = candidate.resolve(strict=True)

                    if not resolved.is_file():
                        continue

                    if not _is_within_root(resolved, root):
                        continue

                    discovered.append(resolved)
                except OSError:
                    continue

    except OSError:
        return ComposerLockDiscoveryResult(
            repository_root=root,
            files=tuple(),
            found=False,
            status="DISCOVERY_ERROR",
        )

    # Deterministic output and duplicate protection.
    unique_files = tuple(sorted(set(discovered), key=lambda p: str(p)))

    return ComposerLockDiscoveryResult(
        repository_root=root,
        files=unique_files,
        found=bool(unique_files),
        status="FOUND" if unique_files else "NOT_FOUND",
    )
