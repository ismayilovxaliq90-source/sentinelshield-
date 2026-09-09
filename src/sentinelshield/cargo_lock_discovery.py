from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


CARGO_LOCK_FILENAME = "Cargo.lock"


@dataclass(frozen=True)
class CargoLockDiscoveryResult:
    """
    Result of TASK 61 — Cargo.lock Discovery.
    """

    repository_root: Path
    files: tuple[Path, ...]
    found: bool
    status: str


def _resolve_repository_root(repository_root: str | Path) -> Path:
    if repository_root is None:
        raise TypeError("repository_root must not be None")

    if not isinstance(repository_root, (str, Path)):
        raise TypeError("repository_root must be str or pathlib.Path")

    if isinstance(repository_root, str):
        repository_root = repository_root.strip()

        if not repository_root:
            raise ValueError("repository_root must not be empty")

    if "\x00" in str(repository_root):
        raise ValueError(
            "repository_root must not contain NULL character"
        )

    root = Path(repository_root).expanduser()

    try:
        root = root.resolve(strict=True)
    except FileNotFoundError as exc:
        raise FileNotFoundError(
            f"repository root does not exist: {root}"
        ) from exc
    except OSError as exc:
        raise OSError(
            f"unable to resolve repository root: {root!s}"
        ) from exc

    if not root.is_dir():
        raise NotADirectoryError(
            f"repository root is not a directory: {root}"
        )

    return root


def _discover_directories(root: Path) -> tuple[Path, ...]:
    """
    Recursively discover directories without following directory symlinks.
    """
    directories: list[Path] = [root]
    index = 0

    while index < len(directories):
        current = directories[index]
        index += 1

        try:
            entries = sorted(
                current.iterdir(),
                key=lambda item: item.name.casefold(),
            )
        except OSError:
            continue

        for entry in entries:
            try:
                if entry.is_dir() and not entry.is_symlink():
                    directories.append(entry)
            except OSError:
                continue

    return tuple(directories)


def _inside_root(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def discover_cargo_lock(
    repository_root: str | Path,
) -> CargoLockDiscoveryResult:
    """
    TASK 61 — Cargo.lock Discovery.

    Performs read-only recursive discovery of Cargo.lock files.

    No Cargo command is executed.
    No package manager is executed.
    No file is created or modified.
    Directory symlinks are not traversed.
    Symlinked Cargo.lock files are ignored.
    """

    root = _resolve_repository_root(repository_root)

    discovered: set[Path] = set()

    for directory in _discover_directories(root):
        candidate = directory / CARGO_LOCK_FILENAME

        try:
            # Do not accept a symlink itself as the discovered lockfile.
            if candidate.is_symlink():
                continue

            if not candidate.is_file():
                continue

            resolved = candidate.resolve(strict=True)

            if not _inside_root(resolved, root):
                continue

            if resolved.name != CARGO_LOCK_FILENAME:
                continue

            if not resolved.is_file():
                continue

            discovered.add(resolved)

        except (OSError, RuntimeError):
            continue

    files = tuple(
        sorted(
            discovered,
            key=lambda path: path.as_posix(),
        )
    )

    return CargoLockDiscoveryResult(
        repository_root=root,
        files=files,
        found=bool(files),
        status="FOUND" if files else "NOT_FOUND",
    )


__all__ = [
    "CARGO_LOCK_FILENAME",
    "CargoLockDiscoveryResult",
    "discover_cargo_lock",
]
