from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


CARGO_TOML_FILENAME = "Cargo.toml"


@dataclass(frozen=True)
class CargoTomlDiscoveryResult:
    """
    Result of TASK 60 — Cargo.toml Discovery.
    """

    repository_root: Path
    files: tuple[Path, ...]
    found: bool
    status: str


def _resolve_repository_root(repository_root: str | Path) -> Path:
    """
    Validate and resolve repository_root without modifying the filesystem.
    """
    if repository_root is None:
        raise TypeError("repository_root must not be None")

    if not isinstance(repository_root, (str, Path)):
        raise TypeError("repository_root must be str or pathlib.Path")

    if isinstance(repository_root, str):
        if not repository_root.strip():
            raise ValueError("repository_root must not be empty")

        if "\x00" in repository_root:
            raise ValueError(
                "repository_root must not contain NULL character"
            )

        repository_root = repository_root.strip()

    else:
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


def _iter_directories(root: Path):
    """
    Recursively walk directories without following directory symlinks.

    The root itself is yielded.
    """
    stack = [root]

    while stack:
        current = stack.pop()
        yield current

        try:
            entries = list(current.iterdir())
        except OSError:
            continue

        directories: list[Path] = []

        for entry in entries:
            try:
                if entry.is_dir() and not entry.is_symlink():
                    directories.append(entry)
            except OSError:
                continue

        directories.sort(key=lambda path: path.name.casefold())

        stack.extend(reversed(directories))


def _is_within_root(path: Path, root: Path) -> bool:
    """
    Return True only when path is root itself or a descendant of root.
    """
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def discover_cargo_toml(
    repository_root: str | Path,
) -> CargoTomlDiscoveryResult:
    """
    TASK 60 — Cargo.toml Discovery.

    Read-only recursive discovery of Cargo.toml files.

    Guarantees:
    - no file creation
    - no file modification
    - no Cargo execution
    - no package-manager execution
    - directory symlinks are not traversed
    - results are deterministic
    """
    root = _resolve_repository_root(repository_root)

    discovered: list[Path] = []

    for directory in _iter_directories(root):
        candidate = directory / CARGO_TOML_FILENAME

        try:
            if not candidate.is_file():
                continue

            if candidate.is_symlink():
                continue

            resolved = candidate.resolve(strict=True)

            if not _is_within_root(resolved, root):
                continue

            discovered.append(resolved)

        except (OSError, RuntimeError):
            continue

    unique_files = tuple(sorted(set(discovered), key=lambda path: path.as_posix()))

    return CargoTomlDiscoveryResult(
        repository_root=root,
        files=unique_files,
        found=bool(unique_files),
        status="FOUND" if unique_files else "NOT_FOUND",
    )
