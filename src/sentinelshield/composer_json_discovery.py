from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


COMPOSER_JSON_FILENAME = "composer.json"


@dataclass(frozen=True)
class ComposerJsonDiscoveryResult:
    """
    Result of TASK 62 — composer.json Discovery.
    """

    repository_root: Path
    files: tuple[Path, ...]
    found: bool
    status: str


def _resolve_repository_root(
    repository_root: str | Path,
) -> Path:
    """
    Validate and resolve the repository root.

    This function is read-only.
    """
    if repository_root is None:
        raise TypeError(
            "repository_root must not be None"
        )

    if not isinstance(
        repository_root,
        (str, Path),
    ):
        raise TypeError(
            "repository_root must be str or pathlib.Path"
        )

    if isinstance(repository_root, str):
        repository_root = repository_root.strip()

        if not repository_root:
            raise ValueError(
                "repository_root must not be empty"
            )

    raw_path = str(repository_root)

    if "\x00" in raw_path:
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
            f"unable to resolve repository root: {root}"
        ) from exc

    if not root.is_dir():
        raise NotADirectoryError(
            f"repository root is not a directory: {root}"
        )

    return root


def _walk_directories(
    root: Path,
):
    """
    Recursively walk directories without following
    directory symlinks.
    """
    stack = [root]

    while stack:
        current = stack.pop()
        yield current

        try:
            entries = sorted(
                current.iterdir(),
                key=lambda path: path.name.casefold(),
                reverse=True,
            )
        except (OSError, PermissionError):
            continue

        for entry in entries:
            try:
                if entry.is_symlink():
                    continue

                if entry.is_dir():
                    stack.append(entry)

            except (OSError, PermissionError):
                continue


def _is_within_root(
    path: Path,
    root: Path,
) -> bool:
    """
    Ensure a discovered file remains within repository_root.
    """
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def discover_composer_json(
    repository_root: str | Path,
) -> ComposerJsonDiscoveryResult:
    """
    TASK 62 — composer.json Discovery.

    Discovers composer.json files recursively inside the
    supplied repository root.

    Safety:
    - read-only
    - no Composer execution
    - no dependency installation
    - no build/test execution
    - no filesystem modification
    - no traversal through directory symlinks
    - symlinked composer.json files are ignored
    - deterministic ordering
    """

    root = _resolve_repository_root(
        repository_root
    )

    discovered: set[Path] = set()

    for directory in _walk_directories(root):
        candidate = directory / COMPOSER_JSON_FILENAME

        try:
            if candidate.is_symlink():
                continue

            if not candidate.is_file():
                continue

            resolved = candidate.resolve(
                strict=True
            )

            if not _is_within_root(
                resolved,
                root,
            ):
                continue

            if resolved.name != COMPOSER_JSON_FILENAME:
                continue

            if not resolved.is_file():
                continue

            discovered.add(resolved)

        except (
            OSError,
            RuntimeError,
        ):
            continue

    files = tuple(
        sorted(
            discovered,
            key=lambda path: path.as_posix(),
        )
    )

    return ComposerJsonDiscoveryResult(
        repository_root=root,
        files=files,
        found=bool(files),
        status=(
            "FOUND"
            if files
            else "NOT_FOUND"
        ),
    )


__all__ = [
    "COMPOSER_JSON_FILENAME",
    "ComposerJsonDiscoveryResult",
    "discover_composer_json",
]
