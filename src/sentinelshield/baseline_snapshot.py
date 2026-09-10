from __future__ import annotations

import hashlib
import json
import os
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


class BaselineSnapshotError(RuntimeError):
    """Raised when a baseline snapshot cannot be created."""


@dataclass(frozen=True)
class BaselineFile:
    path: str
    kind: str
    fingerprint: str


@dataclass(frozen=True)
class BaselineSnapshot:
    repository_root: str
    head: str
    branch: str | None
    tracked_files: tuple[BaselineFile, ...]
    status_entries: tuple[str, ...]
    files: tuple[BaselineFile, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            indent=2,
        )


def _run_git(
    root: Path,
    args: list[str],
    timeout: float,
) -> str:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise BaselineSnapshotError(
            f"Git command failed: git {' '.join(args)}"
        ) from exc

    return result.stdout


def _get_branch(
    root: Path,
    timeout: float,
) -> str | None:
    """
    Return the current branch name.

    A detached HEAD is valid repository state for a baseline snapshot.
    In that case git symbolic-ref exits with code 1 and branch is None.

    Other failures remain errors.
    """
    try:
        result = subprocess.run(
            [
                "git",
                "symbolic-ref",
                "--quiet",
                "--short",
                "HEAD",
            ],
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise BaselineSnapshotError(
            "Git command failed: "
            "git symbolic-ref --quiet --short HEAD"
        ) from exc

    if result.returncode == 0:
        branch = result.stdout.strip()
        return branch or None

    if result.returncode == 1:
        return None

    raise BaselineSnapshotError(
        "Git command failed: "
        "git symbolic-ref --quiet --short HEAD"
    )


def _fingerprint_file(path: Path) -> str:
    digest = hashlib.sha256()

    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError as exc:
        raise BaselineSnapshotError(
            f"Unable to fingerprint file: {path}"
        ) from exc

    return digest.hexdigest()


def _fingerprint_symlink(path: Path) -> str:
    try:
        target = os.readlink(path)
    except OSError as exc:
        raise BaselineSnapshotError(
            f"Unable to inspect symlink: {path}"
        ) from exc

    return hashlib.sha256(
        target.encode("utf-8", errors="surrogateescape")
    ).hexdigest()


def _fingerprint_directory(path: Path) -> str:
    digest = hashlib.sha256()

    try:
        entries = sorted(
            entry.name
            for entry in path.iterdir()
        )
    except OSError as exc:
        raise BaselineSnapshotError(
            f"Unable to inspect directory: {path}"
        ) from exc

    for name in entries:
        digest.update(
            name.encode(
                "utf-8",
                errors="surrogateescape",
            )
        )
        digest.update(b"\0")

    return digest.hexdigest()


def _snapshot_path(
    root: Path,
    relative_path: str,
) -> BaselineFile:
    path = root / relative_path

    try:
        if path.is_symlink():
            return BaselineFile(
                path=relative_path,
                kind="symlink",
                fingerprint=_fingerprint_symlink(path),
            )

        if path.is_file():
            return BaselineFile(
                path=relative_path,
                kind="file",
                fingerprint=_fingerprint_file(path),
            )

        if path.is_dir():
            return BaselineFile(
                path=relative_path,
                kind="directory",
                fingerprint=_fingerprint_directory(path),
            )

        stat = path.stat()
        metadata = (
            f"{stat.st_mode}:"
            f"{stat.st_size}:"
            f"{stat.st_mtime_ns}"
        )

        return BaselineFile(
            path=relative_path,
            kind="other",
            fingerprint=hashlib.sha256(
                metadata.encode("utf-8")
            ).hexdigest(),
        )
    except OSError as exc:
        raise BaselineSnapshotError(
            f"Unable to inspect path: {path}"
        ) from exc


def _get_tracked_paths(
    root: Path,
    timeout: float,
) -> tuple[str, ...]:
    output = _run_git(
        root,
        ["ls-files", "-z"],
        timeout,
    )

    if not output:
        return ()

    return tuple(
        item
        for item in output.split("\0")
        if item
    )


def _get_status_entries(
    root: Path,
    timeout: float,
) -> tuple[str, ...]:
    output = _run_git(
        root,
        [
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--no-renames",
        ],
        timeout,
    )

    if not output:
        return ()

    return tuple(
        line
        for line in output.splitlines()
        if line
    )


def create_baseline_snapshot(
    start_path: str | os.PathLike[str],
    timeout: float = 10.0,
) -> BaselineSnapshot:
    if isinstance(start_path, (str, os.PathLike)) is False:
        raise BaselineSnapshotError(
            "start_path must be a path"
        )

    try:
        root = Path(start_path).expanduser().resolve()
    except OSError as exc:
        raise BaselineSnapshotError(
            "Unable to resolve repository path"
        ) from exc

    if not root.exists():
        raise BaselineSnapshotError(
            f"Repository path does not exist: {root}"
        )

    if not root.is_dir():
        raise BaselineSnapshotError(
            f"Repository path is not a directory: {root}"
        )

    try:
        git_root = _run_git(
            root,
            ["rev-parse", "--show-toplevel"],
            timeout,
        ).strip()
    except BaselineSnapshotError:
        raise

    if not git_root:
        raise BaselineSnapshotError(
            "Unable to determine repository root"
        )

    repository_root = Path(git_root).resolve()

    if repository_root != root:
        root = repository_root

    head = _run_git(
        root,
        ["rev-parse", "HEAD"],
        timeout,
    ).strip()

    if not head:
        raise BaselineSnapshotError(
            "Repository HEAD is empty"
        )

    branch = _get_branch(
        root,
        timeout,
    )

    tracked_paths = _get_tracked_paths(
        root,
        timeout,
    )

    status_entries = _get_status_entries(
        root,
        timeout,
    )

    tracked_files = tuple(
        _snapshot_path(root, relative_path)
        for relative_path in tracked_paths
    )

    return BaselineSnapshot(
        repository_root=str(root),
        head=head,
        branch=branch,
        tracked_files=tracked_files,
        status_entries=status_entries,
        files=tracked_files,
    )
