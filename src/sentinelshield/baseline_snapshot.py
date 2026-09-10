from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import subprocess
from typing import Optional


@dataclass(frozen=True)
class BaselineFile:
    path: str
    kind: str
    fingerprint: str


@dataclass(frozen=True)
class BaselineSnapshot:
    repository_root: Path
    head: str
    branch: Optional[str]
    detached_head: bool
    status: tuple[str, ...]
    files: tuple[BaselineFile, ...]
    valid: bool
    reason: str


def _run_git(
    repository_root: Path,
    arguments: list[str],
    timeout: float,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *arguments],
        cwd=repository_root,
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
    )


def _find_repository_root(
    start_path: Path,
    timeout: float,
) -> Optional[Path]:
    result = _run_git(
        start_path,
        ["rev-parse", "--show-toplevel"],
        timeout,
    )

    if result.returncode != 0:
        return None

    value = result.stdout.strip()

    if not value:
        return None

    return Path(value).resolve()


def _git_value(
    repository_root: Path,
    arguments: list[str],
    timeout: float,
) -> str:
    result = _run_git(
        repository_root,
        arguments,
        timeout,
    )

    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip()
            or "Git command failed"
        )

    value = result.stdout.strip()

    if not value:
        raise RuntimeError(
            f"Git returned empty output for: {arguments!r}"
        )

    return value


def _git_status(
    repository_root: Path,
    timeout: float,
) -> tuple[str, ...]:
    result = _run_git(
        repository_root,
        [
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--no-renames",
        ],
        timeout,
    )

    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip()
            or "git status failed"
        )

    return tuple(
        line
        for line in result.stdout.splitlines()
        if line
    )


def _hash_file(path: Path) -> str:
    digest = sha256()

    with path.open("rb") as handle:
        for chunk in iter(
            lambda: handle.read(1024 * 1024),
            b"",
        ):
            digest.update(chunk)

    return digest.hexdigest()


def _fingerprint_path(
    repository_root: Path,
    relative_path: str,
) -> tuple[str, str]:
    path = repository_root / relative_path

    if path.is_symlink():
        target = path.readlink().as_posix()

        return (
            "symlink",
            sha256(
                target.encode("utf-8")
            ).hexdigest(),
        )

    if path.is_file():
        return (
            "file",
            _hash_file(path),
        )

    if path.is_dir():
        digest = sha256()

        entries = sorted(
            child
            for child in path.rglob("*")
            if child.is_file() or child.is_symlink()
        )

        for child in entries:
            child_relative = (
                child.relative_to(repository_root)
                .as_posix()
            )

            if child.is_symlink():
                child_value = (
                    "symlink:"
                    + child.readlink().as_posix()
                )
            else:
                child_value = (
                    "file:"
                    + _hash_file(child)
                )

            digest.update(
                child_relative.encode("utf-8")
            )
            digest.update(b"\0")
            digest.update(
                child_value.encode("utf-8")
            )
            digest.update(b"\0")

        return (
            "directory",
            digest.hexdigest(),
        )

    metadata = path.stat()

    value = (
        f"{metadata.st_mode}:"
        f"{metadata.st_size}:"
        f"{metadata.st_mtime_ns}"
    )

    return (
        "other",
        sha256(
            value.encode("utf-8")
        ).hexdigest(),
    )


def _tracked_and_untracked_paths(
    repository_root: Path,
    timeout: float,
) -> tuple[str, ...]:
    result = _run_git(
        repository_root,
        [
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ],
        timeout,
    )

    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip()
            or "git ls-files failed"
        )

    raw = result.stdout

    paths = [
        item
        for item in raw.split("\0")
        if item
    ]

    return tuple(sorted(set(paths)))


def create_baseline_snapshot(
    start_path: str | Path,
    timeout: float = 10.0,
) -> BaselineSnapshot:
    try:
        start = (
            Path(start_path)
            .expanduser()
            .resolve()
        )
    except (OSError, RuntimeError, TypeError) as error:
        return BaselineSnapshot(
            repository_root=Path(".").resolve(),
            head="",
            branch=None,
            detached_head=False,
            status=(),
            files=(),
            valid=False,
            reason=f"INVALID_START_PATH: {error}",
        )

    if not start.exists():
        return BaselineSnapshot(
            repository_root=start,
            head="",
            branch=None,
            detached_head=False,
            status=(),
            files=(),
            valid=False,
            reason="START_PATH_NOT_FOUND",
        )

    if not start.is_dir():
        return BaselineSnapshot(
            repository_root=start,
            head="",
            branch=None,
            detached_head=False,
            status=(),
            files=(),
            valid=False,
            reason="START_PATH_NOT_DIRECTORY",
        )

    try:
        root = _find_repository_root(
            start,
            timeout,
        )
    except subprocess.TimeoutExpired:
        return BaselineSnapshot(
            repository_root=start,
            head="",
            branch=None,
            detached_head=False,
            status=(),
            files=(),
            valid=False,
            reason="GIT_ROOT_TIMEOUT",
        )
    except OSError as error:
        return BaselineSnapshot(
            repository_root=start,
            head="",
            branch=None,
            detached_head=False,
            status=(),
            files=(),
            valid=False,
            reason=f"GIT_ROOT_ERROR: {error}",
        )

    if root is None:
        return BaselineSnapshot(
            repository_root=start,
            head="",
            branch=None,
            detached_head=False,
            status=(),
            files=(),
            valid=False,
            reason="NOT_A_GIT_REPOSITORY",
        )

    try:
        head = _git_value(
            root,
            ["rev-parse", "HEAD"],
            timeout,
        )

        branch_result = _run_git(
            root,
            [
                "symbolic-ref",
                "--quiet",
                "--short",
                "HEAD",
            ],
            timeout,
        )

        if branch_result.returncode == 0:
            branch = branch_result.stdout.strip()
            detached_head = False
        else:
            branch = None
            detached_head = True

        status = _git_status(
            root,
            timeout,
        )

        paths = _tracked_and_untracked_paths(
            root,
            timeout,
        )

        files: list[BaselineFile] = []

        for relative_path in paths:
            kind, fingerprint = _fingerprint_path(
                root,
                relative_path,
            )

            files.append(
                BaselineFile(
                    path=relative_path,
                    kind=kind,
                    fingerprint=fingerprint,
                )
            )

    except subprocess.TimeoutExpired:
        return BaselineSnapshot(
            repository_root=root,
            head="",
            branch=None,
            detached_head=False,
            status=(),
            files=(),
            valid=False,
            reason="BASELINE_GIT_TIMEOUT",
        )
    except (OSError, RuntimeError) as error:
        return BaselineSnapshot(
            repository_root=root,
            head="",
            branch=None,
            detached_head=False,
            status=(),
            files=(),
            valid=False,
            reason=f"BASELINE_CREATION_ERROR: {error}",
        )

    return BaselineSnapshot(
        repository_root=root,
        head=head,
        branch=branch,
        detached_head=detached_head,
        status=status,
        files=tuple(files),
        valid=True,
        reason="BASELINE_SNAPSHOT_CREATED",
    )


def baseline_has_changes(
    snapshot: BaselineSnapshot,
) -> bool:
    return bool(snapshot.status)


__all__ = [
    "BaselineFile",
    "BaselineSnapshot",
    "create_baseline_snapshot",
    "baseline_has_changes",
]
