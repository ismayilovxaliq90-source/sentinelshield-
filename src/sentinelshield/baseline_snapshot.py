from __future__ import annotations

from dataclasses import dataclass, asdict
from hashlib import sha256
import json
from pathlib import Path
import subprocess
from typing import Optional


@dataclass(frozen=True)
class BaselineFile:
    path: str
    status: str
    fingerprint: str


@dataclass(frozen=True)
class BaselineSnapshot:
    repository_root: Path
    head: str
    branch: Optional[str]
    files: tuple[BaselineFile, ...]
    valid: bool
    reason: str

    def to_dict(self) -> dict:
        return {
            "repository_root": str(self.repository_root),
            "head": self.head,
            "branch": self.branch,
            "files": [
                asdict(item)
                for item in self.files
            ],
            "valid": self.valid,
            "reason": self.reason,
        }

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            indent=2,
            sort_keys=True,
        )


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


def _get_head(
    repository_root: Path,
    timeout: float,
) -> str:
    result = _run_git(
        repository_root,
        ["rev-parse", "HEAD"],
        timeout,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"Unable to determine HEAD: "
            f"{result.stderr.strip()}"
        )

    head = result.stdout.strip()

    if not head:
        raise RuntimeError("Repository HEAD is empty")

    return head


def _get_branch(
    repository_root: Path,
    timeout: float,
) -> Optional[str]:
    result = _run_git(
        repository_root,
        ["symbolic-ref", "--quiet", "--short", "HEAD"],
        timeout,
    )

    if result.returncode == 0:
        branch = result.stdout.strip()
        return branch or None

    return None


def _get_status(
    repository_root: Path,
    timeout: float,
) -> tuple[tuple[str, str], ...]:
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
            f"Unable to determine repository status: "
            f"{result.stderr.strip()}"
        )

    entries: list[tuple[str, str]] = []

    for line in result.stdout.splitlines():
        if not line:
            continue

        if len(line) < 3:
            raise RuntimeError(
                f"Invalid git status line: {line!r}"
            )

        status = line[:2]
        path = line[3:]

        entries.append((status, path))

    return tuple(entries)


def _tracked_files(
    repository_root: Path,
    timeout: float,
) -> tuple[str, ...]:
    result = _run_git(
        repository_root,
        [
            "ls-files",
            "-z",
        ],
        timeout,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"Unable to enumerate tracked files: "
            f"{result.stderr.strip()}"
        )

    return tuple(
        value
        for value in result.stdout.split("\0")
        if value
    )


def _status_map(
    statuses: tuple[tuple[str, str], ...],
) -> dict[str, str]:
    return {
        path: status
        for status, path in statuses
    }


def _fingerprint_path(
    repository_root: Path,
    relative_path: str,
) -> str:
    path = repository_root / relative_path

    if not path.exists() and not path.is_symlink():
        return "MISSING"

    if path.is_symlink():
        target = path.readlink().as_posix()

        return (
            "SYMLINK:"
            + sha256(
                target.encode("utf-8")
            ).hexdigest()
        )

    if path.is_file():
        digest = sha256()

        with path.open("rb") as handle:
            for chunk in iter(
                lambda: handle.read(1024 * 1024),
                b"",
            ):
                digest.update(chunk)

        return "FILE:" + digest.hexdigest()

    if path.is_dir():
        digest = sha256()

        children = sorted(
            child
            for child in path.rglob("*")
            if child.is_file() or child.is_symlink()
        )

        for child in children:
            relative = child.relative_to(
                repository_root
            ).as_posix()

            if child.is_symlink():
                child_value = (
                    "SYMLINK:"
                    + child.readlink().as_posix()
                )
            else:
                child_digest = sha256()

                with child.open("rb") as handle:
                    for chunk in iter(
                        lambda: handle.read(1024 * 1024),
                        b"",
                    ):
                        child_digest.update(chunk)

                child_value = (
                    "FILE:"
                    + child_digest.hexdigest()
                )

            digest.update(
                relative.encode("utf-8")
            )
            digest.update(b"\0")
            digest.update(child_value.encode("utf-8"))
            digest.update(b"\0")

        return "DIR:" + digest.hexdigest()

    try:
        stat = path.stat()

        metadata = (
            f"{stat.st_mode}:"
            f"{stat.st_size}:"
            f"{stat.st_mtime_ns}"
        )
    except OSError as error:
        metadata = f"STAT_ERROR:{error}"

    return "OTHER:" + sha256(
        metadata.encode("utf-8")
    ).hexdigest()


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
            files=(),
            valid=False,
            reason=f"INVALID_START_PATH: {error}",
        )

    if not start.exists():
        return BaselineSnapshot(
            repository_root=start,
            head="",
            branch=None,
            files=(),
            valid=False,
            reason="START_PATH_NOT_FOUND",
        )

    if not start.is_dir():
        return BaselineSnapshot(
            repository_root=start,
            head="",
            branch=None,
            files=(),
            valid=False,
            reason="START_PATH_NOT_DIRECTORY",
        )

    try:
        repository_root = _find_repository_root(
            start,
            timeout,
        )
    except subprocess.TimeoutExpired:
        return BaselineSnapshot(
            repository_root=start,
            head="",
            branch=None,
            files=(),
            valid=False,
            reason="GIT_ROOT_TIMEOUT",
        )
    except OSError as error:
        return BaselineSnapshot(
            repository_root=start,
            head="",
            branch=None,
            files=(),
            valid=False,
            reason=f"GIT_ROOT_ERROR: {error}",
        )

    if repository_root is None:
        return BaselineSnapshot(
            repository_root=start,
            head="",
            branch=None,
            files=(),
            valid=False,
            reason="NOT_A_GIT_REPOSITORY",
        )

    try:
        head = _get_head(
            repository_root,
            timeout,
        )

        branch = _get_branch(
            repository_root,
            timeout,
        )

        statuses = _get_status(
            repository_root,
            timeout,
        )

        tracked = _tracked_files(
            repository_root,
            timeout,
        )

        status_by_path = _status_map(statuses)

        paths = set(tracked)

        for _, path in statuses:
            paths.add(path)

        baseline_files: list[BaselineFile] = []

        for path in sorted(paths):
            status = status_by_path.get(
                path,
                "  ",
            )

            fingerprint = _fingerprint_path(
                repository_root,
                path,
            )

            baseline_files.append(
                BaselineFile(
                    path=path,
                    status=status,
                    fingerprint=fingerprint,
                )
            )

    except subprocess.TimeoutExpired:
        return BaselineSnapshot(
            repository_root=repository_root,
            head="",
            branch=None,
            files=(),
            valid=False,
            reason="BASELINE_GIT_TIMEOUT",
        )
    except (OSError, RuntimeError) as error:
        return BaselineSnapshot(
            repository_root=repository_root,
            head="",
            branch=None,
            files=(),
            valid=False,
            reason=f"BASELINE_CREATION_ERROR: {error}",
        )

    return BaselineSnapshot(
        repository_root=repository_root,
        head=head,
        branch=branch,
        files=tuple(baseline_files),
        valid=True,
        reason="BASELINE_SNAPSHOT_CREATED",
    )


__all__ = [
    "BaselineFile",
    "BaselineSnapshot",
    "create_baseline_snapshot",
]
