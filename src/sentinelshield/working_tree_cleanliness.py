from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import subprocess
from typing import Optional


@dataclass(frozen=True)
class WorkingTreeChange:
    status: str
    path: str


@dataclass(frozen=True)
class WorkingTreeResult:
    valid: bool
    repository_root: Optional[Path]
    clean: bool
    changed: bool
    changes: tuple[WorkingTreeChange, ...]
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

    root_text = result.stdout.strip()

    if not root_text:
        return None

    return Path(root_text)


def _parse_porcelain_status(
    output: str,
) -> tuple[WorkingTreeChange, ...]:
    changes: list[WorkingTreeChange] = []

    for line in output.splitlines():
        if not line:
            continue

        if len(line) < 3:
            continue

        status = line[:2]
        path = line[3:]

        changes.append(
            WorkingTreeChange(
                status=status,
                path=path,
            )
        )

    return tuple(changes)


def evaluate_working_tree_cleanliness(
    start_path: str | Path,
    timeout: float = 10.0,
) -> WorkingTreeResult:
    try:
        start = Path(start_path).expanduser().resolve()
    except (OSError, RuntimeError, TypeError) as error:
        return WorkingTreeResult(
            valid=False,
            repository_root=None,
            clean=False,
            changed=False,
            changes=(),
            reason=f"INVALID_START_PATH: {error}",
        )

    if not start.exists():
        return WorkingTreeResult(
            valid=False,
            repository_root=None,
            clean=False,
            changed=False,
            changes=(),
            reason="START_PATH_NOT_FOUND",
        )

    if not start.is_dir():
        return WorkingTreeResult(
            valid=False,
            repository_root=None,
            clean=False,
            changed=False,
            changes=(),
            reason="START_PATH_NOT_DIRECTORY",
        )

    try:
        repository_root = _find_repository_root(
            start,
            timeout,
        )
    except subprocess.TimeoutExpired:
        return WorkingTreeResult(
            valid=False,
            repository_root=None,
            clean=False,
            changed=False,
            changes=(),
            reason="GIT_TIMEOUT",
        )
    except OSError as error:
        return WorkingTreeResult(
            valid=False,
            repository_root=None,
            clean=False,
            changed=False,
            changes=(),
            reason=f"GIT_EXECUTION_ERROR: {error}",
        )

    if repository_root is None:
        return WorkingTreeResult(
            valid=False,
            repository_root=None,
            clean=False,
            changed=False,
            changes=(),
            reason="NOT_A_GIT_REPOSITORY",
        )

    try:
        status_result = _run_git(
            repository_root,
            [
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
                "--no-renames",
            ],
            timeout,
        )
    except subprocess.TimeoutExpired:
        return WorkingTreeResult(
            valid=False,
            repository_root=repository_root,
            clean=False,
            changed=False,
            changes=(),
            reason="GIT_STATUS_TIMEOUT",
        )
    except OSError as error:
        return WorkingTreeResult(
            valid=False,
            repository_root=repository_root,
            clean=False,
            changed=False,
            changes=(),
            reason=f"GIT_STATUS_EXECUTION_ERROR: {error}",
        )

    if status_result.returncode != 0:
        return WorkingTreeResult(
            valid=False,
            repository_root=repository_root,
            clean=False,
            changed=False,
            changes=(),
            reason="GIT_STATUS_FAILED",
        )

    changes = _parse_porcelain_status(
        status_result.stdout
    )

    clean = len(changes) == 0

    return WorkingTreeResult(
        valid=True,
        repository_root=repository_root,
        clean=clean,
        changed=not clean,
        changes=changes,
        reason="WORKING_TREE_CLEAN" if clean else "WORKING_TREE_DIRTY",
    )


__all__ = [
    "WorkingTreeChange",
    "WorkingTreeResult",
    "evaluate_working_tree_cleanliness",
]
