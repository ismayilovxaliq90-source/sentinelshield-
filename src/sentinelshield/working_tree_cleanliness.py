from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import subprocess
from typing import Optional


# ============================================================
# TASK 182 — WORKING TREE CLEANLINESS EVALUATION
#
# SERVER-ONLY EXECUTION
#
# This module evaluates the actual Git working tree.
# Real execution belongs in the isolated Server / GitHub
# Actions runner, not in the developer's local WSL execution
# phase.
#
# TASK 183 separately handles protection of pre-existing
# changes.
# ============================================================


class WorkingTreeCleanlinessError(ValueError):
    """Raised when Task 182 input is invalid."""


@dataclass(frozen=True)
class WorkingTreeChange:
    """
    One Git working-tree change.

    status:
        Two-character porcelain-v1 status code.

    path:
        Repository-relative path reported by Git.

    index_status:
        First porcelain status character.

    worktree_status:
        Second porcelain status character.
    """

    status: str
    path: str
    index_status: str
    worktree_status: str


@dataclass(frozen=True)
class WorkingTreeCleanlinessResult:
    """
    Complete Task 182 evaluation result.
    """

    valid: bool
    repository_root: Optional[str]
    clean: bool
    changed: bool
    change_count: int
    changes: tuple[WorkingTreeChange, ...]
    return_code: Optional[int]
    reason: str


def _validate_repository_path(
    repository_path: str | Path,
) -> Path:
    if isinstance(repository_path, bool):
        raise WorkingTreeCleanlinessError(
            "repository_path must be a string or Path"
        )

    if not isinstance(repository_path, (str, Path)):
        raise WorkingTreeCleanlinessError(
            "repository_path must be a string or Path"
        )

    raw = str(repository_path)

    if not raw.strip():
        raise WorkingTreeCleanlinessError(
            "repository_path must not be empty"
        )

    if "\x00" in raw:
        raise WorkingTreeCleanlinessError(
            "repository_path contains a NULL character"
        )

    return Path(raw).expanduser().resolve()


def _validate_timeout(timeout: float) -> None:
    if isinstance(timeout, bool):
        raise WorkingTreeCleanlinessError(
            "timeout must be a positive number"
        )

    if not isinstance(timeout, (int, float)):
        raise WorkingTreeCleanlinessError(
            "timeout must be a positive number"
        )

    if timeout <= 0 or timeout > 120:
        raise WorkingTreeCleanlinessError(
            "timeout must be greater than 0 and at most 120 seconds"
        )


def _run_git(
    arguments: list[str],
    repository_root: Path,
    timeout: float,
) -> subprocess.CompletedProcess[str]:
    """
    Execute Git without a shell.

    No user-controlled string is interpolated into a shell
    command.
    """
    return subprocess.run(
        ["git", *arguments],
        cwd=str(repository_root),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
        shell=False,
    )


def _parse_porcelain_line(
    line: str,
) -> Optional[WorkingTreeChange]:
    """
    Parse one Git porcelain-v1 status line.

    Normal porcelain-v1 entries have two status characters
    followed by a space and then the path.

    Examples:

        M  file.py
         M file.py
        MM file.py
        ?? new.py
        D  deleted.py
        A  added.py
        R  old.py -> new.py

    Empty lines are ignored.
    """
    if not line:
        return None

    if len(line) < 3:
        return WorkingTreeChange(
            status=line[:2].ljust(2),
            path=line[2:].strip(),
            index_status=line[0] if line else " ",
            worktree_status=line[1] if len(line) > 1 else " ",
        )

    return WorkingTreeChange(
        status=line[:2],
        path=line[3:],
        index_status=line[0],
        worktree_status=line[1],
    )


def _parse_status_output(
    output: str,
) -> tuple[WorkingTreeChange, ...]:
    changes: list[WorkingTreeChange] = []

    for line in output.splitlines():
        change = _parse_porcelain_line(line)

        if change is not None:
            changes.append(change)

    return tuple(changes)


def evaluate_working_tree_cleanliness(
    repository_path: str | Path,
    *,
    timeout: float = 10.0,
) -> WorkingTreeCleanlinessResult:
    """
    Evaluate whether a Git working tree is completely clean.

    Clean means:
        - no staged changes
        - no unstaged changes
        - no untracked files
        - no added/deleted/modified/renamed/copied entries

    Ignored files are not included because Git status is run
    without --ignored.

    This function does not modify the repository.
    It only reads Git state.

    TASK 183 is responsible for deciding how pre-existing
    changes are protected.
    """
    _validate_timeout(timeout)

    root_input = _validate_repository_path(repository_path)

    if not root_input.exists():
        return WorkingTreeCleanlinessResult(
            valid=False,
            repository_root=None,
            clean=False,
            changed=False,
            change_count=0,
            changes=(),
            return_code=None,
            reason="REPOSITORY_PATH_NOT_FOUND",
        )

    if not root_input.is_dir():
        return WorkingTreeCleanlinessResult(
            valid=False,
            repository_root=None,
            clean=False,
            changed=False,
            change_count=0,
            changes=(),
            return_code=None,
            reason="REPOSITORY_PATH_NOT_DIRECTORY",
        )

    # --------------------------------------------------------
    # First establish the actual repository root.
    # --------------------------------------------------------
    try:
        root_result = _run_git(
            ["rev-parse", "--show-toplevel"],
            root_input,
            timeout,
        )
    except subprocess.TimeoutExpired:
        return WorkingTreeCleanlinessResult(
            valid=False,
            repository_root=None,
            clean=False,
            changed=False,
            change_count=0,
            changes=(),
            return_code=None,
            reason="REPOSITORY_ROOT_TIMEOUT",
        )
    except FileNotFoundError:
        return WorkingTreeCleanlinessResult(
            valid=False,
            repository_root=None,
            clean=False,
            changed=False,
            change_count=0,
            changes=(),
            return_code=None,
            reason="GIT_NOT_AVAILABLE",
        )
    except OSError:
        return WorkingTreeCleanlinessResult(
            valid=False,
            repository_root=None,
            clean=False,
            changed=False,
            change_count=0,
            changes=(),
            return_code=None,
            reason="GIT_EXECUTION_ERROR",
        )

    if root_result.returncode != 0:
        return WorkingTreeCleanlinessResult(
            valid=False,
            repository_root=None,
            clean=False,
            changed=False,
            change_count=0,
            changes=(),
            return_code=root_result.returncode,
            reason="NOT_A_GIT_REPOSITORY",
        )

    repository_root_text = root_result.stdout.strip()

    if not repository_root_text:
        return WorkingTreeCleanlinessResult(
            valid=False,
            repository_root=None,
            clean=False,
            changed=False,
            change_count=0,
            changes=(),
            return_code=root_result.returncode,
            reason="REPOSITORY_ROOT_NOT_DETECTED",
        )

    repository_root = Path(repository_root_text).resolve()

    # --------------------------------------------------------
    # Git status:
    #
    # --porcelain=v1
    #     Stable machine-readable format.
    #
    # --untracked-files=all
    #     Detect untracked files individually rather than
    #     collapsing untracked directories.
    #
    # No --ignored:
    #     Ignored files do not make the working tree dirty.
    # --------------------------------------------------------
    try:
        status_result = _run_git(
            [
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            ],
            repository_root,
            timeout,
        )
    except subprocess.TimeoutExpired:
        return WorkingTreeCleanlinessResult(
            valid=False,
            repository_root=str(repository_root),
            clean=False,
            changed=False,
            change_count=0,
            changes=(),
            return_code=None,
            reason="WORKING_TREE_STATUS_TIMEOUT",
        )
    except FileNotFoundError:
        return WorkingTreeCleanlinessResult(
            valid=False,
            repository_root=str(repository_root),
            clean=False,
            changed=False,
            change_count=0,
            changes=(),
            return_code=None,
            reason="GIT_NOT_AVAILABLE",
        )
    except OSError:
        return WorkingTreeCleanlinessResult(
            valid=False,
            repository_root=str(repository_root),
            clean=False,
            changed=False,
            change_count=0,
            changes=(),
            return_code=None,
            reason="GIT_EXECUTION_ERROR",
        )

    if status_result.returncode != 0:
        return WorkingTreeCleanlinessResult(
            valid=False,
            repository_root=str(repository_root),
            clean=False,
            changed=False,
            change_count=0,
            changes=(),
            return_code=status_result.returncode,
            reason="WORKING_TREE_STATUS_FAILED",
        )

    changes = _parse_status_output(status_result.stdout)

    changed = bool(changes)
    clean = not changed

    if clean:
        return WorkingTreeCleanlinessResult(
            valid=True,
            repository_root=str(repository_root),
            clean=True,
            changed=False,
            change_count=0,
            changes=(),
            return_code=status_result.returncode,
            reason="WORKING_TREE_CLEAN",
        )

    return WorkingTreeCleanlinessResult(
        valid=False,
        repository_root=str(repository_root),
        clean=False,
        changed=True,
        change_count=len(changes),
        changes=changes,
        return_code=status_result.returncode,
        reason="WORKING_TREE_DIRTY",
    )


def working_tree_cleanliness_evaluation(
    repository_path: str | Path,
    *,
    timeout: float = 10.0,
) -> WorkingTreeCleanlinessResult:
    """Compatibility alias."""
    return evaluate_working_tree_cleanliness(
        repository_path,
        timeout=timeout,
    )


def check_working_tree_cleanliness(
    repository_path: str | Path,
    *,
    timeout: float = 10.0,
) -> WorkingTreeCleanlinessResult:
    """Compatibility alias."""
    return evaluate_working_tree_cleanliness(
        repository_path,
        timeout=timeout,
    )


def is_working_tree_clean(
    repository_path: str | Path,
    *,
    timeout: float = 10.0,
) -> bool:
    """Return only the clean/dirty result."""
    return evaluate_working_tree_cleanliness(
        repository_path,
        timeout=timeout,
    ).clean


__all__ = [
    "WorkingTreeCleanlinessError",
    "WorkingTreeChange",
    "WorkingTreeCleanlinessResult",
    "evaluate_working_tree_cleanliness",
    "working_tree_cleanliness_evaluation",
    "check_working_tree_cleanliness",
    "is_working_tree_clean",
]
