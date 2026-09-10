from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import subprocess
from typing import Optional


# ============================================================
# TASK 181 — REPOSITORY STATE VALIDATION
# Server-only execution task.
#
# IMPORTANT:
# This module is intended to execute only inside an isolated
# server / GitHub Actions runner.
# ============================================================


class RepositoryStateValidationError(ValueError):
    """Raised when repository-state validation input is invalid."""


@dataclass(frozen=True)
class RepositoryStateResult:
    valid: bool
    repository_root: Optional[str]
    git_directory: Optional[str]
    head: Optional[str]
    branch: Optional[str]
    detached_head: bool
    git_version: Optional[str]
    return_code: Optional[int]
    reason: str


_GIT_VERSION_RE = re.compile(
    r"\bgit\s+version\s+(\d+)(?:\.(\d+))?(?:\.(\d+))?",
    re.IGNORECASE,
)


def _validate_path_input(repository_path: str | Path) -> Path:
    if isinstance(repository_path, bool):
        raise RepositoryStateValidationError(
            "repository_path must be a string or Path"
        )

    if not isinstance(repository_path, (str, Path)):
        raise RepositoryStateValidationError(
            "repository_path must be a string or Path"
        )

    raw = str(repository_path)

    if not raw.strip():
        raise RepositoryStateValidationError(
            "repository_path must not be empty"
        )

    if "\x00" in raw:
        raise RepositoryStateValidationError(
            "repository_path contains a NULL character"
        )

    return Path(raw).expanduser().resolve()


def _run_git(
    args: list[str],
    cwd: Path,
    timeout: float,
) -> subprocess.CompletedProcess[str]:
    """
    Execute a fixed Git command without shell interpretation.

    No shell=True is ever used.
    Arguments are generated internally and are not interpreted
    as shell commands.
    """
    return subprocess.run(
        ["git", *args],
        cwd=str(cwd),
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


def _parse_git_version(output: str) -> Optional[str]:
    match = _GIT_VERSION_RE.search(output or "")
    if not match:
        return None

    major = match.group(1)
    minor = match.group(2) or "0"
    patch = match.group(3) or "0"

    return f"{major}.{minor}.{patch}"


def _git_version(timeout: float) -> tuple[Optional[str], Optional[int], str]:
    try:
        result = subprocess.run(
            ["git", "--version"],
            cwd=None,
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
    except FileNotFoundError:
        return None, None, "GIT_NOT_AVAILABLE"
    except subprocess.TimeoutExpired:
        return None, None, "GIT_VERSION_TIMEOUT"
    except OSError:
        return None, None, "GIT_VERSION_EXECUTION_ERROR"

    combined = f"{result.stdout}\n{result.stderr}"
    version = _parse_git_version(combined)

    if result.returncode != 0:
        return version, result.returncode, "GIT_VERSION_COMMAND_FAILED"

    if version is None:
        return None, result.returncode, "GIT_VERSION_NOT_DETECTED"

    return version, result.returncode, "GIT_VERSION_VALID"


def validate_repository_state(
    repository_path: str | Path,
    *,
    timeout: float = 10.0,
) -> RepositoryStateResult:
    """
    Validate the basic Git repository state required before
    server-side remediation work.

    Validation scope for TASK 181:
      1. Input path validity.
      2. Git executable availability.
      3. Git version availability.
      4. Repository existence.
      5. Repository root detection.
      6. Git directory detection.
      7. HEAD resolution.
      8. Current branch/ref detection.
      9. Detached HEAD detection.
      10. Repository state consistency.

    TASK 182 handles working-tree cleanliness.
    TASK 183 handles protection of existing changes.
    """
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise RepositoryStateValidationError(
            "timeout must be a positive number"
        )

    if timeout <= 0 or timeout > 120:
        raise RepositoryStateValidationError(
            "timeout must be greater than 0 and at most 120 seconds"
        )

    root_input = _validate_path_input(repository_path)

    if not root_input.exists():
        return RepositoryStateResult(
            valid=False,
            repository_root=None,
            git_directory=None,
            head=None,
            branch=None,
            detached_head=False,
            git_version=None,
            return_code=None,
            reason="REPOSITORY_PATH_NOT_FOUND",
        )

    if not root_input.is_dir():
        return RepositoryStateResult(
            valid=False,
            repository_root=None,
            git_directory=None,
            head=None,
            branch=None,
            detached_head=False,
            git_version=None,
            return_code=None,
            reason="REPOSITORY_PATH_NOT_DIRECTORY",
        )

    version, version_rc, version_reason = _git_version(timeout)

    if version_reason == "GIT_NOT_AVAILABLE":
        return RepositoryStateResult(
            valid=False,
            repository_root=None,
            git_directory=None,
            head=None,
            branch=None,
            detached_head=False,
            git_version=None,
            return_code=None,
            reason="GIT_NOT_AVAILABLE",
        )

    if version_reason != "GIT_VERSION_VALID":
        return RepositoryStateResult(
            valid=False,
            repository_root=None,
            git_directory=None,
            head=None,
            branch=None,
            detached_head=False,
            git_version=version,
            return_code=version_rc,
            reason=version_reason,
        )

    # --------------------------------------------------------
    # 1. Resolve repository root.
    # --------------------------------------------------------
    try:
        root_result = _run_git(
            ["rev-parse", "--show-toplevel"],
            root_input,
            timeout,
        )
    except subprocess.TimeoutExpired:
        return RepositoryStateResult(
            valid=False,
            repository_root=None,
            git_directory=None,
            head=None,
            branch=None,
            detached_head=False,
            git_version=version,
            return_code=None,
            reason="REPOSITORY_ROOT_TIMEOUT",
        )
    except (FileNotFoundError, OSError):
        return RepositoryStateResult(
            valid=False,
            repository_root=None,
            git_directory=None,
            head=None,
            branch=None,
            detached_head=False,
            git_version=version,
            return_code=None,
            reason="REPOSITORY_ROOT_EXECUTION_ERROR",
        )

    if root_result.returncode != 0:
        return RepositoryStateResult(
            valid=False,
            repository_root=None,
            git_directory=None,
            head=None,
            branch=None,
            detached_head=False,
            git_version=version,
            return_code=root_result.returncode,
            reason="NOT_A_GIT_REPOSITORY",
        )

    repository_root_text = root_result.stdout.strip()

    if not repository_root_text:
        return RepositoryStateResult(
            valid=False,
            repository_root=None,
            git_directory=None,
            head=None,
            branch=None,
            detached_head=False,
            git_version=version,
            return_code=root_result.returncode,
            reason="REPOSITORY_ROOT_NOT_DETECTED",
        )

    repository_root = Path(repository_root_text).resolve()

    # --------------------------------------------------------
    # 2. Verify Git directory.
    # --------------------------------------------------------
    try:
        git_dir_result = _run_git(
            ["rev-parse", "--git-dir"],
            repository_root,
            timeout,
        )
    except subprocess.TimeoutExpired:
        return RepositoryStateResult(
            valid=False,
            repository_root=str(repository_root),
            git_directory=None,
            head=None,
            branch=None,
            detached_head=False,
            git_version=version,
            return_code=None,
            reason="GIT_DIRECTORY_TIMEOUT",
        )
    except (FileNotFoundError, OSError):
        return RepositoryStateResult(
            valid=False,
            repository_root=str(repository_root),
            git_directory=None,
            head=None,
            branch=None,
            detached_head=False,
            git_version=version,
            return_code=None,
            reason="GIT_DIRECTORY_EXECUTION_ERROR",
        )

    if git_dir_result.returncode != 0:
        return RepositoryStateResult(
            valid=False,
            repository_root=str(repository_root),
            git_directory=None,
            head=None,
            branch=None,
            detached_head=False,
            git_version=version,
            return_code=git_dir_result.returncode,
            reason="GIT_DIRECTORY_NOT_RESOLVED",
        )

    git_directory_text = git_dir_result.stdout.strip()

    if not git_directory_text:
        return RepositoryStateResult(
            valid=False,
            repository_root=str(repository_root),
            git_directory=None,
            head=None,
            branch=None,
            detached_head=False,
            git_version=version,
            return_code=git_dir_result.returncode,
            reason="GIT_DIRECTORY_EMPTY",
        )

    git_directory = Path(git_directory_text)

    if not git_directory.is_absolute():
        git_directory = (repository_root / git_directory).resolve()
    else:
        git_directory = git_directory.resolve()

    if not git_directory.exists():
        return RepositoryStateResult(
            valid=False,
            repository_root=str(repository_root),
            git_directory=str(git_directory),
            head=None,
            branch=None,
            detached_head=False,
            git_version=version,
            return_code=git_dir_result.returncode,
            reason="GIT_DIRECTORY_MISSING",
        )

    # --------------------------------------------------------
    # 3. Resolve HEAD.
    # --------------------------------------------------------
    try:
        head_result = _run_git(
            ["rev-parse", "HEAD"],
            repository_root,
            timeout,
        )
    except subprocess.TimeoutExpired:
        return RepositoryStateResult(
            valid=False,
            repository_root=str(repository_root),
            git_directory=str(git_directory),
            head=None,
            branch=None,
            detached_head=False,
            git_version=version,
            return_code=None,
            reason="HEAD_RESOLUTION_TIMEOUT",
        )
    except (FileNotFoundError, OSError):
        return RepositoryStateResult(
            valid=False,
            repository_root=str(repository_root),
            git_directory=str(git_directory),
            head=None,
            branch=None,
            detached_head=False,
            git_version=version,
            return_code=None,
            reason="HEAD_RESOLUTION_EXECUTION_ERROR",
        )

    if head_result.returncode != 0:
        return RepositoryStateResult(
            valid=False,
            repository_root=str(repository_root),
            git_directory=str(git_directory),
            head=None,
            branch=None,
            detached_head=False,
            git_version=version,
            return_code=head_result.returncode,
            reason="HEAD_NOT_RESOLVED",
        )

    head = head_result.stdout.strip()

    if not re.fullmatch(r"[0-9a-fA-F]{40}", head):
        return RepositoryStateResult(
            valid=False,
            repository_root=str(repository_root),
            git_directory=str(git_directory),
            head=head or None,
            branch=None,
            detached_head=False,
            git_version=version,
            return_code=head_result.returncode,
            reason="INVALID_HEAD",
        )

    # --------------------------------------------------------
    # 4. Resolve symbolic branch/ref.
    #
    # --abbrev-ref HEAD returns:
    #   branch name       -> main
    #   detached HEAD     -> HEAD
    # --------------------------------------------------------
    try:
        branch_result = _run_git(
            ["symbolic-ref", "--quiet", "--short", "HEAD"],
            repository_root,
            timeout,
        )
    except subprocess.TimeoutExpired:
        return RepositoryStateResult(
            valid=False,
            repository_root=str(repository_root),
            git_directory=str(git_directory),
            head=head,
            branch=None,
            detached_head=False,
            git_version=version,
            return_code=None,
            reason="BRANCH_RESOLUTION_TIMEOUT",
        )
    except (FileNotFoundError, OSError):
        return RepositoryStateResult(
            valid=False,
            repository_root=str(repository_root),
            git_directory=str(git_directory),
            head=head,
            branch=None,
            detached_head=False,
            git_version=version,
            return_code=None,
            reason="BRANCH_RESOLUTION_EXECUTION_ERROR",
        )

    detached_head = branch_result.returncode != 0

    if detached_head:
        branch = None
    else:
        branch = branch_result.stdout.strip() or None

    # --------------------------------------------------------
    # TASK 181 policy:
    #
    # A valid repository must have:
    #   - working Git executable
    #   - detectable Git version
    #   - repository root
    #   - Git directory
    #   - valid HEAD
    #
    # Detached HEAD is reported, but is NOT automatically a
    # repository corruption condition. GitHub Actions checkout
    # can legitimately operate from a detached commit.
    # --------------------------------------------------------
    return RepositoryStateResult(
        valid=True,
        repository_root=str(repository_root),
        git_directory=str(git_directory),
        head=head,
        branch=branch,
        detached_head=detached_head,
        git_version=version,
        return_code=0,
        reason=(
            "VALID_REPOSITORY_STATE_DETACHED_HEAD"
            if detached_head
            else "VALID_REPOSITORY_STATE"
        ),
    )


def repository_state_validation(
    repository_path: str | Path,
    *,
    timeout: float = 10.0,
) -> RepositoryStateResult:
    """Compatibility alias for validate_repository_state."""
    return validate_repository_state(
        repository_path,
        timeout=timeout,
    )


def check_repository_state(
    repository_path: str | Path,
    *,
    timeout: float = 10.0,
) -> RepositoryStateResult:
    """Compatibility alias for validate_repository_state."""
    return validate_repository_state(
        repository_path,
        timeout=timeout,
    )


def is_repository_state_valid(
    repository_path: str | Path,
    *,
    timeout: float = 10.0,
) -> bool:
    """Return only the repository-state validity flag."""
    return validate_repository_state(
        repository_path,
        timeout=timeout,
    ).valid


__all__ = [
    "RepositoryStateValidationError",
    "RepositoryStateResult",
    "validate_repository_state",
    "repository_state_validation",
    "check_repository_state",
    "is_repository_state_valid",
]
