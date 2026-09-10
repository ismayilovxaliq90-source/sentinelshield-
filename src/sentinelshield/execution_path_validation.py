from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


class ExecutionPathValidationError(ValueError):
    """Raised when an execution path policy is invalid."""


@dataclass(frozen=True)
class ExecutionPathPolicy:
    allow_workspace_root: bool = True
    allow_existing_symlinks: bool = True
    require_within_workspace: bool = True
    reject_symlink_escape: bool = True
    max_path_length: int = 4096

    def __post_init__(self) -> None:
        for name in (
            "allow_workspace_root",
            "allow_existing_symlinks",
            "require_within_workspace",
            "reject_symlink_escape",
        ):
            if not isinstance(getattr(self, name), bool):
                raise TypeError(f"{name} must be bool")

        if (
            isinstance(self.max_path_length, bool)
            or not isinstance(self.max_path_length, int)
        ):
            raise TypeError("max_path_length must be int")

        if self.max_path_length < 1:
            raise ExecutionPathValidationError(
                "max_path_length must be >= 1"
            )


@dataclass(frozen=True)
class ExecutionPathValidationResult:
    allowed: bool
    candidate: Optional[str]
    resolved_candidate: Optional[str]
    workspace_root: Optional[str]
    reason: str
    exists: bool
    is_symlink: bool

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "candidate": self.candidate,
            "resolved_candidate": self.resolved_candidate,
            "workspace_root": self.workspace_root,
            "reason": self.reason,
            "exists": self.exists,
            "is_symlink": self.is_symlink,
        }


def _failure(
    candidate: Optional[str],
    workspace_root: Optional[str],
    reason: str,
    *,
    resolved_candidate: Optional[str] = None,
    exists: bool = False,
    is_symlink: bool = False,
) -> ExecutionPathValidationResult:
    return ExecutionPathValidationResult(
        allowed=False,
        candidate=candidate,
        resolved_candidate=resolved_candidate,
        workspace_root=workspace_root,
        reason=reason,
        exists=exists,
        is_symlink=is_symlink,
    )


def _has_control_character(value: str) -> bool:
    return any(
        ord(char) < 0x20 or ord(char) == 0x7F
        for char in value
    )


def _within(base: Path, candidate: Path) -> bool:
    try:
        candidate.relative_to(base)
        return True
    except ValueError:
        return False


def _is_symlink_path(path: Path) -> bool:
    try:
        return path.is_symlink()
    except OSError:
        return False


def validate_execution_path(
    workspace_root: str | os.PathLike[str],
    candidate: str | os.PathLike[str],
    policy: ExecutionPathPolicy | None = None,
) -> ExecutionPathValidationResult:
    """
    Validate an execution path without modifying or executing anything.

    The candidate must resolve inside the designated execution workspace.
    Existing symlinks are checked using their resolved destination, preventing
    a symlink from escaping the workspace.
    """
    active_policy = policy or ExecutionPathPolicy()

    if not isinstance(workspace_root, (str, os.PathLike)):
        return _failure(
            None,
            None,
            "WORKSPACE_ROOT_INVALID_TYPE",
        )

    if not isinstance(candidate, (str, os.PathLike)):
        return _failure(
            None,
            os.fspath(workspace_root),
            "CANDIDATE_INVALID_TYPE",
        )

    try:
        workspace_text = os.fspath(workspace_root)
        candidate_text = os.fspath(candidate)
    except TypeError:
        return _failure(
            None,
            None,
            "PATH_CONVERSION_FAILED",
        )

    if not isinstance(workspace_text, str):
        workspace_text = os.fsdecode(workspace_text)

    if not isinstance(candidate_text, str):
        candidate_text = os.fsdecode(candidate_text)

    if not workspace_text:
        return _failure(
            candidate_text,
            workspace_text,
            "WORKSPACE_ROOT_EMPTY",
        )

    if not candidate_text:
        return _failure(
            candidate_text,
            workspace_text,
            "CANDIDATE_EMPTY",
        )

    if len(workspace_text) > active_policy.max_path_length:
        return _failure(
            candidate_text,
            workspace_text,
            "WORKSPACE_ROOT_TOO_LONG",
        )

    if len(candidate_text) > active_policy.max_path_length:
        return _failure(
            candidate_text,
            workspace_text,
            "CANDIDATE_TOO_LONG",
        )

    if "\x00" in workspace_text or "\x00" in candidate_text:
        return _failure(
            candidate_text,
            workspace_text,
            "NULL_CHARACTER_NOT_ALLOWED",
        )

    if _has_control_character(workspace_text):
        return _failure(
            candidate_text,
            workspace_text,
            "WORKSPACE_CONTROL_CHARACTER_NOT_ALLOWED",
        )

    if _has_control_character(candidate_text):
        return _failure(
            candidate_text,
            workspace_text,
            "CANDIDATE_CONTROL_CHARACTER_NOT_ALLOWED",
        )

    try:
        workspace = Path(workspace_text).expanduser().resolve(
            strict=False
        )
        raw_candidate = Path(candidate_text).expanduser()

        if raw_candidate.is_absolute():
            candidate_path = raw_candidate
        else:
            candidate_path = workspace / raw_candidate

        candidate_resolved = candidate_path.resolve(strict=False)

    except (OSError, RuntimeError, ValueError) as exc:
        return _failure(
            candidate_text,
            workspace_text,
            f"PATH_RESOLUTION_FAILED:{type(exc).__name__}",
        )

    exists = False
    try:
        exists = candidate_path.exists()
    except OSError:
        exists = False

    is_symlink = _is_symlink_path(candidate_path)

    if active_policy.require_within_workspace:
        if not _within(workspace, candidate_resolved):
            return _failure(
                candidate_text,
                str(workspace),
                "WORKSPACE_ESCAPE",
                resolved_candidate=str(candidate_resolved),
                exists=exists,
                is_symlink=is_symlink,
            )

    if is_symlink and not active_policy.allow_existing_symlinks:
        return _failure(
            candidate_text,
            str(workspace),
            "SYMLINK_NOT_ALLOWED",
            resolved_candidate=str(candidate_resolved),
            exists=exists,
            is_symlink=True,
        )

    if (
        is_symlink
        and active_policy.reject_symlink_escape
        and not _within(workspace, candidate_resolved)
    ):
        return _failure(
            candidate_text,
            str(workspace),
            "SYMLINK_WORKSPACE_ESCAPE",
            resolved_candidate=str(candidate_resolved),
            exists=exists,
            is_symlink=True,
        )

    if (
        candidate_resolved == workspace
        and not active_policy.allow_workspace_root
    ):
        return _failure(
            candidate_text,
            str(workspace),
            "WORKSPACE_ROOT_NOT_ALLOWED",
            resolved_candidate=str(candidate_resolved),
            exists=exists,
            is_symlink=is_symlink,
        )

    return ExecutionPathValidationResult(
        allowed=True,
        candidate=candidate_text,
        resolved_candidate=str(candidate_resolved),
        workspace_root=str(workspace),
        reason="EXECUTION_PATH_VALID",
        exists=exists,
        is_symlink=is_symlink,
    )


def require_valid_execution_path(
    workspace_root: str | os.PathLike[str],
    candidate: str | os.PathLike[str],
    policy: ExecutionPathPolicy | None = None,
) -> ExecutionPathValidationResult:
    result = validate_execution_path(
        workspace_root=workspace_root,
        candidate=candidate,
        policy=policy,
    )

    if not result.allowed:
        raise ExecutionPathValidationError(result.reason)

    return result
