from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import tempfile
import uuid


WORKSPACE_MARKER = ".sentinelshield-workspace"
WORKSPACE_MODE = 0o700


class TemporaryWorkspaceError(RuntimeError):
    """Raised when temporary workspace handling is unsafe or invalid."""


@dataclass(frozen=True)
class TemporaryWorkspace:
    path: Path
    marker: Path
    mode: int = WORKSPACE_MODE


def _validate_path(value: object, field: str) -> Path:
    if isinstance(value, (str, os.PathLike)):
        try:
            path = Path(value)
        except (TypeError, ValueError) as exc:
            raise TemporaryWorkspaceError(
                f"Invalid {field}"
            ) from exc
    else:
        raise TemporaryWorkspaceError(
            f"{field} must be a path"
        )

    if "\x00" in str(path):
        raise TemporaryWorkspaceError(
            f"{field} contains NULL character"
        )

    return path


def _canonical(path: Path) -> Path:
    try:
        return path.resolve(strict=False)
    except OSError as exc:
        raise TemporaryWorkspaceError(
            f"Unable to resolve path: {path}"
        ) from exc


def _is_within(root: Path, candidate: Path) -> bool:
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False


def prepare_temporary_workspace(
    base_dir: str | os.PathLike[str] | None = None,
    repository_root: str | os.PathLike[str] | None = None,
) -> TemporaryWorkspace:
    """
    Create a unique, private temporary workspace.

    The base directory itself must not be a symlink.
    The created workspace must remain outside the repository root.
    No commands or external processes are executed.
    """
    if base_dir is None:
        base = Path(tempfile.gettempdir())
    else:
        base = _validate_path(base_dir, "base_dir")

    if base.exists() and base.is_symlink():
        raise TemporaryWorkspaceError(
            f"Refusing symlink base directory: {base}"
        )

    if base.is_file():
        raise TemporaryWorkspaceError(
            f"Base path is not a directory: {base}"
        )

    try:
        base.mkdir(
            parents=True,
            exist_ok=True,
        )
    except OSError as exc:
        raise TemporaryWorkspaceError(
            f"Unable to prepare base directory: {base}"
        ) from exc

    if base.is_symlink():
        raise TemporaryWorkspaceError(
            f"Refusing symlink base directory: {base}"
        )

    canonical_base = _canonical(base)

    repository: Path | None = None
    if repository_root is not None:
        repository_path = _validate_path(
            repository_root,
            "repository_root",
        )

        if repository_path.exists() and repository_path.is_symlink():
            raise TemporaryWorkspaceError(
                f"Refusing symlink repository root: {repository_path}"
            )

        repository = _canonical(repository_path)

    for _ in range(10):
        candidate = canonical_base / (
            f"sentinelshield-{uuid.uuid4().hex}"
        )

        if candidate.exists() or candidate.is_symlink():
            continue

        if repository is not None and _is_within(
            repository,
            candidate,
        ):
            continue

        try:
            candidate.mkdir(
                mode=WORKSPACE_MODE,
                parents=False,
                exist_ok=False,
            )
        except FileExistsError:
            continue
        except OSError as exc:
            raise TemporaryWorkspaceError(
                f"Unable to create temporary workspace: {candidate}"
            ) from exc

        try:
            os.chmod(candidate, WORKSPACE_MODE)

            if candidate.is_symlink():
                raise TemporaryWorkspaceError(
                    "Created workspace unexpectedly became a symlink"
                )

            marker = candidate / WORKSPACE_MARKER

            marker.write_text(
                "sentinelshield temporary workspace\n",
                encoding="utf-8",
            )

            os.chmod(marker, 0o600)

            return TemporaryWorkspace(
                path=candidate,
                marker=marker,
                mode=WORKSPACE_MODE,
            )

        except Exception:
            shutil.rmtree(
                candidate,
                ignore_errors=True,
            )
            raise

    raise TemporaryWorkspaceError(
        "Unable to allocate unique temporary workspace"
    )


def cleanup_temporary_workspace(
    workspace: TemporaryWorkspace,
) -> None:
    if not isinstance(
        workspace,
        TemporaryWorkspace,
    ):
        raise TypeError(
            "workspace must be a TemporaryWorkspace"
        )

    path = _canonical(workspace.path)

    if path.is_symlink():
        raise TemporaryWorkspaceError(
            "Refusing cleanup of symlink workspace"
        )

    if not path.is_dir():
        raise TemporaryWorkspaceError(
            f"Workspace directory does not exist: {path}"
        )

    marker = path / WORKSPACE_MARKER

    if not marker.is_file() or marker.is_symlink():
        raise TemporaryWorkspaceError(
            "Refusing cleanup: invalid workspace marker"
        )

    try:
        marker.unlink()

        # The workspace is owned exclusively by SentinelShield.
        # Remove all remaining workspace contents before removing
        # the workspace itself.
        for entry in path.iterdir():
            if entry.is_symlink() or entry.is_file():
                entry.unlink()
            elif entry.is_dir():
                shutil.rmtree(entry)
            else:
                entry.unlink()

        path.rmdir()

    except OSError as exc:
        raise TemporaryWorkspaceError(
            f"Unable to clean temporary workspace: {path}"
        ) from exc


def workspace_contains(
    workspace: TemporaryWorkspace,
    candidate: str | os.PathLike[str],
) -> bool:
    if not isinstance(
        workspace,
        TemporaryWorkspace,
    ):
        raise TypeError(
            "workspace must be a TemporaryWorkspace"
        )

    candidate_path = _validate_path(
        candidate,
        "candidate",
    )

    workspace_path = _canonical(workspace.path)

    if workspace_path.is_symlink():
        raise TemporaryWorkspaceError(
            "Workspace path is a symlink"
        )

    resolved_candidate = _canonical(candidate_path)

    return _is_within(
        workspace_path,
        resolved_candidate,
    )
