from __future__ import annotations

import os
import secrets
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path


class TemporaryWorkspaceError(RuntimeError):
    """Raised when a secure temporary workspace cannot be prepared."""


_WORKSPACE_MARKER = ".sentinelshield-workspace"
_DEFAULT_PREFIX = "sentinelshield-"


@dataclass(frozen=True)
class TemporaryWorkspace:
    path: Path
    base_dir: Path
    marker: Path
    mode: int

    def exists(self) -> bool:
        return self.path.is_dir()

    def to_dict(self) -> dict[str, str | int]:
        return {
            "path": str(self.path),
            "base_dir": str(self.base_dir),
            "marker": str(self.marker),
            "mode": self.mode,
        }


def _canonical(path: Path) -> Path:
    try:
        return path.expanduser().resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise TemporaryWorkspaceError(
            f"Unable to resolve path: {path}"
        ) from exc


def _validate_prefix(prefix: str) -> str:
    if not isinstance(prefix, str):
        raise TypeError("prefix must be a string")

    if not prefix:
        raise ValueError("prefix must not be empty")

    if prefix.strip() != prefix:
        raise ValueError("prefix must not have surrounding whitespace")

    if any(
        character in prefix
        for character in ("\x00", "\n", "\r", "\t")
    ):
        raise ValueError("prefix contains forbidden control characters")

    if "/" in prefix or "\\" in prefix:
        raise ValueError("prefix must not contain path separators")

    if len(prefix) > 64:
        raise ValueError("prefix is too long")

    return prefix


def _validate_base_dir(base_dir: Path) -> Path:
    base = _canonical(base_dir)

    try:
        if base.exists():
            if not base.is_dir():
                raise TemporaryWorkspaceError(
                    f"Base directory is not a directory: {base}"
                )

            if base.is_symlink():
                raise TemporaryWorkspaceError(
                    f"Base directory must not be a symlink: {base}"
                )

            return base

        base.mkdir(
            parents=True,
            exist_ok=False,
            mode=0o700,
        )

    except FileExistsError as exc:
        raise TemporaryWorkspaceError(
            f"Base directory creation collision: {base}"
        ) from exc
    except OSError as exc:
        raise TemporaryWorkspaceError(
            f"Unable to prepare base directory: {base}"
        ) from exc

    return _canonical(base)


def _assert_not_repository_child(
    workspace: Path,
    repository_root: Path | None,
) -> None:
    if repository_root is None:
        return

    repository = _canonical(repository_root)

    try:
        workspace.relative_to(repository)
    except ValueError:
        return

    raise TemporaryWorkspaceError(
        "Temporary workspace must be outside repository root"
    )


def _secure_directory(path: Path) -> None:
    try:
        os.chmod(path, 0o700)
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError as exc:
        raise TemporaryWorkspaceError(
            f"Unable to secure workspace permissions: {path}"
        ) from exc

    if mode != 0o700:
        raise TemporaryWorkspaceError(
            f"Workspace permissions are not 0700: {oct(mode)}"
        )


def _create_marker(path: Path) -> Path:
    marker = path / _WORKSPACE_MARKER

    try:
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
        )

        descriptor = os.open(
            marker,
            flags,
            0o600,
        )

        with os.fdopen(
            descriptor,
            "w",
            encoding="utf-8",
        ) as handle:
            handle.write("sentinelshield-temporary-workspace\n")

        return marker

    except FileExistsError as exc:
        raise TemporaryWorkspaceError(
            f"Workspace marker already exists: {marker}"
        ) from exc
    except OSError as exc:
        raise TemporaryWorkspaceError(
            f"Unable to create workspace marker: {marker}"
        ) from exc


def prepare_temporary_workspace(
    base_dir: str | os.PathLike[str] | None = None,
    *,
    prefix: str = _DEFAULT_PREFIX,
    repository_root: str | os.PathLike[str] | None = None,
) -> TemporaryWorkspace:
    """
    Prepare a private temporary workspace.

    No repository files are modified. The workspace is created outside the
    repository and is restricted to owner-only access.
    """
    validated_prefix = _validate_prefix(prefix)

    if base_dir is None:
        try:
            base = _canonical(
                Path(tempfile.gettempdir())
            )
        except Exception as exc:
            raise TemporaryWorkspaceError(
                "Unable to determine system temporary directory"
            ) from exc
    else:
        base = _validate_base_dir(
            Path(base_dir)
        )

    repository = (
        _canonical(Path(repository_root))
        if repository_root is not None
        else None
    )

    # mkdtemp uses an atomic creation operation and therefore avoids the
    # classic check-then-create collision problem.
    try:
        workspace_text = tempfile.mkdtemp(
            prefix=validated_prefix,
            dir=str(base),
        )
    except OSError as exc:
        raise TemporaryWorkspaceError(
            f"Unable to create temporary workspace in {base}"
        ) from exc

    workspace = _canonical(
        Path(workspace_text)
    )

    try:
        _assert_not_repository_child(
            workspace,
            repository,
        )

        if workspace == base:
            raise TemporaryWorkspaceError(
                "Workspace path must differ from base directory"
            )

        if workspace.is_symlink():
            raise TemporaryWorkspaceError(
                "Temporary workspace unexpectedly became a symlink"
            )

        if not workspace.is_dir():
            raise TemporaryWorkspaceError(
                "Temporary workspace is not a directory"
            )

        _secure_directory(workspace)

        marker = _create_marker(workspace)

        try:
            os.chmod(marker, 0o600)
        except OSError as exc:
            raise TemporaryWorkspaceError(
                f"Unable to secure marker permissions: {marker}"
            ) from exc

        marker_mode = stat.S_IMODE(
            marker.stat().st_mode
        )

        if marker_mode != 0o600:
            raise TemporaryWorkspaceError(
                f"Marker permissions are not 0600: "
                f"{oct(marker_mode)}"
            )

        return TemporaryWorkspace(
            path=workspace,
            base_dir=base,
            marker=marker,
            mode=0o700,
        )

    except Exception:
        # Best-effort cleanup only for a workspace created by this function.
        try:
            if workspace.exists() and workspace.is_dir():
                marker = workspace / _WORKSPACE_MARKER
                if marker.exists() or marker.is_symlink():
                    marker.unlink(missing_ok=True)
                workspace.rmdir()
        except OSError:
            pass

        raise


def cleanup_temporary_workspace(
    workspace: TemporaryWorkspace,
) -> None:
    """
    Safely remove a workspace created by prepare_temporary_workspace.

    Removal is permitted only when the expected marker is present.
    """
    if not isinstance(workspace, TemporaryWorkspace):
        raise TypeError(
            "workspace must be a TemporaryWorkspace"
        )

    path = _canonical(workspace.path)
    marker = path / _WORKSPACE_MARKER

    if path.is_symlink():
        raise TemporaryWorkspaceError(
            "Refusing to clean a symlink workspace"
        )

    if not path.is_dir():
        raise TemporaryWorkspaceError(
            f"Workspace directory does not exist: {path}"
        )

    if not marker.is_file() or marker.is_symlink():
        raise TemporaryWorkspaceError(
            "Refusing cleanup: workspace marker is missing or invalid"
        )

    try:
        marker.unlink()
        path.rmdir()
    except OSError as exc:
        raise TemporaryWorkspaceError(
            f"Unable to clean temporary workspace: {path}"
        ) from exc


def workspace_contains(
    workspace: TemporaryWorkspace,
    candidate: str | os.PathLike[str],
) -> bool:
    """Return True only when candidate is physically under workspace."""
    if not isinstance(workspace, TemporaryWorkspace):
        raise TypeError(
            "workspace must be a TemporaryWorkspace"
        )

    root = _canonical(workspace.path)
    item = _canonical(Path(candidate))

    try:
        item.relative_to(root)
    except ValueError:
        return False

    return True
