from __future__ import annotations

import os
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path


class TemporaryWorkspaceError(RuntimeError):
    """Raised when a secure temporary workspace cannot be prepared."""


WORKSPACE_MARKER = ".sentinelshield-workspace"
DEFAULT_PREFIX = "sentinelshield-"


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

    if prefix != prefix.strip():
        raise ValueError(
            "prefix must not have surrounding whitespace"
        )

    if any(
        char in prefix
        for char in ("\x00", "\n", "\r", "\t")
    ):
        raise ValueError(
            "prefix contains forbidden control characters"
        )

    if "/" in prefix or "\\" in prefix:
        raise ValueError(
            "prefix must not contain path separators"
        )

    if len(prefix) > 64:
        raise ValueError("prefix is too long")

    return prefix


def _validate_base_dir(base_dir: Path) -> Path:
    base = _canonical(base_dir)

    try:
        if base.exists():
            if base.is_symlink():
                raise TemporaryWorkspaceError(
                    f"Base directory must not be a symlink: {base}"
                )

            if not base.is_dir():
                raise TemporaryWorkspaceError(
                    f"Base directory is not a directory: {base}"
                )

            return base

        base.mkdir(
            parents=True,
            exist_ok=False,
            mode=0o700,
        )

    except TemporaryWorkspaceError:
        raise
    except FileExistsError as exc:
        raise TemporaryWorkspaceError(
            f"Base directory creation collision: {base}"
        ) from exc
    except OSError as exc:
        raise TemporaryWorkspaceError(
            f"Unable to prepare base directory: {base}"
        ) from exc

    return _canonical(base)


def _assert_outside_repository(
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


def _secure_workspace(path: Path) -> int:
    try:
        os.chmod(path, 0o700)
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError as exc:
        raise TemporaryWorkspaceError(
            f"Unable to secure workspace: {path}"
        ) from exc

    if mode != 0o700:
        raise TemporaryWorkspaceError(
            f"Workspace permissions are not 0700: {oct(mode)}"
        )

    return mode


def _create_marker(path: Path) -> Path:
    marker = path / WORKSPACE_MARKER

    try:
        fd = os.open(
            marker,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )

        with os.fdopen(
            fd,
            "w",
            encoding="utf-8",
        ) as handle:
            handle.write(
                "sentinelshield-temporary-workspace\n"
            )

    except FileExistsError as exc:
        raise TemporaryWorkspaceError(
            f"Workspace marker already exists: {marker}"
        ) from exc
    except OSError as exc:
        raise TemporaryWorkspaceError(
            f"Unable to create workspace marker: {marker}"
        ) from exc

    return marker


def prepare_temporary_workspace(
    base_dir: str | os.PathLike[str] | None = None,
    *,
    prefix: str = DEFAULT_PREFIX,
    repository_root: str | os.PathLike[str] | None = None,
) -> TemporaryWorkspace:
    """
    Create a private, unique temporary workspace.

    The workspace is created atomically by tempfile.mkdtemp(),
    restricted to owner-only access, and must remain outside
    the repository root when one is supplied.
    """
    validated_prefix = _validate_prefix(prefix)

    if base_dir is None:
        base = _canonical(Path(tempfile.gettempdir()))
    else:
        base = _validate_base_dir(Path(base_dir))

    repository = (
        _canonical(Path(repository_root))
        if repository_root is not None
        else None
    )

    try:
        raw_path = tempfile.mkdtemp(
            prefix=validated_prefix,
            dir=str(base),
        )
    except OSError as exc:
        raise TemporaryWorkspaceError(
            f"Unable to create temporary workspace in {base}"
        ) from exc

    workspace = _canonical(Path(raw_path))

    try:
        if workspace.is_symlink():
            raise TemporaryWorkspaceError(
                "Temporary workspace must not be a symlink"
            )

        if not workspace.is_dir():
            raise TemporaryWorkspaceError(
                "Temporary workspace is not a directory"
            )

        if workspace == base:
            raise TemporaryWorkspaceError(
                "Workspace path must differ from base directory"
            )

        _assert_outside_repository(
            workspace,
            repository,
        )

        mode = _secure_workspace(workspace)
        marker = _create_marker(workspace)

        try:
            os.chmod(marker, 0o600)
            marker_mode = stat.S_IMODE(marker.stat().st_mode)
        except OSError as exc:
            raise TemporaryWorkspaceError(
                f"Unable to secure workspace marker: {marker}"
            ) from exc

        if marker_mode != 0o600:
            raise TemporaryWorkspaceError(
                f"Workspace marker permissions are not 0600: "
                f"{oct(marker_mode)}"
            )

        return TemporaryWorkspace(
            path=workspace,
            base_dir=base,
            marker=marker,
            mode=mode,
        )

    except Exception:
        try:
            marker = workspace / WORKSPACE_MARKER

            if marker.exists() or marker.is_symlink():
                marker.unlink()

            if workspace.exists() and workspace.is_dir():
                workspace.rmdir()

        except OSError:
            pass

        raise


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

    root = _canonical(workspace.path)
    item = _canonical(Path(candidate))

    try:
        item.relative_to(root)
    except ValueError:
        return False

    return True


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
    marker = path / WORKSPACE_MARKER

    if path.is_symlink():
        raise TemporaryWorkspaceError(
            "Refusing cleanup of symlink workspace"
        )

    if not path.is_dir():
        raise TemporaryWorkspaceError(
            f"Workspace directory does not exist: {path}"
        )

    if not marker.is_file() or marker.is_symlink():
        raise TemporaryWorkspaceError(
            "Refusing cleanup: invalid workspace marker"
        )

    try:
        marker.unlink()
        path.rmdir()
    except OSError as exc:
        raise TemporaryWorkspaceError(
            f"Unable to clean temporary workspace: {path}"
        ) from exc
