from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path

import pytest

from sentinelshield.temporary_workspace import (
    TemporaryWorkspace,
    TemporaryWorkspaceError,
    WORKSPACE_MARKER,
    cleanup_temporary_workspace,
    prepare_temporary_workspace,
    workspace_contains,
)


def test_workspace_is_created(tmp_path):
    workspace = prepare_temporary_workspace(
        base_dir=tmp_path,
    )

    try:
        assert isinstance(
            workspace,
            TemporaryWorkspace,
        )
        assert workspace.path.is_dir()
        assert workspace.path.parent == tmp_path.resolve()
        assert workspace.marker.is_file()
    finally:
        cleanup_temporary_workspace(workspace)


def test_workspace_permissions_are_0700(tmp_path):
    workspace = prepare_temporary_workspace(
        base_dir=tmp_path,
    )

    try:
        mode = stat.S_IMODE(
            os.stat(workspace.path).st_mode
        )

        assert mode == 0o700
        assert workspace.mode == 0o700
    finally:
        cleanup_temporary_workspace(workspace)


def test_marker_permissions_are_0600(tmp_path):
    workspace = prepare_temporary_workspace(
        base_dir=tmp_path,
    )

    try:
        mode = stat.S_IMODE(
            os.stat(workspace.marker).st_mode
        )

        assert mode == 0o600
    finally:
        cleanup_temporary_workspace(workspace)


def test_marker_content(tmp_path):
    workspace = prepare_temporary_workspace(
        base_dir=tmp_path,
    )

    try:
        assert workspace.marker.name == WORKSPACE_MARKER
        assert (
            workspace.marker.read_text(
                encoding="utf-8"
            )
            == "sentinelshield-temporary-workspace\n"
        )
    finally:
        cleanup_temporary_workspace(workspace)


def test_two_workspaces_are_unique(tmp_path):
    first = prepare_temporary_workspace(
        base_dir=tmp_path,
    )
    second = prepare_temporary_workspace(
        base_dir=tmp_path,
    )

    try:
        assert first.path != second.path
        assert first.path.exists()
        assert second.path.exists()
    finally:
        cleanup_temporary_workspace(first)
        cleanup_temporary_workspace(second)


def test_workspace_is_outside_repository(tmp_path):
    repository = tmp_path / "repo"
    repository.mkdir()

    workspace = prepare_temporary_workspace(
        base_dir=tmp_path,
        repository_root=repository,
    )

    try:
        assert not workspace_contains(
            workspace,
            repository,
        )
        assert workspace.path != repository
    finally:
        cleanup_temporary_workspace(workspace)


def test_workspace_inside_repository_is_rejected(tmp_path):
    repository = tmp_path / "repo"
    repository.mkdir()

    base = repository / "temporary"
    base.mkdir()

    with pytest.raises(TemporaryWorkspaceError):
        prepare_temporary_workspace(
            base_dir=base,
            repository_root=repository,
        )


def test_workspace_contains_child(tmp_path):
    workspace = prepare_temporary_workspace(
        base_dir=tmp_path,
    )

    try:
        child = workspace.path / "child.txt"
        child.write_text(
            "data\n",
            encoding="utf-8",
        )

        assert workspace_contains(
            workspace,
            child,
        )
    finally:
        cleanup_temporary_workspace(workspace)


def test_workspace_does_not_contain_outside_path(tmp_path):
    workspace = prepare_temporary_workspace(
        base_dir=tmp_path,
    )

    try:
        outside = tmp_path / "outside.txt"

        assert not workspace_contains(
            workspace,
            outside,
        )
    finally:
        cleanup_temporary_workspace(workspace)


def test_cleanup_removes_workspace(tmp_path):
    workspace = prepare_temporary_workspace(
        base_dir=tmp_path,
    )

    path = workspace.path

    cleanup_temporary_workspace(workspace)

    assert not path.exists()


def test_cleanup_requires_marker(tmp_path):
    workspace = prepare_temporary_workspace(
        base_dir=tmp_path,
    )

    workspace.marker.unlink()

    with pytest.raises(TemporaryWorkspaceError):
        cleanup_temporary_workspace(workspace)

    workspace.path.rmdir()


def test_symlink_base_is_rejected(tmp_path):
    real = tmp_path / "real"
    real.mkdir()

    link = tmp_path / "link"
    link.symlink_to(
        real,
        target_is_directory=True,
    )

    with pytest.raises(TemporaryWorkspaceError):
        prepare_temporary_workspace(
            base_dir=link,
        )


def test_file_as_base_is_rejected(tmp_path):
    base = tmp_path / "base-file"
    base.write_text(
        "not-directory\n",
        encoding="utf-8",
    )

    with pytest.raises(TemporaryWorkspaceError):
        prepare_temporary_workspace(
            base_dir=base,
        )


@pytest.mark.parametrize(
    "prefix",
    [
        "",
        " bad",
        "bad ",
        "bad/name",
        "bad\\name",
        "bad\x00name",
        "bad\nname",
        "bad\tname",
    ],
)
def test_invalid_prefix_rejected(tmp_path, prefix):
    with pytest.raises(
        (TypeError, ValueError)
    ):
        prepare_temporary_workspace(
            base_dir=tmp_path,
            prefix=prefix,
        )


def test_non_string_prefix_rejected(tmp_path):
    with pytest.raises(TypeError):
        prepare_temporary_workspace(
            base_dir=tmp_path,
            prefix=123,  # type: ignore[arg-type]
        )


def test_default_system_temp_directory_supported():
    workspace = prepare_temporary_workspace()

    try:
        assert workspace.path.is_dir()
        assert workspace.base_dir.is_dir()
    finally:
        cleanup_temporary_workspace(workspace)


def test_to_dict(tmp_path):
    workspace = prepare_temporary_workspace(
        base_dir=tmp_path,
    )

    try:
        data = workspace.to_dict()

        assert data["path"] == str(workspace.path)
        assert data["base_dir"] == str(
            workspace.base_dir
        )
        assert data["marker"] == str(
            workspace.marker
        )
        assert data["mode"] == 0o700
    finally:
        cleanup_temporary_workspace(workspace)
