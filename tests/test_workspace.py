from pathlib import Path

import pytest

from sentinelshield.workspace import Workspace, WorkspaceViolation


@pytest.fixture
def workspace(tmp_path):
    root = tmp_path / "workspace"
    root.mkdir()

    return Workspace(root)


def test_workspace_root_is_allowed(workspace):
    assert workspace.contains(workspace.root)


def test_path_inside_workspace_is_allowed(workspace):
    path = workspace.root / "data" / "file.txt"

    assert workspace.contains(path)


def test_validate_returns_resolved_path(workspace):
    path = workspace.root / "data" / "file.txt"

    result = workspace.validate(path)

    assert result == path.resolve()


def test_path_outside_workspace_is_rejected(workspace, tmp_path):
    outside = tmp_path / "outside.txt"

    assert workspace.contains(outside) is False

    with pytest.raises(WorkspaceViolation):
        workspace.validate(outside)


def test_parent_traversal_is_rejected(workspace):
    malicious = workspace.root / ".." / "outside.txt"

    assert workspace.contains(malicious) is False

    with pytest.raises(WorkspaceViolation):
        workspace.validate(malicious)


def test_relative_workspace_path(workspace):
    path = workspace.path("data/test.txt")

    assert path == (workspace.root / "data/test.txt").resolve()
    assert workspace.contains(path)
