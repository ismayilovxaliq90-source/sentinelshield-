from pathlib import Path

import pytest

from sentinelshield.project_path import (
    ProjectPathValidator,
    ProjectPathViolation,
)


def test_valid_project_path(tmp_path):
    workspace = tmp_path / "workspace"
    project = workspace / "project1"

    workspace.mkdir()
    project.mkdir()

    validator = ProjectPathValidator(workspace)

    result = validator.validate(project)

    assert result == project.resolve()


def test_project_path_outside_workspace_is_rejected(tmp_path):
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"

    workspace.mkdir()
    outside.mkdir()

    validator = ProjectPathValidator(workspace)

    with pytest.raises(ProjectPathViolation):
        validator.validate(outside)


def test_parent_traversal_is_rejected(tmp_path):
    workspace = tmp_path / "workspace"
    secret = tmp_path / "secret"

    workspace.mkdir()
    secret.mkdir()

    validator = ProjectPathValidator(workspace)

    with pytest.raises(ProjectPathViolation):
        validator.validate(
            workspace / ".." / "secret"
        )


def test_missing_project_is_rejected(tmp_path):
    workspace = tmp_path / "workspace"

    workspace.mkdir()

    validator = ProjectPathValidator(workspace)

    with pytest.raises(ProjectPathViolation):
        validator.validate(
            workspace / "missing"
        )


def test_file_is_rejected(tmp_path):
    workspace = tmp_path / "workspace"
    project_file = workspace / "project.txt"

    workspace.mkdir()
    project_file.write_text("test")

    validator = ProjectPathValidator(workspace)

    with pytest.raises(ProjectPathViolation):
        validator.validate(project_file)


def test_symlink_escape_is_rejected(tmp_path):
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"

    workspace.mkdir()
    outside.mkdir()

    link = workspace / "project_link"
    link.symlink_to(outside, target_is_directory=True)

    validator = ProjectPathValidator(workspace)

    with pytest.raises(ProjectPathViolation):
        validator.validate(link)
