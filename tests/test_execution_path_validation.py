from __future__ import annotations

import os
from pathlib import Path

import pytest

from sentinelshield.execution_path_validation import (
    ExecutionPathPolicy,
    ExecutionPathValidationError,
    require_valid_execution_path,
    validate_execution_path,
)


def test_workspace_path_is_allowed(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    result = validate_execution_path(
        workspace,
        workspace,
    )

    assert result.allowed is True
    assert result.reason == "EXECUTION_PATH_VALID"
    assert result.resolved_candidate == str(workspace.resolve())


def test_nested_path_is_allowed(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    nested = workspace / "project" / "file.txt"

    result = validate_execution_path(workspace, nested)

    assert result.allowed is True


def test_relative_nested_path_is_resolved_inside_workspace(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    result = validate_execution_path(
        workspace,
        "project/file.txt",
    )

    assert result.allowed is True
    assert Path(result.resolved_candidate).is_absolute()


@pytest.mark.parametrize(
    "candidate",
    [
        "../outside",
        "../../outside",
        "../workspace-evil/file",
        "a/../../outside",
    ],
)
def test_parent_traversal_is_rejected(tmp_path: Path, candidate: str):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    result = validate_execution_path(workspace, candidate)

    assert result.allowed is False
    assert result.reason == "WORKSPACE_ESCAPE"


def test_absolute_path_outside_workspace_is_rejected(tmp_path: Path):
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"

    workspace.mkdir()
    outside.mkdir()

    result = validate_execution_path(workspace, outside)

    assert result.allowed is False
    assert result.reason == "WORKSPACE_ESCAPE"


def test_existing_file_inside_workspace_is_allowed(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    target = workspace / "safe.txt"
    target.write_text("safe", encoding="utf-8")

    result = validate_execution_path(workspace, target)

    assert result.allowed is True
    assert result.exists is True
    assert result.is_symlink is False


def test_missing_path_inside_workspace_is_allowed_for_validation(
    tmp_path: Path,
):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    target = workspace / "new.txt"

    result = validate_execution_path(workspace, target)

    assert result.allowed is True
    assert result.exists is False


def test_symlink_inside_workspace_to_inside_workspace_is_allowed(
    tmp_path: Path,
):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    target = workspace / "target"
    target.mkdir()

    link = workspace / "link"
    link.symlink_to(target, target_is_directory=True)

    result = validate_execution_path(workspace, link)

    assert result.allowed is True
    assert result.is_symlink is True


def test_symlink_escape_is_rejected(tmp_path: Path):
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"

    workspace.mkdir()
    outside.mkdir()

    link = workspace / "escape"
    link.symlink_to(outside, target_is_directory=True)

    result = validate_execution_path(workspace, link)

    assert result.allowed is False
    assert result.reason == "WORKSPACE_ESCAPE"
    assert result.is_symlink is True


def test_symlink_can_be_disabled_by_policy(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    target = workspace / "target"
    target.mkdir()

    link = workspace / "link"
    link.symlink_to(target, target_is_directory=True)

    policy = ExecutionPathPolicy(
        allow_existing_symlinks=False,
    )

    result = validate_execution_path(
        workspace,
        link,
        policy,
    )

    assert result.allowed is False
    assert result.reason == "SYMLINK_NOT_ALLOWED"


@pytest.mark.parametrize(
    "candidate",
    [
        "safe\x00evil",
        "safe\nfile",
        "safe\rfile",
        "safe\x01file",
        "safe\x7ffile",
    ],
)
def test_dangerous_characters_are_rejected(
    tmp_path: Path,
    candidate: str,
):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    result = validate_execution_path(workspace, candidate)

    assert result.allowed is False


def test_empty_workspace_is_rejected():
    result = validate_execution_path("", "file")

    assert result.allowed is False
    assert result.reason == "WORKSPACE_ROOT_EMPTY"


def test_empty_candidate_is_rejected(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    result = validate_execution_path(workspace, "")

    assert result.allowed is False
    assert result.reason == "CANDIDATE_EMPTY"


def test_invalid_workspace_type_is_rejected():
    result = validate_execution_path(
        object(),
        "file",
    )

    assert result.allowed is False
    assert result.reason == "WORKSPACE_ROOT_INVALID_TYPE"


def test_invalid_candidate_type_is_rejected(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    result = validate_execution_path(
        workspace,
        object(),
    )

    assert result.allowed is False
    assert result.reason == "CANDIDATE_INVALID_TYPE"


def test_boolean_policy_values_are_rejected():
    with pytest.raises(TypeError):
        ExecutionPathPolicy(
            allow_workspace_root=1,
        )

    with pytest.raises(TypeError):
        ExecutionPathPolicy(
            allow_existing_symlinks=1,
        )

    with pytest.raises(TypeError):
        ExecutionPathPolicy(
            require_within_workspace=1,
        )

    with pytest.raises(TypeError):
        ExecutionPathPolicy(
            reject_symlink_escape=1,
        )


def test_boolean_max_path_length_is_rejected():
    with pytest.raises(TypeError):
        ExecutionPathPolicy(max_path_length=True)


def test_invalid_max_path_length_is_rejected():
    with pytest.raises(ExecutionPathValidationError):
        ExecutionPathPolicy(max_path_length=0)


def test_max_path_length_is_enforced(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    policy = ExecutionPathPolicy(
        max_path_length=4,
    )

    result = validate_execution_path(
        workspace,
        "12345",
        policy,
    )

    assert result.allowed is False
    assert result.reason == "CANDIDATE_TOO_LONG"


def test_workspace_root_can_be_forbidden(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    policy = ExecutionPathPolicy(
        allow_workspace_root=False,
    )

    result = validate_execution_path(
        workspace,
        workspace,
        policy,
    )

    assert result.allowed is False
    assert result.reason == "WORKSPACE_ROOT_NOT_ALLOWED"


def test_require_valid_path_returns_result(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    result = require_valid_execution_path(
        workspace,
        "safe/file.txt",
    )

    assert result.allowed is True


def test_require_valid_path_fails_closed(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    with pytest.raises(ExecutionPathValidationError):
        require_valid_execution_path(
            workspace,
            "../outside",
        )


def test_result_to_dict(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    result = validate_execution_path(
        workspace,
        "file.txt",
    )

    data = result.to_dict()

    assert data["allowed"] is True
    assert data["candidate"] == "file.txt"
    assert data["workspace_root"] == str(workspace.resolve())
    assert data["reason"] == "EXECUTION_PATH_VALID"


def test_pathlike_inputs_are_supported(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    candidate = workspace / "file.txt"

    result = validate_execution_path(
        workspace,
        candidate,
    )

    assert result.allowed is True
