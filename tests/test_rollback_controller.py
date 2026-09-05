from pathlib import Path

import pytest

from sentinelshield.rollback_controller import (
    RollbackAction,
    RollbackController,
    RollbackError,
    RollbackPlan,
)


def make_baseline(workspace: Path):
    controller = RollbackController(workspace)

    return controller._current_files()


def baseline_from_current(workspace: Path):
    controller = RollbackController(workspace)

    current = controller._current_files()

    return [
        {
            "path": path,
            "size": values[0],
            "sha256": values[1],
        }
        for path, values in current.items()
    ]


def test_workspace_must_exist(tmp_path):
    missing = tmp_path / "missing"

    with pytest.raises(RollbackError):
        RollbackController(missing)


def test_workspace_must_be_directory(tmp_path):
    file_path = tmp_path / "file.txt"
    file_path.write_text("x")

    with pytest.raises(RollbackError):
        RollbackController(file_path)


def test_clean_workspace_produces_empty_plan(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    (workspace / "a.txt").write_text(
        "hello",
        encoding="utf-8",
    )

    baseline = baseline_from_current(workspace)

    controller = RollbackController(workspace)

    plan = controller.create_plan(baseline)

    assert isinstance(plan, RollbackPlan)
    assert plan.is_empty is True
    assert plan.actions == ()


def test_new_file_is_marked_for_delete(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    (workspace / "a.txt").write_text(
        "original",
        encoding="utf-8",
    )

    baseline = baseline_from_current(workspace)

    (workspace / "new.txt").write_text(
        "new",
        encoding="utf-8",
    )

    controller = RollbackController(workspace)
    plan = controller.create_plan(baseline)

    assert RollbackAction(
        action="DELETE",
        path="new.txt",
    ) in plan.actions


def test_deleted_file_is_marked_missing(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    (workspace / "a.txt").write_text(
        "original",
        encoding="utf-8",
    )

    baseline = baseline_from_current(workspace)

    (workspace / "a.txt").unlink()

    controller = RollbackController(workspace)
    plan = controller.create_plan(baseline)

    assert RollbackAction(
        action="MISSING",
        path="a.txt",
    ) in plan.actions


def test_modified_file_is_marked_restore(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    (workspace / "a.txt").write_text(
        "original",
        encoding="utf-8",
    )

    baseline = baseline_from_current(workspace)

    (workspace / "a.txt").write_text(
        "modified",
        encoding="utf-8",
    )

    controller = RollbackController(workspace)
    plan = controller.create_plan(baseline)

    assert RollbackAction(
        action="RESTORE",
        path="a.txt",
    ) in plan.actions


def test_plan_is_deterministically_sorted(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    (workspace / "z.txt").write_text("z")
    (workspace / "a.txt").write_text("a")

    baseline = baseline_from_current(workspace)

    (workspace / "new-z.txt").write_text("z")
    (workspace / "new-a.txt").write_text("a")

    controller = RollbackController(workspace)
    plan = controller.create_plan(baseline)

    paths = [action.path for action in plan.actions]

    assert paths == sorted(paths)


def test_plan_validation_accepts_valid_plan(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    controller = RollbackController(workspace)

    plan = RollbackPlan(
        actions=(
            RollbackAction(
                action="DELETE",
                path="new.txt",
            ),
        )
    )

    assert controller.validate_plan(plan) is True


def test_plan_validation_rejects_wrong_type(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    controller = RollbackController(workspace)

    with pytest.raises(TypeError):
        controller.validate_plan("invalid")


def test_plan_validation_rejects_unknown_action(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    controller = RollbackController(workspace)

    plan = RollbackPlan(
        actions=(
            RollbackAction(
                action="EXECUTE",
                path="file.txt",
            ),
        )
    )

    assert controller.validate_plan(plan) is False


def test_plan_validation_rejects_empty_path(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    controller = RollbackController(workspace)

    plan = RollbackPlan(
        actions=(
            RollbackAction(
                action="DELETE",
                path="",
            ),
        )
    )

    assert controller.validate_plan(plan) is False


def test_plan_validation_rejects_absolute_path(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    controller = RollbackController(workspace)

    plan = RollbackPlan(
        actions=(
            RollbackAction(
                action="DELETE",
                path="/etc/passwd",
            ),
        )
    )

    assert controller.validate_plan(plan) is False


def test_plan_validation_rejects_parent_traversal(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    controller = RollbackController(workspace)

    plan = RollbackPlan(
        actions=(
            RollbackAction(
                action="DELETE",
                path="../outside.txt",
            ),
        )
    )

    assert controller.validate_plan(plan) is False


def test_file_hash_is_sha256(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    file_path = workspace / "a.txt"
    file_path.write_text(
        "hello",
        encoding="utf-8",
    )

    controller = RollbackController(workspace)

    digest = controller._hash_file(file_path)

    assert len(digest) == 64
    assert all(
        character in "0123456789abcdef"
        for character in digest
    )


def test_current_files_returns_relative_paths(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    nested = workspace / "sub"
    nested.mkdir()

    (nested / "file.txt").write_text("data")

    controller = RollbackController(workspace)

    current = controller._current_files()

    assert "sub/file.txt" in current


def test_baseline_conversion_preserves_metadata(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    (workspace / "a.txt").write_text(
        "abc",
        encoding="utf-8",
    )

    controller = RollbackController(workspace)
    current = controller._current_files()

    baseline = [
        {
            "path": path,
            "size": values[0],
            "sha256": values[1],
        }
        for path, values in current.items()
    ]

    converted = controller._baseline_files(baseline)

    assert converted == current


def test_multiple_changes_are_detected(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    (workspace / "keep.txt").write_text("keep")
    (workspace / "modify.txt").write_text("old")
    (workspace / "delete.txt").write_text("delete")

    baseline = baseline_from_current(workspace)

    (workspace / "modify.txt").write_text("new")
    (workspace / "delete.txt").unlink()
    (workspace / "new.txt").write_text("new")

    controller = RollbackController(workspace)
    plan = controller.create_plan(baseline)

    assert RollbackAction(
        action="RESTORE",
        path="modify.txt",
    ) in plan.actions

    assert RollbackAction(
        action="MISSING",
        path="delete.txt",
    ) in plan.actions

    assert RollbackAction(
        action="DELETE",
        path="new.txt",
    ) in plan.actions


def test_controller_does_not_modify_workspace(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    file_path = workspace / "a.txt"
    file_path.write_text("original")

    baseline = baseline_from_current(workspace)

    file_path.write_text("modified")

    controller = RollbackController(workspace)
    controller.create_plan(baseline)

    assert file_path.read_text() == "modified"


def test_empty_plan_validation(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    controller = RollbackController(workspace)

    plan = RollbackPlan(actions=())

    assert plan.is_empty is True
    assert controller.validate_plan(plan) is True


def test_plan_actions_are_immutable(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    action = RollbackAction(
        action="DELETE",
        path="file.txt",
    )

    plan = RollbackPlan(actions=(action,))

    with pytest.raises(AttributeError):
        action.path = "other.txt"

    assert len(plan.actions) == 1
