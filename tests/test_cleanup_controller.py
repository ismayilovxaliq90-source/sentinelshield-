from pathlib import Path

import pytest

from sentinelshield.cleanup_controller import (
    CleanupAction,
    CleanupController,
    CleanupError,
    CleanupResult,
)


def test_controller_requires_existing_workspace(tmp_path):
    workspace = tmp_path / "missing"

    with pytest.raises(CleanupError):
        CleanupController(workspace)


def test_controller_requires_directory(tmp_path):
    file_path = tmp_path / "file.txt"
    file_path.write_text("data")

    with pytest.raises(CleanupError):
        CleanupController(file_path)


def test_initial_registry_is_empty(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    controller = CleanupController(workspace)

    assert controller.registered_paths == ()


def test_register_file(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    file_path = workspace / "temp.txt"
    file_path.write_text("temporary")

    controller = CleanupController(workspace)
    registered = controller.register("temp.txt")

    assert registered == file_path.resolve()
    assert controller.registered_paths == ("temp.txt",)


def test_register_directory(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    directory = workspace / "temp"
    directory.mkdir()

    controller = CleanupController(workspace)
    controller.register(directory)

    assert controller.registered_paths == ("temp",)


def test_register_absolute_inside_workspace(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    file_path = workspace / "temp.txt"
    file_path.write_text("temporary")

    controller = CleanupController(workspace)
    controller.register(file_path)

    assert controller.registered_paths == ("temp.txt",)


def test_register_outside_workspace_is_rejected(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    outside = tmp_path / "outside.txt"
    outside.write_text("outside")

    controller = CleanupController(workspace)

    with pytest.raises(CleanupError):
        controller.register(outside)


def test_register_parent_traversal_is_rejected(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    outside = tmp_path / "outside.txt"
    outside.write_text("outside")

    controller = CleanupController(workspace)

    with pytest.raises(CleanupError):
        controller.register("../outside.txt")


def test_workspace_root_cannot_be_registered(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    controller = CleanupController(workspace)

    with pytest.raises(CleanupError):
        controller.register(".")


def test_duplicate_registration_is_idempotent(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    file_path = workspace / "temp.txt"
    file_path.write_text("temporary")

    controller = CleanupController(workspace)

    controller.register("temp.txt")
    controller.register("temp.txt")

    assert controller.registered_paths == ("temp.txt",)


def test_unregister_existing_path(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    file_path = workspace / "temp.txt"
    file_path.write_text("temporary")

    controller = CleanupController(workspace)
    controller.register("temp.txt")

    assert controller.unregister("temp.txt") is True
    assert controller.registered_paths == ()


def test_unregister_missing_path_returns_false(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    controller = CleanupController(workspace)

    assert controller.unregister("missing.txt") is False


def test_clear_registry(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    (workspace / "a.tmp").write_text("a")
    (workspace / "b.tmp").write_text("b")

    controller = CleanupController(workspace)
    controller.register("a.tmp")
    controller.register("b.tmp")

    controller.clear_registry()

    assert controller.registered_paths == ()


def test_plan_contains_file_action(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    (workspace / "temp.txt").write_text("temporary")

    controller = CleanupController(workspace)
    controller.register("temp.txt")

    plan = controller.plan()

    assert plan == (
        CleanupAction(
            action="REMOVE_FILE",
            path="temp.txt",
        ),
    )


def test_plan_contains_directory_action(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    directory = workspace / "temp"
    directory.mkdir()

    controller = CleanupController(workspace)
    controller.register("temp")

    plan = controller.plan()

    assert plan == (
        CleanupAction(
            action="REMOVE_DIRECTORY",
            path="temp",
        ),
    )


def test_plan_reports_missing_path(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    controller = CleanupController(workspace)
    controller.register("missing.tmp")

    plan = controller.plan()

    assert plan == (
        CleanupAction(
            action="NOT_FOUND",
            path="missing.tmp",
        ),
    )


def test_plan_is_deterministic(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    (workspace / "z.tmp").write_text("z")
    (workspace / "a.tmp").write_text("a")

    controller = CleanupController(workspace)

    controller.register("z.tmp")
    controller.register("a.tmp")

    plan = controller.plan()

    assert [action.path for action in plan] == [
        "a.tmp",
        "z.tmp",
    ]


def test_execute_removes_file(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    file_path = workspace / "temp.txt"
    file_path.write_text("temporary")

    controller = CleanupController(workspace)
    controller.register("temp.txt")

    result = controller.execute()

    assert isinstance(result, CleanupResult)
    assert result.success is True
    assert file_path.exists() is False
    assert controller.registered_paths == ()


def test_execute_removes_directory(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    directory = workspace / "temp"
    directory.mkdir()
    (directory / "data.txt").write_text("data")

    controller = CleanupController(workspace)
    controller.register("temp")

    result = controller.execute()

    assert result.success is True
    assert directory.exists() is False


def test_execute_handles_missing_path_safely(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    controller = CleanupController(workspace)
    controller.register("missing.tmp")

    result = controller.execute()

    assert result.success is True
    assert result.errors == ()
    assert controller.registered_paths == ()


def test_execute_does_not_remove_unregistered_file(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    file_path = workspace / "important.txt"
    file_path.write_text("keep")

    controller = CleanupController(workspace)

    result = controller.execute()

    assert result.success is True
    assert file_path.exists() is True


def test_execute_can_remove_multiple_resources(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    (workspace / "a.tmp").write_text("a")

    directory = workspace / "b.tmp"
    directory.mkdir()
    (directory / "data").write_text("b")

    controller = CleanupController(workspace)
    controller.register("a.tmp")
    controller.register("b.tmp")

    result = controller.execute()

    assert result.success is True
    assert not (workspace / "a.tmp").exists()
    assert not (workspace / "b.tmp").exists()


def test_cleanup_result_contains_completed_actions(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    (workspace / "temp.txt").write_text("temporary")

    controller = CleanupController(workspace)
    controller.register("temp.txt")

    result = controller.execute()

    assert len(result.actions) == 1
    assert result.actions[0].action == "REMOVE_FILE"
    assert result.actions[0].path == "temp.txt"


def test_cleanup_result_is_immutable(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    result = CleanupResult(
        success=True,
        actions=(),
        errors=(),
    )

    with pytest.raises(AttributeError):
        result.success = False


def test_cleanup_action_is_immutable():
    action = CleanupAction(
        action="REMOVE_FILE",
        path="temp.txt",
    )

    with pytest.raises(AttributeError):
        action.path = "other.txt"


def test_register_non_path_object_is_rejected_safely(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    controller = CleanupController(workspace)

    with pytest.raises(TypeError):
        controller.register(None)
