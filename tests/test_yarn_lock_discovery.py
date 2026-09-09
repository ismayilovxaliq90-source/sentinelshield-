from pathlib import Path

from sentinelshield.yarn_lock_discovery import (
    discover_yarn_lock,
    discover_yarn_locks,
)


def test_root_yarn_lock(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "yarn.lock").write_text("")

    result = discover_yarn_lock(root)

    assert result.found is True
    assert result.files == (Path("yarn.lock"),)
    assert result.file_count == 1
    assert result.reason == "YARN_LOCK_FOUND"


def test_nested_yarn_lock(tmp_path):
    root = tmp_path / "project"
    nested = root / "apps" / "web"
    nested.mkdir(parents=True)
    (nested / "yarn.lock").write_text("")

    result = discover_yarn_lock(root)

    assert result.found is True
    assert result.files == (
        Path("apps/web/yarn.lock"),
    )


def test_multiple_yarn_locks(tmp_path):
    root = tmp_path / "project"
    app = root / "app"
    service = root / "service"
    app.mkdir(parents=True)
    service.mkdir(parents=True)

    (root / "yarn.lock").write_text("")
    (app / "yarn.lock").write_text("")
    (service / "yarn.lock").write_text("")

    result = discover_yarn_lock(root)

    assert result.file_count == 3
    assert result.files == (
        Path("app/yarn.lock"),
        Path("service/yarn.lock"),
        Path("yarn.lock"),
    )


def test_deterministic_order(tmp_path):
    root = tmp_path / "project"
    z = root / "z"
    a = root / "a"
    z.mkdir(parents=True)
    a.mkdir(parents=True)

    (z / "yarn.lock").write_text("")
    (a / "yarn.lock").write_text("")

    result = discover_yarn_lock(root)

    assert result.files == (
        Path("a/yarn.lock"),
        Path("z/yarn.lock"),
    )


def test_node_modules_is_ignored(tmp_path):
    root = tmp_path / "project"
    ignored = root / "node_modules"
    ignored.mkdir(parents=True)
    (ignored / "yarn.lock").write_text("")

    result = discover_yarn_lock(root)

    assert result.found is False
    assert result.files == ()


def test_git_is_ignored(tmp_path):
    root = tmp_path / "project"
    ignored = root / ".git"
    ignored.mkdir(parents=True)
    (ignored / "yarn.lock").write_text("")

    result = discover_yarn_lock(root)

    assert result.found is False


def test_venv_is_ignored(tmp_path):
    root = tmp_path / "project"
    ignored = root / ".venv"
    ignored.mkdir(parents=True)
    (ignored / "yarn.lock").write_text("")

    result = discover_yarn_lock(root)

    assert result.found is False


def test_symlink_file_is_ignored(tmp_path):
    root = tmp_path / "project"
    target = tmp_path / "target"
    root.mkdir()
    target.write_text("")

    (root / "yarn.lock").symlink_to(target)

    result = discover_yarn_lock(root)

    assert result.found is False


def test_symlink_directory_is_not_followed(tmp_path):
    root = tmp_path / "project"
    target = tmp_path / "target"
    root.mkdir()
    target.mkdir()
    (target / "yarn.lock").write_text("")

    (root / "linked").symlink_to(
        target,
        target_is_directory=True,
    )

    result = discover_yarn_lock(root)

    assert result.found is False


def test_non_yarn_files_are_ignored(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "package.json").write_text("{}")
    (root / "package-lock.json").write_text("{}")

    result = discover_yarn_lock(root)

    assert result.found is False
    assert result.file_count == 0
    assert result.reason == "YARN_LOCK_NOT_FOUND"


def test_empty_project(tmp_path):
    root = tmp_path / "project"
    root.mkdir()

    result = discover_yarn_lock(root)

    assert result.found is False
    assert result.files == ()
    assert result.file_count == 0


def test_path_is_relative(tmp_path):
    root = tmp_path / "project"
    nested = root / "frontend"
    nested.mkdir(parents=True)
    (nested / "yarn.lock").write_text("")

    result = discover_yarn_lock(root)

    assert not result.files[0].is_absolute()


def test_none():
    result = discover_yarn_lock(None)
    assert result.reason == "PATH_IS_NONE"


def test_empty():
    result = discover_yarn_lock("   ")
    assert result.reason == "PATH_IS_EMPTY"


def test_unsupported_type():
    result = discover_yarn_lock(123)
    assert result.reason == "UNSUPPORTED_PATH_TYPE"


def test_null_character():
    result = discover_yarn_lock("/tmp/a\x00b")
    assert result.reason == "NULL_CHARACTER_NOT_ALLOWED"


def test_missing_path(tmp_path):
    result = discover_yarn_lock(tmp_path / "missing")
    assert result.reason == "PATH_DOES_NOT_EXIST"


def test_file_path(tmp_path):
    file = tmp_path / "file.txt"
    file.write_text("x")

    result = discover_yarn_lock(file)

    assert result.reason == "PATH_IS_NOT_DIRECTORY"


def test_alias_function(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "yarn.lock").write_text("")

    result = discover_yarn_locks(root)

    assert result.found is True
    assert result.files == (Path("yarn.lock"),)
