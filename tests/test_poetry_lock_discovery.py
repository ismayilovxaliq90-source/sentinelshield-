from pathlib import Path

from sentinelshield.poetry_lock_discovery import (
    discover_poetry_lock,
)


def test_poetry_lock_found(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "poetry.lock").write_text("")

    result = discover_poetry_lock(root)

    assert result.found is True
    assert result.root == root.resolve()
    assert result.files == (Path("poetry.lock"),)
    assert result.count == 1
    assert result.reason == "POETRY_LOCK_FOUND"


def test_poetry_lock_not_found(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "pyproject.toml").write_text("")

    result = discover_poetry_lock(root)

    assert result.found is False
    assert result.files == ()
    assert result.count == 0
    assert result.reason == "POETRY_LOCK_NOT_FOUND"


def test_nested_poetry_lock(tmp_path):
    root = tmp_path / "project"
    nested = root / "services" / "api"
    nested.mkdir(parents=True)
    (nested / "poetry.lock").write_text("")

    result = discover_poetry_lock(root)

    assert result.found is True
    assert result.files == (
        Path("services/api/poetry.lock"),
    )


def test_multiple_poetry_locks(tmp_path):
    root = tmp_path / "project"
    first = root / "apps" / "one"
    second = root / "apps" / "two"
    first.mkdir(parents=True)
    second.mkdir(parents=True)

    (first / "poetry.lock").write_text("")
    (second / "poetry.lock").write_text("")

    result = discover_poetry_lock(root)

    assert result.found is True
    assert result.count == 2
    assert result.files == (
        Path("apps/one/poetry.lock"),
        Path("apps/two/poetry.lock"),
    )


def test_paths_are_relative(tmp_path):
    root = tmp_path / "project"
    nested = root / "backend"
    nested.mkdir(parents=True)
    (nested / "poetry.lock").write_text("")

    result = discover_poetry_lock(root)

    assert result.files[0] == Path("backend/poetry.lock")
    assert not result.files[0].is_absolute()


def test_deterministic_order(tmp_path):
    root = tmp_path / "project"
    for name in ("z", "a", "m"):
        directory = root / name
        directory.mkdir(parents=True)
        (directory / "poetry.lock").write_text("")

    result = discover_poetry_lock(root)

    assert result.files == (
        Path("a/poetry.lock"),
        Path("m/poetry.lock"),
        Path("z/poetry.lock"),
    )


def test_ignored_directory_not_scanned(tmp_path):
    root = tmp_path / "project"
    ignored = root / ".venv"
    ignored.mkdir(parents=True)
    (ignored / "poetry.lock").write_text("")

    result = discover_poetry_lock(root)

    assert result.found is False
    assert result.files == ()


def test_node_modules_not_scanned(tmp_path):
    root = tmp_path / "project"
    ignored = root / "node_modules"
    ignored.mkdir(parents=True)
    (ignored / "poetry.lock").write_text("")

    result = discover_poetry_lock(root)

    assert result.found is False


def test_symlink_not_followed(tmp_path):
    root = tmp_path / "project"
    target = tmp_path / "target"
    root.mkdir()
    target.mkdir()
    (target / "poetry.lock").write_text("")

    (root / "linked").symlink_to(
        target,
        target_is_directory=True,
    )

    result = discover_poetry_lock(root)

    assert result.found is False


def test_empty_project(tmp_path):
    root = tmp_path / "project"
    root.mkdir()

    result = discover_poetry_lock(root)

    assert result.found is False
    assert result.count == 0


def test_none():
    result = discover_poetry_lock(None)
    assert result.reason == "PATH_IS_NONE"


def test_empty():
    result = discover_poetry_lock("   ")
    assert result.reason == "PATH_IS_EMPTY"


def test_unsupported_type():
    result = discover_poetry_lock(123)
    assert result.reason == "UNSUPPORTED_PATH_TYPE"


def test_null_character():
    result = discover_poetry_lock("/tmp/a\x00b")
    assert result.reason == "NULL_CHARACTER_NOT_ALLOWED"


def test_missing_path(tmp_path):
    result = discover_poetry_lock(tmp_path / "missing")
    assert result.reason == "PATH_DOES_NOT_EXIST"


def test_file_path(tmp_path):
    file = tmp_path / "project.txt"
    file.write_text("x")

    result = discover_poetry_lock(file)

    assert result.reason == "PATH_IS_NOT_DIRECTORY"
