from pathlib import Path

from sentinelshield.pyproject_discovery import (
    discover_pyproject,
)


def test_root_pyproject_discovered(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "pyproject.toml").write_text("[project]\n")

    result = discover_pyproject(root)

    assert result.found is True
    assert result.files == (Path("pyproject.toml"),)
    assert result.count == 1
    assert result.reason == "PYPROJECT_TOML_DISCOVERED"


def test_nested_pyproject_discovered(tmp_path):
    root = tmp_path / "project"
    nested = root / "services" / "api"
    nested.mkdir(parents=True)
    (nested / "pyproject.toml").write_text("")

    result = discover_pyproject(root)

    assert result.found is True
    assert result.files == (
        Path("services/api/pyproject.toml"),
    )


def test_multiple_pyprojects(tmp_path):
    root = tmp_path / "project"
    (root / "a").mkdir(parents=True)
    (root / "b").mkdir(parents=True)

    (root / "a" / "pyproject.toml").write_text("")
    (root / "b" / "pyproject.toml").write_text("")

    result = discover_pyproject(root)

    assert result.count == 2
    assert result.files == (
        Path("a/pyproject.toml"),
        Path("b/pyproject.toml"),
    )


def test_deterministic_order(tmp_path):
    root = tmp_path / "project"
    for name in ("z", "a", "m"):
        directory = root / name
        directory.mkdir(parents=True)
        (directory / "pyproject.toml").write_text("")

    result = discover_pyproject(root)

    assert result.files == (
        Path("a/pyproject.toml"),
        Path("m/pyproject.toml"),
        Path("z/pyproject.toml"),
    )


def test_non_target_toml_ignored(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "config.toml").write_text("")

    result = discover_pyproject(root)

    assert result.found is False
    assert result.count == 0
    assert result.reason == "PYPROJECT_TOML_NOT_FOUND"


def test_ignored_directory_not_scanned(tmp_path):
    root = tmp_path / "project"
    ignored = root / ".venv" / "package"
    ignored.mkdir(parents=True)
    (ignored / "pyproject.toml").write_text("")

    result = discover_pyproject(root)

    assert result.found is False
    assert result.files == ()


def test_node_modules_not_scanned(tmp_path):
    root = tmp_path / "project"
    ignored = root / "node_modules" / "pkg"
    ignored.mkdir(parents=True)
    (ignored / "pyproject.toml").write_text("")

    result = discover_pyproject(root)

    assert result.found is False


def test_symlink_not_followed(tmp_path):
    root = tmp_path / "project"
    target = tmp_path / "target"
    root.mkdir()
    target.mkdir()
    (target / "pyproject.toml").write_text("")

    (root / "linked").symlink_to(target, target_is_directory=True)

    result = discover_pyproject(root)

    assert result.found is False


def test_paths_are_relative(tmp_path):
    root = tmp_path / "project"
    nested = root / "src"
    nested.mkdir(parents=True)
    (nested / "pyproject.toml").write_text("")

    result = discover_pyproject(root)

    assert all(not path.is_absolute() for path in result.files)


def test_case_sensitive_target(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "PYPROJECT.TOML").write_text("")

    result = discover_pyproject(root)

    assert result.found is False


def test_none():
    result = discover_pyproject(None)
    assert result.reason == "PATH_IS_NONE"


def test_empty():
    result = discover_pyproject("   ")
    assert result.reason == "PATH_IS_EMPTY"


def test_unsupported_type():
    result = discover_pyproject(123)
    assert result.reason == "UNSUPPORTED_PATH_TYPE"


def test_null_character():
    result = discover_pyproject("/tmp/a\x00b")
    assert result.reason == "NULL_CHARACTER_NOT_ALLOWED"


def test_missing_path(tmp_path):
    result = discover_pyproject(tmp_path / "missing")
    assert result.reason == "PATH_DOES_NOT_EXIST"


def test_file_path(tmp_path):
    file = tmp_path / "file.txt"
    file.write_text("x")

    result = discover_pyproject(file)

    assert result.reason == "PATH_IS_NOT_DIRECTORY"


def test_empty_project(tmp_path):
    root = tmp_path / "project"
    root.mkdir()

    result = discover_pyproject(root)

    assert result.found is False
    assert result.files == ()
    assert result.count == 0
    assert result.reason == "PYPROJECT_TOML_NOT_FOUND"
