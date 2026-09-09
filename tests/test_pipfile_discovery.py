from pathlib import Path

from sentinelshield.pipfile_discovery import (
    discover_pipfiles,
)


def test_basic_pipfile_discovery(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "Pipfile").write_text(
        "[packages]\nrequests = \"*\"\n"
    )

    result = discover_pipfiles(root)

    assert result.found is True
    assert result.files == (Path("Pipfile"),)
    assert result.count == 1
    assert result.reason == "PIPFILE_DISCOVERED"


def test_nested_pipfile_discovery(tmp_path):
    root = tmp_path / "project"
    nested = root / "services" / "api"
    nested.mkdir(parents=True)
    (nested / "Pipfile").write_text("")

    result = discover_pipfiles(root)

    assert result.found is True
    assert result.files == (
        Path("services/api/Pipfile"),
    )


def test_multiple_pipfiles(tmp_path):
    root = tmp_path / "project"
    first = root / "app"
    second = root / "service"
    first.mkdir(parents=True)
    second.mkdir(parents=True)

    (first / "Pipfile").write_text("")
    (second / "Pipfile").write_text("")

    result = discover_pipfiles(root)

    assert result.count == 2
    assert result.files == (
        Path("app/Pipfile"),
        Path("service/Pipfile"),
    )


def test_only_exact_pipfile_name(tmp_path):
    root = tmp_path / "project"
    root.mkdir()

    (root / "Pipfile").write_text("")
    (root / "pipfile").write_text("")
    (root / "Pipfile.txt").write_text("")
    (root / "Pipfile.lock").write_text("")

    result = discover_pipfiles(root)

    assert result.files == (Path("Pipfile"),)
    assert result.count == 1


def test_deterministic_order(tmp_path):
    root = tmp_path / "project"
    root.mkdir()

    for directory in ("zeta", "alpha", "middle"):
        path = root / directory
        path.mkdir()
        (path / "Pipfile").write_text("")

    result = discover_pipfiles(root)

    assert result.files == (
        Path("alpha/Pipfile"),
        Path("middle/Pipfile"),
        Path("zeta/Pipfile"),
    )


def test_ignored_directories_are_not_scanned(tmp_path):
    root = tmp_path / "project"
    root.mkdir()

    ignored = root / ".venv"
    ignored.mkdir()
    (ignored / "Pipfile").write_text("")

    node_modules = root / "node_modules"
    node_modules.mkdir()
    (node_modules / "Pipfile").write_text("")

    result = discover_pipfiles(root)

    assert result.found is False
    assert result.files == ()


def test_symlink_directory_is_not_followed(tmp_path):
    root = tmp_path / "project"
    target = tmp_path / "target"

    root.mkdir()
    target.mkdir()
    (target / "Pipfile").write_text("")

    (root / "linked").symlink_to(
        target,
        target_is_directory=True,
    )

    result = discover_pipfiles(root)

    assert result.found is False
    assert result.files == ()


def test_symlink_file_is_not_collected(tmp_path):
    root = tmp_path / "project"
    target = tmp_path / "Pipfile"

    root.mkdir()
    target.write_text("")
    (root / "Pipfile").symlink_to(target)

    result = discover_pipfiles(root)

    assert result.found is False


def test_empty_project(tmp_path):
    root = tmp_path / "project"
    root.mkdir()

    result = discover_pipfiles(root)

    assert result.found is False
    assert result.files == ()
    assert result.count == 0
    assert result.reason == "PIPFILE_NOT_FOUND"


def test_relative_paths(tmp_path):
    root = tmp_path / "project"
    nested = root / "src"
    nested.mkdir(parents=True)
    (nested / "Pipfile").write_text("")

    result = discover_pipfiles(root)

    assert all(not path.is_absolute() for path in result.files)


def test_none():
    result = discover_pipfiles(None)
    assert result.reason == "PATH_IS_NONE"


def test_empty():
    result = discover_pipfiles("   ")
    assert result.reason == "PATH_IS_EMPTY"


def test_unsupported_type():
    result = discover_pipfiles(123)
    assert result.reason == "UNSUPPORTED_PATH_TYPE"


def test_null_character():
    result = discover_pipfiles("/tmp/a\x00b")
    assert result.reason == "NULL_CHARACTER_NOT_ALLOWED"


def test_missing_path(tmp_path):
    result = discover_pipfiles(tmp_path / "missing")
    assert result.reason == "PATH_DOES_NOT_EXIST"


def test_file_path(tmp_path):
    file = tmp_path / "file.txt"
    file.write_text("x")

    result = discover_pipfiles(file)

    assert result.reason == "PATH_IS_NOT_DIRECTORY"


def test_path_object_input(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "Pipfile").write_text("")

    result = discover_pipfiles(Path(root))

    assert result.found is True
    assert result.count == 1
