from pathlib import Path

from sentinelshield.package_json_discovery import (
    discover_package_json,
    discover_package_json_files,
)


def test_root_package_json_is_found(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "package.json").write_text("{}")

    result = discover_package_json(root)

    assert result.found is True
    assert result.files == (Path("package.json"),)
    assert result.count == 1
    assert result.reason == "PACKAGE_JSON_FOUND"


def test_nested_package_json_is_found(tmp_path):
    root = tmp_path / "project"
    nested = root / "apps" / "web"
    nested.mkdir(parents=True)
    (nested / "package.json").write_text("{}")

    result = discover_package_json(root)

    assert result.found is True
    assert result.files == (
        Path("apps/web/package.json"),
    )


def test_multiple_package_json_files(tmp_path):
    root = tmp_path / "project"
    first = root / "apps" / "web"
    second = root / "apps" / "api"

    first.mkdir(parents=True)
    second.mkdir(parents=True)

    (root / "package.json").write_text("{}")
    (first / "package.json").write_text("{}")
    (second / "package.json").write_text("{}")

    result = discover_package_json(root)

    assert result.count == 3
    assert result.files == (
        Path("apps/api/package.json"),
        Path("apps/web/package.json"),
        Path("package.json"),
    )


def test_paths_are_relative(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "package.json").write_text("{}")

    result = discover_package_json(root)

    assert all(not path.is_absolute() for path in result.files)


def test_deterministic_order(tmp_path):
    root = tmp_path / "project"
    root.mkdir()

    for name in ("z", "a", "m"):
        directory = root / "apps" / name
        directory.mkdir(parents=True)
        (directory / "package.json").write_text("{}")

    result = discover_package_json(root)

    assert result.files == (
        Path("apps/a/package.json"),
        Path("apps/m/package.json"),
        Path("apps/z/package.json"),
    )


def test_package_json_content_is_not_parsed(tmp_path):
    root = tmp_path / "project"
    root.mkdir()

    (root / "package.json").write_text(
        "{ this is intentionally invalid JSON"
    )

    result = discover_package_json(root)

    assert result.found is True
    assert result.count == 1
    assert result.reason == "PACKAGE_JSON_FOUND"


def test_similar_filename_is_not_detected(tmp_path):
    root = tmp_path / "project"
    root.mkdir()

    (root / "package.json.bak").write_text("{}")
    (root / "my-package.json").write_text("{}")

    result = discover_package_json(root)

    assert result.found is False
    assert result.files == ()
    assert result.reason == "PACKAGE_JSON_NOT_FOUND"


def test_ignored_node_modules_is_not_scanned(tmp_path):
    root = tmp_path / "project"
    ignored = root / "node_modules" / "dependency"
    ignored.mkdir(parents=True)

    (ignored / "package.json").write_text("{}")

    result = discover_package_json(root)

    assert result.found is False
    assert result.count == 0


def test_ignored_git_directory_is_not_scanned(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    ignored = root / ".git"
    ignored.mkdir()

    (ignored / "package.json").write_text("{}")

    result = discover_package_json(root)

    assert result.found is False


def test_ignored_venv_directory_is_not_scanned(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    ignored = root / ".venv"
    ignored.mkdir()

    (ignored / "package.json").write_text("{}")

    result = discover_package_json(root)

    assert result.found is False


def test_symlink_file_is_not_detected(tmp_path):
    root = tmp_path / "project"
    target = tmp_path / "real-package.json"

    root.mkdir()
    target.write_text("{}")

    (root / "package.json").symlink_to(target)

    result = discover_package_json(root)

    assert result.found is False


def test_symlink_directory_is_not_followed(tmp_path):
    root = tmp_path / "project"
    target = tmp_path / "external"

    root.mkdir()
    target.mkdir()
    (target / "package.json").write_text("{}")

    (root / "linked").symlink_to(target, target_is_directory=True)

    result = discover_package_json(root)

    assert result.found is False


def test_empty_project(tmp_path):
    root = tmp_path / "project"
    root.mkdir()

    result = discover_package_json(root)

    assert result.found is False
    assert result.files == ()
    assert result.count == 0
    assert result.reason == "PACKAGE_JSON_NOT_FOUND"


def test_none():
    result = discover_package_json(None)

    assert result.found is False
    assert result.reason == "PATH_IS_NONE"


def test_empty_path():
    result = discover_package_json("   ")

    assert result.reason == "PATH_IS_EMPTY"


def test_unsupported_type():
    result = discover_package_json(123)

    assert result.reason == "UNSUPPORTED_PATH_TYPE"


def test_null_character():
    result = discover_package_json("/tmp/a\x00b")

    assert result.reason == "NULL_CHARACTER_NOT_ALLOWED"


def test_missing_path(tmp_path):
    result = discover_package_json(tmp_path / "missing")

    assert result.reason == "PATH_DOES_NOT_EXIST"


def test_file_path(tmp_path):
    file = tmp_path / "project.txt"
    file.write_text("x")

    result = discover_package_json(file)

    assert result.reason == "PATH_IS_NOT_DIRECTORY"


def test_wrapper_function_matches_primary_function(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "package.json").write_text("{}")

    direct = discover_package_json(root)
    wrapped = discover_package_json_files(root)

    assert wrapped == direct
