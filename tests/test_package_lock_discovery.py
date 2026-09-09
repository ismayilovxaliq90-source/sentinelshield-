from pathlib import Path

from sentinelshield.package_lock_discovery import (
    discover_package_lock,
    discover_package_lockfile,
)


def test_basic_package_lock_discovery(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "package-lock.json").write_text(
        '{"name":"demo","lockfileVersion":3}'
    )

    result = discover_package_lock(root)

    assert result.found is True
    assert result.files == (Path("package-lock.json"),)
    assert result.count == 1
    assert result.lockfile_version == 3
    assert result.reason == "PACKAGE_LOCK_DISCOVERED"


def test_nested_package_lock(tmp_path):
    root = tmp_path / "project"
    nested = root / "apps" / "web"
    nested.mkdir(parents=True)
    (nested / "package-lock.json").write_text(
        '{"lockfileVersion":2}'
    )

    result = discover_package_lock(root)

    assert result.found is True
    assert result.files == (
        Path("apps/web/package-lock.json"),
    )
    assert result.lockfile_version == 2


def test_multiple_package_locks(tmp_path):
    root = tmp_path / "project"
    first = root / "frontend"
    second = root / "backend"
    first.mkdir(parents=True)
    second.mkdir(parents=True)

    (first / "package-lock.json").write_text("{}")
    (second / "package-lock.json").write_text("{}")

    result = discover_package_lock(root)

    assert result.found is True
    assert result.count == 2
    assert result.files == (
        Path("backend/package-lock.json"),
        Path("frontend/package-lock.json"),
    )
    assert result.lockfile_version is None


def test_missing_package_lock(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "package.json").write_text("{}")

    result = discover_package_lock(root)

    assert result.found is False
    assert result.files == ()
    assert result.count == 0
    assert result.lockfile_version is None
    assert result.reason == "PACKAGE_LOCK_NOT_FOUND"


def test_ignored_node_modules(tmp_path):
    root = tmp_path / "project"
    ignored = root / "node_modules" / "dependency"
    ignored.mkdir(parents=True)
    (ignored / "package-lock.json").write_text("{}")

    result = discover_package_lock(root)

    assert result.found is False
    assert result.files == ()


def test_symlink_is_not_followed(tmp_path):
    root = tmp_path / "project"
    target = tmp_path / "target"
    root.mkdir()
    target.mkdir()

    (target / "package-lock.json").write_text("{}")
    (root / "linked").symlink_to(target, target_is_directory=True)

    result = discover_package_lock(root)

    assert result.found is False


def test_invalid_json_does_not_break_discovery(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "package-lock.json").write_text("{invalid")

    result = discover_package_lock(root)

    assert result.found is True
    assert result.count == 1
    assert result.lockfile_version is None
    assert result.reason == "PACKAGE_LOCK_DISCOVERED"


def test_non_object_json_has_no_version(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "package-lock.json").write_text("[]")

    result = discover_package_lock(root)

    assert result.found is True
    assert result.lockfile_version is None


def test_boolean_lockfile_version_is_invalid(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "package-lock.json").write_text(
        '{"lockfileVersion":true}'
    )

    result = discover_package_lock(root)

    assert result.found is True
    assert result.lockfile_version is None


def test_float_integer_lockfile_version(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "package-lock.json").write_text(
        '{"lockfileVersion":3.0}'
    )

    result = discover_package_lock(root)

    assert result.lockfile_version == 3


def test_non_integer_float_version(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "package-lock.json").write_text(
        '{"lockfileVersion":3.5}'
    )

    result = discover_package_lock(root)

    assert result.lockfile_version is None


def test_deterministic_order(tmp_path):
    root = tmp_path / "project"
    root.mkdir()

    for name in ("z", "a", "m"):
        directory = root / name
        directory.mkdir()
        (directory / "package-lock.json").write_text("{}")

    result = discover_package_lock(root)

    assert result.files == (
        Path("a/package-lock.json"),
        Path("m/package-lock.json"),
        Path("z/package-lock.json"),
    )


def test_result_paths_are_relative(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "package-lock.json").write_text("{}")

    result = discover_package_lock(root)

    assert all(not path.is_absolute() for path in result.files)


def test_none():
    result = discover_package_lock(None)
    assert result.reason == "PATH_IS_NONE"


def test_empty():
    result = discover_package_lock("   ")
    assert result.reason == "PATH_IS_EMPTY"


def test_unsupported_type():
    result = discover_package_lock(123)
    assert result.reason == "UNSUPPORTED_PATH_TYPE"


def test_null_character():
    result = discover_package_lock("/tmp/a\x00b")
    assert result.reason == "NULL_CHARACTER_NOT_ALLOWED"


def test_missing_path(tmp_path):
    result = discover_package_lock(tmp_path / "missing")
    assert result.reason == "PATH_DOES_NOT_EXIST"


def test_file_path(tmp_path):
    file = tmp_path / "package-lock.json"
    file.write_text("{}")

    result = discover_package_lock(file)

    assert result.reason == "PATH_IS_NOT_DIRECTORY"


def test_alias_function(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "package-lock.json").write_text(
        '{"lockfileVersion":3}'
    )

    result = discover_package_lockfile(root)

    assert result.found is True
    assert result.lockfile_version == 3
