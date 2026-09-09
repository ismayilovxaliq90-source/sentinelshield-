from pathlib import Path

from sentinelshield.pipfile_lock_discovery import (
    discover_pipfile_lock,
)


def test_root_pipfile_lock_detected(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "Pipfile.lock").write_text("{}")

    result = discover_pipfile_lock(root)

    assert result.found is True
    assert result.files == (Path("Pipfile.lock"),)
    assert result.count == 1
    assert result.reason == "PIPFILE_LOCK_DISCOVERED"


def test_nested_pipfile_lock_detected(tmp_path):
    root = tmp_path / "project"
    nested = root / "services" / "api"
    nested.mkdir(parents=True)
    (nested / "Pipfile.lock").write_text("{}")

    result = discover_pipfile_lock(root)

    assert result.found is True
    assert result.files == (
        Path("services/api/Pipfile.lock"),
    )


def test_multiple_pipfile_locks(tmp_path):
    root = tmp_path / "project"
    a = root / "apps" / "a"
    b = root / "apps" / "b"
    a.mkdir(parents=True)
    b.mkdir(parents=True)

    (a / "Pipfile.lock").write_text("{}")
    (b / "Pipfile.lock").write_text("{}")

    result = discover_pipfile_lock(root)

    assert result.count == 2
    assert result.files == (
        Path("apps/a/Pipfile.lock"),
        Path("apps/b/Pipfile.lock"),
    )


def test_result_paths_are_relative(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "Pipfile.lock").write_text("{}")

    result = discover_pipfile_lock(root)

    assert result.files[0] == Path("Pipfile.lock")
    assert not result.files[0].is_absolute()


def test_deterministic_order(tmp_path):
    root = tmp_path / "project"

    z = root / "z"
    a = root / "a"
    m = root / "m"

    z.mkdir(parents=True)
    a.mkdir(parents=True)
    m.mkdir(parents=True)

    (z / "Pipfile.lock").write_text("{}")
    (a / "Pipfile.lock").write_text("{}")
    (m / "Pipfile.lock").write_text("{}")

    result = discover_pipfile_lock(root)

    assert result.files == (
        Path("a/Pipfile.lock"),
        Path("m/Pipfile.lock"),
        Path("z/Pipfile.lock"),
    )


def test_pipfile_without_lock_is_not_detected(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "Pipfile").write_text("")

    result = discover_pipfile_lock(root)

    assert result.found is False
    assert result.count == 0
    assert result.reason == "PIPFILE_LOCK_NOT_FOUND"


def test_similar_filename_is_not_detected(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "Pipfile.lock.bak").write_text("{}")

    result = discover_pipfile_lock(root)

    assert result.found is False


def test_case_insensitive_filename(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "PIPFILE.LOCK").write_text("{}")

    result = discover_pipfile_lock(root)

    assert result.found is True


def test_ignored_directory_not_scanned(tmp_path):
    root = tmp_path / "project"
    ignored = root / "node_modules"
    ignored.mkdir(parents=True)
    (ignored / "Pipfile.lock").write_text("{}")

    result = discover_pipfile_lock(root)

    assert result.found is False
    assert result.files == ()


def test_symlink_directory_not_followed(tmp_path):
    root = tmp_path / "project"
    target = tmp_path / "target"

    root.mkdir()
    target.mkdir()
    (target / "Pipfile.lock").write_text("{}")

    (root / "linked").symlink_to(
        target,
        target_is_directory=True,
    )

    result = discover_pipfile_lock(root)

    assert result.found is False


def test_empty_project(tmp_path):
    root = tmp_path / "project"
    root.mkdir()

    result = discover_pipfile_lock(root)

    assert result.found is False
    assert result.files == ()
    assert result.count == 0


def test_none():
    result = discover_pipfile_lock(None)

    assert result.reason == "PATH_IS_NONE"


def test_empty():
    result = discover_pipfile_lock("   ")

    assert result.reason == "PATH_IS_EMPTY"


def test_unsupported_type():
    result = discover_pipfile_lock(123)

    assert result.reason == "UNSUPPORTED_PATH_TYPE"


def test_null_character():
    result = discover_pipfile_lock("/tmp/a\x00b")

    assert result.reason == "NULL_CHARACTER_NOT_ALLOWED"


def test_missing_path(tmp_path):
    result = discover_pipfile_lock(
        tmp_path / "missing"
    )

    assert result.reason == "PATH_DOES_NOT_EXIST"


def test_file_path(tmp_path):
    file = tmp_path / "file.txt"
    file.write_text("x")

    result = discover_pipfile_lock(file)

    assert result.reason == "PATH_IS_NOT_DIRECTORY"
