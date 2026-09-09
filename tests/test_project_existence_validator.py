from pathlib import Path

from sentinelshield.project_existence_validator import (
    ProjectExistenceResult,
    ProjectExistenceValidator,
    validate_project_existence,
)


def test_existing_directory(tmp_path):
    result = validate_project_existence(tmp_path)

    assert isinstance(result, ProjectExistenceResult)
    assert result.exists is True
    assert result.path == tmp_path
    assert result.reason == "PROJECT_EXISTS"


def test_existing_file(tmp_path):
    file_path = tmp_path / "project.txt"
    file_path.write_text("test", encoding="utf-8")

    result = validate_project_existence(file_path)

    assert result.exists is True
    assert result.path == file_path
    assert result.reason == "PROJECT_EXISTS"


def test_missing_path(tmp_path):
    missing = tmp_path / "missing-project"

    result = validate_project_existence(missing)

    assert result.exists is False
    assert result.path == missing
    assert result.reason == "PROJECT_NOT_FOUND"


def test_string_path(tmp_path):
    result = validate_project_existence(str(tmp_path))

    assert result.exists is True
    assert result.path == tmp_path
    assert result.reason == "PROJECT_EXISTS"


def test_path_with_whitespace(tmp_path):
    result = validate_project_existence(
        f"  {tmp_path}  "
    )

    assert result.exists is True
    assert result.path == tmp_path


def test_none():
    result = validate_project_existence(None)

    assert result.exists is False
    assert result.path is None
    assert result.reason == "PATH_IS_NONE"


def test_empty_string():
    result = validate_project_existence("")

    assert result.exists is False
    assert result.path is None
    assert result.reason == "PATH_IS_EMPTY"


def test_whitespace_only():
    result = validate_project_existence("   ")

    assert result.exists is False
    assert result.path is None
    assert result.reason == "PATH_IS_EMPTY"


def test_null_character():
    result = validate_project_existence(
        "/tmp/project\x00evil"
    )

    assert result.exists is False
    assert result.path is None
    assert result.reason == (
        "NULL_CHARACTER_NOT_ALLOWED"
    )


def test_integer_is_rejected():
    result = validate_project_existence(123)

    assert result.exists is False
    assert result.path is None
    assert result.reason == "UNSUPPORTED_PATH_TYPE"


def test_list_is_rejected():
    result = validate_project_existence(
        ["/tmp/project"]
    )

    assert result.exists is False
    assert result.path is None
    assert result.reason == "UNSUPPORTED_PATH_TYPE"


def test_missing_path_is_not_created(tmp_path):
    missing = tmp_path / "not-created"

    result = validate_project_existence(missing)

    assert result.exists is False
    assert not missing.exists()


def test_filesystem_tree_is_unchanged(tmp_path):
    before = sorted(
        str(p.relative_to(tmp_path))
        for p in tmp_path.rglob("*")
    )

    validate_project_existence(tmp_path)

    after = sorted(
        str(p.relative_to(tmp_path))
        for p in tmp_path.rglob("*")
    )

    assert before == after


def test_permission_error_is_handled(monkeypatch, tmp_path):
    original_exists = Path.exists

    def fake_exists(self):
        if self == tmp_path:
            raise PermissionError("denied")
        return original_exists(self)

    monkeypatch.setattr(
        Path,
        "exists",
        fake_exists,
    )

    result = validate_project_existence(tmp_path)

    assert result.exists is False
    assert result.path == tmp_path
    assert result.reason == (
        "FILESYSTEM_PERMISSION_DENIED"
    )


def test_os_error_is_handled(monkeypatch, tmp_path):
    original_exists = Path.exists

    def fake_exists(self):
        if self == tmp_path:
            raise OSError("filesystem failure")
        return original_exists(self)

    monkeypatch.setattr(
        Path,
        "exists",
        fake_exists,
    )

    result = validate_project_existence(tmp_path)

    assert result.exists is False
    assert result.path == tmp_path
    assert result.reason == "FILESYSTEM_OS_ERROR"
