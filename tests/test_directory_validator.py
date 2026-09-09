from pathlib import Path

from sentinelshield.directory_validator import (
    DirectoryValidationResult,
    DirectoryValidator,
    validate_directory,
)


def test_existing_directory_is_valid(tmp_path):
    result = validate_directory(tmp_path)

    assert isinstance(
        result,
        DirectoryValidationResult,
    )
    assert result.valid is True
    assert result.path == tmp_path
    assert result.reason == "DIRECTORY_VALID"


def test_existing_file_is_not_directory(tmp_path):
    file_path = tmp_path / "project.txt"
    file_path.write_text("test", encoding="utf-8")

    result = validate_directory(file_path)

    assert result.valid is False
    assert result.path == file_path
    assert result.reason == "PATH_IS_NOT_DIRECTORY"


def test_missing_path_is_rejected(tmp_path):
    missing = tmp_path / "missing-project"

    result = validate_directory(missing)

    assert result.valid is False
    assert result.path == missing
    assert result.reason == "PATH_NOT_FOUND"


def test_string_directory_is_valid(tmp_path):
    result = validate_directory(str(tmp_path))

    assert result.valid is True
    assert result.path == tmp_path


def test_whitespace_is_normalized(tmp_path):
    result = validate_directory(
        f"  {tmp_path}  "
    )

    assert result.valid is True
    assert result.path == tmp_path


def test_none_is_rejected():
    result = validate_directory(None)

    assert result.valid is False
    assert result.path is None
    assert result.reason == "PATH_IS_NONE"


def test_empty_string_is_rejected():
    result = validate_directory("")

    assert result.valid is False
    assert result.reason == "PATH_IS_EMPTY"


def test_whitespace_only_is_rejected():
    result = validate_directory("   ")

    assert result.valid is False
    assert result.reason == "PATH_IS_EMPTY"


def test_null_character_is_rejected():
    result = validate_directory(
        "/tmp/project\x00evil"
    )

    assert result.valid is False
    assert result.reason == (
        "NULL_CHARACTER_NOT_ALLOWED"
    )


def test_integer_is_rejected():
    result = validate_directory(123)

    assert result.valid is False
    assert result.path is None
    assert result.reason == "UNSUPPORTED_PATH_TYPE"


def test_list_is_rejected():
    result = validate_directory(
        ["/tmp/project"]
    )

    assert result.valid is False
    assert result.reason == "UNSUPPORTED_PATH_TYPE"


def test_home_directory_is_valid():
    result = validate_directory("~")

    assert result.valid is True
    assert result.path == Path.home()


def test_missing_directory_is_not_created(tmp_path):
    missing = tmp_path / "new-project"

    assert not missing.exists()

    result = validate_directory(missing)

    assert result.valid is False
    assert result.reason == "PATH_NOT_FOUND"
    assert not missing.exists()


def test_permission_error_is_handled(
    monkeypatch,
    tmp_path,
):
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

    result = validate_directory(tmp_path)

    assert result.valid is False
    assert result.path == tmp_path
    assert result.reason == (
        "FILESYSTEM_PERMISSION_DENIED"
    )


def test_os_error_is_handled(
    monkeypatch,
    tmp_path,
):
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

    result = validate_directory(tmp_path)

    assert result.valid is False
    assert result.path == tmp_path
    assert result.reason == "FILESYSTEM_OS_ERROR"


def test_filesystem_is_not_modified(tmp_path):
    project = tmp_path / "project"
    project.mkdir()

    before = sorted(
        str(path.relative_to(tmp_path))
        for path in tmp_path.rglob("*")
    )

    result = validate_directory(project)

    after = sorted(
        str(path.relative_to(tmp_path))
        for path in tmp_path.rglob("*")
    )

    assert result.valid is True
    assert before == after
