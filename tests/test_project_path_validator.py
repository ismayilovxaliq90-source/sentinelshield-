from pathlib import Path

from sentinelshield.project_path_validator import (
    PathValidationResult,
    ProjectPathValidator,
    validate_project_path,
)


def test_valid_string_path():
    result = validate_project_path(
        "/tmp/project"
    )

    assert isinstance(
        result,
        PathValidationResult,
    )
    assert result.valid is True
    assert result.normalized == "/tmp/project"
    assert result.reason == "VALID"


def test_path_is_trimmed():
    result = validate_project_path(
        "   /tmp/project   "
    )

    assert result.valid is True
    assert result.normalized == "/tmp/project"


def test_path_object_is_valid():
    result = validate_project_path(
        Path("/tmp/project")
    )

    assert result.valid is True
    assert result.normalized == "/tmp/project"


def test_none_is_rejected():
    result = validate_project_path(None)

    assert result.valid is False
    assert result.normalized is None
    assert result.reason == "PATH_IS_NONE"


def test_empty_string_is_rejected():
    result = validate_project_path("")

    assert result.valid is False
    assert result.normalized is None
    assert result.reason == "PATH_IS_EMPTY"


def test_whitespace_only_is_rejected():
    result = validate_project_path("     ")

    assert result.valid is False
    assert result.normalized is None
    assert result.reason == "PATH_IS_EMPTY"


def test_null_character_is_rejected():
    result = validate_project_path(
        "/tmp/project\x00evil"
    )

    assert result.valid is False
    assert result.reason == (
        "NULL_CHARACTER_NOT_ALLOWED"
    )


def test_null_character_in_path_object_is_rejected():
    path = Path("/tmp/project\x00evil")

    result = validate_project_path(path)

    assert result.valid is False
    assert result.reason == (
        "NULL_CHARACTER_NOT_ALLOWED"
    )


def test_integer_is_rejected():
    result = validate_project_path(123)

    assert result.valid is False
    assert result.reason == (
        "UNSUPPORTED_PATH_TYPE"
    )


def test_list_is_rejected():
    result = validate_project_path(
        ["/tmp/project"]
    )

    assert result.valid is False
    assert result.reason == (
        "UNSUPPORTED_PATH_TYPE"
    )


def test_validation_is_read_only(tmp_path):
    before = sorted(
        str(p.relative_to(tmp_path))
        for p in tmp_path.rglob("*")
    )

    result = validate_project_path(
        str(tmp_path)
    )

    after = sorted(
        str(p.relative_to(tmp_path))
        for p in tmp_path.rglob("*")
    )

    assert result.valid is True
    assert before == after
