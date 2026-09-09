from pathlib import Path

from sentinelshield.empty_path_validator import (
    EmptyPathValidationResult,
    EmptyPathValidator,
    validate_empty_path,
)


def test_empty_string_is_rejected():
    result = validate_empty_path("")

    assert isinstance(result, EmptyPathValidationResult)
    assert result.valid is False
    assert result.reason == "PATH_IS_EMPTY"


def test_whitespace_is_rejected():
    result = validate_empty_path("   ")

    assert result.valid is False
    assert result.reason == "PATH_IS_EMPTY"


def test_tabs_and_newlines_are_rejected():
    result = validate_empty_path("\t\n")

    assert result.valid is False
    assert result.reason == "PATH_IS_EMPTY"


def test_normal_path_is_accepted():
    result = validate_empty_path("/tmp/project")

    assert result.valid is True
    assert result.reason == "PATH_IS_NOT_EMPTY"


def test_path_with_surrounding_whitespace_is_not_empty():
    result = validate_empty_path("  /tmp/project  ")

    assert result.valid is True
    assert result.reason == "PATH_IS_NOT_EMPTY"


def test_path_object_is_accepted():
    result = validate_empty_path(Path("/tmp/project"))

    assert result.valid is True
    assert result.reason == "PATH_IS_NOT_EMPTY"


def test_none_is_rejected():
    result = validate_empty_path(None)

    assert result.valid is False
    assert result.reason == "PATH_IS_NONE"


def test_unsupported_type_is_rejected():
    result = validate_empty_path(123)

    assert result.valid is False
    assert result.reason == "UNSUPPORTED_PATH_TYPE"


def test_validator_is_read_only(tmp_path):
    before = sorted(
        str(p.relative_to(tmp_path))
        for p in tmp_path.rglob("*")
    )

    result = validate_empty_path(
        str(tmp_path / "project")
    )

    after = sorted(
        str(p.relative_to(tmp_path))
        for p in tmp_path.rglob("*")
    )

    assert result.valid is True
    assert before == after
