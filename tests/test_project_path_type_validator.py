from pathlib import Path

from sentinelshield.project_path_type_validator import (
    PathTypeValidationResult,
    ProjectPathTypeValidator,
    validate_project_path_type,
)


def test_string_is_supported():
    result = validate_project_path_type("/tmp/project")

    assert isinstance(result, PathTypeValidationResult)
    assert result.valid is True
    assert result.value_type == "str"
    assert result.reason == "SUPPORTED_PATH_TYPE"


def test_path_is_supported():
    result = validate_project_path_type(Path("/tmp/project"))

    assert result.valid is True
    assert result.value_type == "Path"
    assert result.reason == "SUPPORTED_PATH_TYPE"


def test_none_is_rejected():
    result = validate_project_path_type(None)

    assert result.valid is False
    assert result.value_type == "NoneType"
    assert result.reason == "PATH_TYPE_IS_NONE"


def test_integer_is_rejected():
    result = validate_project_path_type(123)

    assert result.valid is False
    assert result.value_type == "int"
    assert result.reason == "UNSUPPORTED_PATH_TYPE"


def test_float_is_rejected():
    result = validate_project_path_type(12.5)

    assert result.valid is False
    assert result.value_type == "float"
    assert result.reason == "UNSUPPORTED_PATH_TYPE"


def test_list_is_rejected():
    result = validate_project_path_type(["/tmp/project"])

    assert result.valid is False
    assert result.value_type == "list"
    assert result.reason == "UNSUPPORTED_PATH_TYPE"


def test_dict_is_rejected():
    result = validate_project_path_type({"path": "/tmp/project"})

    assert result.valid is False
    assert result.value_type == "dict"
    assert result.reason == "UNSUPPORTED_PATH_TYPE"


def test_bytes_are_rejected():
    result = validate_project_path_type(b"/tmp/project")

    assert result.valid is False
    assert result.value_type == "bytes"
    assert result.reason == "UNSUPPORTED_PATH_TYPE"


def test_arbitrary_object_is_rejected():
    class FakePath:
        def __str__(self):
            return "/tmp/project"

    result = validate_project_path_type(FakePath())

    assert result.valid is False
    assert result.reason == "UNSUPPORTED_PATH_TYPE"


def test_validator_does_not_touch_filesystem(tmp_path):
    before = sorted(
        str(path.relative_to(tmp_path))
        for path in tmp_path.rglob("*")
    )

    result = validate_project_path_type(
        str(tmp_path / "project")
    )

    after = sorted(
        str(path.relative_to(tmp_path))
        for path in tmp_path.rglob("*")
    )

    assert result.valid is True
    assert before == after
