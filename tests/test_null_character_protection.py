from pathlib import Path

from sentinelshield.null_character_protection import (
    NullCharacterValidationResult,
    NullCharacterProtector,
    validate_null_character,
)


def test_normal_path_is_valid():
    result = validate_null_character("/tmp/project")

    assert isinstance(
        result,
        NullCharacterValidationResult,
    )
    assert result.valid is True
    assert result.reason == "NO_NULL_CHARACTER"


def test_null_character_at_end_is_rejected():
    result = validate_null_character(
        "/tmp/project\x00"
    )

    assert result.valid is False
    assert result.reason == (
        "NULL_CHARACTER_NOT_ALLOWED"
    )


def test_null_character_in_middle_is_rejected():
    result = validate_null_character(
        "/tmp/pro\x00ject"
    )

    assert result.valid is False
    assert result.reason == (
        "NULL_CHARACTER_NOT_ALLOWED"
    )


def test_null_character_at_start_is_rejected():
    result = validate_null_character(
        "\x00/tmp/project"
    )

    assert result.valid is False
    assert result.reason == (
        "NULL_CHARACTER_NOT_ALLOWED"
    )


def test_null_character_after_home_path_is_rejected():
    result = validate_null_character(
        "~/project\x00evil"
    )

    assert result.valid is False
    assert result.reason == (
        "NULL_CHARACTER_NOT_ALLOWED"
    )


def test_path_object_with_null_is_rejected():
    path = Path("/tmp/project\x00evil")

    result = validate_null_character(path)

    assert result.valid is False
    assert result.reason == (
        "NULL_CHARACTER_NOT_ALLOWED"
    )


def test_none_is_rejected():
    result = validate_null_character(None)

    assert result.valid is False
    assert result.reason == "PATH_IS_NONE"


def test_integer_is_rejected():
    result = validate_null_character(123)

    assert result.valid is False
    assert result.reason == "UNSUPPORTED_PATH_TYPE"


def test_empty_string_has_no_null_character():
    result = validate_null_character("")

    assert result.valid is True
    assert result.reason == "NO_NULL_CHARACTER"


def test_validator_does_not_modify_filesystem(tmp_path):
    before = sorted(
        str(path.relative_to(tmp_path))
        for path in tmp_path.rglob("*")
    )

    result = validate_null_character(
        str(tmp_path / "project")
    )

    after = sorted(
        str(path.relative_to(tmp_path))
        for path in tmp_path.rglob("*")
    )

    assert result.valid is True
    assert before == after
