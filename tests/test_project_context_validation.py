from dataclasses import FrozenInstanceError
from pathlib import Path

from sentinelshield.project_context import (
    ProjectContext,
    create_project_context,
)
from sentinelshield.project_context_validation import (
    ProjectContextValidationResult,
    ProjectContextValidator,
    validate_project_context,
)


def make_context(
    tmp_path,
    identity="identity",
    exists=True,
    is_directory=True,
):
    result = create_project_context(
        tmp_path,
        identity,
        exists=exists,
        is_directory=is_directory,
    )

    assert result.valid is True
    assert result.context is not None

    return result.context


def test_valid_context_passes(tmp_path):
    context = make_context(tmp_path)

    result = validate_project_context(context)

    assert isinstance(result, ProjectContextValidationResult)
    assert result.valid is True
    assert result.reason == "PROJECT_CONTEXT_VALID"


def test_none_context_is_rejected():
    result = validate_project_context(None)

    assert result.valid is False
    assert result.reason == "CONTEXT_IS_NONE"


def test_wrong_context_type_is_rejected():
    result = validate_project_context(
        {"project_path": "/tmp/project"}
    )

    assert result.valid is False
    assert result.reason == "INVALID_CONTEXT_TYPE"


def test_project_path_must_be_path_object(tmp_path):
    context = make_context(tmp_path)

    object.__setattr__(
        context,
        "project_path",
        "/tmp/project",
    )

    result = validate_project_context(context)

    assert result.valid is False
    assert result.reason == "INVALID_PROJECT_PATH"


def test_null_character_in_project_path_is_rejected(tmp_path):
    context = make_context(tmp_path)

    object.__setattr__(
        context,
        "project_path",
        Path("/tmp/project\x00evil"),
    )

    result = validate_project_context(context)

    assert result.valid is False
    assert result.reason == "NULL_CHARACTER_NOT_ALLOWED"


def test_identity_must_be_string(tmp_path):
    context = make_context(tmp_path)

    object.__setattr__(
        context,
        "project_identity",
        123,
    )

    result = validate_project_context(context)

    assert result.valid is False
    assert result.reason == "INVALID_PROJECT_IDENTITY"


def test_empty_identity_is_rejected(tmp_path):
    context = make_context(tmp_path)

    object.__setattr__(
        context,
        "project_identity",
        "   ",
    )

    result = validate_project_context(context)

    assert result.valid is False
    assert result.reason == "PROJECT_IDENTITY_IS_EMPTY"


def test_exists_must_be_boolean(tmp_path):
    context = make_context(tmp_path)

    object.__setattr__(
        context,
        "exists",
        "true",
    )

    result = validate_project_context(context)

    assert result.valid is False
    assert result.reason == "INVALID_EXISTS_FLAG"


def test_is_directory_must_be_boolean(tmp_path):
    context = make_context(tmp_path)

    object.__setattr__(
        context,
        "is_directory",
        "true",
    )

    result = validate_project_context(context)

    assert result.valid is False
    assert result.reason == "INVALID_DIRECTORY_FLAG"


def test_existing_non_directory_is_rejected(tmp_path):
    context = make_context(
        tmp_path,
        exists=True,
        is_directory=True,
    )

    object.__setattr__(
        context,
        "is_directory",
        False,
    )

    result = validate_project_context(context)

    assert result.valid is False
    assert result.reason == (
        "EXISTING_PROJECT_IS_NOT_DIRECTORY"
    )


def test_nonexistent_context_can_be_valid(tmp_path):
    context = make_context(
        tmp_path / "missing",
        exists=False,
        is_directory=True,
    )

    result = validate_project_context(context)

    assert result.valid is True
    assert result.reason == "PROJECT_CONTEXT_VALID"


def test_validator_does_not_modify_filesystem(tmp_path):
    context = make_context(tmp_path)

    before = sorted(
        str(path.relative_to(tmp_path))
        for path in tmp_path.rglob("*")
    )

    result = validate_project_context(context)

    after = sorted(
        str(path.relative_to(tmp_path))
        for path in tmp_path.rglob("*")
    )

    assert result.valid is True
    assert before == after


def test_validator_does_not_execute_project_code(tmp_path):
    marker = tmp_path / "marker.txt"

    context = make_context(tmp_path)

    result = validate_project_context(context)

    assert result.valid is True
    assert not marker.exists()


def test_validator_instance_works(tmp_path):
    context = make_context(tmp_path)

    result = ProjectContextValidator().validate(
        context
    )

    assert result.valid is True


def test_result_is_immutable(tmp_path):
    context = make_context(tmp_path)

    result = validate_project_context(context)

    try:
        result.valid = False
        changed = True
    except (FrozenInstanceError, AttributeError):
        changed = False

    assert changed is False
    assert result.valid is True
