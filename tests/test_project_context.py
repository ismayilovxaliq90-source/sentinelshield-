from pathlib import Path

from sentinelshield.project_context import (
    ProjectContext,
    ProjectContextResult,
    ProjectContextBuilder,
    create_project_context,
)


def test_valid_context_is_created(tmp_path):
    result = create_project_context(
        tmp_path,
        "abc123",
    )

    assert isinstance(result, ProjectContextResult)
    assert result.valid is True
    assert result.reason == "PROJECT_CONTEXT_CREATED"

    assert isinstance(result.context, ProjectContext)
    assert result.context.project_path == tmp_path
    assert result.context.project_identity == "abc123"
    assert result.context.exists is True
    assert result.context.is_directory is True


def test_string_path_is_converted_to_path(tmp_path):
    result = create_project_context(
        str(tmp_path),
        "identity",
    )

    assert result.valid is True
    assert result.context.project_path == tmp_path


def test_path_whitespace_is_normalized(tmp_path):
    result = create_project_context(
        f"  {tmp_path}  ",
        "identity",
    )

    assert result.valid is True
    assert result.context.project_path == tmp_path


def test_none_path_is_rejected():
    result = create_project_context(
        None,
        "identity",
    )

    assert result.valid is False
    assert result.context is None
    assert result.reason == "PATH_IS_NONE"


def test_empty_path_is_rejected():
    result = create_project_context(
        "",
        "identity",
    )

    assert result.valid is False
    assert result.reason == "PATH_IS_EMPTY"


def test_null_character_is_rejected():
    result = create_project_context(
        "/tmp/project\x00evil",
        "identity",
    )

    assert result.valid is False
    assert result.reason == (
        "NULL_CHARACTER_NOT_ALLOWED"
    )


def test_unsupported_path_type_is_rejected():
    result = create_project_context(
        123,
        "identity",
    )

    assert result.valid is False
    assert result.reason == "UNSUPPORTED_PATH_TYPE"


def test_identity_must_be_string(tmp_path):
    result = create_project_context(
        tmp_path,
        123,
    )

    assert result.valid is False
    assert result.reason == "IDENTITY_IS_INVALID"


def test_empty_identity_is_rejected(tmp_path):
    result = create_project_context(
        tmp_path,
        "   ",
    )

    assert result.valid is False
    assert result.reason == "IDENTITY_IS_EMPTY"


def test_exists_flag_must_be_boolean(tmp_path):
    result = create_project_context(
        tmp_path,
        "identity",
        exists="true",
    )

    assert result.valid is False
    assert result.reason == "EXISTS_FLAG_INVALID"


def test_directory_flag_must_be_boolean(tmp_path):
    result = create_project_context(
        tmp_path,
        "identity",
        is_directory="true",
    )

    assert result.valid is False
    assert result.reason == "DIRECTORY_FLAG_INVALID"


def test_existing_file_cannot_be_project_context(tmp_path):
    file_path = tmp_path / "file.txt"
    file_path.write_text("test", encoding="utf-8")

    result = create_project_context(
        file_path,
        "identity",
        exists=True,
        is_directory=False,
    )

    assert result.valid is False
    assert result.reason == (
        "EXISTING_PROJECT_IS_NOT_DIRECTORY"
    )


def test_nonexistent_directory_context_can_be_represented(
    tmp_path,
):
    missing = tmp_path / "missing"

    result = create_project_context(
        missing,
        "identity",
        exists=False,
        is_directory=True,
    )

    assert result.valid is True
    assert result.context.exists is False
    assert result.context.is_directory is True


def test_context_is_immutable(tmp_path):
    result = create_project_context(
        tmp_path,
        "identity",
    )

    context = result.context

    assert context is not None

    try:
        context.project_identity = "changed"
        changed = True
    except Exception:
        changed = False

    assert changed is False
    assert context.project_identity == "identity"


def test_builder_and_function_return_same_shape(tmp_path):
    builder_result = ProjectContextBuilder().create(
        tmp_path,
        "identity",
    )

    function_result = create_project_context(
        tmp_path,
        "identity",
    )

    assert builder_result == function_result


def test_filesystem_is_not_modified(tmp_path):
    before = sorted(
        str(path.relative_to(tmp_path))
        for path in tmp_path.rglob("*")
    )

    result = create_project_context(
        tmp_path,
        "identity",
    )

    after = sorted(
        str(path.relative_to(tmp_path))
        for path in tmp_path.rglob("*")
    )

    assert result.valid is True
    assert before == after


def test_context_does_not_require_filesystem_access(
    tmp_path,
):
    missing = tmp_path / "not-created"

    result = create_project_context(
        missing,
        "identity",
        exists=False,
        is_directory=True,
    )

    assert result.valid is True
    assert not missing.exists()
