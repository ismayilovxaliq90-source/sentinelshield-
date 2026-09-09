from pathlib import Path

from sentinelshield.whitespace_normalizer import (
    normalize_project_path_whitespace,
)


def test_leading_and_trailing_whitespace_is_removed():
    assert (
        normalize_project_path_whitespace(
            "   /tmp/project   "
        )
        == "/tmp/project"
    )


def test_tabs_and_newlines_are_removed():
    assert (
        normalize_project_path_whitespace(
            "\t/tmp/project\n"
        )
        == "/tmp/project"
    )


def test_clean_path_is_unchanged():
    assert (
        normalize_project_path_whitespace(
            "/tmp/project"
        )
        == "/tmp/project"
    )


def test_internal_whitespace_is_preserved():
    assert (
        normalize_project_path_whitespace(
            "  /tmp/my project  "
        )
        == "/tmp/my project"
    )


def test_empty_string_remains_empty():
    assert (
        normalize_project_path_whitespace("")
        == ""
    )


def test_whitespace_only_becomes_empty():
    assert (
        normalize_project_path_whitespace("   ")
        == ""
    )


def test_none_remains_none():
    assert (
        normalize_project_path_whitespace(None)
        is None
    )


def test_path_object_is_normalized():
    result = normalize_project_path_whitespace(
        Path("  /tmp/project  ")
    )

    assert isinstance(result, Path)
    assert str(result) == "/tmp/project"


def test_unsupported_type_is_unchanged():
    value = 123

    assert (
        normalize_project_path_whitespace(value)
        == value
    )


def test_filesystem_is_not_modified(tmp_path):
    before = sorted(
        str(path.relative_to(tmp_path))
        for path in tmp_path.rglob("*")
    )

    result = normalize_project_path_whitespace(
        f"  {tmp_path / 'project'}  "
    )

    after = sorted(
        str(path.relative_to(tmp_path))
        for path in tmp_path.rglob("*")
    )

    assert str(result) == str(
        tmp_path / "project"
    )
    assert before == after
