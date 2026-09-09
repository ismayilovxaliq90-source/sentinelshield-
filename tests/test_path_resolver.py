from pathlib import Path

from sentinelshield.path_resolver import (
    PathResolutionResult,
    ProjectPathResolver,
    resolve_project_path,
)


def test_absolute_path_is_resolved(tmp_path):
    result = resolve_project_path(str(tmp_path))

    assert isinstance(result, PathResolutionResult)
    assert result.valid is True
    assert result.resolved == tmp_path.resolve()
    assert result.reason == "PATH_RESOLVED"


def test_relative_path_becomes_absolute(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    result = resolve_project_path("./project")

    assert result.valid is True
    assert result.resolved == (tmp_path / "project").resolve()
    assert result.resolved.is_absolute()


def test_dot_dot_is_normalized(tmp_path):
    target = tmp_path / "project"
    target.mkdir()

    result = resolve_project_path(
        str(target / ".." / "project")
    )

    assert result.valid is True
    assert result.resolved == target.resolve()


def test_home_path_is_expanded():
    result = resolve_project_path("~/project")

    assert result.valid is True
    assert result.resolved == (
        Path.home() / "project"
    ).resolve()


def test_nonexistent_path_is_allowed(tmp_path):
    target = tmp_path / "does-not-exist"

    result = resolve_project_path(target)

    assert result.valid is True
    assert result.resolved == target.resolve()


def test_symlink_is_resolved(tmp_path):
    target = tmp_path / "real-project"
    link = tmp_path / "project-link"

    target.mkdir()
    link.symlink_to(target, target_is_directory=True)

    result = resolve_project_path(link)

    assert result.valid is True
    assert result.resolved == target.resolve()


def test_none_is_rejected():
    result = resolve_project_path(None)

    assert result.valid is False
    assert result.resolved is None
    assert result.reason == "PATH_IS_NONE"


def test_empty_string_is_rejected():
    result = resolve_project_path("")

    assert result.valid is False
    assert result.reason == "PATH_IS_EMPTY"


def test_whitespace_only_is_rejected():
    result = resolve_project_path("   ")

    assert result.valid is False
    assert result.reason == "PATH_IS_EMPTY"


def test_null_character_is_rejected():
    result = resolve_project_path(
        "/tmp/project\x00evil"
    )

    assert result.valid is False
    assert result.reason == (
        "NULL_CHARACTER_NOT_ALLOWED"
    )


def test_unsupported_type_is_rejected():
    result = resolve_project_path(123)

    assert result.valid is False
    assert result.reason == "UNSUPPORTED_PATH_TYPE"


def test_resolution_does_not_create_target(tmp_path):
    target = tmp_path / "new-project"

    assert not target.exists()

    result = resolve_project_path(target)

    assert result.valid is True
    assert result.resolved == target.resolve()
    assert not target.exists()


def test_resolver_does_not_modify_existing_tree(tmp_path):
    project = tmp_path / "project"
    nested = project / "src"
    nested.mkdir(parents=True)

    before = sorted(
        str(p.relative_to(tmp_path))
        for p in tmp_path.rglob("*")
    )

    result = resolve_project_path(nested / "..")

    after = sorted(
        str(p.relative_to(tmp_path))
        for p in tmp_path.rglob("*")
    )

    assert result.valid is True
    assert before == after
