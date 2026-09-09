from pathlib import Path

from sentinelshield.project_identity import (
    ProjectIdentityResult,
    ProjectIdentityGenerator,
    generate_project_identity,
)


def test_identity_is_generated():
    result = generate_project_identity("/tmp/project")

    assert isinstance(
        result,
        ProjectIdentityResult,
    )
    assert result.valid is True
    assert result.identity is not None
    assert len(result.identity) == 64
    assert result.reason == "PROJECT_IDENTITY_GENERATED"


def test_identity_is_deterministic():
    first = generate_project_identity("/tmp/project")
    second = generate_project_identity("/tmp/project")

    assert first.identity == second.identity
    assert first.project_path == second.project_path


def test_different_paths_have_different_identities():
    first = generate_project_identity("/tmp/project-a")
    second = generate_project_identity("/tmp/project-b")

    assert first.identity != second.identity


def test_str_and_path_produce_same_identity():
    string_result = generate_project_identity(
        "/tmp/project"
    )
    path_result = generate_project_identity(
        Path("/tmp/project")
    )

    assert string_result.identity == path_result.identity


def test_relative_and_absolute_same_identity(
    tmp_path,
    monkeypatch,
):
    monkeypatch.chdir(tmp_path)

    relative = generate_project_identity(
        "./project"
    )
    absolute = generate_project_identity(
        tmp_path / "project"
    )

    assert relative.identity == absolute.identity
    assert relative.project_path == absolute.project_path


def test_dot_dot_is_canonicalized(tmp_path):
    target = tmp_path / "project"

    first = generate_project_identity(target)
    second = generate_project_identity(
        target / ".." / "project"
    )

    assert first.identity == second.identity


def test_home_expansion_is_canonicalized():
    result = generate_project_identity(
        "~/project"
    )

    expected = generate_project_identity(
        Path.home() / "project"
    )

    assert result.identity == expected.identity


def test_identity_does_not_depend_on_file_contents(
    tmp_path,
):
    project = tmp_path / "project"
    project.mkdir()

    first = generate_project_identity(project)

    (project / "file.txt").write_text(
        "first",
        encoding="utf-8",
    )

    second = generate_project_identity(project)

    (project / "file.txt").write_text(
        "second",
        encoding="utf-8",
    )

    third = generate_project_identity(project)

    assert first.identity == second.identity
    assert second.identity == third.identity


def test_nonexistent_project_can_have_identity(
    tmp_path,
):
    project = tmp_path / "missing-project"

    result = generate_project_identity(project)

    assert result.valid is True
    assert result.project_path == project.resolve()
    assert result.identity is not None
    assert not project.exists()


def test_none_is_rejected():
    result = generate_project_identity(None)

    assert result.valid is False
    assert result.identity is None
    assert result.reason == "PATH_IS_NONE"


def test_empty_string_is_rejected():
    result = generate_project_identity("")

    assert result.valid is False
    assert result.identity is None
    assert result.reason == "PATH_IS_EMPTY"


def test_whitespace_only_is_rejected():
    result = generate_project_identity("   ")

    assert result.valid is False
    assert result.reason == "PATH_IS_EMPTY"


def test_null_character_is_rejected():
    result = generate_project_identity(
        "/tmp/project\x00evil"
    )

    assert result.valid is False
    assert result.identity is None
    assert result.reason == (
        "NULL_CHARACTER_NOT_ALLOWED"
    )


def test_integer_is_rejected():
    result = generate_project_identity(123)

    assert result.valid is False
    assert result.identity is None
    assert result.reason == "UNSUPPORTED_PATH_TYPE"


def test_identity_has_expected_sha256_format():
    result = generate_project_identity(
        "/tmp/project"
    )

    assert result.valid is True
    assert result.identity is not None

    int(result.identity, 16)

    assert len(result.identity) == 64


def test_filesystem_is_not_modified(tmp_path):
    project = tmp_path / "project"

    before = sorted(
        str(path.relative_to(tmp_path))
        for path in tmp_path.rglob("*")
    )

    result = generate_project_identity(project)

    after = sorted(
        str(path.relative_to(tmp_path))
        for path in tmp_path.rglob("*")
    )

    assert result.valid is True
    assert before == after


def test_symlink_target_resolves_to_same_identity(
    tmp_path,
):
    target = tmp_path / "real-project"
    link = tmp_path / "project-link"

    target.mkdir()

    link.symlink_to(
        target,
        target_is_directory=True,
    )

    target_result = generate_project_identity(
        target
    )
    link_result = generate_project_identity(
        link
    )

    assert target_result.identity == link_result.identity
