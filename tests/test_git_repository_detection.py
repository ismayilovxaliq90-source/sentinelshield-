from pathlib import Path

from sentinelshield.git_repository_detection import (
    GitRepositoryDetectionResult,
    GitRepositoryDetector,
    detect_git_repository,
)


def test_git_directory_is_detected(tmp_path):
    repository = tmp_path / "repo"
    repository.mkdir()

    git = repository / ".git"
    git.mkdir()

    result = detect_git_repository(repository)

    assert isinstance(
        result,
        GitRepositoryDetectionResult,
    )
    assert result.is_git_repository is True
    assert result.repository_path == repository
    assert result.git_path == git
    assert result.git_marker_type == "DIRECTORY"
    assert result.reason == "GIT_DIRECTORY_FOUND"


def test_git_file_is_detected(tmp_path):
    repository = tmp_path / "repo"
    repository.mkdir()

    git = repository / ".git"
    git.write_text(
        "gitdir: /tmp/example/.git/worktrees/demo\n",
        encoding="utf-8",
    )

    result = detect_git_repository(repository)

    assert result.is_git_repository is True
    assert result.repository_path == repository
    assert result.git_path == git
    assert result.git_marker_type == "FILE"
    assert result.reason == "GIT_FILE_FOUND"


def test_nested_directory_without_git_marker_is_not_repository(
    tmp_path,
):
    repository = tmp_path / "repo"
    nested = repository / "src" / "package"
    nested.mkdir(parents=True)

    (repository / ".git").mkdir()

    result = detect_git_repository(nested)

    assert result.is_git_repository is False
    assert result.repository_path == nested
    assert result.reason == "GIT_REPOSITORY_NOT_FOUND"


def test_file_input_checks_parent(tmp_path):
    repository = tmp_path / "repo"
    repository.mkdir()
    (repository / ".git").mkdir()

    source = repository / "main.py"
    source.write_text(
        "print('test')\n",
        encoding="utf-8",
    )

    result = detect_git_repository(source)

    assert result.is_git_repository is True
    assert result.repository_path == repository


def test_non_git_directory_is_rejected(tmp_path):
    directory = tmp_path / "project"
    directory.mkdir()

    result = detect_git_repository(directory)

    assert result.is_git_repository is False
    assert result.repository_path == directory
    assert result.git_path is None
    assert result.git_marker_type is None
    assert result.reason == "GIT_REPOSITORY_NOT_FOUND"


def test_none_is_rejected():
    result = detect_git_repository(None)

    assert result.is_git_repository is False
    assert result.repository_path is None
    assert result.reason == "PATH_IS_NONE"


def test_empty_string_is_rejected():
    result = detect_git_repository("")

    assert result.is_git_repository is False
    assert result.reason == "PATH_IS_EMPTY"


def test_whitespace_only_is_rejected():
    result = detect_git_repository("   ")

    assert result.is_git_repository is False
    assert result.reason == "PATH_IS_EMPTY"


def test_null_character_is_rejected():
    result = detect_git_repository(
        "/tmp/project\x00evil"
    )

    assert result.is_git_repository is False
    assert result.reason == (
        "NULL_CHARACTER_NOT_ALLOWED"
    )


def test_integer_is_rejected():
    result = detect_git_repository(123)

    assert result.is_git_repository is False
    assert result.reason == "UNSUPPORTED_PATH_TYPE"


def test_path_object_is_supported(tmp_path):
    repository = tmp_path / "repo"
    repository.mkdir()
    (repository / ".git").mkdir()

    result = GitRepositoryDetector().detect(
        Path(repository)
    )

    assert result.is_git_repository is True
    assert result.repository_path == repository


def test_home_expansion_is_supported(tmp_path, monkeypatch):
    monkeypatch.setenv(
        "HOME",
        str(tmp_path),
    )

    repository = tmp_path / "repo"
    repository.mkdir()
    (repository / ".git").mkdir()

    result = detect_git_repository(
        "~/repo"
    )

    assert result.is_git_repository is True
    assert result.repository_path == repository


def test_git_marker_is_only_checked_at_given_directory(
    tmp_path,
):
    outer = tmp_path / "outer"
    inner = outer / "inner"

    inner.mkdir(parents=True)
    (outer / ".git").mkdir()

    result = detect_git_repository(inner)

    assert result.is_git_repository is False
    assert result.repository_path == inner


def test_git_directory_marker_is_not_required_to_contain_files(
    tmp_path,
):
    repository = tmp_path / "repo"
    repository.mkdir()
    (repository / ".git").mkdir()

    result = detect_git_repository(repository)

    assert result.is_git_repository is True


def test_result_is_immutable(tmp_path):
    repository = tmp_path / "repo"
    repository.mkdir()
    (repository / ".git").mkdir()

    result = detect_git_repository(repository)

    try:
        result.is_git_repository = False
        changed = True
    except Exception:
        changed = False

    assert changed is False
    assert result.is_git_repository is True


def test_detection_does_not_modify_filesystem(tmp_path):
    repository = tmp_path / "repo"
    repository.mkdir()
    (repository / ".git").mkdir()

    before = sorted(
        str(path.relative_to(tmp_path))
        for path in tmp_path.rglob("*")
    )

    result = detect_git_repository(repository)

    after = sorted(
        str(path.relative_to(tmp_path))
        for path in tmp_path.rglob("*")
    )

    assert result.is_git_repository is True
    assert before == after


def test_detector_does_not_execute_project_code(
    tmp_path,
):
    repository = tmp_path / "repo"
    repository.mkdir()
    (repository / ".git").mkdir()

    marker = repository / "executed.txt"

    (repository / "setup.py").write_text(
        f"open({str(marker)!r}, 'w').write('executed')\n",
        encoding="utf-8",
    )

    result = detect_git_repository(repository)

    assert result.is_git_repository is True
    assert not marker.exists()


def test_regular_directory_named_git_file_is_detected(
    tmp_path,
):
    repository = tmp_path / "repo"
    repository.mkdir()

    git = repository / ".git"
    git.write_text(
        "gitdir: /some/path\n",
        encoding="utf-8",
    )

    result = detect_git_repository(repository)

    assert result.is_git_repository is True
    assert result.git_marker_type == "FILE"
