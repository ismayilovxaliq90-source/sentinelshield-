from pathlib import Path

from sentinelshield.working_tree_cleanliness import (
    WorkingTreeChange,
    WorkingTreeResult,
    _parse_porcelain_status,
    evaluate_working_tree_cleanliness,
)


def test_parse_clean_status():
    assert _parse_porcelain_status("") == ()


def test_parse_modified_file():
    result = _parse_porcelain_status(" M src/example.py\n")

    assert result == (
        WorkingTreeChange(
            status=" M",
            path="src/example.py",
        ),
    )


def test_parse_staged_file():
    result = _parse_porcelain_status("M  src/example.py\n")

    assert result == (
        WorkingTreeChange(
            status="M ",
            path="src/example.py",
        ),
    )


def test_parse_untracked_file():
    result = _parse_porcelain_status("?? new_file.txt\n")

    assert result == (
        WorkingTreeChange(
            status="??",
            path="new_file.txt",
        ),
    )


def test_parse_multiple_changes():
    result = _parse_porcelain_status(
        " M src/example.py\n"
        "M  tests/example.py\n"
        "?? new_file.txt\n"
    )

    assert len(result) == 3
    assert result[0].path == "src/example.py"
    assert result[1].path == "tests/example.py"
    assert result[2].path == "new_file.txt"


def test_non_git_directory_is_invalid(tmp_path):
    result = evaluate_working_tree_cleanliness(tmp_path)

    assert result.valid is False
    assert result.clean is False
    assert result.changed is False
    assert result.reason == "NOT_A_GIT_REPOSITORY"


def test_missing_start_path_is_invalid(tmp_path):
    missing = tmp_path / "missing"

    result = evaluate_working_tree_cleanliness(missing)

    assert result.valid is False
    assert result.reason == "START_PATH_NOT_FOUND"


def test_file_start_path_is_invalid(tmp_path):
    file_path = tmp_path / "file.txt"
    file_path.write_text("test")

    result = evaluate_working_tree_cleanliness(file_path)

    assert result.valid is False
    assert result.reason == "START_PATH_NOT_DIRECTORY"


def test_git_repository_cleanliness(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    import subprocess

    subprocess.run(
        ["git", "init"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )

    result = evaluate_working_tree_cleanliness(repo)

    assert isinstance(result, WorkingTreeResult)
    assert result.valid is True
    assert result.repository_root == repo
    assert result.clean is True
    assert result.changed is False
    assert result.changes == ()
    assert result.reason == "WORKING_TREE_CLEAN"


def test_git_repository_detects_modified_file(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    import subprocess

    subprocess.run(
        ["git", "init"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )

    file_path = repo / "tracked.txt"
    file_path.write_text("original")

    subprocess.run(
        ["git", "add", "tracked.txt"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )

    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Task182",
            "-c",
            "user.email=task182@example.invalid",
            "commit",
            "-m",
            "baseline",
        ],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )

    file_path.write_text("modified")

    result = evaluate_working_tree_cleanliness(repo)

    assert result.valid is True
    assert result.clean is False
    assert result.changed is True
    assert len(result.changes) == 1
    assert result.changes[0].path == "tracked.txt"
    assert result.reason == "WORKING_TREE_DIRTY"


def test_git_repository_detects_untracked_file(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    import subprocess

    subprocess.run(
        ["git", "init"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )

    file_path = repo / "new.txt"
    file_path.write_text("new")

    result = evaluate_working_tree_cleanliness(repo)

    assert result.valid is True
    assert result.clean is False
    assert result.changed is True
    assert len(result.changes) == 1
    assert result.changes[0].status == "??"
    assert result.changes[0].path == "new.txt"
    assert result.reason == "WORKING_TREE_DIRTY"
