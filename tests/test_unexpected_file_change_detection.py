from pathlib import Path
import subprocess

import pytest

from sentinelshield.unexpected_file_change_detection import (
    UnexpectedFileChangeError,
    collect_git_changes,
    detect_unexpected_file_changes,
    validate_unexpected_file_change_result,
)


def init_repo(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "init"],
        cwd=path,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return path


def git_commit(path: Path) -> None:
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=path,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "SentinelShield Test"],
        cwd=path,
        check=True,
    )
    subprocess.run(
        ["git", "add", "."],
        cwd=path,
        check=True,
    )
    subprocess.run(
        ["git", "commit", "-m", "baseline"],
        cwd=path,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def test_clean_repository_passes(tmp_path):
    repo = init_repo(tmp_path / "repo")
    (repo / "tracked.txt").write_text("baseline", encoding="utf-8")
    git_commit(repo)

    result = detect_unexpected_file_changes(repo)

    assert result.valid is True
    assert result.clean is True
    assert result.unexpected_changes == ()
    assert validate_unexpected_file_change_result(result) is True


def test_unexpected_modified_file_fails(tmp_path):
    repo = init_repo(tmp_path / "repo")
    (repo / "tracked.txt").write_text("baseline", encoding="utf-8")
    git_commit(repo)

    (repo / "tracked.txt").write_text("changed", encoding="utf-8")

    result = detect_unexpected_file_changes(repo)

    assert result.clean is False
    assert len(result.unexpected_changes) == 1
    assert result.modified_files == ("tracked.txt",)
    assert validate_unexpected_file_change_result(result) is False


def test_expected_modified_file_is_accepted(tmp_path):
    repo = init_repo(tmp_path / "repo")
    (repo / "manifest.txt").write_text("1", encoding="utf-8")
    git_commit(repo)

    (repo / "manifest.txt").write_text("2", encoding="utf-8")

    result = detect_unexpected_file_changes(
        repo,
        expected_changes=["manifest.txt"],
    )

    assert result.unexpected_changes == ()
    assert len(result.expected_changes) == 1
    assert result.clean is False
    assert validate_unexpected_file_change_result(result) is False


def test_unexpected_new_file_fails(tmp_path):
    repo = init_repo(tmp_path / "repo")
    (repo / "tracked.txt").write_text("baseline", encoding="utf-8")
    git_commit(repo)

    (repo / "unexpected.txt").write_text("unexpected", encoding="utf-8")

    result = detect_unexpected_file_changes(repo)

    assert result.added_files == ("unexpected.txt",)
    assert len(result.unexpected_changes) == 1


def test_unexpected_deleted_file_fails(tmp_path):
    repo = init_repo(tmp_path / "repo")
    (repo / "tracked.txt").write_text("baseline", encoding="utf-8")
    git_commit(repo)

    (repo / "tracked.txt").unlink()

    result = detect_unexpected_file_changes(repo)

    assert result.deleted_files == ("tracked.txt",)
    assert len(result.unexpected_changes) == 1


def test_nested_file_is_detected(tmp_path):
    repo = init_repo(tmp_path / "repo")
    nested = repo / "service" / "src"
    nested.mkdir(parents=True)
    target = nested / "main.py"
    target.write_text("print('x')", encoding="utf-8")
    git_commit(repo)

    target.write_text("print('y')", encoding="utf-8")

    result = detect_unexpected_file_changes(repo)

    assert result.modified_files == ("service/src/main.py",)


def test_outside_repository_expected_path_is_rejected(tmp_path):
    repo = init_repo(tmp_path / "repo")
    (repo / "tracked.txt").write_text("baseline", encoding="utf-8")
    git_commit(repo)

    outside = tmp_path / "outside.txt"

    with pytest.raises(UnexpectedFileChangeError):
        detect_unexpected_file_changes(
            repo,
            expected_changes=[str(outside)],
        )


def test_invalid_repository_is_rejected(tmp_path):
    with pytest.raises(UnexpectedFileChangeError):
        detect_unexpected_file_changes(tmp_path / "missing")


def test_result_serialization(tmp_path):
    repo = init_repo(tmp_path / "repo")
    (repo / "tracked.txt").write_text("baseline", encoding="utf-8")
    git_commit(repo)

    (repo / "new.txt").write_text("new", encoding="utf-8")

    result = detect_unexpected_file_changes(repo)
    data = result.to_dict()

    assert data["valid"] is True
    assert data["passed"] is False
    assert "new.txt" in data["added_files"]


def test_git_change_collection_has_relative_paths(tmp_path):
    repo = init_repo(tmp_path / "repo")
    (repo / "a.txt").write_text("a", encoding="utf-8")
    git_commit(repo)

    (repo / "b.txt").write_text("b", encoding="utf-8")

    changes = collect_git_changes(repo)

    assert len(changes) == 1
    assert changes[0].path == "b.txt"
    assert changes[0].status == "A"
