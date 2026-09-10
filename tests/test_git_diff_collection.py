from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from sentinelshield.git_diff_collection import (
    GitDiffCollectionError,
    GitDiffCollectionResult,
    GitDiffFile,
    collect_git_diff,
    collect_git_diff_collection,
    validate_git_diff_collection,
)


def init_repo(path: Path) -> None:
    subprocess.run(
        ["git", "init", "-q", "-b", "main"],
        cwd=path,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.email", "task216@example.invalid"],
        cwd=path,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Task 216"],
        cwd=path,
        check=True,
    )


def commit_all(path: Path, message: str) -> None:
    subprocess.run(["git", "add", "."], cwd=path, check=True)
    subprocess.run(
        ["git", "commit", "-q", "-m", message],
        cwd=path,
        check=True,
    )


def test_clean_repository_has_no_changes(tmp_path: Path) -> None:
    init_repo(tmp_path)
    (tmp_path / "README.md").write_text("baseline\n", encoding="utf-8")
    commit_all(tmp_path, "baseline")

    result = collect_git_diff(tmp_path)

    assert result.has_changes is False
    assert result.changed_files == 0
    assert result.additions == 0
    assert result.deletions == 0


def test_modified_file_is_collected(tmp_path: Path) -> None:
    init_repo(tmp_path)
    target = tmp_path / "app.py"
    target.write_text("one\n", encoding="utf-8")
    commit_all(tmp_path, "baseline")

    target.write_text("one\ntwo\n", encoding="utf-8")

    result = collect_git_diff(tmp_path)

    assert result.changed_files == 1
    assert result.files[0].path == "app.py"
    assert result.files[0].status == "modified"
    assert result.additions == 1


def test_added_file_is_collected_from_diff(tmp_path: Path) -> None:
    init_repo(tmp_path)
    (tmp_path / "base.txt").write_text("base\n", encoding="utf-8")
    commit_all(tmp_path, "baseline")

    (tmp_path / "new.txt").write_text("new\n", encoding="utf-8")
    subprocess.run(["git", "add", "new.txt"], cwd=tmp_path, check=True)

    result = collect_git_diff(tmp_path)

    assert any(
        item.path == "new.txt" and item.status == "added"
        for item in result.files
    )


def test_untracked_file_is_collected(tmp_path: Path) -> None:
    init_repo(tmp_path)
    (tmp_path / "base.txt").write_text("base\n", encoding="utf-8")
    commit_all(tmp_path, "baseline")

    (tmp_path / "untracked.txt").write_text(
        "temporary\n",
        encoding="utf-8",
    )

    result = collect_git_diff(tmp_path)

    assert any(
        item.path == "untracked.txt" and item.status == "untracked"
        for item in result.files
    )


def test_untracked_can_be_excluded(tmp_path: Path) -> None:
    init_repo(tmp_path)
    (tmp_path / "base.txt").write_text("base\n", encoding="utf-8")
    commit_all(tmp_path, "baseline")

    (tmp_path / "untracked.txt").write_text(
        "temporary\n",
        encoding="utf-8",
    )

    result = collect_git_diff(
        tmp_path,
        include_untracked=False,
    )

    assert all(item.path != "untracked.txt" for item in result.files)


def test_deleted_file_is_collected(tmp_path: Path) -> None:
    init_repo(tmp_path)
    target = tmp_path / "delete.txt"
    target.write_text("remove\n", encoding="utf-8")
    commit_all(tmp_path, "baseline")

    target.unlink()

    result = collect_git_diff(tmp_path)

    assert any(
        item.path == "delete.txt" and item.status == "deleted"
        for item in result.files
    )


def test_rename_is_collected(tmp_path: Path) -> None:
    init_repo(tmp_path)
    source = tmp_path / "old.txt"
    source.write_text("same\n", encoding="utf-8")
    commit_all(tmp_path, "baseline")

    destination = tmp_path / "new.txt"
    source.rename(destination)

    subprocess.run(
        ["git", "add", "-A"],
        cwd=tmp_path,
        check=True,
    )

    result = collect_git_diff(tmp_path)

    assert any(
        item.path == "new.txt" and item.status == "renamed"
        for item in result.files
    )


def test_baseline_reference_can_be_used(tmp_path: Path) -> None:
    init_repo(tmp_path)
    target = tmp_path / "app.py"
    target.write_text("one\n", encoding="utf-8")
    commit_all(tmp_path, "baseline")

    baseline = subprocess.check_output(
        ["git", "rev-parse", "HEAD"],
        cwd=tmp_path,
        text=True,
    ).strip()

    target.write_text("one\ntwo\n", encoding="utf-8")

    result = collect_git_diff(
        tmp_path,
        baseline=baseline,
    )

    assert result.baseline == baseline
    assert result.changed_files == 1


def test_secret_values_are_redacted(tmp_path: Path) -> None:
    init_repo(tmp_path)
    target = tmp_path / "secret.txt"
    target.write_text("baseline\n", encoding="utf-8")
    commit_all(tmp_path, "baseline")

    target.write_text(
        "token=super-secret-value\n"
        "password=another-secret\n"
        "Authorization: Bearer abcdefghijklmnop\n",
        encoding="utf-8",
    )

    result = collect_git_diff(tmp_path)

    assert "super-secret-value" not in result.raw_diff
    assert "another-secret" not in result.raw_diff
    assert "abcdefghijklmnop" not in result.raw_diff
    assert "<REDACTED>" in result.raw_diff


def test_invalid_repository_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(GitDiffCollectionError):
        collect_git_diff(tmp_path)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        "-bad-reference",
        "bad\x00reference",
    ],
)
def test_invalid_baseline_is_rejected(
    tmp_path: Path,
    value: str,
) -> None:
    init_repo(tmp_path)
    (tmp_path / "base.txt").write_text("base\n", encoding="utf-8")
    commit_all(tmp_path, "baseline")

    with pytest.raises(GitDiffCollectionError):
        collect_git_diff(tmp_path, baseline=value)


def test_path_length_is_limited() -> None:
    with pytest.raises(GitDiffCollectionError):
        GitDiffFile(path="x" * 4097, status="modified")


def test_invalid_status_is_rejected() -> None:
    with pytest.raises(GitDiffCollectionError):
        GitDiffFile(path="a.txt", status="invalid")


def test_counts_must_be_real_integers() -> None:
    with pytest.raises(GitDiffCollectionError):
        GitDiffFile(
            path="a.txt",
            status="modified",
            additions=True,
        )


def test_result_serialization(tmp_path: Path) -> None:
    result = GitDiffCollectionResult(
        repository_root=str(tmp_path),
        baseline=None,
        files=(
            GitDiffFile(
                path="a.txt",
                status="modified",
                additions=2,
                deletions=1,
            ),
        ),
        additions=2,
        deletions=1,
        changed_files=1,
    )

    payload = result.to_json()
    parsed = json.loads(payload)

    assert parsed["changed_files"] == 1
    assert parsed["files"][0]["path"] == "a.txt"


def test_result_validation(tmp_path: Path) -> None:
    result = GitDiffCollectionResult(
        repository_root=str(tmp_path),
    )

    assert validate_git_diff_collection(result) is True


def test_result_validation_rejects_wrong_type() -> None:
    assert validate_git_diff_collection(object()) is False


def test_public_alias_matches_primary_function(tmp_path: Path) -> None:
    init_repo(tmp_path)
    (tmp_path / "base.txt").write_text("base\n", encoding="utf-8")
    commit_all(tmp_path, "baseline")

    first = collect_git_diff(tmp_path)
    second = collect_git_diff_collection(tmp_path)

    assert first.to_dict() == second.to_dict()
