import subprocess
from pathlib import Path

from sentinelshield.existing_change_protection import (
    ExistingChange,
    ExistingChangeProtectionResult,
    capture_existing_change_protection,
    verify_existing_change_protection,
)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )


def _git_commit(repo: Path) -> None:
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Task183",
            "-c",
            "user.email=task183@example.invalid",
            "commit",
            "-m",
            "baseline",
        ],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )


def test_result_dataclasses_exist():
    change = ExistingChange(
        status=" M",
        path="file.py",
        content_hash="abc",
    )

    result = ExistingChangeProtectionResult(
        valid=True,
        repository_root=Path("/tmp/repo"),
        protected=True,
        existing_changes=(change,),
        change_count=1,
        reason="TEST",
    )

    assert result.valid is True
    assert result.protected is True
    assert result.change_count == 1
    assert result.existing_changes[0].path == "file.py"


def test_non_git_directory_fails(tmp_path):
    result = capture_existing_change_protection(tmp_path)

    assert result.valid is False
    assert result.protected is False
    assert result.reason == "NOT_A_GIT_REPOSITORY"


def test_missing_path_fails(tmp_path):
    result = capture_existing_change_protection(
        tmp_path / "missing"
    )

    assert result.valid is False
    assert result.reason == "START_PATH_NOT_FOUND"


def test_file_path_fails(tmp_path):
    file_path = tmp_path / "file.txt"
    file_path.write_text("x")

    result = capture_existing_change_protection(file_path)

    assert result.valid is False
    assert result.reason == "START_PATH_NOT_DIRECTORY"


def test_clean_repository_is_protected(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    _git(repo, "init")

    file_path = repo / "file.txt"
    file_path.write_text("baseline")

    _git(repo, "add", "file.txt")
    _git_commit(repo)

    result = capture_existing_change_protection(repo)

    assert result.valid is True
    assert result.protected is True
    assert result.change_count == 0
    assert result.existing_changes == ()
    assert result.reason == "NO_EXISTING_CHANGES"


def test_modified_file_is_identified_and_protected(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    _git(repo, "init")

    file_path = repo / "file.txt"
    file_path.write_text("baseline")

    _git(repo, "add", "file.txt")
    _git_commit(repo)

    file_path.write_text("user change")

    result = capture_existing_change_protection(repo)

    assert result.valid is True
    assert result.protected is True
    assert result.change_count == 1
    assert result.existing_changes[0].status == " M"
    assert result.existing_changes[0].path == "file.txt"
    assert result.existing_changes[0].content_hash is not None
    assert result.reason == "EXISTING_CHANGES_IDENTIFIED_AND_PROTECTED"


def test_untracked_file_is_identified(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    _git(repo, "init")

    file_path = repo / "new.txt"
    file_path.write_text("new content")

    result = capture_existing_change_protection(repo)

    assert result.valid is True
    assert result.protected is True
    assert result.change_count == 1
    assert result.existing_changes[0].status == "??"
    assert result.existing_changes[0].path == "new.txt"


def test_pre_existing_change_is_preserved(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    _git(repo, "init")

    file_path = repo / "file.txt"
    file_path.write_text("baseline")

    _git(repo, "add", "file.txt")
    _git_commit(repo)

    file_path.write_text("user change")

    before = capture_existing_change_protection(repo)

    result = verify_existing_change_protection(
        before,
        repo,
    )

    assert result.valid is True
    assert result.protected is True
    assert result.reason == "PRE_EXISTING_CHANGES_PRESERVED"


def test_pre_existing_change_modification_is_detected(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    _git(repo, "init")

    file_path = repo / "file.txt"
    file_path.write_text("baseline")

    _git(repo, "add", "file.txt")
    _git_commit(repo)

    file_path.write_text("original user change")

    before = capture_existing_change_protection(repo)

    file_path.write_text("changed by later process")

    result = verify_existing_change_protection(
        before,
        repo,
    )

    assert result.valid is True
    assert result.protected is False
    assert "PRE_EXISTING_CHANGE_MODIFIED" in result.reason


def test_pre_existing_change_removal_is_detected(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    _git(repo, "init")

    file_path = repo / "file.txt"
    file_path.write_text("baseline")

    _git(repo, "add", "file.txt")
    _git_commit(repo)

    file_path.write_text("user change")

    before = capture_existing_change_protection(repo)

    file_path.unlink()

    result = verify_existing_change_protection(
        before,
        repo,
    )

    assert result.valid is True
    assert result.protected is False
    assert "PRE_EXISTING_CHANGE_REMOVED" in result.reason


def test_invalid_before_state_fails_closed(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    _git(repo, "init")

    invalid_before = ExistingChangeProtectionResult(
        valid=False,
        repository_root=None,
        protected=False,
        existing_changes=(),
        change_count=0,
        reason="INVALID",
    )

    result = verify_existing_change_protection(
        invalid_before,
        repo,
    )

    assert result.valid is False
    assert result.protected is False
    assert result.reason == "INVALID_BEFORE_PROTECTION_STATE"
